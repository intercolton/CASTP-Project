//! Diagnostic server (spec 4): TCP/TLS/HTTP/1.1/HTTP/2 endpoints on one
//! port, with every accepted TCP connection logged — including the ones
//! that never finish a TLS handshake, which is exactly what a client sees as
//! "connects, then hangs".

mod body;
mod handler;
mod quic;
mod tls;

use anyhow::{Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use probe_common::config::ServerConfig;
use probe_common::counting::Counting;
use probe_common::jsonl::JsonlWriter;
use probe_common::{ErrorCode, Phase, ProbeEvent, Side, TestType, Transport};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

pub use handler::{DOWNLOAD_PATH, ECHO_PATH, PROBE_PATH, SESSION_PATH};

/// Events flow through this channel to a single writer task.
pub type EventTx = mpsc::Sender<ProbeEvent>;

pub struct Handle {
    pub addr: SocketAddr,
    /// UDP address of the QUIC/HTTP/3 listener, when enabled.
    pub quic_addr: Option<SocketAddr>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Handle {
    /// Stops accepting, closes open connections and flushes the log.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.task.await.context("server task panicked")?
    }

    /// Waits until the server stops on its own (it only does on error).
    pub async fn wait(self) -> Result<()> {
        self.task.await.context("server task panicked")?
    }
}

/// Validates certificates and the key without binding any port.
pub fn check(cfg: &ServerConfig) -> Result<()> {
    tls::server_config(&cfg.tls.cert_file, &cfg.tls.key_file)?;
    if cfg.quic.enable {
        tls::quic_server_config(&cfg.tls.cert_file, &cfg.tls.key_file)?;
    }
    Ok(())
}

/// Binds the listener and starts serving in the background.
pub async fn start(cfg: ServerConfig) -> Result<Handle> {
    let acceptor = tls::acceptor(&cfg.tls.cert_file, &cfg.tls.key_file)?;
    let listener = TcpListener::bind(&cfg.server.listen)
        .await
        .with_context(|| format!("bind {}", cfg.server.listen))?;
    let addr = listener.local_addr()?;

    let log_path = cfg.server.data_dir.join("server-events.jsonl");
    let mut writer = JsonlWriter::open(&log_path, cfg.logs.max_file_bytes, cfg.logs.keep_files)
        .with_context(|| format!("open {}", log_path.display()))?;
    let (tx, mut rx) = mpsc::channel::<ProbeEvent>(4096);
    // File writes block; they run on their own thread, not on a runtime worker.
    let writer_task = tokio::task::spawn_blocking(move || {
        while let Some(ev) = rx.blocking_recv() {
            if let Err(e) = writer.write(&ev) {
                tracing::error!("cannot write event: {e}");
            }
        }
    });

    let (sd_tx, sd_rx) = watch::channel(false);
    let shared = Arc::new(Shared {
        cfg,
        acceptor,
        tx,
        limit: Arc::new(Semaphore::new(0)),
    });
    shared.limit.add_permits(shared.cfg.limits.max_connections);
    tracing::info!(%addr, id = %shared.cfg.server.id, "listening");

    let mut quic_addr = None;
    let quic_task = match (shared.cfg.quic.enable, shared.cfg.quic.listen.clone()) {
        (true, Some(listen)) => {
            let ep = quic::endpoint(&shared, &listen)?;
            quic_addr = Some(ep.local_addr()?);
            tracing::info!(addr = ?quic_addr, "QUIC listening");
            Some(tokio::spawn(quic::accept_loop(
                ep,
                shared.clone(),
                sd_rx.clone(),
            )))
        }
        _ => None,
    };

    let task = tokio::spawn(async move {
        let r = accept_loop(listener, shared, sd_rx).await;
        if let Some(q) = quic_task {
            let _ = q.await;
        }
        // All senders are gone once connections are closed: the writer drains and stops.
        let _ = writer_task.await;
        r
    });
    Ok(Handle {
        addr,
        quic_addr,
        shutdown: sd_tx,
        task,
    })
}

pub(crate) struct Shared {
    cfg: ServerConfig,
    acceptor: tokio_rustls::TlsAcceptor,
    tx: EventTx,
    limit: Arc<Semaphore>,
}

/// Concurrent HTTP/2 streams per connection.
pub const MAX_H2_STREAMS: u32 = 4;

/// How long open connections get to finish after a shutdown request
/// before they are cut; their events are logged either way.
pub(crate) const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut conns = JoinSet::new();
    let mut refused = Refusals::new(Transport::Tcp);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        // Out of descriptors or similar: back off instead of spinning.
                        tracing::warn!("accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // Checked before spawning: a flood of refused connections
                // costs neither a task nor a blocking log write each.
                let Ok(permit) = shared.limit.clone().try_acquire_owned() else {
                    drop(stream);
                    refused.note(&shared, peer);
                    continue;
                };
                let shared = shared.clone();
                let sd = shutdown.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    handle_conn(shared, stream, peer, sd).await
                });
            }
        }
    }
    refused.flush(&shared);
    drain(conns).await;
    Ok(())
}

/// Waits for connection tasks that are winding down after a shutdown
/// request, then aborts whatever is still left.
pub(crate) async fn drain(mut conns: JoinSet<()>) {
    let wait = async { while conns.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(3), wait)
        .await
        .is_err()
    {
        tracing::warn!("connections did not finish after shutdown, aborting them");
    }
    conns.shutdown().await;
}

/// Connections turned away by the connection limit. Logged at most once a
/// second, with the count, so a flood cannot crowd out the journal.
pub(crate) struct Refusals {
    transport: Transport,
    count: u64,
    since: Instant,
    last_peer: Option<SocketAddr>,
}

impl Refusals {
    pub(crate) fn new(transport: Transport) -> Self {
        Refusals {
            transport,
            count: 0,
            since: Instant::now(),
            last_peer: None,
        }
    }

    pub(crate) fn note(&mut self, shared: &Shared, peer: SocketAddr) {
        self.count += 1;
        self.last_peer = Some(peer);
        if self.since.elapsed() >= Duration::from_secs(1) {
            self.flush(shared);
        }
    }

    pub(crate) fn flush(&mut self, shared: &Shared) {
        let Some(peer) = self.last_peer.take() else {
            return;
        };
        let cfg = &shared.cfg;
        let tt = match self.transport {
            Transport::Quic => TestType::QuicAccept,
            _ => TestType::TcpAccept,
        };
        let mut ev = ProbeEvent::new(
            ProbeEvent::new_test_id(),
            &cfg.server.id,
            "server",
            &cfg.server.id,
            tt,
            self.transport,
        );
        ev.side = Side::Server;
        ev.peer = Some(peer.to_string());
        ev.phase = Some(Phase::TcpConnected);
        if self.transport == Transport::Quic {
            ev.phase = Some(Phase::FirstBytesReceived);
        }
        ev.duration_ms = self.since.elapsed().as_millis() as u64;
        let ev = ev.fail(
            ErrorCode::Unknown,
            format!(
                "server connection limit ({}) reached: {} connection(s) refused in {:.1} s, last from {peer}",
                cfg.limits.max_connections,
                self.count,
                self.since.elapsed().as_secs_f64()
            ),
        );
        if shared.tx.try_send(ev).is_err() {
            tracing::warn!("event queue full, dropped a refusal event");
        }
        self.count = 0;
        self.since = Instant::now();
    }
}

async fn handle_conn(
    shared: Arc<Shared>,
    stream: TcpStream,
    peer: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) {
    let start = Instant::now();
    let cfg = &shared.cfg;
    let mut ev = ProbeEvent::new(
        ProbeEvent::new_test_id(),
        &cfg.server.id,
        "server",
        &cfg.server.id,
        TestType::TcpAccept,
        Transport::Tcp,
    );
    ev.side = Side::Server;
    ev.peer = Some(peer.to_string());
    ev.phase = Some(Phase::TcpConnected);

    let _ = stream.set_nodelay(true);
    let (io, counters) = Counting::new(stream);
    let hs_timeout = Duration::from_secs(cfg.limits.handshake_timeout_seconds);
    let hs = tokio::select! {
        hs = tokio::time::timeout(hs_timeout, shared.acceptor.accept(io)) => Some(hs),
        _ = shutdown.changed() => None,
    };
    let tls = match hs {
        Some(Ok(Ok(tls))) => tls,
        other => {
            let (code, detail) = match other {
                None => (
                    ErrorCode::RemoteClosed,
                    "server shut down during the TLS handshake".into(),
                ),
                Some(Err(_)) => (
                    ErrorCode::TlsHandshakeFailed,
                    format!("no complete TLS handshake within {}s", hs_timeout.as_secs()),
                ),
                Some(Ok(Err(e))) => match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => (
                        ErrorCode::RemoteClosed,
                        "peer closed before TLS finished".into(),
                    ),
                    std::io::ErrorKind::ConnectionReset => {
                        (ErrorCode::TcpReset, "reset before TLS finished".into())
                    }
                    _ => (ErrorCode::TlsHandshakeFailed, e.to_string()),
                },
                Some(Ok(Ok(_))) => unreachable!(),
            };
            if counters.received() > 0 {
                ev.phase = Some(Phase::FirstBytesReceived);
            }
            ev.duration_ms = start.elapsed().as_millis() as u64;
            ev.bytes_sent = counters.sent();
            ev.bytes_received = counters.received();
            let _ = shared.tx.send(ev.fail(code, detail)).await;
            return;
        }
    };
    ev.handshake_ms = Some(start.elapsed().as_millis() as u64);
    ev.phase = Some(Phase::HandshakeDone);
    let version;
    {
        let (_, conn) = tls.get_ref();
        ev.alpn = conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        ev.tls_stack = Some(tls::TLS_STACK.into());
        version = conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_default();
    }

    let requests = Arc::new(AtomicU64::new(0));
    let in_flight = Arc::new(AtomicU64::new(0));
    let svc = handler::Service {
        server_id: cfg.server.id.clone(),
        peer,
        tx: shared.tx.clone(),
        limits: cfg.limits.clone(),
        requests: requests.clone(),
        in_flight: in_flight.clone(),
        budget: Arc::new(AtomicU64::new(cfg.limits.max_session_bytes)),
        conn_start: start,
    };
    let timer = hyper_util::rt::TokioTimer::new();
    let idle = Duration::from_secs(cfg.limits.idle_timeout_seconds);
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    // Without a timer hyper silently skips the HTTP/1 header-read timeout.
    builder
        .http1()
        .timer(timer.clone())
        .header_read_timeout(idle);
    builder
        .http2()
        .timer(timer)
        // PING finds a dead peer; it does not count as activity (idle_watch).
        .keep_alive_interval((idle / 2).clamp(Duration::from_millis(500), Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20))
        // Enough for a browser-like client; caps parallel /download streams.
        .max_concurrent_streams(MAX_H2_STREAMS)
        .adaptive_window(true);
    let conn = builder.serve_connection(TokioIo::new(tls), svc);
    tokio::pin!(conn);
    let max = tokio::time::sleep(Duration::from_secs(cfg.limits.max_session_seconds + 30));
    tokio::pin!(max);
    let outcome = tokio::select! {
        r = conn.as_mut() => End::Closed(r),
        _ = &mut max => End::SessionLimit,
        _ = idle_watch(&requests, &in_flight, idle) => End::Idle,
        _ = shutdown.changed() => {
            // GOAWAY / Connection: close; requests in flight get a short grace.
            conn.as_mut().graceful_shutdown();
            match tokio::time::timeout(SHUTDOWN_GRACE, conn.as_mut()).await {
                Ok(r) => End::Closed(r),
                Err(_) => End::Shutdown,
            }
        }
    };

    let n = requests.load(Ordering::Relaxed);
    if n > 0 {
        ev.phase = Some(Phase::Completed);
    }
    ev.duration_ms = start.elapsed().as_millis() as u64;
    ev.bytes_sent = counters.sent();
    ev.bytes_received = counters.received();
    ev.detail = Some(format!("{version}, {n} request(s)"));
    let ev = match outcome {
        End::SessionLimit => ev.fail(
            ErrorCode::ApplicationTimeout,
            "connection exceeded the session limit",
        ),
        End::Shutdown => ev.fail(
            ErrorCode::RemoteClosed,
            format!("{version}, {n} request(s), cut by server shutdown"),
        ),
        // Keeping a served connection open and then going quiet is what
        // browsers do; a peer that never asked for anything is not.
        End::Idle if n > 0 => {
            ev.detail = Some(format!(
                "{version}, {n} request(s), closed after {} s idle",
                idle.as_secs()
            ));
            ev.succeed()
        }
        End::Idle => ev.fail(
            ErrorCode::ApplicationTimeout,
            format!(
                "no request and no traffic for {} s after the handshake, closed",
                idle.as_secs()
            ),
        ),
        // The connection's job is the handshake; a peer that leaves afterwards,
        // with or without requests, ended it normally (a TLS-only test does).
        End::Closed(r) => {
            // Our own close_notify failing because the peer already left is not news.
            let shutdown_only = matches!(&r, Err(e)
                if e.downcast_ref::<hyper::Error>().is_some_and(|h| h.is_shutdown()));
            if let (Err(e), false) = (r, shutdown_only) {
                ev.detail = Some(format!(
                    "{version}, {n} request(s), closed: {}",
                    probe_common::error_chain(&*e)
                ));
            }
            ev.succeed()
        }
    };
    let _ = shared.tx.send(ev).await;
}

/// How a served connection ended.
enum End {
    Closed(std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>),
    SessionLimit,
    Idle,
    Shutdown,
}

/// Returns once the connection has had no request in flight and no new
/// request for `idle`.
///
/// Activity is counted in requests, not bytes: HTTP/2 keepalive PINGs and
/// their ACKs move bytes on an otherwise unused connection and would keep
/// it (and its connection slot) forever. A request in flight counts in
/// either direction, so a one-way leg of a split-path cascade (an upload
/// that gets almost nothing back, a slow heartbeat session) is not idle.
async fn idle_watch(requests: &AtomicU64, in_flight: &AtomicU64, idle: Duration) {
    let tick = (idle / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
    let mut seen = requests.load(Ordering::Relaxed);
    let mut since = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(tick).await;
        let now = requests.load(Ordering::Relaxed);
        if now != seen || in_flight.load(Ordering::Relaxed) > 0 {
            seen = now;
            since = tokio::time::Instant::now();
        } else if since.elapsed() >= idle {
            return;
        }
    }
}
