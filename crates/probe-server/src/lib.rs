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
    let writer_task = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
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

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut conns = JoinSet::new();
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
                let shared = shared.clone();
                conns.spawn(async move { handle_conn(shared, stream, peer).await });
            }
        }
    }
    conns.shutdown().await;
    Ok(())
}

async fn handle_conn(shared: Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
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

    let Ok(_permit) = shared.limit.clone().try_acquire_owned() else {
        ev.duration_ms = start.elapsed().as_millis() as u64;
        let _ = shared
            .tx
            .send(ev.fail(
                ErrorCode::Unknown,
                "server connection limit reached, closed",
            ))
            .await;
        return;
    };

    let _ = stream.set_nodelay(true);
    let (io, counters) = Counting::new(stream);
    let hs_timeout = Duration::from_secs(cfg.limits.handshake_timeout_seconds);
    let hs = tokio::time::timeout(hs_timeout, shared.acceptor.accept(io)).await;
    let tls = match hs {
        Ok(Ok(tls)) => tls,
        other => {
            let (code, detail) = match other {
                Err(_) => (
                    ErrorCode::TlsHandshakeFailed,
                    format!("no complete TLS handshake within {}s", hs_timeout.as_secs()),
                ),
                Ok(Err(e)) => match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => (
                        ErrorCode::RemoteClosed,
                        "peer closed before TLS finished".into(),
                    ),
                    std::io::ErrorKind::ConnectionReset => {
                        (ErrorCode::TcpReset, "reset before TLS finished".into())
                    }
                    _ => (ErrorCode::TlsHandshakeFailed, e.to_string()),
                },
                Ok(Ok(_)) => unreachable!(),
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
    let svc = handler::Service {
        server_id: cfg.server.id.clone(),
        peer,
        tx: shared.tx.clone(),
        limits: cfg.limits.clone(),
        requests: requests.clone(),
    };
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .adaptive_window(true);
    let conn = builder.serve_connection(TokioIo::new(tls), svc);
    let max = Duration::from_secs(cfg.limits.max_session_seconds + 30);
    let result = tokio::time::timeout(max, conn).await;

    let n = requests.load(Ordering::Relaxed);
    if n > 0 {
        ev.phase = Some(Phase::Completed);
    }
    ev.duration_ms = start.elapsed().as_millis() as u64;
    ev.bytes_sent = counters.sent();
    ev.bytes_received = counters.received();
    ev.detail = Some(format!("{version}, {n} request(s)"));
    let ev = match result {
        Err(_) => ev.fail(
            ErrorCode::ApplicationTimeout,
            "connection exceeded the session limit",
        ),
        // The connection's job is the handshake; a peer that leaves afterwards,
        // with or without requests, ended it normally (a TLS-only test does).
        Ok(r) => {
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
