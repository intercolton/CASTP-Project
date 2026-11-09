//! One function per short test (spec 6.1). Each opens its own connection
//! from scratch and returns exactly one event describing how far it got.

use crate::netutil::{self, Counters, Counting, Failure};
use crate::tlsutil::{self, TLS_STACK};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::{TokioExecutor, TokioIo};
use probe_common::config::{ControlConfig, LimitsSection, TargetConfig};
use probe_common::{ErrorCode, Phase, ProbeEvent, TestType, Transport};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Path on the probe server that answers short requests and logs the test id.
pub const PROBE_PATH: &str = "/probe";
pub const TEST_ID_HEADER: &str = "x-astp-test-id";

#[derive(Clone)]
pub struct Ctx {
    pub probe_id: String,
    pub network_id: String,
    pub iface: Option<String>,
    pub limits: LimitsSection,
}

impl Ctx {
    pub(crate) fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.connect_timeout_seconds)
    }
    pub(crate) fn tls_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.tls_timeout_seconds)
    }
    pub(crate) fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.request_timeout_seconds)
    }
}

/// An in-progress test: the event being filled in and its monotonic start.
pub(crate) struct Attempt {
    pub(crate) ev: ProbeEvent,
    start: Instant,
    counters: Option<Counters>,
}

impl Attempt {
    pub(crate) fn new(
        ctx: &Ctx,
        target_id: &str,
        test_type: TestType,
        transport: Transport,
    ) -> Self {
        let mut ev = ProbeEvent::new(
            ProbeEvent::new_test_id(),
            &ctx.probe_id,
            &ctx.network_id,
            target_id,
            test_type,
            transport,
        );
        ev.interface = ctx.iface.clone();
        ev.phase = Some(Phase::None);
        Attempt {
            ev,
            start: Instant::now(),
            counters: None,
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub(crate) fn reached(&mut self, phase: Phase) {
        self.ev.phase = Some(phase);
    }

    pub(crate) fn finish(mut self, result: Result<Option<String>, Failure>) -> ProbeEvent {
        self.ev.duration_ms = self.elapsed_ms();
        if let Some(c) = &self.counters {
            self.ev.bytes_sent = c.sent();
            self.ev.bytes_received = c.received();
        }
        match result {
            Ok(detail) => {
                self.ev.detail = detail;
                self.ev.succeed()
            }
            Err(f) => self.ev.fail(f.code, f.detail),
        }
    }

    /// Resolve and connect, recording the phase and connect latency.
    pub(crate) async fn open(
        &mut self,
        ctx: &Ctx,
        host: &str,
        port: u16,
    ) -> Result<Counting<TcpStream>, Failure> {
        let addrs = netutil::resolve(host, port, ctx.connect_timeout()).await?;
        self.reached(Phase::DnsResolved);
        let t = Instant::now();
        let stream =
            netutil::connect(addrs[0], ctx.iface.as_deref(), ctx.connect_timeout()).await?;
        self.ev.connect_ms = Some(t.elapsed().as_millis() as u64);
        self.reached(Phase::TcpConnected);
        let (counting, counters) = Counting::new(stream);
        self.counters = Some(counters);
        Ok(counting)
    }
}

pub async fn dns(ctx: &Ctx, t: &TargetConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::DnsResolution, Transport::Udp);
    let r = netutil::resolve(&t.host, t.port, ctx.connect_timeout()).await;
    let r = r.map(|addrs| {
        a.reached(Phase::DnsResolved);
        Some(format!("{} address(es)", addrs.len()))
    });
    a.finish(r)
}

pub async fn tcp(ctx: &Ctx, t: &TargetConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::TcpConnect, Transport::Tcp);
    let r = a.open(ctx, &t.host, t.port).await.map(|_| None);
    a.finish(r)
}

pub async fn tls(ctx: &Ctx, t: &TargetConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::TlsHandshake, Transport::Tcp);
    a.ev.tls_stack = Some(TLS_STACK.into());
    let r = async {
        let io = a.open(ctx, &t.host, t.port).await?;
        let cfg = tlsutil::client_config(t.ca_file.as_deref(), &[], true)?;
        let ts = Instant::now();
        let mut hs = tlsutil::handshake(cfg, t.server_name(), io, ctx.tls_timeout()).await?;
        a.ev.handshake_ms = Some(ts.elapsed().as_millis() as u64);
        a.reached(Phase::HandshakeDone);
        // close_notify, so the server records a clean end rather than an EOF.
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut hs.stream).await;
        Ok(Some(hs.version))
    }
    .await;
    a.finish(r)
}

pub async fn https_get(ctx: &Ctx, t: &TargetConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::HttpsGet, Transport::Tcp);
    a.ev.tls_stack = Some(TLS_STACK.into());
    let path = format!("{PROBE_PATH}?test_id={}", a.ev.test_id);
    let r = http_exchange(
        &mut a,
        ctx,
        &t.host,
        t.port,
        t.server_name(),
        t.ca_file.as_deref(),
        &path,
        false,
        true,
    )
    .await;
    a.finish(r)
}

pub async fn h2(ctx: &Ctx, t: &TargetConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::H2Request, Transport::Tcp);
    a.ev.tls_stack = Some(TLS_STACK.into());
    let path = format!("{PROBE_PATH}?test_id={}", a.ev.test_id);
    let r = http_exchange(
        &mut a,
        ctx,
        &t.host,
        t.port,
        t.server_name(),
        t.ca_file.as_deref(),
        &path,
        true,
        true,
    )
    .await;
    a.finish(r)
}

/// HTTPS GET to an independent resource. Any HTTP response counts as
/// reachable: the control answers "does this network reach the internet",
/// not "is that site healthy".
pub async fn control(ctx: &Ctx, c: &ControlConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &c.id, TestType::HttpsGet, Transport::Tcp);
    a.ev.control = true;
    a.ev.tls_stack = Some(TLS_STACK.into());
    let r = async {
        let uri: http::Uri = c
            .url
            .parse()
            .map_err(|e| Failure::new(ErrorCode::Unknown, format!("bad control url: {e}")))?;
        let host = uri
            .host()
            .ok_or_else(|| Failure::new(ErrorCode::Unknown, "control url has no host"))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);
        let path = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_owned();
        http_exchange(&mut a, ctx, &host, port, &host, None, &path, false, false).await
    }
    .await;
    a.finish(r)
}

#[allow(clippy::too_many_arguments)]
async fn http_exchange(
    a: &mut Attempt,
    ctx: &Ctx,
    host: &str,
    port: u16,
    server_name: &str,
    ca_file: Option<&std::path::Path>,
    path: &str,
    use_h2: bool,
    require_ok: bool,
) -> Result<Option<String>, Failure> {
    let io = a.open(ctx, host, port).await?;
    let alpn: &[&[u8]] = if use_h2 { &[b"h2"] } else { &[b"http/1.1"] };
    let cfg = tlsutil::client_config(ca_file, alpn, false)?;
    let ts = Instant::now();
    let hs = tlsutil::handshake(cfg, server_name, io, ctx.tls_timeout()).await?;
    a.ev.handshake_ms = Some(ts.elapsed().as_millis() as u64);
    a.ev.alpn = hs.alpn.clone();
    a.reached(Phase::HandshakeDone);
    if use_h2 && hs.alpn.as_deref() != Some("h2") {
        return Err(Failure::new(
            ErrorCode::HttpProtocolError,
            format!("server did not negotiate h2 via ALPN (got {:?})", hs.alpn),
        ));
    }

    // Host/:authority carries the verified TLS name, not a raw IP.
    let authority = if port == 443 {
        server_name.to_owned()
    } else {
        format!("{server_name}:{port}")
    };
    let test_id = a.ev.test_id.clone();
    let deadline = ctx.request_timeout();
    let max_bytes = ctx.limits.max_test_bytes as usize;

    let fut = async {
        let io = TokioIo::new(hs.stream);
        let resp = if use_h2 {
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                    .await
                    .map_err(http_failure)?;
            tokio::spawn(conn);
            let req = http::Request::get(format!("https://{authority}{path}"))
                .header(TEST_ID_HEADER, &test_id)
                .header(http::header::USER_AGENT, "astp-probe/0.1")
                .body(Empty::<Bytes>::new())
                .map_err(|e| Failure::new(ErrorCode::Unknown, e.to_string()))?;
            a.reached(Phase::AppDataSent);
            sender.send_request(req).await.map_err(http_failure)?
        } else {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(http_failure)?;
            tokio::spawn(conn);
            let req = http::Request::get(path)
                .header(http::header::HOST, &authority)
                .header(TEST_ID_HEADER, &test_id)
                .header(http::header::USER_AGENT, "astp-probe/0.1")
                .body(Empty::<Bytes>::new())
                .map_err(|e| Failure::new(ErrorCode::Unknown, e.to_string()))?;
            a.reached(Phase::AppDataSent);
            sender.send_request(req).await.map_err(http_failure)?
        };
        a.reached(Phase::AppDataReceived);
        let status = resp.status();
        let body = Limited::new(resp.into_body(), max_bytes)
            .collect()
            .await
            .map_err(|e| Failure::new(ErrorCode::HttpProtocolError, format!("body: {e}")))?
            .to_bytes();
        Ok::<_, Failure>((status, body.len()))
    };
    let (status, body_len) = match tokio::time::timeout(deadline, fut).await {
        Err(_) => {
            return Err(Failure::new(
                ErrorCode::ApplicationTimeout,
                format!("no complete HTTP response within {}s", deadline.as_secs()),
            ))
        }
        Ok(r) => r?,
    };
    if require_ok && !status.is_success() {
        return Err(Failure::new(
            ErrorCode::HttpProtocolError,
            format!("HTTP status {status}"),
        ));
    }
    a.reached(Phase::Completed);
    Ok(Some(format!(
        "HTTP {} {}, body {} B",
        status.as_u16(),
        hs.version,
        body_len
    )))
}

pub(crate) fn http_failure(e: hyper::Error) -> Failure {
    use std::error::Error as _;
    // The useful part is usually deep in the chain (h2 or I/O), so the
    // detail carries the whole chain.
    let mut detail = e.to_string();
    let mut io_code = None;
    let mut src = e.source();
    while let Some(s) = src {
        detail.push_str(": ");
        detail.push_str(&s.to_string());
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            io_code.get_or_insert(ErrorCode::from_stream_error(io));
        }
        src = s.source();
    }
    let lower = detail.to_lowercase();
    let code = if let Some(c) = io_code {
        c
    } else if e.is_closed() || e.is_incomplete_message() {
        ErrorCode::RemoteClosed
    } else if e.is_timeout() {
        ErrorCode::ApplicationTimeout
    } else if lower.contains("connection reset") {
        ErrorCode::TcpReset
    } else if lower.contains("unexpected end of file")
        // TCP FIN without TLS close_notify: the connection was torn down
        // under the TLS layer (h2 hides the underlying io::Error).
        || lower.contains("close_notify")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
        || lower.contains("go_away")
        || lower.contains("goaway")
    {
        ErrorCode::RemoteClosed
    } else {
        ErrorCode::HttpProtocolError
    };
    Failure::new(code, detail)
}
