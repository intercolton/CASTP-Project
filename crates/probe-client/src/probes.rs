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
pub const PAIR_ID_HEADER: &str = "x-astp-pair-id";

#[derive(Clone)]
pub struct Ctx {
    pub probe_id: String,
    pub network_id: String,
    pub iface: Option<String>,
    pub limits: LimitsSection,
    /// Set while the two halves of a paired cascade probe run: written into
    /// both events and sent to both servers.
    pub pair_id: Option<String>,
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
    /// Which resolved address was used, when DNS gave more than one.
    addr_note: Option<String>,
}

/// At most this many resolved addresses are tried, one after another.
pub(crate) const MAX_ADDRS: usize = 4;

/// Tries `addrs` in order until `connect` succeeds. Returns the result and,
/// when there was a choice, a note naming the address used and what
/// happened to the ones before it.
pub(crate) async fn first_working<T, F, Fut>(
    addrs: &[std::net::SocketAddr],
    mut connect: F,
) -> (Result<(std::net::SocketAddr, T), Failure>, Option<String>)
where
    F: FnMut(std::net::SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Result<T, Failure>>,
{
    let addrs = &addrs[..addrs.len().min(MAX_ADDRS)];
    let mut tried = Vec::new();
    let mut last = None;
    for &addr in addrs {
        match connect(addr).await {
            Ok(v) => {
                let note = (addrs.len() > 1).then(|| {
                    if tried.is_empty() {
                        format!("addr {addr} (1st of {})", addrs.len())
                    } else {
                        format!("addr {addr} after {}", tried.join(", "))
                    }
                });
                return (Ok((addr, v)), note);
            }
            Err(f) => {
                tried.push(format!("{addr}: {}", f.code));
                last = Some(f);
            }
        }
    }
    let note = (addrs.len() > 1).then(|| format!("tried {}", tried.join(", ")));
    let f = last.unwrap_or_else(|| Failure::new(ErrorCode::DnsFailure, "no address to try"));
    (Err(f), note)
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
        ev.pair_id = ctx.pair_id.clone();
        ev.phase = Some(Phase::None);
        Attempt {
            ev,
            start: Instant::now(),
            counters: None,
            addr_note: None,
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub(crate) fn set_addr_note(&mut self, note: Option<String>) {
        self.addr_note = note;
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
        let note = self.addr_note.take();
        let with_note = |d: Option<String>| match (d, &note) {
            (Some(d), Some(n)) => Some(format!("{d}; {n}")),
            (d, None) => d,
            (None, Some(n)) => Some(n.clone()),
        };
        match result {
            Ok(detail) => {
                self.ev.detail = with_note(detail);
                self.ev.succeed()
            }
            Err(f) => {
                let detail = with_note(Some(f.detail)).unwrap_or_default();
                self.ev.fail(f.code, detail)
            }
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
        let mut t = Instant::now();
        let (r, note) = first_working(&addrs, |addr| {
            t = Instant::now();
            netutil::connect(addr, ctx.iface.as_deref(), ctx.connect_timeout())
        })
        .await;
        self.addr_note = note;
        let (_, stream) = r?;
        // Latency of the connect that worked, not of the ones before it.
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
    // getaddrinfo cannot be bound to a device: with a VPN up the query may
    // go through the tunnel while every other test bypasses it.
    let r = match (&ctx.iface, r) {
        (Some(dev), Ok(d)) => Ok(Some(format!(
            "{}; system resolver, not bound to {dev}",
            d.unwrap_or_default()
        ))),
        (Some(dev), Err(f)) => Err(Failure::new(
            f.code,
            format!("{}; system resolver, not bound to {dev}", f.detail),
        )),
        (None, r) => r,
    };
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
    // detail carries the whole chain; the code comes from the first typed
    // error in it that says something definite.
    let mut detail = e.to_string();
    let mut typed = None;
    let mut src = e.source();
    while let Some(s) = src {
        detail.push_str(": ");
        detail.push_str(&s.to_string());
        if typed.is_none() {
            typed = typed_code(s);
        }
        src = s.source();
    }
    let code = typed
        .or_else(|| {
            if e.is_timeout() {
                Some(ErrorCode::ApplicationTimeout)
            } else if e.is_closed() || e.is_incomplete_message() {
                Some(ErrorCode::RemoteClosed)
            } else {
                None
            }
        })
        .unwrap_or_else(|| text_code(&detail));
    Failure::new(code, detail)
}

/// Classifies one error of a hyper error chain by its type.
fn typed_code(s: &(dyn std::error::Error + 'static)) -> Option<ErrorCode> {
    let known = |c| (c != ErrorCode::Unknown).then_some(c);
    if let Some(h2e) = s.downcast_ref::<h2::Error>() {
        // h2 keeps the transport error to itself; it is not in the chain.
        if let Some(io) = h2e.get_io() {
            return known(ErrorCode::from_stream_error(io));
        }
        if h2e.is_go_away() || h2e.is_reset() {
            return Some(if h2e.is_remote() {
                // The peer sent GOAWAY or RST_STREAM: it ended the exchange.
                ErrorCode::RemoteClosed
            } else {
                // Our own h2 stack gave up on what the peer sent.
                ErrorCode::HttpProtocolError
            });
        }
        // A protocol error h2 detected in what the peer sent.
        return h2e.reason().map(|_| ErrorCode::HttpProtocolError);
    }
    if let Some(io) = s.downcast_ref::<std::io::Error>() {
        return known(ErrorCode::from_stream_error(io));
    }
    None
}

/// Last resort for errors that reach us only as text. Each pattern is
/// pinned by a test so a wording change in a dependency shows up there.
fn text_code(detail: &str) -> ErrorCode {
    let lower = detail.to_lowercase();
    if lower.contains("connection reset") {
        ErrorCode::TcpReset
    } else if lower.contains("unexpected end of file")
        // TCP FIN without TLS close_notify: torn down under the TLS layer.
        || lower.contains("close_notify")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
    {
        ErrorCode::RemoteClosed
    } else {
        ErrorCode::HttpProtocolError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[tokio::test]
    async fn falls_back_to_the_next_address() {
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        let t = std::time::Duration::from_secs(5);

        let (r, note) =
            first_working(&[dead_addr, live_addr], |a| netutil::connect(a, None, t)).await;
        assert_eq!(r.unwrap().0, live_addr);
        let note = note.unwrap();
        assert!(
            note.contains(&format!("addr {live_addr} after {dead_addr}: tcp_refused")),
            "{note}"
        );

        let (r, note) =
            first_working(&[dead_addr, dead_addr], |a| netutil::connect(a, None, t)).await;
        assert_eq!(r.unwrap_err().code, ErrorCode::TcpRefused);
        assert!(note.unwrap().starts_with("tried "));

        // A single address adds no note: details stay as they were.
        let (r, note) = first_working(&[live_addr], |a| netutil::connect(a, None, t)).await;
        assert!(r.is_ok());
        assert!(note.is_none());
    }

    #[test]
    fn typed_errors_are_classified() {
        // The peer sent something h2 rejects.
        let proto = h2::Error::from(h2::Reason::PROTOCOL_ERROR);
        assert_eq!(typed_code(&proto), Some(ErrorCode::HttpProtocolError));
        let reset = io::Error::new(io::ErrorKind::ConnectionReset, "x");
        assert_eq!(typed_code(&reset), Some(ErrorCode::TcpReset));
        let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "x");
        assert_eq!(typed_code(&eof), Some(ErrorCode::RemoteClosed));
        // An I/O error that says nothing definite falls through to the text.
        assert_eq!(typed_code(&io::Error::other("x")), None);
    }

    /// Wording the text fallback depends on. rustls: a TCP FIN without
    /// close_notify; std: the reset and EOF messages.
    #[test]
    fn text_fallback_patterns() {
        let eof = io::Error::from(io::ErrorKind::UnexpectedEof).to_string();
        assert_eq!(text_code(&eof), ErrorCode::RemoteClosed, "{eof}");
        let reset = io::Error::from_raw_os_error(libc_econnreset()).to_string();
        assert_eq!(text_code(&reset), ErrorCode::TcpReset, "{reset}");
        let tls = rustls_eof_without_close_notify();
        assert_eq!(tls.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            text_code(&tls.to_string()),
            ErrorCode::RemoteClosed,
            "{tls}"
        );
        assert_eq!(
            text_code("frame with invalid size"),
            ErrorCode::HttpProtocolError
        );
    }

    /// The error rustls gives when TCP closes under an established TLS
    /// session without close_notify, produced in memory.
    fn rustls_eof_without_close_notify() -> io::Error {
        use std::io::Read;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["probe.test".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let provider = crate::tlsutil::provider();
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![der],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            std::sync::Arc::new(client_cfg),
            "probe.test".try_into().unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(std::sync::Arc::new(server_cfg)).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut &buf[..]).unwrap();
            server.process_new_packets().unwrap();
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            client.read_tls(&mut &buf[..]).unwrap();
            client.process_new_packets().unwrap();
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking());
        // TCP FIN: zero bytes, no close_notify alert first.
        assert_eq!(client.read_tls(&mut &[][..]).unwrap(), 0);
        client.process_new_packets().unwrap();
        client.reader().read(&mut [0u8; 16]).unwrap_err()
    }

    fn libc_econnreset() -> i32 {
        if cfg!(windows) {
            10054
        } else if cfg!(any(target_os = "macos", target_os = "ios")) {
            54
        } else {
            104
        }
    }
}
