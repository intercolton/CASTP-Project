//! HTTP endpoints (spec 4.2). Every request is logged with the client's
//! test id so the analyzer can join client and server views of one test.
//!
//! - `GET /probe`                       short control answer
//! - `GET /echo`                        tiny answer for application RTT
//! - `GET /download?bytes=N`            N bytes, capped by the server limit
//! - `GET /session?seconds=S&interval_ms=I&size=B` heartbeats for a long session
//! - `POST /session?seconds=S`                upstream long session; the
//!   response streams acknowledgements (`<bytes received>\n`) as data
//!   arrives and ends with `done <total>\n`
//!
//! Any request may carry `pair_id` (query or `x-astp-pair-id`): the two
//! halves of a paired cascade probe share it, on both servers.

use crate::body::{ChannelBody, GenBody};
use crate::EventTx;
use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::Incoming;
use probe_common::config::ServerLimitsSection;
use probe_common::{Direction, ErrorCode, Phase, ProbeEvent, Side, TestType, Transport};
use std::convert::Infallible;
use std::future::{ready, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const PROBE_PATH: &str = "/probe";
pub const ECHO_PATH: &str = "/echo";
pub const DOWNLOAD_PATH: &str = "/download";
pub const SESSION_PATH: &str = "/session";
const TEST_ID_HEADER: &str = "x-astp-test-id";
const PAIR_ID_HEADER: &str = "x-astp-pair-id";
/// Upload acknowledgements are sent at most this often.
const ACK_EVERY: Duration = Duration::from_millis(200);
/// Answer bodies shared by the TCP and QUIC listeners, so the logged
/// `bytes_sent` is the real length in both.
pub const PROBE_BODY: &str = "ok astp\n";
pub const ECHO_BODY: &str = "echo\n";

type RespBody = UnsyncBoxBody<Bytes, Infallible>;

#[derive(Clone)]
pub struct Service {
    pub server_id: String,
    pub peer: SocketAddr,
    pub tx: EventTx,
    pub limits: ServerLimitsSection,
    pub requests: Arc<AtomicU64>,
    /// Bytes this connection may still move through `/download`,
    /// `/session` and uploads, shared by all its requests: parallel HTTP/2
    /// streams cannot multiply `max_session_bytes`.
    pub budget: Arc<AtomicU64>,
    /// When the TCP connection was accepted (monotonic).
    pub conn_start: Instant,
}

/// `detail` for a request outside the probe API: status, method, path and
/// user agent, each cut to 200 characters.
pub(crate) fn other_detail<B>(req: &Request<B>, status: u16) -> String {
    let path: String = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .chars()
        .take(200)
        .collect();
    let ua: String = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .chars()
        .take(200)
        .collect();
    format!("{status} {} {path} ua={ua}", req.method())
}

/// Why a request body broke off: the peer went away (FIN or RST) or sent
/// something malformed.
fn abort_code(e: &hyper::Error) -> ErrorCode {
    use std::error::Error as _;
    let mut src = e.source();
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            let c = ErrorCode::from_stream_error(io);
            if c != ErrorCode::Unknown {
                return c;
            }
        }
        if let Some(h2e) = s.downcast_ref::<h2::Error>() {
            if let Some(io) = h2e.get_io() {
                return ErrorCode::from_stream_error(io);
            }
            if h2e.is_reset() || h2e.is_go_away() {
                return ErrorCode::RemoteClosed;
            }
        }
        src = s.source();
    }
    if e.is_incomplete_message() || e.is_closed() || e.is_canceled() {
        ErrorCode::RemoteClosed
    } else {
        ErrorCode::HttpProtocolError
    }
}

/// Takes up to `want` bytes from `budget`; returns how many were granted.
pub(crate) fn take(budget: &AtomicU64, want: u64) -> u64 {
    let mut got = 0;
    let _ = budget.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
        got = left.min(want);
        Some(left - got)
    });
    got
}

impl hyper::service::Service<Request<Incoming>> for Service {
    type Response = Response<RespBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if req.method() == http::Method::POST && req.uri().path() == SESSION_PATH {
            return Box::pin(ready(Ok(self.upload_session(req))));
        }
        Box::pin(ready(Ok(self.route(&req))))
    }
}

pub(crate) fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

fn text(status: StatusCode, s: &'static str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from_static(s.as_bytes())).boxed_unsync())
        .expect("static response is valid")
}

/// Server-side event for one request, keyed by the client's test id when
/// it sent one (header first, then the `test_id` query parameter).
pub(crate) fn request_event<B>(
    server_id: &str,
    peer: SocketAddr,
    req: &Request<B>,
    test_type: TestType,
    transport: Transport,
    alpn: &str,
    conn_start: Instant,
) -> ProbeEvent {
    let test_id = req
        .headers()
        .get(TEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .or_else(|| query_param(req.uri().query(), "test_id"))
        .filter(|s| !s.is_empty() && s.len() <= 64)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("server-{}", ProbeEvent::new_test_id()));
    let mut ev = ProbeEvent::new(
        test_id, server_id, "server", server_id, test_type, transport,
    );
    ev.side = Side::Server;
    ev.peer = Some(peer.to_string());
    ev.alpn = Some(alpn.into());
    ev.since_conn_ms = Some(conn_start.elapsed().as_millis() as u64);
    ev.pair_id = req
        .headers()
        .get(PAIR_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .or_else(|| query_param(req.uri().query(), "pair_id"))
        .filter(|s| !s.is_empty() && s.len() <= 64)
        .map(str::to_owned);
    ev
}

impl Service {
    fn event(&self, req: &Request<Incoming>, test_type: TestType) -> ProbeEvent {
        let alpn = if req.version() == Version::HTTP_2 {
            "h2"
        } else {
            "http/1.1"
        };
        request_event(
            &self.server_id,
            self.peer,
            req,
            test_type,
            Transport::Tcp,
            alpn,
            self.conn_start,
        )
    }

    /// Requests outside the probe API: typos, browsers, scanners. Logged
    /// with method and path so unexpected visitors are visible.
    fn log_other(&self, req: &Request<Incoming>, status: u16) {
        let tt = if req.version() == Version::HTTP_2 {
            TestType::H2Request
        } else {
            TestType::HttpsGet
        };
        let mut ev = self.event(req, tt);
        ev.detail = Some(other_detail(req, status));
        ev.phase = Some(Phase::Completed);
        if self.tx.try_send(ev.succeed()).is_err() {
            tracing::warn!("event queue full, dropped a request event");
        }
    }

    fn log_now(&self, mut ev: ProbeEvent, bytes_sent: u64) {
        ev.bytes_sent = bytes_sent;
        ev.phase = Some(Phase::Completed);
        if self.tx.try_send(ev.succeed()).is_err() {
            tracing::warn!("event queue full, dropped a request event");
        }
    }

    /// Upstream long session: the client sends heartbeats and the server
    /// acknowledges the running byte total on the response stream, so the
    /// client can tell a frozen uplink from a slow one. The response starts
    /// at once; the acknowledgements are the only data sent back.
    fn upload_session(&self, req: Request<Incoming>) -> Response<RespBody> {
        let seconds: u64 = query_param(req.uri().query(), "seconds")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60)
            .clamp(1, self.limits.max_session_seconds);
        let mut ev = self.event(&req, TestType::LongSession);
        ev.direction = Some(Direction::Up);
        let (ack_tx, ack_rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let this = self.clone();
        let body = req.into_body();
        tokio::spawn(async move { this.receive_upload(body, seconds, ev, ack_tx).await });
        Response::builder()
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(ChannelBody::new(ack_rx).boxed_unsync())
            .expect("valid response")
    }

    async fn receive_upload(
        &self,
        mut body: Incoming,
        seconds: u64,
        mut ev: ProbeEvent,
        ack: tokio::sync::mpsc::Sender<Bytes>,
    ) {
        let started = Instant::now();
        let deadline =
            Duration::from_secs(seconds.saturating_add(self.limits.idle_timeout_seconds));
        let mut received = 0u64;
        let mut acked = 0u64;
        let mut last_ack = Instant::now();
        let read = async {
            while let Some(frame) = body.frame().await {
                let frame =
                    frame.map_err(|e| (abort_code(&e), format!("upload broken off: {e}")))?;
                let Some(data) = frame.data_ref() else {
                    continue;
                };
                let n = data.len() as u64;
                received += n;
                if received > self.limits.max_session_bytes || take(&self.budget, n) < n {
                    return Err((
                        ErrorCode::Unknown,
                        "upload exceeded max_session_bytes".to_owned(),
                    ));
                }
                if last_ack.elapsed() >= ACK_EVERY {
                    // A client that stopped reading acks is not waited for.
                    if ack.try_send(Bytes::from(format!("{received}\n"))).is_ok() {
                        acked = received;
                        last_ack = Instant::now();
                    }
                }
            }
            Ok(())
        };
        let outcome = tokio::time::timeout(deadline, read).await;
        let (line, ev) = {
            ev.duration_ms = started.elapsed().as_millis() as u64;
            ev.bytes_received = received;
            ev.bytes_sent = acked;
            ev.phase = Some(if received > 0 {
                Phase::AppDataReceived
            } else {
                Phase::HandshakeDone
            });
            match outcome {
                Ok(Ok(())) if received > 0 => {
                    ev.phase = Some(Phase::Completed);
                    (format!("done {received}\n"), ev.succeed())
                }
                Ok(Ok(())) => (
                    "empty\n".to_owned(),
                    ev.fail(ErrorCode::RemoteClosed, "empty upload"),
                ),
                Ok(Err((code, detail))) => (format!("error {received}\n"), ev.fail(code, detail)),
                Err(_) => (
                    format!("timeout {received}\n"),
                    ev.fail(
                        ErrorCode::ApplicationTimeout,
                        "upload exceeded the session limit",
                    ),
                ),
            }
        };
        if self.tx.try_send(ev).is_err() {
            tracing::warn!("event queue full, dropped an upload event");
        }
        let _ = tokio::time::timeout(ACK_EVERY * 10, ack.send(Bytes::from(line))).await;
    }

    fn route(&self, req: &Request<Incoming>) -> Response<RespBody> {
        if req.method() != http::Method::GET {
            self.log_other(req, 405);
            return text(StatusCode::METHOD_NOT_ALLOWED, "GET only\n");
        }
        let q = req.uri().query();
        match req.uri().path() {
            PROBE_PATH => {
                let tt = if req.version() == Version::HTTP_2 {
                    TestType::H2Request
                } else {
                    TestType::HttpsGet
                };
                self.log_now(self.event(req, tt), PROBE_BODY.len() as u64);
                text(StatusCode::OK, PROBE_BODY)
            }
            ECHO_PATH => {
                self.log_now(self.event(req, TestType::Echo), ECHO_BODY.len() as u64);
                text(StatusCode::OK, ECHO_BODY)
            }
            DOWNLOAD_PATH => {
                let want: u64 = query_param(q, "bytes")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1024 * 1024);
                let bytes = take(&self.budget, want.min(self.limits.max_session_bytes));
                if bytes == 0 && want > 0 {
                    self.log_other(req, 429);
                    return text(
                        StatusCode::TOO_MANY_REQUESTS,
                        "connection byte budget used up\n",
                    );
                }
                let deadline =
                    Instant::now() + Duration::from_secs(self.limits.max_session_seconds);
                let mut ev = self.event(req, TestType::Download);
                ev.direction = Some(Direction::Down);
                let body = GenBody::download(bytes, deadline, (self.tx.clone(), ev));
                Response::builder()
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .header(http::header::CONTENT_LENGTH, bytes)
                    .body(body.boxed_unsync())
                    .expect("valid response")
            }
            SESSION_PATH => {
                let seconds: u64 = query_param(q, "seconds")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60)
                    .clamp(1, self.limits.max_session_seconds);
                let interval_ms: u64 = query_param(q, "interval_ms")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1000)
                    .clamp(100, 60_000);
                let size: usize = query_param(q, "size")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(64);
                let mut ev = self.event(req, TestType::LongSession);
                ev.direction = Some(Direction::Down);
                let body = GenBody::session(
                    size,
                    Duration::from_millis(interval_ms),
                    Instant::now() + Duration::from_secs(seconds),
                    self.budget.clone(),
                    (self.tx.clone(), ev),
                );
                Response::builder()
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .body(body.boxed_unsync())
                    .expect("valid response")
            }
            _ => {
                self.log_other(req, 404);
                text(StatusCode::NOT_FOUND, "not found\n")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::query_param;

    #[test]
    fn parses_query() {
        let q = Some("a=1&bytes=42&test_id=abc");
        assert_eq!(query_param(q, "bytes"), Some("42"));
        assert_eq!(query_param(q, "test_id"), Some("abc"));
        assert_eq!(query_param(q, "missing"), None);
        assert_eq!(query_param(None, "a"), None);
    }
}
