//! HTTP endpoints (spec 4.2). Every request is logged with the client's
//! test id so the analyzer can join client and server views of one test.
//!
//! - `GET /probe`                       short control answer
//! - `GET /echo`                        tiny answer for application RTT
//! - `GET /download?bytes=N`            N bytes, capped by the server limit
//! - `GET /session?seconds=S&interval_ms=I&size=B` heartbeats for a long session

use crate::body::GenBody;
use crate::EventTx;
use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::Incoming;
use probe_common::config::ServerLimitsSection;
use probe_common::{Phase, ProbeEvent, Side, TestType, Transport};
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
            let this = self.clone();
            return Box::pin(async move { Ok(this.upload_session(req).await) });
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
        ev.detail = Some(format!("{status} {} {path} ua={ua}", req.method()));
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

    /// Upstream long session: the client sends heartbeats, the server counts
    /// them and answers with the byte total. This is the opposite direction
    /// of `GET /session` and is not run at the same time by the scheduler.
    async fn upload_session(&self, req: Request<Incoming>) -> Response<RespBody> {
        let q = req.uri().query().map(str::to_owned);
        let seconds: u64 = query_param(q.as_deref(), "seconds")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60)
            .clamp(1, self.limits.max_session_seconds);
        let mut ev = self.event(&req, TestType::LongSession);
        ev.detail = Some("direction=up".into());
        let started = Instant::now();
        let deadline =
            Duration::from_secs(seconds.saturating_add(self.limits.idle_timeout_seconds));
        let mut received = 0u64;
        let mut body = req.into_body();
        let read = async {
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|e| e.to_string())?;
                if let Some(data) = frame.data_ref() {
                    let n = data.len() as u64;
                    received += n;
                    if received > self.limits.max_session_bytes {
                        return Err("upload exceeded max_session_bytes".into());
                    }
                    if take(&self.budget, n) < n {
                        return Err("upload exceeded the connection byte budget".into());
                    }
                }
            }
            Ok::<(), String>(())
        };
        let outcome = tokio::time::timeout(deadline, read).await;
        ev.duration_ms = started.elapsed().as_millis() as u64;
        ev.bytes_received = received;
        ev.phase = Some(if received > 0 {
            Phase::AppDataReceived
        } else {
            Phase::HandshakeDone
        });
        let (status, msg, ev) = match outcome {
            Ok(Ok(())) if received > 0 => (StatusCode::OK, format!("{received}\n"), ev.succeed()),
            Ok(Ok(())) => (
                StatusCode::BAD_REQUEST,
                "empty upload\n".into(),
                ev.fail(probe_common::ErrorCode::RemoteClosed, "empty upload"),
            ),
            Ok(Err(detail)) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "limit\n".into(),
                ev.fail(probe_common::ErrorCode::Unknown, detail),
            ),
            Err(_) => (
                StatusCode::REQUEST_TIMEOUT,
                "timeout\n".into(),
                ev.fail(
                    probe_common::ErrorCode::ApplicationTimeout,
                    "upload exceeded the session limit",
                ),
            ),
        };
        if self.tx.try_send(ev).is_err() {
            tracing::warn!("event queue full, dropped an upload event");
        }
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(msg)).boxed_unsync())
            .expect("valid response")
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
                let ev = self.event(req, TestType::Download);
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
                let ev = self.event(req, TestType::LongSession);
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
