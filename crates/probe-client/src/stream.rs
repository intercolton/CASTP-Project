//! Streaming tests over TLS + HTTP/2 (spec 6.1, long sessions): a bulk
//! download and a long session of periodic heartbeats from the server.
//!
//! Both watch the gap between data frames. A connection that silently stops
//! delivering ("freeze") is reported as `application_timeout` with how many
//! bytes and seconds it lasted; one that is torn down is `tcp_reset` or
//! `remote_closed`. The difference is the point of the test.

use crate::netutil::Failure;
use crate::probes::{http_failure, Attempt, Ctx, TEST_ID_HEADER};
use crate::tlsutil::{self, TLS_STACK};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use probe_common::config::TargetConfig;
use probe_common::{ErrorCode, Phase, ProbeEvent, TestType, Transport};
use std::time::{Duration, Instant};

pub const DOWNLOAD_PATH: &str = "/download";
pub const SESSION_PATH: &str = "/session";

/// Parameters of a long session; the server sends `size` bytes every
/// `interval_ms` for `seconds`.
#[derive(Debug, Clone, Copy)]
pub struct SessionPlan {
    pub seconds: u64,
    pub interval_ms: u64,
    pub size: usize,
    /// No data for this long counts as a freeze.
    pub stall_seconds: u64,
}

impl Default for SessionPlan {
    fn default() -> Self {
        SessionPlan {
            seconds: 300,
            interval_ms: 1000,
            size: 1024,
            stall_seconds: 15,
        }
    }
}

/// How a stream ended, measured from the moment the request went out.
struct Flow {
    bytes: u64,
    started: Instant,
    last_frame: Instant,
    max_gap: Duration,
}

impl Flow {
    fn new() -> Self {
        let now = Instant::now();
        Flow {
            bytes: 0,
            started: now,
            last_frame: now,
            max_gap: Duration::ZERO,
        }
    }

    fn at(&self) -> String {
        format!(
            "{} B after {:.1} s",
            self.bytes,
            self.started.elapsed().as_secs_f64()
        )
    }

    fn summary(&self) -> String {
        let secs = self.started.elapsed().as_secs_f64();
        let kbit = if secs > 0.0 {
            self.bytes as f64 * 8.0 / 1000.0 / secs
        } else {
            0.0
        };
        format!(
            "{} B in {:.1} s ({:.0} kbit/s), max gap {} ms",
            self.bytes,
            secs,
            kbit,
            self.max_gap.as_millis()
        )
    }
}

pub async fn download(ctx: &Ctx, t: &TargetConfig, bytes: u64) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::Download, Transport::Tcp);
    a.ev.tls_stack = Some(TLS_STACK.into());
    let bytes = bytes.min(ctx.limits.max_test_bytes);
    let path = format!("{DOWNLOAD_PATH}?bytes={bytes}&test_id={}", a.ev.test_id);
    let stall = Duration::from_secs(10);
    // Generous ceiling: even 64 kbit/s finishes 1 MiB in about two minutes.
    let limit = ctx.request_timeout() + Duration::from_secs(bytes / 8_000 + 30);
    let r = stream(&mut a, ctx, t, &path, stall, limit, |_| {}).await;
    let r = r.and_then(|flow| {
        if flow.bytes == bytes {
            Ok(Some(flow.summary()))
        } else {
            Err(Failure::new(
                ErrorCode::RemoteClosed,
                format!("stream ended early: {} of {bytes} B", flow.bytes),
            ))
        }
    });
    a.finish(r)
}

/// `progress` is called about every 30 s with seconds elapsed and bytes so far.
pub async fn long_session(
    ctx: &Ctx,
    t: &TargetConfig,
    plan: SessionPlan,
    mut progress: impl FnMut(u64, u64),
) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::LongSession, Transport::Tcp);
    a.ev.tls_stack = Some(TLS_STACK.into());
    let path = format!(
        "{SESSION_PATH}?seconds={}&interval_ms={}&size={}&test_id={}",
        plan.seconds, plan.interval_ms, plan.size, a.ev.test_id
    );
    let stall = Duration::from_secs(plan.stall_seconds);
    let limit = Duration::from_secs(plan.seconds + 60);
    let mut next_report = 30;
    let r = stream(&mut a, ctx, t, &path, stall, limit, |flow| {
        let secs = flow.started.elapsed().as_secs();
        if secs >= next_report {
            progress(secs, flow.bytes);
            next_report = secs + 30;
        }
    })
    .await;
    let r = r.and_then(|flow| {
        // The server may cap the session below what was asked; within two
        // intervals of the requested length counts as the full session.
        let lasted = flow.started.elapsed();
        let want = Duration::from_secs(plan.seconds)
            .saturating_sub(Duration::from_millis(2 * plan.interval_ms));
        if lasted >= want {
            Ok(Some(flow.summary()))
        } else {
            Err(Failure::new(
                ErrorCode::RemoteClosed,
                format!(
                    "server ended the session early: {} (asked {} s)",
                    flow.at(),
                    plan.seconds
                ),
            ))
        }
    });
    a.finish(r)
}

/// TLS + HTTP/2 GET of `path`, reading the body frame by frame.
async fn stream(
    a: &mut Attempt,
    ctx: &Ctx,
    t: &TargetConfig,
    path: &str,
    stall: Duration,
    limit: Duration,
    mut on_frame: impl FnMut(&Flow),
) -> Result<Flow, Failure> {
    let io = a.open(ctx, &t.host, t.port).await?;
    let cfg = tlsutil::client_config(t.ca_file.as_deref(), &[b"h2"], false)?;
    let ts = Instant::now();
    let hs = tlsutil::handshake(cfg, t.server_name(), io, ctx.tls_timeout()).await?;
    a.ev.handshake_ms = Some(ts.elapsed().as_millis() as u64);
    a.ev.alpn = hs.alpn.clone();
    a.reached(Phase::HandshakeDone);
    if hs.alpn.as_deref() != Some("h2") {
        return Err(Failure::new(
            ErrorCode::HttpProtocolError,
            format!("server did not negotiate h2 via ALPN (got {:?})", hs.alpn),
        ));
    }

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(hs.stream))
            .await
            .map_err(http_failure)?;
    let conn = tokio::spawn(conn);
    let authority = if t.port == 443 {
        t.server_name().to_owned()
    } else {
        format!("{}:{}", t.server_name(), t.port)
    };
    let req = http::Request::get(format!("https://{authority}{path}"))
        .header(TEST_ID_HEADER, &a.ev.test_id)
        .header(http::header::USER_AGENT, "astp-probe/0.1")
        .body(Empty::<Bytes>::new())
        .map_err(|e| Failure::new(ErrorCode::Unknown, e.to_string()))?;
    a.reached(Phase::AppDataSent);

    let mut flow = Flow::new();
    let deadline = tokio::time::Instant::now() + limit;
    let result = async {
        let resp = match tokio::time::timeout(ctx.request_timeout(), sender.send_request(req)).await
        {
            Err(_) => {
                return Err(Failure::new(
                    ErrorCode::ApplicationTimeout,
                    format!(
                        "no response headers within {}s",
                        ctx.request_timeout().as_secs()
                    ),
                ))
            }
            Ok(r) => r.map_err(http_failure)?,
        };
        a.reached(Phase::AppDataReceived);
        if !resp.status().is_success() {
            return Err(Failure::new(
                ErrorCode::HttpProtocolError,
                format!("HTTP status {}", resp.status()),
            ));
        }
        let mut body = resp.into_body();
        flow.last_frame = Instant::now();
        loop {
            let wait = stall.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            match tokio::time::timeout(wait, body.frame()).await {
                Err(_) if tokio::time::Instant::now() >= deadline => {
                    return Err(Failure::new(
                        ErrorCode::ApplicationTimeout,
                        format!(
                            "still running after the {} s limit: {}",
                            limit.as_secs(),
                            flow.at()
                        ),
                    ))
                }
                Err(_) => {
                    return Err(Failure::new(
                        ErrorCode::ApplicationTimeout,
                        format!(
                            "stalled: no data for {} s at {}",
                            stall.as_secs(),
                            flow.at()
                        ),
                    ))
                }
                Ok(None) => return Ok(()),
                Ok(Some(Err(e))) => {
                    let f = http_failure(e);
                    return Err(Failure::new(
                        f.code,
                        format!("{} at {}", f.detail, flow.at()),
                    ));
                }
                Ok(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        let now = Instant::now();
                        flow.max_gap = flow.max_gap.max(now - flow.last_frame);
                        flow.last_frame = now;
                        flow.bytes += data.len() as u64;
                        on_frame(&flow);
                    }
                }
            }
        }
    }
    .await;
    conn.abort();
    a.ev.bytes_received = flow.bytes;
    result?;
    a.reached(Phase::Completed);
    Ok(flow)
}
