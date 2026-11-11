//! Streaming tests over TLS + HTTP/2 (spec 6.1, long sessions): a bulk
//! download, a long session of periodic heartbeats from the server, and its
//! mirror image, an upload session of heartbeats to the server.
//!
//! Both watch the gap between data frames. A connection that silently stops
//! delivering ("freeze") is reported as `application_timeout` with how many
//! bytes and seconds it lasted; one that is torn down is `tcp_reset` or
//! `remote_closed`. The difference is the point of the test.

use crate::netutil::Failure;
use crate::probes::{http_failure, Attempt, Ctx, PAIR_ID_HEADER, TEST_ID_HEADER};
use crate::tlsutil::{self, TLS_STACK};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Frame};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use probe_common::config::TargetConfig;
use probe_common::{Direction, ErrorCode, Phase, ProbeEvent, TestType, Transport};
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

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

impl SessionPlan {
    /// Rejects plans whose result would be meaningless: a freeze threshold
    /// shorter than two heartbeat intervals reports every pause as a
    /// freeze, and a zero threshold times out at once.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=3600).contains(&self.seconds) {
            return Err("long session length must be within 1..=3600 s".into());
        }
        if !(100..=60_000).contains(&self.interval_ms) {
            return Err("heartbeat interval must be within 100..=60000 ms".into());
        }
        if self.stall_seconds == 0 {
            return Err("freeze threshold (--stall-seconds) must be >= 1 s".into());
        }
        if self.stall_seconds.saturating_mul(1000) < self.interval_ms.saturating_mul(2) {
            return Err(format!(
                "freeze threshold {} s is shorter than two heartbeat intervals ({} ms): every pause would count as a freeze",
                self.stall_seconds,
                2 * self.interval_ms
            ));
        }
        Ok(())
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
    a.ev.direction = Some(Direction::Down);
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
    a.ev.direction = Some(Direction::Down);
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

/// TLS + HTTP/2 to `t`, checking that h2 was negotiated. The connection
/// task is returned so the caller can stop it.
async fn open_h2<B>(
    a: &mut Attempt,
    ctx: &Ctx,
    t: &TargetConfig,
) -> Result<(SendRequest<B>, tokio::task::JoinHandle<()>), Failure>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
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
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(hs.stream))
            .await
            .map_err(http_failure)?;
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok((sender, conn))
}

/// A request to `path` on `t` carrying the test and pair ids.
fn request(
    a: &Attempt,
    t: &TargetConfig,
    method: http::Method,
    path: &str,
) -> http::request::Builder {
    let authority = crate::probes::authority(t.server_name(), t.port);
    let mut b = http::Request::builder()
        .method(method)
        .uri(format!("https://{authority}{path}"))
        .header(TEST_ID_HEADER, &a.ev.test_id)
        .header(http::header::USER_AGENT, "astp-probe/0.1");
    if let Some(p) = &a.ev.pair_id {
        b = b.header(PAIR_ID_HEADER, p);
    }
    b
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
    let (mut sender, conn) = open_h2(a, ctx, t).await?;
    let req = request(a, t, http::Method::GET, path)
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

/// Request body fed from a channel: one heartbeat per message.
struct ChannelBody(mpsc::Receiver<Bytes>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|b| b.map(|b| Ok(Frame::data(b))))
    }
}

/// Upload session: `size` bytes every `interval_ms` for `seconds` to
/// `POST /session`. The server acknowledges the running total on the
/// response stream; no acknowledgement progress for `stall_seconds` while
/// data is outstanding is a freeze of the uplink, reported like a download
/// freeze. `progress(seconds, bytes acknowledged)` is called about every 30 s.
pub async fn upload_session(
    ctx: &Ctx,
    t: &TargetConfig,
    plan: SessionPlan,
    mut progress: impl FnMut(u64, u64),
) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::LongSession, Transport::Tcp);
    a.ev.tls_stack = Some(TLS_STACK.into());
    a.ev.direction = Some(Direction::Up);
    let path = format!(
        "{SESSION_PATH}?seconds={}&test_id={}",
        plan.seconds, a.ev.test_id
    );
    let r = upload(&mut a, ctx, t, &path, plan, &mut progress).await;
    a.finish(r.map(Some))
}

/// What the server has acknowledged of an upload.
struct Acks {
    sent: u64,
    acked: u64,
    started: Instant,
    last_ack: Instant,
    max_gap: Duration,
    /// Since when data has been waiting for an acknowledgement.
    waiting_since: Option<Instant>,
}

impl Acks {
    fn at(&self) -> String {
        format!(
            "{} B sent, {} B acknowledged after {:.1} s",
            self.sent,
            self.acked,
            self.started.elapsed().as_secs_f64()
        )
    }

    fn ack(&mut self, n: u64) {
        if n <= self.acked {
            return;
        }
        let now = Instant::now();
        self.max_gap = self.max_gap.max(now - self.last_ack);
        self.last_ack = now;
        self.acked = n;
        self.waiting_since = (self.acked < self.sent).then_some(now);
    }
}

async fn upload(
    a: &mut Attempt,
    ctx: &Ctx,
    t: &TargetConfig,
    path: &str,
    plan: SessionPlan,
    progress: &mut impl FnMut(u64, u64),
) -> Result<String, Failure> {
    let (mut sender, conn) = open_h2::<ChannelBody>(a, ctx, t).await?;
    let (tx, rx) = mpsc::channel::<Bytes>(4);
    let req = request(a, t, http::Method::POST, path)
        .body(ChannelBody(rx))
        .map_err(|e| Failure::new(ErrorCode::Unknown, e.to_string()))?;
    a.reached(Phase::AppDataSent);

    let r = async {
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
        let stall = Duration::from_secs(plan.stall_seconds);
        let chunk = Bytes::from(vec![b'.'; plan.size.max(1)]);
        let now = Instant::now();
        let mut acks = Acks {
            sent: 0,
            acked: 0,
            started: now,
            last_ack: now,
            max_gap: Duration::ZERO,
            waiting_since: None,
        };
        let send_until = tokio::time::Instant::now() + Duration::from_secs(plan.seconds);
        let hard_limit = send_until + Duration::from_secs(60);
        let mut tick = tokio::time::interval(Duration::from_millis(plan.interval_ms.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tx = Some(tx);
        let mut lines = Vec::new();
        let mut next_report = 30;
        let total = loop {
            let stall_at = acks
                .waiting_since
                .map(|w| tokio::time::Instant::from_std(w) + stall);
            tokio::select! {
                _ = tick.tick(), if tx.is_some() => {
                    if tokio::time::Instant::now() >= send_until {
                        // End of the request body: the server answers with its total.
                        tx = None;
                        continue;
                    }
                    let Some(t) = tx.as_ref() else { continue };
                    match t.try_send(chunk.clone()) {
                        Ok(()) => {
                            acks.sent += chunk.len() as u64;
                            acks.waiting_since.get_or_insert_with(Instant::now);
                        }
                        // Not even queued: the connection takes nothing. The
                        // freeze detector reports it if it lasts.
                        Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            return Err(Failure::new(
                                ErrorCode::RemoteClosed,
                                format!("request stream closed at {}", acks.at()),
                            ));
                        }
                    }
                }
                frame = body.frame() => match frame {
                    None => break None,
                    Some(Err(e)) => {
                        let f = http_failure(e);
                        return Err(Failure::new(f.code, format!("{} at {}", f.detail, acks.at())));
                    }
                    Some(Ok(frame)) => {
                        let Some(data) = frame.data_ref() else { continue };
                        lines.extend_from_slice(data);
                        while let Some(i) = lines.iter().position(|&b| b == b'\n') {
                            let line: Vec<u8> = lines.drain(..=i).collect();
                            let line = String::from_utf8_lossy(&line).trim().to_owned();
                            match ack_line(&line) {
                                AckLine::Progress(n) => acks.ack(n),
                                AckLine::Done(n) => {
                                    acks.ack(n);
                                    lines.clear();
                                    break;
                                }
                                AckLine::Failed(msg) => {
                                    return Err(Failure::new(
                                        if msg.starts_with("timeout") {
                                            ErrorCode::ApplicationTimeout
                                        } else {
                                            ErrorCode::HttpProtocolError
                                        },
                                        format!("server ended the upload: {msg} at {}", acks.at()),
                                    ));
                                }
                            }
                        }
                        let secs = acks.started.elapsed().as_secs();
                        if secs >= next_report {
                            progress(secs, acks.acked);
                            next_report = secs + 30;
                        }
                        if tx.is_none() && acks.acked >= acks.sent && acks.sent > 0 {
                            // Body done and everything acknowledged.
                            break Some(acks.acked);
                        }
                    }
                },
                _ = tokio::time::sleep_until(stall_at.unwrap_or(hard_limit)), if stall_at.is_some() => {
                    return Err(Failure::new(
                        ErrorCode::ApplicationTimeout,
                        format!(
                            "stalled: no acknowledgement for {} s at {}",
                            stall.as_secs(),
                            acks.at()
                        ),
                    ));
                }
                _ = tokio::time::sleep_until(hard_limit) => {
                    return Err(Failure::new(
                        ErrorCode::ApplicationTimeout,
                        format!("still running after the session limit: {}", acks.at()),
                    ));
                }
            }
        };
        match total {
            Some(n) if n == acks.sent => Ok(format!(
                "{} B in {:.1} s, max ack gap {} ms",
                n,
                acks.started.elapsed().as_secs_f64(),
                acks.max_gap.as_millis()
            )),
            _ => Err(Failure::new(
                ErrorCode::RemoteClosed,
                format!("upload ended without a full acknowledgement: {}", acks.at()),
            )),
        }
    }
    .await;
    conn.abort();
    if r.is_ok() {
        a.reached(Phase::Completed);
    }
    r
}

enum AckLine {
    Progress(u64),
    Done(u64),
    Failed(String),
}

/// `<n>` is progress, `done <n>` the final total, anything else the
/// server's reason for ending the upload.
fn ack_line(line: &str) -> AckLine {
    if let Ok(n) = line.parse() {
        return AckLine::Progress(n);
    }
    match line.strip_prefix("done ").map(str::parse) {
        Some(Ok(n)) => AckLine::Done(n),
        _ => AckLine::Failed(line.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::SessionPlan;

    #[test]
    fn plan_check() {
        let ok = SessionPlan::default();
        ok.check().unwrap();
        for bad in [
            SessionPlan {
                stall_seconds: 0,
                ..ok
            },
            SessionPlan {
                stall_seconds: 1,
                interval_ms: 1000,
                ..ok
            },
            SessionPlan { seconds: 0, ..ok },
            SessionPlan {
                seconds: 3601,
                ..ok
            },
            SessionPlan {
                interval_ms: 50,
                ..ok
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        SessionPlan {
            stall_seconds: 2,
            interval_ms: 1000,
            ..ok
        }
        .check()
        .unwrap();
    }
}
