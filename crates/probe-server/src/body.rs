//! Generated response bodies for `/download` and `/session`.
//!
//! The body logs its own event when it is dropped, so the server records
//! how many bytes really went out and whether the client stayed to the end —
//! a mid-session disconnect is visible on the server side too.

use crate::EventTx;
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use probe_common::{ErrorCode, Phase, ProbeEvent};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::time::Interval;

const CHUNK: usize = 16 * 1024;
static FILLER: [u8; CHUNK] = [b'.'; CHUNK];

/// Why a body stopped producing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// Download: every promised byte went out.
    Complete,
    /// The time limit ran out first. Normal for a session, a failure for a
    /// download (the client got less than `Content-Length`).
    Deadline,
    /// Session: the byte cap ran out before the requested length.
    ByteCap,
}

pub struct GenBody {
    remaining: u64,
    total: u64,
    chunk: usize,
    /// Session only: the connection's shared byte budget, drawn per chunk.
    budget: Option<Arc<AtomicU64>>,
    /// `Some` for a session (heartbeats), `None` for a download.
    interval: Option<Interval>,
    deadline: Instant,
    sent: u64,
    ended: Option<Ended>,
    log: Option<(EventTx, ProbeEvent, Instant)>,
}

impl GenBody {
    /// `bytes` in chunks as fast as the connection takes them.
    pub fn download(bytes: u64, deadline: Instant, log: (EventTx, ProbeEvent)) -> Self {
        GenBody {
            remaining: bytes,
            total: bytes,
            chunk: CHUNK,
            budget: None,
            interval: None,
            deadline,
            sent: 0,
            ended: None,
            log: Some((log.0, log.1, Instant::now())),
        }
    }

    /// `size`-byte heartbeats every `period` until `deadline` or until the
    /// connection's byte `budget` runs out.
    pub fn session(
        size: usize,
        period: std::time::Duration,
        deadline: Instant,
        budget: Arc<AtomicU64>,
        log: (EventTx, ProbeEvent),
    ) -> Self {
        let mut iv = tokio::time::interval(period);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        GenBody {
            remaining: u64::MAX,
            total: 0,
            chunk: size.clamp(1, CHUNK),
            budget: Some(budget),
            interval: Some(iv),
            deadline,
            sent: 0,
            ended: None,
            log: Some((log.0, log.1, Instant::now())),
        }
    }

    fn is_session(&self) -> bool {
        self.interval.is_some()
    }

    /// Whether the body is finished, and why.
    fn check_end(&self) -> Option<Ended> {
        let late = Instant::now() >= self.deadline;
        match (self.is_session(), self.remaining == 0, late) {
            (false, true, _) => Some(Ended::Complete),
            (true, _, true) | (false, false, true) => Some(Ended::Deadline),
            (true, true, false) => Some(Ended::ByteCap),
            (_, false, false) => None,
        }
    }
}

impl Body for GenBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.ended.is_some() {
            return Poll::Ready(None);
        }
        if let Some(iv) = self.interval.as_mut() {
            if iv.poll_tick(cx).is_pending() {
                return Poll::Pending;
            }
        }
        if let Some(end) = self.check_end() {
            self.ended = Some(end);
            return Poll::Ready(None);
        }
        let mut n = (self.chunk as u64).min(self.remaining);
        if let Some(b) = &self.budget {
            n = crate::handler::take(b, n);
            if n == 0 {
                self.ended = Some(Ended::ByteCap);
                return Poll::Ready(None);
            }
        }
        let n = n as usize;
        self.remaining -= n as u64;
        self.sent += n as u64;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&FILLER[..n])))))
    }

    fn is_end_stream(&self) -> bool {
        self.ended.is_some()
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_session() {
            SizeHint::default()
        } else {
            SizeHint::with_exact(self.remaining)
        }
    }
}

impl Drop for GenBody {
    fn drop(&mut self) {
        let Some((tx, mut ev, start)) = self.log.take() else {
            return;
        };
        ev.duration_ms = start.elapsed().as_millis() as u64;
        ev.bytes_sent = self.sent;
        ev.phase = Some(match self.ended {
            Some(Ended::Complete | Ended::ByteCap) => Phase::Completed,
            Some(Ended::Deadline) if self.is_session() => Phase::Completed,
            _ if self.sent > 0 => Phase::AppDataSent,
            _ => Phase::HandshakeDone,
        });
        let ev = match self.ended {
            Some(Ended::Complete) => ev.succeed(),
            Some(Ended::Deadline) if self.is_session() => ev.succeed(),
            Some(Ended::Deadline) => {
                let secs = start.elapsed().as_secs();
                ev.fail(
                    ErrorCode::ApplicationTimeout,
                    format!(
                        "download cut at the {secs} s session limit: {} of {} B sent",
                        self.sent, self.total
                    ),
                )
            }
            Some(Ended::ByteCap) => {
                ev.detail = Some(format!(
                    "ended early: connection byte budget (max_session_bytes) used up after {} B",
                    self.sent
                ));
                ev.succeed()
            }
            None => ev.fail(
                ErrorCode::RemoteClosed,
                format!("client went away after {} B", self.sent),
            ),
        };
        // Drop cannot await; if the log queue is full the event is lost and
        // that is reported instead of blocking the runtime.
        if tx.try_send(ev).is_err() {
            tracing::warn!("event queue full, dropped a session event");
        }
    }
}

/// A response body fed line by line from a task (upload acknowledgements).
pub struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl ChannelBody {
    pub fn new(rx: tokio::sync::mpsc::Receiver<Bytes>) -> Self {
        ChannelBody { rx }
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.rx.poll_recv(cx).map(|b| b.map(|b| Ok(Frame::data(b))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use probe_common::{TestType, Transport};
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn log() -> ((EventTx, ProbeEvent), mpsc::Receiver<ProbeEvent>) {
        let (tx, rx) = mpsc::channel(4);
        let ev = ProbeEvent::new("t", "s", "server", "s", TestType::Download, Transport::Tcp);
        ((tx, ev), rx)
    }

    async fn drain(mut b: GenBody) -> u64 {
        let mut n = 0;
        while let Some(f) = b.frame().await {
            n += f.unwrap().into_data().map(|d| d.len() as u64).unwrap_or(0);
        }
        n
    }

    #[tokio::test]
    async fn full_download_is_a_success() {
        let (l, mut rx) = log();
        let b = GenBody::download(40_000, Instant::now() + Duration::from_secs(5), l);
        assert_eq!(drain(b).await, 40_000);
        let ev = rx.recv().await.unwrap();
        assert!(ev.success, "{ev:?}");
        assert_eq!(ev.phase, Some(Phase::Completed));
        assert_eq!(ev.bytes_sent, 40_000);
    }

    #[tokio::test]
    async fn download_cut_by_the_deadline_is_a_failure() {
        let (l, mut rx) = log();
        let b = GenBody::download(40_000, Instant::now(), l);
        assert_eq!(drain(b).await, 0);
        let ev = rx.recv().await.unwrap();
        assert!(!ev.success, "{ev:?}");
        assert_eq!(ev.error_code, Some(ErrorCode::ApplicationTimeout));
        assert!(
            ev.detail.as_deref().unwrap().contains("0 of 40000 B"),
            "{ev:?}"
        );
    }

    #[tokio::test]
    async fn session_deadline_is_normal_and_byte_cap_is_noted() {
        let (l, mut rx) = log();
        let b = GenBody::session(
            10,
            Duration::from_millis(1),
            Instant::now() + Duration::from_millis(30),
            Arc::new(AtomicU64::new(1_000_000)),
            l,
        );
        drain(b).await;
        let ev = rx.recv().await.unwrap();
        assert!(ev.success, "{ev:?}");
        assert_eq!(ev.detail, None);

        let (l, mut rx) = log();
        let b = GenBody::session(
            10,
            Duration::from_millis(1),
            Instant::now() + Duration::from_secs(60),
            Arc::new(AtomicU64::new(25)),
            l,
        );
        assert_eq!(drain(b).await, 25);
        let ev = rx.recv().await.unwrap();
        assert!(ev.success, "{ev:?}");
        assert!(ev.detail.as_deref().unwrap().contains("max_session_bytes"));
    }
}
