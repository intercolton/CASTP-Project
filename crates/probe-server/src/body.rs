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
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::time::Interval;

const CHUNK: usize = 16 * 1024;
static FILLER: [u8; CHUNK] = [b'.'; CHUNK];

pub struct GenBody {
    remaining: u64,
    chunk: usize,
    interval: Option<Interval>,
    deadline: Instant,
    sent: u64,
    completed: bool,
    log: Option<(EventTx, ProbeEvent, Instant)>,
}

impl GenBody {
    /// `bytes` in chunks as fast as the connection takes them.
    pub fn download(bytes: u64, deadline: Instant, log: (EventTx, ProbeEvent)) -> Self {
        GenBody {
            remaining: bytes,
            chunk: CHUNK,
            interval: None,
            deadline,
            sent: 0,
            completed: false,
            log: Some((log.0, log.1, Instant::now())),
        }
    }

    /// `size`-byte heartbeats every `period` until `deadline` or `max_bytes`.
    pub fn session(
        size: usize,
        period: std::time::Duration,
        deadline: Instant,
        max_bytes: u64,
        log: (EventTx, ProbeEvent),
    ) -> Self {
        let mut iv = tokio::time::interval(period);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        GenBody {
            remaining: max_bytes,
            chunk: size.clamp(1, CHUNK),
            interval: Some(iv),
            deadline,
            sent: 0,
            completed: false,
            log: Some((log.0, log.1, Instant::now())),
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
        if self.completed {
            return Poll::Ready(None);
        }
        if let Some(iv) = self.interval.as_mut() {
            if iv.poll_tick(cx).is_pending() {
                return Poll::Pending;
            }
        }
        if self.remaining == 0 || Instant::now() >= self.deadline {
            self.completed = true;
            return Poll::Ready(None);
        }
        let n = (self.chunk as u64).min(self.remaining) as usize;
        self.remaining -= n as u64;
        self.sent += n as u64;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&FILLER[..n])))))
    }

    fn is_end_stream(&self) -> bool {
        self.completed
    }

    fn size_hint(&self) -> SizeHint {
        if self.interval.is_none() {
            SizeHint::with_exact(self.remaining)
        } else {
            SizeHint::default()
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
        ev.phase = Some(if self.completed {
            Phase::Completed
        } else if self.sent > 0 {
            Phase::AppDataSent
        } else {
            Phase::HandshakeDone
        });
        let ev = if self.completed {
            ev.succeed()
        } else {
            ev.fail(
                ErrorCode::RemoteClosed,
                format!("client went away after {} B", self.sent),
            )
        };
        // Drop cannot await; if the log queue is full the event is lost and
        // that is reported instead of blocking the runtime.
        if tx.try_send(ev).is_err() {
            tracing::warn!("event queue full, dropped a session event");
        }
    }
}
