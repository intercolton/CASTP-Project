//! A stream wrapper counting raw bytes in each direction, so events report
//! what actually crossed the socket (TLS overhead included).

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Byte counters shared between a stream and the code reporting on it.
#[derive(Debug, Default, Clone)]
pub struct Counters {
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
}

impl Counters {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

/// Wraps a stream and counts raw bytes read and written (TLS overhead included).
pub struct Counting<S> {
    inner: S,
    counters: Counters,
}

impl<S> Counting<S> {
    pub fn new(inner: S) -> (Self, Counters) {
        let counters = Counters::default();
        (
            Counting {
                inner,
                counters: counters.clone(),
            },
            counters,
        )
    }

    /// Adds to existing counters, so several streams can share one total.
    pub fn with_counters(inner: S, counters: Counters) -> Self {
        Counting { inner, counters }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.counters
            .received
            .fetch_add(n as u64, Ordering::Relaxed);
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            self.counters.sent.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
