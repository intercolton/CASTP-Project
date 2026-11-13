//! Byte streams over channels of `Bytes`: what a session reads and writes,
//! whichever HTTP body carries it.

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Chunks in flight between a session and its HTTP stream, per direction.
pub(crate) const CHANNEL_DEPTH: usize = 32;

/// Reads the bytes arriving on a channel; end of channel is EOF.
#[derive(Debug)]
pub struct ByteReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    pending: Bytes,
}

impl ByteReader {
    /// A reader that is already at EOF.
    pub fn closed() -> Self {
        let (_tx, rx) = mpsc::channel(1);
        ByteReader::new(rx)
    }

    pub(crate) fn new(rx: mpsc::Receiver<io::Result<Bytes>>) -> Self {
        ByteReader {
            rx,
            pending: Bytes::new(),
        }
    }
}

impl AsyncRead for ByteReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while self.pending.is_empty() {
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(Some(Ok(b))) => self.pending = b,
            }
        }
        let n = self.pending.len().min(buf.remaining());
        buf.put_slice(&self.pending[..n]);
        self.pending.advance(n);
        Poll::Ready(Ok(()))
    }
}

/// Writes into a channel; shutdown closes it, which ends the HTTP body.
#[derive(Debug)]
pub struct ByteWriter {
    tx: PollSender<Bytes>,
}

impl ByteWriter {
    pub(crate) fn new(tx: mpsc::Sender<Bytes>) -> Self {
        ByteWriter {
            tx: PollSender::new(tx),
        }
    }
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "HTTP stream closed")
}

impl AsyncWrite for ByteWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(gone())),
            Poll::Ready(Ok(())) => {
                let n = data.len().min(64 * 1024);
                self.tx
                    .send_item(Bytes::copy_from_slice(&data[..n]))
                    .map_err(|_| gone())?;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx.close();
        Poll::Ready(Ok(()))
    }
}

/// An HTTP body fed from a channel.
pub(crate) struct ChannelBody(pub(crate) mpsc::Receiver<Bytes>);

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

/// Forwards the data frames of an HTTP body into a channel; errors and
/// the end of the body are forwarded too.
pub(crate) async fn pump_body<B>(mut body: B, tx: mpsc::Sender<io::Result<Bytes>>)
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    while let Some(frame) = body.frame().await {
        let item = match frame {
            Ok(f) => match f.into_data() {
                Ok(d) if d.is_empty() => continue,
                Ok(d) => Ok(d),
                Err(_) => continue,
            },
            Err(e) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                e.to_string(),
            )),
        };
        let stop = item.is_err();
        if tx.send(item).await.is_err() || stop {
            return;
        }
    }
}

/// The two halves of one session stream.
#[derive(Debug)]
pub struct SessionIo {
    pub reader: ByteReader,
    pub writer: ByteWriter,
}

/// Channels for one session: the halves for the session and the ends the
/// transport plugs into its HTTP stream.
pub(crate) fn session_channels() -> (
    SessionIo,
    mpsc::Sender<io::Result<Bytes>>,
    mpsc::Receiver<Bytes>,
) {
    let (in_tx, in_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (out_tx, out_rx) = mpsc::channel(CHANNEL_DEPTH);
    (
        SessionIo {
            reader: ByteReader::new(in_rx),
            writer: ByteWriter::new(out_tx),
        },
        in_tx,
        out_rx,
    )
}
