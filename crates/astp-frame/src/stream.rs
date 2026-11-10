//! Read frames from an unstructured byte stream (the TCP profile).
//!
//! [`FrameReader`] owns every byte it has already taken. Dropping
//! [`FrameReader::read_frame`] while it is `Pending` leaves those bytes in
//! the reader. The next call continues the same frame.

use std::fmt;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};

use astp_types::FRAME_HEADER_LEN;
use tokio::io::{AsyncRead, ReadBuf};

use crate::codec::decode_with;
use crate::error::FrameError;
use crate::header::{DecodeLimits, RawHeader};
use crate::types::Frame;

/// Finished payload buffers larger than this are dropped.
///
/// Smaller ones are cleared and kept, so a run of small frames does not
/// allocate on every frame, and an idle connection does not hold the
/// last 64 KiB payload.
const PAYLOAD_RETAIN_MAX: usize = 8 * 1024;

/// Most payload bytes one poll will take from the socket.
///
/// The buffer grows as those bytes arrive. `Length` is not reserved up
/// front.
const PAYLOAD_READ_CHUNK: usize = 4 * 1024;

/// What one step of the read state machine decided.
enum Step {
    /// The state machine moved forward without waiting on the socket.
    Continue,
    /// The socket returned `Pending`. No byte from that poll was kept.
    Wait,
    /// The public read is finished.
    Done(Result<Option<Frame>, FrameError>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// No byte of the next frame is stored.
    Ready,
    /// `header_filled` bytes of the header are stored.
    Header,
    /// `payload_filled` bytes of a payload that passed the length cap
    /// are stored.
    Payload,
    /// A previous read returned `Err`. Do not poll the socket.
    Poisoned,
}

/// Stateful reader of ASTP-M frames from an [`AsyncRead`] byte stream.
///
/// The reader does not look at the next frame until the current header
/// and, when the length cap allows it, the current payload have been
/// taken. `Length` above the active limit is rejected from the 8-byte
/// header, before any payload byte is read. A legal payload is appended
/// as each read completes. The reader does not reserve `Length` bytes
/// when the header arrives.
///
/// # Cancel safety
///
/// [`Self::read_frame`] is cancel-safe. The partial header and the
/// partial payload live in this struct, not in the future. Bytes are
/// copied into that storage only after `poll_read` returns `Ready`.
/// A `Pending` result means that poll consumed nothing: this is the
/// [`AsyncRead`] contract, and a reader that writes into the buffer and
/// then returns `Pending` is not a correct [`AsyncRead`].
///
/// Dropping the future at `Pending` (`select!`, a timeout, or task
/// cancellation) therefore leaves the stored prefix in place. The next
/// [`Self::read_frame`] continues the same frame. It does not start a
/// new header at the socket's current offset. Cancellation itself is
/// not an error and does not poison the reader.
///
/// # Poison
///
/// Any `Err` poisons the reader. That call returns the original error.
/// Every later [`Self::read_frame`] returns [`FrameError::Poisoned`] and
/// does not poll the socket. [`Ok(None)`](Self::read_frame), a clean EOF
/// before the first byte of a frame, does not poison. A session that
/// sees `Err` closes the connection. It does not keep reading frames.
///
/// # Header errors
///
/// Any error taken from the 8-byte header poisons the reader, and the
/// connection must be closed. The payload is not allocated, not read,
/// and not discarded. The cursor stays on the first unread byte after
/// the header (or earlier, if the header itself was short). This reader
/// does not resynchronize, and it does not promise that the cursor is
/// on a later frame boundary.
///
/// `Length` is checked before version and flags. An overlong `Length`
/// is [`FrameError::FrameTooLong`], including when the version is
/// unknown or reserved flags are set. [`FrameError::UnknownVersion`]
/// and [`FrameError::ReservedFlags`] are returned only when `Length`
/// is within the limit, and they are returned as soon as the header
/// is complete. When both the version and the flags are wrong, the
/// version error is the one returned. A `Length` of zero has no
/// payload bytes; the reader is still poisoned.
///
/// # Alignment
///
/// Poison always stops this reader. It does not always leave the socket
/// mid-frame. Here "aligned" means the cursor is on a frame boundary:
/// the next byte would be the first byte of a later frame, or the stream
/// is at EOF. Header errors are not aligned.
///
/// * [`FrameError::FrameTooLong`], [`FrameError::UnknownVersion`], and
///   [`FrameError::ReservedFlags`] never allocate the payload and never
///   read it. The cursor stays immediately after the 8-byte header.
///   Not aligned. The connection must be closed.
/// * [`FrameError::Io`] or [`FrameError::Incomplete`] while the header
///   or the payload is still short: not aligned. Bytes already stored
///   are dropped with the poison. They are not reused as a new header.
/// * [`FrameError::Alloc`] while reserving room for the next payload
///   bytes: not aligned. The first reserve happens before any payload
///   byte is read. A later reserve can fail after some payload bytes
///   are already stored. The reader is poisoned either way.
/// * A body, padding, type, or TLV error after all `8 + Length` bytes
///   have been read: the cursor is aligned, and the reader is still
///   poisoned. The following frame is not parsed.
///
/// # Buffer
///
/// The 8-byte header and the payload bytes that have arrived live in
/// one buffer. [`decode_with`](crate::decode_with) reads that buffer.
/// There is no second copy of the frame.
///
/// When a frame finishes, a buffer whose capacity is above 8 KiB is
/// dropped. A smaller buffer is cleared and kept for the next frame.
/// The same rule runs on poison, so a failed large frame does not stay
/// allocated. Dropping [`Self::read_frame`] at `Pending` does not free
/// a partial payload: those bytes still belong to the current frame.
///
/// One-shot [`crate::decode`] checks version, then flags, then length.
/// That buffer is already in memory, so the order cannot desynchronize
/// a socket.
///
/// # Limits
///
/// The [`DecodeLimits`] value is fixed for the life of the reader. A
/// `CONFIG` TLV `max_frame` is payload. It does not change this limit,
/// including for the frame that carried the TLV. The session applies a
/// new limit by constructing another reader at a frame boundary.
///
/// `reader` follows the [`AsyncRead`] contract: `Ok(0)` is EOF.
pub struct FrameReader<R> {
    reader: R,
    limits: DecodeLimits,
    stage: Stage,
    header: [u8; FRAME_HEADER_LEN],
    header_filled: usize,
    /// Header bytes followed by the payload bytes received so far,
    /// once a payload has been accepted. Empty between frames, aside
    /// from any retained capacity.
    payload: Vec<u8>,
    /// Payload bytes received. Does not count the header prefix.
    payload_filled: usize,
    /// Declared `Length` for the payload in progress.
    payload_expected: usize,
}

impl<R> FrameReader<R> {
    /// Reader with the default payload ceiling of 65535 bytes.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self::with_limits(reader, DecodeLimits::DEFAULT)
    }

    /// Reader with an explicit length ceiling.
    ///
    /// The ceiling used on the wire is
    /// [`DecodeLimits::effective_max`]: `min(limits.max_frame, 65535)`.
    /// It does not change for the life of this reader. A decoded
    /// `max_frame` TLV does not update it.
    #[must_use]
    pub fn with_limits(reader: R, limits: DecodeLimits) -> Self {
        Self {
            reader,
            limits,
            stage: Stage::Ready,
            header: [0; FRAME_HEADER_LEN],
            header_filled: 0,
            payload: Vec::new(),
            payload_filled: 0,
            payload_expected: 0,
        }
    }

    /// Return the inner reader.
    ///
    /// The cursor is wherever the last read left it. See the alignment
    /// rules above. A new [`FrameReader`] wrapped around a cursor that
    /// is not on a frame boundary will not find that boundary again.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// The limits this reader was built with.
    #[must_use]
    pub fn limits(&self) -> DecodeLimits {
        self.limits
    }

    /// `true` after [`Self::read_frame`] has returned `Err`.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        matches!(self.stage, Stage::Poisoned)
    }

    fn poison(&mut self) {
        self.stage = Stage::Poisoned;
        self.header = [0; FRAME_HEADER_LEN];
        self.header_filled = 0;
        self.retain_payload_buf();
    }

    /// Drop a large payload buffer. Keep a small one for the next frame.
    fn retain_payload_buf(&mut self) {
        self.payload_filled = 0;
        self.payload_expected = 0;
        if self.payload.capacity() > PAYLOAD_RETAIN_MAX {
            self.payload = Vec::new();
        } else {
            self.payload.clear();
        }
    }

    fn fail(&mut self, err: FrameError) -> Step {
        self.poison();
        Step::Done(Err(err))
    }

    fn begin_header(&mut self) -> Step {
        self.header = [0; FRAME_HEADER_LEN];
        self.header_filled = 0;
        self.payload_filled = 0;
        self.stage = Stage::Header;
        Step::Continue
    }

    fn accept_header(&mut self) -> Step {
        let header = match RawHeader::parse(&self.header) {
            Ok(header) => header,
            Err(err) => return self.fail(err),
        };
        // Length before version and flags. An overlong claim must not
        // allocate, must not be read, and must not be reported as a
        // version or flag error.
        let length = match header.checked_length(self.limits) {
            Ok(length) => length,
            Err(err) => return self.fail(err),
        };
        match header.version_and_flags() {
            Ok(()) => self.start_payload(length),
            // Do not read the payload. The reader is poisoned and the
            // connection must be closed.
            Err(fault) => self.fail(fault.into_error()),
        }
    }

    fn start_payload(&mut self, length: usize) -> Step {
        self.payload.clear();
        self.payload_filled = 0;
        self.payload_expected = length;
        // Reserve the header plus at most one read chunk, not `Length`.
        let hint = FRAME_HEADER_LEN.saturating_add(length.min(PAYLOAD_READ_CHUNK));
        if self.payload.capacity() < hint {
            let need = hint.saturating_sub(self.payload.len());
            if self.payload.try_reserve_exact(need).is_err() {
                return self.fail(FrameError::Alloc { length: hint });
            }
        }
        self.payload.extend_from_slice(&self.header);
        self.stage = Stage::Payload;
        Step::Continue
    }

    fn take_header_bytes(&mut self, n: usize) -> Step {
        if n == 0 {
            if self.header_filled == 0 {
                self.stage = Stage::Ready;
                return Step::Done(Ok(None));
            }
            return self.fail(FrameError::Incomplete);
        }
        self.header_filled = self.header_filled.saturating_add(n);
        if self.header_filled > FRAME_HEADER_LEN {
            return self.fail(FrameError::Incomplete);
        }
        if self.header_filled == FRAME_HEADER_LEN {
            self.accept_header()
        } else {
            Step::Continue
        }
    }

    fn finish_payload(&mut self) -> Step {
        debug_assert_eq!(
            self.payload.len(),
            FRAME_HEADER_LEN.saturating_add(self.payload_expected)
        );
        // Decode the one buffer. Do not copy it into a second vec.
        let decoded = decode_with(&self.payload, self.limits);
        self.header_filled = 0;
        match decoded {
            Ok(frame) => {
                self.retain_payload_buf();
                self.stage = Stage::Ready;
                Step::Done(Ok(Some(frame)))
            }
            Err(err) => self.fail(err),
        }
    }
}

impl<R> FrameReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Read the next frame.
    ///
    /// `Ok(None)` is a clean EOF before the first byte of a frame. Any
    /// `Err` poisons this reader. The connection must be closed. A
    /// header error does not read the payload; see [`FrameReader`].
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe. Partial header and payload bytes stay in `self`
    /// when the future is dropped at `Pending`. See [`FrameReader`].
    ///
    /// # Errors
    ///
    /// [`FrameError::FrameTooLong`] if `Length` exceeds the limit. The
    /// payload is not allocated and not read, even when the version or
    /// flags are also illegal.
    ///
    /// [`FrameError::UnknownVersion`] or [`FrameError::ReservedFlags`]
    /// once the header is complete and `Length` is within the limit.
    /// The payload is not read.
    ///
    /// [`FrameError::Incomplete`] if EOF arrives after at least one byte
    /// of this frame, or before a declared payload is complete.
    ///
    /// [`FrameError::Io`] if the socket fails mid-frame.
    ///
    /// [`FrameError::Poisoned`] if an earlier read already failed.
    ///
    /// Other parse errors match [`crate::decode`]. They are returned
    /// only after `8 + Length` bytes have been taken.
    ///
    /// ```
    /// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
    /// use std::io::Cursor;
    /// use astp_frame::{encode, Frame, FrameBody, FrameReader};
    /// let frame = Frame { key_epoch: None, body: FrameBody::Padding };
    /// let bytes = encode(&frame, None).unwrap();
    /// let mut reader = FrameReader::new(Cursor::new(bytes));
    /// assert_eq!(reader.read_frame().await.unwrap().unwrap(), frame);
    /// assert!(reader.read_frame().await.unwrap().is_none());
    /// # });
    /// ```
    pub async fn read_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        poll_fn(|cx| self.poll_read_frame(cx)).await
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Frame>, FrameError>> {
        loop {
            // Copy the stage so the arms can borrow `self` mutably.
            let stage = self.stage;
            let step = match stage {
                Stage::Poisoned => return Poll::Ready(Err(FrameError::Poisoned)),
                Stage::Ready => self.begin_header(),
                Stage::Header => self.poll_header(cx),
                Stage::Payload => self.poll_payload(cx),
            };
            match step {
                Step::Continue => {}
                Step::Wait => return Poll::Pending,
                Step::Done(result) => return Poll::Ready(result),
            }
        }
    }

    fn poll_header(&mut self, cx: &mut Context<'_>) -> Step {
        let filled = self.header_filled;
        if filled >= FRAME_HEADER_LEN {
            return self.accept_header();
        }
        match poll_read_some(&mut self.reader, cx, &mut self.header[filled..]) {
            Poll::Pending => Step::Wait,
            Poll::Ready(Err(err)) => self.fail(err),
            Poll::Ready(Ok(n)) => self.take_header_bytes(n),
        }
    }

    fn poll_payload(&mut self, cx: &mut Context<'_>) -> Step {
        if self.payload_filled >= self.payload_expected {
            return self.finish_payload();
        }
        let remaining = self.payload_expected.saturating_sub(self.payload_filled);
        let want = remaining.min(PAYLOAD_READ_CHUNK);
        let start = self.payload.len();
        if self.payload.capacity().saturating_sub(start) < want
            && self.payload.try_reserve(want).is_err()
        {
            return self.fail(FrameError::Alloc { length: want });
        }
        let Some(end) = start.checked_add(want) else {
            return self.fail(FrameError::Alloc { length: want });
        };
        // `try_reserve` already made room, so this resize does not allocate.
        self.payload.resize(end, 0);
        match poll_read_some(&mut self.reader, cx, &mut self.payload[start..]) {
            Poll::Pending => {
                // This poll kept no byte. Drop the spare tail.
                self.payload.truncate(start);
                Step::Wait
            }
            Poll::Ready(Err(err)) => {
                self.payload.truncate(start);
                self.fail(err)
            }
            Poll::Ready(Ok(0)) => {
                self.payload.truncate(start);
                self.fail(FrameError::Incomplete)
            }
            Poll::Ready(Ok(n)) => {
                let Some(kept) = start.checked_add(n) else {
                    self.payload.truncate(start);
                    return self.fail(FrameError::Incomplete);
                };
                self.payload.truncate(kept);
                self.payload_filled = self.payload_filled.saturating_add(n);
                if self.payload_filled >= self.payload_expected {
                    self.finish_payload()
                } else {
                    Step::Continue
                }
            }
        }
    }
}

impl<R> fmt::Debug for FrameReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Header and payload bytes can be a TUN packet. Counts only.
        f.debug_struct("FrameReader")
            .field("limits", &self.limits)
            .field("stage", &self.stage)
            .field("header_filled", &self.header_filled)
            .field("payload_filled", &self.payload_filled)
            .field("payload_expected", &self.payload_expected)
            .field("payload_len", &self.payload.len())
            .field("payload_capacity", &self.payload.capacity())
            .finish_non_exhaustive()
    }
}

/// Pull the next bytes into `buf`.
///
/// `Pending` commits nothing. `Ready(Ok(0))` is EOF. `Ready(Ok(n))` is
/// `n` bytes already written at the front of `buf`.
fn poll_read_some<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<Result<usize, FrameError>>
where
    R: AsyncRead + Unpin,
{
    let mut read_buf = ReadBuf::new(buf);
    match Pin::new(reader).poll_read(cx, &mut read_buf) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameReader, PAYLOAD_RETAIN_MAX};
    use crate::{encode, Frame, FrameBody};

    #[tokio::test]
    async fn large_frame_releases_the_payload_allocation() {
        let big = Frame {
            key_epoch: None,
            body: FrameBody::Disconnect {
                code: 7,
                reason: "x".repeat(60_000),
            },
        };
        let small = Frame {
            key_epoch: None,
            body: FrameBody::Padding,
        };
        let mut bytes = encode(&big, None).unwrap();
        bytes.extend(encode(&small, None).unwrap());
        bytes.extend(encode(&small, None).unwrap());
        let mut frames = FrameReader::new(std::io::Cursor::new(bytes));
        assert_eq!(frames.read_frame().await.unwrap().unwrap(), big);
        assert_eq!(
            frames.payload.capacity(),
            0,
            "an idle reader must not keep a buffer above {PAYLOAD_RETAIN_MAX} bytes"
        );
        assert_eq!(frames.read_frame().await.unwrap().unwrap(), small);
        let kept = frames.payload.capacity();
        assert!(kept > 0, "a small frame should keep its buffer");
        assert!(kept <= PAYLOAD_RETAIN_MAX);
        assert_eq!(frames.read_frame().await.unwrap().unwrap(), small);
        assert_eq!(frames.payload.capacity(), kept);
        assert!(frames.read_frame().await.unwrap().is_none());
        assert!(!frames.is_poisoned());
    }
}
