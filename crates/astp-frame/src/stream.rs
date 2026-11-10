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
use crate::header::{DecodeLimits, HeaderFault, RawHeader};
use crate::types::Frame;

/// Scratch size for discarding a payload that will not be decoded.
///
/// The discarded bytes are not stored. A legal frame is at most 65535
/// bytes, so this only bounds how much one poll pulls.
const DISCARD_CHUNK: usize = 512;

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
    /// `Length` is legal and the header is not. Discard the payload,
    /// then return this fault.
    Discard(HeaderFault),
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
/// header, before the payload is allocated or read.
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
/// # Alignment
///
/// Poison always stops this reader. It does not always leave the socket
/// mid-frame. Here "aligned" means the cursor is on a frame boundary:
/// the next byte would be the first byte of a later frame, or the stream
/// is at EOF.
///
/// * [`FrameError::FrameTooLong`] never allocates the payload and never
///   reads it. This includes a header whose version is unknown or whose
///   reserved flags are set. `Length` is checked before version and
///   flags, so an overlong header is `FrameTooLong` and not
///   [`FrameError::UnknownVersion`] or [`FrameError::ReservedFlags`].
///   The cursor stays immediately after the 8-byte header. Not aligned.
/// * [`FrameError::UnknownVersion`] and [`FrameError::ReservedFlags`]
///   are returned only when `Length` is within the limit. The payload
///   is read and discarded first, then the error is returned, and the
///   cursor is aligned. A `Length` of zero discards nothing and is
///   still aligned. When both the version and the flags are wrong, the
///   version error is the one returned. If the discard hits EOF or an
///   I/O error, that error is returned instead and the cursor is not
///   aligned.
/// * [`FrameError::Io`] or [`FrameError::Incomplete`] while the header
///   or the payload is still short: not aligned. Bytes already stored
///   are dropped with the poison. They are not reused as a new header.
/// * [`FrameError::Alloc`] while reserving the payload buffer happens
///   before that payload is read. Not aligned. An allocation failure
///   while copying an already-read frame into the decode buffer happens
///   after the cursor has passed that frame. Aligned, then poisoned.
/// * A body, padding, type, or TLV error after all `8 + Length` bytes
///   have been read: the cursor is aligned, and the reader is still
///   poisoned. The following frame is not parsed.
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
    payload: Vec<u8>,
    payload_filled: usize,
    discard_remaining: usize,
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
            discard_remaining: 0,
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
        self.payload = Vec::new();
        self.payload_filled = 0;
        self.discard_remaining = 0;
    }

    fn fail(&mut self, err: FrameError) -> Step {
        self.poison();
        Step::Done(Err(err))
    }

    fn begin_header(&mut self) -> Step {
        self.header = [0; FRAME_HEADER_LEN];
        self.header_filled = 0;
        self.payload_filled = 0;
        self.discard_remaining = 0;
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
            Err(fault) => {
                self.discard_remaining = length;
                self.stage = Stage::Discard(fault);
                Step::Continue
            }
        }
    }

    fn start_payload(&mut self, length: usize) -> Step {
        self.payload.clear();
        self.payload_filled = 0;
        if self.payload.try_reserve_exact(length).is_err() {
            return self.fail(FrameError::Alloc { length });
        }
        self.payload.resize(length, 0);
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

    fn take_payload_bytes(&mut self, n: usize) -> Step {
        if n == 0 {
            return self.fail(FrameError::Incomplete);
        }
        self.payload_filled = self.payload_filled.saturating_add(n);
        if self.payload_filled > self.payload.len() {
            return self.fail(FrameError::Incomplete);
        }
        if self.payload_filled == self.payload.len() {
            self.finish_payload()
        } else {
            Step::Continue
        }
    }

    fn finish_payload(&mut self) -> Step {
        let total = FRAME_HEADER_LEN.saturating_add(self.payload.len());
        let mut buf = Vec::new();
        if buf.try_reserve_exact(total).is_err() {
            return self.fail(FrameError::Alloc { length: total });
        }
        buf.extend_from_slice(&self.header);
        buf.extend_from_slice(&self.payload);
        // The frame bytes are in `buf`. Drop the copy held here before
        // decode so a poisoned reader does not keep a TUN payload.
        self.payload.clear();
        self.payload_filled = 0;
        self.header_filled = 0;
        match decode_with(&buf, self.limits) {
            Ok(frame) => {
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
    /// `Err` poisons this reader; see [`FrameReader`] for which errors
    /// discard a legal payload and which leave the cursor mid-frame.
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
    /// after a legal payload has been discarded.
    ///
    /// [`FrameError::Incomplete`] if EOF arrives after at least one byte
    /// of this frame, or before a declared payload (including a discard)
    /// is complete.
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
                Stage::Discard(fault) => self.poll_discard(cx, fault),
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
        if self.payload_filled >= self.payload.len() {
            return self.finish_payload();
        }
        let filled = self.payload_filled;
        match poll_read_some(&mut self.reader, cx, &mut self.payload[filled..]) {
            Poll::Pending => Step::Wait,
            Poll::Ready(Err(err)) => self.fail(err),
            Poll::Ready(Ok(n)) => self.take_payload_bytes(n),
        }
    }

    fn poll_discard(&mut self, cx: &mut Context<'_>, fault: HeaderFault) -> Step {
        if self.discard_remaining == 0 {
            let err = fault.into_error();
            return self.fail(err);
        }
        let want = self.discard_remaining.min(DISCARD_CHUNK);
        let mut scratch = [0u8; DISCARD_CHUNK];
        match poll_read_some(&mut self.reader, cx, &mut scratch[..want]) {
            Poll::Pending => Step::Wait,
            Poll::Ready(Err(err)) => self.fail(err),
            Poll::Ready(Ok(0)) => self.fail(FrameError::Incomplete),
            Poll::Ready(Ok(n)) => {
                self.discard_remaining = self.discard_remaining.saturating_sub(n);
                if self.discard_remaining == 0 {
                    let err = fault.into_error();
                    self.fail(err)
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
            .field("payload_len", &self.payload.len())
            .field("discard_remaining", &self.discard_remaining)
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
