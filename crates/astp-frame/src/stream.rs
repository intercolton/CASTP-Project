//! Read one frame from an unstructured byte stream (the TCP profile).
//!
//! The reader does not look at the next frame until the current header and
//! payload have been taken. `Length` above the active limit is rejected
//! from the 8-byte header, before the payload is allocated or read.

use astp_types::FRAME_HEADER_LEN;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::codec::decode_with;
use crate::error::FrameError;
use crate::header::{DecodeLimits, RawHeader};
use crate::types::Frame;

/// Read one frame, using the default limit of 65535 bytes of payload.
///
/// ```
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// use std::io::Cursor;
/// use astp_frame::{encode, read_frame, Frame, FrameBody};
/// let frame = Frame { key_epoch: None, body: FrameBody::Padding };
/// let bytes = encode(&frame, None).unwrap();
/// let mut cur = Cursor::new(bytes);
/// assert_eq!(read_frame(&mut cur).await.unwrap().unwrap(), frame);
/// assert!(read_frame(&mut cur).await.unwrap().is_none());
/// # });
/// ```
///
/// # Clean end of stream
///
/// `Ok(None)` means the reader hit EOF before the first byte of the next
/// frame. That is the end of the stream, not a broken frame.
///
/// # Errors
///
/// [`FrameError::Incomplete`] if EOF arrives after at least one byte of
/// this frame, or before a declared payload is complete.
/// [`FrameError::FrameTooLong`] if the header `Length` exceeds the limit;
/// the payload is not read. Other parse errors match [`crate::decode`].
/// Bytes already pulled from `reader` stay consumed: this function does
/// not rewind the stream.
///
/// `reader` follows the [`AsyncRead`] contract: `Ok(0)` is EOF.
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<Frame>, FrameError>
where
    R: AsyncRead + Unpin,
{
    read_frame_with(reader, DecodeLimits::DEFAULT).await
}

/// [`read_frame`] with an explicit [`DecodeLimits`].
///
/// # Errors
///
/// Same as [`read_frame`]. A `max_frame` below 65535 rejects a longer
/// `Length` before the payload is read. The protocol ceiling stays 65535
/// even if `max_frame` is higher; see [`DecodeLimits::effective_max`].
pub async fn read_frame_with<R>(
    reader: &mut R,
    limits: DecodeLimits,
) -> Result<Option<Frame>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header_bytes = [0u8; FRAME_HEADER_LEN];
    if !read_exact(reader, &mut header_bytes, true).await? {
        return Ok(None);
    }
    let header = RawHeader::parse(&header_bytes)?;
    // Version, reserved flags, and the length limit, before any payload read.
    header.check(limits)?;
    let length = usize::try_from(header.length).map_err(|_| FrameError::FrameTooLong {
        length: header.length,
        max_frame: limits.effective_max(),
    })?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| FrameError::Alloc { length })?;
    payload.resize(length, 0);
    if !payload.is_empty() && !read_exact(reader, &mut payload, false).await? {
        return Err(FrameError::Incomplete);
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(FRAME_HEADER_LEN.saturating_add(payload.len()))
        .map_err(|_| FrameError::Alloc {
            length: FRAME_HEADER_LEN.saturating_add(payload.len()),
        })?;
    buf.extend_from_slice(&header_bytes);
    buf.extend_from_slice(&payload);
    decode_with(&buf, limits).map(Some)
}

/// Fill `buf`. `Ok(false)` is a clean EOF before the first byte, and only
/// when `clean_eof` is set. Any later EOF is [`FrameError::Incomplete`].
async fn read_exact<R>(reader: &mut R, buf: &mut [u8], clean_eof: bool) -> Result<bool, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            if filled == 0 && clean_eof {
                return Ok(false);
            }
            return Err(FrameError::Incomplete);
        }
        filled = filled.saturating_add(n);
        if filled > buf.len() {
            return Err(FrameError::Incomplete);
        }
    }
    Ok(true)
}
