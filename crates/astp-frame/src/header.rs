//! The 8-byte big-endian frame header.

use astp_types::{FLAG_RESERVED_MASK, FRAME_HEADER_LEN, FRAME_VERSION, MAX_FRAME_LENGTH};

use crate::error::FrameError;
use crate::wire::copy_prefix;

/// Caller limit on the `Length` field.
///
/// The protocol ceiling is [`MAX_FRAME_LENGTH`] (65535). `max_frame` can
/// only tighten that ceiling. A stored value above 65535 does not raise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum accepted `Length`, before the protocol ceiling is applied.
    pub max_frame: u32,
}

impl DecodeLimits {
    /// Default limit: the v1 protocol ceiling, 65535.
    pub const DEFAULT: Self = Self {
        max_frame: MAX_FRAME_LENGTH,
    };

    /// `min(max_frame, 65535)`.
    #[must_use]
    pub const fn effective_max(self) -> u32 {
        if self.max_frame < MAX_FRAME_LENGTH {
            self.max_frame
        } else {
            MAX_FRAME_LENGTH
        }
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Header fields before the payload is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawHeader {
    pub version: u8,
    pub ty: u8,
    pub flags: u16,
    pub length: u32,
}

impl RawHeader {
    /// Read the first 8 bytes. Does not look at the payload.
    pub(crate) fn parse(buf: &[u8]) -> Result<Self, FrameError> {
        let bytes = copy_prefix::<FRAME_HEADER_LEN>(buf).ok_or(FrameError::Incomplete)?;
        Ok(Self {
            version: bytes[0],
            ty: bytes[1],
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }

    /// Version, reserved flags, then the length limit.
    ///
    /// Called before the payload is read so an overlong `Length` cannot
    /// allocate. The order matches spec draft 0.3 §5.1 once the header
    /// itself is in hand.
    pub(crate) fn check(self, limits: DecodeLimits) -> Result<(), FrameError> {
        if self.version != FRAME_VERSION {
            return Err(FrameError::UnknownVersion {
                version: self.version,
            });
        }
        if self.flags & FLAG_RESERVED_MASK != 0 {
            return Err(FrameError::ReservedFlags { flags: self.flags });
        }
        let max_frame = limits.effective_max();
        if self.length > max_frame {
            return Err(FrameError::FrameTooLong {
                length: self.length,
                max_frame,
            });
        }
        Ok(())
    }
}

pub(crate) fn push_header(out: &mut Vec<u8>, ty: u8, flags: u16, length: u32) {
    out.push(FRAME_VERSION);
    out.push(ty);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
}
