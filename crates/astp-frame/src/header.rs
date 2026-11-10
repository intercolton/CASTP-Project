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

    /// Version, then reserved flags.
    ///
    /// Does not look at `Length`. [`Self::check`] uses this order for a
    /// buffer that is already in memory. The stream reader checks
    /// [`Self::checked_length`] first so an overlong `Length` is reported
    /// even when the version or flags are also wrong.
    pub(crate) fn version_and_flags(self) -> Result<(), HeaderFault> {
        if self.version != FRAME_VERSION {
            return Err(HeaderFault::UnknownVersion {
                version: self.version,
            });
        }
        if self.flags & FLAG_RESERVED_MASK != 0 {
            return Err(HeaderFault::ReservedFlags { flags: self.flags });
        }
        Ok(())
    }

    /// `Length` as a `usize` when it is within `limits`.
    ///
    /// Does not look at version or flags. A value above the limit fails
    /// before the caller allocates or reads a payload.
    pub(crate) fn checked_length(self, limits: DecodeLimits) -> Result<usize, FrameError> {
        let max_frame = limits.effective_max();
        if self.length > max_frame {
            return Err(FrameError::FrameTooLong {
                length: self.length,
                max_frame,
            });
        }
        usize::try_from(self.length).map_err(|_| FrameError::FrameTooLong {
            length: self.length,
            max_frame,
        })
    }

    /// Version, reserved flags, then the length limit.
    ///
    /// This is the order for [`crate::decode_with`], where the bytes are
    /// already in hand. An overlong `Length` still fails before the payload
    /// slice is required. The stream reader does not use this order; see
    /// [`crate::FrameReader`].
    pub(crate) fn check(self, limits: DecodeLimits) -> Result<(), FrameError> {
        self.version_and_flags().map_err(HeaderFault::into_error)?;
        self.checked_length(limits)?;
        Ok(())
    }
}

/// Version or reserved-flag failure, with `Length` left unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderFault {
    /// `Version` was not `0x01`.
    UnknownVersion {
        /// The version byte from the header.
        version: u8,
    },
    /// One or more of flag bits 2–15 were set.
    ReservedFlags {
        /// The full flags word from the header.
        flags: u16,
    },
}

impl HeaderFault {
    pub(crate) fn into_error(self) -> FrameError {
        match self {
            Self::UnknownVersion { version } => FrameError::UnknownVersion { version },
            Self::ReservedFlags { flags } => FrameError::ReservedFlags { flags },
        }
    }
}

pub(crate) fn push_header(out: &mut Vec<u8>, ty: u8, flags: u16, length: u32) {
    out.push(FRAME_VERSION);
    out.push(ty);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
}
