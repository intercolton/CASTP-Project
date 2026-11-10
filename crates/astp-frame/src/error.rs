//! Parse and encode errors.
//!
//! Variants are stable names for tests and for the session layer. Display
//! text never includes a TUN payload or TLV value bytes.

use std::io;

use thiserror::Error;

/// Failure while encoding or decoding one ASTP-M frame.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The buffer ended before a header or a payload was complete.
    ///
    /// Also used when a stream reaches EOF after at least one byte of the
    /// frame has already been read. A clean EOF before the first byte of
    /// the next frame is [`Ok(None)`](crate::read_frame), not this error.
    #[error("incomplete frame")]
    Incomplete,

    /// `buf` contained bytes after the single frame `Length` describes.
    ///
    /// Spec draft 0.3 §5.1 requires one datagram payload to be exactly one
    /// frame (`Length == len(datagram) - 8`).
    #[error("trailing {extra} byte(s) after the frame")]
    TrailingBytes {
        /// Bytes past `8 + Length`.
        extra: usize,
    },

    /// `Version` was not `0x01`.
    #[error("unknown frame version {version:#04x}")]
    UnknownVersion {
        /// The version byte from the header.
        version: u8,
    },

    /// `Type` is not assigned in v1.
    ///
    /// This includes the reserved split-path range `0x40..=0x4F` and any
    /// other unassigned code, such as `0x99`.
    #[error("unknown frame type {ty:#04x}")]
    UnknownType {
        /// The type byte from the header.
        ty: u8,
    },

    /// One or more of flag bits 2–15 were set.
    #[error("reserved flag bits are set ({flags:#06x})")]
    ReservedFlags {
        /// The full flags word from the header.
        flags: u16,
    },

    /// `Length` is above the protocol ceiling or the caller’s `max_frame`.
    ///
    /// Raised from the header. The payload is not allocated and, on a
    /// stream, not read.
    #[error("frame length {length} exceeds limit {max_frame}")]
    FrameTooLong {
        /// The `Length` field from the header, or the encoded payload size.
        length: u32,
        /// The limit that rejected it (at most 65535).
        max_frame: u32,
    },

    /// `PAD` was set but the trailer does not fit in the payload.
    #[error("inconsistent padding")]
    BadPadding,

    /// `KEY_EPOCH` was set and the content (after padding) was empty.
    #[error("KEY_EPOCH set but content is empty")]
    EmptyKeyEpoch,

    /// A typed body had the wrong length.
    #[error("invalid {kind} body length {length}")]
    BadBodyLength {
        /// Frame type name, for example `PING` or `CONFIG`.
        kind: &'static str,
        /// Actual body length in bytes.
        length: usize,
    },

    /// IPv4 body failed the codec checks (version, minimum size, total length).
    #[error("invalid IPv4 packet")]
    BadIpv4,

    /// IPv6 body failed the codec checks (version, minimum size, payload length).
    #[error("invalid IPv6 packet")]
    BadIpv6,

    /// `DISCONNECT` reason bytes were not valid UTF-8.
    #[error("DISCONNECT reason is not valid UTF-8")]
    InvalidUtf8,

    /// A TLV header or value was cut off before the end of the body.
    #[error("truncated TLV")]
    TruncatedTlv,

    /// A known TLV type carried a value of the wrong size.
    #[error("TLV {ty:#06x} has invalid value length {length}")]
    BadTlvLength {
        /// TLV type code.
        ty: u16,
        /// Actual value length in bytes.
        length: usize,
    },

    /// An address or route prefix was outside `0..=32` (IPv4) or `0..=128` (IPv6).
    #[error("TLV {ty:#06x} prefix {prefix} is out of range")]
    BadPrefix {
        /// TLV type code.
        ty: u16,
        /// The prefix byte from the value.
        prefix: u8,
    },

    /// A route include/exclude byte was neither 0 nor 1.
    #[error("TLV {ty:#06x} route flag {flag} is not 0 or 1")]
    BadRouteFlag {
        /// TLV type code.
        ty: u16,
        /// The flag byte from the value.
        flag: u8,
    },

    /// [`crate::Tlv::Raw`] was asked to encode a type that already has a variant.
    #[error("raw TLV {ty:#06x} uses a type assigned in v1")]
    KnownTlvAsRaw {
        /// TLV type code.
        ty: u16,
    },

    /// A TLV value did not fit in the `u16` length field.
    #[error("TLV {ty:#06x} value length {length} exceeds u16")]
    TlvValueTooLong {
        /// TLV type code.
        ty: u16,
        /// Actual value length in bytes.
        length: usize,
    },

    /// The operating-system CSPRNG could not fill camouflage padding.
    ///
    /// The encoder returns this instead of writing zeros or panicking.
    /// `detail` is the RNG error text, not frame contents.
    #[error("operating-system CSPRNG failed while generating padding: {detail}")]
    Random {
        /// Display text of the RNG error.
        detail: String,
    },

    /// The payload fit the length limit, but the allocator refused the buffer.
    ///
    /// Legal frames are at most 64 KiB of payload. This is an out-of-memory
    /// failure, not a malformed header.
    #[error("failed to allocate a {length}-byte frame buffer")]
    Alloc {
        /// Requested buffer size in bytes.
        length: usize,
    },

    /// The stream reader hit an I/O error.
    ///
    /// `Ok(0)` from [`tokio::io::AsyncRead`] is EOF, not this variant.
    #[error("I/O error while reading a frame")]
    Io(#[source] io::Error),
}

impl From<io::Error> for FrameError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
