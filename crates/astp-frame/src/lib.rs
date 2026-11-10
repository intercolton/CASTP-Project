//! ASTP-M v1 frame codec.
//!
//! Frames are the cleartext application records carried *inside* an
//! already decrypted QUIC or TLS session. This crate does not encrypt,
//! does not build an AEAD nonce, does not run a handshake, and does not
//! open a TUN device or a socket. Wire layout: spec draft 0.3 §5.
//!
//! ```
//! use astp_frame::{decode, encode, Frame, FrameBody};
//!
//! let frame = Frame {
//!     key_epoch: None,
//!     body: FrameBody::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
//! };
//! let bytes = encode(&frame, None).expect("ping");
//! assert_eq!(decode(&bytes).expect("round trip"), frame);
//! ```
//!
//! # Limits
//!
//! * The header is 8 bytes. `Length` is a big-endian `u32`, but v1 accepts
//!   only `0..=65535` ([`MAX_FRAME_LENGTH`]). Anything larger is
//!   [`FrameError::FrameTooLong`].
//! * [`DecodeLimits::max_frame`] defaults to 65535 and can only tighten
//!   that ceiling. A larger stored value does not raise it.
//! * [`FrameReader`] checks `Length` before it reads the payload, so an
//!   overlong header does not reserve a multi-megabyte buffer. A legal
//!   payload buffer grows as bytes arrive; it is not reserved to
//!   `Length` when the header arrives. An unknown version or reserved
//!   flags also poison the
//!   reader without reading the payload. Partial reads stay in the
//!   reader across cancellation. Any error poisons it; a later read
//!   does not touch the socket, and the connection must be closed.
//!   A header error does not leave the cursor on a frame boundary.
//! * Untrusted bytes produce [`FrameError`]. Library paths do not panic on
//!   a short, malformed, or overlong frame, and they do not log TUN payloads.
//!
//! # Padding
//!
//! [`encode`] / [`encode_to`] are the raw path: pass `None` for no `PAD`
//! flag, or `Some(octets)` to set the flag and use those exact octets.
//! [`camouflage_pad_len`] and [`encode_camouflage`] implement profile v1
//! (step 64, minimum wire size 64, `max_pad` 255) for every frame type.
//! The production encoder fills padding from the OS CSPRNG. The decoder
//! accepts a short frame and any padding octets.
//!
//! # Reserved numbers
//!
//! Types `0x40..=0x4F` and TLV `0x000C` / `0x000D` are reserved for a
//! possible later split-path. This crate does not assign them. A reserved
//! type is [`FrameError::UnknownType`], the same error as any other
//! unknown type. A reserved TLV is returned as [`Tlv::Raw`].
//!
//! Numeric identifiers live in `astp-types` and are re-exported here when
//! the codec’s own API mentions them.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod codec;
mod config;
mod error;
mod header;
mod padding;
mod stream;
mod types;
mod wire;

pub use codec::{decode, decode_with, encode, encode_to};
pub use config::{is_known_tlv, Config, RouteUpdate, Tlv};
pub use error::FrameError;
pub use header::DecodeLimits;
pub use padding::{
    camouflage_pad_len, encode_camouflage, encode_camouflage_with, CamouflageProfile,
};
pub use stream::FrameReader;
pub use types::{Frame, FrameBody, Ipv4Packet, Ipv6Packet};

pub use astp_types::{
    DEFAULT_MAX_PAD, DEFAULT_MIN_WIRE_SIZE, DEFAULT_PADDING_STEP, FLAG_KEY_EPOCH, FLAG_PAD,
    FLAG_RESERVED_MASK, FRAME_HEADER_LEN, FRAME_VERSION, MAX_FRAME_LENGTH,
};
