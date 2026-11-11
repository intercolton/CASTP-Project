//! Owned frame values. Invalid combinations that the wire can still
//! express (bad version, unknown type, bad padding) are [`FrameError`]s,
//! not variants.

use astp_types::{
    FRAME_CONFIG, FRAME_CONFIG_ACK, FRAME_DISCONNECT, FRAME_PADDING, FRAME_PING, FRAME_PONG,
    FRAME_ROUTE_UPDATE, FRAME_TUN_IPV4, FRAME_TUN_IPV6, FRAME_WINDOW,
};

use crate::config::{Config, RouteUpdate};
use crate::error::FrameError;
use crate::wire::copy_at;

/// One decoded frame, with padding already removed.
///
/// `key_epoch` is `Some` exactly when the `KEY_EPOCH` flag was set. The
/// epoch byte is not part of [`Frame::body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Key epoch carried in front of the body, when the flag is set.
    pub key_epoch: Option<u8>,
    /// Typed body after padding and the optional epoch byte are removed.
    pub body: FrameBody,
}

/// Body of a v1 frame.
///
/// There is no variant for an unknown type. Reserved codes `0x40..=0x4F`
/// are unknown types and fail at decode. Unknown CONFIG TLV records use
/// [`crate::Tlv::Raw`] instead of failing the frame.
///
/// The enum is `non_exhaustive`: adding a variant later is not a breaking
/// change for downstream `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameBody {
    /// `PADDING`. The body is empty.
    Padding,
    /// `PING`. Eight opaque bytes the peer echoes.
    Ping([u8; 8]),
    /// `PONG`. The eight bytes from the matching `PING`.
    Pong([u8; 8]),
    /// `TUN_IPV4`. One raw IPv4 packet, already checked by the codec.
    TunIpv4(Ipv4Packet),
    /// `TUN_IPV6`. One raw IPv6 packet, already checked by the codec.
    TunIpv6(Ipv6Packet),
    /// `CONFIG`. `cfg_id` plus zero or more TLV records.
    Config(Config),
    /// `CONFIG_ACK`. `code` is not restricted to 0, 1, or 2.
    ConfigAck {
        /// Proposal identifier, matching `CONFIG.cfg_id`.
        cfg_id: u32,
        /// Status byte for the session. The codec accepts any value.
        code: u8,
    },
    /// `ROUTE_UPDATE`. TLV records without a leading `cfg_id`.
    RouteUpdate(RouteUpdate),
    /// `DISCONNECT`. `reason` is valid UTF-8 and may be empty.
    Disconnect {
        /// Application reason code (`u16` on the wire).
        code: u16,
        /// Human-readable reason. Empty is allowed.
        reason: String,
    },
    /// `WINDOW`. Applied credit, exactly four bytes on the wire.
    Window {
        /// Credit in bytes, as a `u32`.
        credit: u32,
    },
}

impl FrameBody {
    /// Wire type code for this body.
    #[must_use]
    pub const fn type_code(&self) -> u8 {
        match self {
            Self::Padding => FRAME_PADDING,
            Self::Ping(_) => FRAME_PING,
            Self::Pong(_) => FRAME_PONG,
            Self::TunIpv4(_) => FRAME_TUN_IPV4,
            Self::TunIpv6(_) => FRAME_TUN_IPV6,
            Self::Config(_) => FRAME_CONFIG,
            Self::ConfigAck { .. } => FRAME_CONFIG_ACK,
            Self::RouteUpdate(_) => FRAME_ROUTE_UPDATE,
            Self::Disconnect { .. } => FRAME_DISCONNECT,
            Self::Window { .. } => FRAME_WINDOW,
        }
    }
}

/// IPv4 packet accepted by the frame codec.
///
/// Checks, and only these checks: length at least 20, version nibble 4,
/// and `Total Length` (bytes 2–3) equal to the body length and at least 20.
/// A shorter `Total Length` (a tail past the IP packet) is rejected, which
/// is the same rule as “`Total Length` ≤ body and not strictly less”.
/// Checksums, IHL, and multicast policy are not inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    bytes: Vec<u8>,
}

impl Ipv4Packet {
    /// Validate `bytes` and take ownership.
    ///
    /// # Errors
    ///
    /// [`FrameError::BadIpv4`] when the codec checks fail.
    pub fn new(bytes: Vec<u8>) -> Result<Self, FrameError> {
        validate_ipv4(&bytes)?;
        Ok(Self { bytes })
    }

    /// Raw packet, starting at the version/IHL octet.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Ipv4Packet {
    /// The raw packet, consuming the wrapper.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl AsRef<[u8]> for Ipv4Packet {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// IPv6 packet accepted by the frame codec.
///
/// Checks: length at least 40, version nibble 6, and `Payload Length`
/// (bytes 4–5) + 40 equal to the body length. A jumbo payload (length
/// field 0 with a packet longer than 40 bytes) does not pass, because
/// the lengths would differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {
    bytes: Vec<u8>,
}

impl Ipv6Packet {
    /// Validate `bytes` and take ownership.
    ///
    /// # Errors
    ///
    /// [`FrameError::BadIpv6`] when the codec checks fail.
    pub fn new(bytes: Vec<u8>) -> Result<Self, FrameError> {
        validate_ipv6(&bytes)?;
        Ok(Self { bytes })
    }

    /// Raw packet, starting at the version/traffic-class octet.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Ipv6Packet {
    /// The raw packet, consuming the wrapper.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl AsRef<[u8]> for Ipv6Packet {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub(crate) fn validate_ipv4(body: &[u8]) -> Result<(), FrameError> {
    if body.len() < 20 {
        return Err(FrameError::BadIpv4);
    }
    let version = body.first().copied().ok_or(FrameError::BadIpv4)? >> 4;
    if version != 4 {
        return Err(FrameError::BadIpv4);
    }
    let total = u16::from_be_bytes(copy_at::<2>(body, 2).ok_or(FrameError::BadIpv4)?);
    // `body.len() >= 20` above, so this also rules out total < 20.
    if usize::from(total) != body.len() {
        return Err(FrameError::BadIpv4);
    }
    Ok(())
}

pub(crate) fn validate_ipv6(body: &[u8]) -> Result<(), FrameError> {
    if body.len() < 40 {
        return Err(FrameError::BadIpv6);
    }
    let version = body.first().copied().ok_or(FrameError::BadIpv6)? >> 4;
    if version != 6 {
        return Err(FrameError::BadIpv6);
    }
    let payload_len = u16::from_be_bytes(copy_at::<2>(body, 4).ok_or(FrameError::BadIpv6)?);
    let declared = usize::from(payload_len).saturating_add(40);
    if declared != body.len() {
        return Err(FrameError::BadIpv6);
    }
    Ok(())
}

pub(crate) fn decode_ipv4(body: &[u8]) -> Result<Ipv4Packet, FrameError> {
    Ipv4Packet::new(body.to_vec())
}

pub(crate) fn decode_ipv6(body: &[u8]) -> Result<Ipv6Packet, FrameError> {
    Ipv6Packet::new(body.to_vec())
}
