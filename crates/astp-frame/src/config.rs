//! CONFIG and ROUTE_UPDATE TLV records (spec draft 0.3 §5.4).
//!
//! Known types have a fixed value length. A wrong length, a prefix past
//! the address family, or a route flag other than 0 or 1 is a parse error.
//! Any other type number, including the reserved split-path numbers
//! `0x000C` and `0x000D`, is kept as [`Tlv::Raw`] and is not an error.

use std::net::{Ipv4Addr, Ipv6Addr};

use astp_types::{
    TLV_ADDR4, TLV_ADDR6, TLV_DNS4, TLV_DNS6, TLV_IDLE_TIMEOUT, TLV_KEEPALIVE, TLV_MAX_FRAME,
    TLV_MTU, TLV_ROUTE4, TLV_ROUTE6, TLV_SESSION_ID,
};

use crate::error::FrameError;
use crate::wire::{copy_exact, copy_prefix};

/// One CONFIG or ROUTE_UPDATE record.
///
/// The enum is `non_exhaustive`: adding a variant later is not a breaking
/// change for downstream `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tlv {
    /// `addr4`: IPv4 address and prefix length `0..=32`.
    Addr4 {
        /// Client IPv4 address.
        addr: Ipv4Addr,
        /// Prefix length, 0 through 32.
        prefix: u8,
    },
    /// `addr6`: IPv6 address and prefix length `0..=128`.
    Addr6 {
        /// Client IPv6 address.
        addr: Ipv6Addr,
        /// Prefix length, 0 through 128.
        prefix: u8,
    },
    /// `mtu`: tunnel MTU.
    Mtu(u16),
    /// `dns4`: one IPv4 DNS address.
    Dns4(Ipv4Addr),
    /// `dns6`: one IPv6 DNS address.
    Dns6(Ipv6Addr),
    /// `route4`: IPv4 destination, prefix, and include/exclude.
    Route4 {
        /// Destination address.
        dest: Ipv4Addr,
        /// Prefix length, 0 through 32.
        prefix: u8,
        /// `true` is include (wire 1). `false` is exclude (wire 0).
        include: bool,
    },
    /// `route6`: IPv6 destination, prefix, and include/exclude.
    Route6 {
        /// Destination address.
        dest: Ipv6Addr,
        /// Prefix length, 0 through 128.
        prefix: u8,
        /// `true` is include (wire 1). `false` is exclude (wire 0).
        include: bool,
    },
    /// `keepalive`: PING interval in milliseconds.
    Keepalive(u32),
    /// `idle_timeout`: idle timeout in milliseconds.
    IdleTimeout(u32),
    /// `session_id`: 16-byte reconnect identifier. Not a secret.
    SessionId([u8; 16]),
    /// `max_frame`: session cap for the frame `Length` field, as a `u32`.
    ///
    /// The codec stores the value. It does not apply it by itself; pass a
    /// [`crate::DecodeLimits`] when decoding.
    MaxFrame(u32),
    /// A TLV type this crate does not interpret, including `0x000C` and `0x000D`.
    ///
    /// Encoding a raw record whose type is one of the known variants above
    /// is [`FrameError::KnownTlvAsRaw`]. Use the typed variant instead.
    Raw {
        /// Type code, not one of the assigned v1 types.
        ty: u16,
        /// Value bytes, not including the 4-byte TLV header.
        value: Vec<u8>,
    },
}

/// `CONFIG` body: a proposal id plus TLV records packed back to back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Random proposal identifier. Echoed in `CONFIG_ACK`.
    pub cfg_id: u32,
    /// Zero or more records. A truncated record is a parse error.
    pub tlvs: Vec<Tlv>,
}

/// `ROUTE_UPDATE` body: the same TLV records as [`Config`], without `cfg_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteUpdate {
    /// Zero or more records.
    pub tlvs: Vec<Tlv>,
}

/// `true` when `ty` has a typed [`Tlv`] variant in v1.
///
/// `0x000C` and `0x000D` are reserved and return `false`.
#[must_use]
pub const fn is_known_tlv(ty: u16) -> bool {
    matches!(
        ty,
        TLV_ADDR4
            | TLV_ADDR6
            | TLV_MTU
            | TLV_DNS4
            | TLV_DNS6
            | TLV_ROUTE4
            | TLV_ROUTE6
            | TLV_KEEPALIVE
            | TLV_IDLE_TIMEOUT
            | TLV_SESSION_ID
            | TLV_MAX_FRAME
    )
}

pub(crate) fn decode_config(body: &[u8]) -> Result<Config, FrameError> {
    let id_bytes = copy_prefix::<4>(body).ok_or(FrameError::BadBodyLength {
        kind: "CONFIG",
        length: body.len(),
    })?;
    let tlvs = decode_tlv_list(body.get(4..).ok_or(FrameError::BadBodyLength {
        kind: "CONFIG",
        length: body.len(),
    })?)?;
    Ok(Config {
        cfg_id: u32::from_be_bytes(id_bytes),
        tlvs,
    })
}

pub(crate) fn encode_config(cfg: &Config, out: &mut Vec<u8>) -> Result<(), FrameError> {
    out.extend_from_slice(&cfg.cfg_id.to_be_bytes());
    encode_tlv_list(&cfg.tlvs, out)
}

pub(crate) fn decode_tlv_list(mut rest: &[u8]) -> Result<Vec<Tlv>, FrameError> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let header = copy_prefix::<4>(rest).ok_or(FrameError::TruncatedTlv)?;
        let ty = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let after = rest.get(4..).ok_or(FrameError::TruncatedTlv)?;
        let value = after.get(..len).ok_or(FrameError::TruncatedTlv)?;
        out.push(decode_one(ty, value)?);
        rest = after.get(len..).ok_or(FrameError::TruncatedTlv)?;
    }
    Ok(out)
}

pub(crate) fn encode_tlv_list(tlvs: &[Tlv], out: &mut Vec<u8>) -> Result<(), FrameError> {
    for tlv in tlvs {
        encode_one(tlv, out)?;
    }
    Ok(())
}

// Wire length of `tlvs`, including each 4-byte header. Same checks as
// `encode_tlv_list`, without copying the values.
pub(crate) fn encoded_tlvs_len(tlvs: &[Tlv]) -> Result<usize, FrameError> {
    let mut total = 0usize;
    for tlv in tlvs {
        total = total.saturating_add(encoded_one_len(tlv)?);
    }
    Ok(total)
}

fn encoded_one_len(tlv: &Tlv) -> Result<usize, FrameError> {
    let value_len = match tlv {
        Tlv::Addr4 { prefix, .. } => {
            check_prefix(TLV_ADDR4, *prefix, 32)?;
            5
        }
        Tlv::Addr6 { prefix, .. } => {
            check_prefix(TLV_ADDR6, *prefix, 128)?;
            17
        }
        Tlv::Mtu(_) => 2,
        Tlv::Dns4(_) => 4,
        Tlv::Dns6(_) => 16,
        Tlv::Route4 { prefix, .. } => {
            check_prefix(TLV_ROUTE4, *prefix, 32)?;
            6
        }
        Tlv::Route6 { prefix, .. } => {
            check_prefix(TLV_ROUTE6, *prefix, 128)?;
            18
        }
        Tlv::Keepalive(_) | Tlv::IdleTimeout(_) | Tlv::MaxFrame(_) => 4,
        Tlv::SessionId(_) => 16,
        Tlv::Raw { ty, value } => {
            if is_known_tlv(*ty) {
                return Err(FrameError::KnownTlvAsRaw { ty: *ty });
            }
            if u16::try_from(value.len()).is_err() {
                return Err(FrameError::TlvValueTooLong {
                    ty: *ty,
                    length: value.len(),
                });
            }
            value.len()
        }
    };
    Ok(4usize.saturating_add(value_len))
}

fn decode_one(ty: u16, value: &[u8]) -> Result<Tlv, FrameError> {
    if let Some(expected) = expected_len(ty) {
        if value.len() != expected {
            return Err(FrameError::BadTlvLength {
                ty,
                length: value.len(),
            });
        }
    } else {
        return Ok(Tlv::Raw {
            ty,
            value: value.to_vec(),
        });
    }

    match ty {
        TLV_ADDR4 => {
            let addr = ipv4_at(value).ok_or(FrameError::BadTlvLength {
                ty,
                length: value.len(),
            })?;
            let prefix = byte_at(value, 4, ty)?;
            check_prefix(ty, prefix, 32)?;
            Ok(Tlv::Addr4 { addr, prefix })
        }
        TLV_ADDR6 => {
            let addr = ipv6_at(value).ok_or(FrameError::BadTlvLength {
                ty,
                length: value.len(),
            })?;
            let prefix = byte_at(value, 16, ty)?;
            check_prefix(ty, prefix, 128)?;
            Ok(Tlv::Addr6 { addr, prefix })
        }
        TLV_MTU => Ok(Tlv::Mtu(read_u16(value, ty)?)),
        TLV_DNS4 => Ok(Tlv::Dns4(ipv4_exact(value, ty)?)),
        TLV_DNS6 => Ok(Tlv::Dns6(ipv6_exact(value, ty)?)),
        TLV_ROUTE4 => {
            let dest = ipv4_at(value).ok_or(FrameError::BadTlvLength {
                ty,
                length: value.len(),
            })?;
            let prefix = byte_at(value, 4, ty)?;
            let flag = byte_at(value, 5, ty)?;
            check_prefix(ty, prefix, 32)?;
            Ok(Tlv::Route4 {
                dest,
                prefix,
                include: route_include(ty, flag)?,
            })
        }
        TLV_ROUTE6 => {
            let dest = ipv6_at(value).ok_or(FrameError::BadTlvLength {
                ty,
                length: value.len(),
            })?;
            let prefix = byte_at(value, 16, ty)?;
            let flag = byte_at(value, 17, ty)?;
            check_prefix(ty, prefix, 128)?;
            Ok(Tlv::Route6 {
                dest,
                prefix,
                include: route_include(ty, flag)?,
            })
        }
        TLV_KEEPALIVE => Ok(Tlv::Keepalive(read_u32(value, ty)?)),
        TLV_IDLE_TIMEOUT => Ok(Tlv::IdleTimeout(read_u32(value, ty)?)),
        TLV_SESSION_ID => Ok(Tlv::SessionId(copy_exact::<16>(value).ok_or(
            FrameError::BadTlvLength {
                ty,
                length: value.len(),
            },
        )?)),
        TLV_MAX_FRAME => Ok(Tlv::MaxFrame(read_u32(value, ty)?)),
        // `expected_len` and this match list the same assigned types.
        _ => Err(FrameError::KnownTlvAsRaw { ty }),
    }
}

fn encode_one(tlv: &Tlv, out: &mut Vec<u8>) -> Result<(), FrameError> {
    match tlv {
        Tlv::Addr4 { addr, prefix } => {
            check_prefix(TLV_ADDR4, *prefix, 32)?;
            let mut value = [0u8; 5];
            value[..4].copy_from_slice(&addr.octets());
            value[4] = *prefix;
            push_tlv(out, TLV_ADDR4, &value)
        }
        Tlv::Addr6 { addr, prefix } => {
            check_prefix(TLV_ADDR6, *prefix, 128)?;
            let mut value = [0u8; 17];
            value[..16].copy_from_slice(&addr.octets());
            value[16] = *prefix;
            push_tlv(out, TLV_ADDR6, &value)
        }
        Tlv::Mtu(mtu) => push_tlv(out, TLV_MTU, &mtu.to_be_bytes()),
        Tlv::Dns4(addr) => push_tlv(out, TLV_DNS4, &addr.octets()),
        Tlv::Dns6(addr) => push_tlv(out, TLV_DNS6, &addr.octets()),
        Tlv::Route4 {
            dest,
            prefix,
            include,
        } => {
            check_prefix(TLV_ROUTE4, *prefix, 32)?;
            let mut value = [0u8; 6];
            value[..4].copy_from_slice(&dest.octets());
            value[4] = *prefix;
            value[5] = u8::from(*include);
            push_tlv(out, TLV_ROUTE4, &value)
        }
        Tlv::Route6 {
            dest,
            prefix,
            include,
        } => {
            check_prefix(TLV_ROUTE6, *prefix, 128)?;
            let mut value = [0u8; 18];
            value[..16].copy_from_slice(&dest.octets());
            value[16] = *prefix;
            value[17] = u8::from(*include);
            push_tlv(out, TLV_ROUTE6, &value)
        }
        Tlv::Keepalive(ms) => push_tlv(out, TLV_KEEPALIVE, &ms.to_be_bytes()),
        Tlv::IdleTimeout(ms) => push_tlv(out, TLV_IDLE_TIMEOUT, &ms.to_be_bytes()),
        Tlv::SessionId(id) => push_tlv(out, TLV_SESSION_ID, id),
        Tlv::MaxFrame(limit) => push_tlv(out, TLV_MAX_FRAME, &limit.to_be_bytes()),
        Tlv::Raw { ty, value } => {
            if is_known_tlv(*ty) {
                return Err(FrameError::KnownTlvAsRaw { ty: *ty });
            }
            push_tlv(out, *ty, value)
        }
    }
}

const fn expected_len(ty: u16) -> Option<usize> {
    Some(match ty {
        TLV_ADDR4 => 5,
        TLV_ADDR6 => 17,
        TLV_MTU => 2,
        TLV_DNS4 => 4,
        TLV_DNS6 => 16,
        TLV_ROUTE4 => 6,
        TLV_ROUTE6 => 18,
        TLV_KEEPALIVE | TLV_IDLE_TIMEOUT | TLV_MAX_FRAME => 4,
        TLV_SESSION_ID => 16,
        _ => return None,
    })
}

fn push_tlv(out: &mut Vec<u8>, ty: u16, value: &[u8]) -> Result<(), FrameError> {
    let len = u16::try_from(value.len()).map_err(|_| FrameError::TlvValueTooLong {
        ty,
        length: value.len(),
    })?;
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn check_prefix(ty: u16, prefix: u8, max: u8) -> Result<(), FrameError> {
    if prefix > max {
        Err(FrameError::BadPrefix { ty, prefix })
    } else {
        Ok(())
    }
}

fn route_include(ty: u16, flag: u8) -> Result<bool, FrameError> {
    match flag {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(FrameError::BadRouteFlag { ty, flag }),
    }
}

fn byte_at(value: &[u8], index: usize, ty: u16) -> Result<u8, FrameError> {
    value.get(index).copied().ok_or(FrameError::BadTlvLength {
        ty,
        length: value.len(),
    })
}

fn ipv4_at(value: &[u8]) -> Option<Ipv4Addr> {
    copy_prefix::<4>(value).map(Ipv4Addr::from)
}

fn ipv6_at(value: &[u8]) -> Option<Ipv6Addr> {
    copy_prefix::<16>(value).map(Ipv6Addr::from)
}

fn ipv4_exact(value: &[u8], ty: u16) -> Result<Ipv4Addr, FrameError> {
    copy_exact::<4>(value)
        .map(Ipv4Addr::from)
        .ok_or(FrameError::BadTlvLength {
            ty,
            length: value.len(),
        })
}

fn ipv6_exact(value: &[u8], ty: u16) -> Result<Ipv6Addr, FrameError> {
    copy_exact::<16>(value)
        .map(Ipv6Addr::from)
        .ok_or(FrameError::BadTlvLength {
            ty,
            length: value.len(),
        })
}

fn read_u16(value: &[u8], ty: u16) -> Result<u16, FrameError> {
    copy_exact::<2>(value)
        .map(u16::from_be_bytes)
        .ok_or(FrameError::BadTlvLength {
            ty,
            length: value.len(),
        })
}

fn read_u32(value: &[u8], ty: u16) -> Result<u32, FrameError> {
    copy_exact::<4>(value)
        .map(u32::from_be_bytes)
        .ok_or(FrameError::BadTlvLength {
            ty,
            length: value.len(),
        })
}
