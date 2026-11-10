//! Encode and decode one complete frame.

use astp_types::{
    FLAG_KEY_EPOCH, FLAG_PAD, FRAME_CONFIG, FRAME_CONFIG_ACK, FRAME_DISCONNECT, FRAME_HEADER_LEN,
    FRAME_PADDING, FRAME_PING, FRAME_PONG, FRAME_ROUTE_UPDATE, FRAME_TUN_IPV4, FRAME_TUN_IPV6,
    FRAME_WINDOW, MAX_FRAME_LENGTH,
};

use crate::config::{
    decode_config, decode_tlv_list, encode_config, encode_tlv_list, encoded_tlvs_len,
};
use crate::error::FrameError;
use crate::header::{push_header, DecodeLimits, RawHeader};
use crate::types::{decode_ipv4, decode_ipv6, validate_ipv4, validate_ipv6, Frame, FrameBody};
use crate::wire::{copy_at, copy_exact, copy_prefix};

/// Encode one frame and append it to `out`.
///
/// `pad_octets` is the raw encode path: `None` leaves `PAD` clear, `Some`
/// sets `PAD` and writes those octets plus a big-endian `pad_len`. The
/// octets are stored as given (tests pass a fixed pattern). This function
/// does not apply the camouflage profile; use [`crate::encode_camouflage`]
/// for that.
///
/// On error, `out` is left unchanged.
///
/// # Errors
///
/// Returns [`FrameError`] when the body is not valid for its type, the
/// padding does not fit in a `u16`, or the payload would exceed 65535 bytes.
pub fn encode_to(
    frame: &Frame,
    pad_octets: Option<&[u8]>,
    out: &mut Vec<u8>,
) -> Result<(), FrameError> {
    let encoded = assemble(frame, pad_octets)?;
    out.extend_from_slice(&encoded);
    Ok(())
}

/// Encode one frame into a new buffer. See [`encode_to`].
///
/// # Errors
///
/// Same as [`encode_to`].
pub fn encode(frame: &Frame, pad_octets: Option<&[u8]>) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::new();
    encode_to(frame, pad_octets, &mut out)?;
    Ok(out)
}

/// Decode one frame that occupies `buf` exactly.
///
/// Uses [`DecodeLimits::DEFAULT`] (max `Length` 65535).
///
/// # Errors
///
/// Returns [`FrameError`] for a short buffer, a bad header, bad padding,
/// or a body that fails the checks for its type. Extra bytes after the
/// frame are [`FrameError::TrailingBytes`].
pub fn decode(buf: &[u8]) -> Result<Frame, FrameError> {
    decode_with(buf, DecodeLimits::DEFAULT)
}

/// Decode one frame with a caller-supplied length ceiling.
///
/// Check order once 8 header bytes are present: version, reserved flags,
/// `Length` against [`DecodeLimits::effective_max`], then “the buffer is
/// exactly `8 + Length` bytes”, then padding, then the key-epoch byte,
/// then the type. An illegal `Length` is rejected before the payload is
/// required to be present, so a 65536-byte claim does not allocate.
/// [`crate::FrameReader`] checks `Length` first. A version or flag error
/// on that stream does not read the payload either: the reader is
/// poisoned and the connection must be closed.
///
/// # Errors
///
/// Same as [`decode`], plus [`FrameError::FrameTooLong`] when `Length`
/// exceeds the tightened limit.
pub fn decode_with(buf: &[u8], limits: DecodeLimits) -> Result<Frame, FrameError> {
    let header = RawHeader::parse(buf)?;
    header.check(limits)?;
    let payload = payload_slice(buf, header.length, limits)?;
    let content = if header.flags & FLAG_PAD != 0 {
        strip_pad(payload)?
    } else {
        payload
    };
    let (key_epoch, body_bytes) = if header.flags & FLAG_KEY_EPOCH != 0 {
        match content.split_first() {
            Some((epoch, rest)) => (Some(*epoch), rest),
            None => return Err(FrameError::EmptyKeyEpoch),
        }
    } else {
        (None, content)
    };
    let body = decode_body(header.ty, body_bytes)?;
    Ok(Frame { key_epoch, body })
}

pub(crate) fn encoded_content(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    let mut content = Vec::new();
    if let Some(epoch) = frame.key_epoch {
        content.push(epoch);
    }
    let start = content.len();
    encode_body(&frame.body, &mut content)?;
    debug_assert_eq!(
        content.len().saturating_sub(start),
        body_len(&frame.body).unwrap_or(usize::MAX)
    );
    Ok(content)
}

/// Length of the unpadded content, including the key-epoch byte.
///
/// Same validation as [`encoded_content`], without copying the body.
pub(crate) fn encoded_content_len(frame: &Frame) -> Result<usize, FrameError> {
    let epoch = usize::from(frame.key_epoch.is_some());
    Ok(epoch.saturating_add(body_len(&frame.body)?))
}

fn body_len(body: &FrameBody) -> Result<usize, FrameError> {
    match body {
        FrameBody::Padding => Ok(0),
        FrameBody::Ping(_) | FrameBody::Pong(_) => Ok(8),
        FrameBody::TunIpv4(packet) => {
            validate_ipv4(packet.as_bytes())?;
            Ok(packet.as_bytes().len())
        }
        FrameBody::TunIpv6(packet) => {
            validate_ipv6(packet.as_bytes())?;
            Ok(packet.as_bytes().len())
        }
        FrameBody::Config(cfg) => Ok(4usize.saturating_add(encoded_tlvs_len(&cfg.tlvs)?)),
        FrameBody::ConfigAck { .. } => Ok(5),
        FrameBody::RouteUpdate(update) => encoded_tlvs_len(&update.tlvs),
        FrameBody::Disconnect { reason, .. } => Ok(2usize.saturating_add(reason.len())),
        FrameBody::Window { .. } => Ok(4),
    }
}

// Payload length after padding. Validation errors match `assemble`
// and are returned before the body is copied.
fn declared_payload_len(frame: &Frame, pad_octets: Option<&[u8]>) -> Result<usize, FrameError> {
    let mut len = encoded_content_len(frame)?;
    if let Some(octets) = pad_octets {
        u16::try_from(octets.len()).map_err(|_| FrameError::BadPadding)?;
        len = len.saturating_add(octets.len()).saturating_add(2);
    }
    Ok(len)
}

fn frame_too_long(length: usize) -> FrameError {
    FrameError::FrameTooLong {
        length: u32::try_from(length).unwrap_or(u32::MAX),
        max_frame: MAX_FRAME_LENGTH,
    }
}

fn assemble(frame: &Frame, pad_octets: Option<&[u8]>) -> Result<Vec<u8>, FrameError> {
    // Refuse before copying a body that cannot fit. Validation errors
    // (bad prefix, bad IP, raw TLV of a known type, pad that does not
    // fit in a `u16`) still win over `FrameTooLong`.
    let declared = declared_payload_len(frame, pad_octets)?;
    if declared > usize::try_from(MAX_FRAME_LENGTH).unwrap_or(usize::MAX) {
        return Err(frame_too_long(declared));
    }
    let mut payload = encoded_content(frame)?;
    let mut flags = 0u16;
    if frame.key_epoch.is_some() {
        flags |= FLAG_KEY_EPOCH;
    }
    if let Some(octets) = pad_octets {
        let pad_len = u16::try_from(octets.len()).map_err(|_| FrameError::BadPadding)?;
        flags |= FLAG_PAD;
        payload.extend_from_slice(octets);
        payload.extend_from_slice(&pad_len.to_be_bytes());
    }
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    if length > MAX_FRAME_LENGTH {
        return Err(FrameError::FrameTooLong {
            length,
            max_frame: MAX_FRAME_LENGTH,
        });
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(FRAME_HEADER_LEN.saturating_add(payload.len()))
        .map_err(|_| FrameError::Alloc {
            length: FRAME_HEADER_LEN.saturating_add(payload.len()),
        })?;
    push_header(&mut encoded, frame.body.type_code(), flags, length);
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

fn payload_slice(buf: &[u8], length: u32, limits: DecodeLimits) -> Result<&[u8], FrameError> {
    let length_usize = usize::try_from(length).map_err(|_| FrameError::FrameTooLong {
        length,
        max_frame: limits.effective_max(),
    })?;
    let total = FRAME_HEADER_LEN
        .checked_add(length_usize)
        .ok_or(FrameError::FrameTooLong {
            length,
            max_frame: limits.effective_max(),
        })?;
    if buf.len() < total {
        return Err(FrameError::Incomplete);
    }
    if buf.len() > total {
        return Err(FrameError::TrailingBytes {
            extra: buf.len() - total,
        });
    }
    buf.get(FRAME_HEADER_LEN..total)
        .ok_or(FrameError::Incomplete)
}

fn strip_pad(payload: &[u8]) -> Result<&[u8], FrameError> {
    if payload.len() < 2 {
        return Err(FrameError::BadPadding);
    }
    let at = payload.len() - 2;
    let trailer = copy_at::<2>(payload, at).ok_or(FrameError::BadPadding)?;
    let pad_len = usize::from(u16::from_be_bytes(trailer));
    let tail = pad_len.checked_add(2).ok_or(FrameError::BadPadding)?;
    if tail > payload.len() {
        return Err(FrameError::BadPadding);
    }
    let content_end = payload.len() - tail;
    payload.get(..content_end).ok_or(FrameError::BadPadding)
}

fn decode_body(ty: u8, body: &[u8]) -> Result<FrameBody, FrameError> {
    // `0x40..=0x4F` is reserved for a later split-path and falls through
    // to the unknown-type error, same as `0x99`.
    match ty {
        FRAME_PADDING => {
            if body.is_empty() {
                Ok(FrameBody::Padding)
            } else {
                Err(FrameError::BadBodyLength {
                    kind: "PADDING",
                    length: body.len(),
                })
            }
        }
        FRAME_PING => Ok(FrameBody::Ping(exact_8(body, "PING")?)),
        FRAME_PONG => Ok(FrameBody::Pong(exact_8(body, "PONG")?)),
        FRAME_TUN_IPV4 => Ok(FrameBody::TunIpv4(decode_ipv4(body)?)),
        FRAME_TUN_IPV6 => Ok(FrameBody::TunIpv6(decode_ipv6(body)?)),
        FRAME_CONFIG => Ok(FrameBody::Config(decode_config(body)?)),
        FRAME_CONFIG_ACK => {
            let bytes = copy_exact::<5>(body).ok_or(FrameError::BadBodyLength {
                kind: "CONFIG_ACK",
                length: body.len(),
            })?;
            let cfg_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok(FrameBody::ConfigAck {
                cfg_id,
                code: bytes[4],
            })
        }
        FRAME_ROUTE_UPDATE => Ok(FrameBody::RouteUpdate(crate::config::RouteUpdate {
            tlvs: decode_tlv_list(body)?,
        })),
        FRAME_DISCONNECT => {
            let code_bytes = copy_prefix::<2>(body).ok_or(FrameError::BadBodyLength {
                kind: "DISCONNECT",
                length: body.len(),
            })?;
            let code = u16::from_be_bytes(code_bytes);
            let reason_bytes = body.get(2..).ok_or(FrameError::BadBodyLength {
                kind: "DISCONNECT",
                length: body.len(),
            })?;
            let reason = std::str::from_utf8(reason_bytes)
                .map_err(|_| FrameError::InvalidUtf8)?
                .to_owned();
            Ok(FrameBody::Disconnect { code, reason })
        }
        FRAME_WINDOW => {
            let credit =
                u32::from_be_bytes(copy_exact::<4>(body).ok_or(FrameError::BadBodyLength {
                    kind: "WINDOW",
                    length: body.len(),
                })?);
            Ok(FrameBody::Window { credit })
        }
        _ => Err(FrameError::UnknownType { ty }),
    }
}

fn exact_8(body: &[u8], kind: &'static str) -> Result<[u8; 8], FrameError> {
    copy_exact::<8>(body).ok_or(FrameError::BadBodyLength {
        kind,
        length: body.len(),
    })
}

fn encode_body(body: &FrameBody, out: &mut Vec<u8>) -> Result<(), FrameError> {
    match body {
        FrameBody::Padding => Ok(()),
        FrameBody::Ping(bytes) | FrameBody::Pong(bytes) => {
            out.extend_from_slice(bytes);
            Ok(())
        }
        FrameBody::TunIpv4(packet) => {
            validate_ipv4(packet.as_bytes())?;
            out.extend_from_slice(packet.as_bytes());
            Ok(())
        }
        FrameBody::TunIpv6(packet) => {
            validate_ipv6(packet.as_bytes())?;
            out.extend_from_slice(packet.as_bytes());
            Ok(())
        }
        FrameBody::Config(cfg) => encode_config(cfg, out),
        FrameBody::ConfigAck { cfg_id, code } => {
            out.extend_from_slice(&cfg_id.to_be_bytes());
            out.push(*code);
            Ok(())
        }
        FrameBody::RouteUpdate(update) => encode_tlv_list(&update.tlvs, out),
        FrameBody::Disconnect { code, reason } => {
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(reason.as_bytes());
            Ok(())
        }
        FrameBody::Window { credit } => {
            out.extend_from_slice(&credit.to_be_bytes());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{body_len, decode, encode_body, encoded_content, encoded_content_len};
    use crate::config::{Config, RouteUpdate, Tlv};
    use crate::types::{Frame, FrameBody, Ipv4Packet, Ipv6Packet};

    #[test]
    fn random_bytes_do_not_panic() {
        let mut state = 0x1234_5678u32;
        for _ in 0..300 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = (state % 96) as usize;
            let mut buf = vec![0u8; len];
            for byte in &mut buf {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 16) as u8;
            }
            let _ = decode(&buf);
        }
    }

    #[test]
    fn body_len_matches_encode_body() {
        let mut ipv4 = vec![0u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
        let ipv4 = Ipv4Packet::new(ipv4).unwrap();
        let mut ipv6 = vec![0u8; 40];
        ipv6[0] = 0x60;
        let ipv6 = Ipv6Packet::new(ipv6).unwrap();
        let tlvs = vec![
            Tlv::Addr4 {
                addr: Ipv4Addr::LOCALHOST,
                prefix: 32,
            },
            Tlv::Raw {
                ty: 0x000C,
                value: vec![1, 2, 3],
            },
        ];
        let bodies = vec![
            FrameBody::Padding,
            FrameBody::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
            FrameBody::Pong([8, 7, 6, 5, 4, 3, 2, 1]),
            FrameBody::TunIpv4(ipv4),
            FrameBody::TunIpv6(ipv6),
            FrameBody::Config(Config {
                cfg_id: 9,
                tlvs: tlvs.clone(),
            }),
            FrameBody::ConfigAck { cfg_id: 9, code: 1 },
            FrameBody::RouteUpdate(RouteUpdate { tlvs }),
            FrameBody::Disconnect {
                code: 4,
                reason: "bye".to_owned(),
            },
            FrameBody::Disconnect {
                code: 4,
                reason: "x".repeat(100),
            },
            FrameBody::Window { credit: 32 },
        ];
        for body in &bodies {
            let mut buf = Vec::new();
            encode_body(body, &mut buf).unwrap();
            assert_eq!(buf.len(), body_len(body).unwrap(), "{body:?}");
        }
        let frame = Frame {
            key_epoch: Some(3),
            body: FrameBody::Ping([0; 8]),
        };
        let encoded = encoded_content(&frame).unwrap();
        assert_eq!(encoded.len(), encoded_content_len(&frame).unwrap());
    }
}
