//! Shared ASTP-M constants.
//!
//! This is not the network probe. Frame encode and decode live in
//! `astp-frame`. Transport and TLS are not implemented in this crate.
//!
//! The numeric identifiers below follow spec draft 0.3 §5. They are not a
//! codec. Types `0x40..=0x4F` and TLV `0x000C` / `0x000D` are reserved for
//! a possible later split-path and are not assigned to any v1 feature.

/// Protocol name.
pub const PROTOCOL_NAME: &str = "ASTP-M";

/// Application frame version (`0x01`).
pub const FRAME_VERSION: u8 = 1;

/// Size of the frame header in bytes.
pub const FRAME_HEADER_LEN: usize = 8;

/// Largest `Length` value accepted in v1, inclusive.
///
/// The field is a `u32`, but any value above this one is a parse error.
pub const MAX_FRAME_LENGTH: u32 = 65_535;

/// `Flags` bit 0: padding is present at the end of the payload.
pub const FLAG_PAD: u16 = 0x0001;

/// `Flags` bit 1: the first content byte is a key epoch.
pub const FLAG_KEY_EPOCH: u16 = 0x0002;

/// `Flags` bits 2–15. They must be zero on the wire.
pub const FLAG_RESERVED_MASK: u16 = 0xFFFC;

/// `PADDING` (`0x00`). Body is empty.
pub const FRAME_PADDING: u8 = 0x00;

/// `PING` (`0x01`). Body is exactly 8 opaque bytes.
pub const FRAME_PING: u8 = 0x01;

/// `PONG` (`0x02`). Body is exactly 8 opaque bytes.
pub const FRAME_PONG: u8 = 0x02;

/// `TUN_IPV4` (`0x10`). Body is one raw IPv4 packet.
pub const FRAME_TUN_IPV4: u8 = 0x10;

/// `TUN_IPV6` (`0x11`). Body is one raw IPv6 packet.
pub const FRAME_TUN_IPV6: u8 = 0x11;

/// `CONFIG` (`0x20`). Body is `cfg_id` plus TLV records.
pub const FRAME_CONFIG: u8 = 0x20;

/// `CONFIG_ACK` (`0x21`). Body is `cfg_id` plus one status byte.
pub const FRAME_CONFIG_ACK: u8 = 0x21;

/// `ROUTE_UPDATE` (`0x22`). Body is TLV records without `cfg_id`.
pub const FRAME_ROUTE_UPDATE: u8 = 0x22;

/// `DISCONNECT` (`0x30`). Body is a code plus a UTF-8 reason.
pub const FRAME_DISCONNECT: u8 = 0x30;

/// `WINDOW` (`0x31`). Body is a `u32` credit.
pub const FRAME_WINDOW: u8 = 0x31;

/// First type code reserved for a future split-path, inclusive.
///
/// The whole range [`FRAME_RESERVED_SPLIT_FIRST`]..=[`FRAME_RESERVED_SPLIT_LAST`]
/// is rejected as an unknown type in v1.
pub const FRAME_RESERVED_SPLIT_FIRST: u8 = 0x40;

/// Last type code reserved for a future split-path, inclusive.
pub const FRAME_RESERVED_SPLIT_LAST: u8 = 0x4F;

/// TLV `addr4` (`0x0001`). Value is 4 address bytes plus a prefix.
pub const TLV_ADDR4: u16 = 0x0001;

/// TLV `addr6` (`0x0002`). Value is 16 address bytes plus a prefix.
pub const TLV_ADDR6: u16 = 0x0002;

/// TLV `mtu` (`0x0003`). Value is a `u16`.
pub const TLV_MTU: u16 = 0x0003;

/// TLV `dns4` (`0x0004`). Value is one IPv4 address.
pub const TLV_DNS4: u16 = 0x0004;

/// TLV `dns6` (`0x0005`). Value is one IPv6 address.
pub const TLV_DNS6: u16 = 0x0005;

/// TLV `route4` (`0x0006`). Value is dest, prefix, and include/exclude.
pub const TLV_ROUTE4: u16 = 0x0006;

/// TLV `route6` (`0x0007`). Value is dest, prefix, and include/exclude.
pub const TLV_ROUTE6: u16 = 0x0007;

/// TLV `keepalive` (`0x0008`). Value is milliseconds as a `u32`.
pub const TLV_KEEPALIVE: u16 = 0x0008;

/// TLV `idle_timeout` (`0x0009`). Value is milliseconds as a `u32`.
pub const TLV_IDLE_TIMEOUT: u16 = 0x0009;

/// TLV `session_id` (`0x000A`). Value is 16 bytes.
pub const TLV_SESSION_ID: u16 = 0x000A;

/// TLV `max_frame` (`0x000B`). Value is a `u32`.
pub const TLV_MAX_FRAME: u16 = 0x000B;

/// TLV number reserved for a future split-path field.
///
/// Not assigned in v1. A decoder keeps it as an unknown raw TLV.
pub const TLV_RESERVED_SPLIT_C: u16 = 0x000C;

/// TLV number reserved for a future split-path field.
///
/// Not assigned in v1. A decoder keeps it as an unknown raw TLV.
pub const TLV_RESERVED_SPLIT_D: u16 = 0x000D;

/// Camouflage profile v1: wire-size step, in bytes (spec draft 0.3 §5.2).
pub const DEFAULT_PADDING_STEP: u32 = 64;

/// Camouflage profile v1: minimum frame size on the wire, including the header.
pub const DEFAULT_MIN_WIRE_SIZE: u32 = 64;

/// Camouflage profile v1: maximum padding octets, not counting the `pad_len` trailer.
pub const DEFAULT_MAX_PAD: u16 = 255;

/// Public ALPN on the QUIC path. This is a wire default.
pub const ALPN_H3: &[u8] = b"h3";

/// Public ALPN on the TCP + TLS path. This is a wire default.
pub const ALPN_H2: &[u8] = b"h2";

/// Spare internal token for tests and an explicit config.
/// Not the public default ALPN.
pub const ALPN_ASTP_M: &[u8] = b"astp-m/1";

#[cfg(test)]
mod tests {
    use super::{
        ALPN_ASTP_M, ALPN_H2, ALPN_H3, DEFAULT_MAX_PAD, DEFAULT_MIN_WIRE_SIZE,
        DEFAULT_PADDING_STEP, FLAG_KEY_EPOCH, FLAG_PAD, FLAG_RESERVED_MASK, FRAME_HEADER_LEN,
        FRAME_RESERVED_SPLIT_FIRST, FRAME_RESERVED_SPLIT_LAST, FRAME_VERSION, MAX_FRAME_LENGTH,
        PROTOCOL_NAME, TLV_RESERVED_SPLIT_C, TLV_RESERVED_SPLIT_D,
    };

    #[test]
    fn public_alpn_is_h3_and_h2() {
        assert_eq!(PROTOCOL_NAME, "ASTP-M");
        assert_eq!(FRAME_VERSION, 1);
        assert_eq!(ALPN_H3, b"h3");
        assert_eq!(ALPN_H2, b"h2");
        assert_eq!(ALPN_ASTP_M, b"astp-m/1");
        assert_ne!(ALPN_ASTP_M, ALPN_H3);
        assert_ne!(ALPN_ASTP_M, ALPN_H2);
    }

    #[test]
    fn frame_limits_and_reserved_numbers_match_spec_0_3() {
        assert_eq!(FRAME_HEADER_LEN, 8);
        assert_eq!(MAX_FRAME_LENGTH, 65_535);
        assert_eq!(FLAG_PAD, 0x0001);
        assert_eq!(FLAG_KEY_EPOCH, 0x0002);
        assert_eq!(FLAG_RESERVED_MASK, 0xFFFC);
        assert_eq!(FLAG_PAD | FLAG_KEY_EPOCH | FLAG_RESERVED_MASK, 0xFFFF);
        assert_eq!(FRAME_RESERVED_SPLIT_FIRST, 0x40);
        assert_eq!(FRAME_RESERVED_SPLIT_LAST, 0x4F);
        assert_eq!(TLV_RESERVED_SPLIT_C, 0x000C);
        assert_eq!(TLV_RESERVED_SPLIT_D, 0x000D);
        assert_eq!(DEFAULT_PADDING_STEP, 64);
        assert_eq!(DEFAULT_MIN_WIRE_SIZE, 64);
        assert_eq!(DEFAULT_MAX_PAD, 255);
    }
}
