//! Skeleton of shared ASTP-M constants.
//!
//! This is not the network probe. The frame codec, transport choice, and
//! TLS are not implemented in this crate.

/// Protocol name.
pub const PROTOCOL_NAME: &str = "ASTP-M";

/// Application frame version (`0x01`). This is not a codec.
pub const FRAME_VERSION: u8 = 1;

/// Public ALPN on the QUIC path. This is a wire default.
pub const ALPN_H3: &[u8] = b"h3";

/// Public ALPN on the TCP + TLS path. This is a wire default.
pub const ALPN_H2: &[u8] = b"h2";

/// Spare internal token for tests and an explicit config.
/// Not the public default ALPN.
pub const ALPN_ASTP_M: &[u8] = b"astp-m/1";

#[cfg(test)]
mod tests {
    use super::{ALPN_ASTP_M, ALPN_H2, ALPN_H3, FRAME_VERSION, PROTOCOL_NAME};

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
}
