//! Failures of the QUIC and HTTP/3 transport.
//!
//! Display text is for logs. It does not include TUN payloads, exporter
//! output, or certificate bytes.

use thiserror::Error;

/// Why a QUIC or HTTP/3 operation failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The UDP endpoint could not be created or bound.
    #[error("QUIC endpoint failed: {detail}")]
    Endpoint {
        /// I/O error text.
        detail: String,
    },

    /// `QuicServerConfig::try_from` rejected the rustls config, or the
    /// config is not one this crate will use for QUIC.
    #[error("TLS config cannot be used for QUIC: {detail}")]
    TlsConfig {
        /// quinn or rustls error text.
        detail: String,
    },

    /// `max_early_data_size` was not 0. 0-RTT stays off.
    #[error("0-RTT is enabled on the QUIC server config")]
    ZeroRttEnabled,

    /// `send_half_rtt_data` was set. This crate does not send 0.5-RTT data.
    #[error("server half-RTT data is enabled on the QUIC server config")]
    HalfRttEnabled,

    /// The handshake did not finish within `handshake_timeout`.
    #[error("QUIC handshake timed out")]
    HandshakeTimeout,

    /// The QUIC connection failed or was closed.
    #[error("QUIC connection failed: {detail}")]
    Connection {
        /// quinn error text.
        detail: String,
    },

    /// HTTP/3 rejected the request, the response, or a datagram.
    #[error("HTTP/3 failed: {detail}")]
    H3 {
        /// h3 or h3-datagram error text.
        detail: String,
    },

    /// [`astp_frame::FrameReader`] returned an error. The connection is closed.
    #[error("frame error: {0}")]
    Frame(astp_frame::FrameError),

    /// A frame did not finish within `frame_read_timeout`. The connection is closed.
    #[error("frame read timed out")]
    FrameReadTimeout,

    /// The tunnel stream is finished, or datagrams for it are no longer accepted.
    #[error("tunnel closed")]
    TunnelClosed,

    /// The TLS exporter could not produce a channel binding.
    #[error("channel binding failed: {0}")]
    Binding(#[from] astp_crypto::CryptoError),

    /// The accept loop or the HTTP/3 driver has stopped.
    #[error("transport is closed")]
    Closed,

    /// A caller-supplied address, name, or limit cannot be used.
    #[error("invalid argument: {detail}")]
    Invalid {
        /// What was rejected. Not key material.
        detail: String,
    },
}
