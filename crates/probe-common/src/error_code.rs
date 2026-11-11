//! Error classification (section 8 of the spec).
//!
//! A code names what the probe observed, not why it happened: `tcp_timeout`
//! means no answer arrived in time, not that a DPI box dropped the packet.

use serde::{Deserialize, Serialize};
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    DnsFailure,
    TcpTimeout,
    TcpRefused,
    TcpReset,
    TlsHandshakeFailed,
    TlsCertificateError,
    QuicTimeout,
    HttpProtocolError,
    ApplicationTimeout,
    RemoteClosed,
    LocalNetworkUnavailable,
    /// The probe or this build cannot run the test (never reported as success).
    Unsupported,
    Unknown,
}

impl ErrorCode {
    pub const ALL: [ErrorCode; 13] = [
        ErrorCode::DnsFailure,
        ErrorCode::TcpTimeout,
        ErrorCode::TcpRefused,
        ErrorCode::TcpReset,
        ErrorCode::TlsHandshakeFailed,
        ErrorCode::TlsCertificateError,
        ErrorCode::QuicTimeout,
        ErrorCode::HttpProtocolError,
        ErrorCode::ApplicationTimeout,
        ErrorCode::RemoteClosed,
        ErrorCode::LocalNetworkUnavailable,
        ErrorCode::Unsupported,
        ErrorCode::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::DnsFailure => "dns_failure",
            ErrorCode::TcpTimeout => "tcp_timeout",
            ErrorCode::TcpRefused => "tcp_refused",
            ErrorCode::TcpReset => "tcp_reset",
            ErrorCode::TlsHandshakeFailed => "tls_handshake_failed",
            ErrorCode::TlsCertificateError => "tls_certificate_error",
            ErrorCode::QuicTimeout => "quic_timeout",
            ErrorCode::HttpProtocolError => "http_protocol_error",
            ErrorCode::ApplicationTimeout => "application_timeout",
            ErrorCode::RemoteClosed => "remote_closed",
            ErrorCode::LocalNetworkUnavailable => "local_network_unavailable",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Unknown => "unknown",
        }
    }

    /// Classify an I/O error raised while a TCP connection was being opened.
    pub fn from_connect_error(e: &io::Error) -> ErrorCode {
        match e.kind() {
            io::ErrorKind::TimedOut => ErrorCode::TcpTimeout,
            io::ErrorKind::ConnectionRefused => ErrorCode::TcpRefused,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                ErrorCode::TcpReset
            }
            io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::AddrNotAvailable => ErrorCode::LocalNetworkUnavailable,
            _ => ErrorCode::Unknown,
        }
    }

    /// Classify an I/O error raised on an established stream.
    pub fn from_stream_error(e: &io::Error) -> ErrorCode {
        match e.kind() {
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                ErrorCode::TcpReset
            }
            io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe => ErrorCode::RemoteClosed,
            io::ErrorKind::TimedOut => ErrorCode::ApplicationTimeout,
            io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown => ErrorCode::LocalNetworkUnavailable,
            _ => ErrorCode::Unknown,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_names_match_as_str() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    #[test]
    fn classifies_connect_errors() {
        let e = |k| io::Error::new(k, "x");
        assert_eq!(
            ErrorCode::from_connect_error(&e(io::ErrorKind::ConnectionRefused)),
            ErrorCode::TcpRefused
        );
        assert_eq!(
            ErrorCode::from_connect_error(&e(io::ErrorKind::TimedOut)),
            ErrorCode::TcpTimeout
        );
        assert_eq!(
            ErrorCode::from_connect_error(&e(io::ErrorKind::ConnectionReset)),
            ErrorCode::TcpReset
        );
        assert_eq!(
            ErrorCode::from_connect_error(&e(io::ErrorKind::NetworkUnreachable)),
            ErrorCode::LocalNetworkUnavailable
        );
        assert_eq!(
            ErrorCode::from_connect_error(&e(io::ErrorKind::Other)),
            ErrorCode::Unknown
        );
    }

    #[test]
    fn classifies_stream_errors() {
        let e = |k| io::Error::new(k, "x");
        assert_eq!(
            ErrorCode::from_stream_error(&e(io::ErrorKind::UnexpectedEof)),
            ErrorCode::RemoteClosed
        );
        assert_eq!(
            ErrorCode::from_stream_error(&e(io::ErrorKind::ConnectionReset)),
            ErrorCode::TcpReset
        );
    }
}
