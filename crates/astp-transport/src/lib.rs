//! ASTP-M v1 transport (`docs/design/session.md`).
//!
//! A session is one HTTP request whose request body carries client→server
//! frames and whose response body carries server→client frames:
//!
//! - TCP: TLS 1.3 with ALPN `h2`, HTTP/2 ([`serve_tcp`], [`connect_tcp`]);
//! - QUIC: ALPN `h3`, HTTP/3 ([`serve_quic`], [`connect_quic`]).
//!
//! The request is `POST <session_path>` with
//! `authorization: Bearer <credential>`; the credential is bound to the
//! connection's TLS exporter (`astp-crypto`). Every request that is not an
//! authenticated session gets the [`Decoy`] site, the same answer whatever
//! was wrong with it.
//!
//! The transport hands each session over as a [`SessionIo`] byte stream;
//! framing and session state are `astp-session`'s business.

#![forbid(unsafe_code)]

mod decoy;
mod io;
mod quic;
mod tcp;

pub use decoy::Decoy;
pub use io::{ByteReader, ByteWriter, SessionIo};
pub use quic::{connect_quic, quic_endpoint_server, serve_quic};
pub use tcp::{connect_tcp, serve_tcp, ServerOptions};

use std::net::SocketAddr;

/// An authenticated session, handed from a listener to its owner.
pub struct Accepted {
    pub client: astp_crypto::ClientId,
    pub peer: SocketAddr,
    /// `"h2"` or `"h3"`.
    pub transport: &'static str,
    pub io: SessionIo,
}

/// Why a client could not open a session.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("QUIC: {0}")]
    Quic(String),
    #[error("protocol: {0}")]
    Protocol(String),
    /// The server answered something other than 200: from the client's
    /// side indistinguishable from a wrong key, path or server.
    #[error("server did not accept the session (HTTP {0})")]
    Refused(u16),
    #[error("timed out")]
    Timeout,
}

/// Aborts the task it holds when dropped: the HTTP connection of a client
/// session lives exactly as long as the session.
#[derive(Debug)]
pub struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) const AUTH_SCHEME: &str = "Bearer ";

pub(crate) fn auth_header(token: &str) -> String {
    format!("{AUTH_SCHEME}{token}")
}

/// `host[:port]` for the request URI, from the verified TLS name.
pub(crate) fn authority(name: &rustls::pki_types::ServerName<'_>, port: u16) -> String {
    let host = match name {
        rustls::pki_types::ServerName::DnsName(d) => d.as_ref().to_owned(),
        rustls::pki_types::ServerName::IpAddress(ip) => match std::net::IpAddr::from(*ip) {
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            v4 => v4.to_string(),
        },
        _ => "localhost".to_owned(),
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests;
