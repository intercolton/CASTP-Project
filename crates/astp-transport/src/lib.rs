//! QUIC and HTTP/3 transport for ASTP-M.
//!
//! The listener speaks TLS 1.3 with ALPN `h3`. A negotiated `h2` (or any
//! other ALPN) is closed with application code 0 and an empty reason.
//! Channel binding is the same exporter as `astp-crypto`. The HTTP/3 tunnel
//! in this task is `POST /t`: frames on the body go through
//! [`astp_frame::FrameReader`], and HTTP datagrams are bound to that stream.
//!
//! This is not the network probe.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
#[path = "h3.rs"]
mod http3;
mod limits;
pub mod quic;

pub use error::TransportError;
pub use http3::{
    ClientTunnel, Http3Client, Http3Options, Http3Server, HttpResponse, ServerTunnel, TunnelInput,
};
pub use limits::QuicLimits;
pub use quic::{connect, Accepted, QuicClient, QuicServer};

/// Primary carrier for the QUIC tunnel after the task 4 measurement.
///
/// `true` means HTTP datagrams bound to `POST /t`. The stream body stays:
/// it is the HTTP/2 path, and the measurement did not retire it.
/// See `docs/architecture.md`.
pub const QUIC_PRIMARY_DATAGRAMS: bool = true;
