//! ASTP-M v1 session (`docs/design/session.md`).
//!
//! The session runs over any byte stream: inside the body pair of an
//! HTTP/2 or HTTP/3 request in production, over an in-memory pipe in
//! tests. It does no I/O of its own beyond that stream and two packet
//! channels to the local side, so it does not know about TUN devices or
//! sockets.
//!
//! 1. [`server_handshake`] / [`client_handshake`]: `CONFIG` and
//!    `CONFIG_ACK`.
//! 2. [`run`]: packets both ways, `PING`/`PONG` keepalive, idle timeout,
//!    `WINDOW` credit, `DISCONNECT`.

#![forbid(unsafe_code)]

mod params;
mod session;

pub use params::{
    route_tlvs, routes_of, Route, SessionParams, DEFAULT_IDLE_TIMEOUT, DEFAULT_KEEPALIVE,
    DEFAULT_MTU,
};
pub use session::{
    client_handshake, code, run, server_handshake, EndReason, Event, Link, Packet, Role,
    SessionError, Stats, INITIAL_WINDOW,
};

#[cfg(test)]
mod tests;
