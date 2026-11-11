//! ASTP-M TLS 1.3 configuration and the channel-bound authenticator.
//!
//! This crate does not open sockets, speak HTTP, or define a production
//! credential format. QUIC and TCP listeners are later tasks. The network
//! probe is a different set of crates and is not used here.
//!
//! # Invariants
//!
//! * TLS 1.3 only. The workspace `rustls` crate still enables its `tls12`
//!   feature because the probe needs it. Protocol versions are restricted
//!   in each config this crate builds.
//! * No 0-RTT. Servers set `max_early_data_size` to 0 and
//!   `send_half_rtt_data` to false. Clients set `enable_early_data` to false.
//! * The server name is verified. Nothing in this crate turns certificate
//!   or name checks off. An IP literal dial host without `tls_server_name`
//!   is a configuration error.
//! * ALPN follows the transport: QUIC configs carry [`QUIC_ALPN`] (`h3`),
//!   TLS-over-TCP configs carry [`TCP_ALPN`] (`h2`), on server and client
//!   alike. `astp-m/1` is not offered.
//! * [`client_config`] returns the config with the server name it verifies
//!   ([`ClientTlsConfig`]); transports take the name from there.
//! * mTLS is off unless [`ClientAuth::Required`] is set.
//! * Our own keys (the server certificate and the optional mTLS client
//!   key) must be Ed25519 or ECDSA P-256. Peer chains are not filtered,
//!   so a public CA may still use RSA or P-384.
//! * Channel binding is the TLS 1.3 exporter [`CHANNEL_BINDING_LABEL`],
//!   [`CHANNEL_BINDING_LEN`] bytes, with an empty context (`None`).
//!
//! ```
//! use astp_crypto::{CHANNEL_BINDING_LABEL, CHANNEL_BINDING_LEN};
//!
//! assert_eq!(CHANNEL_BINDING_LABEL, "EXPORTER-ASTP-M auth v1");
//! assert_eq!(CHANNEL_BINDING_LEN, 32);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod auth;
mod tls;

pub use auth::{
    channel_binding, AuthError, Authenticator, ChannelBinding, ClientId, TlsSession,
    CHANNEL_BINDING_LABEL, CHANNEL_BINDING_LEN,
};
pub use tls::{
    client_config, server_config, AlpnMode, ClientAuth, ClientOptions, ClientTlsConfig,
    CryptoError, Identity, ServerOptions, TrustAnchors, QUIC_ALPN, TCP_ALPN,
};

#[cfg(any(test, feature = "test-util"))]
pub use auth::StaticTokenAuthenticator;

#[cfg(test)]
#[allow(missing_docs)]
#[path = "../tests/suite/tls.rs"]
mod tls_tests;
