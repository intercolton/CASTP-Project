//! Channel binding and the [`Authenticator`] contract.
//!
//! No transport and no HTTP. A production credential format is a later task.
//! Every [`AuthError`] is for logs only: a remote peer must not be able to
//! tell the variants apart (the camouflage response is a later task).

use std::fmt;

use thiserror::Error;

use crate::tls::CryptoError;

/// TLS exporter label for the ASTP-M channel binding.
///
/// Passed to rustls as bytes. rustls uses it as the TLS 1.3 exporter label
/// (RFC 8446) and does not add another `EXPORTER` prefix.
pub const CHANNEL_BINDING_LABEL: &str = "EXPORTER-ASTP-M auth v1";

/// Exporter output length, in bytes.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// Binding of one TLS connection, from the exporter.
///
/// Two sides of the same handshake produce the same value. A different
/// connection produces a different value. Debug output is redacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChannelBinding([u8; CHANNEL_BINDING_LEN]);

impl ChannelBinding {
    /// Wraps exporter output computed elsewhere, e.g. by a QUIC stack with
    /// [`CHANNEL_BINDING_LABEL`], [`CHANNEL_BINDING_LEN`] bytes and an empty
    /// context. TLS-over-TCP callers use [`channel_binding`] instead.
    pub fn from_exporter(bytes: [u8; CHANNEL_BINDING_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw exporter output.
    pub fn as_bytes(&self) -> &[u8; CHANNEL_BINDING_LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for ChannelBinding {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelBinding([redacted])")
    }
}

/// Opaque client identifier returned by a successful [`Authenticator`].
///
/// The bytes are not a wire format. Debug output shows the length only.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientId {
    bytes: Vec<u8>,
}

impl ClientId {
    /// Wrap caller-supplied bytes. Any length is accepted, including empty.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Borrow the opaque bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for ClientId {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientId({} bytes)", self.bytes.len())
    }
}

/// Why [`Authenticator::verify`] failed.
///
/// The three variants exist so a server can log the cause. They must not be
/// shown differently to the peer: each one is an authentication failure, and
/// the connection then looks like an ordinary site.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The credential does not match this channel binding.
    #[error("authentication rejected")]
    Rejected,

    /// The credential is not the shape this authenticator verifies.
    #[error("authentication credential is malformed")]
    Malformed,

    /// The authenticator could not complete the check.
    #[error("internal authentication error")]
    Internal,
}

/// Verifies a credential bound to one TLS connection.
///
/// Implementors compare secrets in constant time when the check uses a
/// shared secret. This trait does not read the socket and does not parse HTTP.
pub trait Authenticator: Send + Sync {
    /// Check `credential` against `binding`.
    ///
    /// `Ok` is the client that presented it. Any [`AuthError`] rejects the
    /// attempt; the variant is log detail, not a peer-visible code.
    fn verify(&self, binding: &ChannelBinding, credential: &[u8]) -> Result<ClientId, AuthError>;
}

mod sealed {
    pub trait Sealed {}
}

/// A rustls session that can produce the ASTP-M channel binding.
///
/// Implemented for [`rustls::Connection`], [`rustls::ClientConnection`], and
/// [`rustls::ServerConnection`]. The trait is sealed. QUIC uses a separate
/// exporter path in a later task.
pub trait TlsSession: sealed::Sealed {
    /// Write this session's exporter output into `output`.
    ///
    /// Prefer [`channel_binding`], which fixes the length, label, and context.
    fn export_astp_channel_binding(&self, output: &mut [u8]) -> Result<(), rustls::Error>;
}

macro_rules! impl_tls_session {
    ($ty:ty) => {
        impl sealed::Sealed for $ty {}

        impl TlsSession for $ty {
            fn export_astp_channel_binding(&self, output: &mut [u8]) -> Result<(), rustls::Error> {
                // `None` is the empty exporter context. rustls hashes a missing
                // context as an empty slice, so this matches an empty context.
                self.export_keying_material(output, CHANNEL_BINDING_LABEL.as_bytes(), None)
                    .map(|_| ())
            }
        }
    };
}

impl_tls_session!(rustls::ClientConnection);
impl_tls_session!(rustls::ServerConnection);
impl_tls_session!(rustls::Connection);

/// Derive the channel binding from a completed rustls session.
///
/// Fails if the handshake is not finished or the exporter rejects the
/// length. The label is [`CHANNEL_BINDING_LABEL`] and the context is empty.
pub fn channel_binding(conn: &impl TlsSession) -> Result<ChannelBinding, CryptoError> {
    let mut bytes = [0u8; CHANNEL_BINDING_LEN];
    match conn.export_astp_channel_binding(&mut bytes) {
        Ok(()) => Ok(ChannelBinding(bytes)),
        Err(err) => {
            bytes.fill(0);
            Err(CryptoError::Exporter {
                detail: err.to_string(),
            })
        }
    }
}

/// Single shared-secret authenticator for tests.
///
/// The credential is HMAC-SHA256 (ring) over the raw channel binding.
/// The tag is compared with `subtle::ConstantTimeEq`. This is not a
/// production credential format: one secret maps to one [`ClientId`].
///
/// Enable the `test-util` feature to use this from another crate. It is also
/// compiled for this crate's own tests.
#[cfg(any(test, feature = "test-util"))]
pub struct StaticTokenAuthenticator {
    key: ring::hmac::Key,
    client_id: ClientId,
}

#[cfg(any(test, feature = "test-util"))]
impl fmt::Debug for StaticTokenAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticTokenAuthenticator")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl StaticTokenAuthenticator {
    /// Build an authenticator from a non-empty secret and the id it accepts.
    ///
    /// An empty secret is [`AuthError::Malformed`].
    pub fn new(secret: &[u8], client_id: ClientId) -> Result<Self, AuthError> {
        if secret.is_empty() {
            return Err(AuthError::Malformed);
        }
        Ok(Self {
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
            client_id,
        })
    }

    /// HMAC-SHA256 of `binding` under this authenticator's secret.
    pub fn credential(&self, binding: &ChannelBinding) -> Result<Vec<u8>, AuthError> {
        let tag = ring::hmac::sign(&self.key, binding.as_bytes());
        let bytes = tag.as_ref();
        if bytes.len() != CHANNEL_BINDING_LEN {
            return Err(AuthError::Internal);
        }
        Ok(bytes.to_vec())
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Authenticator for StaticTokenAuthenticator {
    fn verify(&self, binding: &ChannelBinding, credential: &[u8]) -> Result<ClientId, AuthError> {
        let expected = self.credential(binding)?;
        if credential.len() != expected.len() {
            return Err(AuthError::Malformed);
        }
        // Equal lengths, so this comparison does not return early on length.
        // `ring::constant_time` in ring 0.17 is deprecated and warns.
        let matches =
            subtle::ConstantTimeEq::ct_eq(credential, expected.as_slice()).unwrap_u8() == 1;
        if matches {
            Ok(self.client_id.clone())
        } else {
            Err(AuthError::Rejected)
        }
    }
}
