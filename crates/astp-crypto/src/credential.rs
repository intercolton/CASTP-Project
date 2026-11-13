//! Production credential format v1 (`docs/design/credentials.md`).
//!
//! ```text
//! credential = 0x01 ‖ key_id (16) ‖ HMAC-SHA256(secret, "ASTP-M credential v1" ‖ binding) (32)
//! key_id     = SHA-256("ASTP-M key id v1" ‖ secret)[0..16]
//! ```
//!
//! The binding is the TLS exporter of the connection the credential is
//! sent on, so a credential is good for that one connection only.

use std::collections::HashMap;
use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use ring::{digest, hmac};

use crate::auth::{AuthError, Authenticator, ChannelBinding, ClientId};

/// Length of a client secret, bytes.
pub const SECRET_LEN: usize = 32;
/// Length of a key id, bytes.
pub const KEY_ID_LEN: usize = 16;
/// Length of an encoded credential, bytes.
pub const CREDENTIAL_LEN: usize = 1 + KEY_ID_LEN + 32;
/// First byte of a v1 credential.
pub const CREDENTIAL_VERSION: u8 = 1;

const KEY_ID_LABEL: &[u8] = b"ASTP-M key id v1";
const CREDENTIAL_LABEL: &[u8] = b"ASTP-M credential v1";

/// A client's 32-byte secret. Debug output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSecret([u8; SECRET_LEN]);

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientSecret([redacted])")
    }
}

impl ClientSecret {
    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// A new random secret from the OS CSPRNG.
    pub fn generate() -> Result<Self, AuthError> {
        let mut b = [0u8; SECRET_LEN];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b)
            .map_err(|_| AuthError::Internal)?;
        Ok(Self(b))
    }

    /// Parses the config form: base64url, with or without `=` padding.
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        let t = text.trim().trim_end_matches('=');
        let v = BASE64URL_NOPAD
            .decode(t.as_bytes())
            .map_err(|_| AuthError::Malformed)?;
        let b: [u8; SECRET_LEN] = v.try_into().map_err(|_| AuthError::Malformed)?;
        Ok(Self(b))
    }

    /// The config form: base64url without padding.
    pub fn encode(&self) -> String {
        BASE64URL_NOPAD.encode(&self.0)
    }

    /// Public identifier of this key: the server looks the secret up by it.
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(KEY_ID_LABEL);
        ctx.update(&self.0);
        let d = ctx.finish();
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&d.as_ref()[..KEY_ID_LEN]);
        id
    }

    fn hmac_key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &self.0)
    }
}

fn tag(key: &hmac::Key, binding: &ChannelBinding) -> hmac::Tag {
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(CREDENTIAL_LABEL);
    ctx.update(binding.as_bytes());
    ctx.sign()
}

/// The credential a client presents on the connection with `binding`.
pub fn client_credential(secret: &ClientSecret, binding: &ChannelBinding) -> [u8; CREDENTIAL_LEN] {
    let mut out = [0u8; CREDENTIAL_LEN];
    out[0] = CREDENTIAL_VERSION;
    out[1..1 + KEY_ID_LEN].copy_from_slice(&secret.key_id());
    out[1 + KEY_ID_LEN..].copy_from_slice(tag(&secret.hmac_key(), binding).as_ref());
    out
}

/// Base64url (no padding) of [`client_credential`], for an HTTP header.
pub fn client_credential_header(secret: &ClientSecret, binding: &ChannelBinding) -> String {
    BASE64URL_NOPAD.encode(&client_credential(secret, binding))
}

/// Decodes the header form back to bytes. Any garbage is `Malformed`.
pub fn decode_credential_header(text: &str) -> Result<Vec<u8>, AuthError> {
    let t = text.trim();
    if t.len() > 2 * CREDENTIAL_LEN {
        return Err(AuthError::Malformed);
    }
    BASE64URL_NOPAD
        .decode(t.trim_end_matches('=').as_bytes())
        .map_err(|_| AuthError::Malformed)
}

/// Server-side table of client keys; the production [`Authenticator`].
pub struct KeyTable {
    keys: HashMap<[u8; KEY_ID_LEN], (hmac::Key, ClientId)>,
    /// Used when the key id is unknown, so the check costs the same.
    decoy: hmac::Key,
}

impl fmt::Debug for KeyTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyTable")
            .field("clients", &self.keys.len())
            .finish_non_exhaustive()
    }
}

/// Two clients were configured with the same secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("two clients share one secret")]
pub struct DuplicateKey;

impl KeyTable {
    /// An empty table.
    pub fn new() -> Result<Self, AuthError> {
        Ok(Self {
            keys: HashMap::new(),
            decoy: ClientSecret::generate()?.hmac_key(),
        })
    }

    /// Adds a client. Each secret may appear once.
    pub fn insert(&mut self, secret: &ClientSecret, id: ClientId) -> Result<(), DuplicateKey> {
        let kid = secret.key_id();
        if self.keys.contains_key(&kid) {
            return Err(DuplicateKey);
        }
        self.keys.insert(kid, (secret.hmac_key(), id));
        Ok(())
    }

    /// Number of clients.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// No clients configured.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Authenticator for KeyTable {
    fn verify(&self, binding: &ChannelBinding, credential: &[u8]) -> Result<ClientId, AuthError> {
        if credential.len() != CREDENTIAL_LEN || credential[0] != CREDENTIAL_VERSION {
            return Err(AuthError::Malformed);
        }
        let mut kid = [0u8; KEY_ID_LEN];
        kid.copy_from_slice(&credential[1..1 + KEY_ID_LEN]);
        let found = self.keys.get(&kid);
        let key = found.map(|(k, _)| k).unwrap_or(&self.decoy);
        // Computed for unknown ids too: timing does not tell them apart.
        let expected = tag(key, binding);
        let ok = subtle::ConstantTimeEq::ct_eq(&credential[1 + KEY_ID_LEN..], expected.as_ref())
            .unwrap_u8()
            == 1;
        match (found, ok) {
            (Some((_, id)), true) => Ok(id.clone()),
            _ => Err(AuthError::Rejected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(b: u8) -> ChannelBinding {
        ChannelBinding::from_exporter([b; 32])
    }

    #[test]
    fn credential_round_trip_and_binding() {
        let alice = ClientSecret::generate().unwrap();
        let bob = ClientSecret::generate().unwrap();
        let mut table = KeyTable::new().unwrap();
        table.insert(&alice, ClientId::new("alice")).unwrap();
        table.insert(&bob, ClientId::new("bob")).unwrap();
        assert_eq!(table.insert(&bob, ClientId::new("bob2")), Err(DuplicateKey));

        let c = client_credential(&alice, &binding(1));
        assert_eq!(c.len(), CREDENTIAL_LEN);
        assert_eq!(
            table.verify(&binding(1), &c).unwrap(),
            ClientId::new("alice")
        );
        // Another connection: another binding.
        assert_eq!(table.verify(&binding(2), &c), Err(AuthError::Rejected));
        // Unknown key.
        let eve = ClientSecret::generate().unwrap();
        let ce = client_credential(&eve, &binding(1));
        assert_eq!(table.verify(&binding(1), &ce), Err(AuthError::Rejected));
        // Bob's key id with Alice's tag.
        let mut mixed = client_credential(&bob, &binding(1));
        mixed[1 + KEY_ID_LEN..].copy_from_slice(&c[1 + KEY_ID_LEN..]);
        assert_eq!(table.verify(&binding(1), &mixed), Err(AuthError::Rejected));
        // Shape errors.
        assert_eq!(
            table.verify(&binding(1), &c[..48]),
            Err(AuthError::Malformed)
        );
        let mut v2 = c;
        v2[0] = 2;
        assert_eq!(table.verify(&binding(1), &v2), Err(AuthError::Malformed));
    }

    #[test]
    fn header_and_secret_encodings() {
        let s = ClientSecret::generate().unwrap();
        assert_eq!(ClientSecret::parse(&s.encode()).unwrap(), s);
        assert_eq!(ClientSecret::parse(&format!("{}=", s.encode())).unwrap(), s);
        assert!(ClientSecret::parse("short").is_err());
        assert!(!format!("{s:?}").contains(&s.encode()));
        let h = client_credential_header(&s, &binding(3));
        assert!(!h.contains('='));
        assert_eq!(
            decode_credential_header(&h).unwrap(),
            client_credential(&s, &binding(3)).to_vec()
        );
        assert!(decode_credential_header("!!").is_err());
        assert!(decode_credential_header(&"A".repeat(500)).is_err());
    }

    #[test]
    fn key_id_is_stable_and_distinct() {
        let a = ClientSecret::from_bytes([7; 32]);
        assert_eq!(a.key_id(), ClientSecret::from_bytes([7; 32]).key_id());
        assert_ne!(a.key_id(), ClientSecret::from_bytes([8; 32]).key_id());
    }
}
