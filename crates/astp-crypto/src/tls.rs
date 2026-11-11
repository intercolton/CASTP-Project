//! TLS 1.3 `ServerConfig` and `ClientConfig` for ASTP-M.
//!
//! Versions are selected in the builder. The workspace does not turn off
//! rustls' `tls12` feature: the probe still needs TLS 1.2.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astp_types::{ALPN_H2, ALPN_H3};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use thiserror::Error;

/// ALPN on the QUIC path, for server and client alike.
///
/// Each transport carries only its own protocol: a TLS-over-TCP server that
/// would agree to `h3`, or a QUIC client that offers `h2`, looks like no
/// real web server or browser and gives active probing something to see.
/// `astp-m/1` is intentionally absent. It is not the public default.
pub const QUIC_ALPN: &[&[u8]] = &[ALPN_H3];

/// ALPN on the TLS-over-TCP path, for server and client alike.
pub const TCP_ALPN: &[&[u8]] = &[ALPN_H2];

/// Certificate chain and private key used as a server identity or as an
/// optional mTLS client identity.
///
/// DER chains are leaf first, matching rustls.
pub enum Identity {
    /// PEM files. The certificate file may contain a chain. The key file
    /// holds one private key.
    Pem {
        /// Path of the certificate chain.
        certificate: PathBuf,
        /// Path of the private key.
        private_key: PathBuf,
    },
    /// Already decoded certificates and a private key.
    Der {
        /// Leaf certificate first.
        certificates: Vec<CertificateDer<'static>>,
        /// Private key that matches the leaf.
        private_key: PrivateKeyDer<'static>,
    },
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pem {
                certificate,
                private_key,
            } => f
                .debug_struct("Pem")
                .field("certificate", certificate)
                .field("private_key", private_key)
                .finish(),
            Self::Der { certificates, .. } => f
                .debug_struct("Der")
                .field("certificates", &certificates.len())
                .field("private_key", &"redacted")
                .finish(),
        }
    }
}

/// Client-certificate policy. Absent on [`ServerOptions`] means the server
/// does not send `CertificateRequest`.
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// Every client must present a certificate that chains to `roots`.
    Required(RootCertStore),
}

/// Inputs for [`server_config`].
#[derive(Debug)]
pub struct ServerOptions {
    /// Server certificate and key.
    pub identity: Identity,
    /// `None` is the default profile: no client authentication.
    pub client_auth: Option<ClientAuth>,
    /// The transport this config is for; it decides the ALPN list. A QUIC
    /// listener and a TCP listener each get their own config.
    pub alpn: AlpnMode,
}

/// Which roots a client trusts. This is a field, not a Cargo feature.
#[derive(Debug, Clone)]
pub enum TrustAnchors {
    /// The Mozilla root set from `webpki-roots`.
    Webpki,
    /// Only these anchors. An empty store is rejected.
    Explicit(RootCertStore),
}

/// Which transport a config is for, and so which ALPN list it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnMode {
    /// QUIC path: [`QUIC_ALPN`].
    Quic,
    /// TCP path: [`TCP_ALPN`].
    Tcp,
}

impl AlpnMode {
    /// The ALPN list for this transport.
    pub fn protocols(self) -> &'static [&'static [u8]] {
        match self {
            AlpnMode::Quic => QUIC_ALPN,
            AlpnMode::Tcp => TCP_ALPN,
        }
    }
}

/// Inputs for [`client_config`].
///
/// [`ClientOptions::server_name`] is the name the handshake must verify.
/// This crate has no connector that skips that check.
#[derive(Debug)]
pub struct ClientOptions {
    /// Trust anchors for the server certificate.
    pub trust: TrustAnchors,
    /// ALPN list for the transport the caller will use.
    pub alpn: AlpnMode,
    /// Dial host. An IP literal requires [`Self::tls_server_name`].
    pub host: String,
    /// Explicit name to verify. When absent, `host` itself is verified.
    pub tls_server_name: Option<String>,
    /// Optional client certificate for mTLS.
    pub client_identity: Option<Identity>,
}

impl ClientOptions {
    /// Name rustls must verify for this client.
    ///
    /// An IP literal `host` without a non-empty `tls_server_name` is
    /// [`CryptoError::IpLiteralRequiresServerName`]. Transports take the
    /// name from [`ClientTlsConfig`], not from here.
    pub(crate) fn server_name(&self) -> Result<ServerName<'static>, CryptoError> {
        resolve_server_name(&self.host, self.tls_server_name.as_deref())
    }
}

/// A client config together with the one name it was built to verify.
///
/// rustls keeps the server name outside `ClientConfig`, so a config alone
/// lets a caller hand the connector some other name. Transports take both
/// from here.
#[derive(Debug, Clone)]
pub struct ClientTlsConfig {
    config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
}

impl ClientTlsConfig {
    /// The rustls config.
    pub fn config(&self) -> &Arc<rustls::ClientConfig> {
        &self.config
    }

    /// The name the handshake verifies: `tls_server_name`, else `host`.
    pub fn server_name(&self) -> &ServerName<'static> {
        &self.server_name
    }

    /// Both parts, for a connector call such as
    /// `TlsConnector::from(config).connect(name, io)`.
    pub fn into_parts(self) -> (Arc<rustls::ClientConfig>, ServerName<'static>) {
        (self.config, self.server_name)
    }
}

/// Failure while building a TLS config or reading an identity.
///
/// Display text is for logs. It does not include key bytes or certificate
/// contents.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A DER identity contained no certificate.
    #[error("TLS certificate chain is empty")]
    EmptyCertificateChain,

    /// A PEM path could not be read or decoded.
    #[error("TLS identity {path} could not be loaded: {detail}")]
    Identity {
        /// Path that failed.
        path: String,
        /// rustls or I/O error text, not file contents.
        detail: String,
    },

    /// rustls rejected the certificate and key pair.
    #[error("TLS certificate and private key were rejected: {detail}")]
    InvalidIdentity {
        /// rustls error text.
        detail: String,
    },

    /// The protocol-version or provider settings were rejected.
    #[error("TLS configuration was rejected: {detail}")]
    Config {
        /// rustls error text.
        detail: String,
    },

    /// `host` is an IP address and `tls_server_name` was not set.
    #[error("host is an IP literal and tls_server_name is not set")]
    IpLiteralRequiresServerName,

    /// The name that would be verified is empty or not a DNS name or IP.
    #[error("server name cannot be verified: {detail}")]
    InvalidServerName {
        /// Parser error text.
        detail: String,
    },

    /// A trust store or mTLS root set contained no anchors.
    #[error("trust anchor set is empty")]
    EmptyTrustAnchors,

    /// The mTLS client-certificate verifier could not be built.
    #[error("TLS client authentication was rejected: {detail}")]
    ClientAuth {
        /// Verifier error text.
        detail: String,
    },

    /// The TLS exporter could not produce a channel binding.
    #[error("channel binding is not available: {detail}")]
    Exporter {
        /// rustls error text.
        detail: String,
    },

    /// The server certificate key or the mTLS client key is not Ed25519
    /// or ECDSA P-256.
    ///
    /// This does not apply to certificates we only verify. A public CA
    /// chain may still use RSA or P-384.
    #[error("own TLS key must be Ed25519 or ECDSA P-256, got {algorithm}")]
    UnsupportedOwnKey {
        /// `ecdsa-p384`, `rsa`, or `unsupported`. Not key material.
        algorithm: &'static str,
    },
}

/// Build a TLS 1.3 server config.
///
/// ALPN is [`TCP_ALPN`] or [`QUIC_ALPN`] per [`ServerOptions::alpn`].
/// Early data is disabled. Client authentication
/// is disabled unless `client_auth` is [`ClientAuth::Required`]. The
/// server's own key must be Ed25519 or ECDSA P-256.
pub fn server_config(options: ServerOptions) -> Result<Arc<rustls::ServerConfig>, CryptoError> {
    let provider = provider();
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| CryptoError::Config {
            detail: err.to_string(),
        })?;
    let builder = match options.client_auth {
        None => builder.with_no_client_auth(),
        Some(ClientAuth::Required(roots)) => {
            ensure_anchors(&roots)?;
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|err| CryptoError::ClientAuth {
                detail: err.to_string(),
            })?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let (certificates, private_key) = load_identity(options.identity)?;
    let mut config = builder
        .with_single_cert(certificates, private_key)
        .map_err(|err| CryptoError::InvalidIdentity {
            detail: err.to_string(),
        })?;
    config.alpn_protocols = protocol_list(options.alpn.protocols());
    // Refused here, in this config. The tls12 cargo feature stays on.
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Ok(Arc::new(config))
}

/// Build a TLS 1.3 client config.
///
/// The server name is checked while the config is built, including the
/// IP-literal rule, and returned with the config in [`ClientTlsConfig`].
/// Early data is disabled. There is no option to skip certificate checks.
/// An mTLS client key, when set, must be Ed25519 or ECDSA P-256. Peer
/// chains are verified with the ring provider's default algorithms.
pub fn client_config(options: ClientOptions) -> Result<ClientTlsConfig, CryptoError> {
    // The name is not stored on ClientConfig. Resolving it here means an
    // IP dial without tls_server_name never produces a usable config, and
    // the config never travels without the name it was meant for.
    let server_name = options.server_name()?;
    let roots = trust_store(options.trust)?;
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| CryptoError::Config {
            detail: err.to_string(),
        })?
        .with_root_certificates(roots);
    let mut config = match options.client_identity {
        None => builder.with_no_client_auth(),
        Some(identity) => {
            let (certificates, private_key) = load_identity(identity)?;
            builder
                .with_client_auth_cert(certificates, private_key)
                .map_err(|err| CryptoError::InvalidIdentity {
                    detail: err.to_string(),
                })?
        }
    };
    config.alpn_protocols = protocol_list(options.alpn.protocols());
    config.enable_early_data = false;
    Ok(ClientTlsConfig {
        config: Arc::new(config),
        server_name,
    })
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    // `builder_with_protocol_versions` uses the process-default provider and
    // panics when none is installed. Installing one from a library would
    // change every other rustls user in the process. The provider is passed
    // in, and TLS 1.3 is still the only version on the config.
    //
    // `signature_verification_algorithms` stays at the ring default. Peer
    // chains (a public CA, including P-384 or RSA intermediates) are not
    // filtered. The Ed25519 / P-256 limit applies only to keys we load.
    Arc::new(rustls::crypto::ring::default_provider())
}

fn protocol_list(protocols: &[&[u8]]) -> Vec<Vec<u8>> {
    protocols.iter().map(|protocol| protocol.to_vec()).collect()
}

fn trust_store(trust: TrustAnchors) -> Result<RootCertStore, CryptoError> {
    let roots = match trust {
        TrustAnchors::Explicit(roots) => roots,
        TrustAnchors::Webpki => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots
        }
    };
    ensure_anchors(&roots)?;
    Ok(roots)
}

fn ensure_anchors(roots: &RootCertStore) -> Result<(), CryptoError> {
    if roots.is_empty() {
        Err(CryptoError::EmptyTrustAnchors)
    } else {
        Ok(())
    }
}

fn load_identity(
    identity: Identity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), CryptoError> {
    match identity {
        Identity::Pem {
            certificate,
            private_key,
        } => {
            let certificates = load_pem_certs(&certificate)?;
            let key = PrivateKeyDer::from_pem_file(&private_key)
                .map_err(|err| identity_error(&private_key, &err))?;
            Ok((certificates, key))
        }
        Identity::Der {
            certificates,
            private_key,
        } => {
            if certificates.is_empty() {
                return Err(CryptoError::EmptyCertificateChain);
            }
            Ok((certificates, private_key))
        }
    }
    .and_then(|(certificates, private_key)| {
        ensure_own_key(&private_key)?;
        Ok((certificates, private_key))
    })
}

/// Rule D applies to keys we sign with, not to chains we verify.
fn ensure_own_key(key: &PrivateKeyDer<'static>) -> Result<(), CryptoError> {
    let loaded = provider()
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|err| CryptoError::InvalidIdentity {
            detail: err.to_string(),
        })?;
    if loaded
        .choose_scheme(&[
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .is_some()
    {
        return Ok(());
    }
    Err(CryptoError::UnsupportedOwnKey {
        algorithm: disallowed_own_key_name(loaded.as_ref()),
    })
}

fn disallowed_own_key_name(key: &dyn rustls::sign::SigningKey) -> &'static str {
    if key
        .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP384_SHA384])
        .is_some()
    {
        "ecdsa-p384"
    } else if key.algorithm() == rustls::SignatureAlgorithm::RSA {
        "rsa"
    } else {
        "unsupported"
    }
}

fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, CryptoError> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|err| identity_error(path, &err))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| identity_error(path, &err))?;
    if certificates.is_empty() {
        return Err(identity_error(path, "no certificate in file"));
    }
    Ok(certificates)
}

fn identity_error(path: &Path, err: impl std::fmt::Display) -> CryptoError {
    CryptoError::Identity {
        path: path.display().to_string(),
        detail: err.to_string(),
    }
}

fn resolve_server_name(
    host: &str,
    tls_server_name: Option<&str>,
) -> Result<ServerName<'static>, CryptoError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(CryptoError::InvalidServerName {
            detail: "host is empty".into(),
        });
    }
    let explicit = tls_server_name.and_then(|name| {
        let name = name.trim();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    });
    if is_ip_literal(host) && explicit.is_none() {
        return Err(CryptoError::IpLiteralRequiresServerName);
    }
    let name = match explicit {
        Some(name) => name,
        None => host,
    };
    ServerName::try_from(name.to_owned()).map_err(|err| CryptoError::InvalidServerName {
        detail: err.to_string(),
    })
}

fn is_ip_literal(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return false;
    };
    inner.parse::<IpAddr>().is_ok()
}
