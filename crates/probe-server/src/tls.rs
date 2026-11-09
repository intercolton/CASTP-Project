//! TLS server setup: certificate chain and key from PEM files, ALPN for
//! HTTP/2 and HTTP/1.1.

use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub const TLS_STACK: &str = "rustls-0.23/ring";

pub fn server_config(cert_file: &Path, key_file: &Path) -> Result<rustls::ServerConfig> {
    let mut cfg = build(cert_file, key_file, rustls::DEFAULT_VERSIONS)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// QUIC requires TLS 1.3; only HTTP/3 is offered over it.
pub fn quic_server_config(cert_file: &Path, key_file: &Path) -> Result<rustls::ServerConfig> {
    let mut cfg = build(cert_file, key_file, &[&rustls::version::TLS13])?;
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    // Clients may send 0-RTT; the probe does not use it, so it is refused.
    cfg.max_early_data_size = 0;
    Ok(cfg)
}

fn build(
    cert_file: &Path,
    key_file: &Path,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ServerConfig> {
    let certs = CertificateDer::pem_file_iter(cert_file)
        .with_context(|| format!("open {}", cert_file.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificates in {}", cert_file.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificate in {}", cert_file.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .with_context(|| format!("read private key {}", key_file.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("certificate and key do not match")
}

pub fn acceptor(cert_file: &Path, key_file: &Path) -> Result<TlsAcceptor> {
    Ok(TlsAcceptor::from(Arc::new(server_config(
        cert_file, key_file,
    )?)))
}
