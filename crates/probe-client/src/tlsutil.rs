//! TLS client setup on rustls with certificate verification always on
//! (spec 10). Trust comes from the Mozilla root set, or only from a given CA
//! file when a target uses a private test CA.

use crate::netutil::Failure;
use probe_common::ErrorCode;
use rustls::pki_types::{CertificateDer, ServerName};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Label written into every event so results are tied to the ClientHello
/// that produced them. rustls builds one fixed ClientHello shape; it does not
/// imitate any browser.
pub const TLS_STACK: &str = "rustls-0.23/ring";

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn root_store(ca_file: Option<&Path>) -> Result<rustls::RootCertStore, Failure> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        Some(path) => {
            let pem = std::fs::read(path).map_err(|e| {
                Failure::new(
                    ErrorCode::Unknown,
                    format!("read CA {}: {e}", path.display()),
                )
            })?;
            let certs = pem_certs(&pem).map_err(|e| {
                Failure::new(
                    ErrorCode::Unknown,
                    format!("parse CA {}: {e}", path.display()),
                )
            })?;
            for c in certs {
                roots.add(c).map_err(|e| {
                    Failure::new(
                        ErrorCode::Unknown,
                        format!("add CA {}: {e}", path.display()),
                    )
                })?;
            }
        }
    }
    Ok(roots)
}

fn pem_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// Builds a client config. `tls13_only` is used for the TLS 1.3 handshake
/// test; controls accept TLS 1.2 as well.
pub fn client_config(
    ca_file: Option<&Path>,
    alpn: &[&[u8]],
    tls13_only: bool,
) -> Result<Arc<rustls::ClientConfig>, Failure> {
    let versions: &[&rustls::SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .map_err(|e| Failure::new(ErrorCode::Unknown, e.to_string()))?
        .with_root_certificates(root_store(ca_file)?)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

pub struct Handshaken<S> {
    pub stream: TlsStream<S>,
    pub alpn: Option<String>,
    pub version: String,
}

pub async fn handshake<S>(
    cfg: Arc<rustls::ClientConfig>,
    server_name: &str,
    io: S,
    timeout: Duration,
) -> Result<Handshaken<S>, Failure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| Failure::new(ErrorCode::Unknown, format!("bad server name: {e}")))?;
    let connector = TlsConnector::from(cfg);
    match tokio::time::timeout(timeout, connector.connect(name, io)).await {
        Err(_) => Err(Failure::new(
            ErrorCode::TlsHandshakeFailed,
            format!(
                "handshake timeout after {}s (no complete server response)",
                timeout.as_secs()
            ),
        )),
        Ok(Err(e)) => Err(classify_handshake_error(&e)),
        Ok(Ok(stream)) => {
            let (_, conn) = stream.get_ref();
            let alpn = conn
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned());
            let version = conn
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "unknown".into());
            Ok(Handshaken {
                stream,
                alpn,
                version,
            })
        }
    }
}

pub fn classify_handshake_error(e: &io::Error) -> Failure {
    if let Some(tls) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        let code = match tls {
            rustls::Error::InvalidCertificate(_) => ErrorCode::TlsCertificateError,
            _ => ErrorCode::TlsHandshakeFailed,
        };
        return Failure::new(code, tls.to_string());
    }
    match e.kind() {
        io::ErrorKind::UnexpectedEof => Failure::new(
            ErrorCode::TlsHandshakeFailed,
            "connection closed during TLS handshake",
        ),
        io::ErrorKind::ConnectionReset => {
            Failure::new(ErrorCode::TcpReset, "reset during TLS handshake")
        }
        _ => Failure::new(ErrorCode::TlsHandshakeFailed, e.to_string()),
    }
}
