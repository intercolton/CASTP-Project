//! `astp-client` configuration (TOML).

use anyhow::{anyhow, bail, Context, Result};
use astp_crypto::ClientSecret;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub client: ClientSection,
}

/// Which transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportChoice {
    /// HTTP/3 over QUIC first, HTTP/2 over TLS if QUIC fails.
    #[default]
    Auto,
    H3,
    H2,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    /// `host:port` of the server.
    pub server: String,
    /// Name to verify the certificate against when `server` is an IP or
    /// another name.
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// PEM with the only trust anchors to use (private CA). Unset: the
    /// Mozilla root set.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub transport: TransportChoice,
    pub session_path: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default = "default_device")]
    pub device: String,
    /// Point DNS at the servers from CONFIG with resolvectl.
    #[serde(default)]
    pub set_dns: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
}

fn default_device() -> String {
    "astp0".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_connect_timeout() -> u64 {
    10
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Config> {
        let c: Config = toml::from_str(text)?;
        let s = &c.client;
        if !s.session_path.starts_with('/') {
            bail!("client.session_path must start with '/'");
        }
        if s.server
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .is_none()
        {
            bail!("client.server must be host:port");
        }
        if !(1..=120).contains(&s.connect_timeout_seconds) {
            bail!("client.connect_timeout_seconds must be within 1..=120");
        }
        Ok(c)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.client.connect_timeout_seconds)
    }

    /// The secret from the file or the environment.
    pub fn secret(&self, env: impl Fn(&str) -> Option<String>) -> Result<ClientSecret> {
        let s = &self.client;
        let text = match (&s.secret, &s.secret_env) {
            (Some(t), None) => t.clone(),
            (None, Some(var)) => env(var).ok_or_else(|| anyhow!("${var} is not set"))?,
            _ => bail!("set exactly one of client.secret, client.secret_env"),
        };
        ClientSecret::parse(&text)
            .map_err(|_| anyhow!("client secret is not 32 bytes of base64url"))
    }

    /// Host part of `server`, without brackets.
    pub fn host(&self) -> &str {
        let (h, _) = self.client.server.rsplit_once(':').expect("validated");
        h.trim_start_matches('[').trim_end_matches(']')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_file_parses() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let c = Config::load(&root.join("configs/astp-client.example.toml")).unwrap();
        assert_eq!(c.host(), "vpn.example.net");
        assert_eq!(c.client.transport, TransportChoice::Auto);
    }

    #[test]
    fn host_strips_ipv6_brackets() {
        let c = Config::from_toml(
            "[client]\nserver = \"[2001:db8::1]:443\"\nsession_path = \"/x\"\nsecret_env = \"S\"\n",
        )
        .unwrap();
        assert_eq!(c.host(), "2001:db8::1");
        assert!(Config::from_toml("[client]\nserver = \"h\"\nsession_path = \"/x\"\n").is_err());
    }
}
