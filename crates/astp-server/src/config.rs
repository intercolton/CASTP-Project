//! `astp-server` configuration (TOML).

use anyhow::{anyhow, bail, Context, Result};
use astp_crypto::ClientSecret;
use astp_session::Route;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerSection,
    pub tls: TlsSection,
    pub tunnel: TunnelSection,
    #[serde(default)]
    pub decoy: DecoySection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub clients: Vec<ClientEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// TLS + HTTP/2 listener, e.g. "0.0.0.0:443".
    pub listen_tcp: SocketAddr,
    /// QUIC + HTTP/3 listener; unset disables QUIC.
    #[serde(default)]
    pub listen_quic: Option<SocketAddr>,
    /// Secret path of the session endpoint (`astp-server keygen` suggests one).
    pub session_path: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelSection {
    #[serde(default = "default_device")]
    pub device: String,
    /// Server's tunnel address with the tunnel prefix, e.g. "10.77.0.1/24".
    pub address4: String,
    #[serde(default)]
    pub address6: Option<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub dns4: Vec<Ipv4Addr>,
    #[serde(default)]
    pub dns6: Vec<Ipv6Addr>,
    /// Routes pushed to clients: "0.0.0.0/0" through the tunnel,
    /// "!192.168.0.0/16" around it.
    #[serde(default = "default_routes")]
    pub routes: Vec<String>,
    #[serde(default = "default_keepalive")]
    pub keepalive_seconds: u64,
    #[serde(default = "default_idle")]
    pub idle_timeout_seconds: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoySection {
    /// HTML served for `/`.
    #[serde(default)]
    pub index_file: Option<PathBuf>,
    /// HTML served with 404 for every other path.
    #[serde(default)]
    pub not_found_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_handshake")]
    pub handshake_timeout_seconds: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        LimitsSection {
            max_connections: default_max_connections(),
            handshake_timeout_seconds: default_handshake(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    pub name: String,
    /// The client's secret, base64url. Prefer `secret_env`.
    #[serde(default)]
    pub secret: Option<String>,
    /// Environment variable holding the secret.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// The client's tunnel address (inside `tunnel.address4`'s prefix).
    pub address4: Ipv4Addr,
    #[serde(default)]
    pub address6: Option<Ipv6Addr>,
}

fn default_log_level() -> String {
    "info".into()
}
fn default_device() -> String {
    "astp0".into()
}
fn default_mtu() -> u16 {
    astp_session::DEFAULT_MTU
}
fn default_routes() -> Vec<String> {
    vec!["0.0.0.0/0".into()]
}
fn default_keepalive() -> u64 {
    25
}
fn default_idle() -> u64 {
    90
}
fn default_max_connections() -> usize {
    1024
}
fn default_handshake() -> u64 {
    10
}

/// `addr/prefix` for the given family's maximum prefix.
pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (a, p) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("{s:?} is not address/prefix"))?;
    let addr: IpAddr = a.parse().with_context(|| format!("address in {s:?}"))?;
    let prefix: u8 = p.parse().with_context(|| format!("prefix in {s:?}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("prefix {prefix} too long in {s:?}");
    }
    Ok((addr, prefix))
}

/// `"10.0.0.0/8"` (include) or `"!10.0.0.0/8"` (exclude).
pub fn parse_route(s: &str) -> Result<Route> {
    let (include, rest) = match s.strip_prefix('!') {
        Some(r) => (false, r),
        None => (true, s),
    };
    Ok(match parse_cidr(rest.trim())? {
        (IpAddr::V4(dest), prefix) => Route::V4 {
            dest,
            prefix,
            include,
        },
        (IpAddr::V6(dest), prefix) => Route::V6 {
            dest,
            prefix,
            include,
        },
    })
}

fn in_prefix(net: IpAddr, prefix: u8, a: IpAddr) -> bool {
    match (net, a) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// A client with its secret resolved.
#[derive(Debug, Clone)]
pub struct Client {
    pub name: String,
    pub secret: ClientSecret,
    pub address4: Ipv4Addr,
    pub address6: Option<Ipv6Addr>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Config> {
        let c: Config = toml::from_str(text)?;
        c.validate()?;
        Ok(c)
    }

    pub fn keepalive(&self) -> Duration {
        Duration::from_secs(self.tunnel.keepalive_seconds)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.tunnel.idle_timeout_seconds)
    }

    pub fn tunnel4(&self) -> (Ipv4Addr, u8) {
        match parse_cidr(&self.tunnel.address4).expect("validated") {
            (IpAddr::V4(a), p) => (a, p),
            _ => unreachable!("validated as IPv4"),
        }
    }

    pub fn tunnel6(&self) -> Option<(Ipv6Addr, u8)> {
        self.tunnel
            .address6
            .as_deref()
            .map(|s| match parse_cidr(s).expect("validated") {
                (IpAddr::V6(a), p) => (a, p),
                _ => unreachable!("validated as IPv6"),
            })
    }

    pub fn routes(&self) -> Vec<Route> {
        self.tunnel
            .routes
            .iter()
            .map(|r| parse_route(r).expect("validated"))
            .collect()
    }

    /// Clients with secrets resolved from the file or the environment.
    pub fn clients(&self, env: impl Fn(&str) -> Option<String>) -> Result<Vec<Client>> {
        self.clients
            .iter()
            .map(|c| {
                let text = match (&c.secret, &c.secret_env) {
                    (Some(s), None) => s.clone(),
                    (None, Some(var)) => {
                        env(var).ok_or_else(|| anyhow!("client {}: ${var} is not set", c.name))?
                    }
                    _ => bail!("client {}: set exactly one of secret, secret_env", c.name),
                };
                let secret = ClientSecret::parse(&text).map_err(|_| {
                    anyhow!("client {}: secret is not 32 bytes of base64url", c.name)
                })?;
                Ok(Client {
                    name: c.name.clone(),
                    secret,
                    address4: c.address4,
                    address6: c.address6,
                })
            })
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        let p = &self.server.session_path;
        if !p.starts_with('/') || p.len() < 17 || p.contains(['?', '#', ' ']) {
            bail!("server.session_path must be '/' and at least 16 URL-safe characters (astp-server keygen suggests one)");
        }
        let (net4, pre4) = match parse_cidr(&self.tunnel.address4)? {
            (IpAddr::V4(a), p) => (a, p),
            _ => bail!("tunnel.address4 must be IPv4"),
        };
        if pre4 > 30 {
            bail!("tunnel.address4 prefix leaves no room for clients");
        }
        let net6 = match self
            .tunnel
            .address6
            .as_deref()
            .map(parse_cidr)
            .transpose()?
        {
            Some((IpAddr::V6(a), p)) => Some((a, p)),
            Some(_) => bail!("tunnel.address6 must be IPv6"),
            None => None,
        };
        if self.tunnel.mtu < 576 {
            bail!("tunnel.mtu must be >= 576");
        }
        if self.tunnel.keepalive_seconds == 0
            || self.tunnel.idle_timeout_seconds <= self.tunnel.keepalive_seconds
        {
            bail!("tunnel: keepalive_seconds must be > 0 and below idle_timeout_seconds");
        }
        for r in &self.tunnel.routes {
            parse_route(r).with_context(|| format!("tunnel.routes entry {r:?}"))?;
        }
        if !(1..=65_536).contains(&self.limits.max_connections) {
            bail!("limits.max_connections must be within 1..=65536");
        }
        let mut names = std::collections::HashSet::new();
        let mut addrs = std::collections::HashSet::new();
        addrs.insert(IpAddr::V4(net4));
        for c in &self.clients {
            if !names.insert(c.name.as_str()) {
                bail!("duplicate client name {}", c.name);
            }
            if !in_prefix(IpAddr::V4(net4), pre4, IpAddr::V4(c.address4)) {
                bail!(
                    "client {}: address4 {} is outside {}",
                    c.name,
                    c.address4,
                    self.tunnel.address4
                );
            }
            if !addrs.insert(IpAddr::V4(c.address4)) {
                bail!(
                    "client {}: address4 {} is already taken",
                    c.name,
                    c.address4
                );
            }
            if let Some(a6) = c.address6 {
                let Some((n6, p6)) = net6 else {
                    bail!("client {}: address6 without tunnel.address6", c.name);
                };
                if !in_prefix(IpAddr::V6(n6), p6, IpAddr::V6(a6)) || !addrs.insert(IpAddr::V6(a6)) {
                    bail!(
                        "client {}: address6 {a6} is outside the tunnel or taken",
                        c.name
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"
[server]
listen_tcp = "0.0.0.0:443"
session_path = "/abcdefghijklmnop"
[tls]
cert_file = "/etc/astp/cert.pem"
key_file = "/etc/astp/key.pem"
[tunnel]
address4 = "10.77.0.1/24"
address6 = "fd77::1/64"
routes = ["0.0.0.0/0", "!192.168.0.0/16", "::/0"]
[[clients]]
name = "alice"
secret_env = "ALICE"
address4 = "10.77.0.2"
address6 = "fd77::2"
"#;

    #[test]
    fn parses_and_resolves() {
        let c = Config::from_toml(OK).unwrap();
        assert_eq!(c.tunnel4(), ("10.77.0.1".parse().unwrap(), 24));
        assert_eq!(c.routes().len(), 3);
        let (secret, _) = crate::keygen().unwrap();
        let clients = c
            .clients(|k| (k == "ALICE").then(|| secret.clone()))
            .unwrap();
        assert_eq!(clients[0].name, "alice");
        assert!(c.clients(|_| None).is_err());
    }

    #[test]
    fn example_file_parses() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        Config::load(&root.join("configs/astp-server.example.toml")).unwrap();
    }

    #[test]
    fn rejects_bad_values() {
        for (from, to) in [
            ("/abcdefghijklmnop", "/short"),
            ("address4 = \"10.77.0.2\"", "address4 = \"10.78.0.2\""),
            ("address4 = \"10.77.0.2\"", "address4 = \"10.77.0.1\""),
            ("fd77::2", "fd78::2"),
            ("\"0.0.0.0/0\"", "\"0.0.0.0/33\""),
            ("10.77.0.1/24", "10.77.0.1/31"),
        ] {
            let t = OK.replace(from, to);
            assert!(Config::from_toml(&t).is_err(), "{from} -> {to}");
        }
        let dup = format!(
            "{OK}[[clients]]\nname = \"alice\"\nsecret_env = \"X\"\naddress4 = \"10.77.0.9\"\n"
        );
        assert!(Config::from_toml(&dup).is_err());
    }
}
