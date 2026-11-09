//! Client and server configuration (TOML, sections 4.1 and 11 of the spec).
//!
//! Values come from the file first; a small set of environment variables
//! (`ASTP_*`) override them so secrets and per-host settings need not live in
//! the file. Every config is validated before use.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

// ---------------------------------------------------------------- client ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client: ClientSection,
    #[serde(default)]
    pub schedule: ScheduleSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub logs: LogsSection,
    #[serde(default)]
    pub delivery: Option<DeliverySection>,
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
    /// Independent HTTPS resources used to tell "our server is unreachable"
    /// from "this network is down".
    #[serde(default)]
    pub controls: Vec<ControlConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    pub id: String,
    /// Label of the network this client sits in (e.g. "rostelecom-home").
    #[serde(default = "default_network_id")]
    pub network_id: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Bind all probe sockets to this interface (SO_BINDTODEVICE), e.g. "eno1",
    /// so measurements bypass a VPN that owns the default route.
    #[serde(default)]
    pub bind_interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleSection {
    pub quick_interval_seconds: u64,
    pub long_interval_seconds: u64,
    pub long_duration_seconds: u64,
    pub jitter_percent: u8,
}

impl Default for ScheduleSection {
    fn default() -> Self {
        ScheduleSection {
            quick_interval_seconds: 300,
            long_interval_seconds: 1800,
            long_duration_seconds: 300,
            jitter_percent: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub max_connections: usize,
    pub max_test_bytes: u64,
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_tls_timeout")]
    pub tls_timeout_seconds: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        LimitsSection {
            max_connections: 4,
            max_test_bytes: 10 * 1024 * 1024,
            connect_timeout_seconds: 5,
            tls_timeout_seconds: default_tls_timeout(),
            request_timeout_seconds: default_request_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogsSection {
    pub max_file_bytes: u64,
    pub keep_files: usize,
}

impl Default for LogsSection {
    fn default() -> Self {
        LogsSection {
            max_file_bytes: 16 * 1024 * 1024,
            keep_files: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverySection {
    /// HTTPS URL of the server's telemetry endpoint.
    pub url: String,
    /// Name of the environment variable holding the bearer token.
    #[serde(default = "default_token_env")]
    pub token_env: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub id: String,
    /// Host name or IP literal to connect to.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Name to send as SNI and to verify the certificate against. Required
    /// when `host` is an IP literal (spec 10: no disabled verification).
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// PEM file with extra trust anchors (e.g. a private test CA). When set,
    /// only these anchors are trusted for this target.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "yes")]
    pub enable_tcp: bool,
    #[serde(default = "yes")]
    pub enable_tls: bool,
    #[serde(default = "yes")]
    pub enable_h2: bool,
    #[serde(default)]
    pub enable_quic: bool,
    #[serde(default)]
    pub enable_h3: bool,
    #[serde(default = "default_quic_port")]
    pub quic_port: u16,
}

impl TargetConfig {
    pub fn server_name(&self) -> &str {
        self.tls_server_name.as_deref().unwrap_or(&self.host)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    pub id: String,
    /// Full HTTPS URL, e.g. "https://www.wikipedia.org/".
    pub url: String,
}

fn default_network_id() -> String {
    "unknown".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}
fn default_tls_timeout() -> u64 {
    8
}
fn default_request_timeout() -> u64 {
    10
}
fn default_token_env() -> String {
    "ASTP_TOKEN".into()
}
fn default_port() -> u16 {
    443
}
fn default_quic_port() -> u16 {
    443
}
fn yes() -> bool {
    true
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut cfg: ClientConfig = parse_file(path)?;
        cfg.apply_env(|k| std::env::var(k).ok());
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        let cfg: ClientConfig = toml::from_str(s).map_err(|e| ConfigError::Parse {
            path: PathBuf::from("<string>"),
            source: Box::new(e),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// `ASTP_CLIENT_ID`, `ASTP_NETWORK_ID`, `ASTP_DATA_DIR`, `ASTP_BIND_INTERFACE`.
    pub fn apply_env(&mut self, get: impl Fn(&str) -> Option<String>) {
        if let Some(v) = get("ASTP_CLIENT_ID") {
            self.client.id = v;
        }
        if let Some(v) = get("ASTP_NETWORK_ID") {
            self.client.network_id = v;
        }
        if let Some(v) = get("ASTP_DATA_DIR") {
            self.client.data_dir = PathBuf::from(v);
        }
        if let Some(v) = get("ASTP_BIND_INTERFACE") {
            self.client.bind_interface = if v.is_empty() { None } else { Some(v) };
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        if self.client.id.trim().is_empty() {
            return bad("client.id must not be empty".into());
        }
        let s = &self.schedule;
        if s.quick_interval_seconds == 0 || s.long_interval_seconds == 0 {
            return bad("schedule intervals must be > 0".into());
        }
        if !(60..=3600).contains(&s.long_duration_seconds) {
            return bad(
                "schedule.long_duration_seconds must be within 60..=3600 (1–60 min)".into(),
            );
        }
        if s.jitter_percent > 50 {
            return bad("schedule.jitter_percent must be <= 50".into());
        }
        let l = &self.limits;
        if l.max_connections == 0 || l.max_connections > 64 {
            return bad("limits.max_connections must be within 1..=64".into());
        }
        if l.max_test_bytes == 0 {
            return bad("limits.max_test_bytes must be > 0".into());
        }
        for (name, v) in [
            ("connect_timeout_seconds", l.connect_timeout_seconds),
            ("tls_timeout_seconds", l.tls_timeout_seconds),
            ("request_timeout_seconds", l.request_timeout_seconds),
        ] {
            if !(1..=120).contains(&v) {
                return bad(format!("limits.{name} must be within 1..=120"));
            }
        }
        if self.logs.max_file_bytes < 1024 {
            return bad("logs.max_file_bytes must be >= 1024".into());
        }
        let mut ids = std::collections::HashSet::new();
        for t in &self.targets {
            if !ids.insert(t.id.as_str()) {
                return bad(format!("duplicate target id {}", t.id));
            }
            if t.host.trim().is_empty() {
                return bad(format!("target {}: host must not be empty", t.id));
            }
            if t.host.parse::<std::net::IpAddr>().is_ok() && t.tls_server_name.is_none() {
                let needs_tls = t.enable_tls || t.enable_h2 || t.enable_quic || t.enable_h3;
                if needs_tls {
                    return bad(format!(
                        "target {}: host is an IP literal, set tls_server_name so the certificate can be verified",
                        t.id
                    ));
                }
            }
        }
        for c in &self.controls {
            if !ids.insert(c.id.as_str()) {
                return bad(format!("duplicate id {}", c.id));
            }
            if !c.url.starts_with("https://") {
                return bad(format!("control {}: url must be https://", c.id));
            }
        }
        if let Some(d) = &self.delivery {
            if !d.url.starts_with("https://") {
                return bad("delivery.url must be https://".into());
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- server ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub tls: ServerTlsSection,
    #[serde(default)]
    pub quic: QuicSection,
    #[serde(default)]
    pub admin: Option<AdminSection>,
    #[serde(default)]
    pub limits: ServerLimitsSection,
    #[serde(default)]
    pub logs: LogsSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub id: String,
    /// Address for TCP/TLS/HTTP/2, e.g. "0.0.0.0:443".
    pub listen: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsSection {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct QuicSection {
    #[serde(default)]
    pub enable: bool,
    /// UDP address, e.g. "0.0.0.0:443".
    #[serde(default)]
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSection {
    /// Separate listener for telemetry intake and status, e.g. "127.0.0.1:9443".
    pub listen: String,
    /// Name of the environment variable holding the bearer token.
    #[serde(default = "default_token_env")]
    pub token_env: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerLimitsSection {
    pub max_connections: usize,
    pub max_session_seconds: u64,
    pub max_session_bytes: u64,
    pub idle_timeout_seconds: u64,
    pub handshake_timeout_seconds: u64,
}

impl Default for ServerLimitsSection {
    fn default() -> Self {
        ServerLimitsSection {
            max_connections: 64,
            max_session_seconds: 3600,
            max_session_bytes: 64 * 1024 * 1024,
            idle_timeout_seconds: 60,
            handshake_timeout_seconds: 10,
        }
    }
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut cfg: ServerConfig = parse_file(path)?;
        cfg.apply_env(|k| std::env::var(k).ok());
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        let cfg: ServerConfig = toml::from_str(s).map_err(|e| ConfigError::Parse {
            path: PathBuf::from("<string>"),
            source: Box::new(e),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// `ASTP_SERVER_ID`, `ASTP_LISTEN`, `ASTP_DATA_DIR`.
    pub fn apply_env(&mut self, get: impl Fn(&str) -> Option<String>) {
        if let Some(v) = get("ASTP_SERVER_ID") {
            self.server.id = v;
        }
        if let Some(v) = get("ASTP_LISTEN") {
            self.server.listen = v;
        }
        if let Some(v) = get("ASTP_DATA_DIR") {
            self.server.data_dir = PathBuf::from(v);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |m: String| Err(ConfigError::Invalid(m));
        if self.server.id.trim().is_empty() {
            return bad("server.id must not be empty".into());
        }
        if self.server.listen.parse::<std::net::SocketAddr>().is_err() {
            return bad(format!(
                "server.listen is not ip:port: {}",
                self.server.listen
            ));
        }
        if self.quic.enable {
            match &self.quic.listen {
                Some(a) if a.parse::<std::net::SocketAddr>().is_ok() => {}
                _ => return bad("quic.listen must be ip:port when quic.enable = true".into()),
            }
        }
        if let Some(a) = &self.admin {
            if a.listen.parse::<std::net::SocketAddr>().is_err() {
                return bad(format!("admin.listen is not ip:port: {}", a.listen));
            }
            if a.listen == self.server.listen {
                return bad("admin.listen must differ from server.listen".into());
            }
            if let Some(q) = &self.quic.listen {
                if a.listen == *q {
                    return bad("admin.listen must differ from quic.listen".into());
                }
            }
        }
        let l = &self.limits;
        if l.max_connections == 0 {
            return bad("limits.max_connections must be > 0".into());
        }
        if !(60..=3600).contains(&l.max_session_seconds) {
            return bad("limits.max_session_seconds must be within 60..=3600".into());
        }
        if l.max_session_bytes == 0
            || l.idle_timeout_seconds == 0
            || l.handshake_timeout_seconds == 0
        {
            return bad("limits must be > 0".into());
        }
        Ok(())
    }
}

fn parse_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;
    toml::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        source: Box::new(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_EXAMPLE: &str = r#"
[client]
id = "client-01"
log_level = "info"
data_dir = "./data"

[schedule]
quick_interval_seconds = 300
long_interval_seconds = 1800
long_duration_seconds = 300
jitter_percent = 10

[limits]
max_connections = 4
max_test_bytes = 10485760
connect_timeout_seconds = 5

[[targets]]
id = "gateway-01"
host = "probe.example.net"
port = 443
enable_tcp = true
enable_tls = true
enable_h2 = true
enable_quic = true
enable_h3 = true
"#;

    #[test]
    fn parses_spec_example() {
        let c = ClientConfig::from_toml(SPEC_EXAMPLE).unwrap();
        assert_eq!(c.client.id, "client-01");
        assert_eq!(c.limits.tls_timeout_seconds, 8);
        assert_eq!(c.targets[0].server_name(), "probe.example.net");
        assert!(c.targets[0].enable_h3);
    }

    #[test]
    fn minimal_client_uses_defaults() {
        let c = ClientConfig::from_toml("[client]\nid = \"x\"\n").unwrap();
        assert_eq!(c.schedule.quick_interval_seconds, 300);
        assert_eq!(c.limits.max_connections, 4);
        assert_eq!(c.client.network_id, "unknown");
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = ClientConfig::from_toml("[client]\nid = \"x\"\nbogus = 1\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn ip_target_needs_server_name() {
        let t = "[client]\nid=\"x\"\n[[targets]]\nid=\"a\"\nhost=\"192.0.2.1\"\n";
        assert!(matches!(
            ClientConfig::from_toml(t),
            Err(ConfigError::Invalid(_))
        ));
        let t = format!("{t}tls_server_name=\"probe.example.net\"\n");
        let c = ClientConfig::from_toml(&t).unwrap();
        assert_eq!(c.targets[0].server_name(), "probe.example.net");
    }

    #[test]
    fn ip_target_tcp_only_is_fine() {
        let t = "[client]\nid=\"x\"\n[[targets]]\nid=\"a\"\nhost=\"192.0.2.1\"\nenable_tls=false\nenable_h2=false\n";
        ClientConfig::from_toml(t).unwrap();
    }

    #[test]
    fn rejects_bad_limits_and_duplicates() {
        for t in [
            "[client]\nid=\"x\"\n[limits]\nmax_connections=0\nmax_test_bytes=1\nconnect_timeout_seconds=5\n",
            "[client]\nid=\"x\"\n[schedule]\nquick_interval_seconds=1\nlong_interval_seconds=1\nlong_duration_seconds=10\njitter_percent=1\n",
            "[client]\nid=\"x\"\n[[targets]]\nid=\"a\"\nhost=\"h\"\n[[targets]]\nid=\"a\"\nhost=\"h\"\n",
            "[client]\nid=\"x\"\n[[controls]]\nid=\"c\"\nurl=\"http://e.org\"\n",
            "[client]\nid=\"\"\n",
        ] {
            assert!(
                matches!(ClientConfig::from_toml(t), Err(ConfigError::Invalid(_))),
                "should reject: {t}"
            );
        }
    }

    #[test]
    fn env_overrides() {
        let mut c = ClientConfig::from_toml("[client]\nid = \"x\"\n").unwrap();
        c.apply_env(|k| match k {
            "ASTP_NETWORK_ID" => Some("t2-mobile".into()),
            "ASTP_BIND_INTERFACE" => Some("eno1".into()),
            _ => None,
        });
        assert_eq!(c.client.network_id, "t2-mobile");
        assert_eq!(c.client.bind_interface.as_deref(), Some("eno1"));
    }

    const SERVER: &str = r#"
[server]
id = "gateway-01"
listen = "0.0.0.0:443"

[tls]
cert_file = "/etc/astp/cert.pem"
key_file = "/etc/astp/key.pem"

[quic]
enable = true
listen = "0.0.0.0:443"

[admin]
listen = "127.0.0.1:9443"
"#;

    #[test]
    fn parses_server() {
        let s = ServerConfig::from_toml(SERVER).unwrap();
        assert_eq!(s.server.id, "gateway-01");
        assert!(s.quic.enable);
        assert_eq!(s.limits.max_connections, 64);
    }

    #[test]
    fn server_rejects_admin_on_public_port() {
        let t = SERVER.replace("127.0.0.1:9443", "0.0.0.0:443");
        assert!(matches!(
            ServerConfig::from_toml(&t),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn example_files_match_the_schema() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        ClientConfig::load(&root.join("configs/client.example.toml")).unwrap();
        ServerConfig::load(&root.join("configs/server.example.toml")).unwrap();
    }

    #[test]
    fn server_quic_requires_listen() {
        let t = SERVER.replace("listen = \"0.0.0.0:443\"\n\n[admin]", "\n[admin]");
        assert!(ServerConfig::from_toml(&t).is_err());
    }
}
