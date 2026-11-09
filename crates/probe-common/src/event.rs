//! The JSONL event schema (section 8 of the spec).
//!
//! The first block of fields is exactly the one the spec lists. Everything
//! after it is optional, skipped when empty, and exists because measurements
//! showed it is needed to interpret failures: how far the connection got
//! (`phase`), which TLS stack produced the ClientHello (`tls_stack`), and which
//! local interface carried the traffic (`interface`).

use crate::error_code::ErrorCode;
use crate::timefmt;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestType {
    DnsResolution,
    TcpConnect,
    TlsHandshake,
    HttpsGet,
    H2Request,
    QuicHandshake,
    H3Request,
    Echo,
    Download,
    LongSession,
    /// Server side: a TCP connection was accepted (logged before any TLS).
    TcpAccept,
    /// Server side: a QUIC connection attempt arrived.
    QuicAccept,
}

impl TestType {
    pub fn as_str(self) -> &'static str {
        match self {
            TestType::DnsResolution => "dns_resolution",
            TestType::TcpConnect => "tcp_connect",
            TestType::TlsHandshake => "tls_handshake",
            TestType::HttpsGet => "https_get",
            TestType::H2Request => "h2_request",
            TestType::QuicHandshake => "quic_handshake",
            TestType::H3Request => "h3_request",
            TestType::Echo => "echo",
            TestType::Download => "download",
            TestType::LongSession => "long_session",
            TestType::TcpAccept => "tcp_accept",
            TestType::QuicAccept => "quic_accept",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Client,
    Server,
}

/// How far a connection progressed. Ordered: a later variant implies the
/// earlier ones happened. This is what separates "blocked at TCP" from "TCP
/// passed, TLS never finished" from "dropped mid-session".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    None,
    DnsResolved,
    TcpConnected,
    /// Server side: some application bytes arrived but no handshake completed.
    FirstBytesReceived,
    HandshakeDone,
    AppDataSent,
    AppDataReceived,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeEvent {
    pub schema_version: u32,
    pub timestamp: String,
    pub test_id: String,
    pub probe_id: String,
    pub network_id: String,
    pub target_id: String,
    pub test_type: TestType,
    pub transport: Transport,
    pub duration_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub success: bool,
    pub error_code: Option<ErrorCode>,

    #[serde(default = "default_side")]
    pub side: Side,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<Phase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Label of the TLS/QUIC stack that built the handshake, e.g. `rustls-0.23/ring`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_stack: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// True for checks against the independent control resource.
    #[serde(default, skip_serializing_if = "is_false")]
    pub control: bool,
    /// Server side only: the peer address. Reports must not print it verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_ms: Option<u64>,
}

fn default_side() -> Side {
    Side::Client
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ProbeEvent {
    /// A new, not-yet-successful event stamped with the current UTC time.
    pub fn new(
        test_id: impl Into<String>,
        probe_id: impl Into<String>,
        network_id: impl Into<String>,
        target_id: impl Into<String>,
        test_type: TestType,
        transport: Transport,
    ) -> Self {
        ProbeEvent {
            schema_version: SCHEMA_VERSION,
            timestamp: timefmt::now_rfc3339(),
            test_id: test_id.into(),
            probe_id: probe_id.into(),
            network_id: network_id.into(),
            target_id: target_id.into(),
            test_type,
            transport,
            duration_ms: 0,
            bytes_sent: 0,
            bytes_received: 0,
            success: false,
            error_code: None,
            side: Side::Client,
            phase: None,
            detail: None,
            tls_stack: None,
            alpn: None,
            interface: None,
            control: false,
            peer: None,
            connect_ms: None,
            handshake_ms: None,
        }
    }

    pub fn new_test_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub fn succeed(mut self) -> Self {
        self.success = true;
        self.error_code = None;
        self
    }

    pub fn fail(mut self, code: ErrorCode, detail: impl Into<String>) -> Self {
        self.success = false;
        self.error_code = Some(code);
        self.detail = Some(detail.into());
        self
    }

    /// Checks the invariants every written event must hold.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!("unknown schema_version {}", self.schema_version));
        }
        if timefmt::parse_rfc3339(&self.timestamp).is_none() {
            return Err(format!("timestamp is not RFC 3339: {}", self.timestamp));
        }
        if self.test_id.is_empty() || self.probe_id.is_empty() || self.target_id.is_empty() {
            return Err("test_id, probe_id and target_id must not be empty".into());
        }
        match (self.success, self.error_code) {
            (true, Some(c)) => Err(format!("successful event carries error_code {c}")),
            (false, None) => Err("failed event has no error_code".into()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProbeEvent {
        ProbeEvent::new(
            "test-unique-id",
            "client-01",
            "network-a",
            "gateway-01",
            TestType::TlsHandshake,
            Transport::Tcp,
        )
    }

    #[test]
    fn spec_example_parses() {
        let line = r#"{"schema_version":1,"timestamp":"2026-11-02T12:00:00Z","test_id":"test-unique-id","probe_id":"client-01","network_id":"network-a","target_id":"gateway-01","test_type":"tls_handshake","transport":"tcp","duration_ms":83,"bytes_sent":0,"bytes_received":0,"success":true,"error_code":null}"#;
        let e: ProbeEvent = serde_json::from_str(line).unwrap();
        assert_eq!(e.test_type, TestType::TlsHandshake);
        assert_eq!(e.duration_ms, 83);
        assert_eq!(e.side, Side::Client);
        e.validate().unwrap();
    }

    #[test]
    fn required_fields_always_serialized_and_optional_skipped() {
        let e = sample().succeed();
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        for k in [
            "schema_version",
            "timestamp",
            "test_id",
            "probe_id",
            "network_id",
            "target_id",
            "test_type",
            "transport",
            "duration_ms",
            "bytes_sent",
            "bytes_received",
            "success",
            "error_code",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        assert!(v["error_code"].is_null());
        assert!(v.get("detail").is_none());
        assert!(v.get("control").is_none());
    }

    #[test]
    fn round_trip_with_extras() {
        let mut e = sample().fail(ErrorCode::TlsHandshakeFailed, "eof after ClientHello");
        e.phase = Some(Phase::TcpConnected);
        e.tls_stack = Some("rustls-0.23/ring".into());
        e.control = true;
        let s = serde_json::to_string(&e).unwrap();
        let back: ProbeEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
        back.validate().unwrap();
    }

    #[test]
    fn validate_rejects_inconsistent_success() {
        let mut e = sample().succeed();
        e.error_code = Some(ErrorCode::Unknown);
        assert!(e.validate().is_err());
        let mut e = sample();
        e.success = false;
        e.error_code = None;
        assert!(e.validate().is_err());
    }

    #[test]
    fn phases_are_ordered() {
        assert!(Phase::TcpConnected < Phase::HandshakeDone);
        assert!(Phase::HandshakeDone < Phase::Completed);
    }
}
