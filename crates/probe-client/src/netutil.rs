//! DNS and TCP connect with optional interface binding.

pub use probe_common::counting::{Counters, Counting};
use probe_common::ErrorCode;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// A failure with its classification and a human-readable detail.
#[derive(Debug, Clone)]
pub struct Failure {
    pub code: ErrorCode,
    pub detail: String,
}

impl Failure {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Failure {
            code,
            detail: detail.into(),
        }
    }
}

/// Resolves `host:port`. An IP literal resolves without touching DNS.
pub async fn resolve(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>, Failure> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await {
        Err(_) => Err(Failure::new(
            ErrorCode::DnsFailure,
            format!("no DNS answer within {}s", timeout.as_secs()),
        )),
        Ok(Err(e)) => Err(Failure::new(ErrorCode::DnsFailure, e.to_string())),
        Ok(Ok(addrs)) => {
            // IPv4 first: IPv6 is only used when explicitly targeted (spec 5.3).
            let mut v: Vec<SocketAddr> = addrs.collect();
            v.sort_by_key(|a| !a.is_ipv4());
            if v.is_empty() {
                Err(Failure::new(ErrorCode::DnsFailure, "empty DNS answer"))
            } else {
                Ok(v)
            }
        }
    }
}

/// SO_BINDTODEVICE: traffic leaves through `dev` regardless of the routing
/// table, which is how tests bypass a VPN tunnel on the same machine.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_to_interface(socket: &socket2::Socket, dev: &str) -> Result<(), Failure> {
    socket.bind_device(Some(dev.as_bytes())).map_err(|e| {
        Failure::new(
            ErrorCode::LocalNetworkUnavailable,
            format!("bind to interface {dev}: {e}"),
        )
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn bind_to_interface(_socket: &socket2::Socket, dev: &str) -> Result<(), Failure> {
    Err(Failure::new(
        ErrorCode::Unsupported,
        format!("binding to interface {dev} is only supported on Linux; turn the VPN off instead"),
    ))
}

/// Opens a TCP connection, optionally bound to `iface` with SO_BINDTODEVICE.
pub async fn connect(
    addr: SocketAddr,
    iface: Option<&str>,
    timeout: Duration,
) -> Result<TcpStream, Failure> {
    let domain = socket2::Domain::for_address(addr);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .map_err(|e| Failure::new(ErrorCode::LocalNetworkUnavailable, format!("socket: {e}")))?;
    if let Some(dev) = iface {
        bind_to_interface(&socket, dev)?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|e| Failure::new(ErrorCode::Unknown, format!("nonblocking: {e}")))?;
    let std_stream: std::net::TcpStream = socket.into();
    let sock = tokio::net::TcpSocket::from_std_stream(std_stream);
    match tokio::time::timeout(timeout, sock.connect(addr)).await {
        Err(_) => Err(Failure::new(
            ErrorCode::TcpTimeout,
            format!("no SYN-ACK within {}s", timeout.as_secs()),
        )),
        Ok(Err(e)) => Err(Failure::new(
            ErrorCode::from_connect_error(&e),
            e.to_string(),
        )),
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn ip_literal_skips_dns() {
        let v = resolve("192.0.2.7", 443, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(v, vec!["192.0.2.7:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn dns_failure_is_classified() {
        // A DNS label is at most 63 octets (RFC 1035 §3.1): the length
        // lives in the low 6 bits of the label-length byte. This name
        // cannot be encoded in a query, so the stub resolver rejects it
        // in-process and never sends a packet.
        let host = "a".repeat(64);
        let f = resolve(&host, 443, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(f.code, ErrorCode::DnsFailure);
        assert!(
            !f.detail.contains("no DNS answer within"),
            "lookup blocked on the network: {f:?}"
        );
    }

    #[tokio::test]
    async fn refused_is_classified() {
        // Bind then drop to get a port nobody listens on.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        // Windows retries the SYN for ~2 s before reporting the refusal.
        let f = connect(addr, None, Duration::from_secs(10))
            .await
            .unwrap_err();
        assert_eq!(f.code, ErrorCode::TcpRefused);
    }

    /// Hermetic: a local listener whose accept queue is full drops further
    /// SYNs (Linux, `tcp_abort_on_overflow = 0`), so the connect sees no
    /// SYN-ACK. No packet leaves the machine, unlike probing a TEST-NET
    /// address, which a proxy or filter can answer with a refusal.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_is_classified() {
        let listener = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        listener
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        listener.listen(0).unwrap();
        let addr = listener.local_addr().unwrap().as_socket().unwrap();

        // Never accepted: fill the queue until a connect stops completing.
        let mut held = Vec::new();
        let mut full = false;
        for _ in 0..16 {
            match connect(addr, None, Duration::from_millis(300)).await {
                Ok(s) => held.push(s),
                Err(f) => {
                    assert_eq!(f.code, ErrorCode::TcpTimeout, "{f:?}");
                    full = true;
                    break;
                }
            }
        }
        assert!(full, "accept queue never filled ({} connected)", held.len());

        let f = connect(addr, None, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert_eq!(f.code, ErrorCode::TcpTimeout, "{f:?}");
        assert!(f.detail.contains("no SYN-ACK"), "{f:?}");
        drop(listener);
    }

    #[tokio::test]
    async fn bad_interface_is_reported() {
        let f = connect(
            "127.0.0.1:9".parse().unwrap(),
            Some("no-such-if0"),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        let expected = if cfg!(any(target_os = "linux", target_os = "android")) {
            ErrorCode::LocalNetworkUnavailable
        } else {
            ErrorCode::Unsupported
        };
        assert_eq!(f.code, expected);
        assert!(f.detail.contains("no-such-if0"));
    }

    #[tokio::test]
    async fn counting_counts_both_directions() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(b"0123456789").await.unwrap();
        });
        let s = connect(addr, None, Duration::from_secs(2)).await.unwrap();
        let (mut c, counters) = Counting::new(s);
        c.write_all(b"hello").await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        assert_eq!(counters.sent(), 5);
        assert_eq!(counters.received(), 10);
    }
}
