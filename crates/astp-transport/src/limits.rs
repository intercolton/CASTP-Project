//! Timeouts and caps for one QUIC endpoint.

use std::time::Duration;

/// Limits for a QUIC listener or client.
///
/// Defaults: handshake 10 s, 256 handshakes in flight, retry of unvalidated
/// addresses from 128 of those, idle 30 s, client keep-alive 10 s, 1024
/// established connections, 10 s to read one ASTP-M frame, 16 KiB of HTTP/3
/// field section, 8 MiB datagram buffers.
#[derive(Debug, Clone)]
pub struct QuicLimits {
    /// `Incoming` to `Connection`. A stalled ClientHello frees its slot.
    pub handshake_timeout: Duration,
    /// Simultaneous handshakes that have not finished. Further attempts are refused.
    pub max_pending_handshakes: usize,
    /// Unvalidated addresses are answered with `retry()` once this many handshakes are pending.
    ///
    /// Refusing at [`Self::max_pending_handshakes`] still wins when the count is already there.
    pub retry_threshold: usize,
    /// QUIC idle timeout. The default is 30 s.
    pub max_idle_timeout: Duration,
    /// Client keep-alive interval. The default is 10 s. Servers do not send keep-alives.
    pub keep_alive_interval: Duration,
    /// Established connections. Further attempts are refused.
    ///
    /// A slow peer must not be able to hold a slot with a trickle of bytes
    /// after the 4 KiB + 8 byte mark where [`astp_frame::FrameReader`] may
    /// retain up to 64 KiB. This cap and [`Self::frame_read_timeout`] are
    /// that limit.
    pub max_connections: usize,
    /// How long [`astp_frame::FrameReader`] may wait for the next byte of one frame.
    pub frame_read_timeout: Duration,
    /// HTTP/3 `SETTINGS_MAX_FIELD_SECTION_SIZE`. The default is 16 KiB.
    pub max_field_section_size: u64,
    /// Quinn receive buffer for QUIC datagrams. `None` would disable them.
    pub datagram_receive_buffer_size: usize,
    /// Quinn send buffer for QUIC datagrams.
    pub datagram_send_buffer_size: usize,
}

impl Default for QuicLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            max_pending_handshakes: 256,
            retry_threshold: 128,
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            max_connections: 1024,
            frame_read_timeout: Duration::from_secs(10),
            max_field_section_size: 16 * 1024,
            datagram_receive_buffer_size: 8 * 1024 * 1024,
            datagram_send_buffer_size: 8 * 1024 * 1024,
        }
    }
}

impl QuicLimits {
    pub(crate) fn transport_config(
        &self,
        keep_alive: bool,
    ) -> Result<quinn::TransportConfig, super::TransportError> {
        let idle = quinn::IdleTimeout::try_from(self.max_idle_timeout).map_err(|_| {
            super::TransportError::Invalid {
                detail: "idle timeout is too large".into(),
            }
        })?;
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(idle));
        if keep_alive {
            transport.keep_alive_interval(Some(self.keep_alive_interval));
        }
        transport.datagram_receive_buffer_size(Some(self.datagram_receive_buffer_size));
        transport.datagram_send_buffer_size(self.datagram_send_buffer_size);
        Ok(transport)
    }
}
