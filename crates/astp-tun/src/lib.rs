//! ASTP-M v1 TUN side (`docs/design/network.md`).
//!
//! - [`Tun`]: a Linux TUN device (`IFF_TUN | IFF_NO_PI`), read and written
//!   as whole IP packets without blocking the runtime.
//! - [`packet`]: version and addresses of a raw IP packet.
//! - [`netcfg`]: addresses, MTU and routes through `ip` (iproute2).
//! - [`pump`]: moves packets between a device and two channels.

pub mod netcfg;
pub mod packet;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Tun;

#[cfg(not(target_os = "linux"))]
mod other;
#[cfg(not(target_os = "linux"))]
pub use other::Tun;

use tokio::sync::mpsc;

/// Largest packet read from a device.
pub const MAX_PACKET: usize = 65_535;

/// Copies packets from `tun` to `to_net` and from `from_net` to `tun`
/// until either channel closes or the device fails. A full `to_net`
/// drops the packet, as an interface queue would.
pub async fn pump(
    tun: &Tun,
    to_net: mpsc::Sender<Vec<u8>>,
    mut from_net: mpsc::Receiver<Vec<u8>>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        tokio::select! {
            r = tun.recv(&mut buf) => {
                let n = r?;
                if n == 0 {
                    continue;
                }
                match to_net.try_send(buf[..n].to_vec()) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                }
            }
            p = from_net.recv() => match p {
                None => return Ok(()),
                Some(p) => {
                    if let Err(e) = tun.send(&p).await {
                        // A single bad packet (EINVAL) must not end the tunnel.
                        tracing::debug!("TUN write: {e}");
                    }
                }
            }
        }
    }
}
