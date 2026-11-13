//! Non-Linux placeholder: the device cannot be created.

use std::io;

/// Not available on this platform.
#[derive(Debug)]
pub struct Tun(());

impl Tun {
    pub fn create(_name: &str) -> io::Result<Tun> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN devices are only supported on Linux",
        ))
    }
    pub fn name(&self) -> &str {
        ""
    }
    pub async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    pub async fn send(&self, _pkt: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
