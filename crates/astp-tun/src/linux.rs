//! `/dev/net/tun` on Linux.

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

/// `struct ifreq` as TUNSETIFF reads it: name, then the flags member of
/// the union, padded to the full 40 bytes.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// A TUN device. Closed (and removed by the kernel) when dropped.
#[derive(Debug)]
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl Tun {
    /// Creates a TUN device. `name` may contain `%d` for the kernel to
    /// pick a number (e.g. `astp%d`). Needs `CAP_NET_ADMIN`.
    pub fn create(name: &str) -> io::Result<Tun> {
        if name.is_empty() || name.len() >= IFNAMSIZ || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad interface name {name:?}"),
            ));
        }
        // SAFETY: a NUL-terminated path literal; the result is checked.
        let raw = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut req = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: `req` is a valid, writable ifreq-sized buffer for the call.
        let r = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut req as *mut IfReq) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = CStr::from_bytes_until_nul(&req.name)
            .map_err(|_| io::Error::other("kernel returned an unterminated name"))?
            .to_string_lossy()
            .into_owned();
        // SAFETY: `fd` is owned by the AsyncFd from here on and nothing
        // else closes or reuses the descriptor while it is registered.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Tun { fd, name: actual })
    }

    /// The interface name the kernel gave the device.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one packet into `buf`.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let r = guard.try_io(|fd| {
                // SAFETY: `buf` is valid for `buf.len()` writable bytes.
                let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes one packet.
    pub async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            let r = guard.try_io(|fd| {
                // SAFETY: `pkt` is valid for `pkt.len()` readable bytes.
                let n = unsafe { libc::write(fd.as_raw_fd(), pkt.as_ptr().cast(), pkt.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }
}
