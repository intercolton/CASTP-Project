//! Small big-endian readers that fail instead of panicking on a short slice.

/// Copy the first `N` bytes. Returns `None` when `buf` is shorter than `N`.
pub(crate) fn copy_prefix<const N: usize>(buf: &[u8]) -> Option<[u8; N]> {
    let slice = buf.get(..N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Some(out)
}

/// Copy `buf` only when its length is exactly `N`.
pub(crate) fn copy_exact<const N: usize>(buf: &[u8]) -> Option<[u8; N]> {
    if buf.len() != N {
        return None;
    }
    copy_prefix(buf)
}

/// Copy `N` bytes starting at `at`.
pub(crate) fn copy_at<const N: usize>(buf: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    copy_prefix(buf.get(at..end)?)
}
