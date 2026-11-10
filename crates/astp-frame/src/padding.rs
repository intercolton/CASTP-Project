//! Camouflage padding profile v1 (spec draft 0.3 §5.2).
//!
//! The helper decides whether `PAD` is needed and how many octets to add.
//! The production encoder fills those octets from the operating-system
//! CSPRNG (`rand::rngs::OsRng`). A raw [`crate::encode`] with `pad_octets
//! == None` still emits an unpadded frame; the decoder accepts both.

use astp_types::{DEFAULT_MAX_PAD, DEFAULT_MIN_WIRE_SIZE, DEFAULT_PADDING_STEP, MAX_FRAME_LENGTH};

use crate::codec::{encode_to, encoded_content};
use crate::error::FrameError;
use crate::types::Frame;

/// Defaults from spec draft 0.3 §5.2: step 64, minimum wire size 64, `max_pad` 255.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CamouflageProfile {
    /// Wire-size step in bytes. The v1 profile uses 64. Zero does not panic.
    pub padding_step: u32,
    /// Minimum encoded size in bytes, including the 8-byte header.
    pub min_wire_size: u32,
    /// Maximum number of padding octets, not counting the 2-byte `pad_len`.
    pub max_pad: u16,
}

impl CamouflageProfile {
    /// The v1 profile.
    pub const V1: Self = Self {
        padding_step: DEFAULT_PADDING_STEP,
        min_wire_size: DEFAULT_MIN_WIRE_SIZE,
        max_pad: DEFAULT_MAX_PAD,
    };
}

impl Default for CamouflageProfile {
    fn default() -> Self {
        Self::V1
    }
}

/// How many padding octets the camouflage profile needs.
///
/// `content_len` is the length of the content *before* `PAD` is applied
/// and already includes the key-epoch byte when that flag will be set.
///
/// Returns `None` when `8 + content_len` is already at least `min_wire`
/// and a multiple of `step` (no `PAD` flag). Otherwise returns the octet
/// count, not including the 2-byte `pad_len` trailer. When the aligned
/// count would exceed `max_pad`, the result is `Some(max_pad)` and the
/// wire size may stay unaligned.
///
/// `step == 0` does not panic and does not align. If the bare frame is
/// already at least `min_wire`, the result is `None`; otherwise the frame
/// is padded toward `min_wire`, still capped by `max_pad`.
#[must_use]
pub fn camouflage_pad_len(
    content_len: usize,
    step: u32,
    min_wire: u32,
    max_pad: u16,
) -> Option<u16> {
    let content = u64::try_from(content_len).unwrap_or(u64::MAX);
    let step = u64::from(step);
    let min_wire = u64::from(min_wire);
    let cap = u64::from(max_pad);
    let bare = 8u64.saturating_add(content);

    if step == 0 {
        if bare >= min_wire {
            return None;
        }
        return cap_pad(min_wire.max(bare.saturating_add(2)), bare, cap, max_pad);
    }

    if bare >= min_wire && bare % step == 0 {
        return None;
    }
    let min_target = bare.saturating_add(2).max(min_wire);
    let target = match align_up(min_target, step) {
        Some(value) => value,
        None => return Some(max_pad),
    };
    cap_pad(target, bare, cap, max_pad)
}

fn cap_pad(target: u64, bare: u64, cap: u64, max_pad: u16) -> Option<u16> {
    let pad = target.saturating_sub(bare).saturating_sub(2);
    if pad > cap {
        Some(max_pad)
    } else {
        Some(u16::try_from(pad).unwrap_or(max_pad))
    }
}

fn align_up(value: u64, step: u64) -> Option<u64> {
    if step == 0 {
        return Some(value);
    }
    let rem = value % step;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(step - rem)
    }
}

/// Encode with camouflage profile v1.
///
/// Padding octets come from [`rand::rngs::OsRng`] (`TryRngCore::try_fill_bytes`).
/// The decoder accepts any octets; only this encoder is required to use a
/// CSPRNG. When the profile says no padding is needed, the `PAD` flag stays
/// clear. If the OS generator fails, this returns [`FrameError::Random`]
/// and does not emit an all-zero pad.
///
/// # Errors
///
/// Same as [`crate::encode`]. Also [`FrameError::FrameTooLong`] when the
/// padded payload would exceed 65535 bytes, and [`FrameError::Random`] when
/// the CSPRNG fails.
pub fn encode_camouflage(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    encode_camouflage_with(frame, &CamouflageProfile::V1, fill_os_random)
}

/// Encode with an explicit profile and padding source.
///
/// `fill` is called only when the profile asks for one or more padding
/// octets. It is not called for the 2-byte `pad_len` trailer, and not when
/// `pad_len` is 0 or padding is omitted. Tests pass a closure that writes
/// a fixed byte and returns `Ok(())`. Production code uses [`encode_camouflage`].
///
/// # Errors
///
/// Same as [`encode_camouflage`], plus whatever `fill` returns.
pub fn encode_camouflage_with(
    frame: &Frame,
    profile: &CamouflageProfile,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), FrameError>,
) -> Result<Vec<u8>, FrameError> {
    let content = encoded_content(frame)?;
    let decided = camouflage_pad_len(
        content.len(),
        profile.padding_step,
        profile.min_wire_size,
        profile.max_pad,
    );
    let pad = match decided {
        None => None,
        Some(n) => {
            let total = content
                .len()
                .saturating_add(usize::from(n))
                .saturating_add(2);
            if total > usize::try_from(MAX_FRAME_LENGTH).unwrap_or(usize::MAX) {
                return Err(FrameError::FrameTooLong {
                    length: u32::try_from(total).unwrap_or(u32::MAX),
                    max_frame: MAX_FRAME_LENGTH,
                });
            }
            let mut octets = vec![0u8; usize::from(n)];
            if !octets.is_empty() {
                fill(&mut octets)?;
            }
            Some(octets)
        }
    };
    let mut out = Vec::new();
    encode_to(frame, pad.as_deref(), &mut out)?;
    Ok(out)
}

fn fill_os_random(buf: &mut [u8]) -> Result<(), FrameError> {
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, buf).map_err(|err| {
        FrameError::Random {
            detail: err.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{camouflage_pad_len, encode_camouflage, CamouflageProfile};
    use crate::decode;
    use crate::types::{Frame, FrameBody};

    #[test]
    fn helper_matches_v3_v12_and_the_cap() {
        assert_eq!(camouflage_pad_len(8, 64, 64, 255), Some(46));
        assert_eq!(camouflage_pad_len(20, 64, 64, 255), Some(34));
        assert_eq!(camouflage_pad_len(56, 64, 64, 255), None);
        assert_eq!(camouflage_pad_len(8, 64, 64, 10), Some(10));
        assert_eq!(camouflage_pad_len(54, 64, 64, 255), Some(0));
        assert_eq!(camouflage_pad_len(100, 64, 64, 255), Some(18));
    }

    #[test]
    fn helper_does_not_panic_on_extremes() {
        let _ = camouflage_pad_len(usize::MAX, 64, 64, 255);
        let _ = camouflage_pad_len(usize::MAX, 0, 64, 255);
        let _ = camouflage_pad_len(0, 0, 64, 255);
        assert_eq!(camouflage_pad_len(0, 0, 64, 255), Some(54));
        assert_eq!(camouflage_pad_len(56, 0, 64, 255), None);
    }

    #[test]
    fn profile_v1_constants() {
        assert_eq!(CamouflageProfile::V1, CamouflageProfile::default());
        assert_eq!(CamouflageProfile::V1.padding_step, 64);
        assert_eq!(CamouflageProfile::V1.min_wire_size, 64);
        assert_eq!(CamouflageProfile::V1.max_pad, 255);
    }

    #[test]
    fn os_rng_pad_is_applied_for_a_short_ping() {
        let frame = Frame {
            key_epoch: None,
            body: FrameBody::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
        };
        let bytes = encode_camouflage(&frame).expect("camouflage");
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[0..4], &[0x01, 0x01, 0x00, 0x01]);
        let pad = &bytes[16..62];
        assert_eq!(pad.len(), 46);
        assert!(
            pad.iter().any(|byte| *byte != 0),
            "OsRng padding octets were left as zeros"
        );
        assert_eq!(&bytes[62..64], &0x002Eu16.to_be_bytes());
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded, frame);
    }
}
