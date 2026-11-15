//! CC 5.1 — the **per-stream call DEK** under the group exporter
//! (CIRISVerify#308, CIRISConstitution#169).
//!
//! ```text
//! exporter_secret = MLS-Exporter(label = "ciris-stream-dek/v1", context = "", length = 32)
//! DEK(stream_id, epoch) = HKDF-SHA256(ikm  = exporter_secret,
//!                                     salt = "",
//!                                     info = b"ciris-stream-dek/v1" ‖ stream_id_utf8 ‖ epoch_be8,
//!                                     len  = 32)
//! ```
//!
//! One label, [`STREAM_DEK_LABEL`], serves both the exporter call and the
//! `info` tag. `epoch_be8` is the `u64` epoch big-endian (the CC 5.3.3.1
//! encoding). There is no length prefix: the fixed tag, the fixed-length
//! stream id and the fixed 8-byte epoch parse unambiguously.
//!
//! ## What the caller supplies
//!
//! Verify does no MLS. The caller passes the 32-byte output of
//! **exactly** `MLS-Exporter("ciris-stream-dek/v1", "", 32)` on the group's
//! epoch `epoch`: label [`STREAM_DEK_LABEL`], an **empty** context, length 32.
//! A different label or a non-empty context yields different bytes from every
//! other implementation. The exporter secret itself is never wrapped; a
//! `key_grant:stream:v1` wraps the DEK this module returns and so opens one
//! stream only.
//!
//! ## The stream id
//!
//! `stream_id` is the A/V stream label `av-{lowercase hex of the 32-byte A/V
//! header stream_id}` (67 bytes), the one spelling edge, persist and the
//! CC 5.3.3.1 nonce prefix share ([`av_stream_id`] builds it). Anything else is
//! refused: in particular a bare 64-hex id, which persist reserves for the
//! inline blob's one-leaf log (CIRISPersist#953).
//!
//! ## Not to be confused with
//!
//! [`crate::epoch_key::derive_epoch_key`] (salted, length-prefixed, a stream
//! root rather than an MLS exporter secret). The two derive different bytes and
//! neither is a variant of the other.
//!
//! Known answers: `tests/vectors/stream_dek/stream_dek_vectors.json`, generated
//! independently of this code (see the README beside it).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The one CC 5.1 label: the MLS exporter label and the HKDF `info` tag.
pub const STREAM_DEK_LABEL: &str = "ciris-stream-dek/v1";
/// Exporter context the caller must use: empty.
pub const STREAM_DEK_EXPORTER_CONTEXT: &[u8] = b"";
/// Exporter output length the caller must request, and the DEK length.
pub const STREAM_DEK_LEN: usize = 32;
/// Prefix of an A/V stream id.
pub const AV_STREAM_ID_PREFIX: &str = "av-";
/// Length of an A/V stream id: `av-` + 64 lowercase hex digits.
pub const AV_STREAM_ID_LEN: usize = 3 + 64;

/// Why a stream DEK was not derived.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StreamDekError {
    /// `stream_id` is not `av-` followed by 64 lowercase hex digits.
    #[error("stream_id is not av-{{64 lowercase hex}}")]
    MalformedStreamId,
}

/// The A/V stream id string for a 32-byte A/V header stream id:
/// `av-{lowercase hex}`.
#[must_use]
pub fn av_stream_id(header_stream_id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(AV_STREAM_ID_LEN);
    s.push_str(AV_STREAM_ID_PREFIX);
    s.push_str(&hex::encode(header_stream_id));
    s
}

/// Check that `stream_id` is `av-` followed by exactly 64 lowercase hex
/// digits.
///
/// # Errors
/// [`StreamDekError::MalformedStreamId`] otherwise.
pub fn validate_stream_id(stream_id: &str) -> Result<(), StreamDekError> {
    let hex_part = stream_id
        .strip_prefix(AV_STREAM_ID_PREFIX)
        .ok_or(StreamDekError::MalformedStreamId)?;
    if hex_part.len() == 64
        && hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(StreamDekError::MalformedStreamId)
    }
}

/// The HKDF `info`: `b"ciris-stream-dek/v1" ‖ utf8(stream_id) ‖ u64_be(epoch)`.
/// Does not validate `stream_id`.
#[must_use]
pub fn stream_dek_info(stream_id: &str, epoch: u64) -> Vec<u8> {
    let sid = stream_id.as_bytes();
    let mut info = Vec::with_capacity(STREAM_DEK_LABEL.len() + sid.len() + 8);
    info.extend_from_slice(STREAM_DEK_LABEL.as_bytes());
    info.extend_from_slice(sid);
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

/// CC 5.1 — the DEK of `stream_id` at `epoch`.
///
/// `exporter_secret` MUST be `MLS-Exporter("ciris-stream-dek/v1", "", 32)` of
/// the group at `epoch` (see the module docs). Deterministic, no I/O.
///
/// # Errors
/// [`StreamDekError::MalformedStreamId`] when `stream_id` is not
/// `av-{64 lowercase hex}`.
pub fn stream_dek(
    exporter_secret: &[u8; STREAM_DEK_LEN],
    stream_id: &str,
    epoch: u64,
) -> Result<Zeroizing<[u8; STREAM_DEK_LEN]>, StreamDekError> {
    validate_stream_id(stream_id)?;
    let mut out = Zeroizing::new([0u8; STREAM_DEK_LEN]);
    // Empty salt: RFC 5869's HashLen-zeros default.
    Hkdf::<Sha256>::new(None, exporter_secret)
        .expand(&stream_dek_info(stream_id, epoch), out.as_mut())
        .expect("HKDF-SHA256 expand of 32 bytes is within the RFC 5869 cap");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [0x42; 32];

    fn sid(b: u8) -> String {
        av_stream_id(&[b; 32])
    }

    #[test]
    fn label_is_the_cc_5_1_label() {
        assert_eq!(STREAM_DEK_LABEL.as_bytes(), b"ciris-stream-dek/v1");
        assert!(STREAM_DEK_EXPORTER_CONTEXT.is_empty());
    }

    #[test]
    fn av_stream_id_shape() {
        let s = sid(0xab);
        assert_eq!(s.len(), AV_STREAM_ID_LEN);
        assert!(s.starts_with("av-abab"));
        assert!(validate_stream_id(&s).is_ok());
    }

    #[test]
    fn streams_epochs_and_secrets_are_isolated() {
        let a0 = stream_dek(&SECRET, &sid(1), 0).unwrap();
        let a1 = stream_dek(&SECRET, &sid(1), 1).unwrap();
        let b0 = stream_dek(&SECRET, &sid(2), 0).unwrap();
        let o0 = stream_dek(&[0x11; 32], &sid(1), 0).unwrap();
        assert_ne!(*a0, *a1);
        assert_ne!(*a0, *b0);
        assert_ne!(*a0, *o0);
        assert_eq!(*a0, *stream_dek(&SECRET, &sid(1), 0).unwrap());
    }

    #[test]
    fn info_layout() {
        let s = sid(3);
        let info = stream_dek_info(&s, 5);
        assert_eq!(info.len(), STREAM_DEK_LABEL.len() + AV_STREAM_ID_LEN + 8);
        assert!(info.starts_with(STREAM_DEK_LABEL.as_bytes()));
        assert_eq!(&info[info.len() - 8..], &5u64.to_be_bytes());
    }

    #[test]
    fn malformed_stream_ids_are_refused() {
        let hex = "ab".repeat(32);
        for bad in [
            hex.clone(),
            format!("av-{}", hex.to_uppercase()),
            format!("av-{}", &hex[..63]),
            format!("av-{hex}0"),
            format!("AV-{hex}"),
            String::new(),
            "av-".to_string(),
        ] {
            assert_eq!(
                stream_dek(&SECRET, &bad, 0).unwrap_err(),
                StreamDekError::MalformedStreamId,
                "{bad:?}"
            );
        }
    }
}
