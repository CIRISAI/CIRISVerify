//! CC 5.1 `CLM-epoch-keying` — per-`(stream_id, epoch)` DEK + stream-nonce
//! derivation (CIRISVerify#193).
//!
//! The **epoch-keyed counterpart** of `scope_privacy::derive_symbol_key`:
//! a stream's long-lived root secret is ratcheted into an independent
//! content-encryption key (and stream nonce) for each epoch, so compromise of one
//! epoch's DEK yields nothing about any other epoch (epoch isolation).
//!
//! ## Pinned formula (Verify-authored)
//!
//! ```text
//! info(label, stream_id, epoch) = utf8(label) ‖ u32_be(len(stream_id)) ‖ utf8(stream_id)
//!                                            ‖ u64_be(epoch)
//!
//! epoch_key   = HKDF-SHA256(salt = SALT_EPOCH, ikm = stream_root,
//!                           info = info(LABEL_EPOCH_KEY,   stream_id, epoch), L = 32)
//! epoch_nonce = HKDF-SHA256(salt = SALT_EPOCH, ikm = stream_root,
//!                           info = info(LABEL_EPOCH_NONCE, stream_id, epoch), L = 24)
//! ```
//!
//! Full HKDF (Extract-then-Expand, RFC 5869) — **not** the Expand-only form
//! `scope_privacy::expander_subkey` uses, because `stream_root` is not required
//! to be a uniformly-random 32-byte PRK.
//!
//! **Domain separation is load-bearing:**
//! - distinct `info` **labels** for the key vs the nonce, so the stream nonce can
//!   never equal (or leak) the DEK;
//! - the stream_id is **length-prefixed** (`u32_be` — the codebase's §19.0 lp
//!   discipline), so `("ab", e)` and `("a", …)` can never produce a colliding
//!   `info`;
//! - `epoch` is fixed-width big-endian, so epochs are totally ordered on the wire.
//!
//! **Cross-impl flag:** this formula is pinned HERE as the first conformant impl
//! (same treatment as `derive_symbol_key` / the `RecordType` integers).
//! CIRISConformance goldens it byte-for-byte (CC 5.1 `CLM-epoch-keying`);
//! CIRISPersist#432 consumes it. Any change is a wire-format break.

use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF **salt** for every CC 5.1 epoch derivation (the Extract step).
pub const SALT_EPOCH: &[u8] = b"CIRIS-epoch-key-v1";

/// `info` label for the per-epoch **content-encryption key** (DEK).
pub const LABEL_EPOCH_KEY: &str = "ciris/clm/epoch-dek/v1";

/// `info` label for the per-epoch **stream nonce** — a DISTINCT label, so the
/// nonce is cryptographically independent of the DEK.
pub const LABEL_EPOCH_NONCE: &str = "ciris/clm/epoch-nonce/v1";

/// Stream-nonce length: 24 bytes (XChaCha20-Poly1305, the AEAD this substrate
/// uses for content — see `crate::xchacha`).
pub const EPOCH_NONCE_LEN: usize = 24;

/// Build the domain-separated `info`:
/// `utf8(label) ‖ u32_be(len(stream_id)) ‖ utf8(stream_id) ‖ u64_be(epoch)`.
fn epoch_info(label: &str, stream_id: &str, epoch: u64) -> Vec<u8> {
    let id = stream_id.as_bytes();
    let mut info = Vec::with_capacity(label.len() + 4 + id.len() + 8);
    info.extend_from_slice(label.as_bytes());
    // u32-length-prefix the stream_id so a longer id can never impersonate a
    // shorter one followed by other bytes (concatenation ambiguity).
    info.extend_from_slice(&(u32::try_from(id.len()).unwrap_or(u32::MAX)).to_be_bytes());
    info.extend_from_slice(id);
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

/// HKDF-SHA256(salt = [`SALT_EPOCH`], ikm = `stream_root`, info, L) → `out`.
fn expand(stream_root: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(SALT_EPOCH), stream_root);
    hk.expand(info, out)
        .expect("HKDF-SHA256 expand of <= 255*32 bytes is within the RFC 5869 cap");
}

/// CC 5.1 — derive the **per-epoch DEK** for `(stream_id, epoch)` from the
/// stream's root secret. Deterministic, no I/O.
///
/// Epoch isolation: two different epochs (or two different streams) yield
/// independent keys; recovering one reveals nothing about another.
#[must_use]
pub fn derive_epoch_key(stream_root: &[u8; 32], stream_id: &str, epoch: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    expand(
        stream_root,
        &epoch_info(LABEL_EPOCH_KEY, stream_id, epoch),
        &mut out,
    );
    out
}

/// CC 5.1 — derive the **per-epoch stream nonce** (24 B, XChaCha20-Poly1305) for
/// `(stream_id, epoch)`. Uses a DISTINCT `info` label from
/// [`derive_epoch_key`], so the nonce is independent of the DEK.
#[must_use]
pub fn derive_epoch_stream_nonce(
    stream_root: &[u8; 32],
    stream_id: &str,
    epoch: u64,
) -> [u8; EPOCH_NONCE_LEN] {
    let mut out = [0u8; EPOCH_NONCE_LEN];
    expand(
        stream_root,
        &epoch_info(LABEL_EPOCH_NONCE, stream_id, epoch),
        &mut out,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256 as S};

    const ROOT: [u8; 32] = [0x42; 32];

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(
            derive_epoch_key(&ROOT, "stream-1", 7),
            derive_epoch_key(&ROOT, "stream-1", 7)
        );
        assert_eq!(
            derive_epoch_stream_nonce(&ROOT, "stream-1", 7),
            derive_epoch_stream_nonce(&ROOT, "stream-1", 7)
        );
    }

    #[test]
    fn epochs_are_isolated() {
        let a = derive_epoch_key(&ROOT, "s", 1);
        let b = derive_epoch_key(&ROOT, "s", 2);
        assert_ne!(a, b, "a different epoch must give an independent key");
    }

    #[test]
    fn streams_are_isolated() {
        assert_ne!(
            derive_epoch_key(&ROOT, "s1", 1),
            derive_epoch_key(&ROOT, "s2", 1)
        );
    }

    #[test]
    fn roots_are_isolated() {
        let other = [0x11u8; 32];
        assert_ne!(
            derive_epoch_key(&ROOT, "s", 1),
            derive_epoch_key(&other, "s", 1)
        );
    }

    /// The nonce is derived under a DISTINCT label — it must never coincide with
    /// (or be a prefix of) the DEK for the same (stream, epoch).
    #[test]
    fn nonce_is_independent_of_the_dek() {
        let k = derive_epoch_key(&ROOT, "s", 3);
        let n = derive_epoch_stream_nonce(&ROOT, "s", 3);
        assert_eq!(n.len(), 24);
        assert_ne!(
            &k[..EPOCH_NONCE_LEN],
            &n[..],
            "nonce must not be a prefix of the DEK"
        );
    }

    /// The length-prefix closes the concatenation-ambiguity hole: without it,
    /// `("ab", e)` and `("a", …)` could collide in `info`.
    #[test]
    fn stream_id_is_length_prefixed_no_concat_collision() {
        assert_ne!(
            derive_epoch_key(&ROOT, "ab", 1),
            derive_epoch_key(&ROOT, "a", 1)
        );
        // The lp is present in the info bytes.
        let info = epoch_info(LABEL_EPOCH_KEY, "abc", 5);
        assert_eq!(
            &info[LABEL_EPOCH_KEY.len()..LABEL_EPOCH_KEY.len() + 4],
            &3u32.to_be_bytes()
        );
        assert_eq!(&info[info.len() - 8..], &5u64.to_be_bytes());
    }

    /// Cross-impl golden — CIRISConformance MUST reproduce these byte-for-byte
    /// (CC 5.1 `CLM-epoch-keying`). Pinned as SHA-256 over `key ‖ nonce` for
    /// `stream_root = [0x42;32]`, `stream_id = "stream-1"`, `epoch = 7`.
    #[test]
    fn cross_impl_golden_vector() {
        let k = derive_epoch_key(&ROOT, "stream-1", 7);
        let n = derive_epoch_stream_nonce(&ROOT, "stream-1", 7);
        let mut h = S::new();
        h.update(k);
        h.update(n);
        let digest = hex::encode(h.finalize());
        // Emitted by this impl (verify is the first conformant impl); conformance
        // goldens it. A change here is a WIRE BREAK.
        assert_eq!(
            digest,
            "38091aeb6cd2cce8ae7225cfd9614f35128a9c2c5f482847dc4ceedee69f61f0"
        );
    }
}
