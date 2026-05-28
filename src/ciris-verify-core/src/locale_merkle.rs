//! Per-locale build_manifest Merkle composition verifier
//! (CIRISVerify#37 Phase 2, v3.9.0+).
//!
//! Canonical-bytes contract pinned by CIRISRegistry FSD-002 v1.4.3
//! §3.2.1.2. The parent `provenance:build_manifest:{target}` manifest
//! is a Merkle root over per-locale leaves. This module implements
//! the leaf hash + inclusion-proof walk side; the parent signature
//! verification stays in `security/build_manifest.rs::verify_build_manifest`.
//!
//! ## Why a separate Merkle layer?
//!
//! 29 localized artifacts under one coarse parent manifest hash means
//! a locale-targeted attack (e.g. a Burmese doctrinal substitution
//! `accord_1.2b_my.txt`) may pass the coarse parent check while only
//! the `my` leaf actually changed. The Merkle structure gives each
//! locale its own attestable identity — a consumer fetching the
//! Burmese leaf can verify its inclusion in the parent root signed
//! by the per-primitive steward.
//!
//! ## Leaf hash (§3.2.1.2)
//!
//! ```text
//! leaf_hash[lang_code] = sha256(
//!     0x00 ||                                  // RFC 6962 leaf-domain prefix
//!     "ciris.locale_manifest.v1\n" ||
//!     "target=" || target_string || "\n" ||
//!     "locale=" || lang_code || "\n" ||
//!     "files_root=" || files_merkle_root_hex || "\n" ||
//!     "build_id=" || build_id || "\n" ||
//!     "signer_identity=" || signer_key_id
//! )
//! ```
//!
//! ## Parent hash (§3.2.1.2)
//!
//! ```text
//! parent_hash(left, right) = sha256(0x01 || left || right)
//! ```
//!
//! ## Padding (§3.2.1.2)
//!
//! For non-power-of-2 leaf counts (e.g. 29 → 32), duplicate the last
//! leaf to reach the next power of 2 — RFC 6962 convention. Verify
//! reconstruction must apply the same discipline.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::VerifyError;

/// Domain prefix for the per-locale leaf canonical bytes (§3.2.1.2).
/// Trailing newline is part of the prefix.
pub const LOCALE_LEAF_DOMAIN_PREFIX: &str = "ciris.locale_manifest.v1\n";

/// RFC 6962 leaf-domain prefix byte.
pub const RFC6962_LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 parent-domain prefix byte.
pub const RFC6962_PARENT_PREFIX: u8 = 0x01;

/// One per-locale leaf — the fields the leaf hash is computed over.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocaleLeaf {
    /// Target string (e.g. `ios-mobile-bundle`,
    /// `python-source-tree`). Same domain as
    /// `provenance:build_manifest:{target}`.
    pub target: String,
    /// ISO 639-1 lowercase code, or the literal `polyglot` for the
    /// unified-locale case.
    pub lang_code: String,
    /// SHA-256 hex of the locale's file-tree Merkle root.
    pub files_root: String,
    /// Canonical build identifier (UUIDv7 or similar).
    pub build_id: String,
    /// Per-primitive steward `key_id` that signed the locale sub-manifest.
    pub signer_identity: String,
}

impl LocaleLeaf {
    /// Compute the per-leaf hash per §3.2.1.2. Output is a 32-byte
    /// SHA-256 digest — the value that participates in the parent
    /// Merkle tree.
    #[must_use]
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([RFC6962_LEAF_PREFIX]);
        hasher.update(LOCALE_LEAF_DOMAIN_PREFIX);
        hasher.update(b"target=");
        hasher.update(&self.target);
        hasher.update(b"\n");
        hasher.update(b"locale=");
        hasher.update(&self.lang_code);
        hasher.update(b"\n");
        hasher.update(b"files_root=");
        hasher.update(&self.files_root);
        hasher.update(b"\n");
        hasher.update(b"build_id=");
        hasher.update(&self.build_id);
        hasher.update(b"\n");
        hasher.update(b"signer_identity=");
        hasher.update(&self.signer_identity);
        hasher.finalize().into()
    }
}

/// RFC 6962 parent hash with the v1.4.3 §3.2.1.2 domain prefix.
#[must_use]
pub fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([RFC6962_PARENT_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Inclusion proof shape returned by Registry's per-locale GET endpoint
/// (§3.2.1.2 wire shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocaleInclusionProof {
    /// Hex-encoded SHA-256 of the leaf (with `sha256:` prefix per the
    /// wire shape, but accepted without prefix too).
    pub leaf_hash: String,
    /// The locale this proof covers.
    pub lang_code: String,
    /// Sibling hashes along the path to root, leaf-to-root order.
    /// Each is hex-encoded (optionally `sha256:`-prefixed).
    pub sibling_hashes: Vec<String>,
    /// 0-based position of the leaf in the (padded) tree. Determines
    /// path direction at each level.
    pub leaf_index: u64,
    /// Post-padding leaf count — must be a power of 2.
    pub tree_size: u64,
}

/// Walk the inclusion proof and reconstruct the claimed parent root.
/// Compares against `expected_root`; returns `Ok(())` on match.
///
/// Inputs:
/// - `leaf`: the locale-leaf data the consumer is verifying inclusion of.
/// - `proof`: the inclusion proof returned by Registry's GET endpoint.
///   Must reference the same `lang_code` as `leaf` and a non-zero,
///   power-of-2 `tree_size`.
/// - `expected_root`: the Merkle root claimed by the parent
///   `provenance:build_manifest:{target}` attestation (verified
///   upstream by `verify_build_manifest`).
///
/// Invariants enforced:
/// - `proof.lang_code == leaf.lang_code`
/// - `proof.leaf_hash` matches `leaf.leaf_hash()` (the consumer is
///   verifying the leaf they actually fetched, not a substituted one)
/// - `proof.tree_size` is a power of 2 (post-padding contract)
/// - `proof.leaf_index < proof.tree_size`
/// - sibling-hash count equals `log2(tree_size)`
pub fn verify_locale_inclusion(
    leaf: &LocaleLeaf,
    proof: &LocaleInclusionProof,
    expected_root: &[u8; 32],
) -> Result<(), VerifyError> {
    if proof.lang_code != leaf.lang_code {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "locale inclusion proof lang_code mismatch: leaf={}, proof={}",
                leaf.lang_code, proof.lang_code
            ),
        });
    }

    let computed_leaf = leaf.leaf_hash();
    let proof_leaf = decode_hex32(&proof.leaf_hash, "leaf_hash")?;
    if computed_leaf != proof_leaf {
        return Err(VerifyError::IntegrityError {
            message: "locale inclusion proof leaf_hash != computed leaf hash from sub-manifest"
                .to_string(),
        });
    }

    if proof.tree_size == 0 || (proof.tree_size & (proof.tree_size - 1)) != 0 {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "locale inclusion proof tree_size not a power of 2 (got {}); padding contract violated",
                proof.tree_size
            ),
        });
    }
    if proof.leaf_index >= proof.tree_size {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "locale inclusion proof leaf_index {} >= tree_size {}",
                proof.leaf_index, proof.tree_size
            ),
        });
    }

    let expected_proof_depth = proof.tree_size.trailing_zeros() as usize;
    if proof.sibling_hashes.len() != expected_proof_depth {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "locale inclusion proof sibling count {} != log2(tree_size)={}",
                proof.sibling_hashes.len(),
                expected_proof_depth
            ),
        });
    }

    // Walk leaf → root combining with siblings. Bit `i` of leaf_index
    // tells us whether at depth `i` we're the left or right child.
    let mut current = computed_leaf;
    let mut index = proof.leaf_index;
    for (i, sibling_hex) in proof.sibling_hashes.iter().enumerate() {
        let sibling = decode_hex32(sibling_hex, &format!("sibling_hashes[{i}]"))?;
        let is_right = index & 1 == 1;
        current = if is_right {
            parent_hash(&sibling, &current)
        } else {
            parent_hash(&current, &sibling)
        };
        index >>= 1;
    }

    if &current != expected_root {
        return Err(VerifyError::IntegrityError {
            message: "locale inclusion proof reconstructed root != expected parent root"
                .to_string(),
        });
    }

    Ok(())
}

/// Construct the Merkle root over a fully-built leaf set, applying
/// the RFC 6962 last-leaf-duplication padding for non-power-of-2 leaf
/// counts (§3.2.1.2). Useful for testing and for callers that have
/// all leaves and want to produce the parent root.
///
/// Returns `Err` if `leaves` is empty.
pub fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], VerifyError> {
    if leaves.is_empty() {
        return Err(VerifyError::IntegrityError {
            message: "merkle_root called on empty leaf set".to_string(),
        });
    }

    // RFC 6962 padding: duplicate last leaf up to next power of 2.
    let n = leaves.len();
    let padded_n = n.next_power_of_two();
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    if padded_n > n {
        let last = *layer.last().unwrap();
        layer.resize(padded_n, last);
    }

    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| parent_hash(&pair[0], &pair[1]))
            .collect();
    }
    Ok(layer[0])
}

/// Emit the federation_provenance attestation entry for the verified
/// locale leaf. Call only after [`verify_locale_inclusion`] returned
/// `Ok` — the entry asserts inclusion in the steward-signed parent.
#[must_use]
pub fn locale_leaf_to_attestation_entries(
    leaf: &LocaleLeaf,
    attester: &str,
) -> Vec<crate::federation_provenance::AttestationEntry> {
    use crate::federation_provenance::{dim, AttestationEntry};
    vec![AttestationEntry::pass(
        dim::provenance_build_manifest_locale(&leaf.target, &leaf.lang_code),
        attester,
    )
    .with_source_ref(format!("sha256:{}", hex_encode(&leaf.leaf_hash())))]
}

fn decode_hex32(s: &str, field: &str) -> Result<[u8; 32], VerifyError> {
    let stripped = s.strip_prefix("sha256:").unwrap_or(s);
    let bytes = hex_decode(stripped).map_err(|e| VerifyError::IntegrityError {
        message: format!("{field}: hex decode failed ({e})"),
    })?;
    if bytes.len() != 32 {
        return Err(VerifyError::IntegrityError {
            message: format!("{field}: expected 32 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string odd length ({})", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex char: {:?}", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_for(target: &str, lang: &str) -> LocaleLeaf {
        LocaleLeaf {
            target: target.to_string(),
            lang_code: lang.to_string(),
            files_root: format!("{:0>64}", lang),
            build_id: "01HQK3M9F0X2Y4Z6T8R9W1V5N3".to_string(),
            signer_identity: "verify-steward-2026".to_string(),
        }
    }

    /// FSD-002 §3.2.1.2 byte-layout stability: a change to the leaf
    /// hash formula breaks federation-wide inclusion-proof
    /// verification. Lock the byte representation.
    #[test]
    fn leaf_hash_matches_fsd_byte_layout() {
        let leaf = LocaleLeaf {
            target: "ios-mobile-bundle".into(),
            lang_code: "my".into(),
            files_root: "a".repeat(64),
            build_id: "build-1".into(),
            signer_identity: "verify-steward-2026".into(),
        };
        let mut expected = Sha256::new();
        expected.update([RFC6962_LEAF_PREFIX]);
        expected.update(LOCALE_LEAF_DOMAIN_PREFIX);
        expected.update(b"target=ios-mobile-bundle\n");
        expected.update(b"locale=my\n");
        expected.update(format!("files_root={}\n", "a".repeat(64)).as_bytes());
        expected.update(b"build_id=build-1\n");
        expected.update(b"signer_identity=verify-steward-2026");
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(leaf.leaf_hash(), expected);
    }

    #[test]
    fn parent_hash_uses_rfc6962_prefix() {
        let l = [0xAAu8; 32];
        let r = [0xBBu8; 32];
        let p = parent_hash(&l, &r);
        let mut expected = Sha256::new();
        expected.update([RFC6962_PARENT_PREFIX]);
        expected.update(l);
        expected.update(r);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(p, expected);
    }

    #[test]
    fn merkle_root_power_of_two_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
        let root = merkle_root(&leaves).unwrap();
        // Manually compose: parent(parent(0,1), parent(2,3)).
        let p01 = parent_hash(&leaves[0], &leaves[1]);
        let p23 = parent_hash(&leaves[2], &leaves[3]);
        let expected = parent_hash(&p01, &p23);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_pads_to_next_power_of_two_by_duplicating_last_leaf() {
        // 3 leaves → pad to 4 by duplicating leaves[2].
        let leaves: Vec<[u8; 32]> = (0..3).map(|i| [i as u8; 32]).collect();
        let root = merkle_root(&leaves).unwrap();
        // Reference: should equal merkle_root with explicit padding.
        let padded = vec![leaves[0], leaves[1], leaves[2], leaves[2]];
        let expected = merkle_root(&padded).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_29_leaves_padded_to_32() {
        // Realistic case from FSD-002 §3.2.1.2 example: 29 locales
        // padded to 32 by duplicating leaves[28].
        let leaves: Vec<[u8; 32]> = (0..29).map(|i| [i as u8; 32]).collect();
        let root = merkle_root(&leaves).unwrap();
        let mut padded: Vec<[u8; 32]> = leaves.clone();
        for _ in 29..32 {
            padded.push(leaves[28]);
        }
        let expected = merkle_root(&padded).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_empty_leaves_rejected() {
        assert!(merkle_root(&[]).is_err());
    }

    #[test]
    fn inclusion_proof_round_trips_under_power_of_two() {
        // 4 leaves, prove inclusion of index 1.
        let leaves: Vec<LocaleLeaf> = ["en", "id", "my", "th"]
            .iter()
            .map(|l| leaf_for("ios-mobile-bundle", l))
            .collect();
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(LocaleLeaf::leaf_hash).collect();
        let root = merkle_root(&leaf_hashes).unwrap();

        // Build the proof for leaf index 1 (id): sibling at level 0
        // is leaf 0; sibling at level 1 is parent(leaf 2, leaf 3).
        let sibling_0 = leaf_hashes[0];
        let parent_23 = parent_hash(&leaf_hashes[2], &leaf_hashes[3]);

        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf_hashes[1]),
            lang_code: "id".to_string(),
            sibling_hashes: vec![hex_encode(&sibling_0), hex_encode(&parent_23)],
            leaf_index: 1,
            tree_size: 4,
        };

        verify_locale_inclusion(&leaves[1], &proof, &root).expect("inclusion proof should verify");
    }

    #[test]
    fn inclusion_proof_round_trips_with_padding() {
        // 3 leaves padded to 4; prove inclusion of index 2 (the
        // padded leaf is leaves[2] duplicated to slot 3).
        let leaves: Vec<LocaleLeaf> = ["en", "id", "my"]
            .iter()
            .map(|l| leaf_for("ios-mobile-bundle", l))
            .collect();
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(LocaleLeaf::leaf_hash).collect();
        let root = merkle_root(&leaf_hashes).unwrap();

        // Padded tree: [en, id, my, my]
        // Proof for index 2 (my): sibling-0 = leaves[3] = my_hash;
        // sibling-1 = parent(en, id).
        let parent_01 = parent_hash(&leaf_hashes[0], &leaf_hashes[1]);

        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf_hashes[2]),
            lang_code: "my".to_string(),
            sibling_hashes: vec![hex_encode(&leaf_hashes[2]), hex_encode(&parent_01)],
            leaf_index: 2,
            tree_size: 4,
        };

        verify_locale_inclusion(&leaves[2], &proof, &root)
            .expect("padded-tree inclusion proof should verify");
    }

    #[test]
    fn inclusion_proof_rejects_tampered_leaf() {
        let leaves: Vec<LocaleLeaf> = ["en", "id", "my", "th"]
            .iter()
            .map(|l| leaf_for("ios-mobile-bundle", l))
            .collect();
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(LocaleLeaf::leaf_hash).collect();
        let root = merkle_root(&leaf_hashes).unwrap();

        let sibling_0 = leaf_hashes[0];
        let parent_23 = parent_hash(&leaf_hashes[2], &leaf_hashes[3]);
        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf_hashes[1]),
            lang_code: "id".to_string(),
            sibling_hashes: vec![hex_encode(&sibling_0), hex_encode(&parent_23)],
            leaf_index: 1,
            tree_size: 4,
        };

        // Tamper: a Burmese-substitution attack — present a different
        // leaf where the proof claimed `id`.
        let tampered_leaf = leaf_for("ios-mobile-bundle", "my");
        let result = verify_locale_inclusion(&tampered_leaf, &proof, &root);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        // Could fail on lang_code mismatch OR leaf-hash mismatch
        // depending on which gate trips first — both are valid
        // rejections.
        assert!(msg.contains("lang_code") || msg.contains("leaf_hash"));
    }

    #[test]
    fn inclusion_proof_rejects_non_power_of_2_tree_size() {
        let leaf = leaf_for("ios-mobile-bundle", "id");
        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf.leaf_hash()),
            lang_code: "id".to_string(),
            sibling_hashes: vec![],
            leaf_index: 0,
            tree_size: 29, // not a power of 2 — padding contract violated
        };
        let result = verify_locale_inclusion(&leaf, &proof, &[0u8; 32]);
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("power of 2"));
    }

    #[test]
    fn inclusion_proof_rejects_out_of_range_leaf_index() {
        let leaf = leaf_for("ios-mobile-bundle", "id");
        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf.leaf_hash()),
            lang_code: "id".to_string(),
            sibling_hashes: vec![],
            leaf_index: 5,
            tree_size: 4,
        };
        let result = verify_locale_inclusion(&leaf, &proof, &[0u8; 32]);
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("leaf_index"));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_sibling_count() {
        let leaf = leaf_for("ios-mobile-bundle", "id");
        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf.leaf_hash()),
            lang_code: "id".to_string(),
            sibling_hashes: vec![hex_encode(&[0u8; 32])], // 1 sibling but tree_size=4 needs 2
            leaf_index: 1,
            tree_size: 4,
        };
        let result = verify_locale_inclusion(&leaf, &proof, &[0u8; 32]);
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("sibling"));
    }

    #[test]
    fn locale_leaf_to_attestation_entries_emits_per_locale_dimension() {
        let leaf = leaf_for("ios-mobile-bundle", "my");
        let entries = locale_leaf_to_attestation_entries(&leaf, "verify-steward-2026");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].dimension,
            "provenance:build_manifest:ios-mobile-bundle:locale:my"
        );
        assert_eq!(entries[0].score, 1.0);
        assert!(entries[0]
            .source_ref
            .as_deref()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn hex_decode_accepts_sha256_prefix() {
        let with_prefix = format!("sha256:{}", "a".repeat(64));
        let bytes = decode_hex32(&with_prefix, "test").unwrap();
        assert_eq!(bytes, [0xAAu8; 32]);
    }

    #[test]
    fn hex_decode_accepts_uppercase() {
        let bytes = decode_hex32(&"A".repeat(64), "test").unwrap();
        assert_eq!(bytes, [0xAAu8; 32]);
    }

    #[test]
    fn inclusion_proof_rejects_lang_code_mismatch() {
        let leaf = leaf_for("ios-mobile-bundle", "id");
        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf.leaf_hash()),
            lang_code: "my".to_string(), // doesn't match leaf.lang_code
            sibling_hashes: vec![],
            leaf_index: 0,
            tree_size: 1,
        };
        let result = verify_locale_inclusion(&leaf, &proof, &leaf.leaf_hash());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("lang_code"));
    }
}
