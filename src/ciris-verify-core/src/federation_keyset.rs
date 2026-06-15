//! Federation M-of-N bootstrap-keyset canonical encoding (CIRISVerify#31
//! Part A).
//!
//! The federation's trust anchor scales from 1 key to M-of-N
//! (e.g. 2-of-3, then 3-of-5) **without a protocol change** — this is
//! the load-bearing property of CIRISNodeCore's
//! `federation_announcement` primitive. For that to be a sound
//! property, every peer must compute *exactly the same bytes* for the
//! current `{bootstrap_threshold, bootstrap_key_set}` state — rotation
//! announcements canonical-hash to that representation, signatures
//! bind to it, and peer-to-peer comparison reduces to a byte-equality
//! check.
//!
//! This module is the substrate: a [`FederationKeyset`] value type +
//! [`federation_keyset_signing_bytes`] canonical encoding. Same
//! discipline as `SignedTreeHead::signing_bytes`,
//! `TransparencyEntry::canonical_bytes`, `FederationEnvelope`, and
//! `BuildManifest`.
//!
//! ## Rotation flow (the property this substrate enables)
//!
//! A rotation that replaces the federation's current
//! `(threshold_old, members_old)` with a new
//! `(threshold_new, members_new)` is verified by:
//!
//! 1. Compute the new keyset's canonical bytes (this module).
//! 2. Verify that ≥ `threshold_old` *distinct* members of the **old**
//!    keyset signed those exact bytes
//!    ([`crate::threshold::verify_threshold_signatures`]).
//! 3. On success, the federation's current keyset becomes
//!    `(threshold_new, members_new)`, ready to authorize the next
//!    rotation.
//!
//! The rotation announcement's body shape and CLI tooling belong
//! downstream (CIRISNodeCore today; CIRISAgent's bundled-registry FSD
//! post-3.0 fold-in). CIRISVerify owns the canonical-bytes substrate
//! and the threshold-verification primitive; the announcement shape is
//! consumer.

use crate::threshold::ThresholdMember;
use serde::{Deserialize, Serialize};

/// Domain-separation prefix for federation-keyset canonical bytes.
/// Stable wire constant — changing it invalidates every previously
/// signed keyset transition.
pub const FEDERATION_KEYSET_DOMAIN_SEP: &[u8] = b"CIRIS-FEDERATION-KEYSET-V1";

/// Current canonical-bytes schema version. Bumped on an incompatible
/// layout change; the value is *inside* the signed bytes so a verifier
/// can never be fooled into reading new bytes as old.
pub const FEDERATION_KEYSET_SCHEMA_VERSION: u8 = 1;

/// The federation's M-of-N bootstrap state.
///
/// `members` is a *set* — the canonical encoding sorts by `member_id`
/// before hashing, so two peers with the same logical membership
/// compute byte-identical canonical bytes regardless of the order
/// their lists happen to be in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationKeyset {
    /// Canonical-bytes schema version (see [`FEDERATION_KEYSET_SCHEMA_VERSION`]).
    pub schema_version: u8,
    /// `M` — the minimum number of distinct members that must sign for
    /// a rotation (or any keyset-authorized event) to be valid.
    pub threshold: u32,
    /// `N` — the trusted member set.
    pub members: Vec<ThresholdMember>,
}

impl FederationKeyset {
    /// Canonical bytes a rotation announcement signs.
    ///
    /// `domain_sep · schema_version · threshold(u32 LE) · count(u32 LE) ·
    /// per member (sorted by `member_id` ASCII-lex): LP(member_id) ·
    /// LP(ed25519_pubkey_base64) · LP(mldsa65_pubkey_base64_or_empty)`.
    /// `LP` is a `u32`-length-prefixed byte string. Deterministic.
    ///
    /// **Sorting by `member_id`** is the canonicalization step that
    /// makes two peers with logically-equal but list-order-differing
    /// keysets agree on the bytes. Equivalent to the discipline RFC
    /// 8785 / JCS apply to JSON, scoped to this structure.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        federation_keyset_signing_bytes(self)
    }
}

/// Free-fn form (the canonical one — [`FederationKeyset::signing_bytes`]
/// delegates here).
#[must_use]
pub fn federation_keyset_signing_bytes(keyset: &FederationKeyset) -> Vec<u8> {
    fn lp(buf: &mut Vec<u8>, b: &[u8]) {
        buf.extend_from_slice(&(u32::try_from(b.len()).unwrap_or(u32::MAX)).to_le_bytes());
        buf.extend_from_slice(b);
    }
    let mut sorted: Vec<&ThresholdMember> = keyset.members.iter().collect();
    sorted.sort_by(|a, b| a.member_id.cmp(&b.member_id));

    let mut buf = Vec::with_capacity(FEDERATION_KEYSET_DOMAIN_SEP.len() + 64 + sorted.len() * 64);
    buf.extend_from_slice(FEDERATION_KEYSET_DOMAIN_SEP);
    buf.push(keyset.schema_version);
    buf.extend_from_slice(&keyset.threshold.to_le_bytes());
    buf.extend_from_slice(&(u32::try_from(sorted.len()).unwrap_or(u32::MAX)).to_le_bytes());
    for m in sorted {
        lp(&mut buf, m.member_id.as_bytes());
        lp(&mut buf, m.ed25519_public_key_base64.as_bytes());
        // Hybrid-pending member: encode as a zero-length string, not
        // an omitted field — every member must contribute the same
        // number of length-prefixed fields, so the structure stays
        // unambiguous.
        let mldsa = m.mldsa65_public_key_base64.as_deref().unwrap_or("");
        lp(&mut buf, mldsa.as_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str, ed: &str, mldsa: Option<&str>) -> ThresholdMember {
        ThresholdMember {
            member_id: id.to_string(),
            ed25519_public_key_base64: ed.to_string(),
            mldsa65_public_key_base64: mldsa.map(str::to_string),
            role: None,
        }
    }

    fn keyset(threshold: u32, members: Vec<ThresholdMember>) -> FederationKeyset {
        FederationKeyset {
            schema_version: FEDERATION_KEYSET_SCHEMA_VERSION,
            threshold,
            members,
        }
    }

    #[test]
    fn signing_bytes_begin_with_domain_sep() {
        let ks = keyset(2, vec![member("a", "AA==", None)]);
        let b = federation_keyset_signing_bytes(&ks);
        assert!(b.starts_with(FEDERATION_KEYSET_DOMAIN_SEP));
    }

    #[test]
    fn signing_bytes_deterministic() {
        let ks = keyset(
            2,
            vec![
                member("alice", "ed-a", Some("mldsa-a")),
                member("bob", "ed-b", Some("mldsa-b")),
                member("carol", "ed-c", None),
            ],
        );
        assert_eq!(ks.signing_bytes(), ks.signing_bytes());
    }

    #[test]
    fn members_canonicalize_via_member_id_sort() {
        let abc = keyset(
            2,
            vec![
                member("alice", "ed-a", Some("mldsa-a")),
                member("bob", "ed-b", Some("mldsa-b")),
                member("carol", "ed-c", None),
            ],
        );
        let cba = keyset(
            2,
            vec![
                member("carol", "ed-c", None),
                member("bob", "ed-b", Some("mldsa-b")),
                member("alice", "ed-a", Some("mldsa-a")),
            ],
        );
        assert_eq!(
            abc.signing_bytes(),
            cba.signing_bytes(),
            "set-shaped membership must canonicalize regardless of Vec order"
        );
    }

    #[test]
    fn signing_bytes_sensitive_to_threshold() {
        let m = vec![member("a", "ed", None), member("b", "ed", None)];
        let a = keyset(1, m.clone()).signing_bytes();
        let b = keyset(2, m).signing_bytes();
        assert_ne!(a, b, "threshold must affect the canonical bytes");
    }

    #[test]
    fn signing_bytes_sensitive_to_membership() {
        let a = keyset(1, vec![member("a", "ed", None)]).signing_bytes();
        let b = keyset(1, vec![member("a", "ed", None), member("b", "ed2", None)]).signing_bytes();
        assert_ne!(a, b, "adding a member must affect the canonical bytes");
    }

    #[test]
    fn signing_bytes_sensitive_to_member_id_rename() {
        let a = keyset(1, vec![member("alice", "ed", None)]).signing_bytes();
        let b = keyset(1, vec![member("alyce", "ed", None)]).signing_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn signing_bytes_sensitive_to_ed_pubkey_change() {
        let a = keyset(1, vec![member("a", "ed-1", None)]).signing_bytes();
        let b = keyset(1, vec![member("a", "ed-2", None)]).signing_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn hybrid_pending_versus_full_hybrid_differ() {
        // Same member_id and ed-pubkey, but one has a PQC pubkey and
        // one does not — the bytes must differ so a peer cannot
        // ambiguously interpret "hybrid-pending" as "full hybrid".
        let pending = keyset(1, vec![member("a", "ed", None)]).signing_bytes();
        let full = keyset(1, vec![member("a", "ed", Some("mldsa"))]).signing_bytes();
        assert_ne!(pending, full);
    }

    /// Length-prefixing makes the field boundary between member_id and
    /// pubkey unambiguous — moving a byte across it changes the bytes.
    #[test]
    fn no_field_boundary_ambiguity() {
        let a = keyset(1, vec![member("ab", "c", None)]).signing_bytes();
        let b = keyset(1, vec![member("a", "bc", None)]).signing_bytes();
        assert_ne!(a, b);
    }

    /// Round-trip: a real M-of-N keyset rotation works with the
    /// threshold-signature primitive over these canonical bytes. This
    /// is the contract that makes #31 Part A useful — verify the
    /// canonical bytes are *what gets signed* for a rotation.
    #[test]
    fn rotation_canonical_bytes_round_trip_with_threshold_verify() {
        use crate::threshold::{verify_threshold_signatures, ThresholdSignature};
        use base64::Engine;
        use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

        let b64 = base64::engine::general_purpose::STANDARD;

        // Build three signers as the OLD keyset's members.
        let parties: Vec<(String, Ed25519Signer, MlDsa65Signer)> = (0..3)
            .map(|i| {
                (
                    format!("steward-{i}"),
                    Ed25519Signer::random().unwrap(),
                    MlDsa65Signer::new().unwrap(),
                )
            })
            .collect();
        let old_members: Vec<ThresholdMember> = parties
            .iter()
            .map(|(id, ed, mldsa)| ThresholdMember {
                member_id: id.clone(),
                ed25519_public_key_base64: b64.encode(ed.public_key().unwrap()),
                mldsa65_public_key_base64: Some(b64.encode(mldsa.public_key().unwrap())),
                role: None,
            })
            .collect();

        // The NEW keyset (what we're rotating to).
        let new_keyset = keyset(
            3, // new threshold of 3
            vec![
                member("new-a", "ed-new-a", Some("mldsa-new-a")),
                member("new-b", "ed-new-b", Some("mldsa-new-b")),
                member("new-c", "ed-new-c", Some("mldsa-new-c")),
                member("new-d", "ed-new-d", Some("mldsa-new-d")),
                member("new-e", "ed-new-e", Some("mldsa-new-e")),
            ],
        );

        // Two of the three old stewards (matching the old 2-of-3
        // threshold) sign the new keyset's canonical bytes.
        let bytes = new_keyset.signing_bytes();
        let signatures: Vec<ThresholdSignature> = parties[0..2]
            .iter()
            .map(|(id, ed, mldsa)| {
                let ed_sig = ed.sign(&bytes).unwrap();
                let mut bound = bytes.clone();
                bound.extend_from_slice(&ed_sig);
                let pqc_sig = mldsa.sign(&bound).unwrap();
                ThresholdSignature {
                    member_id: id.clone(),
                    ed25519_signature_base64: b64.encode(&ed_sig),
                    mldsa65_signature_base64: Some(b64.encode(&pqc_sig)),
                }
            })
            .collect();

        // The rotation is authorized: 2 ≥ old threshold (2).
        let old_threshold = 2;
        assert_eq!(
            verify_threshold_signatures(&bytes, &old_members, &signatures, old_threshold),
            Ok(2)
        );

        // Sanity: had only one old steward signed, the rotation would
        // fail (insufficient).
        assert!(
            verify_threshold_signatures(&bytes, &old_members, &signatures[..1], old_threshold)
                .is_err()
        );
    }
}
