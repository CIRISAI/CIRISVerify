//! Verifiers for objects of the earlier form (CC 8.11.12), verify-only.
//!
//! v23.0.0 moved every producer to the CC 2.6.1.7 composite
//! ML-DSA-65-Ed25519 signature and removed the bound-hybrid form
//! (Ed25519 over the bytes, then ML-DSA-65 over `bytes ‖ ed25519_sig`). The
//! constitution keeps that form for objects in the ceremony row's past: they
//! were signed before the cut, are still held (persist's audit and stream
//! STHs, §19 witness and durable-storage objects), and must still verify.
//! This module is their reader. It has no producer and never will: no
//! `sign_head`, no `cosign`, no bound-hybrid signer. Forward objects use the
//! composite ([`crate::substrate::verify_composite`],
//! [`crate::transparency::SignedTreeHead`]).
//!
//! ## Why one module, not `substrate::earlier` + `transparency::earlier`
//!
//! The earlier form is one signature construction read in two places. Keeping
//! both readers here puts every CC 8.11.12 entry point behind one path, so an
//! audit that "nothing produces the earlier form" reads one file, and the
//! forward modules stay composite-only, as their own docs state. The preimages
//! themselves are unchanged and still come from the forward modules
//! (`signing_preimage()` / `canonical_preimage()` on the §19 shapes,
//! [`SignedTreeHead::signing_bytes`]).
//!
//! ## Rules (v22.2.1, unchanged)
//!
//! - Ed25519 is verified strictly over the bytes; ML-DSA-65 (empty FIPS 204
//!   context) over `bytes ‖ ed25519_sig`. Both must verify; there is no
//!   classical-only path, and a missing ML-DSA-65 half is refused.
//! - An earlier-form STH carries its keys inside its `HybridSignature`; it
//!   counts only when those keys equal the caller's pinned keys.
//!
//! Pure tier: no clock, no randomness, no I/O.

#[allow(unused_imports)]
use crate::prelude::*;

use crate::utc::UtcDateTime;
use ciris_crypto::{
    ClassicalVerifier, Ed25519Verifier, HybridSignature, HybridVerifier, MlDsa65Verifier,
    PqcVerifier,
};
use serde::{Deserialize, Serialize};

use crate::substrate::HolonomicError;
use crate::transparency::{SignedTreeHead, WitnessConsistencyProof};

const ED25519_PUBKEY_LEN: usize = 32;

/// Verify a §19 object of the earlier form: the bound hybrid pair over its
/// preimage, PQC mandatory.
///
/// CC 8.11.12: verifies objects of the earlier form, in the ceremony row's
/// past; never produces them. Forward objects use the composite
/// ([`crate::substrate::verify_composite`]).
///
/// Both halves must verify against the caller-pinned keys:
/// 1. Ed25519 (strict) over `preimage`;
/// 2. ML-DSA-65 over `preimage ‖ ed25519_sig`, so the PQC half commits to the
///    exact classical signature.
///
/// `mldsa65_sig` is `Option` to model the wire, where the half can be absent;
/// `None` is refused, never read as "classical-only acceptable". The error is
/// opaque about which half failed, as the forward gate is.
///
/// # Errors
///
/// [`HolonomicError::MalformedKeyOrSignature`] if `ed25519_pubkey` is not 32
/// bytes; [`HolonomicError::SignatureInvalid`] if either half is missing or
/// does not verify (including an empty `mldsa65_pubkey`).
pub fn verify_bound_hybrid(
    preimage: &[u8],
    ed25519_sig: &[u8],
    mldsa65_sig: Option<&[u8]>,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
) -> Result<(), HolonomicError> {
    if ed25519_pubkey.len() != ED25519_PUBKEY_LEN {
        return Err(HolonomicError::MalformedKeyOrSignature);
    }
    if !matches!(
        Ed25519Verifier::new().verify(ed25519_pubkey, preimage, ed25519_sig),
        Ok(true)
    ) {
        return Err(HolonomicError::SignatureInvalid);
    }
    let Some(pqc_sig) = mldsa65_sig else {
        return Err(HolonomicError::SignatureInvalid);
    };
    if mldsa65_pubkey.is_empty() {
        return Err(HolonomicError::SignatureInvalid);
    }
    let mut bound = Vec::with_capacity(preimage.len() + ed25519_sig.len());
    bound.extend_from_slice(preimage);
    bound.extend_from_slice(ed25519_sig);
    if !matches!(
        MlDsa65Verifier::new().verify(mldsa65_pubkey, &bound, pqc_sig),
        Ok(true)
    ) {
        return Err(HolonomicError::SignatureInvalid);
    }
    Ok(())
}

fn hybrid_verifier() -> HybridVerifier<Ed25519Verifier, MlDsa65Verifier> {
    HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new())
}

/// Whether `sig` verifies over `bytes` under the pinned keys: the keys it
/// carries must equal them, then the bound hybrid must verify.
fn hybrid_verifies_pinned(
    bytes: &[u8],
    sig: &HybridSignature,
    classical_pk: &[u8],
    pqc_pk: &[u8],
) -> bool {
    if sig.classical.public_key != classical_pk || sig.pqc.public_key != pqc_pk {
        return false;
    }
    // HybridVerifier returns Err on a mismatch, never Ok(false); fold both.
    hybrid_verifier().verify(bytes, sig).unwrap_or(false)
}

/// A signed tree head of the earlier form: v22's `SignedTreeHead`, whose
/// operator and witness signatures are `ciris_crypto::HybridSignature`s
/// (Ed25519 + ML-DSA-65, PQC covering classical). Same serde shape as v22, so
/// a stored v22 STH deserializes as is, and the same signing bytes
/// ([`SignedTreeHead::signing_bytes`]).
///
/// CC 8.11.12: verifies objects of the earlier form, in the ceremony row's
/// past; never produces them. Forward objects use the composite
/// ([`SignedTreeHead`]). Read-only: there is no constructor that signs, no
/// `sign_head` and no `cosign`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarlierSignedTreeHead {
    /// Identifier of the log this head describes.
    pub log_id: String,
    /// Number of leaves at the time of signing.
    pub tree_size: u64,
    /// Merkle root at `tree_size`.
    pub root_hash: [u8; 32],
    /// Wall-clock time the STH was signed.
    pub timestamp: UtcDateTime,
    /// The operator's bound hybrid signature over [`Self::signing_bytes_of`].
    pub signature: HybridSignature,
    /// Witness cosignatures of the earlier form.
    #[serde(default)]
    pub witness_signatures: Vec<EarlierWitnessSignature>,
}

impl EarlierSignedTreeHead {
    /// Parse a stored v22 STH from its JSON.
    ///
    /// CC 8.11.12: reads objects of the earlier form; never produces them.
    ///
    /// # Errors
    /// The `serde_json` error if `json` is not a v22 `SignedTreeHead`.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The bytes the operator and every witness signed: v22's (and the
    /// forward form's) [`SignedTreeHead::signing_bytes`] over this head.
    ///
    /// CC 8.11.12: verifies objects of the earlier form; never produces them.
    #[must_use]
    pub fn signing_bytes_of(&self) -> Vec<u8> {
        SignedTreeHead::signing_bytes(
            &self.log_id,
            self.tree_size,
            &self.root_hash,
            self.timestamp,
        )
    }

    /// Whether the operator's signature verifies under the log's pinned
    /// Ed25519 (`classical_pk`) and ML-DSA-65 (`pqc_pk`) keys. The keys the
    /// signature carries must equal the pinned ones. Any error is `false`.
    /// Freshness is the caller's policy, as for the forward form.
    ///
    /// CC 8.11.12: verifies objects of the earlier form, in the ceremony
    /// row's past; never produces them. Forward objects use the composite.
    #[must_use]
    pub fn verify(&self, classical_pk: &[u8], pqc_pk: &[u8]) -> bool {
        hybrid_verifies_pinned(
            &self.signing_bytes_of(),
            &self.signature,
            classical_pk,
            pqc_pk,
        )
    }

    /// Count the distinct trusted witnesses that validly cosigned this STH,
    /// by v22's rules: the `witness_id` is in `trusted`; the keys in the
    /// cosignature equal that witness's pinned keys; its consistency proof
    /// verifies against this head (CEG §10.3.1); the hybrid signature
    /// verifies over [`Self::signing_bytes_of`]. A `witness_id` counts once.
    ///
    /// CC 8.11.12: verifies objects of the earlier form, in the ceremony
    /// row's past; never produces them. Forward objects use the composite.
    #[must_use]
    pub fn count_valid_witnesses(&self, trusted: &[EarlierTrustedWitness]) -> usize {
        let bytes = self.signing_bytes_of();
        let mut counted: Vec<&str> = Vec::new();
        for ws in &self.witness_signatures {
            if counted.contains(&ws.witness_id.as_str()) {
                continue;
            }
            let Some(tw) = trusted.iter().find(|t| t.witness_id == ws.witness_id) else {
                continue;
            };
            if ws
                .consistency_proof
                .verify(self.tree_size, &self.root_hash)
                .is_err()
            {
                continue;
            }
            if hybrid_verifies_pinned(
                &bytes,
                &ws.signature,
                &tw.classical_public_key,
                &tw.pqc_public_key,
            ) {
                counted.push(&ws.witness_id);
            }
        }
        counted.len()
    }

    /// Whether `quorum` distinct trusted witnesses validly cosigned this STH
    /// ([`Self::count_valid_witnesses`]). A `quorum` of 0 is vacuously met.
    ///
    /// CC 8.11.12: verifies objects of the earlier form, in the ceremony
    /// row's past; never produces them. Forward objects use the composite.
    #[must_use]
    pub fn witness_quorum_met(&self, trusted: &[EarlierTrustedWitness], quorum: usize) -> bool {
        self.count_valid_witnesses(trusted) >= quorum
    }
}

/// A witness cosignature of the earlier form: v22's `WitnessSignature`, same
/// serde shape.
///
/// CC 8.11.12: verifies objects of the earlier form, in the ceremony row's
/// past; never produces them. Forward objects use the composite
/// ([`crate::transparency::WitnessSignature`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarlierWitnessSignature {
    /// Stable identifier for the witness.
    pub witness_id: String,
    /// Bound hybrid signature over the STH's signing bytes.
    pub signature: HybridSignature,
    /// Consistency proof from the witness's prior STH (or genesis).
    pub consistency_proof: WitnessConsistencyProof,
}

/// A pinned witness for earlier-form cosignatures: its id and its Ed25519 and
/// ML-DSA-65 public keys (v22's `TrustedWitness`).
///
/// CC 8.11.12: verifies objects of the earlier form, in the ceremony row's
/// past; never produces them. Forward objects use the composite
/// ([`crate::transparency::TrustedWitness`]).
#[derive(Debug, Clone)]
pub struct EarlierTrustedWitness {
    /// Stable witness identifier (matches `EarlierWitnessSignature::witness_id`).
    pub witness_id: String,
    /// Pinned Ed25519 public key.
    pub classical_public_key: Vec<u8>,
    /// Pinned ML-DSA-65 public key.
    pub pqc_public_key: Vec<u8>,
}

#[cfg(all(test, feature = "std"))]
mod tests {
    //! Fixtures are signed here with `ciris_crypto::HybridSigner` (Ed25519 +
    //! ML-DSA-65), the v22 producer, which only tests use.
    use super::*;
    use crate::substrate::{Preimage, DOMAIN_SIGNED_CLAIM};
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, HybridSigner, MlDsa65Signer, PqcSigner};

    type Signer = HybridSigner<Ed25519Signer, MlDsa65Signer>;

    struct Id {
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Id {
        fn new() -> Self {
            Self {
                ed: Ed25519Signer::random().unwrap(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }
        fn ed_pub(&self) -> Vec<u8> {
            self.ed.public_key().unwrap()
        }
        fn mldsa_pub(&self) -> Vec<u8> {
            self.mldsa.public_key().unwrap()
        }
        /// The bound-hybrid discipline, as v22 signed.
        fn sign(&self, preimage: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let ed_sig = self.ed.sign(preimage).unwrap();
            let mut bound = preimage.to_vec();
            bound.extend_from_slice(&ed_sig);
            (ed_sig, self.mldsa.sign(&bound).unwrap())
        }
    }

    fn claim() -> Vec<u8> {
        Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"claim").finish()
    }

    #[test]
    fn bound_hybrid_round_trips() {
        let id = Id::new();
        let p = claim();
        let (ed, ml) = id.sign(&p);
        assert!(verify_bound_hybrid(&p, &ed, Some(&ml), &id.ed_pub(), &id.mldsa_pub()).is_ok());
    }

    #[test]
    fn missing_pqc_half_is_refused() {
        let id = Id::new();
        let p = claim();
        let (ed, _) = id.sign(&p);
        assert_eq!(
            verify_bound_hybrid(&p, &ed, None, &id.ed_pub(), &id.mldsa_pub()),
            Err(HolonomicError::SignatureInvalid)
        );
        // An empty pinned ML-DSA key is no PQC half either.
        let (ed, ml) = id.sign(&p);
        assert!(verify_bound_hybrid(&p, &ed, Some(&ml), &id.ed_pub(), &[]).is_err());
    }

    #[test]
    fn classical_only_with_grafted_classical_is_refused() {
        // Downgrade: an attacker's classical half under another key, PQC dropped.
        let id = Id::new();
        let attacker = Id::new();
        let p = claim();
        let (att_ed, _) = attacker.sign(&p);
        assert!(verify_bound_hybrid(&p, &att_ed, None, &id.ed_pub(), &id.mldsa_pub()).is_err());
        // A valid classical half alone, PQC replaced by an unrelated signature.
        let (ed, _) = id.sign(&p);
        let (_, att_ml) = attacker.sign(&p);
        assert!(
            verify_bound_hybrid(&p, &ed, Some(&att_ml), &id.ed_pub(), &id.mldsa_pub()).is_err()
        );
    }

    #[test]
    fn swapped_halves_are_refused() {
        let id = Id::new();
        let p = claim();
        let (ed, ml) = id.sign(&p);
        assert!(verify_bound_hybrid(&p, &ml, Some(&ed), &id.ed_pub(), &id.mldsa_pub()).is_err());
        assert!(verify_bound_hybrid(&p, &ed, Some(&ml), &id.mldsa_pub(), &id.ed_pub()).is_err());
        // ML-DSA over the bare preimage (not bound to the classical signature).
        let unbound = id.mldsa.sign(&p).unwrap();
        assert!(
            verify_bound_hybrid(&p, &ed, Some(&unbound), &id.ed_pub(), &id.mldsa_pub()).is_err()
        );
    }

    #[test]
    fn tampered_preimage_and_wrong_keys_fail() {
        let id = Id::new();
        let other = Id::new();
        let p = claim();
        let (ed, ml) = id.sign(&p);
        let tampered = Preimage::new(DOMAIN_SIGNED_CLAIM).lp(b"CLAIM").finish();
        assert_eq!(
            verify_bound_hybrid(&tampered, &ed, Some(&ml), &id.ed_pub(), &id.mldsa_pub()),
            Err(HolonomicError::SignatureInvalid)
        );
        assert_eq!(
            verify_bound_hybrid(&p, &ed, Some(&ml), &id.ed_pub(), &other.mldsa_pub()),
            Err(HolonomicError::SignatureInvalid)
        );
        assert_eq!(
            verify_bound_hybrid(&p, &ed, Some(&ml), &[0; 31], &id.mldsa_pub()),
            Err(HolonomicError::MalformedKeyOrSignature)
        );
    }

    fn signer() -> Signer {
        HybridSigner::new(
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        )
        .unwrap()
    }

    fn keys(s: &HybridSignature) -> (Vec<u8>, Vec<u8>) {
        (s.classical.public_key.clone(), s.pqc.public_key.clone())
    }

    /// An STH signed the way v22's `TransparencyLog::sign_head` did.
    fn sth(operator: &Signer) -> EarlierSignedTreeHead {
        let ts = UtcDateTime::from_timestamp(1_700_000_000, 12_345).unwrap();
        let root = [0x42; 32];
        let bytes = SignedTreeHead::signing_bytes("audit-log", 4, &root, ts);
        EarlierSignedTreeHead {
            log_id: "audit-log".into(),
            tree_size: 4,
            root_hash: root,
            timestamp: ts,
            signature: operator.sign(&bytes).unwrap(),
            witness_signatures: Vec::new(),
        }
    }

    /// As v22's `SignedTreeHead::cosign`, test-only.
    fn cosign(head: &EarlierSignedTreeHead, id: &str, w: &Signer) -> EarlierWitnessSignature {
        EarlierWitnessSignature {
            witness_id: id.into(),
            signature: w.sign(&head.signing_bytes_of()).unwrap(),
            consistency_proof: WitnessConsistencyProof::genesis(),
        }
    }

    fn pin(ws: &EarlierWitnessSignature) -> EarlierTrustedWitness {
        let (c, p) = keys(&ws.signature);
        EarlierTrustedWitness {
            witness_id: ws.witness_id.clone(),
            classical_public_key: c,
            pqc_public_key: p,
        }
    }

    #[test]
    fn sth_verifies_under_pinned_keys_only() {
        let op = signer();
        let head = sth(&op);
        let (c, p) = keys(&head.signature);
        assert!(head.verify(&c, &p));
        let (oc, opq) = keys(&sth(&signer()).signature);
        assert!(!head.verify(&oc, &p));
        assert!(!head.verify(&c, &opq));
        let mut tampered = head.clone();
        tampered.root_hash[0] ^= 1;
        assert!(!tampered.verify(&c, &p));
        let mut tampered = head.clone();
        tampered.tree_size += 1;
        assert!(!tampered.verify(&c, &p));
        // A stripped PQC half does not verify.
        let mut stripped = head;
        stripped.signature.pqc.signature.clear();
        assert!(!stripped.verify(&c, &p));
    }

    #[test]
    fn sth_v22_json_round_trips_and_verifies() {
        let op = signer();
        let mut head = sth(&op);
        let w = signer();
        head.witness_signatures.push(cosign(&head, "w1", &w));
        let json = serde_json::to_string(&head).unwrap();
        // The v22 shape: HybridSignature inline, root_hash as a byte array.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["signature"]["classical"]["public_key"].is_array());
        assert!(v["root_hash"].is_array());
        assert!(v["witness_signatures"][0]["consistency_proof"].is_object());
        let back = EarlierSignedTreeHead::from_json(&json).unwrap();
        let (c, p) = keys(&head.signature);
        assert!(back.verify(&c, &p));
        let trusted = [pin(&head.witness_signatures[0])];
        assert!(back.witness_quorum_met(&trusted, 1));
        // `witness_signatures` defaults when absent (v22 `#[serde(default)]`).
        let mut v = v;
        v.as_object_mut().unwrap().remove("witness_signatures");
        let bare: EarlierSignedTreeHead = serde_json::from_value(v).unwrap();
        assert!(bare.witness_signatures.is_empty());
        assert!(bare.verify(&c, &p));
        // A forward (composite) STH is not an earlier-form STH.
        assert!(serde_json::from_str::<SignedTreeHead>(&json).is_err());
    }

    #[test]
    fn witness_quorum_rules() {
        let op = signer();
        let mut head = sth(&op);
        let (w1, w2) = (signer(), signer());
        let c1 = cosign(&head, "witness-1", &w1);
        let c2 = cosign(&head, "witness-2", &w2);
        head.witness_signatures.push(c1.clone());
        let trusted1 = [pin(&c1)];
        assert_eq!(head.count_valid_witnesses(&trusted1), 1);
        assert!(!head.witness_quorum_met(&trusted1, 2));
        head.witness_signatures.push(c2.clone());
        let trusted = [pin(&c1), pin(&c2)];
        assert_eq!(head.count_valid_witnesses(&trusted), 2);
        assert!(head.witness_quorum_met(&trusted, 2));
        // Untrusted id ignored.
        assert_eq!(head.count_valid_witnesses(&[]), 0);
        assert!(head.witness_quorum_met(&[], 0));
        // Same id, different pinned key: not counted.
        let imposter = cosign(&head, "witness-1", &signer());
        assert_eq!(head.count_valid_witnesses(&[pin(&imposter)]), 0);
        // Duplicates count once.
        let mut dup = sth(&op);
        dup.witness_signatures.push(cosign(&dup, "witness-1", &w1));
        dup.witness_signatures.push(cosign(&dup, "witness-1", &w1));
        assert_eq!(dup.count_valid_witnesses(&trusted), 1);
        // A tampered head breaks every cosignature.
        let mut t = head.clone();
        t.root_hash[0] ^= 1;
        assert_eq!(t.count_valid_witnesses(&trusted), 0);
        // A consistency proof that does not verify does not count.
        let mut bad = head;
        for ws in &mut bad.witness_signatures {
            ws.consistency_proof.consistency_path.push([0; 32]);
        }
        assert_eq!(bad.count_valid_witnesses(&trusted), 0);
    }
}
