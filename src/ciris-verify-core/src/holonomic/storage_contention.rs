//! CC 6.1.5.2 §Q storage-contention — the two PIN-NORMATIVE signed substrate
//! shapes the CEG replication storage-contention axis introduces (CIRISVerify#170,
//! CIRISConstitution CC 0.9):
//!
//!   * [`StorageBudgetV1`] — an owner's per-`cohort_scope` allotment
//!     (`budget_bytes` ceiling + `pin_reserve_bytes` floor) and the
//!     `pinned_class` set it elects to spend budget on (B3), with a monotonic
//!     `revision` anti-rollback.
//!   * [`CorpusWantV1`] — a peer's want/have advertisement: exactly which
//!     corpus it will accept and its per-object `size_cap_bytes` (B4). A
//!     producer pulls only against it — wanted-then-pulled, never
//!     unsolicited-pushed.
//!
//! # CC 6.1 substrate shapes, NOT CC 2.1 attestations
//!
//! Both are substrate-framing objects — no 1+4 change. Their signing preimage
//! uses the **CC 6.1.3 binary discipline** ([`Preimage`] — length-prefixed,
//! big-endian, 16-byte domain-separated — **NOT** JCS) and a **bound-hybrid**
//! signature: `Ed25519(preimage)` plus `ML-DSA-65(preimage ‖ ed25519_sig)`
//! ([`verify_bound_hybrid`]). A verifier MUST reject a shape lacking a valid
//! ML-DSA-65 half at ingest and before persistence (CC 5.3.2.4.3.1 store-path —
//! both are federation-tier). Same gate every §19 object rides.
//!
//! # Canonical home
//!
//! These shapes were first implemented standalone in CIRISEdge
//! (`src/replication/storage_contention.rs`, v8.5.0), which re-derived the
//! preimage discipline + bound-hybrid crypto locally. That blocks non-edge
//! consumers (CIRISPersist can't depend on edge) and forks the canonical bytes.
//! This module is the single source of truth: CIRISPersist wraps it on the
//! Python wheel (CIRISPersist#356), CIRISEdge drops its local copy, and
//! CIRISConformance drives the #57 freeze-gate vectors against it.

use super::preimage::{
    verify_bound_hybrid, BoundHybridSig, HolonomicError, Preimage, DOMAIN_CORPUS_WANT,
    DOMAIN_STORAGE_BUDGET,
};

/// Wire version pinned into both preimages (`version = 1`).
pub const SHAPE_VERSION: u32 = 1;

/// The `self` / `family` `cohort_scope` values that MUST NOT appear in a signed
/// / federated §Q shape (CC 5.2 suppression — B3/B4). A budget or want naming
/// these would leak the existence of structurally-invisible content; those
/// budgets are enforced node-locally only.
pub const SUPPRESSED_SCOPES: [&str; 2] = ["self", "family"];

/// Why a §Q shape failed structural validation (pre-signature). A verifier MUST
/// reject on any of these before consulting the bound-hybrid signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageContentionError {
    /// `pin_reserve_bytes > budget_bytes` for some scope (B3: floor ≤ ceiling).
    ReserveExceedsBudget {
        /// The offending `cohort_scope`.
        scope: String,
        /// Its `pin_reserve_bytes`.
        reserve: u64,
        /// Its `budget_bytes`.
        budget: u64,
    },
    /// A `self` / `family` scope appeared in a signed shape (CC 5.2 / B3).
    SuppressedScope(String),
    /// A list that MUST be lexicographically sorted (over UTF-8 bytes) +
    /// deduplicated was not (the PIN-NORMATIVE canonical-order rule).
    NotSortedDedup(&'static str),
}

impl core::fmt::Display for StorageContentionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReserveExceedsBudget {
                scope,
                reserve,
                budget,
            } => write!(
                f,
                "pin_reserve_bytes ({reserve}) exceeds budget_bytes ({budget}) for scope {scope:?}"
            ),
            Self::SuppressedScope(s) => write!(
                f,
                "suppressed cohort_scope {s:?} MUST NOT appear in a signed §Q shape (CC 5.2)"
            ),
            Self::NotSortedDedup(field) => write!(
                f,
                "{field} is not lexicographically sorted + deduplicated (PIN-NORMATIVE)"
            ),
        }
    }
}

impl std::error::Error for StorageContentionError {}

/// `true` iff `it` yields strictly-ascending (sorted, no duplicates) items.
fn is_sorted_dedup<'a, I: Iterator<Item = &'a str>>(mut it: I) -> bool {
    let mut prev: Option<&str> = None;
    for cur in it.by_ref() {
        if let Some(p) = prev {
            if cur <= p {
                return false;
            }
        }
        prev = Some(cur);
    }
    true
}

/// One `cohort_scope`'s allotment inside a [`StorageBudgetV1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeBudget {
    /// The `cohort_scope` this allotment binds (`community` | `affiliations` |
    /// `species` | …). NEVER `self` / `family` (B3 suppression).
    pub cohort_scope: String,
    /// Total byte ceiling for this scope.
    pub budget_bytes: u64,
    /// Byte floor reserved for pinned corpus (MUST be ≤ `budget_bytes`).
    pub pin_reserve_bytes: u64,
}

/// The owner's per-`cohort_scope` storage allotment (CC 6.1.5.2 §Q B3). A higher
/// `revision` from the same `node_id` supersedes; a lower one MUST be rejected
/// (anti-rollback). Bound-hybrid signed — the signature travels alongside on the
/// wire (see [`verify_storage_budget_v1`]); this struct is the signed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageBudgetV1 {
    /// The owner node this budget binds.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// Monotonic revision; a higher value from the same `node_id` supersedes
    /// (anti-rollback, B3).
    pub revision: u64,
    /// Per-`cohort_scope` allotments. MUST be sorted by `cohort_scope`
    /// (lexicographic over UTF-8 bytes) and deduplicated.
    pub scopes: Vec<ScopeBudget>,
    /// Corpus `subject_kind`s the owner elects to pin (B2-ii). MUST be sorted
    /// (lexicographic over UTF-8 bytes) and deduplicated.
    pub pinned_class: Vec<String>,
}

impl StorageBudgetV1 {
    /// The exact bytes the bound-hybrid signature covers (CC 6.1.3 binary
    /// discipline — length-prefixed, big-endian, domain-separated):
    ///
    /// ```text
    /// b"CIRIS-STG-BUDGET" ‖ u32_be(version=1)
    ///   ‖ lp(node_id) ‖ lp(epoch_id) ‖ u64_be(revision)
    ///   ‖ u32_be(scope_count)
    ///   ‖ scope_count × ( lp(cohort_scope) ‖ u64_be(budget_bytes) ‖ u64_be(pin_reserve_bytes) )
    ///   ‖ u32_be(pinned_class_count) ‖ pinned_class_count × lp(subject_kind)
    /// ```
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut p = Preimage::new(DOMAIN_STORAGE_BUDGET)
            .u32_be(SHAPE_VERSION)
            .lp(self.node_id.as_bytes())
            .lp(self.epoch_id.as_bytes())
            .u64_be(self.revision)
            .u32_be(self.scopes.len() as u32);
        for s in &self.scopes {
            p = p
                .lp(s.cohort_scope.as_bytes())
                .u64_be(s.budget_bytes)
                .u64_be(s.pin_reserve_bytes);
        }
        p = p.u32_be(self.pinned_class.len() as u32);
        for c in &self.pinned_class {
            p = p.lp(c.as_bytes());
        }
        p.finish()
    }

    /// Structural validation (CC 6.1.5.2 §Q — pre-signature). A verifier MUST
    /// reject on any failure: `pin_reserve > budget`; a `self`/`family` scope
    /// entry; or `scopes[].cohort_scope` / `pinned_class` not sorted+deduped.
    ///
    /// # Errors
    /// [`StorageContentionError`] on the first structural violation found.
    pub fn validate(&self) -> Result<(), StorageContentionError> {
        for s in &self.scopes {
            if SUPPRESSED_SCOPES.contains(&s.cohort_scope.as_str()) {
                return Err(StorageContentionError::SuppressedScope(
                    s.cohort_scope.clone(),
                ));
            }
            if s.pin_reserve_bytes > s.budget_bytes {
                return Err(StorageContentionError::ReserveExceedsBudget {
                    scope: s.cohort_scope.clone(),
                    reserve: s.pin_reserve_bytes,
                    budget: s.budget_bytes,
                });
            }
        }
        if !is_sorted_dedup(self.scopes.iter().map(|s| s.cohort_scope.as_str())) {
            return Err(StorageContentionError::NotSortedDedup(
                "scopes[].cohort_scope",
            ));
        }
        if !is_sorted_dedup(self.pinned_class.iter().map(String::as_str)) {
            return Err(StorageContentionError::NotSortedDedup("pinned_class"));
        }
        Ok(())
    }

    /// `true` iff `self` supersedes `other` under the anti-rollback rule: same
    /// `node_id`, strictly-higher `revision` (B3). A lower/equal revision from
    /// the same node MUST be rejected by the caller.
    #[must_use]
    pub fn supersedes(&self, other: &Self) -> bool {
        self.node_id == other.node_id && self.revision > other.revision
    }
}

/// A peer's want/have advertisement (CC 6.1.5.2 §Q B4). A producer MUST NOT push
/// a corpus object exceeding `size_cap_bytes`, nor any object whose `content_id`
/// is absent from an active `CorpusWantV1` from the receiver — wanted-then-
/// pulled, never unsolicited-pushed. Bound-hybrid signed (payload; sig travels
/// alongside — see [`verify_corpus_want_v1`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusWantV1 {
    /// The advertising peer.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// The scope this want draws budget from. NEVER `self` / `family`.
    pub cohort_scope: String,
    /// Max single-object size this peer will accept.
    pub size_cap_bytes: u64,
    /// Advertised headroom in the scope.
    pub remaining_budget_bytes: u64,
    /// Content-addressed ids wanted. MUST be sorted (lexicographic over UTF-8
    /// bytes) and deduplicated.
    pub want: Vec<String>,
}

impl CorpusWantV1 {
    /// The exact bytes the bound-hybrid signature covers (CC 6.1.3):
    ///
    /// ```text
    /// b"CIRIS-WANT-HAVE\0" ‖ u32_be(version=1)
    ///   ‖ lp(node_id) ‖ lp(epoch_id) ‖ lp(cohort_scope)
    ///   ‖ u64_be(size_cap_bytes) ‖ u64_be(remaining_budget_bytes)
    ///   ‖ u32_be(want_count) ‖ want_count × lp(content_id)
    /// ```
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut p = Preimage::new(DOMAIN_CORPUS_WANT)
            .u32_be(SHAPE_VERSION)
            .lp(self.node_id.as_bytes())
            .lp(self.epoch_id.as_bytes())
            .lp(self.cohort_scope.as_bytes())
            .u64_be(self.size_cap_bytes)
            .u64_be(self.remaining_budget_bytes)
            .u32_be(self.want.len() as u32);
        for cid in &self.want {
            p = p.lp(cid.as_bytes());
        }
        p.finish()
    }

    /// Structural validation: no `self`/`family` scope; `want` sorted+deduped.
    ///
    /// # Errors
    /// [`StorageContentionError`] on the first structural violation found.
    pub fn validate(&self) -> Result<(), StorageContentionError> {
        if SUPPRESSED_SCOPES.contains(&self.cohort_scope.as_str()) {
            return Err(StorageContentionError::SuppressedScope(
                self.cohort_scope.clone(),
            ));
        }
        if !is_sorted_dedup(self.want.iter().map(String::as_str)) {
            return Err(StorageContentionError::NotSortedDedup("want"));
        }
        Ok(())
    }

    /// `true` iff a producer may push `content_id` of `object_bytes` against this
    /// want (B4): the id is wanted AND within the advertised size cap.
    #[must_use]
    pub fn admits(&self, content_id: &str, object_bytes: u64) -> bool {
        object_bytes <= self.size_cap_bytes && self.want.iter().any(|w| w == content_id)
    }
}

/// Outcome of verifying a §Q shape at ingest — structure + bound-hybrid signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageContentionVerification {
    /// Structure valid AND both signature halves verified — admissible.
    HybridVerified,
    /// Structural validation failed (the carried reason).
    Invalid(StorageContentionError),
    /// Structure valid but the bound-hybrid signature failed (bad/absent
    /// classical or ML-DSA-65 half).
    SignatureFailed,
}

/// Verify a [`StorageBudgetV1`] at ingest: structure first, then the bound-hybrid
/// signature over its CC 6.1.3 preimage (PQC-mandatory — a missing/invalid
/// ML-DSA-65 half is rejected). Pass only [`StorageContentionVerification::HybridVerified`].
#[must_use]
pub fn verify_storage_budget_v1(
    budget: &StorageBudgetV1,
    sig_ed25519: &[u8],
    sig_ml_dsa_65: &[u8],
    ed25519_pubkey: &[u8],
    ml_dsa_65_pubkey: &[u8],
) -> StorageContentionVerification {
    if let Err(e) = budget.validate() {
        return StorageContentionVerification::Invalid(e);
    }
    verify_shape_sig(
        &budget.signing_preimage(),
        sig_ed25519,
        sig_ml_dsa_65,
        ed25519_pubkey,
        ml_dsa_65_pubkey,
    )
}

/// Verify a [`CorpusWantV1`] at ingest (structure + bound-hybrid signature).
#[must_use]
pub fn verify_corpus_want_v1(
    want: &CorpusWantV1,
    sig_ed25519: &[u8],
    sig_ml_dsa_65: &[u8],
    ed25519_pubkey: &[u8],
    ml_dsa_65_pubkey: &[u8],
) -> StorageContentionVerification {
    if let Err(e) = want.validate() {
        return StorageContentionVerification::Invalid(e);
    }
    verify_shape_sig(
        &want.signing_preimage(),
        sig_ed25519,
        sig_ml_dsa_65,
        ed25519_pubkey,
        ml_dsa_65_pubkey,
    )
}

/// Shared bound-hybrid verify over a §Q preimage.
fn verify_shape_sig(
    preimage: &[u8],
    sig_ed25519: &[u8],
    sig_ml_dsa_65: &[u8],
    ed25519_pubkey: &[u8],
    ml_dsa_65_pubkey: &[u8],
) -> StorageContentionVerification {
    let sig = BoundHybridSig {
        ed25519: sig_ed25519,
        mldsa65: Some(sig_ml_dsa_65),
    };
    match verify_bound_hybrid(preimage, &sig, ed25519_pubkey, ml_dsa_65_pubkey) {
        Ok(()) => StorageContentionVerification::HybridVerified,
        Err(HolonomicError::ClassicalSignatureInvalid)
        | Err(HolonomicError::PqcHalfMissingOrInvalid)
        | Err(HolonomicError::MalformedKeyOrSignature)
        | Err(HolonomicError::Invariant { .. }) => StorageContentionVerification::SignatureFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    struct Id {
        ed: Ed25519Signer,
        pqc: MlDsa65Signer,
    }

    fn id() -> Id {
        Id {
            ed: Ed25519Signer::random().unwrap(),
            pqc: MlDsa65Signer::new().unwrap(),
        }
    }

    /// Bound-hybrid sign a preimage the producer way: Ed25519 over preimage,
    /// ML-DSA-65 over `preimage ‖ ed25519_sig`.
    fn bound_sign(id: &Id, preimage: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let ed_sig = id.ed.sign(preimage).unwrap();
        let mut bound = preimage.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = id.pqc.sign(&bound).unwrap();
        (ed_sig, pqc_sig)
    }

    fn budget() -> StorageBudgetV1 {
        StorageBudgetV1 {
            node_id: "node-1".into(),
            epoch_id: "epoch-1".into(),
            revision: 3,
            scopes: vec![
                ScopeBudget {
                    cohort_scope: "affiliations".into(),
                    budget_bytes: 1_000,
                    pin_reserve_bytes: 200,
                },
                ScopeBudget {
                    cohort_scope: "community".into(),
                    budget_bytes: 2_000,
                    pin_reserve_bytes: 0,
                },
            ],
            pinned_class: vec!["av_chunk".into(), "trace".into()],
        }
    }

    fn want() -> CorpusWantV1 {
        CorpusWantV1 {
            node_id: "node-1".into(),
            epoch_id: "epoch-1".into(),
            cohort_scope: "community".into(),
            size_cap_bytes: 4_096,
            remaining_budget_bytes: 1_800,
            want: vec!["cid-a".into(), "cid-b".into()],
        }
    }

    #[test]
    fn storage_budget_hybrid_round_trip_admits() {
        let id = id();
        let b = budget();
        let (ed, pqc) = bound_sign(&id, &b.signing_preimage());
        assert_eq!(
            verify_storage_budget_v1(
                &b,
                &ed,
                &pqc,
                &id.ed.public_key().unwrap(),
                &id.pqc.public_key().unwrap()
            ),
            StorageContentionVerification::HybridVerified
        );
    }

    #[test]
    fn storage_budget_missing_pqc_rejected() {
        let id = id();
        let b = budget();
        let (ed, _pqc) = bound_sign(&id, &b.signing_preimage());
        // Empty PQC half → SignatureFailed (PQC-mandatory, CC 6.1.3).
        assert_eq!(
            verify_storage_budget_v1(
                &b,
                &ed,
                &[],
                &id.ed.public_key().unwrap(),
                &id.pqc.public_key().unwrap()
            ),
            StorageContentionVerification::SignatureFailed
        );
    }

    #[test]
    fn storage_budget_tamper_breaks_signature() {
        let id = id();
        let b = budget();
        let (ed, pqc) = bound_sign(&id, &b.signing_preimage());
        let mut tampered = b.clone();
        tampered.revision = 99; // preimage diverges from what was signed
        assert_eq!(
            verify_storage_budget_v1(
                &tampered,
                &ed,
                &pqc,
                &id.ed.public_key().unwrap(),
                &id.pqc.public_key().unwrap()
            ),
            StorageContentionVerification::SignatureFailed
        );
    }

    #[test]
    fn suppressed_scope_and_reserve_and_order_rejected() {
        let mut b = budget();
        b.scopes[0].cohort_scope = "self".into();
        assert!(matches!(
            b.validate(),
            Err(StorageContentionError::SuppressedScope(_))
        ));

        let mut b = budget();
        b.scopes[0].pin_reserve_bytes = b.scopes[0].budget_bytes + 1;
        assert!(matches!(
            b.validate(),
            Err(StorageContentionError::ReserveExceedsBudget { .. })
        ));

        let mut b = budget();
        b.scopes.reverse(); // community before affiliations → not sorted
        assert!(matches!(
            b.validate(),
            Err(StorageContentionError::NotSortedDedup(_))
        ));
    }

    #[test]
    fn supersedes_is_same_node_strictly_higher_revision() {
        let a = budget();
        let mut older = budget();
        older.revision = 2;
        assert!(a.supersedes(&older));
        assert!(!older.supersedes(&a));
        let mut other_node = budget();
        other_node.node_id = "node-2".into();
        assert!(!a.supersedes(&other_node));
    }

    #[test]
    fn corpus_want_round_trip_and_admits() {
        let id = id();
        let w = want();
        let (ed, pqc) = bound_sign(&id, &w.signing_preimage());
        assert_eq!(
            verify_corpus_want_v1(
                &w,
                &ed,
                &pqc,
                &id.ed.public_key().unwrap(),
                &id.pqc.public_key().unwrap()
            ),
            StorageContentionVerification::HybridVerified
        );
        assert!(w.admits("cid-a", 4_096));
        assert!(!w.admits("cid-a", 4_097)); // over size cap
        assert!(!w.admits("cid-z", 1)); // not wanted
    }

    #[test]
    fn corpus_want_unsorted_rejected() {
        let mut w = want();
        w.want = vec!["cid-b".into(), "cid-a".into()];
        assert!(matches!(
            w.validate(),
            Err(StorageContentionError::NotSortedDedup("want"))
        ));
    }
}
