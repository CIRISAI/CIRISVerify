//! §19.1 WholenessWitness — divergence-detection Merkle witness (CEG 1.0-RC11).
//!
//! A `wholeness_witness:` object is a peer's **hybrid-signed Merkle root over a
//! scoped projection of the claims it holds**, used to *detect* cross-peer state
//! divergence and *trigger* the §10.1.6 quorum-merge — it never decides a merge
//! and MUST NOT replace `monotonic_quorum`/`revision` anti-rollback (the
//! supersession trap: "reconstitute from any fragment" could otherwise resurrect
//! a revoked key). It is the **inverse** of the §10.3 transparency-log witness
//! (an independent STH cosigner) and provides **no** append-only/consistency
//! guarantee — never substitute it for §10.3.1 / §10.5.1.
//!
//! ## What this module pins (the §19.6 / #57 vector target)
//!
//! The Merkle construction is **fully specified by §19.1 and KAT-locked here**,
//! distinct from the [`crate::transparency`] RFC 6962 log:
//! - `leaf order` is **lexicographic over leaf bytes** (the §0.9.2.1
//!   set-semantics rule — v4.0.0's "either order as long as both agree" is the
//!   §0.9-class divergence hazard and is non-conformant);
//! - `leaf = SHA-256(leaf_bytes)`, `node = SHA-256(left ‖ right)`;
//! - **odd node duplicated** (`node = SHA-256(last ‖ last)`);
//! - **empty tree** → `SHA-256(b"WW-v1-empty")`.
//!
//! It does **NOT** use the RFC 6962 `0x00`/`0x01` domain prefixes (§19.1 pins
//! the no-prefix form; adopting them for CVE-2012-2459 second-preimage safety is
//! flagged open, to settle with the fixed-impl pin — CIRISEdge#143).
//!
//! ## Authority (N3 / N4)
//!
//! A WholenessWitness is federation-tier: hybrid PQC verified **at ingest and
//! before persistence** ([`crate::holonomic::verify_bound_hybrid`]);
//! [`compare_witnesses`] MUST NOT run on an unverified witness. Two
//! validly-signed witnesses from the same `(peer_id, epoch_id,
//! claim_namespace_set)` with **different** `merkle_root` are **non-repudiable
//! equivocation** ([`Equivocation`]) — retained and surfaced as a `hard_case:*`,
//! never silently reconciled.

use sha2::{Digest, Sha256};

use super::preimage::WW_EMPTY_SENTINEL;

/// A 32-byte SHA-256 Merkle node/root.
pub type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Compute the WholenessWitness Merkle root over `leaf_bytes` per §19.1.
///
/// Leaves are sorted **lexicographically over their raw bytes** (MUST, §19.1 /
/// §0.9.2.1) before hashing — so two honest peers holding the same leaf *set*
/// in any input order produce the same root. `leaf = SHA-256(bytes)`, internal
/// `node = SHA-256(left ‖ right)`, an odd node at a level is duplicated, and an
/// empty leaf set yields `SHA-256(b"WW-v1-empty")`.
///
/// WW-2 (anonymous/`self` exclusion) is the **caller's** leaf-walk precondition
/// — this function hashes exactly the leaves it is given. [`verify_witness`]
/// guards the namespace-set side.
#[must_use]
pub fn compute_merkle_root(leaf_bytes: &[Vec<u8>]) -> Hash {
    if leaf_bytes.is_empty() {
        return sha256(&[WW_EMPTY_SENTINEL]);
    }
    // Lexicographic over raw leaf bytes (set-semantics), then hash each leaf.
    let mut sorted: Vec<&Vec<u8>> = leaf_bytes.iter().collect();
    sorted.sort_unstable();
    let mut level: Vec<Hash> = sorted.iter().map(|b| sha256(&[b.as_slice()])).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            // Odd node at the end → duplicate it (node = SHA256(last ‖ last)).
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(sha256(&[&left, &right]));
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// A WholenessWitness as parsed off the wire (its signed scalar members plus
/// the bound-hybrid signature halves). The exact signed-preimage field layout is
/// pinned by §19.1 and frozen by the §19.6 vectors (CIRISEdge#143); this struct
/// carries what the invariant checks need.
///
/// Note the absence of any `verified: bool` — per the §19.0 F-5 rule a verdict
/// is recomputed at the gate, never read from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WholenessWitness {
    /// The witnessing peer's stable id.
    pub peer_id: String,
    /// Per-peer monotonic epoch (anti-rollback checked before use as an
    /// `EpochBehind` reconciliation input — the eclipse guard, N4).
    pub epoch_id: u64,
    /// The namespaces this root covers (WW-1 per-namespace opt-in). MUST NOT
    /// name an anonymous-tier or `cohort_scope: self` namespace (WW-2). Encoded
    /// lexicographically sorted in the canonical preimage.
    pub claim_namespaces: Vec<String>,
    /// The Merkle root over the (lexicographically-ordered, WW-2-filtered) leaves.
    pub merkle_root: Hash,
    /// Number of Merkle leaves the root covers (a signed scalar, distinct from
    /// `claim_namespaces.len()`).
    pub leaf_count: u32,
    /// Producer observation time, unix-ms (signed scalar).
    pub observed_at_unix_ms: u64,
    /// Witness schema version (`1`).
    pub witness_version: u16,
}

impl WholenessWitness {
    /// Build the §19.1 canonical signing preimage (CEG 1.0-RC11, byte-frozen by
    /// the Edge v4.1.2 §19.6 vectors). Layout, after the
    /// [`DOMAIN_WITNESS_PREIMAGE`](super::preimage::DOMAIN_WITNESS_PREIMAGE) separator:
    /// `u32-lp(peer_id) ‖ u64(epoch_id) ‖ merkle_root[32] ‖ u32(leaf_count) ‖
    /// u32(namespace_count) ‖ [u32-lp(ns)]*(lex-sorted) ‖
    /// u64(observed_at_unix_ms) ‖ u16(witness_version)`.
    #[must_use]
    pub fn canonical_preimage(&self) -> Vec<u8> {
        let mut ns = self.claim_namespaces.clone();
        ns.sort_unstable();
        let mut pre = super::preimage::Preimage::new(super::preimage::DOMAIN_WITNESS_PREIMAGE)
            .lp(self.peer_id.as_bytes())
            .u64_be(self.epoch_id)
            .fixed(&self.merkle_root)
            .u32_be(self.leaf_count)
            .u32_be(ns.len() as u32);
        for n in &ns {
            pre = pre.lp(n.as_bytes());
        }
        pre.u64_be(self.observed_at_unix_ms)
            .u16_be(self.witness_version)
            .finish()
    }

    /// The `(peer_id, epoch_id, sorted claim_namespace_set)` identity an
    /// equivocation is judged against (N4). The namespace set is sorted so
    /// order-only differences don't read as distinct scopes.
    fn equivocation_key(&self) -> (String, u64, Vec<String>) {
        let mut ns = self.claim_namespaces.clone();
        ns.sort_unstable();
        ns.dedup();
        (self.peer_id.clone(), self.epoch_id, ns)
    }
}

/// A reserved namespace fragment that must never appear in `claim_namespaces`
/// (WW-2): witnessing anonymous/`self` rows re-attributes deniable/self-private
/// content to a stable `peer_id`.
const FORBIDDEN_NAMESPACE_MARKERS: &[&str] = &["anonymous", "self"];

/// Verify a WholenessWitness for ingest (N3) — the §19.0 PQC-mandatory gate plus
/// the WW-2 namespace guard plus (when the caller supplies the leaves) a
/// recompute of the root.
///
/// `witness_preimage` is the §19.1 signed preimage (built via
/// [`crate::holonomic::Preimage`] over the witness's members). `leaves`, when
/// `Some`, are re-hashed and the resulting root must equal `witness.merkle_root`
/// — catching a signer who signs a root inconsistent with the disclosed leaves.
///
/// # Errors
///
/// Propagates [`HolonomicError`](super::preimage::HolonomicError) from the
/// signature gate; returns
/// [`HolonomicError::Invariant`](super::preimage::HolonomicError::Invariant) for an empty/forbidden namespace set
/// (`"ww_namespace"`) or a leaf/root mismatch (`"ww_root_mismatch"`).
pub fn verify_witness(
    witness: &WholenessWitness,
    witness_preimage: &[u8],
    sig: &super::preimage::BoundHybridSig<'_>,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
    leaves: Option<&[Vec<u8>]>,
) -> Result<(), super::preimage::HolonomicError> {
    use super::preimage::HolonomicError;

    // WW-2 / WW-1: a witness must scope at least one namespace and MUST NOT name
    // an anonymous-tier or self namespace.
    if witness.claim_namespaces.is_empty() {
        return Err(HolonomicError::Invariant {
            reason: "ww_namespace",
        });
    }
    for ns in &witness.claim_namespaces {
        let lower = ns.to_ascii_lowercase();
        if FORBIDDEN_NAMESPACE_MARKERS
            .iter()
            .any(|m| lower.contains(m))
        {
            return Err(HolonomicError::Invariant {
                reason: "ww_namespace",
            });
        }
    }

    // N3: hybrid PQC verified at the gate (before any compare / persist).
    super::preimage::verify_bound_hybrid(witness_preimage, sig, ed25519_pubkey, mldsa65_pubkey)?;

    // If the leaves were disclosed, the signed root must match a recompute.
    if let Some(leaves) = leaves {
        if compute_merkle_root(leaves) != witness.merkle_root {
            return Err(HolonomicError::Invariant {
                reason: "ww_root_mismatch",
            });
        }
    }
    Ok(())
}

/// A non-repudiable equivocation: one peer published two validly-signed roots
/// for the same `(peer_id, epoch_id, claim_namespace_set)` (N4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    /// The equivocating peer.
    pub peer_id: String,
    /// The epoch both witnesses claimed.
    pub epoch_id: u64,
    /// The sorted namespace set both witnesses scoped.
    pub claim_namespaces: Vec<String>,
    /// The two conflicting roots (sorted, so the proof is canonical).
    pub roots: (Hash, Hash),
}

/// A verdict over a set of **already-verified** witnesses (N4 / WW-vs-§10.1.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessComparison {
    /// All witnesses for each identity agreed on one root — no divergence.
    Consistent,
    /// Distinct peers / epochs reported different roots — a **divergence
    /// signal** that MUST be handed to the §10.1.6 quorum-merge for the
    /// rollback-sensitive subject_kinds, never reconciled here.
    Divergent,
    /// One peer published conflicting roots for the same identity — retained and
    /// surfaced, never reconciled (N4).
    Equivocation(Vec<Equivocation>),
}

/// Compare a set of **verified** WholenessWitnesses (N4 / WW-vs-replication).
///
/// **Precondition:** every input MUST have already passed [`verify_witness`] —
/// this function MUST NOT be the verification path (it trusts the signatures
/// were checked at the gate). It classifies, it does not admit:
/// - same identity, conflicting roots → [`WitnessComparison::Equivocation`]
///   (non-repudiable; surface, never reconcile);
/// - otherwise differing roots across identities → [`WitnessComparison::Divergent`]
///   (hand to §10.1.6 quorum-merge — this function NEVER decides a merge, so it
///   cannot resurrect a revoked key);
/// - all agree → [`WitnessComparison::Consistent`].
#[must_use]
pub fn compare_witnesses(verified: &[WholenessWitness]) -> WitnessComparison {
    use std::collections::BTreeMap;

    // Group roots by equivocation identity.
    let mut by_identity: BTreeMap<(String, u64, Vec<String>), Vec<Hash>> = BTreeMap::new();
    for w in verified {
        by_identity
            .entry(w.equivocation_key())
            .or_default()
            .push(w.merkle_root);
    }

    let mut equivocations = Vec::new();
    let mut distinct_roots_seen = std::collections::BTreeSet::new();
    for ((peer_id, epoch_id, ns), mut roots) in by_identity {
        roots.sort_unstable();
        roots.dedup();
        for r in &roots {
            distinct_roots_seen.insert(*r);
        }
        if roots.len() > 1 {
            // One identity, multiple roots → equivocation. Emit canonical pairs.
            for pair in roots.windows(2) {
                equivocations.push(Equivocation {
                    peer_id: peer_id.clone(),
                    epoch_id,
                    claim_namespaces: ns.clone(),
                    roots: (pair[0], pair[1]),
                });
            }
        }
    }

    if !equivocations.is_empty() {
        WitnessComparison::Equivocation(equivocations)
    } else if distinct_roots_seen.len() > 1 {
        WitnessComparison::Divergent
    } else {
        WitnessComparison::Consistent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    #[test]
    fn empty_tree_is_sentinel_hash() {
        assert_eq!(compute_merkle_root(&[]), sha256(&[WW_EMPTY_SENTINEL]));
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let root = compute_merkle_root(&[leaf(b"a")]);
        assert_eq!(root, sha256(&[b"a"]));
    }

    #[test]
    fn root_is_order_independent_lexicographic() {
        // The whole point of WW-1: input order MUST NOT change the root.
        let r1 = compute_merkle_root(&[leaf(b"c"), leaf(b"a"), leaf(b"b")]);
        let r2 = compute_merkle_root(&[leaf(b"a"), leaf(b"b"), leaf(b"c")]);
        let r3 = compute_merkle_root(&[leaf(b"b"), leaf(b"c"), leaf(b"a")]);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn odd_node_duplicates_last() {
        // 3 leaves: [a,b,c] sorted → level0 = [H(a),H(b),H(c)];
        // level1 = [H(H(a)‖H(b)), H(H(c)‖H(c))]; root = H(level1[0]‖level1[1]).
        let ha = sha256(&[b"a"]);
        let hb = sha256(&[b"b"]);
        let hc = sha256(&[b"c"]);
        let n0 = sha256(&[&ha, &hb]);
        let n1 = sha256(&[&hc, &hc]); // odd → duplicated
        let expected = sha256(&[&n0, &n1]);
        assert_eq!(
            compute_merkle_root(&[leaf(b"a"), leaf(b"b"), leaf(b"c")]),
            expected
        );
    }

    #[test]
    fn two_leaf_root() {
        let ha = sha256(&[b"a"]);
        let hb = sha256(&[b"b"]);
        assert_eq!(
            compute_merkle_root(&[leaf(b"b"), leaf(b"a")]),
            sha256(&[&ha, &hb])
        );
    }

    fn ww(peer: &str, epoch: u64, ns: &[&str], root: Hash) -> WholenessWitness {
        WholenessWitness {
            peer_id: peer.to_string(),
            epoch_id: epoch,
            claim_namespaces: ns.iter().map(|s| s.to_string()).collect(),
            merkle_root: root,
            leaf_count: 0,
            observed_at_unix_ms: 0,
            witness_version: 1,
        }
    }

    #[test]
    fn consistent_when_all_roots_agree() {
        let r = compute_merkle_root(&[leaf(b"x")]);
        let set = vec![
            ww("peer-a", 1, &["scores:medical"], r),
            ww("peer-b", 1, &["scores:medical"], r),
        ];
        assert_eq!(compare_witnesses(&set), WitnessComparison::Consistent);
    }

    #[test]
    fn divergent_across_peers_hands_to_quorum_merge() {
        let r1 = compute_merkle_root(&[leaf(b"x")]);
        let r2 = compute_merkle_root(&[leaf(b"y")]);
        let set = vec![
            ww("peer-a", 1, &["scores:medical"], r1),
            ww("peer-b", 1, &["scores:medical"], r2),
        ];
        assert_eq!(compare_witnesses(&set), WitnessComparison::Divergent);
    }

    #[test]
    fn equivocation_detected_for_one_peer_two_roots() {
        let r1 = compute_merkle_root(&[leaf(b"x")]);
        let r2 = compute_merkle_root(&[leaf(b"y")]);
        // Same (peer, epoch, namespace set), two roots — namespace order varied
        // to prove the key is set-normalized.
        let set = vec![
            ww("peer-a", 7, &["a:ns", "b:ns"], r1),
            ww("peer-a", 7, &["b:ns", "a:ns"], r2),
        ];
        match compare_witnesses(&set) {
            WitnessComparison::Equivocation(proofs) => {
                assert_eq!(proofs.len(), 1);
                assert_eq!(proofs[0].peer_id, "peer-a");
                assert_eq!(proofs[0].epoch_id, 7);
            },
            other => panic!("expected equivocation, got {other:?}"),
        }
    }

    #[test]
    fn verify_witness_rejects_self_namespace() {
        let w = ww("peer-a", 1, &["cohort_scope:self:notes"], [0u8; 32]);
        let sig = super::super::preimage::BoundHybridSig {
            ed25519: &[0u8; 64],
            mldsa65: Some(&[0u8; 8]),
        };
        let err = verify_witness(&w, b"pre", &sig, &[0u8; 32], &[0u8; 8], None).unwrap_err();
        assert!(matches!(
            err,
            super::super::preimage::HolonomicError::Invariant {
                reason: "ww_namespace"
            }
        ));
    }
}
