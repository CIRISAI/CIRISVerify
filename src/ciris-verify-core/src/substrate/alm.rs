//! §19.4 Deterministic ALM topology — capacity authenticity (CEG 1.0-RC11).
//!
//! The application-layer-multicast relay tree for large-N fan-out. Of this
//! section, two things are **PIN-NORMATIVE** and live at Verify; the rest is
//! edge-internal (the §19.0 / §1.1 wire-vs-internal line):
//!
//! - **N8 (capacity authenticity).** Capacity advertisements feeding the
//!   topology MUST be hybrid-verified (`SignedRelayCapacity`, domain
//!   `b"CIRISALM-CAPv2\0\0"`) **before scoring** ([`verify_relay_capacity`]).
//!   Self-asserted `uplink_mbps` MUST NOT be the dominant, unbounded selection
//!   term — determinism amplifies one capacity lie into a *universal* eclipse,
//!   so [`bounded_capacity_score`] caps it per owner-bound identity.
//! - **`compute_alm_topology` is PIN-NORMATIVE as a contract** — a pure,
//!   deterministic, **integer-only** (no IEEE-754, no `HashMap` order) function
//!   whose byte-equal inputs yield byte-equal output across impls. The
//!   byte-exact output is gated on the §19.6 / #57 vectors (incl.
//!   permutation-invariance), **not** transcribed from any one algorithm body —
//!   so this module provides the **input-canonicalization + determinism harness**
//!   ([`canonicalize_snapshot`]) and the capacity gate, and the parent-selection
//!   body (`AlmJoinPlanner`, over per-peer RTT) stays edge-internal.
//!
//! **D6 preserved:** `reachability_observations` are ephemeral planner inputs —
//! never attested, replicated, or witness-leafed (§10.5.6 "reachability is never
//! trust"). They feed the local planner, not any signed/§19.1 surface.

use super::preimage::{BoundHybridSig, HolonomicError, Preimage, DOMAIN_RELAY_CAPACITY};

/// A relay's signed capacity advertisement (§19.4 N8). The exact preimage field
/// set is byte-frozen by the §19.6 vectors; the load-bearing fields the
/// topology scores over are here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRelayCapacity {
    /// The advertising peer (owner-bound identity).
    pub peer_id: String,
    /// Self-asserted uplink capacity, Mbps (NEVER the dominant unbounded term).
    pub uplink_mbps: u32,
    /// Monotonic advert epoch (anti-rollback at the caller).
    pub epoch: u64,
}

impl SignedRelayCapacity {
    /// The §19.4 signed preimage (`b"CIRISALM-CAPv2\0\0"` ‖ peer_id ‖
    /// uplink_mbps_be ‖ epoch_be).
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        Preimage::new(DOMAIN_RELAY_CAPACITY)
            .lp(self.peer_id.as_bytes())
            .u32_be(self.uplink_mbps)
            .u64_be(self.epoch)
            .finish()
    }
}

/// N8: verify a capacity advertisement's bound-hybrid signature
/// (PQC-mandatory) **before** it may feed [`canonicalize_snapshot`] / scoring.
/// An unverified advert MUST NOT influence the topology.
///
/// # Errors
///
/// [`HolonomicError`] from the signature gate.
pub fn verify_relay_capacity(
    cap: &SignedRelayCapacity,
    sig: &BoundHybridSig<'_>,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
) -> Result<(), HolonomicError> {
    let preimage = cap.signing_preimage();
    super::preimage::verify_bound_hybrid(&preimage, sig, ed25519_pubkey, mldsa65_pubkey)
}

/// The per-identity capacity cap (Mbps) beyond which a self-asserted `uplink_mbps`
/// no longer increases selection weight — the N8 anti-eclipse bound. A throughput
/// challenge can raise an identity's *proven* capacity above this; the
/// *self-asserted* term is capped.
pub const CAPACITY_SELECTION_CAP_MBPS: u32 = 1_000;

/// N8: the bounded capacity score a self-asserted advert contributes — `min`ed
/// at [`CAPACITY_SELECTION_CAP_MBPS`] so one capacity lie cannot dominate the
/// deterministic selection and eclipse the tree.
#[must_use]
pub fn bounded_capacity_score(self_asserted_mbps: u32) -> u32 {
    self_asserted_mbps.min(CAPACITY_SELECTION_CAP_MBPS)
}

/// Canonicalize an ALM input snapshot for the deterministic-topology contract:
/// the **verified** capacity adverts sorted by `peer_id` (lexicographic), so the
/// `compute_alm_topology` contract's "byte-equal inputs → byte-equal output"
/// property holds regardless of the order adverts arrived. Integer-only; no
/// floats, no hash-map iteration order.
///
/// **Precondition:** every advert MUST already have passed
/// [`verify_relay_capacity`] (N8) — this canonicalizer orders inputs, it does
/// not authenticate them.
#[must_use]
pub fn canonicalize_snapshot(verified_adverts: &[SignedRelayCapacity]) -> Vec<SignedRelayCapacity> {
    let mut v = verified_adverts.to_vec();
    // Lexicographic by peer_id, then by epoch desc (latest advert wins a tie),
    // then uplink — a total, deterministic order with no float / map dependence.
    v.sort_by(|a, b| {
        a.peer_id
            .cmp(&b.peer_id)
            .then(b.epoch.cmp(&a.epoch))
            .then(a.uplink_mbps.cmp(&b.uplink_mbps))
    });
    // Collapse to the latest advert per peer (dedupe by peer_id, keeping first
    // after the epoch-desc sort).
    v.dedup_by(|a, b| a.peer_id == b.peer_id);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    #[test]
    fn n8_capacity_advert_round_trips_pqc_mandatory() {
        let ed = Ed25519Signer::random().unwrap();
        let mldsa = MlDsa65Signer::new().unwrap();
        let cap = SignedRelayCapacity {
            peer_id: "relay-1".into(),
            uplink_mbps: 500,
            epoch: 3,
        };
        let pre = cap.signing_preimage();
        let ed_sig = ed.sign(&pre).unwrap();
        let mut bound = pre.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).unwrap();
        let good = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: Some(&pqc_sig),
        };
        assert!(verify_relay_capacity(
            &cap,
            &good,
            &ed.public_key().unwrap(),
            &mldsa.public_key().unwrap()
        )
        .is_ok());
        // Classical-only advert is rejected (N8 + PQC-mandatory).
        let co = BoundHybridSig {
            ed25519: &ed_sig,
            mldsa65: None,
        };
        assert!(verify_relay_capacity(
            &cap,
            &co,
            &ed.public_key().unwrap(),
            &mldsa.public_key().unwrap()
        )
        .is_err());
    }

    #[test]
    fn capacity_score_is_bounded() {
        assert_eq!(bounded_capacity_score(500), 500);
        assert_eq!(
            bounded_capacity_score(1_000_000),
            CAPACITY_SELECTION_CAP_MBPS
        );
    }

    #[test]
    fn snapshot_canonicalization_is_permutation_invariant() {
        let a = SignedRelayCapacity {
            peer_id: "a".into(),
            uplink_mbps: 100,
            epoch: 1,
        };
        let b = SignedRelayCapacity {
            peer_id: "b".into(),
            uplink_mbps: 200,
            epoch: 1,
        };
        let s1 = canonicalize_snapshot(&[a.clone(), b.clone()]);
        let s2 = canonicalize_snapshot(&[b, a]);
        assert_eq!(s1, s2, "input order must not change canonical snapshot");
    }

    #[test]
    fn snapshot_keeps_latest_epoch_per_peer() {
        let old = SignedRelayCapacity {
            peer_id: "a".into(),
            uplink_mbps: 100,
            epoch: 1,
        };
        let new = SignedRelayCapacity {
            peer_id: "a".into(),
            uplink_mbps: 900,
            epoch: 5,
        };
        let s = canonicalize_snapshot(&[old, new.clone()]);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].epoch, 5);
    }
}
