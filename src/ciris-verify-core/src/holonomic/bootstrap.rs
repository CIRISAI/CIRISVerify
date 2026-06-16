//! §19.2 Recursive trust bootstrap — trust-*discovery*, not membership
//! (CEG 1.0-RC11, the highest-risk §19 gate, issue #78 F-1).
//!
//! `recursive_trust_bootstrap` lets a peer discover transitive trust by walking
//! a signed witness chain to a root in its own trust graph. It is **reachability
//! discovery beneath CEG's authority layer, not an admission shortcut.** The
//! load-bearing invariants this module enforces:
//!
//! - **N1 (trust ≠ membership).** A successful walk yields **trust+serve
//!   standing only** (§5.6.8.10 TRUST≠MEMBERSHIP). Admission to a
//!   non-`infrastructure` community still requires, *at the destination*, the
//!   §5.6.8.10 owner-binding precondition (a live `user`-owner `delegates_to` +
//!   an admitted `identity_occurrence`) **and** that community's
//!   `consensus_protocol` vote. `infrastructure` roots stay founder-quorum; a
//!   transitive chain MUST NOT satisfy founder-quorum. [`BootstrapVerdict`] can
//!   never express "admitted" — it is structurally incapable of it.
//! - **N2 (self-supplied chains aren't evidence).** Depth MUST be ≤ the §13.3
//!   **5-hop cap**; trust-graph **cycles MUST be rejected**; the §13.3
//!   **aggregate-weight cap** (default 0.5 × root_trust) bounds the standing one
//!   root confers transitively. A caller-supplied chain proves only its
//!   signatures.
//! - **RB-1 (anonymous coexistence).** Anonymous-tier content needs no
//!   trust-graph position; this function MUST NOT be required for or invoked on
//!   anonymous records (a caller concern — documented, not a code path here).
//!
//! Trust weights are **basis points** (`u32`, `10_000` = 1.0) — integer-only, no
//! IEEE-754, so the cap arithmetic is deterministic cross-impl.

use super::preimage::{BoundHybridSig, HolonomicError};

/// The §13.3 default delegation-chain depth cap (hops).
pub const MAX_BOOTSTRAP_HOPS: usize = 5;

/// Trust weight, basis points (`10_000` = 1.0). Integer-only for determinism.
pub type WeightBp = u32;

/// Full trust (1.0) in basis points.
pub const FULL_TRUST_BP: WeightBp = 10_000;

/// A trust root the verifying peer pins in its **own** trust graph: a key it
/// already trusts directly, with the trust it assigns it.
#[derive(Debug, Clone)]
pub struct TrustRoot {
    /// The root peer's id (a hop's `to_peer` must terminate here).
    pub peer_id: String,
    /// The trust this peer assigns the root, basis points.
    pub root_trust_bp: WeightBp,
}

/// One hop of a bootstrap chain: `from_peer` attests trust `weight_bp` in
/// `to_peer`, over a §19.2 `SignedClaim` bound-hybrid signature.
///
/// The `SignedClaim` preimage layout (domain `b"CIRIS-CLAIM-v1\0\0"`) gains
/// owner-binding fields under CIRISEdge#143 and is byte-frozen by the §19.6
/// vectors — the caller builds it via [`crate::holonomic::Preimage`]; this hop
/// carries the bytes plus the pinned pubkeys to verify against.
pub struct BootstrapHop<'a> {
    /// The attesting (delegating) peer.
    pub from_peer: String,
    /// The peer being vouched for.
    pub to_peer: String,
    /// Trust `from_peer` confers on `to_peer`, basis points (≤ `FULL_TRUST_BP`).
    pub weight_bp: WeightBp,
    /// The §19.2 signed preimage these halves cover.
    pub preimage: &'a [u8],
    /// The bound-hybrid signature halves (PQC-mandatory).
    pub sig: BoundHybridSig<'a>,
    /// `from_peer`'s pinned Ed25519 pubkey (the signer of this hop).
    pub from_ed25519_pubkey: &'a [u8],
    /// `from_peer`'s pinned ML-DSA-65 pubkey.
    pub from_mldsa65_pubkey: &'a [u8],
}

/// The verdict of a bootstrap walk. **There is deliberately no `Admitted`
/// variant** (N1): the strongest thing a chain can yield is trust+serve
/// standing, which a downstream membership gate treats as *one input*, never as
/// admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapVerdict {
    /// The chain verified to a pinned root. Confers **trust + serve standing
    /// only** (§5.6.8.10), capped per N2. NOT membership, NOT founder-quorum.
    TrustServeStanding {
        /// The terminal root the chain reached.
        root_peer_id: String,
        /// The transitive standing conferred, basis points, after the §13.3
        /// 0.5 × root_trust cap.
        standing_bp: WeightBp,
    },
    /// The chain did not confer standing (bad signature, over-depth, cycle, or
    /// no terminal trust root). Fail-closed.
    NoStanding {
        /// Short reason tag (`"depth_cap"`, `"cycle"`, `"unrooted"`, a signature
        /// error, …).
        reason: &'static str,
    },
}

/// Walk a bootstrap chain (leaf → … → root-adjacent) and return its standing
/// verdict. **Pure evaluator** (no I/O): every input — the hops, their pubkeys,
/// the trust roots — is caller-supplied.
///
/// Enforced: per-hop bound-hybrid signature (PQC-mandatory); depth ≤
/// [`MAX_BOOTSTRAP_HOPS`] (N2); cycle rejection over the visited peer set (N2);
/// link continuity (`hop[i].to_peer == hop[i+1].from_peer`); the terminal hop's
/// `to_peer` is a pinned [`TrustRoot`]; and the §13.3 aggregate-weight cap
/// (standing = root_trust × ∏ weights, then capped at 0.5 × root_trust).
///
/// Returns [`BootstrapVerdict::TrustServeStanding`] on success — **never**
/// admission. A caller granting membership MUST additionally satisfy
/// [`membership_blocked_without_owner_binding`].
#[must_use]
pub fn recursive_trust_bootstrap(
    chain: &[BootstrapHop<'_>],
    trust_roots: &[TrustRoot],
) -> BootstrapVerdict {
    if chain.is_empty() {
        return BootstrapVerdict::NoStanding { reason: "empty" };
    }
    if chain.len() > MAX_BOOTSTRAP_HOPS {
        return BootstrapVerdict::NoStanding {
            reason: "depth_cap",
        };
    }

    // Cycle + continuity guard over the peer sequence leaf→root.
    let mut visited: Vec<&str> = Vec::with_capacity(chain.len() + 1);
    for (i, hop) in chain.iter().enumerate() {
        // Continuity: this hop's source must equal the previous hop's target.
        if i > 0 && chain[i - 1].to_peer != hop.from_peer {
            return BootstrapVerdict::NoStanding {
                reason: "broken_link",
            };
        }
        // Per-hop signature — PQC-mandatory (F-2). A bad hop kills the chain.
        if verify_hop(hop).is_err() {
            return BootstrapVerdict::NoStanding {
                reason: "hop_signature",
            };
        }
        // Weight sanity: a hop cannot confer more than full trust.
        if hop.weight_bp > FULL_TRUST_BP {
            return BootstrapVerdict::NoStanding {
                reason: "weight_overflow",
            };
        }
        // Cycle: a peer may not reappear as a source.
        if visited.contains(&hop.from_peer.as_str()) {
            return BootstrapVerdict::NoStanding { reason: "cycle" };
        }
        visited.push(&hop.from_peer);
    }

    // Terminal target must be a pinned trust root; final-target cycle check too.
    let terminal = &chain[chain.len() - 1].to_peer;
    if visited.contains(&terminal.as_str()) {
        return BootstrapVerdict::NoStanding { reason: "cycle" };
    }
    let Some(root) = trust_roots.iter().find(|r| &r.peer_id == terminal) else {
        return BootstrapVerdict::NoStanding { reason: "unrooted" };
    };

    // Standing = root_trust × ∏ hop weights, integer-only (basis points),
    // then the §13.3 aggregate-weight cap: ≤ 0.5 × root_trust.
    let mut standing = u64::from(root.root_trust_bp);
    for hop in chain {
        standing = standing * u64::from(hop.weight_bp) / u64::from(FULL_TRUST_BP);
    }
    let cap = u64::from(root.root_trust_bp) / 2;
    let standing_bp = standing.min(cap) as WeightBp;

    BootstrapVerdict::TrustServeStanding {
        root_peer_id: root.peer_id.clone(),
        standing_bp,
    }
}

fn verify_hop(hop: &BootstrapHop<'_>) -> Result<(), HolonomicError> {
    super::preimage::verify_bound_hybrid(
        hop.preimage,
        &hop.sig,
        hop.from_ed25519_pubkey,
        hop.from_mldsa65_pubkey,
    )
}

/// The owner-binding inputs a non-`infrastructure` membership admission requires
/// **in addition to** any bootstrap standing (N1 / §5.6.8.10). Caller-resolved.
#[derive(Debug, Clone, Default)]
pub struct OwnerBinding {
    /// A live `user`-owner `delegates_to` grant exists and resolves.
    pub owner_delegation_present: bool,
    /// The owner's `identity_occurrence` is currently admitted.
    pub identity_occurrence_admitted: bool,
    /// The destination community's `consensus_protocol` vote passed.
    pub consensus_vote_passed: bool,
}

/// N1 enforcement: **bootstrap standing alone never admits.** Returns `true`
/// (membership BLOCKED) unless the §5.6.8.10 owner-binding preconditions AND the
/// community consensus vote are all satisfied. For an `infrastructure` community
/// this is always `true` from bootstrap — infra stays founder-quorum, which a
/// transitive chain MUST NOT satisfy.
///
/// This is the wire-checkable form of "a chain walk yields trust+serve only":
/// even a maximal-standing [`BootstrapVerdict::TrustServeStanding`] cannot move
/// the needle here without the owner-binding the destination resolves itself.
#[must_use]
pub fn membership_blocked_without_owner_binding(
    is_infrastructure_community: bool,
    binding: &OwnerBinding,
) -> bool {
    if is_infrastructure_community {
        // Infra admission is founder-quorum only; bootstrap can't satisfy it.
        return true;
    }
    !(binding.owner_delegation_present
        && binding.identity_occurrence_admitted
        && binding.consensus_vote_passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holonomic::Preimage;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    struct Peer {
        id: String,
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }
    impl Peer {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
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
        fn sign(&self, pre: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let ed_sig = self.ed.sign(pre).unwrap();
            let mut bound = pre.to_vec();
            bound.extend_from_slice(&ed_sig);
            (ed_sig, self.mldsa.sign(&bound).unwrap())
        }
    }

    /// `(preimage, ed_sig, pqc_sig, ed_pub, mldsa_pub)` — a signed hop's bytes.
    type HopBytes = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    /// Build a hop `from → to` with a real bound-hybrid signature.
    fn hop<'a>(
        from: &'a Peer,
        to: &str,
        weight_bp: WeightBp,
        store: &'a mut Vec<HopBytes>,
    ) -> usize {
        let preimage = Preimage::new(super::super::preimage::DOMAIN_SIGNED_CLAIM)
            .lp(from.id.as_bytes())
            .lp(to.as_bytes())
            .u32_be(weight_bp)
            .finish();
        let (ed_sig, pqc_sig) = from.sign(&preimage);
        store.push((preimage, ed_sig, pqc_sig, from.ed_pub(), from.mldsa_pub()));
        store.len() - 1
    }

    #[test]
    fn valid_two_hop_chain_confers_capped_standing() {
        let a = Peer::new("a");
        let b = Peer::new("b");
        let mut store = Vec::new();
        let h0 = hop(&a, "b", FULL_TRUST_BP, &mut store); // a → b, full
        let h1 = hop(&b, "root", FULL_TRUST_BP, &mut store); // b → root, full
        let chain = vec![
            BootstrapHop {
                from_peer: "a".into(),
                to_peer: "b".into(),
                weight_bp: FULL_TRUST_BP,
                preimage: &store[h0].0,
                sig: BoundHybridSig {
                    ed25519: &store[h0].1,
                    mldsa65: Some(&store[h0].2),
                },
                from_ed25519_pubkey: &store[h0].3,
                from_mldsa65_pubkey: &store[h0].4,
            },
            BootstrapHop {
                from_peer: "b".into(),
                to_peer: "root".into(),
                weight_bp: FULL_TRUST_BP,
                preimage: &store[h1].0,
                sig: BoundHybridSig {
                    ed25519: &store[h1].1,
                    mldsa65: Some(&store[h1].2),
                },
                from_ed25519_pubkey: &store[h1].3,
                from_mldsa65_pubkey: &store[h1].4,
            },
        ];
        let roots = vec![TrustRoot {
            peer_id: "root".into(),
            root_trust_bp: FULL_TRUST_BP,
        }];
        match recursive_trust_bootstrap(&chain, &roots) {
            BootstrapVerdict::TrustServeStanding {
                root_peer_id,
                standing_bp,
            } => {
                assert_eq!(root_peer_id, "root");
                // Full×full = full, capped at 0.5×root = 5000.
                assert_eq!(standing_bp, FULL_TRUST_BP / 2);
            },
            other => panic!("expected standing, got {other:?}"),
        }
    }

    #[test]
    fn over_depth_chain_rejected() {
        // 6 hops > 5-hop cap. Build minimal (unsigned-content irrelevant — depth
        // is checked, but signatures are verified per hop, so use real ones).
        let peers: Vec<Peer> = (0..6).map(|i| Peer::new(&format!("p{i}"))).collect();
        let mut store = Vec::new();
        let mut idxs = Vec::new();
        for (i, peer) in peers.iter().enumerate() {
            let to = if i == 5 {
                "root".to_string()
            } else {
                format!("p{}", i + 1)
            };
            idxs.push(hop(peer, &to, FULL_TRUST_BP, &mut store));
        }
        let chain: Vec<BootstrapHop> = (0..6)
            .map(|i| BootstrapHop {
                from_peer: format!("p{i}"),
                to_peer: if i == 5 {
                    "root".into()
                } else {
                    format!("p{}", i + 1)
                },
                weight_bp: FULL_TRUST_BP,
                preimage: &store[idxs[i]].0,
                sig: BoundHybridSig {
                    ed25519: &store[idxs[i]].1,
                    mldsa65: Some(&store[idxs[i]].2),
                },
                from_ed25519_pubkey: &store[idxs[i]].3,
                from_mldsa65_pubkey: &store[idxs[i]].4,
            })
            .collect();
        let roots = vec![TrustRoot {
            peer_id: "root".into(),
            root_trust_bp: FULL_TRUST_BP,
        }];
        assert_eq!(
            recursive_trust_bootstrap(&chain, &roots),
            BootstrapVerdict::NoStanding {
                reason: "depth_cap"
            }
        );
    }

    #[test]
    fn cycle_rejected() {
        let a = Peer::new("a");
        let b = Peer::new("b");
        let mut store = Vec::new();
        let h0 = hop(&a, "b", FULL_TRUST_BP, &mut store);
        let h1 = hop(&b, "a", FULL_TRUST_BP, &mut store); // back to a → cycle
        let chain = vec![
            BootstrapHop {
                from_peer: "a".into(),
                to_peer: "b".into(),
                weight_bp: FULL_TRUST_BP,
                preimage: &store[h0].0,
                sig: BoundHybridSig {
                    ed25519: &store[h0].1,
                    mldsa65: Some(&store[h0].2),
                },
                from_ed25519_pubkey: &store[h0].3,
                from_mldsa65_pubkey: &store[h0].4,
            },
            BootstrapHop {
                from_peer: "b".into(),
                to_peer: "a".into(),
                weight_bp: FULL_TRUST_BP,
                preimage: &store[h1].0,
                sig: BoundHybridSig {
                    ed25519: &store[h1].1,
                    mldsa65: Some(&store[h1].2),
                },
                from_ed25519_pubkey: &store[h1].3,
                from_mldsa65_pubkey: &store[h1].4,
            },
        ];
        let roots = vec![TrustRoot {
            peer_id: "a".into(),
            root_trust_bp: FULL_TRUST_BP,
        }];
        assert_eq!(
            recursive_trust_bootstrap(&chain, &roots),
            BootstrapVerdict::NoStanding { reason: "cycle" }
        );
    }

    #[test]
    fn tampered_hop_signature_rejected() {
        let a = Peer::new("a");
        let mut store = Vec::new();
        let h0 = hop(&a, "root", FULL_TRUST_BP, &mut store);
        // Flip a preimage byte so the signature no longer matches.
        let mut bad_pre = store[h0].0.clone();
        bad_pre[store[h0].0.len() - 1] ^= 1;
        let chain = vec![BootstrapHop {
            from_peer: "a".into(),
            to_peer: "root".into(),
            weight_bp: FULL_TRUST_BP,
            preimage: &bad_pre,
            sig: BoundHybridSig {
                ed25519: &store[h0].1,
                mldsa65: Some(&store[h0].2),
            },
            from_ed25519_pubkey: &store[h0].3,
            from_mldsa65_pubkey: &store[h0].4,
        }];
        let roots = vec![TrustRoot {
            peer_id: "root".into(),
            root_trust_bp: FULL_TRUST_BP,
        }];
        assert_eq!(
            recursive_trust_bootstrap(&chain, &roots),
            BootstrapVerdict::NoStanding {
                reason: "hop_signature"
            }
        );
    }

    #[test]
    fn membership_blocked_without_owner_binding_n1() {
        // Even maximal standing can't admit without owner-binding.
        let none = OwnerBinding::default();
        assert!(membership_blocked_without_owner_binding(false, &none));
        // Infra is always blocked from bootstrap (founder-quorum only).
        let full = OwnerBinding {
            owner_delegation_present: true,
            identity_occurrence_admitted: true,
            consensus_vote_passed: true,
        };
        assert!(membership_blocked_without_owner_binding(true, &full));
        // Non-infra with full owner-binding + consensus → not blocked.
        assert!(!membership_blocked_without_owner_binding(false, &full));
    }
}
