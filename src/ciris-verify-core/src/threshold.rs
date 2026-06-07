//! M-of-N hybrid threshold-signature verification.
//!
//! Generic primitive: given canonical bytes, a set of trusted members
//! (each with their hybrid public keys), and a set of submitted
//! signatures, verify that ≥ `threshold` *distinct* trusted members
//! each produced a valid hybrid signature over the bytes. One library
//! primitive, two named consumers:
//!
//! - **CIRISVerify#31 — federation keyset rotation.** A new
//!   [`crate::federation_keyset::FederationKeyset`] is signed by ≥
//!   (old threshold) of the old keyset's members over the new
//!   keyset's canonical bytes.
//! - **CIRISVerify#32 Ask 3 — `EmergencyShutdown CONSTITUTIONAL`.** A
//!   shutdown intent is signed by ≥ 2 of the 3 HUMANITY_ACCORD holders
//!   before a verify client honors it.
//!
//! The federation's "every signature is hybrid + the PQC binds the
//! classical" discipline applies: each submitted signature carries an
//! Ed25519 half and (when not hybrid-pending) an ML-DSA-65 half. The
//! PQC half covers `bytes ‖ classical_sig` — the bound-signature rule
//! shared with `FederationEnvelope`, `WitnessSignature`, and
//! `ProvenanceLink`.
//!
//! ## What is verified
//!
//! 1. `threshold >= 1` and `threshold <= members.len()` (parameter
//!    sanity — a 0-of-N "threshold" or a threshold larger than the
//!    member set is rejected).
//! 2. Each submitted signature's `member_id` is in `members`.
//!    Submissions from unknown members are silently skipped — they
//!    don't fail verification, they just don't count (same discipline
//!    as `SignedTreeHead::count_valid_witnesses`).
//! 3. The Ed25519 half verifies against the member's pinned Ed25519
//!    public key over `bytes`.
//! 4. If a PQC half is present, it verifies against the member's
//!    pinned ML-DSA-65 public key over `bytes ‖ classical_sig`. A
//!    member that has no PQC public key (`mldsa65_public_key_base64 ==
//!    None`) is hybrid-pending — its classical-only signature still
//!    counts; a *submitted* PQC half against a member without a PQC
//!    pubkey is treated as not-counting (no parent to verify against).
//! 5. Duplicate `member_id` submissions count once.
//! 6. The final distinct-valid count is `≥ threshold`.
//!
//! Any failure of (3) for a given signature simply means that
//! signature doesn't count — the same fail-secure-and-skip rule used
//! everywhere else in CIRISVerify. The verdict is a single
//! `Result<usize, ThresholdError>`: `Ok(count)` on success
//! (`count >= threshold`); `Err` on a parameter error or insufficient
//! count.

use base64::Engine;
use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, MlDsa65Verifier, PqcVerifier};
use serde::{Deserialize, Serialize};

/// Role of a trusted threshold-signing member.
///
/// Used by CEG 0.11+ `cohort_subkind: infrastructure` trust-root
/// communities (CIRISVerify#31 / CIRISRegistry#56), where admission
/// must be evaluated over the founder subset rather than the full
/// member set — the anti-Sybil guardrail that prevents flooding
/// the membership from diluting the admission quorum.
///
/// For non-infrastructure callers, members carry `role: None`
/// (serialized as absent) and are treated as `Member` by anything
/// that asks; the existing flat-member `verify_threshold_signatures`
/// is role-blind and continues to work unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Founding member of the trust root. Admission quorum is
    /// evaluated over this subset for `cohort_subkind: infrastructure`
    /// communities with `admission_quorum_basis: "founders"`.
    Founder,
    /// Non-founding member. Counts toward operational signatures but
    /// not toward admission of new members.
    Member,
}

/// A trusted threshold-signing member — the pinned identity of a key
/// that may contribute toward a threshold.
///
/// Wire-shape mirrors CIRISPersist's `KeyRecord` (base64 strings) so a
/// federation announcement carrying these can be serialized directly
/// between persist, the agent, and verify.
///
/// `role` was added in CIRISVerify v4.9.0 for `cohort_subkind: infrastructure`
/// support (CIRISVerify#31). Existing JSON without the field deserializes
/// with `role: None` and behaves as before — `verify_threshold_signatures`
/// ignores the field; only the new `verify_founder_quorum` consumes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdMember {
    /// Stable identifier for the member.
    pub member_id: String,
    /// Pinned Ed25519 public key (32 bytes), base64 standard.
    pub ed25519_public_key_base64: String,
    /// Pinned ML-DSA-65 public key (1952 bytes), base64 standard.
    /// `None` while the member is hybrid-pending — classical-only
    /// signatures from this member still count toward the threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_public_key_base64: Option<String>,
    /// CEG 0.11+ role (`founder` / `member`). `None` for legacy callers
    /// and non-infrastructure use cases — treated as `Member` by
    /// founder-aware verifiers ([`verify_founder_quorum`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
}

/// A submitted signature toward a threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSignature {
    /// `member_id` of the member that produced this signature.
    pub member_id: String,
    /// Ed25519 signature over `bytes`, base64 standard.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 signature over `bytes ‖ ed25519_signature` (bound),
    /// base64 standard. `None` for a hybrid-pending submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_signature_base64: Option<String>,
}

/// Why a threshold-signature verification was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    /// A `threshold` of 0 is rejected — it would be trivially satisfied
    /// by any submission (or none), which is never the intended policy.
    ZeroThreshold,
    /// `threshold` exceeds the trusted-member-set size — the policy
    /// can never be satisfied. Reported as a parameter error rather
    /// than masked as `Insufficient`, so a misconfigured caller fails
    /// loudly.
    ThresholdExceedsMembers {
        /// The threshold requested.
        threshold: usize,
        /// The number of trusted members supplied.
        members: usize,
    },
    /// Fewer distinct valid signatures than the threshold required.
    Insufficient {
        /// Count of distinct trusted members with a valid hybrid
        /// signature.
        valid: usize,
        /// The threshold the caller required.
        threshold: usize,
    },
}

impl std::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroThreshold => write!(f, "threshold of 0 is never accepted"),
            Self::ThresholdExceedsMembers { threshold, members } => write!(
                f,
                "threshold {threshold} exceeds the trusted-member-set size {members}"
            ),
            Self::Insufficient { valid, threshold } => write!(
                f,
                "insufficient distinct valid signatures: {valid} < threshold {threshold}"
            ),
        }
    }
}

impl std::error::Error for ThresholdError {}

/// Verify an M-of-N hybrid threshold-signature set over `bytes`.
///
/// Returns `Ok(count)` where `count` is the number of *distinct*
/// trusted members whose hybrid signature verified, when `count
/// >= threshold`. Otherwise returns [`ThresholdError`].
///
/// See the module docs for the exact rules. The primitive never
/// panics; any signature that fails for any reason — unknown
/// `member_id`, base64 malformation, classical-half mismatch, PQC-half
/// mismatch — is silently skipped and simply doesn't count toward the
/// threshold. The single returned `usize` is the verdict.
pub fn verify_threshold_signatures(
    bytes: &[u8],
    members: &[ThresholdMember],
    signatures: &[ThresholdSignature],
    threshold: usize,
) -> Result<usize, ThresholdError> {
    if threshold == 0 {
        return Err(ThresholdError::ZeroThreshold);
    }
    if threshold > members.len() {
        return Err(ThresholdError::ThresholdExceedsMembers {
            threshold,
            members: members.len(),
        });
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let ed = Ed25519Verifier::new();
    let mldsa = MlDsa65Verifier::new();
    let mut counted: Vec<&str> = Vec::new();

    for sig in signatures {
        // Already counted this member — duplicate submissions don't
        // contribute twice (M signatures from one member are not M
        // members).
        if counted.contains(&sig.member_id.as_str()) {
            continue;
        }
        // Unknown member — silently skip (the discipline shared with
        // witness verification).
        let Some(member) = members.iter().find(|m| m.member_id == sig.member_id) else {
            continue;
        };

        // Decode the member's Ed25519 pubkey + the submitted classical
        // signature. Any malformation → skip; don't count.
        let Ok(ed_pubkey) = b64.decode(&member.ed25519_public_key_base64) else {
            continue;
        };
        let Ok(classical_sig) = b64.decode(&sig.ed25519_signature_base64) else {
            continue;
        };
        // Classical half must verify for this submission to count.
        if !matches!(ed.verify(&ed_pubkey, bytes, &classical_sig), Ok(true)) {
            continue;
        }

        // PQC half is verified when *both* the submission and the
        // member carry one. A submitted PQC half against a member with
        // no PQC pubkey can't be checked → not counted (fail-secure).
        // A hybrid-pending member + hybrid-pending submission counts
        // on the classical half alone.
        if let Some(pqc_sig_b64) = &sig.mldsa65_signature_base64 {
            let Some(pqc_pubkey_b64) = &member.mldsa65_public_key_base64 else {
                continue;
            };
            let Ok(pqc_sig) = b64.decode(pqc_sig_b64) else {
                continue;
            };
            let Ok(pqc_pubkey) = b64.decode(pqc_pubkey_b64) else {
                continue;
            };
            // Bound signature: PQC covers bytes ‖ classical_sig.
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&classical_sig);
            if !matches!(mldsa.verify(&pqc_pubkey, &bound, &pqc_sig), Ok(true)) {
                continue;
            }
        }

        counted.push(&sig.member_id);
    }

    let valid = counted.len();
    if valid >= threshold {
        Ok(valid)
    } else {
        Err(ThresholdError::Insufficient { valid, threshold })
    }
}

/// Verify an M-of-N hybrid threshold-signature set over `bytes`,
/// **restricted to members with `role == Role::Founder`**.
///
/// CEG 0.11+ `cohort_subkind: infrastructure` communities (the
/// `ciris-canonical` trust root and any sibling service-class trust
/// root) require admission to be evaluated over the founder subset
/// rather than the full member set. Growing the membership with
/// `role: Member` admittees MUST NOT dilute the admission quorum —
/// that's the anti-Sybil property a trust root needs.
///
/// This function filters `members` to founders first, then delegates
/// to [`verify_threshold_signatures`]. Errors:
/// - [`ThresholdError::ThresholdExceedsMembers`] when `threshold` exceeds
///   the founder-subset size (the policy is unsatisfiable).
/// - [`ThresholdError::Insufficient`] when fewer than `threshold`
///   founders signed validly (note: only the founder subset is
///   reported as `members` in the error).
///
/// A signature from a `role: Member` member is silently ignored —
/// not counted, not an error. Signatures from members with `role: None`
/// (legacy / non-infrastructure shape) are likewise ignored, since
/// "founder" must be explicitly declared for a trust root.
pub fn verify_founder_quorum(
    bytes: &[u8],
    members: &[ThresholdMember],
    signatures: &[ThresholdSignature],
    threshold: usize,
) -> Result<usize, ThresholdError> {
    let founders: Vec<ThresholdMember> = members
        .iter()
        .filter(|m| matches!(m.role, Some(Role::Founder)))
        .cloned()
        .collect();
    verify_threshold_signatures(bytes, &founders, signatures, threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    /// A signing party — keys plus the helpers to build a
    /// `ThresholdMember` / `ThresholdSignature` for it.
    struct Party {
        member_id: String,
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Party {
        fn new(id: &str) -> Self {
            Self {
                member_id: id.to_string(),
                ed: Ed25519Signer::random(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }

        fn member(&self, include_pqc: bool) -> ThresholdMember {
            let b64 = base64::engine::general_purpose::STANDARD;
            ThresholdMember {
                member_id: self.member_id.clone(),
                ed25519_public_key_base64: b64.encode(self.ed.public_key().unwrap()),
                mldsa65_public_key_base64: include_pqc
                    .then(|| b64.encode(self.mldsa.public_key().unwrap())),
                role: None,
            }
        }

        fn sign(&self, bytes: &[u8], include_pqc: bool) -> ThresholdSignature {
            let b64 = base64::engine::general_purpose::STANDARD;
            let ed_sig = self.ed.sign(bytes).unwrap();
            let pqc_sig = if include_pqc {
                let mut bound = bytes.to_vec();
                bound.extend_from_slice(&ed_sig);
                Some(b64.encode(self.mldsa.sign(&bound).unwrap()))
            } else {
                None
            };
            ThresholdSignature {
                member_id: self.member_id.clone(),
                ed25519_signature_base64: b64.encode(&ed_sig),
                mldsa65_signature_base64: pqc_sig,
            }
        }
    }

    fn three_parties() -> [Party; 3] {
        [Party::new("a"), Party::new("b"), Party::new("c")]
    }

    // ---------------------------------------------------------------------

    #[test]
    fn two_of_three_with_two_valid_signatures_passes() {
        let parties = three_parties();
        let bytes = b"shutdown intent v1";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        let sigs = vec![parties[0].sign(bytes, true), parties[1].sign(bytes, true)];
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Ok(2)
        );
    }

    #[test]
    fn two_of_three_with_three_valid_signatures_passes() {
        let parties = three_parties();
        let bytes = b"shutdown intent v1";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        let sigs: Vec<_> = parties.iter().map(|p| p.sign(bytes, true)).collect();
        // Threshold met with all three present.
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Ok(3)
        );
    }

    #[test]
    fn two_of_three_with_one_valid_signature_is_insufficient() {
        let parties = three_parties();
        let bytes = b"shutdown intent v1";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        let sigs = vec![parties[0].sign(bytes, true)];
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Err(ThresholdError::Insufficient {
                valid: 1,
                threshold: 2
            })
        );
    }

    #[test]
    fn unknown_member_is_silently_skipped() {
        let parties = three_parties();
        let outsider = Party::new("outsider");
        let bytes = b"x";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        // Two valid signatures + one signature from a non-member —
        // the outsider's signature doesn't fail the verdict, it just
        // doesn't count.
        let sigs = vec![
            parties[0].sign(bytes, true),
            outsider.sign(bytes, true),
            parties[1].sign(bytes, true),
        ];
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Ok(2)
        );
    }

    #[test]
    fn duplicate_member_signatures_count_once() {
        let parties = three_parties();
        let bytes = b"x";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        // Same party submitted twice — counts once. Not enough for 2.
        let sigs = vec![parties[0].sign(bytes, true), parties[0].sign(bytes, true)];
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Err(ThresholdError::Insufficient {
                valid: 1,
                threshold: 2
            })
        );
    }

    #[test]
    fn tampered_classical_signature_does_not_count() {
        let parties = three_parties();
        let bytes = b"x";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut bad = parties[0].sign(bytes, true);
        let mut sig = b64.decode(&bad.ed25519_signature_base64).unwrap();
        sig[0] ^= 1;
        bad.ed25519_signature_base64 = b64.encode(&sig);
        let sigs = vec![bad, parties[1].sign(bytes, true)];
        // One valid, one corrupted — insufficient for 2.
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Err(ThresholdError::Insufficient {
                valid: 1,
                threshold: 2
            })
        );
    }

    #[test]
    fn tampered_pqc_signature_does_not_count() {
        let parties = three_parties();
        let bytes = b"x";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut bad = parties[0].sign(bytes, true);
        let mut sig = b64
            .decode(bad.mldsa65_signature_base64.as_ref().unwrap())
            .unwrap();
        sig[0] ^= 1;
        bad.mldsa65_signature_base64 = Some(b64.encode(&sig));
        let sigs = vec![bad, parties[1].sign(bytes, true)];
        // Classical of party-0 verifies but PQC fails → party-0's
        // submission doesn't count.
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Err(ThresholdError::Insufficient {
                valid: 1,
                threshold: 2
            })
        );
    }

    #[test]
    fn wrong_bytes_means_no_signatures_count() {
        let parties = three_parties();
        let signed_bytes = b"original";
        let verified_bytes = b"different";
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        let sigs: Vec<_> = parties.iter().map(|p| p.sign(signed_bytes, true)).collect();
        assert_eq!(
            verify_threshold_signatures(verified_bytes, &members, &sigs, 2),
            Err(ThresholdError::Insufficient {
                valid: 0,
                threshold: 2
            })
        );
    }

    #[test]
    fn hybrid_pending_member_classical_still_counts() {
        let parties = three_parties();
        let bytes = b"x";
        // First party has no PQC pubkey (hybrid-pending); the others do.
        let members = vec![
            parties[0].member(false),
            parties[1].member(true),
            parties[2].member(true),
        ];
        // Party-0 signs classical-only (no PQC half); parties 1+2 sign
        // full hybrid. Threshold 2 → met.
        let sigs = vec![parties[0].sign(bytes, false), parties[1].sign(bytes, true)];
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Ok(2)
        );
    }

    #[test]
    fn pqc_submission_against_classical_only_member_does_not_count() {
        // Member is hybrid-pending (no pubkey_pqc) but the submission
        // carries a PQC half — there's nothing to verify it against,
        // so it can't be allowed to count fail-secure.
        let parties = three_parties();
        let bytes = b"x";
        let members = vec![
            parties[0].member(false), // no PQC
            parties[1].member(true),
        ];
        // Party-0 submits a (bogus) hybrid signature including PQC, but
        // member-0 has no PQC pubkey → can't verify → doesn't count.
        // Pair with party-1's valid hybrid signature.
        let bad = parties[0].sign(bytes, true);
        let sigs = vec![bad, parties[1].sign(bytes, true)];
        assert_eq!(
            verify_threshold_signatures(bytes, &members, &sigs, 2),
            Err(ThresholdError::Insufficient {
                valid: 1,
                threshold: 2
            })
        );
    }

    #[test]
    fn zero_threshold_is_rejected() {
        let parties = three_parties();
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        assert_eq!(
            verify_threshold_signatures(b"x", &members, &[], 0),
            Err(ThresholdError::ZeroThreshold)
        );
    }

    #[test]
    fn threshold_exceeding_member_set_is_rejected() {
        let parties = three_parties();
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        assert_eq!(
            verify_threshold_signatures(b"x", &members, &[], 4),
            Err(ThresholdError::ThresholdExceedsMembers {
                threshold: 4,
                members: 3,
            })
        );
    }

    #[test]
    fn empty_signatures_returns_insufficient_not_zero_ok() {
        let parties = three_parties();
        let members: Vec<_> = parties.iter().map(|p| p.member(true)).collect();
        assert_eq!(
            verify_threshold_signatures(b"x", &members, &[], 1),
            Err(ThresholdError::Insufficient {
                valid: 0,
                threshold: 1
            })
        );
    }

    /// The HUMANITY_ACCORD 2-of-3 emergency-shutdown shape
    /// (CIRISVerify#32 Ask 3). Verbatim use case — three accord
    /// holders, threshold 2, an emergency-shutdown intent's canonical
    /// bytes.
    #[test]
    fn constitutional_emergency_shutdown_2_of_3_use_case() {
        let holders = three_parties();
        let intent_bytes = b"CIRIS-EMERGENCY-SHUTDOWN-V1\x00<intent payload>";
        let accord_holders: Vec<_> = holders.iter().map(|h| h.member(true)).collect();
        // Two of three holders sign the intent.
        let signatures = vec![
            holders[0].sign(intent_bytes, true),
            holders[2].sign(intent_bytes, true),
        ];
        assert!(verify_threshold_signatures(intent_bytes, &accord_holders, &signatures, 2).is_ok());
        // Only one signature → constitutional shutdown is rejected.
        let one_sig = vec![holders[0].sign(intent_bytes, true)];
        assert!(matches!(
            verify_threshold_signatures(intent_bytes, &accord_holders, &one_sig, 2),
            Err(ThresholdError::Insufficient { .. })
        ));
    }

    // =========================================================================
    // Founder-quorum tests (CIRISVerify#31, CEG 0.11 `cohort_subkind: infrastructure`)
    // =========================================================================

    /// Helper to tag a Party's ThresholdMember with a role.
    fn member_with_role(party: &Party, role: Role) -> ThresholdMember {
        ThresholdMember {
            role: Some(role),
            ..party.member(true)
        }
    }

    /// Lock the CEG 0.11 anti-Sybil property: flooding the membership
    /// with non-founder members must NOT make admission easier. With
    /// 2 founders + 2 non-founder members, threshold=2, the 2 founders
    /// must both sign for the quorum to pass — non-founder signatures
    /// don't count.
    #[test]
    fn founder_quorum_anti_sybil_non_founders_dont_count() {
        let bytes = b"infrastructure-community-admission-payload";
        let founders = [Party::new("founder-us"), Party::new("founder-eu")];
        let non_founders = [Party::new("lens-install"), Party::new("node-install")];

        let mut members: Vec<ThresholdMember> = founders
            .iter()
            .map(|p| member_with_role(p, Role::Founder))
            .collect();
        members.extend(
            non_founders
                .iter()
                .map(|p| member_with_role(p, Role::Member)),
        );

        // Only non-founder signatures — must fail (zero founders signed).
        let sigs_non_founder: Vec<_> = non_founders.iter().map(|p| p.sign(bytes, true)).collect();
        let res = verify_founder_quorum(bytes, &members, &sigs_non_founder, 2);
        assert!(
            matches!(res, Err(ThresholdError::Insufficient { valid: 0, .. })),
            "non-founder signatures must not satisfy founder quorum; got {res:?}"
        );

        // Both founders sign — quorum satisfied.
        let sigs_founders: Vec<_> = founders.iter().map(|p| p.sign(bytes, true)).collect();
        assert_eq!(
            verify_founder_quorum(bytes, &members, &sigs_founders, 2),
            Ok(2)
        );

        // Mixed signatures (1 founder + 1 non-founder) — only 1 founder
        // counted, threshold=2 not met.
        let sigs_mixed = vec![
            founders[0].sign(bytes, true),
            non_founders[0].sign(bytes, true),
        ];
        let res = verify_founder_quorum(bytes, &members, &sigs_mixed, 2);
        assert!(
            matches!(res, Err(ThresholdError::Insufficient { valid: 1, .. })),
            "1 founder + 1 non-founder must report valid=1; got {res:?}"
        );
    }

    /// Members with `role: None` (legacy / non-infrastructure shape)
    /// are treated as Member, not Founder. A keyset of all-`None`
    /// members can never satisfy a founder quorum — fail-secure.
    #[test]
    fn founder_quorum_treats_role_none_as_member() {
        let bytes = b"legacy-keyset-bytes";
        let parties = [Party::new("a"), Party::new("b")];
        // Default member() returns role: None.
        let members: Vec<ThresholdMember> = parties.iter().map(|p| p.member(true)).collect();
        let sigs: Vec<_> = parties.iter().map(|p| p.sign(bytes, true)).collect();
        let res = verify_founder_quorum(bytes, &members, &sigs, 1);
        // Founder subset is EMPTY → threshold=1 exceeds member-set size 0.
        assert!(
            matches!(
                res,
                Err(ThresholdError::ThresholdExceedsMembers {
                    threshold: 1,
                    members: 0
                })
            ),
            "all-None-role keyset must report empty founder subset; got {res:?}"
        );
    }

    /// CEG 0.15 worked example shape: 3 founders, 2-of-3 quorum.
    /// Any 2 of the 3 founders' signatures satisfy admission.
    #[test]
    fn founder_quorum_2_of_3_founders() {
        let bytes = b"ciris-canonical-supersedes-payload";
        let founders = [
            Party::new("registry-steward-us"),
            Party::new("registry-steward-eu"),
            Party::new("registry-steward-apac"),
        ];
        let members: Vec<ThresholdMember> = founders
            .iter()
            .map(|p| member_with_role(p, Role::Founder))
            .collect();

        // us + eu sign — admitted.
        let sigs = vec![founders[0].sign(bytes, true), founders[1].sign(bytes, true)];
        assert_eq!(verify_founder_quorum(bytes, &members, &sigs, 2), Ok(2));

        // us + apac sign — also admitted (any 2 of 3 founders).
        let sigs = vec![founders[0].sign(bytes, true), founders[2].sign(bytes, true)];
        assert_eq!(verify_founder_quorum(bytes, &members, &sigs, 2), Ok(2));

        // Just us — insufficient.
        let sigs = vec![founders[0].sign(bytes, true)];
        assert!(matches!(
            verify_founder_quorum(bytes, &members, &sigs, 2),
            Err(ThresholdError::Insufficient {
                valid: 1,
                threshold: 2
            })
        ));
    }
}
