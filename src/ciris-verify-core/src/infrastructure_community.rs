//! CEG 0.11+ `cohort_subkind: infrastructure` trust-root community
//! substrate (CIRISVerify#31).
//!
//! This module is the CEG-shaped wrapper above
//! [`crate::federation_keyset::FederationKeyset`]. Where `FederationKeyset`
//! is the low-level cryptographic primitive (M-of-N over keys, role-blind),
//! [`InfrastructureCommunity`] carries the full CEG `community` Contribution
//! shape for a trust-root collective of canonical/bootstrap service
//! installs — the shape `ciris-canonical` (Registry + Lens + Node) adopts
//! per CEG 0.15 §5.6.8.10 and CIRISRegistry#56.
//!
//! ## Why both shapes
//!
//! `FederationKeyset` stays as the low-level building block (its v1
//! canonical bytes are stable and proven). `InfrastructureCommunity`
//! produces its own v1 canonical bytes under a distinct domain-separation
//! tag — they're independent schemas, so a peer reading
//! `infrastructure_community_signing_bytes` can never be tricked into
//! interpreting it as a `FederationKeyset` blob and vice-versa.
//!
//! ## CEG 0.15 worked example shape
//!
//! ```text
//! community {
//!     community_key_id:                  "ciris-canonical",
//!     community_name:                    "CIRIS Canonical Services",
//!     cohort_subkind:                    "infrastructure",
//!     cohort_subkind_payload: {
//!         infrastructure_constraint: {
//!             service_class:             "canonical",
//!             admission_quorum_basis:    "founders"
//!         }
//!     },
//!     members: [
//!         {key_id: registry_steward_us,   role: founder},
//!         {key_id: registry_steward_eu,   role: founder},
//!         {key_id: registry_steward_apac, role: founder},
//!     ],
//!     consensus_protocol:                "quorum:2/3",
//!     consensus_protocol_entrenched:     true
//! }
//! ```
//!
//! ## Rotation flow (entrenchment-aware)
//!
//! A `supersedes` Contribution proposes a replacement `InfrastructureCommunity`.
//! The substrate evaluates:
//!
//! 1. [`infrastructure_community_signing_bytes`] of the proposed
//!    community.
//! 2. [`crate::threshold::verify_founder_quorum`] over the OLD
//!    community's founders signed those bytes — admission is over the
//!    founder subset, not the full member set.
//! 3. [`verify_supersedes_preserves_entrenchment`] confirms the new
//!    community didn't weaken `consensus_protocol` or move
//!    `admission_quorum_basis` away from `"founders"`.
//!
//! Only after all three pass is the proposed community admitted as
//! the new current state.
//!
//! ## CLI ceremony tooling
//!
//! Belongs in CIRISRegistry (CIRISRegistry#56's `ciris-canonical`
//! migration). This module owns the canonical-bytes substrate +
//! verification primitives only. Same discipline as
//! [`crate::federation_keyset`].

use crate::threshold::{Role, ThresholdMember};
use serde::{Deserialize, Serialize};

/// Domain-separation prefix for CEG-shaped infrastructure community
/// canonical bytes. Distinct from
/// [`crate::federation_keyset::FEDERATION_KEYSET_DOMAIN_SEP`] so the
/// two schemas can never be confused for each other.
pub const INFRASTRUCTURE_COMMUNITY_DOMAIN_SEP: &[u8] = b"CIRIS-INFRASTRUCTURE-COMMUNITY-V1";

/// Current canonical-bytes schema version for this module. Bumped on
/// any incompatible layout change; the value lives *inside* the
/// signed bytes so a verifier can never be fooled into reading new
/// bytes as old.
pub const INFRASTRUCTURE_COMMUNITY_SCHEMA_VERSION: u8 = 1;

/// The `infrastructure_constraint` payload of a CEG `cohort_subkind:
/// infrastructure` community.
///
/// Per CEG 0.11 trust-root conformance: `admission_quorum_basis` MUST
/// be the literal `"founders"` for a trust-root community. The
/// [`verify_supersedes_preserves_entrenchment`] gate enforces this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfrastructureConstraint {
    /// Open-vocab service class. Examples per CEG 0.15 §5.6.8.10:
    /// `"registry"` | `"lens"` | `"node"` | `"canonical"` (umbrella).
    pub service_class: String,
    /// MUST be `"founders"` for trust-root grade. Carried as a String
    /// (not an enum) because CEG keeps it open-vocab for future
    /// extensibility, and the entrenchment gate enforces the literal
    /// at admission time rather than at the type system.
    pub admission_quorum_basis: String,
}

impl InfrastructureConstraint {
    /// The literal expected for `admission_quorum_basis` in any
    /// trust-root community per CEG 0.11.
    pub const FOUNDERS: &'static str = "founders";

    /// `true` iff `admission_quorum_basis == "founders"` — the
    /// CEG 0.11 trust-root conformance requirement.
    #[must_use]
    pub fn is_founders_basis(&self) -> bool {
        self.admission_quorum_basis == Self::FOUNDERS
    }
}

/// CEG 0.11+ `cohort_subkind: infrastructure` community — the shape
/// the CIRIS canonical services (Registry + Lens + Node) adopt instead
/// of a `family`. See module docs for the worked example.
///
/// `members` is a *set* — the canonical encoding sorts by `member_id`
/// before hashing, so two peers with the same logical membership
/// compute byte-identical canonical bytes regardless of `Vec` order.
/// Members carry `role: Option<Role>` (founder / member); the
/// canonical bytes encode the declared role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfrastructureCommunity {
    /// Canonical-bytes schema version (see
    /// [`INFRASTRUCTURE_COMMUNITY_SCHEMA_VERSION`]).
    pub schema_version: u8,
    /// The federation-level identifier consumers pin. Example:
    /// `"ciris-canonical"` for the umbrella root community.
    pub community_key_id: String,
    /// Human-readable display name. Example: `"CIRIS Canonical Services"`.
    pub community_name: String,
    /// MUST be the literal `"infrastructure"` for trust-root grade.
    pub cohort_subkind: String,
    /// The `infrastructure_constraint` payload.
    pub infrastructure_constraint: InfrastructureConstraint,
    /// Members of the community, each tagged with a `role`. Members
    /// with `role: None` are encoded as legacy/unspecified.
    pub members: Vec<ThresholdMember>,
    /// Symbolic consensus-protocol string per CEG 0.7+. Examples:
    /// `"quorum:2/3"` | `"founder_only"` | `"unanimous"` |
    /// `"majority"` | `"weighted:{rubric}"` | `"custom:{id}"`.
    pub consensus_protocol: String,
    /// `true` iff a `supersedes` cannot weaken `consensus_protocol` or
    /// move `admission_quorum_basis` away from `"founders"`. CEG 0.11
    /// trust-root conformance requires this to be `true`.
    pub consensus_protocol_entrenched: bool,
}

impl InfrastructureCommunity {
    /// The literal expected for `cohort_subkind` in any trust-root
    /// community per CEG 0.11.
    pub const INFRASTRUCTURE: &'static str = "infrastructure";

    /// `true` iff this community meets CEG 0.11 trust-root grade:
    /// `cohort_subkind == "infrastructure"` AND
    /// `infrastructure_constraint.admission_quorum_basis == "founders"`
    /// AND `consensus_protocol_entrenched == true` AND
    /// `consensus_protocol` starts with `"quorum:"`.
    ///
    /// `founder_only` / `unanimous` / bare `majority` are
    /// NON-conformant for trust-root grade per CEG 0.11 — a single
    /// founder must not admit unilaterally; a growable core must not
    /// require all-N.
    #[must_use]
    pub fn is_trust_root_conformant(&self) -> bool {
        self.cohort_subkind == Self::INFRASTRUCTURE
            && self.infrastructure_constraint.is_founders_basis()
            && self.consensus_protocol_entrenched
            && self.consensus_protocol.starts_with("quorum:")
    }

    /// Canonical bytes a rotation (`supersedes`) Contribution signs.
    /// Delegates to [`infrastructure_community_signing_bytes`].
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        infrastructure_community_signing_bytes(self)
    }
}

/// Canonical bytes for an [`InfrastructureCommunity`] (v1 schema).
///
/// Layout:
///
/// ```text
/// INFRASTRUCTURE_COMMUNITY_DOMAIN_SEP
///   · schema_version (u8)
///   · LP(community_key_id)
///   · LP(community_name)
///   · LP(cohort_subkind)
///   · LP(infrastructure_constraint.service_class)
///   · LP(infrastructure_constraint.admission_quorum_basis)
///   · LP(consensus_protocol)
///   · u8(consensus_protocol_entrenched: 0 | 1)
///   · u32 LE (member count)
///   · per member (sorted by member_id ASCII-lex):
///       · LP(member_id)
///       · LP(ed25519_pubkey_base64)
///       · LP(mldsa65_pubkey_base64_or_empty)
///       · u8(role: 0 = unspecified / None, 1 = Founder, 2 = Member)
/// ```
///
/// `LP` is a `u32`-length-prefixed byte string. Deterministic and
/// unambiguous — no field boundary can be moved without changing the
/// bytes.
#[must_use]
pub fn infrastructure_community_signing_bytes(c: &InfrastructureCommunity) -> Vec<u8> {
    fn lp(buf: &mut Vec<u8>, b: &[u8]) {
        buf.extend_from_slice(&(u32::try_from(b.len()).unwrap_or(u32::MAX)).to_le_bytes());
        buf.extend_from_slice(b);
    }

    fn role_byte(r: Option<Role>) -> u8 {
        match r {
            None => 0,
            Some(Role::Founder) => 1,
            Some(Role::Member) => 2,
        }
    }

    let mut sorted: Vec<&ThresholdMember> = c.members.iter().collect();
    sorted.sort_by(|a, b| a.member_id.cmp(&b.member_id));

    let mut buf =
        Vec::with_capacity(INFRASTRUCTURE_COMMUNITY_DOMAIN_SEP.len() + 128 + sorted.len() * 96);
    buf.extend_from_slice(INFRASTRUCTURE_COMMUNITY_DOMAIN_SEP);
    buf.push(c.schema_version);
    lp(&mut buf, c.community_key_id.as_bytes());
    lp(&mut buf, c.community_name.as_bytes());
    lp(&mut buf, c.cohort_subkind.as_bytes());
    lp(
        &mut buf,
        c.infrastructure_constraint.service_class.as_bytes(),
    );
    lp(
        &mut buf,
        c.infrastructure_constraint
            .admission_quorum_basis
            .as_bytes(),
    );
    lp(&mut buf, c.consensus_protocol.as_bytes());
    buf.push(u8::from(c.consensus_protocol_entrenched));
    buf.extend_from_slice(&(u32::try_from(sorted.len()).unwrap_or(u32::MAX)).to_le_bytes());
    for m in sorted {
        lp(&mut buf, m.member_id.as_bytes());
        lp(&mut buf, m.ed25519_public_key_base64.as_bytes());
        let mldsa = m.mldsa65_public_key_base64.as_deref().unwrap_or("");
        lp(&mut buf, mldsa.as_bytes());
        buf.push(role_byte(m.role));
    }
    buf
}

/// Why a `supersedes` rotation was rejected by the entrenchment gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrenchmentViolation {
    /// `consensus_protocol_entrenched` was `true` on the OLD community
    /// but the proposed NEW community's `consensus_protocol` differs.
    /// Entrenchment requires the protocol to be preserved.
    ConsensusProtocolChanged {
        /// The entrenched value.
        old: String,
        /// The proposed value.
        new: String,
    },
    /// `consensus_protocol_entrenched` was `true` on the OLD community
    /// but the proposed NEW community's
    /// `infrastructure_constraint.admission_quorum_basis` differs from
    /// `"founders"`.
    AdmissionQuorumBasisMoved {
        /// The proposed value.
        new: String,
    },
    /// `consensus_protocol_entrenched` was `true` on the OLD community
    /// but the proposed NEW community sets it to `false` — once
    /// entrenched, the entrenchment itself cannot be lifted (otherwise
    /// the door could be lowered in two steps).
    EntrenchmentLifted,
}

impl std::fmt::Display for EntrenchmentViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsensusProtocolChanged { old, new } => write!(
                f,
                "entrenched consensus_protocol {old:?} cannot change to {new:?}"
            ),
            Self::AdmissionQuorumBasisMoved { new } => write!(
                f,
                "entrenched admission_quorum_basis cannot move from \"founders\" to {new:?}"
            ),
            Self::EntrenchmentLifted => write!(
                f,
                "consensus_protocol_entrenched cannot be lowered from true to false"
            ),
        }
    }
}

impl std::error::Error for EntrenchmentViolation {}

/// Verify that a proposed `supersedes` rotation preserves CEG 0.11
/// entrenchment invariants over an old community.
///
/// Returns `Ok(())` if the new community can be admitted (no
/// entrenchment guard violated, OR the old community wasn't
/// entrenched in the first place — in which case the new community
/// MAY freely change consensus_protocol / admission_quorum_basis /
/// entrench-or-not).
///
/// Returns [`EntrenchmentViolation`] otherwise. The substrate emits
/// `hard_case:community_consensus_protocol_violation` per CEG 0.11
/// §7.8 when this rejects.
///
/// This function is purely a consistency check between two community
/// values — it does NOT verify the founder-quorum signatures over the
/// new community's canonical bytes. The caller pairs it with
/// [`crate::threshold::verify_founder_quorum`] for full admission
/// verification.
pub fn verify_supersedes_preserves_entrenchment(
    old: &InfrastructureCommunity,
    new: &InfrastructureCommunity,
) -> Result<(), EntrenchmentViolation> {
    if !old.consensus_protocol_entrenched {
        return Ok(());
    }
    if !new.consensus_protocol_entrenched {
        return Err(EntrenchmentViolation::EntrenchmentLifted);
    }
    if old.consensus_protocol != new.consensus_protocol {
        return Err(EntrenchmentViolation::ConsensusProtocolChanged {
            old: old.consensus_protocol.clone(),
            new: new.consensus_protocol.clone(),
        });
    }
    if new.infrastructure_constraint.admission_quorum_basis != InfrastructureConstraint::FOUNDERS {
        return Err(EntrenchmentViolation::AdmissionQuorumBasisMoved {
            new: new.infrastructure_constraint.admission_quorum_basis.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str, role: Option<Role>) -> ThresholdMember {
        ThresholdMember {
            member_id: id.to_string(),
            ed25519_public_key_base64: format!("ed-{id}"),
            mldsa65_public_key_base64: Some(format!("mldsa-{id}")),
            role,
        }
    }

    fn ciris_canonical_example() -> InfrastructureCommunity {
        InfrastructureCommunity {
            schema_version: INFRASTRUCTURE_COMMUNITY_SCHEMA_VERSION,
            community_key_id: "ciris-canonical".to_string(),
            community_name: "CIRIS Canonical Services".to_string(),
            cohort_subkind: "infrastructure".to_string(),
            infrastructure_constraint: InfrastructureConstraint {
                service_class: "canonical".to_string(),
                admission_quorum_basis: "founders".to_string(),
            },
            members: vec![
                member("registry-steward-us", Some(Role::Founder)),
                member("registry-steward-eu", Some(Role::Founder)),
                member("registry-steward-apac", Some(Role::Founder)),
            ],
            consensus_protocol: "quorum:2/3".to_string(),
            consensus_protocol_entrenched: true,
        }
    }

    #[test]
    fn signing_bytes_begin_with_domain_sep() {
        let c = ciris_canonical_example();
        let b = c.signing_bytes();
        assert!(b.starts_with(INFRASTRUCTURE_COMMUNITY_DOMAIN_SEP));
    }

    #[test]
    fn signing_bytes_distinct_from_federation_keyset_domain() {
        use crate::federation_keyset::FEDERATION_KEYSET_DOMAIN_SEP;
        assert_ne!(
            INFRASTRUCTURE_COMMUNITY_DOMAIN_SEP, FEDERATION_KEYSET_DOMAIN_SEP,
            "schemas must use distinct domain-sep tags so a peer cannot \
             interpret one blob as the other"
        );
    }

    #[test]
    fn signing_bytes_deterministic() {
        let c = ciris_canonical_example();
        assert_eq!(c.signing_bytes(), c.signing_bytes());
    }

    #[test]
    fn members_canonicalize_via_member_id_sort() {
        let abc = ciris_canonical_example();
        let mut cba = abc.clone();
        cba.members.reverse();
        assert_eq!(
            abc.signing_bytes(),
            cba.signing_bytes(),
            "set-shaped members must canonicalize regardless of Vec order"
        );
    }

    #[test]
    fn signing_bytes_sensitive_to_role_change() {
        let founder_only = ciris_canonical_example();
        let mut mixed = founder_only.clone();
        // Demote apac to non-founder.
        mixed.members[2].role = Some(Role::Member);
        assert_ne!(
            founder_only.signing_bytes(),
            mixed.signing_bytes(),
            "role is load-bearing — the canonical bytes must distinguish \
             founder from member"
        );
    }

    #[test]
    fn signing_bytes_sensitive_to_entrenchment_flag() {
        let entrenched = ciris_canonical_example();
        let mut not_entrenched = entrenched.clone();
        not_entrenched.consensus_protocol_entrenched = false;
        assert_ne!(entrenched.signing_bytes(), not_entrenched.signing_bytes());
    }

    #[test]
    fn signing_bytes_sensitive_to_consensus_protocol() {
        let two_of_three = ciris_canonical_example();
        let mut three_of_five = two_of_three.clone();
        three_of_five.consensus_protocol = "quorum:3/5".to_string();
        assert_ne!(two_of_three.signing_bytes(), three_of_five.signing_bytes());
    }

    #[test]
    fn is_trust_root_conformant_accepts_ciris_canonical_example() {
        assert!(
            ciris_canonical_example().is_trust_root_conformant(),
            "CEG 0.15 §5.6.8.10 worked example must conform"
        );
    }

    #[test]
    fn is_trust_root_conformant_rejects_founder_only_protocol() {
        let mut c = ciris_canonical_example();
        c.consensus_protocol = "founder_only".to_string();
        assert!(!c.is_trust_root_conformant());
    }

    #[test]
    fn is_trust_root_conformant_rejects_unentrenched_protocol() {
        let mut c = ciris_canonical_example();
        c.consensus_protocol_entrenched = false;
        assert!(!c.is_trust_root_conformant());
    }

    #[test]
    fn is_trust_root_conformant_rejects_non_founders_basis() {
        let mut c = ciris_canonical_example();
        c.infrastructure_constraint.admission_quorum_basis = "current_members".to_string();
        assert!(!c.is_trust_root_conformant());
    }

    // =========================================================================
    // Entrenchment gate (verify_supersedes_preserves_entrenchment)
    // =========================================================================

    #[test]
    fn entrenchment_admits_no_op_supersedes() {
        let old = ciris_canonical_example();
        let new = old.clone();
        assert_eq!(verify_supersedes_preserves_entrenchment(&old, &new), Ok(()));
    }

    #[test]
    fn entrenchment_admits_membership_growth() {
        // Adding a new non-founder member preserves entrenchment.
        let old = ciris_canonical_example();
        let mut new = old.clone();
        new.members
            .push(member("lens-install-us", Some(Role::Member)));
        assert_eq!(verify_supersedes_preserves_entrenchment(&old, &new), Ok(()));
    }

    #[test]
    fn entrenchment_rejects_consensus_protocol_weakening() {
        // quorum:2/3 → majority (weakening) MUST be rejected when
        // entrenched.
        let old = ciris_canonical_example();
        let mut new = old.clone();
        new.consensus_protocol = "majority".to_string();
        assert_eq!(
            verify_supersedes_preserves_entrenchment(&old, &new),
            Err(EntrenchmentViolation::ConsensusProtocolChanged {
                old: "quorum:2/3".to_string(),
                new: "majority".to_string(),
            })
        );
    }

    #[test]
    fn entrenchment_rejects_consensus_protocol_strengthening_too() {
        // CEG 0.11: entrenched consensus_protocol is FROZEN. Even
        // strengthening (quorum:2/3 → quorum:3/3 unanimous) requires
        // dropping entrenchment first, which is itself rejected.
        let old = ciris_canonical_example();
        let mut new = old.clone();
        new.consensus_protocol = "unanimous".to_string();
        assert!(verify_supersedes_preserves_entrenchment(&old, &new).is_err());
    }

    #[test]
    fn entrenchment_rejects_admission_basis_move() {
        let old = ciris_canonical_example();
        let mut new = old.clone();
        new.infrastructure_constraint.admission_quorum_basis = "current_members".to_string();
        assert_eq!(
            verify_supersedes_preserves_entrenchment(&old, &new),
            Err(EntrenchmentViolation::AdmissionQuorumBasisMoved {
                new: "current_members".to_string(),
            })
        );
    }

    #[test]
    fn entrenchment_rejects_lowering_entrenchment_itself() {
        // Once entrenched=true, a supersedes that sets entrenched=false
        // is rejected. Otherwise the door could be lowered in two
        // steps: drop entrenchment, then weaken protocol.
        let old = ciris_canonical_example();
        let mut new = old.clone();
        new.consensus_protocol_entrenched = false;
        assert_eq!(
            verify_supersedes_preserves_entrenchment(&old, &new),
            Err(EntrenchmentViolation::EntrenchmentLifted)
        );
    }

    #[test]
    fn entrenchment_allows_changes_when_old_was_not_entrenched() {
        // If the OLD community wasn't entrenched, the new one can do
        // whatever it wants — including becoming entrenched itself.
        let mut old = ciris_canonical_example();
        old.consensus_protocol_entrenched = false;
        let mut new = old.clone();
        new.consensus_protocol = "quorum:3/5".to_string();
        new.consensus_protocol_entrenched = true;
        assert_eq!(verify_supersedes_preserves_entrenchment(&old, &new), Ok(()));
    }
}
