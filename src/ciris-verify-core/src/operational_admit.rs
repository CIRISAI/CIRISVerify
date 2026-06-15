//! Operational-data admission verification (CEG 1.0-RC2 §5.6.8.13).
//!
//! The three operational subject_kinds — `organization`,
//! `org_membership`, `partner_record` — federate as signed CEG
//! envelopes (CIRISRegistry#70, the §1.4 sixteenth path). Their
//! *signature verification* at admission is **Verify's**, never the
//! storage substrate's: RC2 §5.6.8.13 pins the two-quorums split —
//! "the substrate's merge logic never counts steward signatures." This
//! module is the callable surface CIRISPersist (CIRISVerify#65) invokes
//! at `put_organization` / `put_org_membership` / `put_partner_record`
//! so nobody builds a third bespoke admission path (§5.6.8.13 forbids
//! it).
//!
//! Two admission shapes, two verification primitives — both already
//! shipped, this module just gives them the operational-data contract:
//!
//! - **`organization` / `org_membership` → single-signer, role-gated**
//!   ([`resolve_role_authority`], the §8.1.12.7.1 `delegates_to`
//!   role-chain resolver). Admitted iff the actor key holds the
//!   required [`OrgRole`] in the org, established by a prior
//!   non-superseded `org_membership` grant, transitively rooted at org
//!   creation by a recognized steward/system key. Explicitly **NOT**
//!   founder-quorum.
//! - **`partner_record` → M-of-N steward quorum**
//!   ([`verify_partner_record_quorum`], reusing
//!   [`crate::threshold::verify_founder_quorum`], CIRISVerify#31). The
//!   signature *set* over byte-identical JCS bytes is admitted iff ≥ M
//!   of N recognized stewards each signed.
//!
//! ## Partition-tolerant by construction — Verify is a pure evaluator
//!
//! Per RC2 §5.6.8.13(A), `supersedes` is **audit lineage only**;
//! resolution MUST NOT require chain completeness. The caller
//! (persist) resolves *current state* — the stable-`org_id`-grouped
//! latest non-superseded/non-withdrawn rows — and hands that set in.
//! This module performs **no I/O**: no directory fetch, no network, no
//! storage read. Every input it trusts (the membership set, the
//! `key_directory` of pinned pubkeys, the `root_stewards` anchor set)
//! is supplied by the caller. That keeps admission decisions
//! deterministic and replayable, and means a network partition can
//! never silently widen authority.
//!
//! ## Identity binding is the load-bearing check
//!
//! A [`HybridSignature`](ciris_crypto::HybridSignature) carries the
//! signer's public keys *inside it*, so a bare hybrid-verify only
//! proves "whoever holds the private key for *these* embedded pubkeys
//! signed it" — not that those pubkeys belong to the claimed
//! `attesting_key_id`. This module therefore verifies every grant
//! signature against the pubkeys **pinned in `key_directory` for that
//! `attesting_key_id`** (reusing [`crate::threshold`]'s bound-signature
//! discipline at threshold 1), never against pubkeys carried by the
//! grant itself. A forged grant that embeds an attacker keypair under a
//! steward's `key_id` fails this binding.
//!
//! ## Fail-secure / fail-closed
//!
//! [`resolve_role_authority`] returns `authorized: false` on *any*
//! ambiguity — a malformed envelope, a missing directory key, an
//! unrooted or cyclic authority chain, a status that isn't `active`.
//! Persist admits MUST treat the absence of a positive verdict as
//! rejection (never fail-open). This is the same opaque-failure
//! discipline used across CIRISVerify.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::VerifyError;
use crate::jcs;
use crate::threshold::{
    verify_founder_quorum, verify_threshold_signatures, ThresholdMember, ThresholdSignature,
};

/// An organizational role (CEG 1.0-RC2 §5.6.8.13 `org_membership.role`).
///
/// `OrgAdmin` is the org superuser — it satisfies any required role and
/// is the only role (besides a root steward) that may *grant* roles.
/// The other three are operational and, under the conservative policy
/// this module ships, satisfy only an exactly-matching requirement.
///
/// **Policy note (flagged for CEG confirmation on CIRISVerify#65):**
/// RC2 §5.6.8.13 enumerates the four roles but does not pin a fuller
/// lattice (e.g. whether `KeyManager` implies `Viewer`). This module
/// implements the strict, minimal-authority reading —
/// `granted.satisfies(required)` is true iff `granted == OrgAdmin` or
/// `granted == required`. If CEG intends a richer ordering it is a
/// one-line change in [`OrgRole::satisfies`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    /// Organization administrator — superuser; may grant roles.
    OrgAdmin,
    /// Manages keys for the org (key registration / rotation).
    KeyManager,
    /// Operates the org's agents/services.
    Operator,
    /// Read-only visibility into org state.
    Viewer,
}

impl OrgRole {
    /// Does a key *holding* `self` satisfy an operation *requiring*
    /// `required`? `OrgAdmin` satisfies everything; every other role
    /// satisfies only itself. See the type-level policy note.
    #[must_use]
    pub fn satisfies(self, required: OrgRole) -> bool {
        self == OrgRole::OrgAdmin || self == required
    }

    /// May a key holding `self` *grant* org roles? Only `OrgAdmin`
    /// (root stewards are handled separately, as the chain anchor).
    #[must_use]
    pub fn may_grant(self) -> bool {
        self == OrgRole::OrgAdmin
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "org_admin" => Some(Self::OrgAdmin),
            "key_manager" => Some(Self::KeyManager),
            "operator" => Some(Self::Operator),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }
}

/// A current (caller-resolved) `org_membership` grant.
///
/// Carries the **signed envelope** (the object whose JCS canonical
/// bytes the granter signed) plus the bound hybrid-signature halves.
/// The authoritative fields — grantee `user_id`, `org_id`, `role`,
/// `status`, granter `attesting_key_id` — are read *from the signed
/// envelope*, never from out-of-band struct fields, so a tampered
/// claim can't disagree with the signed bytes. The granter's public
/// keys are NOT trusted from here; they are resolved from the
/// caller-supplied `key_directory` keyed by `attesting_key_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipGrant {
    /// The signed `org_membership` envelope. MUST contain string
    /// members `user_id`, `org_id`, `role`, `status`, and
    /// `attesting_key_id`. Canonicalized with [`jcs::canonicalize`] to
    /// recover the exact bytes that were signed.
    pub signed_envelope: Value,
    /// Ed25519 signature over `JCS(signed_envelope)`, base64 standard.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 signature over `JCS(signed_envelope) ‖ ed25519_sig`
    /// (bound), base64 standard. `None` for a hybrid-pending granter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_signature_base64: Option<String>,
}

/// The authoritative members parsed out of a grant's signed envelope.
struct ParsedGrant {
    user_id: String,
    org_id: String,
    role: OrgRole,
    active: bool,
    attesting_key_id: String,
}

impl MembershipGrant {
    /// Parse the signed truth out of the envelope. Returns `None` if
    /// any required member is missing/malformed — such a grant is
    /// silently skipped (fail-secure), never trusted.
    fn parse(&self) -> Option<ParsedGrant> {
        let obj = self.signed_envelope.as_object()?;
        let get = |k: &str| obj.get(k)?.as_str();
        let role = OrgRole::from_wire(get("role")?)?;
        // Only `active` grants confer authority. A `suspended` /
        // `withdrawn` / unknown status confers nothing.
        let active = get("status")? == "active";
        Some(ParsedGrant {
            user_id: get("user_id")?.to_string(),
            org_id: get("org_id")?.to_string(),
            role,
            active,
            attesting_key_id: get("attesting_key_id")?.to_string(),
        })
    }

    /// Verify this grant's bound hybrid signature against the granter's
    /// pinned pubkeys in `directory`. Reuses the threshold primitive at
    /// threshold 1 so the exact same bound-signature rule (Ed25519 over
    /// bytes; ML-DSA-65 over `bytes ‖ ed25519_sig`) applies. Returns
    /// `false` on any failure — unknown granter, base64 malformation,
    /// canonicalization error, or signature mismatch.
    fn signature_valid(&self, attesting_key_id: &str, directory: &[ThresholdMember]) -> bool {
        let Ok(bytes) = jcs::canonicalize(&self.signed_envelope) else {
            return false;
        };
        let Some(granter) = directory.iter().find(|m| m.member_id == attesting_key_id) else {
            return false;
        };
        let sig = ThresholdSignature {
            member_id: attesting_key_id.to_string(),
            ed25519_signature_base64: self.ed25519_signature_base64.clone(),
            mldsa65_signature_base64: self.mldsa65_signature_base64.clone(),
        };
        verify_threshold_signatures(&bytes, std::slice::from_ref(granter), &[sig], 1).is_ok()
    }
}

/// Why an authority resolution succeeded or failed. Coarse by design —
/// enough for persist's audit/precedence, not so granular it aids
/// forgery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationReason {
    /// The actor holds the required role via a signature-valid,
    /// root-anchored grant.
    Authorized,
    /// No current grant gives the actor a role satisfying the
    /// requirement.
    NoQualifyingGrant,
    /// A candidate grant existed but its authority chain did not
    /// resolve to a recognized steward root (bad signature somewhere,
    /// granter not authorized, cycle, or unrooted).
    ChainNotAnchored,
}

/// The verdict of [`resolve_role_authority`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAuthorization {
    /// Whether the actor is authorized for the operation. The only
    /// field an admit gate strictly needs; everything else is audit.
    pub authorized: bool,
    /// `attesting_key_id` of the grant that *directly* established the
    /// actor's qualifying role (audit / precedence). `None` when
    /// unauthorized.
    pub established_by: Option<String>,
    /// Whether the authority chain terminated at a recognized steward
    /// root. Always equals `authorized` for a positive verdict; surfaced
    /// explicitly so consumers don't infer it.
    pub root_anchored: bool,
    /// Coarse diagnostic reason.
    pub reason: AuthorizationReason,
}

impl RoleAuthorization {
    fn denied(reason: AuthorizationReason) -> Self {
        Self {
            authorized: false,
            established_by: None,
            root_anchored: false,
            reason,
        }
    }
}

/// Resolve whether `actor_key_id` holds `required_role` in `org_id`
/// (CEG 1.0-RC2 §5.6.8.13, the §8.1.12.7.1 `delegates_to` role-chain
/// resolver). This is the callable persist invokes to gate
/// `organization` / `org_membership` admits.
///
/// # Inputs
/// - `actor_key_id` — the key that signed the operation persist is
///   admitting (the operation envelope's own `attesting_key_id`).
/// - `org_id` — the target org.
/// - `required_role` — the minimum role the operation requires.
/// - `current_memberships` — persist-resolved current state: the
///   latest non-superseded/non-withdrawn `org_membership` grants for
///   this org. Resolution walks authority *within* this set only.
/// - `key_directory` — pinned hybrid pubkeys per `key_id` (from
///   `federation_keys`), used to bind each grant's signature to its
///   claimed granter. Reuses [`ThresholdMember`].
/// - `root_stewards` — `key_id`s recognized as org-creation root
///   authority (the steward/system anchor). A chain is anchored iff it
///   reaches one of these.
///
/// # Semantics
/// The actor is authorized iff some current `active` grant names the
/// actor (`user_id == actor_key_id`) with a role satisfying
/// `required_role`, that grant's signature binds to its granter's
/// pinned pubkeys, and the granter is *either* a `root_steward` *or*
/// itself transitively holds `OrgAdmin` via the same rules — a bounded,
/// cycle-detected walk over `current_memberships`. `supersedes` is
/// never consulted (audit-only); only the supplied current set matters.
///
/// Never panics; fail-closed on every ambiguity.
#[must_use]
pub fn resolve_role_authority(
    actor_key_id: &str,
    org_id: &str,
    required_role: OrgRole,
    current_memberships: &[MembershipGrant],
    key_directory: &[ThresholdMember],
    root_stewards: &[String],
) -> RoleAuthorization {
    // Pre-parse every grant once; drop any that don't parse cleanly.
    let parsed: Vec<(ParsedGrant, &MembershipGrant)> = current_memberships
        .iter()
        .filter_map(|g| g.parse().map(|p| (p, g)))
        .collect();

    // Candidate direct grants: name the actor, right org, active,
    // role satisfies the requirement.
    let mut saw_candidate = false;
    for (p, grant) in &parsed {
        if p.user_id != actor_key_id || p.org_id != org_id || !p.active {
            continue;
        }
        if !p.role.satisfies(required_role) {
            continue;
        }
        saw_candidate = true;
        let mut visited: Vec<String> = Vec::new();
        if grant_is_anchored(
            p,
            grant,
            org_id,
            &parsed,
            key_directory,
            root_stewards,
            &mut visited,
        ) {
            return RoleAuthorization {
                authorized: true,
                established_by: Some(p.attesting_key_id.clone()),
                root_anchored: true,
                reason: AuthorizationReason::Authorized,
            };
        }
    }

    RoleAuthorization::denied(if saw_candidate {
        AuthorizationReason::ChainNotAnchored
    } else {
        AuthorizationReason::NoQualifyingGrant
    })
}

/// Is `grant` (whose parsed form is `p`) signature-valid AND is its
/// granter authorized to have issued it (root steward, or transitively
/// an `OrgAdmin` in the org)? Bounded, cycle-detected walk.
fn grant_is_anchored(
    p: &ParsedGrant,
    grant: &MembershipGrant,
    org_id: &str,
    parsed: &[(ParsedGrant, &MembershipGrant)],
    key_directory: &[ThresholdMember],
    root_stewards: &[String],
    visited: &mut Vec<String>,
) -> bool {
    // The grant must actually be signed by its claimed granter.
    if !grant.signature_valid(&p.attesting_key_id, key_directory) {
        return false;
    }
    // Anchor: granter is a recognized steward/system root.
    if root_stewards.iter().any(|s| s == &p.attesting_key_id) {
        return true;
    }
    // Cycle guard: never revisit a granter on this path.
    if visited.iter().any(|v| v == &p.attesting_key_id) {
        return false;
    }
    visited.push(p.attesting_key_id.clone());

    // The granter must itself hold OrgAdmin in this org, via a current
    // active grant that is *itself* anchored.
    for (gp, ggrant) in parsed {
        if gp.user_id != p.attesting_key_id
            || gp.org_id != org_id
            || !gp.active
            || !gp.role.may_grant()
        {
            continue;
        }
        if grant_is_anchored(
            gp,
            ggrant,
            org_id,
            parsed,
            key_directory,
            root_stewards,
            visited,
        ) {
            return true;
        }
    }
    false
}

/// Verify the M-of-N steward quorum over a `partner_record` envelope
/// (CEG 1.0-RC2 §5.6.8.13 / §5.6.8.10; CIRISVerify#31). This is the
/// callable persist invokes to gate `put_partner_record` admits.
///
/// Canonicalizes `partner_record` with [`jcs::canonicalize`] and
/// delegates to [`verify_founder_quorum`]: the signature *set* is
/// admitted iff ≥ `threshold` distinct stewards in `steward_roster`
/// (those with `role: Founder`) each produced a valid bound hybrid
/// signature over the identical canonical bytes.
///
/// **Determinism precondition (§0.9.2.1 rule 1):** all M stewards must
/// sign byte-identical JCS bytes, so set-semantics arrays
/// (`capabilities_granted` / `capabilities_denied` /
/// `geographic_restrictions` / `allowed_identity_templates`) MUST
/// already be lexicographically sorted *in `partner_record`* before
/// this call — JCS preserves array order and does NOT sort. A
/// mis-ordered array makes otherwise-agreeing stewards sign different
/// bytes and the quorum silently collapses. Use
/// [`check_set_semantics_sorted`] to catch that loudly at the producer.
///
/// Returns `Ok(count)` with the number of distinct valid steward
/// signatures on success, or a [`VerifyError`] on canonicalization
/// failure or insufficient quorum.
pub fn verify_partner_record_quorum(
    partner_record: &Value,
    steward_roster: &[ThresholdMember],
    signatures: &[ThresholdSignature],
    threshold: usize,
) -> Result<usize, VerifyError> {
    let bytes = jcs::canonicalize(partner_record)?;
    verify_founder_quorum(&bytes, steward_roster, signatures, threshold).map_err(|e| {
        VerifyError::IntegrityError {
            message: format!("partner_record steward quorum not met: {e}"),
        }
    })
}

/// Producer-side guard: confirm the named members of `value` are arrays
/// whose string elements are in non-decreasing lexicographic order
/// (set-semantics, §0.9.2.1 rule 1). Returns the first offending field
/// as an error so a mis-ordered multi-signer `partner_record` is caught
/// *before* M stewards sign divergent bytes — far better than a silent
/// quorum collapse at admission.
///
/// A named field that is absent or not an array is skipped (the §0.9.2
/// omit-vs-materialize discipline: this never injects or reorders, it
/// only inspects). Non-string array elements are likewise skipped.
pub fn check_set_semantics_sorted(value: &Value, fields: &[&str]) -> Result<(), VerifyError> {
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    for field in fields {
        let Some(arr) = obj.get(*field).and_then(Value::as_array) else {
            continue;
        };
        let strs: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
        if strs.len() != arr.len() {
            continue; // not a pure string array; not ours to judge
        }
        if strs.windows(2).any(|w| w[0] > w[1]) {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "set-semantics array `{field}` is not lexicographically sorted \
                     (§0.9.2.1 rule 1) — multi-signer JCS bytes would diverge"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
    use serde_json::json;

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    /// A signing identity: a key_id plus its hybrid keypair.
    struct Identity {
        key_id: String,
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Identity {
        fn new(id: &str) -> Self {
            Self {
                key_id: id.to_string(),
                ed: Ed25519Signer::random().unwrap(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }

        fn member(&self) -> ThresholdMember {
            ThresholdMember {
                member_id: self.key_id.clone(),
                ed25519_public_key_base64: b64().encode(self.ed.public_key().unwrap()),
                mldsa65_public_key_base64: Some(b64().encode(self.mldsa.public_key().unwrap())),
                role: None,
            }
        }

        fn founder_member(&self) -> ThresholdMember {
            let mut m = self.member();
            m.role = Some(crate::threshold::Role::Founder);
            m
        }

        /// Hybrid-sign `bytes`, returning (ed_sig_b64, mldsa_sig_b64).
        fn sign_bytes(&self, bytes: &[u8]) -> (String, String) {
            let ed_sig = self.ed.sign(bytes).unwrap();
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = self.mldsa.sign(&bound).unwrap();
            (b64().encode(&ed_sig), b64().encode(&pqc_sig))
        }

        fn threshold_sig(&self, bytes: &[u8]) -> ThresholdSignature {
            let (ed, mldsa) = self.sign_bytes(bytes);
            ThresholdSignature {
                member_id: self.key_id.clone(),
                ed25519_signature_base64: ed,
                mldsa65_signature_base64: Some(mldsa),
            }
        }
    }

    /// Build a signed `org_membership` grant: `granter` asserts that
    /// `subject` holds `role` in `org`, with `status`.
    fn grant(
        granter: &Identity,
        subject: &str,
        org: &str,
        role: &str,
        status: &str,
    ) -> MembershipGrant {
        let envelope = json!({
            "user_id": subject,
            "org_id": org,
            "role": role,
            "status": status,
            "attesting_key_id": granter.key_id,
        });
        let bytes = jcs::canonicalize(&envelope).unwrap();
        let (ed, mldsa) = granter.sign_bytes(&bytes);
        MembershipGrant {
            signed_envelope: envelope,
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: Some(mldsa),
        }
    }

    // ---- role lattice ----------------------------------------------

    #[test]
    fn org_admin_satisfies_everything() {
        for r in [
            OrgRole::OrgAdmin,
            OrgRole::KeyManager,
            OrgRole::Operator,
            OrgRole::Viewer,
        ] {
            assert!(OrgRole::OrgAdmin.satisfies(r));
        }
    }

    #[test]
    fn non_admin_satisfies_only_itself() {
        assert!(OrgRole::Operator.satisfies(OrgRole::Operator));
        assert!(!OrgRole::Operator.satisfies(OrgRole::KeyManager));
        assert!(!OrgRole::Viewer.satisfies(OrgRole::Operator));
        assert!(!OrgRole::KeyManager.satisfies(OrgRole::OrgAdmin));
    }

    // ---- direct grant rooted at a steward --------------------------

    #[test]
    fn direct_grant_from_steward_root_authorizes() {
        let steward = Identity::new("steward-1");
        let admin = Identity::new("admin-1");
        // steward (root) grants OrgAdmin to admin.
        let g = grant(&steward, "admin-1", "org-x", "org_admin", "active");
        let dir = vec![steward.member(), admin.member()];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority("admin-1", "org-x", OrgRole::OrgAdmin, &[g], &dir, &roots);
        assert!(v.authorized);
        assert!(v.root_anchored);
        assert_eq!(v.established_by.as_deref(), Some("steward-1"));
        assert_eq!(v.reason, AuthorizationReason::Authorized);
    }

    // ---- delegated 2-hop chain -------------------------------------

    #[test]
    fn delegated_chain_admin_grants_operator() {
        let steward = Identity::new("steward-1");
        let admin = Identity::new("admin-1");
        let op = Identity::new("op-1");

        // steward -> admin (OrgAdmin); admin -> op (Operator)
        let g_admin = grant(&steward, "admin-1", "org-x", "org_admin", "active");
        let g_op = grant(&admin, "op-1", "org-x", "operator", "active");
        let dir = vec![steward.member(), admin.member(), op.member()];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority(
            "op-1",
            "org-x",
            OrgRole::Operator,
            &[g_admin, g_op],
            &dir,
            &roots,
        );
        assert!(v.authorized);
        assert_eq!(v.established_by.as_deref(), Some("admin-1"));
    }

    // ---- a non-admin granter cannot confer authority ---------------

    #[test]
    fn operator_cannot_grant() {
        let steward = Identity::new("steward-1");
        let admin = Identity::new("admin-1");
        let op = Identity::new("op-1");
        let victim = Identity::new("victim-1");

        let g_admin = grant(&steward, "admin-1", "org-x", "org_admin", "active");
        let g_op = grant(&admin, "op-1", "org-x", "operator", "active");
        // op (only an Operator) tries to grant Operator to victim.
        let g_bad = grant(&op, "victim-1", "org-x", "operator", "active");
        let dir = vec![
            steward.member(),
            admin.member(),
            op.member(),
            victim.member(),
        ];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority(
            "victim-1",
            "org-x",
            OrgRole::Operator,
            &[g_admin, g_op, g_bad],
            &dir,
            &roots,
        );
        assert!(!v.authorized);
        assert_eq!(v.reason, AuthorizationReason::ChainNotAnchored);
    }

    // ---- no qualifying grant ---------------------------------------

    #[test]
    fn no_grant_for_actor_is_unauthorized() {
        let steward = Identity::new("steward-1");
        let admin = Identity::new("admin-1");
        let g = grant(&steward, "admin-1", "org-x", "org_admin", "active");
        let dir = vec![steward.member(), admin.member()];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority("stranger", "org-x", OrgRole::Viewer, &[g], &dir, &roots);
        assert!(!v.authorized);
        assert_eq!(v.reason, AuthorizationReason::NoQualifyingGrant);
    }

    // ---- insufficient role -----------------------------------------

    #[test]
    fn viewer_cannot_satisfy_operator_requirement() {
        let steward = Identity::new("steward-1");
        let admin = Identity::new("admin-1");
        let viewer = Identity::new("viewer-1");
        let g_admin = grant(&steward, "admin-1", "org-x", "org_admin", "active");
        let g_view = grant(&admin, "viewer-1", "org-x", "viewer", "active");
        let dir = vec![steward.member(), admin.member(), viewer.member()];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority(
            "viewer-1",
            "org-x",
            OrgRole::Operator,
            &[g_admin, g_view],
            &dir,
            &roots,
        );
        assert!(!v.authorized);
        assert_eq!(v.reason, AuthorizationReason::NoQualifyingGrant);
    }

    // ---- forged signature (wrong directory key) --------------------

    #[test]
    fn forged_grant_with_attacker_key_fails_binding() {
        let steward = Identity::new("steward-1");
        let attacker = Identity::new("attacker");
        let admin = Identity::new("admin-1");

        // attacker forges a grant CLAIMING to be from steward-1, but
        // signs with their own key.
        let envelope = json!({
            "user_id": "admin-1",
            "org_id": "org-x",
            "role": "org_admin",
            "status": "active",
            "attesting_key_id": "steward-1",
        });
        let bytes = jcs::canonicalize(&envelope).unwrap();
        let (ed, mldsa) = attacker.sign_bytes(&bytes);
        let forged = MembershipGrant {
            signed_envelope: envelope,
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: Some(mldsa),
        };
        // directory pins steward-1 to the REAL steward pubkeys.
        let dir = vec![steward.member(), admin.member()];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority(
            "admin-1",
            "org-x",
            OrgRole::OrgAdmin,
            &[forged],
            &dir,
            &roots,
        );
        assert!(!v.authorized, "forged signature must not bind to steward-1");
        assert_eq!(v.reason, AuthorizationReason::ChainNotAnchored);
    }

    // ---- unrooted chain --------------------------------------------

    #[test]
    fn chain_not_reaching_a_steward_is_unauthorized() {
        let admin = Identity::new("admin-1");
        let op = Identity::new("op-1");
        // admin grants op Operator, but admin's own OrgAdmin grant is
        // absent and admin is not a steward root.
        let g_op = grant(&admin, "op-1", "org-x", "operator", "active");
        let dir = vec![admin.member(), op.member()];
        let roots = vec!["some-other-steward".to_string()];

        let v = resolve_role_authority("op-1", "org-x", OrgRole::Operator, &[g_op], &dir, &roots);
        assert!(!v.authorized);
        assert_eq!(v.reason, AuthorizationReason::ChainNotAnchored);
    }

    // ---- cycle does not loop forever or authorize ------------------

    #[test]
    fn mutual_grants_cycle_is_rejected() {
        let a = Identity::new("a");
        let b = Identity::new("b");
        // a grants b OrgAdmin; b grants a OrgAdmin. No steward root.
        let g_ab = grant(&a, "b", "org-x", "org_admin", "active");
        let g_ba = grant(&b, "a", "org-x", "org_admin", "active");
        let dir = vec![a.member(), b.member()];
        let roots = vec!["steward-1".to_string()];

        let v =
            resolve_role_authority("a", "org-x", OrgRole::OrgAdmin, &[g_ab, g_ba], &dir, &roots);
        assert!(!v.authorized, "a cycle must not bootstrap authority");
    }

    // ---- withdrawn / suspended status confers nothing --------------

    #[test]
    fn withdrawn_grant_confers_no_authority() {
        let steward = Identity::new("steward-1");
        let admin = Identity::new("admin-1");
        let g = grant(&steward, "admin-1", "org-x", "org_admin", "withdrawn");
        let dir = vec![steward.member(), admin.member()];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority("admin-1", "org-x", OrgRole::OrgAdmin, &[g], &dir, &roots);
        assert!(!v.authorized);
        assert_eq!(v.reason, AuthorizationReason::NoQualifyingGrant);
    }

    #[test]
    fn wrong_org_is_unauthorized() {
        let steward = Identity::new("steward-1");
        let admin = Identity::new("admin-1");
        let g = grant(&steward, "admin-1", "org-x", "org_admin", "active");
        let dir = vec![steward.member(), admin.member()];
        let roots = vec!["steward-1".to_string()];

        let v = resolve_role_authority(
            "admin-1",
            "org-y", // different org
            OrgRole::OrgAdmin,
            &[g],
            &dir,
            &roots,
        );
        assert!(!v.authorized);
    }

    // ---- partner_record quorum -------------------------------------

    fn partner_record_sorted() -> Value {
        json!({
            "license_id": "lic-1",
            "license_type": "professional",
            "capabilities_granted": ["billing.read", "billing.write", "identity.read"],
            "capabilities_denied": ["admin.super"],
            "status": "active",
            "revision": 1,
        })
    }

    #[test]
    fn partner_record_quorum_2_of_3_passes() {
        let s1 = Identity::new("s1");
        let s2 = Identity::new("s2");
        let s3 = Identity::new("s3");
        let roster = vec![
            s1.founder_member(),
            s2.founder_member(),
            s3.founder_member(),
        ];
        let pr = partner_record_sorted();
        let bytes = jcs::canonicalize(&pr).unwrap();
        // two of three stewards sign the identical canonical bytes
        let sigs = vec![s1.threshold_sig(&bytes), s2.threshold_sig(&bytes)];

        let count = verify_partner_record_quorum(&pr, &roster, &sigs, 2).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn partner_record_quorum_insufficient_fails() {
        let s1 = Identity::new("s1");
        let s2 = Identity::new("s2");
        let s3 = Identity::new("s3");
        let roster = vec![
            s1.founder_member(),
            s2.founder_member(),
            s3.founder_member(),
        ];
        let pr = partner_record_sorted();
        let bytes = jcs::canonicalize(&pr).unwrap();
        let sigs = vec![s1.threshold_sig(&bytes)]; // only one

        assert!(verify_partner_record_quorum(&pr, &roster, &sigs, 2).is_err());
    }

    #[test]
    fn partner_record_non_founder_signatures_do_not_count() {
        let s1 = Identity::new("s1");
        let s2 = Identity::new("s2");
        let outsider = Identity::new("outsider");
        // outsider is in the roster as a plain Member, not a Founder.
        let roster = vec![s1.founder_member(), s2.founder_member(), outsider.member()];
        let pr = partner_record_sorted();
        let bytes = jcs::canonicalize(&pr).unwrap();
        // s1 (founder) + outsider (member): only 1 founder signs.
        let sigs = vec![s1.threshold_sig(&bytes), outsider.threshold_sig(&bytes)];

        assert!(verify_partner_record_quorum(&pr, &roster, &sigs, 2).is_err());
    }

    // ---- set-semantics sorted guard --------------------------------

    #[test]
    fn sorted_arrays_pass_the_guard() {
        let pr = partner_record_sorted();
        assert!(
            check_set_semantics_sorted(&pr, &["capabilities_granted", "capabilities_denied"])
                .is_ok()
        );
    }

    #[test]
    fn unsorted_array_is_caught() {
        let pr = json!({
            "capabilities_granted": ["identity.read", "billing.read"], // out of order
        });
        let err = check_set_semantics_sorted(&pr, &["capabilities_granted"]).unwrap_err();
        match err {
            VerifyError::IntegrityError { message } => {
                assert!(message.contains("capabilities_granted"));
            },
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn absent_or_non_array_fields_are_skipped() {
        let pr = json!({ "license_id": "lic-1" });
        assert!(check_set_semantics_sorted(&pr, &["capabilities_granted"]).is_ok());
    }
}
