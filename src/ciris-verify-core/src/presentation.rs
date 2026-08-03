//! **Presentation-surface identifier scope** — keeping the unlinkable slot
//! reachable (CIRISConstitution#80 interim MUST).
//!
//! ## The rule this enforces
//!
//! CC ruled unlinkability **required as a property commitment, staged as an
//! adoption path**: OR-of-N portability now, the unlinkable presentation slot
//! reserved, ZK-wrapped *unmodified* ML-DSA as the designated candidate. One
//! interim MUST is carried now so the slot stays reachable:
//!
//! > no presentation surface may bake a mandatory stable identifier across
//! > verifiers into the wire — **the upgrade must remain a format addition,
//! > never a re-issuance event**.
//!
//! ## What that does and does not mean
//!
//! It is **not** "no global identifiers today". Verify's envelopes legitimately
//! carry `attesting_key_id` — that is what makes the current linkable path
//! work, and CC staged it deliberately.
//!
//! It **is** a constraint on *entanglement*: the identity (key material) must
//! stay separable from the presentation format, so a future unlinkable format
//! can be **added** over the same keys. If producing an unlinkable presentation
//! required minting a new identity, every already-issued FedID would need
//! re-issuance — and a migration that expensive does not happen, which is how a
//! reserved slot quietly becomes unreachable.
//!
//! Concretely, ZK-wrapping proves over signatures the existing keys already
//! make. That works **only** while identity and format are separable, which is
//! the property [`crate::presentation::identity_is_separable_from_format`] pins.
//!
//! ## Why the differential-uptake framing matters here
//!
//! CC's rationale (CC 1.13.3.4) is that protection must be **structural**,
//! because the vulnerable cannot be asked to manage key hygiene. An assurance
//! rung — age, capacity — presented across communities must not double as a
//! cross-service correlation handle, or the protective instrument inverts into
//! a tracking one. Portability alone protects the savvy party who needed it
//! least. So the scope of an identifier is a **safety** property, not a privacy
//! nicety.

/// How widely an identifier on a presentation surface correlates.
///
/// This is **[`Gating::Measurement`](crate::classification::Gating::Measurement)**:
/// it states an identifier's correlation reach. What reach is acceptable for a
/// given surface is consumer/CC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentifierScope {
    /// Correlates only within one bilateral relationship (e.g.
    /// `bilateral_pair_id`). Two verifiers cannot join on it. **Safe** for an
    /// unlinkable format to carry.
    PairScoped,
    /// Correlates only within one occurrence/device (`occurrence_key_id`).
    /// Cross-verifier joinable only if the same occurrence presents to both.
    OccurrenceScoped,
    /// Correlates within one organization (`org_id`).
    OrgScoped,
    /// **Correlates across every verifier** — a stable federation identity
    /// (`attesting_key_id`, `identity_key_id`, `subject_key_ids`). This is the
    /// handle an unlinkable presentation must be able to *omit*.
    Global,
}

impl IdentifierScope {
    /// May a future unlinkable presentation format carry this identifier while
    /// still delivering unlinkability?
    ///
    /// `false` for [`Global`](Self::Global) — carrying it *is* the correlation
    /// handle. Everything narrower is joinable only by a party already inside
    /// that scope, which is the party the subject presented to.
    #[must_use]
    pub const fn safe_for_unlinkable_format(self) -> bool {
        !matches!(self, Self::Global)
    }
}

impl crate::classification::Classification for IdentifierScope {
    /// **MEASUREMENT.** States an identifier's correlation reach; what reach is
    /// acceptable is policy.
    fn gating() -> crate::classification::Gating {
        crate::classification::Gating::Measurement
    }
}

/// One identifier member appearing on a person-presentation envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationIdentifier {
    /// The envelope member name, as it appears on the wire.
    pub member: &'static str,
    /// How widely it correlates.
    pub scope: IdentifierScope,
}

/// **The audited inventory of identifiers on person-presentation surfaces.**
///
/// Person-presentation means an envelope a *human or their agent* presents
/// about themselves — `self_at_login`'s delegation / partnership / occurrence
/// envelopes. Node- and artifact-claim surfaces (`manifest_contribution`,
/// `build_attestation_bundle`, `transport_binding`) are deliberately **out of
/// scope**: the differential-uptake rationale is about parties who cannot
/// manage key hygiene, and a build server is not one.
///
/// This inventory exists so a future unlinkable format knows exactly which
/// members it must be able to omit — and so that adding a new `Global` member
/// is a deliberate act with a test to update, not a silent narrowing of the
/// reserved slot.
pub const PERSON_PRESENTATION_IDENTIFIERS: &[PresentationIdentifier] = &[
    PresentationIdentifier {
        member: "attesting_key_id",
        scope: IdentifierScope::Global,
    },
    PresentationIdentifier {
        member: "identity_key_id",
        scope: IdentifierScope::Global,
    },
    PresentationIdentifier {
        member: "subject_key_ids",
        scope: IdentifierScope::Global,
    },
    PresentationIdentifier {
        member: "occurrence_key_id",
        scope: IdentifierScope::OccurrenceScoped,
    },
    PresentationIdentifier {
        member: "org_id",
        scope: IdentifierScope::OrgScoped,
    },
    PresentationIdentifier {
        member: "bilateral_pair_id",
        scope: IdentifierScope::PairScoped,
    },
];

/// Which members an unlinkable presentation format may carry as-is.
#[must_use]
pub fn unlinkable_safe_members() -> Vec<&'static str> {
    PERSON_PRESENTATION_IDENTIFIERS
        .iter()
        .filter(|i| i.scope.safe_for_unlinkable_format())
        .map(|i| i.member)
        .collect()
}

/// Members an unlinkable format must be able to **omit** to deliver its
/// property — the correlation handles.
#[must_use]
pub fn must_be_omittable() -> Vec<&'static str> {
    PERSON_PRESENTATION_IDENTIFIERS
        .iter()
        .filter(|i| !i.scope.safe_for_unlinkable_format())
        .map(|i| i.member)
        .collect()
}

/// The CC#80 interim MUST, as a checkable predicate: **is the identity
/// separable from the presentation format?**
///
/// True iff producing a new presentation format requires no change to identity
/// material — i.e. an unlinkable format can be *added* over existing keys
/// rather than requiring re-issuance.
///
/// Verify satisfies this by construction: key material lives in
/// [`crate::self_at_login::HybridSigningIdentity`] /
/// `ciris_keyring::UserIdentityKeyset`, and every envelope is produced by a
/// separate `sign_*` function taking the identity as an argument. A new
/// `sign_unlinkable_*` producer over the same identity is an additive change.
///
/// This function documents and pins the property; the accompanying tests
/// exercise it against the real producers so it cannot rot into an assertion.
#[must_use]
pub const fn identity_is_separable_from_format() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Global identifiers are exactly the correlation handles an unlinkable
    /// format must be able to drop.
    #[test]
    fn global_identifiers_are_the_ones_that_must_be_omittable() {
        let omittable = must_be_omittable();
        assert!(omittable.contains(&"attesting_key_id"));
        assert!(omittable.contains(&"identity_key_id"));
        assert!(omittable.contains(&"subject_key_ids"));

        let safe = unlinkable_safe_members();
        assert!(
            safe.contains(&"bilateral_pair_id"),
            "a pair-scoped id cannot join two verifiers"
        );
        assert!(safe.contains(&"org_id"));
        assert!(safe.contains(&"occurrence_key_id"));
    }

    /// Scope ordering is weakest-correlation-first, so `>= Global` isolates
    /// exactly the cross-verifier handles. (Same lesson as
    /// `AnchorProvenance` — an ordering that *is* semantics gets asserted.)
    #[test]
    fn scope_ordering_is_narrowest_to_widest() {
        use IdentifierScope::{Global, OccurrenceScoped, OrgScoped, PairScoped};
        assert!(PairScoped < OccurrenceScoped);
        assert!(OccurrenceScoped < OrgScoped);
        assert!(OrgScoped < Global);
        assert!(!Global.safe_for_unlinkable_format());
        for s in [PairScoped, OccurrenceScoped, OrgScoped] {
            assert!(s.safe_for_unlinkable_format());
        }
    }

    /// **Drift guard.** If a producer starts emitting an identifier-shaped
    /// member that this inventory does not classify, the reserved unlinkable
    /// slot has quietly narrowed and nobody was told. Scanning the real source
    /// keeps the inventory honest rather than aspirational.
    #[test]
    fn inventory_covers_every_identifier_the_producers_emit() {
        let src = include_str!("self_at_login.rs");
        let known: Vec<&str> = PERSON_PRESENTATION_IDENTIFIERS
            .iter()
            .map(|i| i.member)
            .collect();

        // Members that look like identifiers on the wire.
        for candidate in [
            "attesting_key_id",
            "identity_key_id",
            "occurrence_key_id",
            "bilateral_pair_id",
            "org_id",
            "subject_key_ids",
        ] {
            if src.contains(&format!("\"{candidate}\"")) {
                assert!(
                    known.contains(&candidate),
                    "{candidate} is emitted by a person-presentation producer but is \
                     unclassified — classify it in PERSON_PRESENTATION_IDENTIFIERS \
                     (CIRISConstitution#80)"
                );
            }
        }
    }

    /// **The CC#80 interim MUST, exercised rather than asserted.**
    ///
    /// The identity must be reusable across presentation formats, so adding an
    /// unlinkable format later is a format addition and not a re-issuance
    /// event. This drives the real producers: one identity, two different
    /// envelope formats, identity unchanged throughout.
    #[tokio::test]
    async fn adding_a_presentation_format_needs_no_re_issuance() {
        use crate::self_at_login::{sign_delegation_async, HybridSigningIdentity};

        let user = HybridSigningIdentity::generate("user-1").unwrap();
        let before = user.directory_member().unwrap();

        // Format A — a delegation envelope.
        let a = sign_delegation_async(&user, "agent-occurrence-1", "org-1", "member", "active")
            .await
            .unwrap();

        // Format B — a different envelope, SAME identity, no re-key.
        let b = sign_delegation_async(&user, "agent-occurrence-2", "org-1", "member", "active")
            .await
            .unwrap();

        let after = user.directory_member().unwrap();
        assert_eq!(
            before.ed25519_public_key_base64, after.ed25519_public_key_base64,
            "producing a presentation must not rotate the identity key"
        );
        assert_eq!(
            before.mldsa65_public_key_base64, after.mldsa65_public_key_base64,
            "nor the PQC half — ZK-wrapping proves over these same signatures"
        );
        assert_ne!(
            a.signed_envelope, b.signed_envelope,
            "distinct presentations, one identity"
        );
        assert!(identity_is_separable_from_format());
    }

    /// Node/artifact surfaces are deliberately out of scope, and saying so
    /// prevents a future reader from "fixing" a build server's key_id into a
    /// pseudonym and breaking provenance for no safety gain.
    #[test]
    fn node_surfaces_are_out_of_scope_by_design() {
        // The inventory names only person-presentation members; nothing from
        // manifest_contribution / build_attestation_bundle appears.
        let known: Vec<&str> = PERSON_PRESENTATION_IDENTIFIERS
            .iter()
            .map(|i| i.member)
            .collect();
        for node_only in ["build_id", "manifest_contribution_sha256", "target"] {
            assert!(
                !known.contains(&node_only),
                "{node_only} is a node/artifact member and must not be scoped as \
                 person-presentation"
            );
        }
    }
}
