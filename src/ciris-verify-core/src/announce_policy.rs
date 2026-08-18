//! **Which cohort scopes may emit a Reticulum announce** — CC 5.4.6
//! `announce-suppress`, ratified against CIRISConstitution#91 (RC4).
//!
//! A Reticulum announce is the broadcast that tells the network a destination
//! exists and is reachable. Announcing a *group-scoped* destination leaks the
//! one fact the cohort tiers exist to withhold: **that the group exists at
//! all**. So CC 5.4.6 suppresses the announce itself, and members resolve each
//! other from a cached directory plus the per-group derivation in
//! [`ciris_crypto::scope_privacy`] instead — no announce, no per-resolution
//! query.
//!
//! ## The ruling this encodes (CIRISConstitution#91)
//!
//! CIRISEdge asked whether the prohibition binds **the packet** or **the
//! leak** — specifically, whether an announce *targeted via RNS native
//! addressing, iterated over the roster set* escapes it, since such an
//! announce reveals nothing to an outsider and so satisfies 5.4.6's stated
//! rationale while reading against its flat text.
//!
//! **Ruled: the packet.** A directed announce *inherits* the prohibition
//! rather than escaping it — the clause binds the **emission**, not the
//! addressing mode. Three legs:
//!
//! 1. **The purposive gloss is rationale, not exception**, because no directed
//!    announce on RNS transport can satisfy it: multi-hop path learning *is*
//!    outsider observation, and the retained path state is exactly the edge
//!    class the subpoena framing promises does not exist.
//! 2. **The flat MUST NOT was never broadcast-era shorthand** — the same
//!    section bans the targeted, non-broadcast per-destination query in the
//!    same breath. The emission class was always the object.
//! 3. **A directed announce trades a claimable guarantee for an unclaimable
//!    one** — *no emission exists* (structural, honestly claimable) for
//!    *emissions exist but resist analysis* (traffic-analysis privacy, which
//!    CEG/RET declines to claim; CC 1.13.3.1, the Anonymous Tier being its
//!    opt-in). A reading must not spend the first to buy the second.
//!
//! ## Why this makes epoch rotation free
//!
//! The ruling surfaced a dilemma that only bites under the *leak* reading:
//! 5.4.6's derivation is epoch-bound, so either derived destinations rotate
//! with the MLS epoch — and every Add/Remove emits a synchronized roster-wide
//! re-announce **wave**, leaking cardinality, timing and membership churn — or
//! they do not, and a removed member keeps every peer's addressing forever,
//! breaking the rebind discipline on the addressing plane.
//!
//! Under the packet reading there is no wave, because there is no emission.
//! Rotation costs nothing observable: members re-derive from the directory and
//! the new epoch secret, and a removed member loses addressing at the next
//! epoch. **The derivation being epoch-bound is a feature here and a defect
//! under the alternative** — which is part of why the alternative lost.
//!
//! ## What remains open
//!
//! Multi-hop *scoped* reach is an amendment-plane question, not a settled
//! prohibition, and the ruling states its bar: **no outsider-observable
//! emission, no outsider-retained path state, no epoch-correlated wave.** Any
//! future proposal is measured against those three.
//!
//! CC 5.4.6's Position record (informative) goes further and names the nearest
//! admissible relaxation — the **blinded-retained-state family (Tor v3 / I2P
//! b33)** — with the field's rotation rule attached: **rotation clocks must be
//! global, never group-event-driven.** That is a live constraint rather than
//! trivia, because today's derivation rotates on the **MLS epoch**, which
//! advances on Add/Remove and is therefore group-event-driven. It is correct
//! now *because nothing is emitted*; under any multi-hop relaxation the
//! trigger would have to move to a global clock. See
//! `ciris_crypto::scope_privacy::derive_destination`.
//!
//! In-group MLS distribution of addressing material was never prohibited —
//! that is the cached-directory discipline itself.

use crate::classification::{Classification, Gating};

/// A destination's cohort scope, as CC 5.4.6 partitions it.
///
/// The discriminator is **not** sensitivity in the abstract: it is whether the
/// tier carries an **anonymity claim**. Federation and Commons scopes carry
/// none, so they announce normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CohortScope {
    /// `self` — InvisibleEncrypted tier.
    SelfScope,
    /// `family` — InvisibleEncrypted tier.
    Family,
    /// `community` — CommunityDek tier.
    Community,
    /// `affiliations` — CommunityDek tier.
    Affiliations,
    /// `federation` — Commons; carries no anonymity claim.
    Federation,
    /// `species` — Commons; carries no anonymity claim.
    Species,
    /// `biosphere` — Commons; carries no anonymity claim.
    Biosphere,
    /// `infrastructure` — the explicit Commons opt-out.
    Infrastructure,
}

impl CohortScope {
    /// The wire string for this scope.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::SelfScope => "self",
            Self::Family => "family",
            Self::Community => "community",
            Self::Affiliations => "affiliations",
            Self::Federation => "federation",
            Self::Species => "species",
            Self::Biosphere => "biosphere",
            Self::Infrastructure => "infrastructure",
        }
    }

    /// Parse a wire string. **Fail-closed**: an unrecognized scope returns
    /// `None`, and a caller MUST treat that as *may not announce* rather than
    /// guessing — see [`wire_may_announce`].
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "self" => Self::SelfScope,
            "family" => Self::Family,
            "community" => Self::Community,
            "affiliations" => Self::Affiliations,
            "federation" => Self::Federation,
            "species" => Self::Species,
            "biosphere" => Self::Biosphere,
            "infrastructure" => Self::Infrastructure,
            _ => return None,
        })
    }

    /// **May a destination at this scope emit a Reticulum announce?**
    /// (CC 5.4.6, normative.)
    ///
    /// `false` for every tier below federation. Per CIRISConstitution#91 this
    /// binds the **emission**: a *targeted* or *directed* announce iterated
    /// over a roster is equally prohibited, because the clause binds what is
    /// emitted rather than who it is addressed to.
    #[must_use]
    pub const fn may_announce(self) -> bool {
        match self {
            Self::SelfScope | Self::Family | Self::Community | Self::Affiliations => false,
            Self::Federation | Self::Species | Self::Biosphere | Self::Infrastructure => true,
        }
    }

    /// Does this scope carry an anonymity claim? The inverse of
    /// [`may_announce`](Self::may_announce), named for the *reason* rather
    /// than the consequence.
    #[must_use]
    pub const fn carries_anonymity_claim(self) -> bool {
        !self.may_announce()
    }
}

/// May a destination carrying this **wire** scope string announce?
///
/// **Fail-closed on an unknown scope** — a scope this build does not recognize
/// returns `false`. CC 5.4.6's fail-secure clause is explicit that absence of
/// announce control "MUST fail toward suppression, never toward announce", so
/// an unrecognized tier must not be admitted to the announcing set by virtue
/// of being unrecognized.
#[must_use]
pub fn wire_may_announce(scope: &str) -> bool {
    CohortScope::from_wire(scope).is_some_and(CohortScope::may_announce)
}

impl Classification for CohortScope {
    /// **NORMATIVE** — tracks CC 5.4.6 as ratified against
    /// CIRISConstitution#91. A consumer may gate on it; disagreement belongs
    /// on the ratifying document, which is exactly the route #91 took.
    fn gating() -> Gating {
        Gating::Normative {
            authority: "CC 5.4.6 (ratified, CIRISConstitution#91)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The partition CC 5.4.6 draws, pinned scope-by-scope.
    #[test]
    fn below_federation_may_not_announce() {
        for s in [
            CohortScope::SelfScope,
            CohortScope::Family,
            CohortScope::Community,
            CohortScope::Affiliations,
        ] {
            assert!(
                !s.may_announce(),
                "{} carries an anonymity claim",
                s.as_wire()
            );
            assert!(s.carries_anonymity_claim());
        }
        for s in [
            CohortScope::Federation,
            CohortScope::Species,
            CohortScope::Biosphere,
            CohortScope::Infrastructure,
        ] {
            assert!(
                s.may_announce(),
                "{} carries no anonymity claim",
                s.as_wire()
            );
        }
    }

    /// **The #91 ruling itself.** The prohibition binds the emission, so a
    /// directed announce inherits it — there is deliberately no addressing-mode
    /// parameter that could relax the answer. This test exists so that adding
    /// one is a visible act.
    #[test]
    fn the_predicate_takes_no_addressing_mode() {
        // If a future change admits a `directed: bool`, this file's doc
        // comment and CC 5.4.6 both have to move first (CIRISConstitution#91).
        let scoped = CohortScope::Family;
        assert!(!scoped.may_announce());
    }

    /// Fail-closed: an unknown scope must not announce by default.
    #[test]
    fn an_unknown_scope_fails_toward_suppression() {
        assert!(!wire_may_announce("some-future-tier"));
        assert!(!wire_may_announce(""));
        assert!(wire_may_announce("federation"));
        assert!(!wire_may_announce("family"));
    }

    /// Wire strings round-trip, so the gate cannot be dodged by spelling.
    #[test]
    fn wire_strings_round_trip() {
        for s in [
            CohortScope::SelfScope,
            CohortScope::Family,
            CohortScope::Community,
            CohortScope::Affiliations,
            CohortScope::Federation,
            CohortScope::Species,
            CohortScope::Biosphere,
            CohortScope::Infrastructure,
        ] {
            assert_eq!(CohortScope::from_wire(s.as_wire()), Some(s));
        }
    }

    /// It is a ruling, so a consumer may gate on it — and the authority is
    /// named, so disagreement has an address.
    #[test]
    fn the_rule_is_gateable_and_names_its_authority() {
        let g = CohortScope::gating();
        assert!(g.may_gate());
        assert_eq!(
            g.amendable_by(),
            Some("CC 5.4.6 (ratified, CIRISConstitution#91)")
        );
    }
}
