//! **May a consumer gate on this?** — the answer, stated in the type
//! (CIRISVerify#238 follow-up).
//!
//! ## Why this module exists
//!
//! Verify ships classifications (`ConsentDisposition`, `AndroidSecurityLevel`,
//! `Purpose`, …) that other repos consume as **policy**. At least three do
//! today. The failure this prevents actually happened:
//!
//! `ConsentClass` was described as *"a proposal from the measuring side, not a
//! ruling"* — **in prose, in a different document**. CIRISPersist#569 read it as
//! a ruling and derived an admission gate from it. It was neither malicious nor
//! careless: nothing in the type said which it was, and the reader had no way to
//! tell without finding the sentence.
//!
//! `is_consent_gated()` fixed that one case. This module is the **pattern**: any
//! classification verify ships states, in the type itself, whether a consumer
//! may gate on it — so the next consumer cannot repeat the mistake by reading
//! the type correctly and the prose not at all.
//!
//! ## The three statuses
//!
//! - [`crate::classification::Gating::Normative`] — tracks a **ratified** rule. Gate on it. If you
//!   believe it is wrong, the disagreement belongs on the ratifying document,
//!   not in a divergent local list.
//! - [`crate::classification::Gating::Measurement`] — states **what verify observed**. Do **not** gate
//!   admission on it as though it were policy: compose your own policy over it.
//!   (Per `MISSION.md` §1.4 — verify carries measurements; tiers are consumer
//!   sugar.)
//! - [`crate::classification::Gating::Proposal`] — verify's **suggestion**, not ratified by anything.
//!   Do **not** gate on it. It exists to be challenged, and carries the tracking
//!   reference where challenging it happens.
//!
//! ## Discipline
//!
//! A `Proposal` is a promise to either get it ratified or withdraw it — the
//! status is not a place to park an opinion indefinitely. `ConsentDisposition`
//! spent one release as an unlabelled proposal, contradicted a ruling, and was
//! caught by a downstream. That is the cost this module prices in.

/// Whether a consumer may gate on a classification verify ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gating {
    /// Tracks a **ratified** rule — gate on it freely.
    Normative {
        /// The ratifying reference (e.g. `"CC 3.4.5"`), so a consumer can read
        /// the rule rather than infer it from the variants.
        authority: &'static str,
    },
    /// States **what verify measured**. A consumer composes its own policy over
    /// this; it MUST NOT be treated as a ruling.
    Measurement,
    /// Verify's **proposal**, not ratified. A consumer MUST NOT gate on it.
    Proposal {
        /// Where the proposal is being adjudicated.
        tracking: &'static str,
    },
}

impl Gating {
    /// May a consumer gate admission/policy on this classification?
    ///
    /// `true` only for [`crate::classification::Gating::Normative`]. A measurement is an input to
    /// policy, not policy; a proposal has no standing at all.
    #[must_use]
    pub const fn may_gate(self) -> bool {
        matches!(self, Self::Normative { .. })
    }

    /// **Propagate through derivation — weakest input wins** (CIRISVerify#244).
    ///
    /// CC's composition-context rule is explicit that the constraint
    /// *inherits*: *"a value derived from a self-subject `capacity:*` row
    /// inherits the constraint, and the trace audit MUST verify label
    /// propagation through derivation, not merely the absence of a direct read
    /// in the loop."* The named failure is **laundering** — a constrained value
    /// passing through a transformation and coming out unconstrained (Meta's
    /// Policy Zones precedent).
    ///
    /// Ordering is `Proposal` < `Measurement` < `Normative`, so a derivation is
    /// **never more gate-able than its weakest input**. Mixing a measurement
    /// into a normative computation yields a measurement, which is the point:
    /// you cannot launder a measurement into policy by aggregating it.
    ///
    /// ## Two normative inputs with *different* authorities
    ///
    /// Returns [`Gating::Measurement`], deliberately. A derived value governed
    /// by two rulings cannot cite *a* ratifying authority, and emitting one of
    /// the two would be precisely the over-claim this module exists to prevent.
    /// A consumer that genuinely needs to gate on such a composite must name
    /// the authority for the *composite*, which is a ruling someone has to
    /// make — not something verify may infer.
    ///
    /// ## Where this is applied
    ///
    /// Verify itself composes no verdict — traced: `AttestBundle` regroups
    /// `AttestationEntry` items and `holonomic::aggregation` folds over `f64`
    /// masses, so **no classification travels through verify's own composition
    /// paths** and there is no laundering path inside this crate. This is the
    /// algebra for **consumers** deriving over verify's outputs, which is where
    /// the risk actually lives.
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            // Any proposal poisons the derivation — it has no standing at all.
            (Self::Proposal { tracking }, _) | (_, Self::Proposal { tracking }) => {
                Self::Proposal { tracking }
            },
            // A measurement anywhere makes the result a measurement.
            (Self::Measurement, _) | (_, Self::Measurement) => Self::Measurement,
            (Self::Normative { authority: a }, Self::Normative { authority: b }) => {
                if a == b {
                    Self::Normative { authority: a }
                } else {
                    // Cannot cite a single authority for the composite.
                    Self::Measurement
                }
            },
        }
    }

    /// Fold [`combine`](Self::combine) over a derivation's inputs.
    ///
    /// An **empty** input set yields [`Gating::Measurement`], not a normative
    /// identity: a value derived from nothing carries no ratified authority,
    /// and returning `Normative` for the empty case would let a consumer
    /// manufacture policy standing out of an empty fold.
    #[must_use]
    pub fn propagate(inputs: impl IntoIterator<Item = Self>) -> Self {
        inputs
            .into_iter()
            .reduce(Self::combine)
            .unwrap_or(Self::Measurement)
    }

    /// One-line rendering for logs and operator diagnostics.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::Normative { authority } => {
                format!("NORMATIVE (tracks {authority}) — a consumer may gate on this")
            },
            Self::Measurement => {
                "MEASUREMENT — what verify observed; compose your own policy, do not gate as policy"
                    .to_string()
            },
            Self::Proposal { tracking } => format!(
                "PROPOSAL (not ratified; see {tracking}) — a consumer MUST NOT gate on this"
            ),
        }
    }
}

/// A classification verify ships for downstream consumption.
///
/// Implementing this is the contract: **say what you are.** A type that a
/// consumer might reasonably read as policy should implement it, so the answer
/// travels with the type instead of living in prose somewhere else.
pub trait Classification {
    /// May a consumer gate on this classification, and on whose authority?
    fn gating() -> Gating;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_normative_may_be_gated_on() {
        assert!(Gating::Normative {
            authority: "CC 3.4.5"
        }
        .may_gate());
        assert!(!Gating::Measurement.may_gate());
        assert!(!Gating::Proposal {
            tracking: "CIRISVerify#238"
        }
        .may_gate());
    }

    /// The rendering must name the authority, because "normative" without a
    /// citation is exactly the ambiguity this module exists to remove.
    #[test]
    fn descriptions_carry_their_authority() {
        assert!(Gating::Normative {
            authority: "CC 3.4.5"
        }
        .describe()
        .contains("CC 3.4.5"));
        assert!(Gating::Proposal {
            tracking: "CIRISVerify#238"
        }
        .describe()
        .contains("MUST NOT"));
        assert!(Gating::Measurement.describe().contains("do not gate"));
    }
}

/// Cross-module proof that every shipped classification declares its status —
/// the guard against a new one being added without an answer.
#[cfg(test)]
mod shipped_classifications {
    use super::{Classification, Gating};
    use crate::device_attestation::{AndroidSecurityLevel, AppAttestEnvironment};
    use crate::federation_provenance::dim::ConsentDisposition;
    use crate::trust_anchor_store::Purpose;

    /// A consumer may gate on these, and each names its ratifying authority.
    #[test]
    fn normative_classifications_name_their_authority() {
        for (what, g) in [
            ("ConsentDisposition", ConsentDisposition::gating()),
            ("Purpose", Purpose::gating()),
        ] {
            assert!(g.may_gate(), "{what} should be gate-able");
            match g {
                Gating::Normative { authority } => {
                    assert!(!authority.is_empty(), "{what} must cite its authority")
                },
                other => panic!("{what}: expected Normative, got {other:?}"),
            }
        }
    }

    /// Device-attestation verdicts are measurements. A consumer that gates
    /// admission directly on them has made hardware a requirement — the exact
    /// inversion `device_attestation`'s docs warn against.
    #[test]
    fn device_attestation_verdicts_are_measurements_not_policy() {
        for (what, g) in [
            ("AndroidSecurityLevel", AndroidSecurityLevel::gating()),
            ("AppAttestEnvironment", AppAttestEnvironment::gating()),
        ] {
            assert_eq!(g, Gating::Measurement, "{what} must be a measurement");
            assert!(!g.may_gate(), "{what} must NOT be gate-able");
        }
    }

    /// **Every shipped classification has its disposition asserted here.**
    ///
    /// Implementing [`Classification`] already forces a type to *declare* a
    /// gating — it cannot ship without an answer. This test covers the other
    /// half, which CIRISConstitution#83 makes explicit: a category change must
    /// be a **visible act**, not a silent edit. Without a per-type assertion, a
    /// classification could be flipped from `Measurement` to `Normative` — the
    /// direction that hands consumers a gate — and nothing would fail.
    ///
    /// The list is deliberately exhaustive and hand-maintained: adding a
    /// classification means adding a row, which is the visible act.
    #[test]
    fn every_shipped_classification_asserts_its_disposition() {
        use crate::presentation::IdentifierScope;
        use crate::redactable::MemberState;
        use crate::trust_anchor_store::AnchorProvenance;

        let all: [(&str, Gating); 7] = [
            (
                "ConsentDisposition",
                Gating::Normative {
                    authority: "CC 3.4.5",
                },
            ),
            (
                "Purpose",
                Gating::Normative {
                    authority: "draft-ietf-rats-concise-ta-stores-02",
                },
            ),
            ("AndroidSecurityLevel", Gating::Measurement),
            ("AppAttestEnvironment", Gating::Measurement),
            // How an anchor reached us. Whether a tier is acceptable is
            // consumer policy — gating on it here would make the sourcing
            // story into an admission rule verify has no standing to impose.
            ("AnchorProvenance", Gating::Measurement),
            // An identifier's correlation reach. What reach is acceptable is
            // CC/consumer policy.
            ("IdentifierScope", Gating::Measurement),
            // Whether a member was disclosed or redacted — an observation
            // about an artifact, not a ruling about it.
            ("MemberState", Gating::Measurement),
        ];

        let actual: [(&str, Gating); 7] = [
            ("ConsentDisposition", ConsentDisposition::gating()),
            ("Purpose", Purpose::gating()),
            ("AndroidSecurityLevel", AndroidSecurityLevel::gating()),
            ("AppAttestEnvironment", AppAttestEnvironment::gating()),
            ("AnchorProvenance", AnchorProvenance::gating()),
            ("IdentifierScope", IdentifierScope::gating()),
            ("MemberState", MemberState::gating()),
        ];

        for ((name, expected), (name2, got)) in all.into_iter().zip(actual) {
            assert_eq!(name, name2);
            assert_eq!(
                expected, got,
                "{name} changed disposition — a category change is a visible act \
                 by a named authority (CIRISConstitution#83), not a silent edit"
            );
        }
    }

    /// No classification ships as an unresolved [`Gating::Proposal`]. A
    /// proposal is a promise to get it ratified or withdraw it — not a place to
    /// park an opinion. `ConsentDisposition` spent one release as an unlabelled
    /// proposal, contradicted a ruling, and was caught by a downstream.
    #[test]
    fn nothing_ships_as_an_unresolved_proposal() {
        use crate::presentation::IdentifierScope;
        use crate::redactable::MemberState;
        use crate::trust_anchor_store::AnchorProvenance;

        for (what, g) in [
            ("ConsentDisposition", ConsentDisposition::gating()),
            ("Purpose", Purpose::gating()),
            ("AndroidSecurityLevel", AndroidSecurityLevel::gating()),
            ("AppAttestEnvironment", AppAttestEnvironment::gating()),
            ("AnchorProvenance", AnchorProvenance::gating()),
            ("IdentifierScope", IdentifierScope::gating()),
            ("MemberState", MemberState::gating()),
        ] {
            assert!(
                !matches!(g, Gating::Proposal { .. }),
                "{what} still ships as a Proposal — ratify it or withdraw it"
            );
        }
    }

    /// CC 3.4.5 specifically — the case that motivated the pattern.
    #[test]
    fn consent_disposition_tracks_cc_3_4_5() {
        assert_eq!(
            ConsentDisposition::gating(),
            Gating::Normative {
                authority: "CC 3.4.5"
            }
        );
    }
}

#[cfg(test)]
mod propagation {
    use super::*;

    const CC: Gating = Gating::Normative {
        authority: "CC 3.4.5",
    };
    const RATS: Gating = Gating::Normative {
        authority: "draft-ietf-rats-concise-ta-stores-02",
    };
    const PROP: Gating = Gating::Proposal {
        tracking: "CIRISVerify#244",
    };

    /// A derivation is never more gate-able than its weakest input — the
    /// anti-laundering property.
    #[test]
    fn measurement_poisons_a_normative_derivation() {
        assert_eq!(CC.combine(Gating::Measurement), Gating::Measurement);
        assert_eq!(Gating::Measurement.combine(CC), Gating::Measurement);
        assert!(!CC.combine(Gating::Measurement).may_gate());
    }

    /// A proposal has no standing, so it poisons anything it touches.
    #[test]
    fn a_proposal_poisons_everything() {
        assert!(matches!(CC.combine(PROP), Gating::Proposal { .. }));
        assert!(matches!(
            Gating::Measurement.combine(PROP),
            Gating::Proposal { .. }
        ));
        assert!(!CC.combine(PROP).may_gate());
    }

    /// Same authority survives; the derived value is still gate-able.
    #[test]
    fn one_authority_survives_derivation() {
        assert_eq!(CC.combine(CC), CC);
        assert!(CC.combine(CC).may_gate());
    }

    /// Two rulings cannot be collapsed into one citation — emitting either
    /// would be the over-claim this module exists to prevent.
    #[test]
    fn differing_authorities_degrade_rather_than_pick_one() {
        assert_eq!(CC.combine(RATS), Gating::Measurement);
        assert_eq!(RATS.combine(CC), Gating::Measurement);
        assert!(!CC.combine(RATS).may_gate());
    }

    /// An empty fold must not manufacture policy standing.
    #[test]
    fn empty_derivation_is_not_normative() {
        assert_eq!(Gating::propagate([]), Gating::Measurement);
        assert!(!Gating::propagate([]).may_gate());
    }

    #[test]
    fn propagate_folds_to_the_weakest() {
        assert_eq!(Gating::propagate([CC, CC, CC]), CC);
        assert_eq!(
            Gating::propagate([CC, Gating::Measurement, CC]),
            Gating::Measurement
        );
        assert!(matches!(
            Gating::propagate([CC, Gating::Measurement, PROP]),
            Gating::Proposal { .. }
        ));
    }

    /// Order must not change the outcome — a fold that depends on input order
    /// would give two nodes with the same evidence different answers.
    #[test]
    fn combine_is_commutative_and_associative_enough_to_fold() {
        let all = [CC, RATS, Gating::Measurement, PROP];
        for a in all {
            for b in all {
                assert_eq!(a.combine(b), b.combine(a), "combine must commute");
            }
        }
        let fwd = Gating::propagate([CC, Gating::Measurement, RATS]);
        let rev = Gating::propagate([RATS, Gating::Measurement, CC]);
        assert_eq!(fwd, rev, "fold must be order-independent");
    }
}
