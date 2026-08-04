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
//! ## The four statuses
//!
//! - [`crate::classification::Gating::Normative`] — **held under a named
//!   authority**. Gate on it. If you believe it is wrong, the disagreement
//!   belongs on the ratifying document, not in a divergent local list.
//! - [`crate::classification::Gating::Structural`] — **cannot vary**. Gate on
//!   it. No authority ratified it and none can waive it; deviating breaks
//!   parsing or dispatch.
//! - [`crate::classification::Gating::Measurement`] — states **what verify observed**. Do **not** gate
//!   admission on it as though it were policy: compose your own policy over it.
//!   (Per `MISSION.md` §1.4 — verify carries measurements; tiers are consumer
//!   sugar.)
//! - [`crate::classification::Gating::Proposal`] — verify's **suggestion**, not ratified by anything.
//!   Do **not** gate on it. It exists to be challenged, and carries the tracking
//!   reference where challenging it happens.
//!
//! ## Why `Normative` and `Structural` are separate (CIRISOntology#3)
//!
//! The arity ruling found that **"binding" is two words wearing one**.
//! `binding_never_varies` covers the held classes (deontic, structural,
//! testimonial), but `axiomatic_binds_by_varying` shows a class that is binding
//! *and* varies — so a reader who infers "held" from "binding" is wrong, and a
//! reader who cannot tell *this would break* from *this is disallowed* will
//! petition the wrong body: asking a standards body to amend a wire format, or
//! filing a bug against a constitutional ruling.
//!
//! [`Gating::amendable_by`](crate::classification::Gating::amendable_by) is the operational form of the distinction — it
//! names who can change it, and returns `None` when nobody can.
//!
//! Verify ships one of each, which is what makes the split load-bearing rather
//! than theoretical: [`crate::federation_provenance::dim::ConsentDisposition`]
//! is `Normative` (CC could rule differently tomorrow and nothing mechanically
//! breaks), while [`crate::trust_anchor_store::Purpose`] is `Structural` (its
//! values are pinned CDDL wire indices; deviating breaks CBOR dispatch against
//! every other CoTS implementation, and no body can waive that).
//!
//! ## Frames: one class is a relation, not a property
//!
//! Eleven of the twelve wrong-kinds are properties of an artifact. `testimonial`
//! is not: it turns on **re-derivability**, and `repairability_not_intrinsic`
//! exhibits one fact with two frames and opposite verdicts, so
//! `repairable_does_not_factor` concludes no artifact-only procedure can assign
//! it *by any procedure whatsoever*. It is irreducibly a relation between an
//! artifact and a [`Frame`](crate::classification::Frame).
//!
//! [`Arity::testimonial`](crate::classification::Arity::testimonial) therefore **refuses an undeclared frame** rather than
//! defaulting one. Defaulting would be the exact failure the ruling names — an
//! unstated assumption about what survives, silently deciding the verdict. And
//! the frame belongs to the *harness*, not the block:
//! `self_declared_frame_undetermined` shows that letting each block declare its
//! own frame just moves the free parameter, since the verdict then turns on
//! which declaration rule was chosen.
//!
//! **Verify supplies no default frame and must not.** Verify is a library; what
//! is retained is a property of the deployment.
//!
//! ## Discipline
//!
//! A `Proposal` is a promise to either get it ratified or withdraw it — the
//! status is not a place to park an opinion indefinitely. `ConsentDisposition`
//! spent one release as an unlabelled proposal, contradicted a ruling, and was
//! caught by a downstream. That is the cost this module prices in.

/// Whether a consumer may gate on a classification verify ships — and, when it
/// may, **on what grounds**.
///
/// The [`Normative`](Self::Normative) / [`Structural`](Self::Structural) split
/// implements CIRISOntology#3's arity ruling (`binding_never_varies` +
/// `axiomatic_binds_by_varying`): "binding" is two words wearing one. See the
/// module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gating {
    /// **Held under a named authority** (deontic). Varying it breaks no machine
    /// — it defies a ratifying body. Gate on it; disagreement belongs on the
    /// ratifying document, not in a divergent local list.
    Normative {
        /// The ratifying reference (e.g. `"CC 3.4.5"`), so a consumer can read
        /// the rule rather than infer it from the variants.
        authority: &'static str,
    },
    /// **Cannot vary** (structural). No authority ratifies this and none can
    /// waive it: deviating breaks parsing or dispatch. Gate on it; disagreement
    /// is a bug report, not an amendment.
    ///
    /// The distinction from [`Normative`](Self::Normative) is not decorative. A
    /// consumer that reads "binding" and cannot tell *this would break* from
    /// *this is disallowed* will petition the wrong body — asking CC to amend a
    /// wire format, or filing a bug against a ruling.
    Structural {
        /// What breaks if it varies (e.g. `"CBOR wire interop with other CoTS
        /// implementations"`).
        breaks: &'static str,
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
    /// `true` for [`Normative`](Self::Normative) and
    /// [`Structural`](Self::Structural) — the two binding dispositions. A
    /// measurement is an input to policy, not policy; a proposal has no
    /// standing at all.
    #[must_use]
    pub const fn may_gate(self) -> bool {
        matches!(self, Self::Normative { .. } | Self::Structural { .. })
    }

    /// **Where to take a disagreement.** The reason the binding split exists.
    ///
    /// Returns the ratifying authority for [`Normative`](Self::Normative) — the
    /// body that can actually change it — and `None` for
    /// [`Structural`](Self::Structural), where no body can: the recourse is a
    /// bug report, not an amendment.
    #[must_use]
    pub const fn amendable_by(self) -> Option<&'static str> {
        match self {
            Self::Normative { authority } => Some(authority),
            _ => None,
        }
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
            (Self::Structural { breaks: a }, Self::Structural { breaks: b }) => {
                if a == b {
                    Self::Structural { breaks: a }
                } else {
                    Self::Measurement
                }
            },
            // A ruling and a mechanism, mixed. The composite cannot honestly
            // claim either ground: citing the authority would imply a body can
            // waive the mechanical constraint, and citing the mechanism would
            // imply the ruling is unamendable. Degrade, per the same logic as
            // two differing authorities.
            (Self::Normative { .. }, Self::Structural { .. })
            | (Self::Structural { .. }, Self::Normative { .. }) => Self::Measurement,
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
                format!(
                    "NORMATIVE (held under {authority}) — a consumer may gate on this; \
                     take disagreement to {authority}"
                )
            },
            Self::Structural { breaks } => format!(
                "STRUCTURAL (cannot vary — breaks {breaks}) — a consumer may gate on this; \
                 no authority can waive it, so disagreement is a bug report"
            ),
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

/// **What the harness declares retained and readable** — the frame a
/// testimonial classification is made against (CIRISOntology#3).
///
/// The frame belongs to the *harness*, declared once and in the open. The
/// ruling is explicit that pushing it into the blocks does not rescue it
/// (`self_declared_frame_undetermined`): let each block declare its own frame
/// and the verdict still turns on which declaration rule was chosen, so the
/// frame is a free parameter wherever it is put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// Who declared this frame. A frame with no declarer is an unstated
    /// assumption wearing a struct.
    pub declared_by: &'static str,
    /// The record classes this harness retains and can re-read.
    pub retained: &'static [&'static str],
}

impl Frame {
    /// Is `fact` recoverable from what this frame retains?
    ///
    /// Mirrors the Lean `Repairable fact c := fact ∈ c`. Decidable *given a
    /// frame* — and that decidability is the whole point: fix what is retained
    /// and the epistemic/testimonial boundary becomes checkable.
    #[must_use]
    pub fn repairable(&self, fact: &str) -> bool {
        self.retained.contains(&fact)
    }
}

/// A testimonial classification was attempted without declaring its frame.
///
/// **Refused, never defaulted.** Defaulting would pick a frame silently, and
/// the ruling's negative result (`repairability_not_intrinsic`) is precisely
/// that the verdict flips with the frame — so a defaulted frame is an
/// unstated assumption that determines the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UndeclaredFrame {
    /// What was being classified, for the diagnostic.
    pub subject: &'static str,
}

impl std::fmt::Display for UndeclaredFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to classify {} as testimonial with no declared frame: \
             repairability is frame-relative, so an undeclared frame silently \
             decides the verdict (CIRISOntology#3)",
            self.subject
        )
    }
}

impl std::error::Error for UndeclaredFrame {}

/// **The arity of a classification's discriminator.**
///
/// Eleven of the twelve wrong-kinds are properties of an artifact: their
/// verdict cannot be moved by anything outside it. `testimonial` is not — it is
/// irreducibly a **relation** between an artifact and a frame
/// (`repairable_does_not_factor`). That is not a defect in the class; it is the
/// class's actual arity, and this type carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    /// **Frame-invariant.** Readable off the artifact alone; no frame can
    /// change the verdict.
    ArtifactOnly,
    /// **A relation**, carrying the frame it was assigned against.
    Testimonial {
        /// The frame this assignment is relative to. Non-optional by
        /// construction — that is the enforcement.
        frame: Frame,
    },
}

impl Arity {
    /// Assign `testimonial`, refusing an undeclared frame.
    ///
    /// This is the enforcement point for CIRISOntology#3 ask (1): there is no
    /// path to a testimonial classification that does not name its frame, and
    /// the `Option` is rejected rather than filled in.
    ///
    /// # Errors
    /// [`UndeclaredFrame`] when `frame` is `None`.
    pub const fn testimonial(
        subject: &'static str,
        frame: Option<Frame>,
    ) -> Result<Self, UndeclaredFrame> {
        match frame {
            Some(frame) => Ok(Self::Testimonial { frame }),
            None => Err(UndeclaredFrame { subject }),
        }
    }

    /// The frame this classification was made against, if it is frame-relative.
    #[must_use]
    pub const fn frame(self) -> Option<Frame> {
        match self {
            Self::Testimonial { frame } => Some(frame),
            Self::ArtifactOnly => None,
        }
    }
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
        let g = ConsentDisposition::gating();
        assert!(g.may_gate(), "ConsentDisposition should be gate-able");
        match g {
            Gating::Normative { authority } => assert!(
                !authority.is_empty(),
                "a Normative classification must cite its authority"
            ),
            other => panic!("ConsentDisposition: expected Normative, got {other:?}"),
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
            // STRUCTURAL, not Normative: pinned CDDL wire indices. Changed in
            // 13.0.0 per CIRISOntology#3's disposition split -- and this table
            // is what forced that change to be declared rather than slipped in.
            (
                "Purpose",
                Gating::Structural {
                    breaks: "CBOR wire interop with other \
                             draft-ietf-rats-concise-ta-stores implementations",
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

    /// **The binding split has teeth** — verify ships one of each, so the
    /// distinction is exercised rather than asserted.
    #[test]
    fn binding_splits_into_ruling_and_mechanism() {
        // A ruling: CC could decide otherwise and nothing mechanically breaks.
        let ruled = ConsentDisposition::gating();
        assert_eq!(ruled.amendable_by(), Some("CC 3.4.5"));

        // A mechanism: no body can waive a pinned CDDL wire index.
        let mechanical = Purpose::gating();
        assert!(matches!(mechanical, Gating::Structural { .. }));
        assert_eq!(
            mechanical.amendable_by(),
            None,
            "a structural constraint has no amending body — the recourse is a bug report"
        );

        // Both bind. That is what the old single `Normative` got right, and
        // why conflating them was easy to miss.
        assert!(ruled.may_gate() && mechanical.may_gate());
    }

    /// A ruling and a mechanism, composed, can claim neither ground.
    #[test]
    fn mixing_a_ruling_with_a_mechanism_degrades() {
        let ruled = Gating::Normative {
            authority: "CC 3.4.5",
        };
        let mech = Gating::Structural {
            breaks: "wire interop",
        };
        assert_eq!(ruled.combine(mech), Gating::Measurement);
        assert_eq!(mech.combine(ruled), Gating::Measurement);

        // Same mechanism composed with itself survives.
        assert_eq!(mech.combine(mech), mech);
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

/// **Frame-relativity** — the arity ruling, exercised (CIRISOntology#3).
///
/// These mirror the Lean theorems rather than restating their conclusions, so
/// a change that quietly reintroduces a defaulted frame fails here.
#[cfg(test)]
mod frames {
    use super::*;
    use crate::federation_provenance::dim::ConsentDisposition;

    /// A harness that retained the record, and one that did not.
    const KEPT: Frame = Frame {
        declared_by: "test-harness/retains-all",
        retained: &["the only record"],
    };
    const LOST: Frame = Frame {
        declared_by: "test-harness/retains-nothing",
        retained: &[],
    };

    /// `repairability_not_intrinsic`: one fact, two frames, opposite verdicts.
    /// This is the whole reason the frame cannot be defaulted.
    #[test]
    fn repairability_is_not_a_property_of_the_fact() {
        assert!(KEPT.repairable("the only record"));
        assert!(!LOST.repairable("the only record"));
    }

    /// `frameInvariant_of_artifact_only`: a discriminator reading only the
    /// artifact cannot be moved by any frame. The other eleven, for free.
    #[test]
    fn artifact_only_discriminators_are_frame_invariant() {
        // An artifact-only predicate ignores its frame argument entirely.
        let artifact_only = |a: &str, _f: &Frame| a.starts_with("sha256:");
        for f in [&KEPT, &LOST] {
            assert!(artifact_only("sha256:abcd", f));
            assert!(!artifact_only("nope", f));
        }
    }

    /// **The enforcement point.** An undeclared frame is REFUSED, not filled in.
    #[test]
    fn testimonial_without_a_frame_is_refused() {
        let err = Arity::testimonial("attestation:self_report", None)
            .expect_err("an undeclared frame must be refused");
        assert_eq!(err.subject, "attestation:self_report");
        assert!(err.to_string().contains("frame-relative"));

        // With a frame, it constructs — and carries the frame it was made
        // against, so the assignment can be re-checked later.
        let ok = Arity::testimonial("attestation:self_report", Some(KEPT)).unwrap();
        assert_eq!(ok.frame(), Some(KEPT));
    }

    /// An artifact-only classification carries no frame — there is nothing for
    /// a frame to change.
    #[test]
    fn artifact_only_carries_no_frame() {
        assert_eq!(Arity::ArtifactOnly.frame(), None);
    }

    /// **Ask 3 — the dimension re-audit.** Exactly one of CC 3.4.5's four
    /// categories is assignable from the artifact alone, and it is the one
    /// whose carve-out rationale *is* re-readability ("a forger never consents
    /// to verification"). The other three refuse without a frame.
    #[test]
    fn dimension_dispositions_re_audited_under_the_frame_rule() {
        assert!(ConsentDisposition::ArtifactVerification.arity(None).is_ok());
        assert!(!ConsentDisposition::ArtifactVerification.is_frame_relative());

        for d in [
            ConsentDisposition::SelfReport,
            ConsentDisposition::LogInfrastructure,
            ConsentDisposition::AbuseResponse,
        ] {
            assert!(d.is_frame_relative());
            assert!(
                d.arity(None).is_err(),
                "{d:?} is frame-relative and must refuse an undeclared frame"
            );
            assert!(d.arity(Some(KEPT)).is_ok());
        }
    }

    /// The frame is not decoration: the SAME self-report is repairable under a
    /// harness that kept an independent record and not under one that did not.
    /// A defaulted frame would silently pick one of these answers.
    #[test]
    fn the_same_self_report_gets_opposite_verdicts_by_frame() {
        let subject = "the only record";
        let under_kept = ConsentDisposition::SelfReport.arity(Some(KEPT)).unwrap();
        let under_lost = ConsentDisposition::SelfReport.arity(Some(LOST)).unwrap();

        assert!(under_kept.frame().unwrap().repairable(subject));
        assert!(!under_lost.frame().unwrap().repairable(subject));
    }
}
