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
