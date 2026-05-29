//! CEG §4 envelope-metadata fields + §0.5 self-attestation admission
//! (CIRISVerify#40, v4.2.0+).
//!
//! Per CIRISRegistry CEG §4 the canonical envelope carries two
//! optional metadata fields beyond the signed canonical bytes:
//!
//! - [`WitnessRelation`] — names the attester's relation to the
//!   attested entity. `self` / `external` / `derived`. Default
//!   `external`. Complements `epistemic_mode` (which names HOW the
//!   claim was formed) — `witness_relation` names WHO the attester
//!   is in relation to the attested.
//! - [`OversightMode`] — `HITL` / `HOTL` / `HOOTL`. The
//!   human-control gradient under which the attestation was
//!   produced. Default `None` (legacy contributions; consumer
//!   policy applies a per-cell default).
//!
//! ## CEG §0.5 fractal-self framing — admission, not gating
//!
//! A `witness_relation: self` attestation MUST be **admitted**
//! (not rejected for lack of cross-attestation). Per the §0.5
//! rule encoded in `MISSION.md` §1.5.1, cross-attestations are
//! upstream of the moment the entity speaks, not downstream gates
//! on it. A reviewer trained on PGP / X.509 / DID atomic-principal
//! frames will want a cross-witness admission gate before
//! accepting a self-attestation; that's the misread.
//!
//! [`admit_attestation`] returns a typed [`AdmissionDecision`]
//! that ALWAYS sets `admitted: true` for self-attestation on a
//! non-reserved dimension. Reserved-prefix attestations follow
//! the separate §7 rule (handled elsewhere).

use serde::{Deserialize, Serialize};

use crate::federation_provenance::AttestationEntry;

/// CEG §4 `witness_relation` field — the attester's relational
/// position to the attested entity.
///
/// Stable wire constants — a change is a federation-wide
/// coordination event. JSON serialization uses lowercase strings
/// matching the spec (`self` / `external` / `derived`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WitnessRelation {
    /// `self` — attester IS the attested entity. Self-attestation.
    /// `attesting_key_id == attested_key_id`. Per §0.5 fractal-self,
    /// admitted on non-reserved dimensions.
    #[serde(rename = "self")]
    Self_,
    /// `external` — attester observed independently. The default
    /// when no relation is declared (CEG §4: "Default `external`.").
    #[default]
    External,
    /// `derived` — attester inferred from other attestations or
    /// signed traces (e.g. F-3 detector attestations).
    Derived,
}

impl WitnessRelation {
    /// Stable wire-string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Self_ => "self",
            Self::External => "external",
            Self::Derived => "derived",
        }
    }
}

/// CEG §4 `oversight_mode` field — the human-control gradient
/// under which the attestation was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OversightMode {
    /// Human-In-The-Loop — every action gated by explicit human
    /// confirmation.
    Hitl,
    /// Human-On-The-Loop — human supervises but does not gate
    /// each action; intervenes on exception.
    Hotl,
    /// Human-Out-Of-The-Loop — fully autonomous within bounds.
    Hootl,
}

impl OversightMode {
    /// Stable wire-string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hitl => "HITL",
            Self::Hotl => "HOTL",
            Self::Hootl => "HOOTL",
        }
    }
}

/// CEG §4 envelope-metadata declaration — the side-channel fields
/// the envelope carries beyond its signed canonical bytes.
///
/// The conformance harness builds this to test §4 declaration +
/// §0.5 self-attestation admission.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeMetadata {
    /// CEG §4: default `external`.
    #[serde(default)]
    pub witness_relation: WitnessRelation,
    /// CEG §4: default `null` (legacy contributions; consumer policy
    /// applies a per-cell default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oversight_mode: Option<OversightMode>,
}

impl EnvelopeMetadata {
    /// Fresh metadata with both fields defaulted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: declare a witness relation.
    #[must_use]
    pub fn with_witness_relation(mut self, r: WitnessRelation) -> Self {
        self.witness_relation = r;
        self
    }

    /// Builder: declare an oversight mode.
    #[must_use]
    pub fn with_oversight_mode(mut self, m: OversightMode) -> Self {
        self.oversight_mode = Some(m);
        self
    }
}

/// CEG §0.5 self-attestation admission result.
///
/// Per the fractal-self framing, admission is the **default** — a
/// self-attestation with zero prior cross-attestations is admitted
/// (not gated for lack of vouching). The decision carries the
/// classified relation + the reason so a consumer applying its own
/// trust policy on top can discriminate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionDecision {
    /// Was the attestation admitted? `true` for all legitimate
    /// CEG §4 attestations on non-reserved dimensions, regardless
    /// of witness_relation. Reserved-prefix violations follow §7
    /// (handled in a separate code path).
    pub admitted: bool,
    /// The classified witness relation (derived from
    /// `attester == attested_key_id` when not explicitly declared,
    /// or carried verbatim when the envelope metadata declared it).
    pub witness_relation: WitnessRelation,
    /// Human-readable reason — what rule fired.
    pub reason: String,
}

/// Classify the witness relation of `entry` against the attested
/// entity `attested_key_id` and return the §0.5 admission decision.
///
/// Per CEG §0.5 fractal-self:
/// - `entry.attester == attested_key_id` → `WitnessRelation::Self_`,
///   admitted (the entity is the already-relationally-constituted
///   one speaking at this scale).
/// - Otherwise → `WitnessRelation::External`, admitted (the
///   attester observed independently).
///
/// `Derived` is not auto-classified — it must be declared in
/// envelope metadata. Use [`admit_with_declared_relation`] when the
/// caller declared the relation via [`EnvelopeMetadata`].
///
/// **No Cartesian gate.** A self-attestation with zero prior
/// cross-attestations is admitted, not rejected. Adding a
/// cross-witness gate before admission would be the misread MISSION.md
/// §1.5.1 explicitly rejects.
#[must_use]
pub fn admit_attestation(entry: &AttestationEntry, attested_key_id: &str) -> AdmissionDecision {
    if entry.attester == attested_key_id {
        AdmissionDecision {
            admitted: true,
            witness_relation: WitnessRelation::Self_,
            reason: format!(
                "§0.5 fractal-self admit: attester {:?} == attested_key_id; \
                 self-attestation admitted on non-reserved dimension {:?}",
                entry.attester, entry.dimension
            ),
        }
    } else {
        AdmissionDecision {
            admitted: true,
            witness_relation: WitnessRelation::External,
            reason: format!(
                "§4 admit: attester {:?} != attested_key_id {:?}; \
                 external attestation admitted on dimension {:?}",
                entry.attester, attested_key_id, entry.dimension
            ),
        }
    }
}

/// Admission decision when the caller has explicitly declared the
/// witness relation via envelope metadata. The declared relation is
/// trusted (the harness is the producer; the conformance test verifies
/// the substrate doesn't second-guess a legitimate declaration).
#[must_use]
pub fn admit_with_declared_relation(
    entry: &AttestationEntry,
    attested_key_id: &str,
    metadata: &EnvelopeMetadata,
) -> AdmissionDecision {
    let declared = metadata.witness_relation;
    // Sanity check: declared `self` only legitimate when
    // attester == attested. Otherwise the producer is lying.
    if declared == WitnessRelation::Self_ && entry.attester != attested_key_id {
        return AdmissionDecision {
            admitted: false,
            witness_relation: WitnessRelation::Self_,
            reason: format!(
                "envelope declared witness_relation:self but attester {:?} != attested_key_id {:?}",
                entry.attester, attested_key_id
            ),
        };
    }
    AdmissionDecision {
        admitted: true,
        witness_relation: declared,
        reason: format!(
            "envelope declared witness_relation:{} — admitted under §0.5 fractal-self",
            declared.as_str()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CEG §4 wire-string stability for witness_relation values.
    #[test]
    fn witness_relation_wire_strings_are_stable() {
        assert_eq!(WitnessRelation::Self_.as_str(), "self");
        assert_eq!(WitnessRelation::External.as_str(), "external");
        assert_eq!(WitnessRelation::Derived.as_str(), "derived");
    }

    /// CEG §4 wire-string stability for oversight_mode values.
    #[test]
    fn oversight_mode_wire_strings_are_stable() {
        assert_eq!(OversightMode::Hitl.as_str(), "HITL");
        assert_eq!(OversightMode::Hotl.as_str(), "HOTL");
        assert_eq!(OversightMode::Hootl.as_str(), "HOOTL");
    }

    #[test]
    fn default_witness_relation_is_external_per_section_4() {
        let m: EnvelopeMetadata = Default::default();
        assert_eq!(m.witness_relation, WitnessRelation::External);
        assert!(
            m.oversight_mode.is_none(),
            "default oversight_mode is null per §4"
        );
    }

    /// CEG §0.5 fractal-self ADMIT: a self-attestation with zero
    /// prior cross-attestations is admitted, not gated.
    #[test]
    fn section_0_5_self_attestation_with_zero_prior_is_admitted() {
        let entry = AttestationEntry::pass("attestation:self_verify", "agent-key-1");
        let decision = admit_attestation(&entry, "agent-key-1");
        assert!(
            decision.admitted,
            "§0.5 fractal-self: self-attestation MUST be admitted (no Cartesian gate)"
        );
        assert_eq!(decision.witness_relation, WitnessRelation::Self_);
        assert!(decision.reason.contains("§0.5"));
    }

    #[test]
    fn external_attestation_is_admitted_with_external_classification() {
        let entry = AttestationEntry::pass("attestation:license_validity", "registry-steward-us");
        let decision = admit_attestation(&entry, "agent-key-1");
        assert!(decision.admitted);
        assert_eq!(decision.witness_relation, WitnessRelation::External);
    }

    #[test]
    fn declared_metadata_carries_through_admission() {
        let entry = AttestationEntry::pass("attestation:self_verify", "agent-key-1");
        let meta = EnvelopeMetadata::new()
            .with_witness_relation(WitnessRelation::Derived)
            .with_oversight_mode(OversightMode::Hotl);
        let decision = admit_with_declared_relation(&entry, "agent-key-1", &meta);
        assert!(decision.admitted);
        assert_eq!(decision.witness_relation, WitnessRelation::Derived);
        assert_eq!(meta.oversight_mode, Some(OversightMode::Hotl));
    }

    /// Producer can't legitimately declare `witness_relation: self`
    /// when attester != attested — that's a lie and we reject.
    #[test]
    fn declared_self_with_attester_mismatch_is_rejected() {
        let entry = AttestationEntry::pass("attestation:license_validity", "registry-steward-us");
        let meta = EnvelopeMetadata::new().with_witness_relation(WitnessRelation::Self_);
        let decision = admit_with_declared_relation(&entry, "agent-key-1", &meta);
        assert!(
            !decision.admitted,
            "declared self with attester mismatch is a lie"
        );
        assert!(decision.reason.contains("declared witness_relation:self"));
    }

    #[test]
    fn json_round_trip_metadata() {
        let m = EnvelopeMetadata::new()
            .with_witness_relation(WitnessRelation::Derived)
            .with_oversight_mode(OversightMode::Hitl);
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"witness_relation\":\"derived\""));
        assert!(json.contains("\"oversight_mode\":\"HITL\""));
        let back: EnvelopeMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn legacy_metadata_with_no_oversight_mode_round_trips() {
        let m = EnvelopeMetadata::new();
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("oversight_mode"));
        let back: EnvelopeMetadata = serde_json::from_str(&json).unwrap();
        assert!(back.oversight_mode.is_none());
        assert_eq!(back.witness_relation, WitnessRelation::External);
    }

    /// Test the conformance harness's three acceptance criteria from #40:
    /// 1. self-attestation with zero prior cross-attestations is admitted
    /// 2. oversight_mode / witness_relation declared on a producer envelope
    ///    round-trip through verify
    #[test]
    fn conformance_harness_acceptance_criteria() {
        // Criterion 1: self-attestation admitted.
        let self_entry = AttestationEntry::pass("attestation:self_verify", "k1");
        let d1 = admit_attestation(&self_entry, "k1");
        assert!(d1.admitted);

        // Criterion 2: round-trip metadata declaration.
        let m = EnvelopeMetadata::new()
            .with_witness_relation(WitnessRelation::Self_)
            .with_oversight_mode(OversightMode::Hootl);
        let json = serde_json::to_string(&m).unwrap();
        let back: EnvelopeMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}
