//! UI-shaped attestation bundle for the Epistemic Commons Framework
//! (CIRISVerify#36, v3.5.0+).
//!
//! [`AttestBundle`] reshapes an already-composed
//! [`FederationProvenance`] into the named-field JSON the
//! CIRISAgent 2.10.0 UI cards consume (ProfileScorecard,
//! Trust Topology). The bundle adds **zero** new verification logic —
//! it is a pure projection over the entry list verify already carries
//! per `MISSION.md` §1.4.
//!
//! ## Composition discipline
//!
//! Bundle construction is *only* a regrouping of
//! [`AttestationEntry`] items into the L1–L5 ladder + named sections
//! (`provenance`, `custody`, `transparency_log`, `cert_validity`).
//! No new attestations are emitted here, no verdicts are composed.
//! The full entry list remains addressable via
//! [`AttestBundle::federation_provenance`] so consumers that need the
//! raw shape never lose information.
//!
//! ## Trait discipline (PyO3 cohabitation)
//!
//! Per the discipline comment on #36, the PyO3 surface for the bundle
//! is a thin marshaller over this Rust type — it serializes the
//! bundle to JSON and returns it. No orchestration on the Python
//! side; no chain-walk logic reimplemented at the FFI boundary.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::federation_provenance::{dim, AttestationEntry, FederationProvenance};

/// One rung of the L1–L5 attestation ladder, projected for UI display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LadderRung {
    /// Did the underlying [`AttestationEntry`] pass under the
    /// dimension's polarity?
    pub passed: bool,
    /// Who produced the attestation (e.g., `"ciris-verify"`, a
    /// registry steward `key_id`).
    pub attester: String,
    /// Optional source reference — a persist row hash, registry URL,
    /// STH hash. Lets the UI link back to the underlying record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}

impl From<&AttestationEntry> for LadderRung {
    fn from(e: &AttestationEntry) -> Self {
        Self {
            passed: e.is_pass(),
            attester: e.attester.clone(),
            source_ref: e.source_ref.clone(),
        }
    }
}

/// The L1–L5 attestation ladder as a named-field projection.
///
/// Each rung is `Option<LadderRung>` — `None` means *not checked* (per
/// FSD-002 §3.2 absence is not implicit pass). The UI renders absent
/// rungs as neutral / "unknown", not as failures.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttestationLadder {
    /// L1 self-verification ("who watches the watchmen").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1: Option<LadderRung>,
    /// L2 hardware attestation (TPM / Keystore / Secure Enclave).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2: Option<LadderRung>,
    /// L3 registry consensus (2-of-3 multi-source).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l3: Option<LadderRung>,
    /// L4 license validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l4: Option<LadderRung>,
    /// L5 agent integrity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l5: Option<LadderRung>,
}

/// Provenance block — SLSA build level + per-target build-manifest
/// hashes (or source refs).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceBlock {
    /// Maximum SLSA level attested under any `provenance:slsa:{level}`
    /// entry. `None` when no SLSA entries are present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slsa_level: Option<u8>,
    /// Map from target triple → source reference for the manifest
    /// (typically the manifest hash). Empty when no build-manifest
    /// dimensions were checked. Values come from
    /// [`AttestationEntry::source_ref`]; the dimension confirms the
    /// hash equality, the `source_ref` carries the hash itself.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub build_manifest: BTreeMap<String, String>,
}

/// Hardware-custody block — where the seed lives.
///
/// `platform` is one of the FSD-002 §3.2 platforms (`tpm`,
/// `ios_secure_enclave`, `android_keystore`, `software_fallback`).
/// `verified` is `false` for `software_fallback` (the one variant
/// that structurally caps at `UNLICENSED_COMMUNITY`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CustodyBlock {
    /// Platform string (lowercased). Empty when no custody entry
    /// was emitted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub platform: String,
    /// Did the custody dimension pass?
    pub verified: bool,
}

/// Transparency-log proof block.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TransparencyLogBlock {
    /// RFC 6962 inclusion proof verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion: Option<TransparencyLogProof>,
    /// RFC 6962 consistency proof verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency: Option<TransparencyLogProof>,
}

/// One transparency-log proof verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransparencyLogProof {
    /// Did the proof verify?
    pub verified: bool,
    /// Who attested.
    pub attester: String,
    /// Optional source reference (e.g., STH hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}

impl From<&AttestationEntry> for TransparencyLogProof {
    fn from(e: &AttestationEntry) -> Self {
        Self {
            verified: e.is_pass(),
            attester: e.attester.clone(),
            source_ref: e.source_ref.clone(),
        }
    }
}

/// Certificate-validity entry for one authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertValidityEntry {
    /// Did the authority's certificate validate?
    pub valid: bool,
    /// Who attested.
    pub attester: String,
    /// Optional source reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}

impl From<&AttestationEntry> for CertValidityEntry {
    fn from(e: &AttestationEntry) -> Self {
        Self {
            valid: e.is_pass(),
            attester: e.attester.clone(),
            source_ref: e.source_ref.clone(),
        }
    }
}

/// UI-shaped attestation bundle (CIRISVerify#36).
///
/// Pure projection over a [`FederationProvenance`] — no new
/// verification, no policy. The full entry list is preserved in
/// [`AttestBundle::federation_provenance`] for consumers that need
/// the raw shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestBundle {
    /// The key (identity, credential, etc.) this bundle attests to.
    pub key_id: String,
    /// L1–L5 ladder.
    pub ladder: AttestationLadder,
    /// SLSA + per-target build manifest provenance.
    pub provenance: ProvenanceBlock,
    /// Hardware custody.
    pub custody: CustodyBlock,
    /// Transparency-log proofs.
    pub transparency_log: TransparencyLogBlock,
    /// Cert validity per authority.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cert_validity: BTreeMap<String, CertValidityEntry>,
    /// Any rollback signal present? Verify owns the `rollback_detected:*`
    /// namespace; a non-zero count is a hard signal (FSD-002 §3.2).
    pub rollback_detected: bool,
    /// The full underlying provenance carrier. Consumers needing the
    /// raw attestation list, cache age, or persist row hash read it
    /// here.
    pub federation_provenance: FederationProvenance,
}

impl AttestBundle {
    /// Project a [`FederationProvenance`] into a UI bundle for
    /// `key_id`. No verification is performed — only regrouping.
    ///
    /// When two entries cover the same ladder level (e.g. one from
    /// the [`crate::unified::FullAttestationResult::to_federation_provenance`]
    /// pass and a richer one from a per-attester `to_attestation_entries`
    /// later), the **first** one wins — the bundle is composed in
    /// emission order and entries are append-only per
    /// [`FederationProvenance::attestations_consumed`].
    #[must_use]
    pub fn from_federation_provenance(
        key_id: impl Into<String>,
        provenance: FederationProvenance,
    ) -> Self {
        let mut ladder = AttestationLadder::default();
        let mut custody = CustodyBlock::default();
        let mut transparency_log = TransparencyLogBlock::default();
        let mut build_manifest: BTreeMap<String, String> = BTreeMap::new();
        let mut cert_validity: BTreeMap<String, CertValidityEntry> = BTreeMap::new();
        let mut slsa_level: Option<u8> = None;
        let mut rollback_detected = false;

        for entry in &provenance.attestations_consumed {
            if entry.is_rollback() {
                rollback_detected = true;
                continue;
            }

            let d = entry.dimension.as_str();

            // Constant (unparameterized) dimensions — first entry per
            // slot wins.
            let matched_constant = match d {
                dim::L1_SELF_VERIFY => {
                    ladder.l1.get_or_insert_with(|| LadderRung::from(entry));
                    true
                },
                dim::L2_HARDWARE => {
                    ladder.l2.get_or_insert_with(|| LadderRung::from(entry));
                    true
                },
                dim::L3_REGISTRY_CONSENSUS => {
                    ladder.l3.get_or_insert_with(|| LadderRung::from(entry));
                    true
                },
                dim::L4_LICENSE_VALIDITY => {
                    ladder.l4.get_or_insert_with(|| LadderRung::from(entry));
                    true
                },
                dim::L5_AGENT_INTEGRITY => {
                    ladder.l5.get_or_insert_with(|| LadderRung::from(entry));
                    true
                },
                dim::TRANSPARENCY_LOG_INCLUSION => {
                    transparency_log
                        .inclusion
                        .get_or_insert_with(|| TransparencyLogProof::from(entry));
                    true
                },
                dim::TRANSPARENCY_LOG_CONSISTENCY => {
                    transparency_log
                        .consistency
                        .get_or_insert_with(|| TransparencyLogProof::from(entry));
                    true
                },
                _ => false,
            };
            if matched_constant {
                continue;
            }

            // Parameterized dimensions.
            if let Some(level_str) = d.strip_prefix("provenance:slsa:") {
                if entry.is_pass() {
                    if let Ok(level) = level_str.parse::<u8>() {
                        slsa_level = Some(slsa_level.map_or(level, |cur| cur.max(level)));
                    }
                }
            } else if let Some(target) = d.strip_prefix("provenance:build_manifest:") {
                let source_ref = entry.source_ref.clone().unwrap_or_default();
                build_manifest
                    .entry(target.to_string())
                    .or_insert(source_ref);
            } else if let Some(platform) = d.strip_prefix("hardware_custody:") {
                if custody.platform.is_empty() {
                    custody.platform = platform.to_string();
                    custody.verified = entry.is_pass();
                }
            } else if let Some(authority) = d.strip_prefix("cert_validity:") {
                cert_validity
                    .entry(authority.to_string())
                    .or_insert_with(|| CertValidityEntry::from(entry));
            }
            // Unknown / future dimensions are preserved in
            // federation_provenance.attestations_consumed below; no
            // projection here.
        }

        Self {
            key_id: key_id.into(),
            ladder,
            provenance: ProvenanceBlock {
                slsa_level,
                build_manifest,
            },
            custody,
            transparency_log,
            cert_validity,
            rollback_detected,
            federation_provenance: provenance,
        }
    }
}

impl crate::unified::FullAttestationResult {
    /// Convenience: compose a [`FederationProvenance`] from `self` and
    /// project it into an [`AttestBundle`] for `key_id`. Equivalent
    /// to `AttestBundle::from_federation_provenance(key_id,
    /// self.to_federation_provenance(attester))`.
    #[must_use]
    pub fn to_attest_bundle(&self, key_id: &str, attester: &str) -> AttestBundle {
        AttestBundle::from_federation_provenance(key_id, self.to_federation_provenance(attester))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation_provenance::AttestationEntry;

    fn fp(entries: Vec<AttestationEntry>) -> FederationProvenance {
        let mut b = FederationProvenance::builder();
        for e in entries {
            b = b.attestation(e);
        }
        b.build()
    }

    #[test]
    fn empty_provenance_yields_all_none_ladder() {
        let bundle =
            AttestBundle::from_federation_provenance("k1", FederationProvenance::default());
        assert_eq!(bundle.key_id, "k1");
        assert!(bundle.ladder.l1.is_none());
        assert!(bundle.ladder.l2.is_none());
        assert!(bundle.ladder.l3.is_none());
        assert!(bundle.ladder.l4.is_none());
        assert!(bundle.ladder.l5.is_none());
        assert!(!bundle.rollback_detected);
        assert!(bundle.custody.platform.is_empty());
        assert!(bundle.cert_validity.is_empty());
        assert!(bundle.provenance.build_manifest.is_empty());
        assert!(bundle.provenance.slsa_level.is_none());
    }

    #[test]
    fn full_l1_l5_pass_populates_ladder() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::L1_SELF_VERIFY, "ciris-verify"),
            AttestationEntry::pass(dim::L2_HARDWARE, "ciris-verify"),
            AttestationEntry::pass(dim::L3_REGISTRY_CONSENSUS, "ciris-verify"),
            AttestationEntry::pass(dim::L4_LICENSE_VALIDITY, "registry-steward-us"),
            AttestationEntry::pass(dim::L5_AGENT_INTEGRITY, "ciris-verify"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("agent-key-1", prov);
        assert!(bundle.ladder.l1.as_ref().unwrap().passed);
        assert!(bundle.ladder.l2.as_ref().unwrap().passed);
        assert!(bundle.ladder.l3.as_ref().unwrap().passed);
        assert!(bundle.ladder.l4.as_ref().unwrap().passed);
        assert!(bundle.ladder.l5.as_ref().unwrap().passed);
        assert_eq!(
            bundle.ladder.l4.as_ref().unwrap().attester,
            "registry-steward-us"
        );
    }

    #[test]
    fn rollback_entry_sets_rollback_detected() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::L1_SELF_VERIFY, "ciris-verify"),
            AttestationEntry::rollback("license_revocation_revision", "ciris-verify"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert!(bundle.rollback_detected);
        // Rollback entries do not appear on the ladder.
        assert!(bundle.ladder.l1.as_ref().unwrap().passed);
    }

    #[test]
    fn build_manifest_target_carries_source_ref() {
        let prov = fp(vec![AttestationEntry::pass(
            dim::provenance_build_manifest("aarch64-apple-ios"),
            "verify-steward-2026",
        )
        .with_source_ref("sha256:deadbeef")]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert_eq!(
            bundle.provenance.build_manifest.get("aarch64-apple-ios"),
            Some(&"sha256:deadbeef".to_string())
        );
    }

    #[test]
    fn slsa_level_takes_maximum() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::provenance_slsa(1), "att"),
            AttestationEntry::pass(dim::provenance_slsa(3), "att"),
            AttestationEntry::pass(dim::provenance_slsa(2), "att"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert_eq!(bundle.provenance.slsa_level, Some(3));
    }

    #[test]
    fn slsa_level_ignores_failing_entries() {
        let prov = fp(vec![
            AttestationEntry::fail(dim::provenance_slsa(3), "att"),
            AttestationEntry::pass(dim::provenance_slsa(1), "att"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        // Only level 1 passed; level 3 failed and is not counted.
        assert_eq!(bundle.provenance.slsa_level, Some(1));
    }

    #[test]
    fn custody_populated_from_hardware_custody_entry() {
        let prov = fp(vec![AttestationEntry::pass(
            dim::hardware_custody("tpm"),
            "ciris-verify",
        )]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert_eq!(bundle.custody.platform, "tpm");
        assert!(bundle.custody.verified);
    }

    #[test]
    fn custody_software_fallback_is_unverified() {
        let prov = fp(vec![AttestationEntry::fail(
            dim::hardware_custody("software_fallback"),
            "ciris-verify",
        )]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert_eq!(bundle.custody.platform, "software_fallback");
        assert!(!bundle.custody.verified);
    }

    #[test]
    fn cert_validity_keyed_by_authority() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::cert_validity("registry-steward-us"), "ciris-verify"),
            AttestationEntry::fail(dim::cert_validity("registry-steward-eu"), "ciris-verify"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert!(
            bundle
                .cert_validity
                .get("registry-steward-us")
                .unwrap()
                .valid
        );
        assert!(
            !bundle
                .cert_validity
                .get("registry-steward-eu")
                .unwrap()
                .valid
        );
    }

    #[test]
    fn transparency_log_inclusion_and_consistency() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::TRANSPARENCY_LOG_INCLUSION, "ciris-verify")
                .with_source_ref("sth:abc123"),
            AttestationEntry::fail(dim::TRANSPARENCY_LOG_CONSISTENCY, "witness-eu"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        let inc = bundle.transparency_log.inclusion.as_ref().unwrap();
        assert!(inc.verified);
        assert_eq!(inc.source_ref.as_deref(), Some("sth:abc123"));
        let cons = bundle.transparency_log.consistency.as_ref().unwrap();
        assert!(!cons.verified);
        assert_eq!(cons.attester, "witness-eu");
    }

    #[test]
    fn first_entry_per_dimension_wins_on_ladder() {
        // If two L1 entries exist (e.g. composed from two sources),
        // the first wins. This preserves emission-order semantics.
        let prov = fp(vec![
            AttestationEntry::pass(dim::L1_SELF_VERIFY, "ciris-verify"),
            AttestationEntry::fail(dim::L1_SELF_VERIFY, "second-attester"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        let l1 = bundle.ladder.l1.as_ref().unwrap();
        assert!(l1.passed);
        assert_eq!(l1.attester, "ciris-verify");
    }

    #[test]
    fn federation_provenance_is_preserved_losslessly() {
        let entries = vec![
            AttestationEntry::pass(dim::L1_SELF_VERIFY, "v").with_source_ref("ref1"),
            AttestationEntry::pass(dim::L4_LICENSE_VALIDITY, "r"),
            // An unknown dimension — must not be lost.
            AttestationEntry::pass("custom:dimension:future", "v"),
        ];
        let prov = fp(entries.clone());
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert_eq!(bundle.federation_provenance.attestations_consumed.len(), 3);
        assert!(bundle
            .federation_provenance
            .entry_for("custom:dimension:future")
            .is_some());
    }

    #[test]
    fn json_shape_matches_36_proposal() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::L1_SELF_VERIFY, "ciris-verify"),
            AttestationEntry::pass(dim::L2_HARDWARE, "ciris-verify"),
            AttestationEntry::pass(dim::hardware_custody("tpm"), "ciris-verify"),
            AttestationEntry::pass(dim::provenance_slsa(2), "registry-steward-us"),
            AttestationEntry::pass(
                dim::provenance_build_manifest("x86_64-unknown-linux-gnu"),
                "verify-steward-2026",
            )
            .with_source_ref("sha256:cafef00d"),
            AttestationEntry::pass(dim::cert_validity("registry-steward-us"), "ciris-verify"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("agent-key-1", prov);
        let j: serde_json::Value = serde_json::to_value(&bundle).unwrap();
        assert_eq!(j["key_id"], "agent-key-1");
        assert_eq!(j["ladder"]["l1"]["passed"], true);
        assert_eq!(j["ladder"]["l2"]["passed"], true);
        assert_eq!(j["provenance"]["slsa_level"], 2);
        assert_eq!(
            j["provenance"]["build_manifest"]["x86_64-unknown-linux-gnu"],
            "sha256:cafef00d"
        );
        assert_eq!(j["custody"]["platform"], "tpm");
        assert_eq!(j["custody"]["verified"], true);
        assert_eq!(j["cert_validity"]["registry-steward-us"]["valid"], true);
        assert_eq!(j["rollback_detected"], false);
        // The full provenance carrier is still addressable.
        assert!(j["federation_provenance"]["attestations_consumed"].is_array());
    }

    #[test]
    fn json_round_trip() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::L1_SELF_VERIFY, "v"),
            AttestationEntry::rollback("license_revocation_revision", "v"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: AttestBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    /// End-to-end: take a `FullAttestationResult`, compose the
    /// bundle via the convenience method.
    #[test]
    fn full_attestation_result_to_bundle_via_convenience_method() {
        use crate::unified::{
            FullAttestationResult, KeyAttestationResult, SelfVerificationResult, SourceCheckResult,
        };

        let r = FullAttestationResult {
            valid: true,
            level: 3,
            level_pending: false,
            self_verification: Some(SelfVerificationResult {
                binary_valid: true,
                functions_valid: true,
                valid: true,
                binary_version: "3.5.0".into(),
                target: "x86_64-unknown-linux-gnu".into(),
                binary_hash: "deadbeef".into(),
                expected_hash: Some("deadbeef".into()),
                functions_checked: 10,
                functions_passed: 10,
                registry_reachable: true,
                error: None,
            }),
            key_attestation: Some(KeyAttestationResult {
                key_type: "portal".into(),
                hardware_type: "tpm".into(),
                has_valid_signature: true,
                binary_version: "3.5.0".into(),
                running_in_vm: false,
                classical_signature: "abc".into(),
                pqc_available: true,
                hardware_backed: true,
                storage_mode: "TPM".into(),
                ed25519_fingerprint: "fp".into(),
                mldsa_fingerprint: None,
                registry_key_status: "active".into(),
                platform_os: "linux".into(),
            }),
            registry_key_status: "active".into(),
            device_attestation: None,
            file_integrity: None,
            python_integrity: None,
            module_integrity: None,
            sources: SourceCheckResult {
                dns_us_reachable: true,
                dns_us_valid: true,
                dns_us_error: None,
                dns_eu_reachable: true,
                dns_eu_valid: true,
                dns_eu_error: None,
                https_reachable: true,
                https_valid: true,
                https_error: None,
                validation_status: "AllSourcesAgree".into(),
            },
            audit_trail: None,
            checks_passed: 5,
            checks_total: 5,
            diagnostics: String::new(),
            errors: vec![],
            timestamp: 0,
        };

        let bundle = r.to_attest_bundle("agent-key-1", "ciris-verify");
        assert_eq!(bundle.key_id, "agent-key-1");
        assert!(bundle.ladder.l1.as_ref().unwrap().passed);
        assert!(bundle.ladder.l2.as_ref().unwrap().passed);
        assert!(bundle.ladder.l3.as_ref().unwrap().passed);
        assert_eq!(bundle.custody.platform, "tpm");
        assert!(bundle.custody.verified);
    }
}
