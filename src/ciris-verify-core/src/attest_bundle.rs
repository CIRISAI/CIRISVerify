//! Measurement-shaped attestation bundle for downstream consumers
//! (CIRISVerify#36, v3.6.0+).
//!
//! [`AttestBundle`] regroups an already-composed
//! [`FederationProvenance`] into named-field measurements. Each field
//! states **what was measured** — not where it sits in any
//! consumer-defined trust ladder. Per `MISSION.md` §1.4, verify
//! carries measurements; tier / level scoring is sugar the consumer
//! applies on top.
//!
//! ## Composition discipline
//!
//! Bundle construction is *only* a regrouping of
//! [`AttestationEntry`] items into named measurement fields
//! (`self_verification`, `hardware_attestation`, `registry_consensus`,
//! `license_validity`, `agent_integrity`) plus the supporting
//! sections (`provenance`, `hardware_custody`, `transparency_log`,
//! `cert_validity`, `rollback_detected`). No new attestations are
//! emitted here, no verdicts are composed, no levels are assigned.
//! The full entry list remains addressable via
//! [`AttestBundle::federation_provenance`] so consumers that need the
//! raw shape never lose information.
//!
//! ## FFI / Python wiring
//!
//! The bundle is exposed through the C FFI as a stateless projection
//! function and re-exposed in the Python binding as
//! `attest_bundle_from_attestation(attestation_json, key_id,
//! attester)`. Both are pure marshallers — no orchestration on the
//! Python side; no chain-walk logic reimplemented at the FFI
//! boundary.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::federation_provenance::{dim, AttestationEntry, FederationProvenance};

/// One measurement fact — the boolean-via-score result of a single
/// attestation dimension, plus its attester and (optional) source
/// reference. Unlike a "verdict," a fact only states what was
/// observed; the consumer decides what (if anything) the fact
/// implies for their trust policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationFact {
    /// Did the underlying [`AttestationEntry`] pass under the
    /// dimension's polarity?
    pub passed: bool,
    /// Who produced the attestation (e.g., `"ciris-verify"`, a
    /// registry steward `key_id`).
    pub attester: String,
    /// Optional source reference — a persist row hash, registry URL,
    /// STH hash. Lets the consumer link back to the underlying record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}

impl From<&AttestationEntry> for AttestationFact {
    fn from(e: &AttestationEntry) -> Self {
        Self {
            passed: e.is_pass(),
            attester: e.attester.clone(),
            source_ref: e.source_ref.clone(),
        }
    }
}

/// SLSA + per-target build-manifest provenance + skill-import
/// provenance + per-locale build-manifest leaves.
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
    /// Per-locale build-manifest leaves (CIRISVerify#37 / Registry#29,
    /// v3.8.0+). Outer key is the target triple (same domain as
    /// [`Self::build_manifest`]); inner key is the ISO `lang_code`.
    /// The parent entry in [`Self::build_manifest`] is the Merkle root
    /// over the per-locale leaves — when both populate, a consumer
    /// can detect a locale-targeted attack (e.g. a Burmese doctrinal
    /// substitution where the parent passes but the `my` leaf fails).
    /// Empty when no per-locale dimensions were checked.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub build_manifest_per_locale: BTreeMap<String, BTreeMap<String, AttestationFact>>,
    /// Community-skill import provenance (CIRISVerify#37 / Registry#28,
    /// v3.8.0+). Key is the full `source` field of
    /// `provenance:skill_import:{source}` (e.g.
    /// `registry:ciris-registry-us`, `direct:https://example.org/skill.tar.gz`,
    /// `local:/opt/ciris/skills/triage.tar.gz`). Empty when no
    /// skill-import dimensions were checked.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub skill_imports: BTreeMap<String, AttestationFact>,
}

/// Hardware-custody fact — where the seed lives.
///
/// `platform` is one of the FSD-002 §3.2 platforms (`tpm`,
/// `ios_secure_enclave`, `android_keystore`, `software_fallback`).
/// `verified` is `false` for `software_fallback` (the one variant
/// without hardware backing).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HardwareCustody {
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
    pub inclusion: Option<AttestationFact>,
    /// RFC 6962 consistency proof verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency: Option<AttestationFact>,
}

/// Measurement-shaped attestation bundle (CIRISVerify#36, v3.6.0+).
///
/// Pure projection over a [`FederationProvenance`] — no new
/// verification, no policy, no levels. Each field names what was
/// measured. Consumers compose tiers / levels / verdicts under their
/// own policy.
///
/// The full entry list is preserved in
/// [`AttestBundle::federation_provenance`] for consumers that need
/// the raw shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestBundle {
    /// The key (identity, credential, etc.) this bundle attests to.
    pub key_id: String,

    // ---- Direct attestation measurements ----
    /// Self-verification: the running CIRISVerify binary attests
    /// itself against its function manifest ("who watches the
    /// watchmen"). FSD-002 dim `attestation:self_verify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_verification: Option<AttestationFact>,
    /// Hardware-rooted attestation (TPM 2.0 / Android Keystore / iOS
    /// Secure Enclave). FSD-002 dim `attestation:hardware`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_attestation: Option<AttestationFact>,
    /// Multi-source registry consensus (2-of-3 by default).
    /// FSD-002 dim `attestation:registry_consensus`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_consensus: Option<AttestationFact>,
    /// Registry-signed, verify-verified license validity.
    /// FSD-002 dim `attestation:license_validity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_validity: Option<AttestationFact>,
    /// Agent source-tree byte-equal against registered manifest.
    /// FSD-002 dim `attestation:agent_integrity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_integrity: Option<AttestationFact>,

    // ---- Supporting measurements ----
    /// SLSA + per-target build manifest provenance.
    pub provenance: ProvenanceBlock,
    /// Where the seed lives (hardware custody).
    pub hardware_custody: HardwareCustody,
    /// Transparency-log inclusion / consistency proofs.
    pub transparency_log: TransparencyLogBlock,
    /// Cert validity keyed by authority id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cert_validity: BTreeMap<String, AttestationFact>,
    /// Was any rollback signal present? Verify owns the
    /// `rollback_detected:*` namespace; a non-zero count is a hard
    /// signal (FSD-002 §3.2). Polarity-negative entries don't appear
    /// elsewhere in the bundle.
    pub rollback_detected: bool,

    /// The full underlying provenance carrier. Consumers needing the
    /// raw attestation list, cache age, or persist row hash read it
    /// here.
    pub federation_provenance: FederationProvenance,
}

impl AttestBundle {
    /// Project a [`FederationProvenance`] into a measurement bundle
    /// for `key_id`. No verification is performed — only regrouping.
    ///
    /// When two entries cover the same dimension (e.g. one from the
    /// [`crate::unified::FullAttestationResult::to_federation_provenance`]
    /// pass and a richer one from a per-attester
    /// `to_attestation_entries` later), the **first** one wins — the
    /// bundle is composed in emission order and entries are
    /// append-only per
    /// [`FederationProvenance::attestations_consumed`].
    #[must_use]
    pub fn from_federation_provenance(
        key_id: impl Into<String>,
        provenance: FederationProvenance,
    ) -> Self {
        let mut self_verification: Option<AttestationFact> = None;
        let mut hardware_attestation: Option<AttestationFact> = None;
        let mut registry_consensus: Option<AttestationFact> = None;
        let mut license_validity: Option<AttestationFact> = None;
        let mut agent_integrity: Option<AttestationFact> = None;
        let mut hardware_custody = HardwareCustody::default();
        let mut transparency_log = TransparencyLogBlock::default();
        let mut build_manifest: BTreeMap<String, String> = BTreeMap::new();
        let mut build_manifest_per_locale: BTreeMap<String, BTreeMap<String, AttestationFact>> =
            BTreeMap::new();
        let mut skill_imports: BTreeMap<String, AttestationFact> = BTreeMap::new();
        let mut cert_validity: BTreeMap<String, AttestationFact> = BTreeMap::new();
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
                dim::SELF_VERIFY => {
                    self_verification.get_or_insert_with(|| AttestationFact::from(entry));
                    true
                },
                dim::HARDWARE => {
                    hardware_attestation.get_or_insert_with(|| AttestationFact::from(entry));
                    true
                },
                dim::REGISTRY_CONSENSUS => {
                    registry_consensus.get_or_insert_with(|| AttestationFact::from(entry));
                    true
                },
                dim::LICENSE_VALIDITY => {
                    license_validity.get_or_insert_with(|| AttestationFact::from(entry));
                    true
                },
                dim::AGENT_INTEGRITY => {
                    agent_integrity.get_or_insert_with(|| AttestationFact::from(entry));
                    true
                },
                dim::TRANSPARENCY_LOG_INCLUSION => {
                    transparency_log
                        .inclusion
                        .get_or_insert_with(|| AttestationFact::from(entry));
                    true
                },
                dim::TRANSPARENCY_LOG_CONSISTENCY => {
                    transparency_log
                        .consistency
                        .get_or_insert_with(|| AttestationFact::from(entry));
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
            } else if let Some(rest) = d.strip_prefix("provenance:build_manifest:") {
                // Two sub-shapes share this prefix:
                //   provenance:build_manifest:{target}                       — parent Merkle root
                //   provenance:build_manifest:{target}:locale:{lang_code}    — per-locale leaf (#37)
                // The locale suffix is detected by the literal `:locale:`
                // delimiter, splitting `{target}` from `{lang_code}`.
                if let Some((target, lang)) = rest.split_once(":locale:") {
                    build_manifest_per_locale
                        .entry(target.to_string())
                        .or_default()
                        .entry(lang.to_string())
                        .or_insert_with(|| AttestationFact::from(entry));
                } else {
                    let source_ref = entry.source_ref.clone().unwrap_or_default();
                    build_manifest.entry(rest.to_string()).or_insert(source_ref);
                }
            } else if let Some(source) = d.strip_prefix("provenance:skill_import:") {
                skill_imports
                    .entry(source.to_string())
                    .or_insert_with(|| AttestationFact::from(entry));
            } else if let Some(platform) = d.strip_prefix("hardware_custody:") {
                if hardware_custody.platform.is_empty() {
                    hardware_custody.platform = platform.to_string();
                    hardware_custody.verified = entry.is_pass();
                }
            } else if let Some(authority) = d.strip_prefix("cert_validity:") {
                cert_validity
                    .entry(authority.to_string())
                    .or_insert_with(|| AttestationFact::from(entry));
            }
            // Unknown / future dimensions are preserved in
            // federation_provenance.attestations_consumed below; no
            // projection here.
        }

        Self {
            key_id: key_id.into(),
            self_verification,
            hardware_attestation,
            registry_consensus,
            license_validity,
            agent_integrity,
            provenance: ProvenanceBlock {
                slsa_level,
                build_manifest,
                build_manifest_per_locale,
                skill_imports,
            },
            hardware_custody,
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
    fn empty_provenance_yields_all_none_measurements() {
        let bundle =
            AttestBundle::from_federation_provenance("k1", FederationProvenance::default());
        assert_eq!(bundle.key_id, "k1");
        assert!(bundle.self_verification.is_none());
        assert!(bundle.hardware_attestation.is_none());
        assert!(bundle.registry_consensus.is_none());
        assert!(bundle.license_validity.is_none());
        assert!(bundle.agent_integrity.is_none());
        assert!(!bundle.rollback_detected);
        assert!(bundle.hardware_custody.platform.is_empty());
        assert!(bundle.cert_validity.is_empty());
        assert!(bundle.provenance.build_manifest.is_empty());
        assert!(bundle.provenance.slsa_level.is_none());
    }

    #[test]
    fn all_measurements_pass_populates_named_fields() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::SELF_VERIFY, "ciris-verify"),
            AttestationEntry::pass(dim::HARDWARE, "ciris-verify"),
            AttestationEntry::pass(dim::REGISTRY_CONSENSUS, "ciris-verify"),
            AttestationEntry::pass(dim::LICENSE_VALIDITY, "registry-steward-us"),
            AttestationEntry::pass(dim::AGENT_INTEGRITY, "ciris-verify"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("agent-key-1", prov);
        assert!(bundle.self_verification.as_ref().unwrap().passed);
        assert!(bundle.hardware_attestation.as_ref().unwrap().passed);
        assert!(bundle.registry_consensus.as_ref().unwrap().passed);
        assert!(bundle.license_validity.as_ref().unwrap().passed);
        assert!(bundle.agent_integrity.as_ref().unwrap().passed);
        assert_eq!(
            bundle.license_validity.as_ref().unwrap().attester,
            "registry-steward-us"
        );
    }

    #[test]
    fn rollback_entry_sets_rollback_detected() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::SELF_VERIFY, "ciris-verify"),
            AttestationEntry::rollback("license_revocation_revision", "ciris-verify"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert!(bundle.rollback_detected);
        // Rollback entries do not appear under named measurements.
        assert!(bundle.self_verification.as_ref().unwrap().passed);
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
    fn hardware_custody_populated_from_hardware_custody_entry() {
        let prov = fp(vec![AttestationEntry::pass(
            dim::hardware_custody("tpm"),
            "ciris-verify",
        )]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert_eq!(bundle.hardware_custody.platform, "tpm");
        assert!(bundle.hardware_custody.verified);
    }

    #[test]
    fn hardware_custody_software_fallback_is_unverified() {
        let prov = fp(vec![AttestationEntry::fail(
            dim::hardware_custody("software_fallback"),
            "ciris-verify",
        )]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert_eq!(bundle.hardware_custody.platform, "software_fallback");
        assert!(!bundle.hardware_custody.verified);
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
                .passed
        );
        assert!(
            !bundle
                .cert_validity
                .get("registry-steward-eu")
                .unwrap()
                .passed
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
        assert!(inc.passed);
        assert_eq!(inc.source_ref.as_deref(), Some("sth:abc123"));
        let cons = bundle.transparency_log.consistency.as_ref().unwrap();
        assert!(!cons.passed);
        assert_eq!(cons.attester, "witness-eu");
    }

    #[test]
    fn first_entry_per_dimension_wins() {
        // If two self_verification entries exist, the first wins.
        // This preserves emission-order semantics.
        let prov = fp(vec![
            AttestationEntry::pass(dim::SELF_VERIFY, "ciris-verify"),
            AttestationEntry::fail(dim::SELF_VERIFY, "second-attester"),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        let sv = bundle.self_verification.as_ref().unwrap();
        assert!(sv.passed);
        assert_eq!(sv.attester, "ciris-verify");
    }

    #[test]
    fn federation_provenance_is_preserved_losslessly() {
        let entries = vec![
            AttestationEntry::pass(dim::SELF_VERIFY, "v").with_source_ref("ref1"),
            AttestationEntry::pass(dim::LICENSE_VALIDITY, "r"),
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
    fn json_shape_names_measurements_not_levels() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::SELF_VERIFY, "ciris-verify"),
            AttestationEntry::pass(dim::HARDWARE, "ciris-verify"),
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
        // Measurements are named by what they are — no l1/l2/l3/l4/l5 sugar.
        assert_eq!(j["self_verification"]["passed"], true);
        assert_eq!(j["hardware_attestation"]["passed"], true);
        // No ladder field — those keys must not exist.
        assert!(j.get("ladder").is_none());
        assert!(j.get("l1").is_none());
        assert_eq!(j["provenance"]["slsa_level"], 2);
        assert_eq!(
            j["provenance"]["build_manifest"]["x86_64-unknown-linux-gnu"],
            "sha256:cafef00d"
        );
        assert_eq!(j["hardware_custody"]["platform"], "tpm");
        assert_eq!(j["hardware_custody"]["verified"], true);
        assert_eq!(j["cert_validity"]["registry-steward-us"]["passed"], true);
        assert_eq!(j["rollback_detected"], false);
        assert!(j["federation_provenance"]["attestations_consumed"].is_array());
    }

    // ----- CIRISVerify#37 (v3.8.0) ProvenanceBlock extensions -----

    #[test]
    fn skill_import_dimension_projects_into_skill_imports_map() {
        let prov = fp(vec![
            AttestationEntry::pass(
                dim::provenance_skill_import("registry:ciris-registry-us"),
                "registry-steward-us",
            )
            .with_source_ref("skill_manifest_sha256:abc123"),
            AttestationEntry::fail(
                dim::provenance_skill_import("direct:https://example.org/skill.tar.gz"),
                "https-publisher-key",
            ),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        let reg = bundle
            .provenance
            .skill_imports
            .get("registry:ciris-registry-us")
            .expect("registry source present");
        assert!(reg.passed);
        assert_eq!(reg.attester, "registry-steward-us");
        assert_eq!(
            reg.source_ref.as_deref(),
            Some("skill_manifest_sha256:abc123")
        );
        let direct = bundle
            .provenance
            .skill_imports
            .get("direct:https://example.org/skill.tar.gz")
            .expect("direct source present");
        assert!(!direct.passed);
    }

    #[test]
    fn per_locale_build_manifest_projects_under_target_then_lang() {
        // Parent root + two locale leaves under the same target. The
        // parent populates `build_manifest`; the leaves populate
        // `build_manifest_per_locale[target][lang]`.
        let prov = fp(vec![
            AttestationEntry::pass(
                dim::provenance_build_manifest("ios-mobile-bundle"),
                "verify-steward-2026",
            )
            .with_source_ref("sha256:parent-merkle-root"),
            AttestationEntry::pass(
                dim::provenance_build_manifest_locale("ios-mobile-bundle", "en"),
                "verify-steward-2026",
            ),
            AttestationEntry::fail(
                dim::provenance_build_manifest_locale("ios-mobile-bundle", "my"),
                "verify-steward-2026",
            ),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        // Parent populated.
        assert_eq!(
            bundle.provenance.build_manifest.get("ios-mobile-bundle"),
            Some(&"sha256:parent-merkle-root".to_string())
        );
        // Locale leaves populated under the same target key.
        let leaves = bundle
            .provenance
            .build_manifest_per_locale
            .get("ios-mobile-bundle")
            .expect("locale leaves under target");
        assert!(leaves.get("en").unwrap().passed, "en leaf passes");
        assert!(!leaves.get("my").unwrap().passed, "my leaf fails");
    }

    #[test]
    fn locale_leaf_with_no_parent_root_still_populates() {
        // A consumer who emitted only the locale leaf without the
        // parent root must still have the leaf surfaced. Defensive
        // case — out-of-order emission must not lose data.
        let prov = fp(vec![AttestationEntry::pass(
            dim::provenance_build_manifest_locale("python-source-tree", "id"),
            "verify-steward-2026",
        )]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        assert!(bundle.provenance.build_manifest.is_empty());
        let leaves = bundle
            .provenance
            .build_manifest_per_locale
            .get("python-source-tree")
            .expect("locale leaf populated even without parent");
        assert!(leaves.get("id").unwrap().passed);
    }

    #[test]
    fn skill_import_and_per_locale_serialize_correctly() {
        let prov = fp(vec![
            AttestationEntry::pass(
                dim::provenance_skill_import("registry:ciris-registry-us"),
                "registry-steward-us",
            ),
            AttestationEntry::pass(
                dim::provenance_build_manifest_locale("ios-mobile-bundle", "en"),
                "verify-steward-2026",
            ),
        ]);
        let bundle = AttestBundle::from_federation_provenance("k", prov);
        let j: serde_json::Value = serde_json::to_value(&bundle).unwrap();
        assert_eq!(
            j["provenance"]["skill_imports"]["registry:ciris-registry-us"]["passed"],
            true
        );
        assert_eq!(
            j["provenance"]["build_manifest_per_locale"]["ios-mobile-bundle"]["en"]["passed"],
            true
        );
    }

    #[test]
    fn json_round_trip() {
        let prov = fp(vec![
            AttestationEntry::pass(dim::SELF_VERIFY, "v"),
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
                binary_version: "3.6.0".into(),
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
                binary_version: "3.6.0".into(),
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
        assert!(bundle.self_verification.as_ref().unwrap().passed);
        assert!(bundle.hardware_attestation.as_ref().unwrap().passed);
        assert!(bundle.registry_consensus.as_ref().unwrap().passed);
        assert_eq!(bundle.hardware_custody.platform, "tpm");
        assert!(bundle.hardware_custody.verified);
    }
}
