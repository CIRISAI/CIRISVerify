//! `SkillImportManifest` — community-skill import provenance verifier
//! (CIRISVerify#37 Phase 2, v3.9.0+).
//!
//! Canonical-bytes contract pinned by CIRISRegistry FSD-002 v1.4.3
//! §3.2.1.1. A `SkillImportManifest` is the signed bytes underlying a
//! `provenance:skill_import:{source}` attestation. Signature scheme
//! is hybrid Ed25519 + ML-DSA-65 per FSD-002 §7 federation discipline.
//!
//! ## Canonical bytes (§3.2.1.1)
//!
//! ```text
//! sha256(
//!     "ciris.skill_import.v1\n" ||
//!     "source=" || source_string || "\n" ||
//!     "skill_manifest_sha256=" || sha256_hex_lowercase || "\n" ||
//!     "signer_identity=" || signer_key_id || "\n" ||
//!     "import_timestamp=" || iso8601_rfc3339_utc || "\n" ||
//!     "capability_declaration=" || sorted_capabilities_json || "\n" ||
//!     "valid_until=" || optional_iso8601_or_empty
//! )
//! ```
//!
//! Capability declaration is a JSON array of capability strings
//! sorted lexicographically, no whitespace. Verify reconstructs the
//! sorted form at verification time — a signer that submits an
//! unsorted array invalidates its own signature.
//!
//! ## Source-type discrimination (consumer policy)
//!
//! This module verifies the cryptographic signature against the
//! supplied `trusted_pubkey`. **It does not select the pubkey for
//! the caller** — picking which key to verify against per source
//! type (`registry:` → registry-steward; `direct:` → URL-bound
//! publisher; `local:` → operator) is a consumer-policy decision the
//! caller makes. The `SourceType` enum exposes the source-type
//! classification so the caller can route key selection deterministically.

use serde::{Deserialize, Serialize};

use crate::error::VerifyError;
use crate::security::function_integrity::{
    verify_hybrid_signature, ManifestSignature, StewardPublicKey,
};

/// Domain prefix for `SkillImportManifest` canonical bytes (FSD-002
/// §3.2.1.1). Trailing newline is part of the prefix.
pub const SKILL_IMPORT_DOMAIN_PREFIX: &str = "ciris.skill_import.v1\n";

/// One `SkillImportManifest`. All `String` fields carry the exact
/// UTF-8 form they were signed under.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillImportManifest {
    /// Source string per §3.2.1.1 source-form table —
    /// `registry:{registry_id}` | `direct:{url}` | `local:{path}`.
    pub source: String,
    /// SHA-256 (lowercase hex, 64 chars) of the skill manifest the
    /// import covers. The signed payload references this hash; the
    /// actual skill bytes verify against this hash separately.
    pub skill_manifest_sha256: String,
    /// `key_id` of the signer (a `federation_keys.key_id` string).
    pub signer_identity: String,
    /// ISO 8601 / RFC 3339 UTC timestamp of the import (e.g.
    /// `2026-05-28T17:30:00Z`).
    pub import_timestamp: String,
    /// Capability strings the imported skill declares. Verify will
    /// sort lexicographically when computing canonical bytes — the
    /// caller may submit in any order.
    pub capability_declaration: Vec<String>,
    /// Optional expiry; canonical bytes include the empty string when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// Hybrid Ed25519 + ML-DSA-65 signature over the canonical bytes.
    pub signature: ManifestSignature,
}

/// Source-type discriminator extracted from the `source` prefix.
/// FSD-002 §3.2.1.1 source-form table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    /// `registry:{registry_id}` — published by a registry steward.
    Registry,
    /// `direct:{url}` — published at an absolute URL.
    Direct,
    /// `local:{path}` — operator-managed local install.
    Local,
}

impl SkillImportManifest {
    /// Classify the source-type from the `source` prefix. `Ok(_)` if
    /// the prefix is one of the three legal forms; `Err` if not.
    /// The caller uses this to route trusted-pubkey selection.
    pub fn source_type(&self) -> Result<SourceType, VerifyError> {
        if self.source.starts_with("registry:") {
            Ok(SourceType::Registry)
        } else if self.source.starts_with("direct:") {
            Ok(SourceType::Direct)
        } else if self.source.starts_with("local:") {
            Ok(SourceType::Local)
        } else {
            Err(VerifyError::IntegrityError {
                message: format!(
                    "SkillImportManifest source prefix not in {{registry:,direct:,local:}}: {:?}",
                    truncate(&self.source, 32)
                ),
            })
        }
    }

    /// Canonical sorted-JSON form of `capability_declaration` per
    /// §3.2.1.1 — lexicographic byte sort, no whitespace, no
    /// trailing newline. This is the exact UTF-8 form the signed
    /// canonical bytes cover.
    #[must_use]
    pub fn canonical_capabilities_json(&self) -> String {
        let mut sorted = self.capability_declaration.clone();
        sorted.sort();
        // serde_json::to_string already produces no-whitespace
        // separators by default for Vec<String>.
        serde_json::to_string(&sorted).unwrap_or_else(|_| "[]".to_string())
    }

    /// Compute the canonical-bytes input (the bytes that feed into
    /// the outer SHA-256) per FSD-002 §3.2.1.1.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let valid_until = self.valid_until.as_deref().unwrap_or("");
        let body = format!(
            "{prefix}source={source}\nskill_manifest_sha256={hash}\nsigner_identity={signer}\nimport_timestamp={ts}\ncapability_declaration={caps}\nvalid_until={valid_until}",
            prefix = SKILL_IMPORT_DOMAIN_PREFIX,
            source = self.source,
            hash = self.skill_manifest_sha256,
            signer = self.signer_identity,
            ts = self.import_timestamp,
            caps = self.canonical_capabilities_json(),
        );
        body.into_bytes()
    }

    /// Emit the federation_provenance attestation entry this
    /// manifest stands for, IFF `verify` returned `Ok`. The dimension
    /// is `provenance:skill_import:{source}` (FSD-002 §3.2 row added
    /// in v1.4.1).
    #[must_use]
    pub fn to_attestation_entries(
        &self,
        attester: &str,
    ) -> Vec<crate::federation_provenance::AttestationEntry> {
        use crate::federation_provenance::{dim, AttestationEntry};
        vec![
            AttestationEntry::pass(dim::provenance_skill_import(&self.source), attester)
                .with_source_ref(format!("sha256:{}", self.skill_manifest_sha256)),
        ]
    }
}

/// Verify a `SkillImportManifest` against a trusted pubkey.
///
/// **Caller selects `trusted_pubkey`** by source type — this function
/// only validates the cryptographic signature plus invariants on the
/// payload shape. Returns `Ok(manifest)` on success so the caller
/// can chain `manifest.to_attestation_entries(attester)` to emit the
/// federation_provenance entry.
///
/// Invariants enforced:
/// - `source` matches one of the three legal prefix forms (§3.2.1.1)
/// - `skill_manifest_sha256` is exactly 64 lowercase hex chars
/// - hybrid Ed25519 + ML-DSA-65 signature verifies against
///   `trusted_pubkey` over `canonical_bytes()`
///
/// What this function does **NOT** check (consumer policy):
/// - whether `valid_until` is in the future
/// - whether the URL in a `direct:{url}` source is HTTPS
/// - whether `signer_identity` matches an expected registry steward
///   id (the trusted_pubkey IS that decision encoded in key form)
pub fn verify_skill_import_manifest(
    bytes: &[u8],
    trusted_pubkey: &StewardPublicKey,
) -> Result<SkillImportManifest, VerifyError> {
    let manifest: SkillImportManifest =
        serde_json::from_slice(bytes).map_err(|e| VerifyError::IntegrityError {
            message: format!("SkillImportManifest parse failed: {}", e),
        })?;

    // Source-prefix discipline.
    let _source_type = manifest.source_type()?;

    // skill_manifest_sha256 invariant: 64 lowercase hex chars.
    if manifest.skill_manifest_sha256.len() != 64
        || !manifest
            .skill_manifest_sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "SkillImportManifest skill_manifest_sha256 not 64 lowercase hex chars: {:?}",
                truncate(&manifest.skill_manifest_sha256, 16)
            ),
        });
    }

    let canonical = manifest.canonical_bytes();
    let sig_valid = verify_hybrid_signature(&canonical, &manifest.signature, trusted_pubkey)?;
    if !sig_valid {
        return Err(VerifyError::IntegrityError {
            message: "SkillImportManifest hybrid signature verification failed".into(),
        });
    }

    Ok(manifest)
}

fn truncate(s: &str, n: usize) -> &str {
    s.get(..n.min(s.len())).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_unsigned_manifest() -> SkillImportManifest {
        SkillImportManifest {
            source: "registry:ciris-registry-us".to_string(),
            skill_manifest_sha256: "a".repeat(64),
            signer_identity: "registry-steward-us".to_string(),
            import_timestamp: "2026-05-28T17:30:00Z".to_string(),
            capability_declaration: vec![
                "domain:medical:triage".to_string(),
                "beneficence:wellness_referral".to_string(),
                "agent_files:adapter:wellness".to_string(),
            ],
            valid_until: Some("2026-08-28T17:30:00Z".to_string()),
            signature: ManifestSignature {
                classical: String::new(),
                classical_algorithm: String::new(),
                pqc: String::new(),
                pqc_algorithm: String::new(),
                key_id: String::new(),
            },
        }
    }

    #[test]
    fn source_type_classifies_three_legal_prefixes() {
        let mut m = minimal_unsigned_manifest();
        assert_eq!(m.source_type().unwrap(), SourceType::Registry);
        m.source = "direct:https://example.org/skill.tar.gz".into();
        assert_eq!(m.source_type().unwrap(), SourceType::Direct);
        m.source = "local:/opt/ciris/skills/triage.tar.gz".into();
        assert_eq!(m.source_type().unwrap(), SourceType::Local);
    }

    #[test]
    fn source_type_rejects_unknown_prefix() {
        let mut m = minimal_unsigned_manifest();
        m.source = "rogue:malicious".into();
        assert!(m.source_type().is_err());
    }

    #[test]
    fn canonical_capabilities_json_sorts_lexicographically() {
        let m = minimal_unsigned_manifest();
        let json = m.canonical_capabilities_json();
        // FSD example: ["agent_files:adapter:wellness","beneficence:wellness_referral","domain:medical:triage"]
        assert_eq!(
            json,
            r#"["agent_files:adapter:wellness","beneficence:wellness_referral","domain:medical:triage"]"#
        );
    }

    #[test]
    fn canonical_capabilities_json_no_whitespace() {
        let m = minimal_unsigned_manifest();
        let json = m.canonical_capabilities_json();
        assert!(!json.contains(' '), "no whitespace per §3.2.1.1");
        assert!(!json.contains('\n'), "no whitespace per §3.2.1.1");
    }

    #[test]
    fn canonical_capabilities_json_empty_array() {
        let mut m = minimal_unsigned_manifest();
        m.capability_declaration = vec![];
        assert_eq!(m.canonical_capabilities_json(), "[]");
    }

    #[test]
    fn canonical_bytes_starts_with_domain_prefix() {
        let m = minimal_unsigned_manifest();
        let bytes = m.canonical_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with(SKILL_IMPORT_DOMAIN_PREFIX));
    }

    #[test]
    fn canonical_bytes_includes_all_fields_in_spec_order() {
        let m = minimal_unsigned_manifest();
        let s = String::from_utf8(m.canonical_bytes()).unwrap();
        // Verify order: domain prefix, source, hash, signer, ts, caps, valid_until.
        let prefix_end = s.find("source=").expect("source= field present");
        let source_end = s
            .find("skill_manifest_sha256=")
            .expect("hash field present");
        let hash_end = s.find("signer_identity=").expect("signer field present");
        let signer_end = s.find("import_timestamp=").expect("ts field present");
        let ts_end = s
            .find("capability_declaration=")
            .expect("caps field present");
        let caps_end = s.find("valid_until=").expect("valid_until field present");
        assert!(prefix_end < source_end);
        assert!(source_end < hash_end);
        assert!(hash_end < signer_end);
        assert!(signer_end < ts_end);
        assert!(ts_end < caps_end);
    }

    #[test]
    fn canonical_bytes_handles_empty_valid_until() {
        let mut m = minimal_unsigned_manifest();
        m.valid_until = None;
        let s = String::from_utf8(m.canonical_bytes()).unwrap();
        // §3.2.1.1: "empty string if no valid_until" — no trailing
        // newline after the empty string per the spec.
        assert!(s.ends_with("valid_until="));
    }

    #[test]
    fn canonical_bytes_sorts_capabilities_regardless_of_input_order() {
        let mut m = minimal_unsigned_manifest();
        let bytes_a = m.canonical_bytes();
        // Reverse the input order — canonical bytes must be identical.
        m.capability_declaration.reverse();
        let bytes_b = m.canonical_bytes();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn to_attestation_entries_emits_provenance_skill_import_with_source_ref() {
        let m = minimal_unsigned_manifest();
        let entries = m.to_attestation_entries("registry-steward-us");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].dimension,
            "provenance:skill_import:registry:ciris-registry-us"
        );
        assert_eq!(entries[0].score, 1.0);
        assert_eq!(entries[0].attester, "registry-steward-us");
        assert_eq!(
            entries[0].source_ref.as_deref(),
            Some(format!("sha256:{}", "a".repeat(64)).as_str())
        );
    }

    fn fake_pubkey() -> StewardPublicKey {
        StewardPublicKey {
            ed25519: &[0u8; 32],
            ml_dsa_65: &[],
        }
    }

    fn fake_signature() -> ManifestSignature {
        ManifestSignature {
            classical: "ZmFrZQ==".to_string(),
            classical_algorithm: String::new(),
            pqc: String::new(),
            pqc_algorithm: String::new(),
            key_id: String::new(),
        }
    }

    #[test]
    fn verify_rejects_invalid_sha256() {
        let mut m = minimal_unsigned_manifest();
        m.skill_manifest_sha256 = "not-a-valid-hash".into();
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("64 lowercase hex"));
    }

    #[test]
    fn verify_rejects_uppercase_sha256() {
        // Lowercase-only is part of the canonical-bytes contract.
        let mut m = minimal_unsigned_manifest();
        m.skill_manifest_sha256 = "A".repeat(64);
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_unknown_source_prefix() {
        let mut m = minimal_unsigned_manifest();
        m.source = "rogue:bad".into();
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("registry"));
    }

    /// FSD-002 §3.2.1.1 canonical-bytes spec stability: a change to
    /// the formula breaks signed-manifest verification across the
    /// federation. Lock the byte representation.
    #[test]
    fn canonical_bytes_matches_fsd_spec_layout() {
        let m = SkillImportManifest {
            source: "registry:reg1".into(),
            skill_manifest_sha256: "0".repeat(64),
            signer_identity: "signer1".into(),
            import_timestamp: "2026-05-28T17:30:00Z".into(),
            capability_declaration: vec!["c2".into(), "c1".into()],
            valid_until: Some("2026-08-28T17:30:00Z".into()),
            signature: ManifestSignature {
                classical: String::new(),
                classical_algorithm: String::new(),
                pqc: String::new(),
                pqc_algorithm: String::new(),
                key_id: String::new(),
            },
        };
        let expected = format!(
            "ciris.skill_import.v1\nsource=registry:reg1\nskill_manifest_sha256={zero}\nsigner_identity=signer1\nimport_timestamp=2026-05-28T17:30:00Z\ncapability_declaration=[\"c1\",\"c2\"]\nvalid_until=2026-08-28T17:30:00Z",
            zero = "0".repeat(64),
        );
        assert_eq!(String::from_utf8(m.canonical_bytes()).unwrap(), expected);
    }
}
