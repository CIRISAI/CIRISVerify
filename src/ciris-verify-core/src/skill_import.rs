//! `SkillImportManifest` — community-skill import provenance verifier
//! (CIRISVerify#37 Phase 2, v3.9.0+; canonicalization tightened to
//! CEG 0.2 §0.5 / §0.6 / §5.2.1 in v4.0.0).
//!
//! Canonical-bytes contract pinned by CIRISRegistry CEG 0.2 §5.2.1
//! (supersedes FSD-002 v1.4.3 §3.2.1.1). A `SkillImportManifest` is
//! the signed bytes underlying a `provenance:skill_import:{source}`
//! attestation. Signature scheme is hybrid Ed25519 + ML-DSA-65 per
//! CEG 0.2 §10.0 federation discipline.
//!
//! ## CEG 0.2 §0.5 date-time canonicalization (v4.0.0+)
//!
//! `import_timestamp` and `valid_until` MUST be canonical RFC 3339:
//! UTC suffix `Z` (not `+00:00`, not lowercase `z`), exactly
//! millisecond precision (3 fractional digits). Form:
//! `YYYY-MM-DDTHH:MM:SS.sssZ`. Producers emit this form; consumers
//! reject any other.
//!
//! ## CEG 0.2 §0.6 hexadecimal canonicalization (v4.0.0+)
//!
//! `skill_manifest_sha256` MUST be lowercase, unpadded (no `0x`
//! prefix, no separators), exactly 64 hex characters. Producers
//! emit lowercase; consumers reject uppercase.
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

/// **v2 domain literal** for `SkillImportManifest` canonical bytes
/// (**CC 3.1.2.1**, normative). Pinned string, carried as the `domain` member
/// of the JCS-canonicalized object — no trailing newline, because v2 is not a
/// delimiter-based encoding.
pub const SKILL_IMPORT_DOMAIN_V2: &str = "ciris.skill_import.v2";

/// **RETIRED (v11.0.0).** The v1 line-oriented domain prefix.
///
/// v1 built its preimage by concatenating `key=value\n` pairs, which is
/// delimiter-injection-capable wherever a field carries attacker-influenceable
/// free text. CC 3.1.2.1 replaced it with `sha256(JCS({…}))` and states
/// *"Producers MUST emit v2."* Retained only so a reader recognizes the old
/// literal in historical artifacts; **nothing in this crate signs or verifies
/// with it.**
#[deprecated(
    since = "11.0.0",
    note = "v1 canonical bytes are delimiter-injection-capable; CC 3.1.2.1 mandates the v2 JCS form. Use SKILL_IMPORT_DOMAIN_V2."
)]
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

    /// The **v2** canonical bytes per **CC 3.1.2.1** — `sha256(JCS({…}))`.
    ///
    /// # Why v2 replaced the v1 line-oriented preimage (a wire break)
    ///
    /// v1 concatenated `key=value\n` pairs. Several of those values carry
    /// **attacker-influenceable free text** — most obviously `source` in its
    /// `direct:{url}` form — and nothing rejected embedded newlines, so a
    /// crafted value could forge field boundaries and make two logically
    /// different manifests produce ambiguous canonical bytes. CC 3.1.2.1 names
    /// exactly this: the JCS form closes an injection surface, and the
    /// accord-invocation encoding is exempt only because it has *"no
    /// attacker-controlled free text"*.
    ///
    /// JCS is immune by construction — structure lives in the encoding, not in
    /// delimiters — so no escaping or newline rejection is needed here.
    ///
    /// Per CC the signature is over the **32-byte digest**, not the preimage,
    /// which also keeps the hardware-token input small (the #113/#116 lesson).
    ///
    /// `valid_until` follows the CC 2.6.1.1 omit-vs-materialize rule: **absent
    /// when unset**, never the v1 empty-string sentinel.
    ///
    /// # Errors
    /// [`VerifyError`] if JCS canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        use sha2::{Digest, Sha256};

        let mut obj = serde_json::Map::new();
        obj.insert(
            "domain".to_string(),
            serde_json::Value::String(SKILL_IMPORT_DOMAIN_V2.to_string()),
        );
        obj.insert(
            "source".to_string(),
            serde_json::Value::String(self.source.clone()),
        );
        obj.insert(
            "skill_manifest_sha256".to_string(),
            serde_json::Value::String(self.skill_manifest_sha256.clone()),
        );
        obj.insert(
            "signer_identity".to_string(),
            serde_json::Value::String(self.signer_identity.clone()),
        );
        obj.insert(
            "import_timestamp".to_string(),
            serde_json::Value::String(self.import_timestamp.clone()),
        );
        // Sorted lexicographically — the array order is part of the value, and
        // JCS canonicalizes the array in place (it does not reorder elements).
        let mut caps = self.capability_declaration.clone();
        caps.sort();
        obj.insert(
            "capability_declaration".to_string(),
            serde_json::Value::Array(caps.into_iter().map(serde_json::Value::String).collect()),
        );
        if let Some(v) = &self.valid_until {
            obj.insert(
                "valid_until".to_string(),
                serde_json::Value::String(v.clone()),
            );
        }

        let jcs_bytes = crate::jcs::canonicalize(&serde_json::Value::Object(obj))?;
        Ok(Sha256::digest(&jcs_bytes).to_vec())
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

    // CEG 0.2 §0.6 hex canonicalization: lowercase, exactly 64,
    // no `0x` prefix, no separators.
    check_canonical_hex64(&manifest.skill_manifest_sha256, "skill_manifest_sha256")?;

    // CEG 0.2 §0.5 date-time canonicalization: import_timestamp and
    // valid_until (if present) must be canonical RFC 3339 with `Z`
    // suffix and exactly millisecond precision.
    check_canonical_rfc3339(&manifest.import_timestamp, "import_timestamp")?;
    if let Some(ref vu) = manifest.valid_until {
        check_canonical_rfc3339(vu, "valid_until")?;
    }

    let canonical = manifest.canonical_bytes()?;
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

/// CEG 0.2 §0.6: lowercase, exactly 64 hex chars, no `0x` prefix,
/// no separators. Rejects uppercase even when otherwise well-formed.
fn check_canonical_hex64(s: &str, field: &str) -> Result<(), VerifyError> {
    if s.len() != 64 {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "{field}: §0.6 violation — expected 64 hex chars, got {} ({:?})",
                s.len(),
                truncate(s, 16),
            ),
        });
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        return Err(VerifyError::IntegrityError {
            message: format!("{field}: §0.6 violation — `0x` prefix not allowed in canonical hex",),
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "{field}: §0.6 violation — non-lowercase-hex char in {:?}",
                truncate(s, 16),
            ),
        });
    }
    Ok(())
}

/// CEG 0.2 §0.5: `YYYY-MM-DDTHH:MM:SS.sssZ`. UTC suffix is uppercase
/// `Z` only (no `+00:00`, no lowercase `z`). Fractional seconds are
/// exactly 3 digits.
///
/// Length is exactly 24 chars. Positions:
/// - `[0..4]` year, `[4]` `-`, `[5..7]` month, `[7]` `-`,
///   `[8..10]` day, `[10]` `T`, `[11..13]` hour, `[13]` `:`,
///   `[14..16]` minute, `[16]` `:`, `[17..19]` second, `[19]` `.`,
///   `[20..23]` millis, `[23]` `Z`.
fn check_canonical_rfc3339(s: &str, field: &str) -> Result<(), VerifyError> {
    let bytes = s.as_bytes();
    if bytes.len() != 24 {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "{field}: §0.5 violation — expected 24-char canonical form, got {} ({:?})",
                s.len(),
                truncate(s, 24),
            ),
        });
    }
    let want = |i: usize, c: u8, label: &str| -> Result<(), VerifyError> {
        if bytes[i] != c {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "{field}: §0.5 violation — expected {label} at position {i}, got {:?}",
                    bytes[i] as char,
                ),
            });
        }
        Ok(())
    };
    want(4, b'-', "`-`")?;
    want(7, b'-', "`-`")?;
    want(10, b'T', "`T`")?;
    want(13, b':', "`:`")?;
    want(16, b':', "`:`")?;
    want(19, b'.', "`.` (millisecond separator)")?;
    want(23, b'Z', "`Z` (UTC suffix)")?;

    let digits_at = |range: std::ops::Range<usize>| -> Result<(), VerifyError> {
        for i in range.clone() {
            if !bytes[i].is_ascii_digit() {
                return Err(VerifyError::IntegrityError {
                    message: format!(
                        "{field}: §0.5 violation — non-digit at position {i} ({:?})",
                        bytes[i] as char,
                    ),
                });
            }
        }
        Ok(())
    };
    digits_at(0..4)?;
    digits_at(5..7)?;
    digits_at(8..10)?;
    digits_at(11..13)?;
    digits_at(14..16)?;
    digits_at(17..19)?;
    digits_at(20..23)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_unsigned_manifest() -> SkillImportManifest {
        SkillImportManifest {
            source: "registry:ciris-registry-us".to_string(),
            skill_manifest_sha256: "a".repeat(64),
            signer_identity: "registry-steward-us".to_string(),
            import_timestamp: "2026-05-28T17:30:00.000Z".to_string(),
            capability_declaration: vec![
                "domain:medical:triage".to_string(),
                "beneficence:wellness_referral".to_string(),
                "agent_files:adapter:wellness".to_string(),
            ],
            valid_until: Some("2026-08-28T17:30:00.000Z".to_string()),
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
    fn v2_canonical_bytes_are_a_sha256_digest() {
        // CC 3.1.2.1: canonical_bytes = sha256(JCS({…})) — the signature is
        // over the 32-byte digest, not over a multi-KB preimage.
        let m = minimal_unsigned_manifest();
        assert_eq!(m.canonical_bytes().unwrap().len(), 32);
    }

    #[test]
    fn v2_canonical_bytes_sort_capabilities_regardless_of_input_order() {
        let mut m = minimal_unsigned_manifest();
        let a = m.canonical_bytes().unwrap();
        m.capability_declaration.reverse();
        let b = m.canonical_bytes().unwrap();
        assert_eq!(a, b, "capability order must not change the preimage");
    }

    /// CC 2.6.1.1 omit-vs-materialize: an unset `valid_until` is **absent**,
    /// not the v1 empty-string sentinel. The two must not be the same object.
    #[test]
    fn v2_omits_valid_until_rather_than_emitting_an_empty_sentinel() {
        let mut absent = minimal_unsigned_manifest();
        absent.valid_until = None;

        let mut empty = minimal_unsigned_manifest();
        empty.valid_until = Some(String::new());

        assert_ne!(
            absent.canonical_bytes().unwrap(),
            empty.canonical_bytes().unwrap(),
            "omitted must differ from present-but-empty (CC 2.6.1.1)"
        );
    }

    /// **The reason v2 exists.** v1 concatenated `key=value\n`, so a `source`
    /// carrying a newline could forge field boundaries and make two logically
    /// different manifests share a preimage. JCS puts the structure in the
    /// encoding, so the same attempt now yields distinct digests.
    #[test]
    fn v2_resists_delimiter_injection_through_free_text_fields() {
        let honest = minimal_unsigned_manifest();

        // The v1 attack shape: smuggle a field boundary inside `source`.
        let mut injected = minimal_unsigned_manifest();
        injected.source = format!(
            "registry:reg1\nskill_manifest_sha256={}\nsigner_identity=attacker",
            "1".repeat(64)
        );

        assert_ne!(
            honest.canonical_bytes().unwrap(),
            injected.canonical_bytes().unwrap(),
            "a newline-bearing source must not collide with an honest manifest"
        );

        // And the injected value round-trips as *data*, not structure: it is
        // still exactly one `source` member.
        let mut also_injected = minimal_unsigned_manifest();
        also_injected.source = injected.source.clone();
        assert_eq!(
            injected.canonical_bytes().unwrap(),
            also_injected.canonical_bytes().unwrap()
        );
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
        assert!(format!("{:?}", result.unwrap_err()).contains("§0.6"));
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
            import_timestamp: "2026-05-28T17:30:00.000Z".into(),
            capability_declaration: vec!["c2".into(), "c1".into()],
            valid_until: Some("2026-08-28T17:30:00.000Z".into()),
            signature: ManifestSignature {
                classical: String::new(),
                classical_algorithm: String::new(),
                pqc: String::new(),
                pqc_algorithm: String::new(),
                key_id: String::new(),
            },
        };
        // CC 3.1.2.1 v2 golden vector — the JCS object this manifest
        // canonicalizes to, written out so a second implementation has an
        // unambiguous target (JCS sorts members lexicographically).
        let expected_jcs = format!(
            r#"{{"capability_declaration":["c1","c2"],"domain":"ciris.skill_import.v2","import_timestamp":"2026-05-28T17:30:00.000Z","signer_identity":"signer1","skill_manifest_sha256":"{zero}","source":"registry:reg1","valid_until":"2026-08-28T17:30:00.000Z"}}"#,
            zero = "0".repeat(64),
        );
        use sha2::{Digest, Sha256};
        assert_eq!(
            m.canonical_bytes().unwrap(),
            Sha256::digest(expected_jcs.as_bytes()).to_vec(),
            "v2 canonical bytes must be sha256 over exactly this JCS form"
        );
    }

    // ----- v4.0.0 CEG 0.2 §0.5 + §0.6 canonicalization tightening -----

    #[test]
    fn verify_rejects_uppercase_hex_per_section_0_6() {
        let mut m = minimal_unsigned_manifest();
        m.skill_manifest_sha256 = "A".repeat(64);
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("§0.6"));
    }

    #[test]
    fn verify_rejects_0x_prefix_per_section_0_6() {
        let mut m = minimal_unsigned_manifest();
        // 64 chars total counting the prefix — the prefix is the
        // rejection, regardless of length.
        m.skill_manifest_sha256 = format!("0x{}", "a".repeat(62));
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("0x"));
    }

    #[test]
    fn verify_rejects_non_canonical_offset_timezone_per_section_0_5() {
        // `+00:00` is forbidden by §0.5 — only `Z` is canonical.
        let mut m = minimal_unsigned_manifest();
        m.import_timestamp = "2026-05-28T17:30:00.000+00:00".into();
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("§0.5"));
    }

    #[test]
    fn verify_rejects_lowercase_z_per_section_0_5() {
        let mut m = minimal_unsigned_manifest();
        m.import_timestamp = "2026-05-28T17:30:00.000z".into();
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("§0.5"));
    }

    #[test]
    fn verify_rejects_missing_millisecond_precision_per_section_0_5() {
        // Pre-v4.0.0 callers using 20-char ISO 8601 (`2026-...:00Z`)
        // without ms precision MUST be rejected under CEG 0.2 §0.5.
        let mut m = minimal_unsigned_manifest();
        m.import_timestamp = "2026-05-28T17:30:00Z".into();
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("§0.5"));
    }

    #[test]
    fn verify_rejects_extra_precision_per_section_0_5() {
        // Microseconds (6 fractional digits) is also rejected — §0.5
        // mandates exactly 3.
        let mut m = minimal_unsigned_manifest();
        m.import_timestamp = "2026-05-28T17:30:00.000000Z".into();
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("§0.5"));
    }

    #[test]
    fn verify_rejects_non_canonical_valid_until_per_section_0_5() {
        // When `valid_until` is present it must be canonical.
        let mut m = minimal_unsigned_manifest();
        m.valid_until = Some("2026-08-28T17:30:00Z".into());
        m.signature = fake_signature();
        let bytes = serde_json::to_vec(&m).unwrap();
        let result = verify_skill_import_manifest(&bytes, &fake_pubkey());
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("§0.5"));
    }

    /// CEG 0.2 §5.2 mechanism-only naming: `attestation:hardware_rooted`
    /// is the v4.0.0 wire string (was `attestation:hardware` in
    /// v3.7.0–v3.9.0). Lock both the const value and the wire form.
    #[test]
    fn ceg_0_2_hardware_rooted_wire_string() {
        assert_eq!(
            crate::federation_provenance::dim::HARDWARE,
            "attestation:hardware_rooted"
        );
    }
}
