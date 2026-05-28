//! CEG 0.2 §10.2 multi-steward `/v1/steward-key` response verifier
//! and `cert_validity:{steward_id}` self-attestation wiring
//! (v4.0.0-rc3+).
//!
//! Per CIRISRegistry CEG 0.2 §10.2:
//!
//! > The response itself is hybrid-signed by the serving region's
//! > steward over `canonical = "ciris.steward_key_response.v1\n" ||
//! > sha256_hex_lowercase(canonicalized_json_body_excluding_signature)`.
//! > Consumers MUST verify the response signature before trusting any
//! > field in the body — placeholder pubkeys without `deployed: true`
//! > MUST NOT be promoted to trust roots.
//!
//! ## What this module ships
//!
//! - [`StewardKeyResponse`] / [`Steward`] /
//!   [`CertValiditySelfAttest`] / [`ThresholdPolicy`] /
//!   [`ResponseSignature`] — wire types matching §10.2.
//! - [`verify_steward_key_response`] — verifies the hybrid response
//!   signature against a caller-supplied trusted_pubkey. Rejects
//!   the body if the signature doesn't verify. **Consumers MUST
//!   call this before reading any field.**
//! - [`StewardKeyResponse::to_attestation_entries`] — emits one
//!   `cert_validity:{steward_id}` entry **per deployed steward**.
//!   Undeployed (placeholder) stewards are structurally excluded
//!   per §10.2 — they're not trust roots and have no cert-validity
//!   self-attestation worth carrying.
//!
//! ## Canonical-bytes status
//!
//! CEG 0.2 §10.2 specifies the domain prefix and SHA-256-of-body
//! shape but does not pin the JSON canonicalization. This module
//! uses `serde_json::to_string` over the body type, producing
//! field-order serialization (no whitespace, no trailing newlines).
//! That's the de-facto canonical form for this struct shape; the
//! 0.2 canonical-bytes redesign workshop (per §5.2.1 scaffold note)
//! is where any strict-JCS upgrade lands. v4.1.x will tighten if
//! the workshop chooses JCS-strict for §10.2 too.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::VerifyError;
use crate::security::function_integrity::{
    verify_hybrid_signature, ManifestSignature, StewardPublicKey,
};

/// Domain prefix for the steward-key response signature (§10.2).
/// The label MUST be present in `response_signature.canonical_bytes_label`
/// — a mismatch is a wire violation.
pub const STEWARD_KEY_RESPONSE_DOMAIN_PREFIX: &str = "ciris.steward_key_response.v1";

/// One steward entry in the `/v1/steward-key` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Steward {
    /// `us` / `eu` / `apac` — the regional locus.
    pub region: String,
    /// `federation_keys.key_id` of this steward.
    pub key_id: String,
    /// Base64url Ed25519 public key.
    pub ed25519_pubkey_b64: String,
    /// Base64url ML-DSA-65 public key.
    pub mldsa65_pubkey_b64: String,
    /// HSM_FIPS_140_3_L3 / etc.
    pub hardware_class: String,
    /// Per §10.2 normative: **only `deployed: true` stewards may be
    /// promoted to trust roots**. Placeholder entries have
    /// `deployed: false` and MUST be ignored by consumers.
    pub deployed: bool,
    /// SHA-256 fingerprint (lowercase hex, 64 chars per §0.6).
    pub fingerprint_sha256_hex: String,
    /// Self-attestation of the steward's cert validity.
    pub cert_validity_self_attest: CertValiditySelfAttest,
}

/// Per-steward self-attestation that the steward's cert chain is
/// valid through `valid_until`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertValiditySelfAttest {
    /// §0.5 canonical RFC 3339 timestamp.
    pub valid_until: String,
    /// Base64url signature of the steward over its own
    /// `cert_validity_self_attest` bytes. Verified separately from
    /// the outer response signature; consumers SHOULD check this
    /// against the steward's pinned pubkey for chain validity.
    pub signature_b64: String,
}

/// `{required, available}` — M-of-N policy.
///
/// `required` is the steward-quorum threshold (e.g. 2-of-3 for
/// production); `available` is the count of `deployed: true`
/// stewards currently serving. When `available < required` the
/// federation is operating below threshold — consumer policy decides
/// whether to degrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPolicy {
    /// Threshold of deployed stewards required for quorum operations.
    pub required: u8,
    /// Number of deployed stewards currently serving.
    pub available: u8,
}

/// Outer response signature shape (§10.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSignature {
    /// Which steward signed (one of the entries in `stewards[]`
    /// with `deployed: true`).
    pub signer_key_id: String,
    /// Base64url Ed25519 signature.
    pub ed25519_b64: String,
    /// Base64url ML-DSA-65 signature.
    pub mldsa65_b64: String,
    /// MUST equal [`STEWARD_KEY_RESPONSE_DOMAIN_PREFIX`].
    pub canonical_bytes_label: String,
}

/// The full `/v1/steward-key` response (§10.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StewardKeyResponse {
    /// Multi-steward set.
    pub stewards: Vec<Steward>,
    /// M-of-N policy.
    pub threshold_policy: ThresholdPolicy,
    /// Outer hybrid signature.
    pub response_signature: ResponseSignature,
}

/// Body fields that participate in the response-signature canonical
/// bytes (everything EXCEPT the signature itself).
#[derive(Serialize)]
struct StewardKeyResponseBody<'a> {
    stewards: &'a [Steward],
    threshold_policy: &'a ThresholdPolicy,
}

impl StewardKeyResponse {
    /// Compute the canonical bytes the outer signature covers
    /// (§10.2):
    /// `"ciris.steward_key_response.v1\n" || sha256_hex_lowercase(body_json)`.
    /// `body_json` excludes the `response_signature` field.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let body = StewardKeyResponseBody {
            stewards: &self.stewards,
            threshold_policy: &self.threshold_policy,
        };
        let body_json = serde_json::to_string(&body).unwrap_or_default();
        let body_hash = sha256_hex_lowercase(body_json.as_bytes());
        let mut out =
            Vec::with_capacity(STEWARD_KEY_RESPONSE_DOMAIN_PREFIX.len() + 1 + body_hash.len());
        out.extend_from_slice(STEWARD_KEY_RESPONSE_DOMAIN_PREFIX.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(body_hash.as_bytes());
        out
    }

    /// Iterate stewards eligible for trust-root promotion per §10.2:
    /// `deployed: true` only. Placeholder stewards are excluded.
    pub fn deployed_stewards(&self) -> impl Iterator<Item = &Steward> {
        self.stewards.iter().filter(|s| s.deployed)
    }

    /// Emit one `cert_validity:{steward_id}` attestation entry per
    /// deployed steward (§10.2 wiring; CIRISVerify#38 rc3).
    ///
    /// The attestation:
    /// - dimension: `cert_validity:{steward.key_id}`
    /// - score: 1.0 (the steward's self-attestation states validity)
    /// - attester: `attester` argument (usually the serving region's
    ///   signer_key_id, since the outer response signature vouches)
    /// - source_ref: `valid_until` from the cert-validity entry, so
    ///   consumers can correlate to the freshness window.
    ///
    /// Undeployed stewards are STRUCTURALLY EXCLUDED — placeholder
    /// pubkeys MUST NOT be promoted to trust roots (§10.2 normative).
    #[must_use]
    pub fn to_attestation_entries(
        &self,
        attester: &str,
    ) -> Vec<crate::federation_provenance::AttestationEntry> {
        use crate::federation_provenance::{dim, AttestationEntry};
        self.deployed_stewards()
            .map(|s| {
                AttestationEntry::pass(dim::cert_validity(&s.key_id), attester).with_source_ref(
                    format!("valid_until:{}", s.cert_validity_self_attest.valid_until),
                )
            })
            .collect()
    }
}

/// Verify a `/v1/steward-key` response (§10.2 normative).
///
/// Caller supplies `trusted_pubkey` — the pinned pubkey for the
/// `signer_key_id` the caller expects. (The function does NOT pick
/// the pubkey; that's consumer policy. The caller looks up the
/// pinned key for `response_signature.signer_key_id` and supplies
/// it here.)
///
/// Invariants enforced:
/// - `response_signature.canonical_bytes_label` MUST equal
///   [`STEWARD_KEY_RESPONSE_DOMAIN_PREFIX`].
/// - Outer hybrid signature MUST verify over [`canonical_bytes`].
/// - `signer_key_id` MUST match a deployed steward in the body
///   (a signer claiming to be a placeholder is rejected).
///
/// Returns `Ok(response)` on success; bytes are then safe to read.
/// On error the consumer MUST NOT promote any field to trust state.
pub fn verify_steward_key_response(
    bytes: &[u8],
    trusted_pubkey: &StewardPublicKey,
) -> Result<StewardKeyResponse, VerifyError> {
    let response: StewardKeyResponse =
        serde_json::from_slice(bytes).map_err(|e| VerifyError::IntegrityError {
            message: format!("StewardKeyResponse parse failed: {}", e),
        })?;

    // Label discipline.
    if response.response_signature.canonical_bytes_label != STEWARD_KEY_RESPONSE_DOMAIN_PREFIX {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "§10.2 violation — canonical_bytes_label is {:?}, expected {:?}",
                response.response_signature.canonical_bytes_label,
                STEWARD_KEY_RESPONSE_DOMAIN_PREFIX,
            ),
        });
    }

    // Signer must be a deployed steward — a placeholder claiming to
    // have signed is structurally invalid (it has no pubkey to sign
    // with that would also be promoted to a trust root).
    let signer = response
        .stewards
        .iter()
        .find(|s| s.key_id == response.response_signature.signer_key_id);
    match signer {
        Some(s) if s.deployed => {},
        Some(_) => {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "§10.2 violation — signer_key_id {:?} matches an undeployed (placeholder) steward; placeholders MUST NOT sign",
                    response.response_signature.signer_key_id,
                ),
            });
        },
        None => {
            return Err(VerifyError::IntegrityError {
                message: format!(
                    "§10.2 violation — signer_key_id {:?} does not appear in stewards[]",
                    response.response_signature.signer_key_id,
                ),
            });
        },
    }

    // Reconstruct the ManifestSignature shape `verify_hybrid_signature`
    // expects so we can reuse the existing verifier. The ed25519 +
    // mldsa65 base64 fields plug straight into the manifest signature
    // shape's classical + pqc fields.
    let manifest_sig = ManifestSignature {
        classical: response.response_signature.ed25519_b64.clone(),
        classical_algorithm: "ed25519".to_string(),
        pqc: response.response_signature.mldsa65_b64.clone(),
        pqc_algorithm: "ml-dsa-65".to_string(),
        key_id: response.response_signature.signer_key_id.clone(),
    };

    let canonical = response.canonical_bytes();
    let sig_valid = verify_hybrid_signature(&canonical, &manifest_sig, trusted_pubkey)?;
    if !sig_valid {
        return Err(VerifyError::IntegrityError {
            message: "StewardKeyResponse hybrid signature did not verify".to_string(),
        });
    }

    Ok(response)
}

fn sha256_hex_lowercase(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_steward(region: &str, key_id: &str, deployed: bool) -> Steward {
        Steward {
            region: region.to_string(),
            key_id: key_id.to_string(),
            ed25519_pubkey_b64: "AAAA".to_string(),
            mldsa65_pubkey_b64: "AAAA".to_string(),
            hardware_class: "HSM_FIPS_140_3_L3".to_string(),
            deployed,
            fingerprint_sha256_hex: "0".repeat(64),
            cert_validity_self_attest: CertValiditySelfAttest {
                valid_until: "2026-08-28T17:30:00.000Z".to_string(),
                signature_b64: "AAAA".to_string(),
            },
        }
    }

    fn sample_response() -> StewardKeyResponse {
        StewardKeyResponse {
            stewards: vec![
                sample_steward("us", "us-steward-2026", true),
                sample_steward("eu", "eu-steward-2026", false),
                sample_steward("apac", "apac-steward-2026", false),
            ],
            threshold_policy: ThresholdPolicy {
                required: 2,
                available: 1,
            },
            response_signature: ResponseSignature {
                signer_key_id: "us-steward-2026".to_string(),
                ed25519_b64: "ZmFrZQ==".to_string(),
                mldsa65_b64: "ZmFrZQ==".to_string(),
                canonical_bytes_label: STEWARD_KEY_RESPONSE_DOMAIN_PREFIX.to_string(),
            },
        }
    }

    fn fake_pubkey() -> StewardPublicKey {
        StewardPublicKey {
            ed25519: &[0u8; 32],
            ml_dsa_65: &[],
        }
    }

    #[test]
    fn canonical_bytes_start_with_domain_prefix_then_newline() {
        let r = sample_response();
        let bytes = r.canonical_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("ciris.steward_key_response.v1\n"));
    }

    #[test]
    fn canonical_bytes_exclude_response_signature_field() {
        // Two responses with identical body but different
        // response_signature must produce identical canonical bytes.
        let mut r1 = sample_response();
        let mut r2 = sample_response();
        r1.response_signature.ed25519_b64 = "AAAA".into();
        r2.response_signature.ed25519_b64 = "BBBB".into();
        assert_eq!(r1.canonical_bytes(), r2.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_differ_when_body_differs() {
        let r1 = sample_response();
        let mut r2 = sample_response();
        r2.threshold_policy.required = 3;
        assert_ne!(r1.canonical_bytes(), r2.canonical_bytes());
    }

    #[test]
    fn deployed_stewards_filters_placeholders() {
        let r = sample_response();
        let deployed: Vec<&Steward> = r.deployed_stewards().collect();
        assert_eq!(deployed.len(), 1);
        assert_eq!(deployed[0].key_id, "us-steward-2026");
    }

    #[test]
    fn to_attestation_entries_emits_only_deployed_stewards() {
        // §10.2 normative: placeholder pubkeys MUST NOT be promoted
        // to trust roots. to_attestation_entries enforces this
        // structurally — undeployed stewards produce no entries.
        let r = sample_response();
        let entries = r.to_attestation_entries("us-steward-2026");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dimension, "cert_validity:us-steward-2026");
        assert_eq!(entries[0].attester, "us-steward-2026");
        assert!(entries[0]
            .source_ref
            .as_deref()
            .unwrap()
            .starts_with("valid_until:"));
    }

    #[test]
    fn to_attestation_entries_returns_empty_when_all_undeployed() {
        let mut r = sample_response();
        for s in &mut r.stewards {
            s.deployed = false;
        }
        let entries = r.to_attestation_entries("attester");
        assert!(entries.is_empty(), "no deployed stewards → no entries");
    }

    #[test]
    fn verify_rejects_wrong_canonical_bytes_label() {
        let mut r = sample_response();
        r.response_signature.canonical_bytes_label = "ciris.other_response.v1".to_string();
        let bytes = serde_json::to_vec(&r).unwrap();
        let err = verify_steward_key_response(&bytes, &fake_pubkey()).unwrap_err();
        assert!(format!("{err}").contains("§10.2"));
        assert!(format!("{err}").contains("canonical_bytes_label"));
    }

    #[test]
    fn verify_rejects_signer_who_is_placeholder() {
        // §10.2 normative: a placeholder (undeployed) steward MUST
        // NOT sign — its pubkey isn't a trust root.
        let mut r = sample_response();
        r.response_signature.signer_key_id = "eu-steward-2026".to_string(); // eu is deployed=false in sample
        let bytes = serde_json::to_vec(&r).unwrap();
        let err = verify_steward_key_response(&bytes, &fake_pubkey()).unwrap_err();
        assert!(format!("{err}").contains("placeholder"));
    }

    #[test]
    fn verify_rejects_signer_not_in_stewards_list() {
        let mut r = sample_response();
        r.response_signature.signer_key_id = "rogue-steward".to_string();
        let bytes = serde_json::to_vec(&r).unwrap();
        let err = verify_steward_key_response(&bytes, &fake_pubkey()).unwrap_err();
        assert!(format!("{err}").contains("does not appear"));
    }

    #[test]
    fn verify_rejects_bad_json() {
        let bytes = b"{not valid json";
        let err = verify_steward_key_response(bytes, &fake_pubkey()).unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn json_round_trip_preserves_all_fields() {
        let r = sample_response();
        let json = serde_json::to_string(&r).unwrap();
        let back: StewardKeyResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stewards.len(), 3);
        assert_eq!(back.threshold_policy.required, 2);
        assert_eq!(back.response_signature.signer_key_id, "us-steward-2026");
        assert_eq!(
            back.response_signature.canonical_bytes_label,
            STEWARD_KEY_RESPONSE_DOMAIN_PREFIX
        );
    }

    /// CEG 0.2 §10.2 byte-layout stability: a change to the domain
    /// prefix string breaks federation-wide steward-key signature
    /// verification. Lock the constant.
    #[test]
    fn domain_prefix_is_stable_wire_constant() {
        assert_eq!(
            STEWARD_KEY_RESPONSE_DOMAIN_PREFIX,
            "ciris.steward_key_response.v1"
        );
    }
}
