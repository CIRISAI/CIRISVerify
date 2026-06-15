//! Hybrid JWT parsing and verification.
//!
//! Handles 4-part JWT format: header.payload.classical_sig.pqc_sig
//!
//! ## Security Properties
//!
//! - PQC signature covers classical signature (binding)
//! - Both signatures must verify for validity
//! - Constant-time signature comparison

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::license::{AutonomyTier, DeploymentConstraints, LicenseDetails, LicenseType};

/// Parser for hybrid license JWTs.
pub struct HybridJwtParser;

impl HybridJwtParser {
    /// Parse a hybrid JWT string.
    ///
    /// Expected format: `header.payload.classical_sig.pqc_sig`
    ///
    /// # Errors
    ///
    /// Returns error if format is invalid or base64 decoding fails.
    pub fn parse(token: &str) -> Result<HybridJwt, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();

        if parts.len() != 4 {
            return Err(JwtError::InvalidFormat(format!(
                "Expected 4 parts for hybrid JWT, got {}",
                parts.len()
            )));
        }

        // Decode header
        let header_bytes = base64url_decode(parts[0])?;
        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| JwtError::JsonError(e.to_string()))?;

        // Decode payload
        let payload_bytes = base64url_decode(parts[1])?;
        let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| JwtError::JsonError(e.to_string()))?;

        // Decode signatures
        let classical_signature = base64url_decode(parts[2])?;
        let pqc_signature = base64url_decode(parts[3])?;

        // Store raw parts for verification
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        Ok(HybridJwt {
            header,
            payload,
            classical_signature,
            pqc_signature,
            signing_input,
        })
    }
}

/// Decoded base64url string.
fn base64url_decode(input: &str) -> Result<Vec<u8>, JwtError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| JwtError::Base64Error(e.to_string()))
}

/// Encode to base64url.
#[allow(dead_code)]
fn base64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Parsed hybrid JWT.
#[derive(Debug, Clone)]
pub struct HybridJwt {
    /// JWT header.
    pub header: JwtHeader,
    /// JWT payload.
    pub payload: LicensePayload,
    /// Classical signature bytes.
    pub classical_signature: Vec<u8>,
    /// PQC signature bytes.
    pub pqc_signature: Vec<u8>,
    /// Raw signing input (header.payload) for verification.
    signing_input: String,
}

impl HybridJwt {
    /// Verify the JWT using steward keys.
    ///
    /// Both signatures must verify:
    /// 1. Classical signature over signing input
    /// 2. PQC signature over (signing input || classical signature)
    ///
    /// # Errors
    ///
    /// Returns error if verification fails or keys are invalid.
    pub fn verify<C, P>(&self, classical_verifier: &C, pqc_verifier: &P) -> Result<bool, JwtError>
    where
        C: ClassicalVerifier,
        P: PqcVerifier,
    {
        // 1. Verify classical signature over signing input
        let classical_valid = classical_verifier
            .verify(self.signing_input.as_bytes(), &self.classical_signature)
            .map_err(|e| JwtError::VerificationError(format!("Classical: {}", e)))?;

        if !classical_valid {
            return Ok(false);
        }

        // 2. Build bound payload: signing_input || classical_signature
        let bound_payload = [self.signing_input.as_bytes(), &self.classical_signature[..]].concat();

        // 3. Verify PQC signature over bound payload
        let pqc_valid = pqc_verifier
            .verify(&bound_payload, &self.pqc_signature)
            .map_err(|e| JwtError::VerificationError(format!("PQC: {}", e)))?;

        Ok(pqc_valid)
    }

    /// Get the signing input for signature verification.
    #[must_use]
    pub fn signing_input(&self) -> &str {
        &self.signing_input
    }

    /// Convert to license details.
    ///
    /// # Panics
    ///
    /// Panics if the original token cannot be reconstructed.
    #[must_use]
    pub fn to_license_details(&self, original_jwt: &str) -> LicenseDetails {
        LicenseDetails {
            license_id: self.payload.jti.clone(),
            license_type: self.payload.license_type,
            organization_name: self.payload.org_name.clone(),
            organization_id: self.payload.org_id.clone(),
            responsible_party: self.payload.responsible_party.clone(),
            responsible_party_contact: self.payload.responsible_party_contact.clone(),
            issued_at: self.payload.iat,
            expires_at: self.payload.exp,
            not_before: self.payload.nbf,
            capabilities: self.payload.capabilities.clone(),
            capabilities_denied: self.payload.capabilities_denied.clone(),
            max_autonomy_tier: self.payload.max_tier,
            constraints: self.payload.constraints.clone(),
            license_jwt: original_jwt.to_string(),
            identity_template: String::new(),
            stewardship_tier: 0,
            permitted_actions: vec![],
            template_hash: vec![],
        }
    }
}

/// JWT header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Algorithm identifier.
    pub alg: String,
    /// Token type.
    #[serde(default = "default_typ")]
    pub typ: String,
    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

fn default_typ() -> String {
    "JWT".to_string()
}

/// License payload (JWT claims).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// JWT ID (license ID).
    pub jti: String,
    /// Issuer (registry URL).
    pub iss: String,
    /// Subject (deployment ID).
    pub sub: String,
    /// Audience.
    #[serde(default)]
    pub aud: Vec<String>,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Not before (Unix timestamp).
    pub nbf: i64,
    /// License type.
    #[serde(rename = "license_type")]
    pub license_type: LicenseType,
    /// Organization name.
    #[serde(rename = "org_name")]
    pub org_name: String,
    /// Organization ID.
    #[serde(rename = "org_id")]
    pub org_id: String,
    /// Responsible licensed party name.
    #[serde(default)]
    pub responsible_party: String,
    /// Contact for the responsible party.
    #[serde(default)]
    pub responsible_party_contact: String,
    /// Granted capabilities.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Denied capabilities.
    #[serde(default)]
    pub capabilities_denied: Vec<String>,
    /// Maximum autonomy tier.
    #[serde(rename = "max_tier")]
    pub max_tier: AutonomyTier,
    /// Deployment constraints.
    #[serde(default)]
    pub constraints: DeploymentConstraints,
}

/// Trait for classical signature verification.
pub trait ClassicalVerifier {
    /// Verify a classical signature.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>;
}

/// Trait for PQC signature verification.
pub trait PqcVerifier {
    /// Verify a PQC signature.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>;
}

/// Steward keys for verification.
#[derive(Debug, Clone)]
pub struct StewardKeys {
    /// Classical public key (ECDSA P-256 or Ed25519).
    pub classical_key: Vec<u8>,
    /// Classical algorithm.
    pub classical_algorithm: String,
    /// PQC public key (ML-DSA-65).
    pub pqc_key: Vec<u8>,
    /// PQC algorithm.
    pub pqc_algorithm: String,
}

// ============================================================================
// License signature verification (CIRISVerify#72 — trust-root gate)
// ============================================================================
//
// A `Licensed*` status MUST NOT be derived from cache contents alone. Before
// the engine maps a `LicenseDetails` to a professional tier, the signed JWT it
// carries is re-verified here against the consensus steward key. A forged cache
// entry (or any JWT not signed by the genuine steward) fails this gate and is
// degraded to community/unverified — closing the masquerade vulnerability.

/// Key-bound Ed25519 verifier adapting `ciris_crypto::Ed25519Verifier` to the
/// local key-bound [`ClassicalVerifier`] trait used by [`HybridJwt::verify`].
struct Ed25519KeyVerifier<'a> {
    public_key: &'a [u8],
}

impl ClassicalVerifier for Ed25519KeyVerifier<'_> {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        use ciris_crypto::{ClassicalVerifier as CryptoClassicalVerifier, Ed25519Verifier};
        Ed25519Verifier::new()
            .verify(self.public_key, data, signature)
            .map_err(|e| e.to_string())
    }
}

/// Key-bound ML-DSA-65 verifier adapting `ciris_crypto::MlDsa65Verifier` to the
/// local key-bound [`PqcVerifier`] trait used by [`HybridJwt::verify`].
struct MlDsa65KeyVerifier<'a> {
    public_key: &'a [u8],
}

impl PqcVerifier for MlDsa65KeyVerifier<'_> {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        use ciris_crypto::{MlDsa65Verifier, PqcVerifier as CryptoPqcVerifier};
        MlDsa65Verifier::new()
            .verify(self.public_key, data, signature)
            .map_err(|e| e.to_string())
    }
}

/// Outcome of verifying a license JWT against the consensus steward key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseVerification {
    /// Both classical and PQC signatures verified against the steward key.
    HybridVerified,
    /// Classical signature verified, but the PQC half could not be checked —
    /// the full PQC steward key was unavailable (e.g. DNS-only consensus, or
    /// the registry has not yet published `steward_key_pqc`) or the PQC backend
    /// is not compiled in. Cryptographically gated by the classical signature
    /// (defeats a forged cache), but **NOT federation-licensable at CEG 1.0**:
    /// per RC7 §10.1.5.1.1 a `Licensed*` tier requires both halves, because a
    /// classical-only license is forgeable by a future Ed25519 break (the HNDL
    /// threat). A `ClassicalVerified` license **degrades to community** until
    /// the hybrid steward key is available — see [`Self::is_licensable`].
    ClassicalVerified,
    /// Verification failed — forged, tampered, malformed, or not signed by the
    /// consensus steward. Callers MUST degrade to community/unverified.
    Failed,
}

impl LicenseVerification {
    /// Whether this outcome permits a federation-tier `Licensed*` status.
    ///
    /// **`HybridVerified` only** (CEG 1.0-RC7 §10.1.5.1.1 / F-AV-14): the PQC
    /// half is MANDATORY at the federation admission boundary — there is no
    /// `require_hybrid: false` posture at 1.0. `ClassicalVerified` is
    /// classically gated (and is the right state to log) but is **not**
    /// federation-licensable; such a license degrades to community until its
    /// hybrid steward key is published. Accepting the classical half alone
    /// would make professional-tier licensing forgeable by a single future
    /// Ed25519 break — the exact threat the hybrid model defends.
    #[must_use]
    pub fn is_licensable(&self) -> bool {
        matches!(self, LicenseVerification::HybridVerified)
    }

    /// Whether the classical steward signature verified (either `HybridVerified`
    /// or `ClassicalVerified`). Defeats a forged cache, but is NOT sufficient
    /// for a federation `Licensed*` tier on its own — use [`Self::is_licensable`]
    /// for the admission decision. Exposed for diagnostics / local-tier logging.
    #[must_use]
    pub fn classical_gate_held(&self) -> bool {
        matches!(
            self,
            LicenseVerification::HybridVerified | LicenseVerification::ClassicalVerified
        )
    }
}

/// Verify a license JWT against the consensus steward key material.
///
/// This is the cryptographic gate that the engine MUST clear before returning
/// any `Licensed*` status (CIRISVerify#72). It is fail-closed: any parse error,
/// missing classical key, or signature mismatch yields
/// [`LicenseVerification::Failed`].
///
/// # Arguments
///
/// * `token` — the raw 4-part hybrid JWT (`header.payload.classical.pqc`).
/// * `consensus_classical_key` — the steward classical (Ed25519) public key
///   agreed by multi-source consensus. This is the authenticated key; the JWT
///   does **not** carry its own trusted keys.
/// * `consensus_pqc_key` — the full steward PQC (ML-DSA-65) public key, if a
///   source provided it. When `None`, only classical verification is performed.
/// * `consensus_pqc_fingerprint` — SHA-256 fingerprint of the steward PQC key
///   from consensus. When present, the supplied `consensus_pqc_key` is bound to
///   it (constant-time) before any PQC trust — a substituted full key fails.
#[must_use]
pub fn verify_license_jwt(
    token: &str,
    consensus_classical_key: &[u8],
    consensus_pqc_key: Option<&[u8]>,
    consensus_pqc_fingerprint: Option<&[u8]>,
) -> LicenseVerification {
    // Fail-closed: an empty/absent classical steward key means we have no
    // authenticated authority to verify against. Never licensable.
    if consensus_classical_key.is_empty() {
        return LicenseVerification::Failed;
    }

    let jwt = match HybridJwtParser::parse(token) {
        Ok(j) => j,
        Err(_) => return LicenseVerification::Failed,
    };

    // 1. Classical signature is the hard gate (always required).
    let classical_verifier = Ed25519KeyVerifier {
        public_key: consensus_classical_key,
    };

    // Decide whether we can also verify the PQC half. The full PQC key must be
    // present AND match the consensus fingerprint (a substituted key is
    // rejected). If the fingerprint is absent we still bind to the key we were
    // given, but treat the result as classical-gated only when PQC can't run.
    let pqc_key_trusted: Option<&[u8]> = match consensus_pqc_key {
        Some(key) if !key.is_empty() => {
            if let Some(expected_fp) = consensus_pqc_fingerprint {
                let actual_fp = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(key);
                    h.finalize().to_vec()
                };
                if ciris_crypto::constant_time_eq(&actual_fp, expected_fp) {
                    Some(key)
                } else {
                    // Full key does not match the consensus fingerprint:
                    // refuse to trust it for PQC, fall back to classical gate.
                    None
                }
            } else {
                Some(key)
            }
        },
        _ => None,
    };

    match pqc_key_trusted {
        Some(pqc_key) => {
            let pqc_verifier = MlDsa65KeyVerifier {
                public_key: pqc_key,
            };
            match jwt.verify(&classical_verifier, &pqc_verifier) {
                Ok(true) => LicenseVerification::HybridVerified,
                // Either signature failed. If the failure was purely because
                // the PQC backend is not compiled in, `verify` returns Err; we
                // retry classical-only below to preserve the classical gate.
                Ok(false) => LicenseVerification::Failed,
                Err(_) => verify_classical_only(&jwt, &classical_verifier),
            }
        },
        None => verify_classical_only(&jwt, &classical_verifier),
    }
}

/// Verify only the classical half of the JWT against the steward key.
///
/// Used when the full PQC steward key is unavailable or the PQC backend is not
/// compiled in. The classical signature alone still defeats a forged cache.
fn verify_classical_only(
    jwt: &HybridJwt,
    classical_verifier: &Ed25519KeyVerifier<'_>,
) -> LicenseVerification {
    let classical_valid = ClassicalVerifier::verify(
        classical_verifier,
        jwt.signing_input().as_bytes(),
        &jwt.classical_signature,
    )
    .unwrap_or(false);

    if classical_valid {
        LicenseVerification::ClassicalVerified
    } else {
        LicenseVerification::Failed
    }
}

/// JWT parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// Invalid JWT format.
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),
    /// Base64 decode error.
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    /// JSON parse error.
    #[error("JSON parse error: {0}")]
    JsonError(String),
    /// Signature verification error.
    #[error("Verification error: {0}")]
    VerificationError(String),
    /// Token expired.
    #[error("Token expired")]
    Expired,
    /// Token not yet valid.
    #[error("Token not yet valid")]
    NotYetValid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_jwt() -> String {
        let header = JwtHeader {
            alg: "CIRIS_HYBRID_V1".to_string(),
            typ: "JWT".to_string(),
            kid: Some("steward-key-2026".to_string()),
        };

        let payload = LicensePayload {
            jti: "lic-12345".to_string(),
            iss: "https://registry.ciris.ai".to_string(),
            sub: "deploy-67890".to_string(),
            aud: vec!["ciris-verify".to_string()],
            iat: 1737936000,
            exp: 1769472000,
            nbf: 1737936000,
            license_type: LicenseType::ProfessionalMedical,
            org_name: "Test Hospital".to_string(),
            org_id: "org-abc123".to_string(),
            responsible_party: "Dr. Jane Smith".to_string(),
            responsible_party_contact: "jsmith@testhospital.org".to_string(),
            capabilities: vec!["domain:medical:triage".to_string()],
            capabilities_denied: vec![],
            max_tier: AutonomyTier::A3High,
            constraints: DeploymentConstraints::default(),
        };

        let header_b64 = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64url_encode(&serde_json::to_vec(&payload).unwrap());

        // Fake signatures for testing parse (not verify)
        let classical_sig = base64url_encode(&[0u8; 64]);
        let pqc_sig = base64url_encode(&[0u8; 128]);

        format!(
            "{}.{}.{}.{}",
            header_b64, payload_b64, classical_sig, pqc_sig
        )
    }

    #[test]
    fn test_parse_valid_jwt() {
        let token = create_test_jwt();
        let jwt = HybridJwtParser::parse(&token).unwrap();

        assert_eq!(jwt.header.alg, "CIRIS_HYBRID_V1");
        assert_eq!(jwt.payload.jti, "lic-12345");
        assert_eq!(jwt.payload.license_type, LicenseType::ProfessionalMedical);
        assert_eq!(jwt.classical_signature.len(), 64);
        assert_eq!(jwt.pqc_signature.len(), 128);
    }

    #[test]
    fn test_parse_invalid_part_count() {
        let result = HybridJwtParser::parse("a.b.c");
        assert!(matches!(result, Err(JwtError::InvalidFormat(_))));
    }

    #[test]
    fn test_parse_invalid_base64() {
        let result = HybridJwtParser::parse("!!!.@@@.###.$$$");
        assert!(matches!(result, Err(JwtError::Base64Error(_))));
    }

    #[test]
    fn test_to_license_details() {
        let token = create_test_jwt();
        let jwt = HybridJwtParser::parse(&token).unwrap();
        let details = jwt.to_license_details(&token);

        assert_eq!(details.license_id, "lic-12345");
        assert_eq!(details.organization_name, "Test Hospital");
        assert_eq!(details.max_autonomy_tier, AutonomyTier::A3High);
    }

    // ========================================================================
    // CIRISVerify#72 — license signature verification (forgery rejection)
    // ========================================================================

    use ciris_crypto::{ClassicalSigner, Ed25519Signer};
    #[cfg(feature = "pqc")]
    use ciris_crypto::{MlDsa65Signer, PqcSigner};

    /// Build a real hybrid-signed JWT signed by `classical_signer` (and, with
    /// the PQC backend, `pqc_signer`). Returns `(token, classical_pubkey,
    /// pqc_pubkey)`.
    fn sign_test_jwt(classical_signer: &Ed25519Signer) -> (String, Vec<u8>, Option<Vec<u8>>) {
        let header = JwtHeader {
            alg: "CIRIS_HYBRID_V1".to_string(),
            typ: "JWT".to_string(),
            kid: Some("steward-key-2026".to_string()),
        };
        let payload = LicensePayload {
            jti: "lic-signed-1".to_string(),
            iss: "https://registry.ciris.ai".to_string(),
            sub: "deploy-1".to_string(),
            aud: vec!["ciris-verify".to_string()],
            iat: 1737936000,
            exp: 1769472000,
            nbf: 1737936000,
            license_type: LicenseType::ProfessionalMedical,
            org_name: "Test Hospital".to_string(),
            org_id: "org-1".to_string(),
            responsible_party: "Dr. Test".to_string(),
            responsible_party_contact: "t@h.org".to_string(),
            capabilities: vec!["domain:medical:triage".to_string()],
            capabilities_denied: vec![],
            max_tier: AutonomyTier::A3High,
            constraints: DeploymentConstraints::default(),
        };

        let header_b64 = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let classical_sig = classical_signer.sign(signing_input.as_bytes()).unwrap();
        let classical_pub = classical_signer.public_key().unwrap();

        // PQC signature covers (signing_input || classical_sig).
        #[cfg(feature = "pqc")]
        let (pqc_sig, pqc_pub): (Vec<u8>, Option<Vec<u8>>) = {
            let pqc = MlDsa65Signer::new().unwrap();
            let mut bound = signing_input.as_bytes().to_vec();
            bound.extend_from_slice(&classical_sig);
            (pqc.sign(&bound).unwrap(), Some(pqc.public_key().unwrap()))
        };
        #[cfg(not(feature = "pqc"))]
        let (pqc_sig, pqc_pub): (Vec<u8>, Option<Vec<u8>>) = (vec![0u8; 8], None);

        let token = format!(
            "{}.{}.{}.{}",
            header_b64,
            payload_b64,
            base64url_encode(&classical_sig),
            base64url_encode(&pqc_sig),
        );
        (token, classical_pub, pqc_pub)
    }

    fn pqc_fingerprint(key: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(key);
        h.finalize().to_vec()
    }

    /// PROOF: a JWT validly signed by the consensus steward verifies.
    #[test]
    fn test_verify_valid_steward_license() {
        let steward = Ed25519Signer::random().unwrap();
        let (token, classical_pub, pqc_pub) = sign_test_jwt(&steward);
        let fp = pqc_pub.as_deref().map(pqc_fingerprint);

        let outcome = verify_license_jwt(&token, &classical_pub, pqc_pub.as_deref(), fp.as_deref());

        assert!(
            outcome.is_licensable(),
            "validly steward-signed license must be licensable, got {:?}",
            outcome
        );
    }

    /// PROOF (the vuln is closed): a forged license — valid 4-part JWT but
    /// signed by an attacker, NOT the consensus steward — is NOT licensable.
    #[test]
    fn test_verify_forged_license_rejected() {
        let steward = Ed25519Signer::random().unwrap();
        let attacker = Ed25519Signer::random().unwrap();

        // Attacker forges a "ProfessionalMedical" JWT under their own key.
        let (forged_token, _attacker_pub, attacker_pqc_pub) = sign_test_jwt(&attacker);
        let attacker_fp = attacker_pqc_pub.as_deref().map(pqc_fingerprint);

        // Verified against the GENUINE steward consensus key.
        let steward_pub = steward.public_key().unwrap();
        let outcome = verify_license_jwt(
            &forged_token,
            &steward_pub,
            attacker_pqc_pub.as_deref(),
            attacker_fp.as_deref(),
        );

        assert_eq!(
            outcome,
            LicenseVerification::Failed,
            "forged license signed by a non-steward key MUST be rejected"
        );
        assert!(!outcome.is_licensable());
    }

    /// A substituted PQC key that does not match the consensus fingerprint must
    /// not be trusted for PQC; we fall back to (and still require) the classical
    /// gate, so a genuine steward-classical-signed token stays classical-only.
    #[cfg(feature = "pqc")]
    #[test]
    fn test_verify_pqc_key_fingerprint_mismatch_falls_back_to_classical() {
        let steward = Ed25519Signer::random().unwrap();
        let (token, classical_pub, _real_pqc_pub) = sign_test_jwt(&steward);

        // Attacker substitutes a different PQC key + matching-but-wrong fingerprint
        let wrong_pqc = MlDsa65Signer::new().unwrap().public_key().unwrap();
        let consensus_fp = pqc_fingerprint(&[0xAB; 32]); // does not match wrong_pqc

        let outcome = verify_license_jwt(
            &token,
            &classical_pub,
            Some(&wrong_pqc),
            Some(&consensus_fp),
        );

        // Classical gate still holds (genuine steward classical sig), PQC refused.
        assert_eq!(outcome, LicenseVerification::ClassicalVerified);
        // Classical gate held, but classical-only is NOT federation-licensable
        // at 1.0 (RC7 §10.1.5.1.1) — degrades to community.
        assert!(outcome.classical_gate_held());
        assert!(!outcome.is_licensable());
    }

    /// Classical-only consensus (no full PQC key, e.g. DNS-only) still gates on
    /// the classical steward signature.
    #[test]
    fn test_verify_classical_only_consensus() {
        let steward = Ed25519Signer::random().unwrap();
        let (token, classical_pub, _pqc_pub) = sign_test_jwt(&steward);

        let outcome = verify_license_jwt(&token, &classical_pub, None, None);
        assert_eq!(outcome, LicenseVerification::ClassicalVerified);
        // Classically gated (defeats a forged cache) but not federation-licensable.
        assert!(outcome.classical_gate_held());
        assert!(!outcome.is_licensable());
    }

    /// A wrong consensus classical key rejects an otherwise-valid token.
    #[test]
    fn test_verify_wrong_consensus_key_rejected() {
        let steward = Ed25519Signer::random().unwrap();
        let (token, _classical_pub, _pqc_pub) = sign_test_jwt(&steward);

        let wrong_key = Ed25519Signer::random().unwrap().public_key().unwrap();
        let outcome = verify_license_jwt(&token, &wrong_key, None, None);
        assert_eq!(outcome, LicenseVerification::Failed);
    }

    /// Empty consensus key fails closed (no authority to verify against).
    #[test]
    fn test_verify_empty_consensus_key_fails_closed() {
        let steward = Ed25519Signer::random().unwrap();
        let (token, _pub, _pqc) = sign_test_jwt(&steward);
        assert_eq!(
            verify_license_jwt(&token, &[], None, None),
            LicenseVerification::Failed
        );
    }

    /// A malformed (non-JWT) token fails closed.
    #[test]
    fn test_verify_malformed_token_fails_closed() {
        let key = Ed25519Signer::random().unwrap().public_key().unwrap();
        assert_eq!(
            verify_license_jwt("not-a-jwt", &key, None, None),
            LicenseVerification::Failed
        );
    }
}
