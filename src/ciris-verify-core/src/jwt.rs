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
        let bound_payload = [
            self.signing_input.as_bytes(),
            &self.classical_signature[..],
        ]
        .concat();

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
            issued_at: self.payload.iat,
            expires_at: self.payload.exp,
            not_before: self.payload.nbf,
            capabilities: self.payload.capabilities.clone(),
            capabilities_denied: self.payload.capabilities_denied.clone(),
            max_autonomy_tier: self.payload.max_tier,
            constraints: self.payload.constraints.clone(),
            license_jwt: original_jwt.to_string(),
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

        format!("{}.{}.{}.{}", header_b64, payload_b64, classical_sig, pqc_sig)
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
}
