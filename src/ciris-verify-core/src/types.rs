//! Protocol types for CIRISVerify requests and responses.

use serde::{Deserialize, Serialize};
use ciris_keyring::PlatformAttestation;

use crate::license::{LicenseDetails, LicenseStatus};

/// Request for license status verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatusRequest {
    /// Unique deployment identifier (hardware-derived if available).
    pub deployment_id: String,

    /// Random nonce to prevent replay attacks (32+ bytes required).
    pub challenge_nonce: Vec<u8>,

    /// Force refresh from remote sources (bypass cache).
    #[serde(default)]
    pub force_refresh: bool,
}

impl LicenseStatusRequest {
    /// Validate the request.
    ///
    /// # Errors
    ///
    /// Returns error if nonce is too short.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.challenge_nonce.len() < 32 {
            return Err("Nonce must be at least 32 bytes");
        }
        Ok(())
    }
}

/// Response containing license status and attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatusResponse {
    /// Overall license status.
    pub status: LicenseStatus,

    /// License details (if licensed).
    pub license: Option<LicenseDetails>,

    /// CRITICAL: This string MUST be displayed to users.
    pub mandatory_disclosure: MandatoryDisclosure,

    /// Hardware attestation proving response authenticity.
    pub attestation: ResponseAttestation,

    /// Multi-source validation results.
    pub validation: ValidationResults,

    /// Response metadata.
    pub metadata: ResponseMetadata,
}

/// Mandatory disclosure that MUST be shown to users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandatoryDisclosure {
    /// The disclosure text.
    pub text: String,

    /// Severity level for display.
    pub severity: DisclosureSeverity,

    /// Locale of the disclosure.
    pub locale: String,
}

/// Severity level for mandatory disclosures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureSeverity {
    /// Informational (licensed professional).
    Info,
    /// Warning (community mode).
    Warning,
    /// Critical (security issue).
    Critical,
}

/// Attestation data for the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAttestation {
    /// Platform attestation from hardware.
    pub platform: PlatformAttestation,

    /// Hybrid signature over the response.
    pub signature: ResponseSignature,

    /// Binary integrity status.
    pub integrity_valid: bool,

    /// Timestamp of attestation.
    pub timestamp: i64,
}

/// Hybrid signature over the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSignature {
    /// Classical signature bytes.
    pub classical: Vec<u8>,

    /// Classical algorithm used.
    pub classical_algorithm: String,

    /// PQC signature bytes.
    pub pqc: Vec<u8>,

    /// PQC algorithm used.
    pub pqc_algorithm: String,
}

/// Multi-source validation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResults {
    /// DNS US source result.
    pub dns_us: SourceResult,

    /// DNS EU source result.
    pub dns_eu: SourceResult,

    /// HTTPS endpoint result.
    pub https: SourceResult,

    /// Overall validation status.
    pub overall: ValidationStatus,
}

/// Result from a single validation source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceResult {
    /// Source identifier.
    pub source: String,

    /// Was the source reachable?
    pub reachable: bool,

    /// Did it return valid data?
    pub valid: bool,

    /// Timestamp of check.
    pub checked_at: i64,

    /// Error message if failed.
    pub error: Option<String>,
}

/// Overall validation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// All 3 sources agree.
    AllSourcesAgree,
    /// 2 of 3 sources agree (degraded).
    PartialAgreement,
    /// Sources disagree (possible attack).
    SourcesDisagree,
    /// No sources reachable (offline).
    NoSourcesReachable,
    /// Validation error.
    ValidationError,
}

/// Response metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    /// Protocol version.
    pub protocol_version: String,

    /// Binary version.
    pub binary_version: String,

    /// Response timestamp.
    pub timestamp: i64,

    /// Recommended cache TTL in seconds.
    pub cache_ttl: u32,

    /// Request ID for debugging.
    pub request_id: String,
}

/// Request to check a specific capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCheckRequest {
    /// Capability identifier (e.g., "domain:medical:triage").
    pub capability: String,

    /// Action requiring this capability.
    pub action: String,

    /// Required autonomy tier.
    pub required_tier: u8,
}

/// Response for capability check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCheckResponse {
    /// Is the capability allowed?
    pub allowed: bool,

    /// Reason for denial (if not allowed).
    pub denial_reason: Option<String>,

    /// Required conditions (if conditionally allowed).
    pub required_conditions: Vec<String>,

    /// Suggested alternative (if denied).
    pub suggested_alternative: Option<String>,
}
