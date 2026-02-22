//! Protocol types for CIRISVerify requests and responses.

use ciris_keyring::PlatformAttestation;
use serde::{Deserialize, Serialize};

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

    // === Runtime validation (v1.2.0) ===
    /// Agent binary hash (from registry).
    #[serde(default)]
    pub agent_hash: Option<Vec<u8>>,

    /// Template YAML hash (SHA-256).
    #[serde(default)]
    pub template_hash: Option<Vec<u8>>,

    /// Currently running identity template name.
    #[serde(default)]
    pub running_template: Option<String>,

    /// Currently active action set.
    #[serde(default)]
    pub active_actions: Option<Vec<String>>,

    /// Current stewardship tier in use.
    #[serde(default)]
    pub current_stewardship_tier: Option<u8>,
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

    // === Runtime validation (v1.2.0) ===
    /// Runtime validation results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_validation: Option<RuntimeValidation>,

    /// Shutdown directive (if emergency or critical violation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shutdown_directive: Option<ShutdownDirective>,

    // === Function integrity (v0.6.0) ===
    /// Function-level integrity verification status.
    ///
    /// Indicates whether the FFI functions match their build-time hashes.
    /// Per threat model AV-2, the status does not reveal WHICH function failed.
    ///
    /// Values: "verified", "tampered", "unavailable:{reason}",
    ///         "signature_invalid", "not_found", "pending"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_integrity: Option<String>,

    // === Binary integrity (v0.6.17) ===
    /// Binary-level self-verification status.
    ///
    /// Indicates whether the CIRISVerify binary matches its registry manifest.
    /// This is the "who watches the watchmen" check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_integrity: Option<BinaryIntegrityStatus>,
}

/// Binary integrity verification status (v0.6.17).
///
/// Reports whether the running CIRISVerify binary matches its registry manifest.
/// This provides "self-verification" capability - the binary can prove it hasn't
/// been tampered with since it was built and published.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIntegrityStatus {
    /// Overall verification status.
    /// Values: "verified", "tampered", "unavailable", "not_found", "pending"
    pub status: String,

    /// CIRISVerify binary version.
    pub version: String,

    /// Target platform (e.g., "x86_64-unknown-linux-gnu").
    pub target: String,

    /// Computed hash of the running binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_hash: Option<String>,

    /// Expected hash from registry manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,

    /// Whether the hashes match.
    pub matches: bool,

    /// Error message if verification failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Timestamp of verification (Unix seconds).
    pub verified_at: i64,
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

    /// PQC signature bytes (ML-DSA-65, bound over classical sig).
    pub pqc: Vec<u8>,

    /// PQC algorithm used.
    pub pqc_algorithm: String,

    /// PQC public key bytes (for verifiers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pqc_public_key: Vec<u8>,

    /// Signature mode (should be "HybridRequired" for v2.0).
    #[serde(default = "default_signature_mode")]
    pub signature_mode: String,
}

fn default_signature_mode() -> String {
    "HybridRequired".to_string()
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

    /// Error message if failed (internal use only, not serialized in responses).
    #[serde(skip_serializing)]
    pub error: Option<String>,

    /// User-visible error category for debugging (serialized to client).
    /// Examples: "timeout", "dns_resolution", "tls_handshake", "connection_refused"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,

    /// User-visible error details for debugging (serialized to client).
    /// Contains sanitized error message without sensitive internals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_details: Option<String>,
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

// =============================================================================
// RUNTIME VALIDATION (v1.2.0)
// =============================================================================

/// Runtime validation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeValidation {
    /// Whether runtime state passes validation.
    pub valid: bool,

    /// List of violations found.
    pub violations: Vec<RuntimeViolation>,

    /// Enforcement action to take.
    pub enforcement_action: EnforcementAction,
}

/// A single runtime violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeViolation {
    /// Human-readable violation description.
    pub description: String,

    /// Violation severity.
    pub severity: ViolationSeverity,

    /// Field that violated (e.g., "running_template", "active_actions").
    pub field: String,

    /// Expected value.
    pub expected: String,

    /// Actual value found.
    pub actual: String,
}

/// Directive to shut down the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownDirective {
    /// Type of shutdown required.
    pub shutdown_type: ShutdownType,

    /// Reason for shutdown.
    pub reason: String,

    /// Deadline in seconds (0 = immediate).
    pub deadline_seconds: u32,

    /// Incident ID for audit trail.
    pub incident_id: String,

    /// Authority that issued the directive.
    pub issued_by: String,
}

/// Severity of a runtime violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Log and continue.
    Warning,
    /// Degrade capabilities.
    Error,
    /// Immediate shutdown required.
    Critical,
}

/// Enforcement action for runtime violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementAction {
    /// No action needed (all valid).
    None,
    /// Log warning, continue.
    Warn,
    /// Reduce to community mode.
    Degrade,
    /// Immediate shutdown required.
    Shutdown,
}

/// Type of shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShutdownType {
    /// Graceful shutdown with deadline.
    Graceful,
    /// Immediate shutdown.
    Immediate,
    /// Emergency kill (SIGTERM + grace + SIGKILL).
    Emergency,
}

// =============================================================================
// REMOTE ATTESTATION PROOF EXPORT
// =============================================================================

/// Exportable attestation proof for third-party verification.
///
/// Contains all data needed for an external verifier to independently confirm:
/// 1. Hardware binding (platform attestation)
/// 2. Cryptographic identity (classical + PQC public keys)
/// 3. Signature validity (dual bound signatures over challenge)
/// 4. Audit trail integrity (Merkle root from transparency log)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProof {
    /// Platform attestation from hardware security module.
    pub platform_attestation: PlatformAttestation,

    /// Hardware-bound public key (classical).
    pub hardware_public_key: Vec<u8>,

    /// Algorithm of the hardware key.
    pub hardware_algorithm: String,

    /// PQC public key (ML-DSA-65).
    pub pqc_public_key: Vec<u8>,

    /// PQC algorithm name.
    pub pqc_algorithm: String,

    /// Challenge nonce provided by verifier.
    pub challenge: Vec<u8>,

    /// Classical signature over the challenge.
    pub classical_signature: Vec<u8>,

    /// PQC signature over (challenge || classical_signature) — bound.
    pub pqc_signature: Vec<u8>,

    /// Merkle root from the transparency log at time of proof.
    pub merkle_root: [u8; 32],

    /// Number of entries in the transparency log.
    pub log_entry_count: u64,

    /// Timestamp when proof was generated.
    pub generated_at: i64,

    /// Binary version of CIRISVerify.
    pub binary_version: String,

    /// Hardware type description.
    pub hardware_type: String,

    /// Whether running in a virtual machine (for transparency).
    /// This does NOT block execution but is reported for verifiers.
    pub running_in_vm: bool,
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
