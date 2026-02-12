//! License types and status definitions.

use serde::{Deserialize, Serialize};

/// License status returned by verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseStatus {
    /// Full steward-backed professional license.
    LicensedProfessional,
    /// Enhanced community with some features.
    LicensedCommunityPlus,
    /// Standard CIRISCare community mode.
    UnlicensedCommunity,
    /// Could not verify (offline grace period).
    UnlicensedUnverified,
    /// Integrity check failed - possible tampering.
    ErrorBinaryTampered,
    /// Multi-source mismatch - possible attack.
    ErrorSourcesDisagree,
    /// Could not reach any verification source.
    ErrorVerificationFailed,
    /// License explicitly revoked.
    ErrorLicenseRevoked,
    /// License past expiration date.
    ErrorLicenseExpired,
}

impl LicenseStatus {
    /// Check if this status allows professional capabilities.
    #[must_use]
    pub fn allows_professional(&self) -> bool {
        matches!(self, Self::LicensedProfessional)
    }

    /// Check if this is an error status.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Self::ErrorBinaryTampered
                | Self::ErrorSourcesDisagree
                | Self::ErrorVerificationFailed
                | Self::ErrorLicenseRevoked
                | Self::ErrorLicenseExpired
        )
    }

    /// Check if this status requires LOCKDOWN.
    #[must_use]
    pub fn requires_lockdown(&self) -> bool {
        matches!(self, Self::ErrorBinaryTampered)
    }

    /// Check if this status requires RESTRICTED mode.
    #[must_use]
    pub fn requires_restricted(&self) -> bool {
        matches!(self, Self::ErrorSourcesDisagree)
    }
}

/// Type of license.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseType {
    /// CIRISCare community.
    Community,
    /// CIRISMedical professional.
    ProfessionalMedical,
    /// CIRISLegal professional.
    ProfessionalLegal,
    /// CIRISFinancial professional.
    ProfessionalFinancial,
    /// All professional modules.
    ProfessionalFull,
}

/// Autonomy tier limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AutonomyTier {
    /// Advisory only (grammar, formatting).
    A0Advisory = 0,
    /// Limited autonomy (static Q&A).
    A1Limited = 1,
    /// Moderate autonomy (recommendations with oversight).
    A2Moderate = 2,
    /// High autonomy (triage, diagnosis support).
    A3High = 3,
    /// Critical autonomy (treatment decisions).
    A4Critical = 4,
}

/// Detailed license information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseDetails {
    /// Unique license identifier.
    pub license_id: String,

    /// License type.
    pub license_type: LicenseType,

    /// Organization name.
    pub organization_name: String,

    /// Organization ID.
    pub organization_id: String,

    /// Issue timestamp (Unix).
    pub issued_at: i64,

    /// Expiration timestamp (Unix).
    pub expires_at: i64,

    /// Not-before timestamp (Unix).
    pub not_before: i64,

    /// Granted capabilities.
    pub capabilities: Vec<String>,

    /// Denied capabilities.
    pub capabilities_denied: Vec<String>,

    /// Maximum autonomy tier.
    pub max_autonomy_tier: AutonomyTier,

    /// Deployment constraints.
    pub constraints: DeploymentConstraints,

    /// Original signed license JWT.
    pub license_jwt: String,

    // === Identity template enforcement (v1.2.0) ===

    /// Identity template name (echo, scout, sage, datum, ally, default, custom).
    #[serde(default)]
    pub identity_template: String,

    /// Stewardship tier (1-5).
    #[serde(default)]
    pub stewardship_tier: u8,

    /// Permitted actions for this template.
    #[serde(default)]
    pub permitted_actions: Vec<String>,

    /// SHA-256 hash of the identity template YAML.
    #[serde(default)]
    pub template_hash: Vec<u8>,
}

/// Constraints on deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConstraints {
    /// Requires human supervisor present.
    pub requires_supervisor: bool,

    /// Required supervisor credentials.
    pub supervisor_credentials: Vec<String>,

    /// Maximum hours offline before degradation.
    pub offline_grace_hours: u32,

    /// Requires hardware attestation for A4 actions.
    pub requires_hardware_attestation: bool,

    /// Geographic restrictions (ISO 3166-1 alpha-2).
    pub allowed_regions: Vec<String>,

    /// Facility type restrictions.
    pub allowed_facility_types: Vec<String>,
}

impl Default for DeploymentConstraints {
    fn default() -> Self {
        Self {
            requires_supervisor: false,
            supervisor_credentials: Vec::new(),
            offline_grace_hours: 72,
            requires_hardware_attestation: false,
            allowed_regions: Vec::new(),
            allowed_facility_types: Vec::new(),
        }
    }
}
