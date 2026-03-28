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

    /// Responsible licensed party name (the human accountable for this deployment).
    #[serde(default)]
    pub responsible_party: String,

    /// Contact for the responsible party (email or phone).
    #[serde(default)]
    pub responsible_party_contact: String,

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

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // LicenseStatus tests
    // =============================================================================

    #[test]
    fn test_license_status_allows_professional() {
        // Only LicensedProfessional allows professional capabilities
        assert!(
            LicenseStatus::LicensedProfessional.allows_professional(),
            "LicensedProfessional should allow professional"
        );

        // All other statuses should NOT allow professional
        assert!(
            !LicenseStatus::LicensedCommunityPlus.allows_professional(),
            "LicensedCommunityPlus should not allow professional"
        );
        assert!(!LicenseStatus::UnlicensedCommunity.allows_professional());
        assert!(!LicenseStatus::UnlicensedUnverified.allows_professional());
        assert!(!LicenseStatus::ErrorBinaryTampered.allows_professional());
        assert!(!LicenseStatus::ErrorSourcesDisagree.allows_professional());
        assert!(!LicenseStatus::ErrorVerificationFailed.allows_professional());
        assert!(!LicenseStatus::ErrorLicenseRevoked.allows_professional());
        assert!(!LicenseStatus::ErrorLicenseExpired.allows_professional());
    }

    #[test]
    fn test_license_status_is_error() {
        // These should be errors
        assert!(LicenseStatus::ErrorBinaryTampered.is_error());
        assert!(LicenseStatus::ErrorSourcesDisagree.is_error());
        assert!(LicenseStatus::ErrorVerificationFailed.is_error());
        assert!(LicenseStatus::ErrorLicenseRevoked.is_error());
        assert!(LicenseStatus::ErrorLicenseExpired.is_error());

        // These should NOT be errors
        assert!(
            !LicenseStatus::LicensedProfessional.is_error(),
            "LicensedProfessional is not an error"
        );
        assert!(!LicenseStatus::LicensedCommunityPlus.is_error());
        assert!(!LicenseStatus::UnlicensedCommunity.is_error());
        assert!(!LicenseStatus::UnlicensedUnverified.is_error());
    }

    #[test]
    fn test_license_status_requires_lockdown() {
        // Only binary tampering requires lockdown
        assert!(
            LicenseStatus::ErrorBinaryTampered.requires_lockdown(),
            "ErrorBinaryTampered should require lockdown"
        );

        // All other statuses should NOT require lockdown
        assert!(!LicenseStatus::ErrorSourcesDisagree.requires_lockdown());
        assert!(!LicenseStatus::ErrorVerificationFailed.requires_lockdown());
        assert!(!LicenseStatus::ErrorLicenseRevoked.requires_lockdown());
        assert!(!LicenseStatus::ErrorLicenseExpired.requires_lockdown());
        assert!(!LicenseStatus::LicensedProfessional.requires_lockdown());
        assert!(!LicenseStatus::UnlicensedCommunity.requires_lockdown());
    }

    #[test]
    fn test_license_status_requires_restricted() {
        // Only sources disagreement requires restricted mode
        assert!(
            LicenseStatus::ErrorSourcesDisagree.requires_restricted(),
            "ErrorSourcesDisagree should require restricted"
        );

        // All other statuses should NOT require restricted
        assert!(!LicenseStatus::ErrorBinaryTampered.requires_restricted());
        assert!(!LicenseStatus::ErrorVerificationFailed.requires_restricted());
        assert!(!LicenseStatus::ErrorLicenseRevoked.requires_restricted());
        assert!(!LicenseStatus::ErrorLicenseExpired.requires_restricted());
        assert!(!LicenseStatus::LicensedProfessional.requires_restricted());
        assert!(!LicenseStatus::UnlicensedCommunity.requires_restricted());
    }

    #[test]
    fn test_license_status_serialization() {
        let status = LicenseStatus::LicensedProfessional;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"LicensedProfessional\"");

        let parsed: LicenseStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }

    // =============================================================================
    // AutonomyTier tests
    // =============================================================================

    #[test]
    fn test_autonomy_tier_ordering() {
        // Verify the ordering is correct: A0 < A1 < A2 < A3 < A4
        assert!(AutonomyTier::A0Advisory < AutonomyTier::A1Limited);
        assert!(AutonomyTier::A1Limited < AutonomyTier::A2Moderate);
        assert!(AutonomyTier::A2Moderate < AutonomyTier::A3High);
        assert!(AutonomyTier::A3High < AutonomyTier::A4Critical);

        // Verify equality
        assert_eq!(AutonomyTier::A0Advisory, AutonomyTier::A0Advisory);

        // Verify max/min work correctly
        let tiers = [
            AutonomyTier::A3High,
            AutonomyTier::A0Advisory,
            AutonomyTier::A4Critical,
            AutonomyTier::A1Limited,
        ];
        assert_eq!(tiers.iter().max(), Some(&AutonomyTier::A4Critical));
        assert_eq!(tiers.iter().min(), Some(&AutonomyTier::A0Advisory));
    }

    #[test]
    fn test_autonomy_tier_discriminant_values() {
        // Verify discriminant values match expected integers
        assert_eq!(AutonomyTier::A0Advisory as u8, 0);
        assert_eq!(AutonomyTier::A1Limited as u8, 1);
        assert_eq!(AutonomyTier::A2Moderate as u8, 2);
        assert_eq!(AutonomyTier::A3High as u8, 3);
        assert_eq!(AutonomyTier::A4Critical as u8, 4);
    }

    #[test]
    fn test_autonomy_tier_serialization() {
        let tier = AutonomyTier::A3High;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"A3High\"");

        let parsed: AutonomyTier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tier);
    }

    // =============================================================================
    // LicenseType tests
    // =============================================================================

    #[test]
    fn test_license_type_equality() {
        assert_eq!(LicenseType::Community, LicenseType::Community);
        assert_ne!(LicenseType::Community, LicenseType::ProfessionalMedical);
        assert_ne!(
            LicenseType::ProfessionalMedical,
            LicenseType::ProfessionalLegal
        );
        assert_ne!(
            LicenseType::ProfessionalFinancial,
            LicenseType::ProfessionalFull
        );
    }

    #[test]
    fn test_license_type_serialization() {
        let license_type = LicenseType::ProfessionalMedical;
        let json = serde_json::to_string(&license_type).unwrap();
        assert_eq!(json, "\"ProfessionalMedical\"");

        let parsed: LicenseType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, license_type);
    }

    // =============================================================================
    // DeploymentConstraints tests
    // =============================================================================

    #[test]
    fn test_deployment_constraints_default() {
        let defaults = DeploymentConstraints::default();

        assert!(!defaults.requires_supervisor, "Default: no supervisor");
        assert!(
            defaults.supervisor_credentials.is_empty(),
            "Default: no credentials"
        );
        assert_eq!(defaults.offline_grace_hours, 72, "Default: 72 hour grace");
        assert!(
            !defaults.requires_hardware_attestation,
            "Default: no HW attestation"
        );
        assert!(defaults.allowed_regions.is_empty(), "Default: no regions");
        assert!(
            defaults.allowed_facility_types.is_empty(),
            "Default: no facility types"
        );
    }

    #[test]
    fn test_deployment_constraints_serialization() {
        let constraints = DeploymentConstraints {
            requires_supervisor: true,
            supervisor_credentials: vec!["MD".into(), "RN".into()],
            offline_grace_hours: 24,
            requires_hardware_attestation: true,
            allowed_regions: vec!["US".into(), "EU".into()],
            allowed_facility_types: vec!["hospital".into()],
        };

        let json = serde_json::to_string(&constraints).unwrap();
        let parsed: DeploymentConstraints = serde_json::from_str(&json).unwrap();

        assert!(parsed.requires_supervisor);
        assert_eq!(parsed.supervisor_credentials.len(), 2);
        assert_eq!(parsed.offline_grace_hours, 24);
        assert!(parsed.requires_hardware_attestation);
        assert_eq!(parsed.allowed_regions.len(), 2);
        assert_eq!(parsed.allowed_facility_types.len(), 1);
    }

    // =============================================================================
    // LicenseDetails tests
    // =============================================================================

    #[test]
    fn test_license_details_serialization_roundtrip() {
        let details = LicenseDetails {
            license_id: "lic-12345".into(),
            license_type: LicenseType::ProfessionalMedical,
            organization_name: "Test Hospital".into(),
            organization_id: "org-001".into(),
            responsible_party: "Dr. Smith".into(),
            responsible_party_contact: "smith@hospital.org".into(),
            issued_at: 1700000000,
            expires_at: 1730000000,
            not_before: 1700000000,
            capabilities: vec!["MEDICAL_TRIAGE".into(), "APPOINTMENT_SCHEDULING".into()],
            capabilities_denied: vec!["PRESCRIBE".into()],
            max_autonomy_tier: AutonomyTier::A3High,
            constraints: DeploymentConstraints::default(),
            license_jwt: "eyJ...".into(),
            identity_template: "medical".into(),
            stewardship_tier: 3,
            permitted_actions: vec!["observe".into(), "speak".into()],
            template_hash: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let json = serde_json::to_string_pretty(&details).unwrap();
        let parsed: LicenseDetails = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.license_id, "lic-12345");
        assert_eq!(parsed.license_type, LicenseType::ProfessionalMedical);
        assert_eq!(parsed.organization_name, "Test Hospital");
        assert_eq!(parsed.responsible_party, "Dr. Smith");
        assert_eq!(parsed.max_autonomy_tier, AutonomyTier::A3High);
        assert_eq!(parsed.capabilities.len(), 2);
        assert_eq!(parsed.identity_template, "medical");
        assert_eq!(parsed.stewardship_tier, 3);
    }

    #[test]
    fn test_license_details_default_fields() {
        // Test that optional fields default correctly when missing
        let json = r#"{
            "license_id": "test",
            "license_type": "Community",
            "organization_name": "Test",
            "organization_id": "org",
            "issued_at": 0,
            "expires_at": 0,
            "not_before": 0,
            "capabilities": [],
            "capabilities_denied": [],
            "max_autonomy_tier": "A0Advisory",
            "constraints": {
                "requires_supervisor": false,
                "supervisor_credentials": [],
                "offline_grace_hours": 72,
                "requires_hardware_attestation": false,
                "allowed_regions": [],
                "allowed_facility_types": []
            },
            "license_jwt": ""
        }"#;

        let details: LicenseDetails = serde_json::from_str(json).unwrap();

        // Fields with #[serde(default)] should have default values
        assert_eq!(details.responsible_party, "");
        assert_eq!(details.responsible_party_contact, "");
        assert_eq!(details.identity_template, "");
        assert_eq!(details.stewardship_tier, 0);
        assert!(details.permitted_actions.is_empty());
        assert!(details.template_hash.is_empty());
    }
}
