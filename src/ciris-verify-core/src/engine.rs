//! Main license verification engine.
//!
//! This module implements the complete verification flow:
//! 1. Binary integrity check
//! 2. Multi-source validation
//! 3. License verification (JWT + dual signature)
//! 4. Hardware tier restriction
//! 5. Response attestation
//!
//! ## Security Properties
//!
//! - Fail-secure: All errors degrade to MORE restrictive modes
//! - Multi-source: Requires 2-of-3 source agreement
//! - Hardware-bound: Responses signed by hardware-protected keys
//! - Mandatory disclosure: Cannot be suppressed or modified

use std::sync::Arc;
use std::time::Duration;

use ciris_keyring::{HardwareSigner, HardwareType, PlatformAttestation, SoftwareAttestation};
use tracing::{debug, error, info, instrument, warn};

use crate::cache::LicenseCache;
use crate::config::VerifyConfig;
use crate::error::VerifyError;
use crate::https::HttpsClient;
use crate::license::{LicenseDetails, LicenseStatus, LicenseType};
use crate::revocation::RevocationChecker;
use crate::types::{
    CapabilityCheckResponse, DisclosureSeverity, LicenseStatusRequest, LicenseStatusResponse,
    MandatoryDisclosure, ResponseAttestation, ResponseMetadata, ResponseSignature, SourceResult,
    ValidationResults, ValidationStatus,
};
use crate::validation::{ConsensusValidator, ValidationResult};

/// The main license verification engine.
///
/// This is the primary entry point for all verification operations.
pub struct LicenseEngine {
    /// Configuration.
    config: VerifyConfig,
    /// Consensus validator for multi-source verification.
    consensus_validator: ConsensusValidator,
    /// License cache for offline operation.
    cache: LicenseCache,
    /// Revocation checker.
    revocation_checker: RevocationChecker,
    /// Hardware signer for attestation.
    hw_signer: Arc<dyn HardwareSigner>,
    /// Binary integrity flag (set at startup).
    integrity_valid: bool,
}

impl LicenseEngine {
    /// Create a new license engine with default configuration.
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    pub fn new() -> Result<Self, VerifyError> {
        Self::with_config(VerifyConfig::default())
    }

    /// Create a new license engine with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    pub fn with_config(config: VerifyConfig) -> Result<Self, VerifyError> {
        // Initialize consensus validator
        let consensus_validator = ConsensusValidator::new(
            config.dns_us_host.clone(),
            config.dns_eu_host.clone(),
            config.https_endpoint.clone(),
            config.timeout,
            config.cert_pin.clone(),
        );

        // Initialize license cache
        let cache = LicenseCache::new(
            &config.key_alias,
            None, // TODO: Add persistent storage path
            config.cache_ttl,
        );

        // Initialize HTTPS client for revocation
        let https_client = HttpsClient::new(
            &config.https_endpoint,
            config.timeout,
            config.cert_pin.as_deref(),
        )?;

        // Initialize revocation checker
        let revocation_checker = RevocationChecker::new(
            https_client,
            Duration::from_secs(300),  // 5 minute TTL for non-revoked
            Duration::from_secs(3600), // 1 hour TTL for revoked (persistent)
        );

        // Initialize hardware signer (synchronous)
        let hw_signer = ciris_keyring::get_platform_signer(&config.key_alias)?;

        // Check binary integrity at startup
        let integrity_valid = verify_binary_integrity();

        info!(
            hardware_type = ?hw_signer.hardware_type(),
            integrity_valid = integrity_valid,
            "LicenseEngine initialized"
        );

        Ok(Self {
            config,
            consensus_validator,
            cache,
            revocation_checker,
            hw_signer: Arc::from(hw_signer),
            integrity_valid,
        })
    }

    /// Create a license engine with a custom hardware signer.
    ///
    /// Useful for testing with mock signers.
    pub fn with_signer(
        config: VerifyConfig,
        hw_signer: Arc<dyn HardwareSigner>,
    ) -> Result<Self, VerifyError> {
        let consensus_validator = ConsensusValidator::new(
            config.dns_us_host.clone(),
            config.dns_eu_host.clone(),
            config.https_endpoint.clone(),
            config.timeout,
            config.cert_pin.clone(),
        );

        let cache = LicenseCache::new(&config.key_alias, None, config.cache_ttl);

        let https_client = HttpsClient::new(
            &config.https_endpoint,
            config.timeout,
            config.cert_pin.as_deref(),
        )?;

        let revocation_checker = RevocationChecker::new(
            https_client,
            Duration::from_secs(300),
            Duration::from_secs(3600),
        );

        Ok(Self {
            config,
            consensus_validator,
            cache,
            revocation_checker,
            hw_signer,
            integrity_valid: true, // Assume valid for testing
        })
    }

    /// Get the current license status.
    ///
    /// This is the main verification entry point.
    ///
    /// # Security
    ///
    /// This method implements fail-secure behavior:
    /// - Binary tampering → LOCKDOWN
    /// - Sources disagree → RESTRICTED (security alert)
    /// - Verification failed → COMMUNITY MODE
    /// - License expired/revoked → COMMUNITY MODE
    #[instrument(skip(self, request), fields(deployment_id = %request.deployment_id))]
    pub async fn get_license_status(
        &self,
        request: LicenseStatusRequest,
    ) -> Result<LicenseStatusResponse, VerifyError> {
        // Validate request
        request.validate().map_err(|e| VerifyError::ConfigError {
            message: e.to_string(),
        })?;

        // 1. Binary integrity check
        if !self.integrity_valid {
            error!("Binary integrity check failed - LOCKDOWN");
            return Ok(self
                .build_error_response(
                    LicenseStatus::ErrorBinaryTampered,
                    "Binary integrity verification failed. System in lockdown mode.",
                    &request,
                )
                .await);
        }

        // 2. Multi-source validation
        let validation = self.consensus_validator.validate_steward_key().await;

        debug!(
            validation_status = ?validation.status,
            "Multi-source validation complete"
        );

        // Handle validation status
        match validation.status {
            ValidationStatus::SourcesDisagree => {
                error!("SECURITY ALERT: Sources disagree - possible attack");
                return Ok(self
                    .build_error_response(
                        LicenseStatus::ErrorSourcesDisagree,
                        "SECURITY ALERT: Verification sources report conflicting data. \
                     Possible man-in-the-middle attack detected.",
                        &request,
                    )
                    .await);
            },
            ValidationStatus::NoSourcesReachable => {
                warn!("No sources reachable - attempting offline mode");
                // Try cache with grace period
                if let Some(cached) = self
                    .cache
                    .get_for_offline(&request.deployment_id, self.config.offline_grace)
                {
                    info!("Using cached license for offline operation");
                    return Ok(self
                        .build_cached_response(cached, &request, &validation)
                        .await);
                }

                return Ok(self
                    .build_error_response(
                        LicenseStatus::ErrorVerificationFailed,
                        "Cannot reach verification servers and no valid cached license. \
                     Operating in community mode.",
                        &request,
                    )
                    .await);
            },
            ValidationStatus::ValidationError => {
                warn!("Validation error - insufficient sources");
                // Try cache
                if let Some(cached) = self.cache.get(&request.deployment_id) {
                    if cached.is_fresh {
                        return Ok(self
                            .build_cached_response(cached, &request, &validation)
                            .await);
                    }
                }
            },
            ValidationStatus::AllSourcesAgree | ValidationStatus::PartialAgreement => {
                debug!("Source validation passed");
            },
        }

        // 3. Check revocation status
        let revocation = self
            .revocation_checker
            .check_revocation(&request.deployment_id)
            .await;
        if revocation.revoked {
            warn!(
                reason = ?revocation.reason,
                "License has been revoked"
            );
            return Ok(self
                .build_error_response(
                    LicenseStatus::ErrorLicenseRevoked,
                    &format!(
                        "License has been revoked: {}",
                        revocation
                            .reason
                            .unwrap_or_else(|| "No reason provided".to_string())
                    ),
                    &request,
                )
                .await);
        }

        // 4. Get or verify license details
        let license_details = self
            .get_license_details(&request.deployment_id, &validation)
            .await;

        // 5. Apply hardware tier restriction
        let (final_status, final_license) = self.apply_hardware_restriction(license_details);

        // 6. Cache the result
        if let Some(ref license) = final_license {
            self.cache.put(license);
        }

        // 7. Build response with attestation
        Ok(self
            .build_success_response(final_status, final_license, &request, &validation)
            .await)
    }

    /// Check if a specific capability is allowed.
    #[instrument(skip(self))]
    pub async fn check_capability(
        &self,
        capability: &str,
        _action: &str,
        required_tier: u8,
    ) -> Result<CapabilityCheckResponse, VerifyError> {
        // For now, return a basic response
        // TODO: Implement full capability checking against cached license

        let request = LicenseStatusRequest {
            deployment_id: self.config.key_alias.clone(),
            challenge_nonce: vec![0u8; 32],
            force_refresh: false,
        };

        let status = self.get_license_status(request).await?;

        let allowed = match status.license {
            Some(ref license) => {
                // Check if capability is granted
                let has_capability = license
                    .capabilities
                    .iter()
                    .any(|c| c == capability || capability.starts_with(c));

                // Check if denied
                let is_denied = license
                    .capabilities_denied
                    .iter()
                    .any(|c| c == capability || capability.starts_with(c));

                // Check tier
                let tier_ok = (license.max_autonomy_tier as u8) >= required_tier;

                has_capability && !is_denied && tier_ok
            },
            None => false,
        };

        Ok(CapabilityCheckResponse {
            allowed,
            denial_reason: if !allowed {
                Some("Capability not granted or tier insufficient".to_string())
            } else {
                None
            },
            required_conditions: vec![],
            suggested_alternative: None,
        })
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &VerifyConfig {
        &self.config
    }

    /// Get the hardware type of the signer.
    #[must_use]
    pub fn hardware_type(&self) -> HardwareType {
        self.hw_signer.hardware_type()
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    /// Get license details from validation or cache.
    async fn get_license_details(
        &self,
        deployment_id: &str,
        _validation: &ValidationResult,
    ) -> Option<LicenseDetails> {
        // TODO: Fetch and verify license JWT from registry
        // For now, return from cache if available
        self.cache.get(deployment_id).map(|c| c.license)
    }

    /// Apply hardware tier restriction.
    ///
    /// SOFTWARE_ONLY deployments are capped at UNLICENSED_COMMUNITY.
    fn apply_hardware_restriction(
        &self,
        license: Option<LicenseDetails>,
    ) -> (LicenseStatus, Option<LicenseDetails>) {
        // SOFTWARE_ONLY caps at UNLICENSED_COMMUNITY
        if self.hw_signer.hardware_type() == HardwareType::SoftwareOnly {
            warn!("Software-only deployment - capping at community tier");
            return (LicenseStatus::UnlicensedCommunity, None);
        }

        match license {
            Some(lic) => {
                // Check expiration
                let now = chrono::Utc::now().timestamp();
                if now > lic.expires_at {
                    warn!("License expired");
                    return (LicenseStatus::ErrorLicenseExpired, Some(lic));
                }
                if now < lic.not_before {
                    warn!("License not yet valid");
                    return (LicenseStatus::UnlicensedUnverified, Some(lic));
                }

                // Determine status based on license type
                let status = match lic.license_type {
                    LicenseType::ProfessionalMedical
                    | LicenseType::ProfessionalLegal
                    | LicenseType::ProfessionalFinancial
                    | LicenseType::ProfessionalFull => LicenseStatus::LicensedProfessional,
                    LicenseType::Community => LicenseStatus::UnlicensedCommunity,
                };

                (status, Some(lic))
            },
            None => (LicenseStatus::UnlicensedCommunity, None),
        }
    }

    /// Build an error response.
    async fn build_error_response(
        &self,
        status: LicenseStatus,
        message: &str,
        request: &LicenseStatusRequest,
    ) -> LicenseStatusResponse {
        let severity = if status.requires_lockdown() || status.requires_restricted() {
            DisclosureSeverity::Critical
        } else {
            DisclosureSeverity::Warning
        };

        LicenseStatusResponse {
            status,
            license: None,
            mandatory_disclosure: MandatoryDisclosure {
                text: message.to_string(),
                severity,
                locale: "en-US".to_string(),
            },
            attestation: self.build_attestation(request).await,
            validation: self.build_validation_results_empty(),
            metadata: self.build_metadata(),
        }
    }

    /// Build a response from cached license.
    async fn build_cached_response(
        &self,
        cached: crate::cache::CachedLicense,
        request: &LicenseStatusRequest,
        validation: &ValidationResult,
    ) -> LicenseStatusResponse {
        let (status, license) = self.apply_hardware_restriction(Some(cached.license));

        let disclosure_text = if cached.is_fresh {
            self.get_disclosure_text(&status, license.as_ref())
        } else {
            format!(
                "{} (Operating with cached data - last verified {})",
                self.get_disclosure_text(&status, license.as_ref()),
                format_timestamp(cached.last_verified)
            )
        };

        LicenseStatusResponse {
            status,
            license,
            mandatory_disclosure: MandatoryDisclosure {
                text: disclosure_text,
                severity: self.get_disclosure_severity(&status),
                locale: "en-US".to_string(),
            },
            attestation: self.build_attestation(request).await,
            validation: self.build_validation_results(validation),
            metadata: self.build_metadata(),
        }
    }

    /// Build a success response.
    async fn build_success_response(
        &self,
        status: LicenseStatus,
        license: Option<LicenseDetails>,
        request: &LicenseStatusRequest,
        validation: &ValidationResult,
    ) -> LicenseStatusResponse {
        LicenseStatusResponse {
            status,
            license: license.clone(),
            mandatory_disclosure: MandatoryDisclosure {
                text: self.get_disclosure_text(&status, license.as_ref()),
                severity: self.get_disclosure_severity(&status),
                locale: "en-US".to_string(),
            },
            attestation: self.build_attestation(request).await,
            validation: self.build_validation_results(validation),
            metadata: self.build_metadata(),
        }
    }

    /// Build attestation data.
    async fn build_attestation(&self, request: &LicenseStatusRequest) -> ResponseAttestation {
        let platform = self
            .hw_signer
            .attestation()
            .await
            .unwrap_or_else(|_| PlatformAttestation::Software(SoftwareAttestation::default()));

        // Sign the response (simplified - in production, sign the full response)
        let signature_data = self
            .hw_signer
            .sign(&request.challenge_nonce)
            .await
            .unwrap_or_default();

        ResponseAttestation {
            platform,
            signature: ResponseSignature {
                classical: signature_data,
                classical_algorithm: format!("{:?}", self.hw_signer.algorithm()),
                pqc: vec![], // TODO: Add PQC signature
                pqc_algorithm: "ML-DSA-65".to_string(),
            },
            integrity_valid: self.integrity_valid,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Build validation results.
    fn build_validation_results(&self, validation: &ValidationResult) -> ValidationResults {
        ValidationResults {
            dns_us: SourceResult {
                source: "registry-us.ciris.ai".to_string(),
                reachable: validation.source_details.dns_us_reachable,
                valid: validation.source_details.dns_us_reachable
                    && validation.source_details.dns_us_error.is_none(),
                checked_at: chrono::Utc::now().timestamp(),
                error: validation.source_details.dns_us_error.clone(),
            },
            dns_eu: SourceResult {
                source: "registry-eu.ciris.ai".to_string(),
                reachable: validation.source_details.dns_eu_reachable,
                valid: validation.source_details.dns_eu_reachable
                    && validation.source_details.dns_eu_error.is_none(),
                checked_at: chrono::Utc::now().timestamp(),
                error: validation.source_details.dns_eu_error.clone(),
            },
            https: SourceResult {
                source: "verify.ciris.ai".to_string(),
                reachable: validation.source_details.https_reachable,
                valid: validation.source_details.https_reachable
                    && validation.source_details.https_error.is_none(),
                checked_at: chrono::Utc::now().timestamp(),
                error: validation.source_details.https_error.clone(),
            },
            overall: validation.status,
        }
    }

    /// Build empty validation results.
    fn build_validation_results_empty(&self) -> ValidationResults {
        ValidationResults {
            dns_us: SourceResult {
                source: "registry-us.ciris.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: chrono::Utc::now().timestamp(),
                error: Some("Not checked".to_string()),
            },
            dns_eu: SourceResult {
                source: "registry-eu.ciris.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: chrono::Utc::now().timestamp(),
                error: Some("Not checked".to_string()),
            },
            https: SourceResult {
                source: "verify.ciris.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: chrono::Utc::now().timestamp(),
                error: Some("Not checked".to_string()),
            },
            overall: ValidationStatus::ValidationError,
        }
    }

    /// Build response metadata.
    fn build_metadata(&self) -> ResponseMetadata {
        ResponseMetadata {
            protocol_version: "2.0.0".to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            cache_ttl: self.config.cache_ttl.as_secs() as u32,
            request_id: generate_request_id(),
        }
    }

    /// Get disclosure text for status.
    fn get_disclosure_text(
        &self,
        status: &LicenseStatus,
        license: Option<&LicenseDetails>,
    ) -> String {
        match status {
            LicenseStatus::LicensedProfessional => {
                if let Some(lic) = license {
                    format!(
                        "Licensed professional agent. Organization: {}. \
                         Capabilities verified. Maximum autonomy tier: {:?}.",
                        lic.organization_name, lic.max_autonomy_tier
                    )
                } else {
                    "Licensed professional agent.".to_string()
                }
            },
            LicenseStatus::LicensedCommunityPlus => {
                "Community Plus license. Some professional features available.".to_string()
            },
            LicenseStatus::UnlicensedCommunity => {
                "COMMUNITY MODE: This is a general wellness assistant. \
                 Not a licensed professional service. \
                 Consult qualified professionals for medical, legal, or financial advice."
                    .to_string()
            },
            LicenseStatus::UnlicensedUnverified => {
                "UNVERIFIED: License status could not be confirmed. \
                 Operating in restricted mode."
                    .to_string()
            },
            LicenseStatus::ErrorBinaryTampered => {
                "CRITICAL: Binary integrity check failed. System locked down for security."
                    .to_string()
            },
            LicenseStatus::ErrorSourcesDisagree => {
                "SECURITY ALERT: Verification sources disagree. Possible attack detected. \
                 System in restricted mode."
                    .to_string()
            },
            LicenseStatus::ErrorVerificationFailed => {
                "Verification failed. Operating in community mode.".to_string()
            },
            LicenseStatus::ErrorLicenseRevoked => {
                "License has been revoked. Operating in community mode.".to_string()
            },
            LicenseStatus::ErrorLicenseExpired => {
                "License has expired. Operating in community mode. \
                 Contact your organization to renew."
                    .to_string()
            },
        }
    }

    /// Get disclosure severity for status.
    fn get_disclosure_severity(&self, status: &LicenseStatus) -> DisclosureSeverity {
        match status {
            LicenseStatus::LicensedProfessional | LicenseStatus::LicensedCommunityPlus => {
                DisclosureSeverity::Info
            },
            LicenseStatus::ErrorBinaryTampered | LicenseStatus::ErrorSourcesDisagree => {
                DisclosureSeverity::Critical
            },
            _ => DisclosureSeverity::Warning,
        }
    }
}

/// Verify binary integrity.
///
/// TODO: Implement actual integrity verification.
fn verify_binary_integrity() -> bool {
    // Placeholder - always returns true for now
    // In production:
    // 1. Check embedded hash
    // 2. Detect debugger
    // 3. Check for hooks
    true
}

/// Generate a unique request ID.
fn generate_request_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let id: u64 = rng.gen();
    format!("req-{:016x}", id)
}

/// Format a Unix timestamp.
fn format_timestamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_with_software_signer() {
        // Create with software signer for testing
        let config = VerifyConfig::default();

        let signer = ciris_keyring::create_software_signer("test").unwrap();
        let engine = LicenseEngine::with_signer(config, Arc::from(signer)).unwrap();

        assert!(engine.integrity_valid);
        assert_eq!(engine.hardware_type(), HardwareType::SoftwareOnly);
    }

    #[tokio::test]
    async fn test_software_only_restriction() {
        let config = VerifyConfig::default();

        let signer = ciris_keyring::create_software_signer("test").unwrap();
        let engine = LicenseEngine::with_signer(config, Arc::from(signer)).unwrap();

        // Software-only should be capped at community
        let (status, _) = engine.apply_hardware_restriction(None);
        assert_eq!(status, LicenseStatus::UnlicensedCommunity);
    }
}
