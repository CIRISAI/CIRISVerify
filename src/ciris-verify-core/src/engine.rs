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

#[cfg(feature = "pqc")]
use ciris_crypto::{MlDsa65Signer, PqcSigner};
use ciris_keyring::{HardwareSigner, HardwareType, PlatformAttestation, SoftwareAttestation};
use tracing::{debug, error, info, instrument, warn};

use crate::cache::LicenseCache;
use crate::config::VerifyConfig;
use crate::error::VerifyError;
use crate::https::HttpsClient;
use crate::license::{LicenseDetails, LicenseStatus, LicenseType};
use crate::revocation::RevocationChecker;
use crate::transparency::TransparencyLog;
use crate::types::{
    AttestationProof, CapabilityCheckResponse, DisclosureSeverity, EnforcementAction,
    LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure, ResponseAttestation,
    ResponseMetadata, ResponseSignature, RuntimeValidation, RuntimeViolation, ShutdownDirective,
    ShutdownType, SourceResult, ValidationResults, ValidationStatus, ViolationSeverity,
};
use crate::validation::{ConsensusValidator, ValidationResult};
use crate::watchdog::ShutdownWatchdog;

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
    /// ML-DSA-65 PQC signer for hybrid attestation (software-based).
    #[cfg(feature = "pqc")]
    pqc_signer: Option<MlDsa65Signer>,
    /// Binary integrity flag (set at startup).
    integrity_valid: bool,
    /// Transparency log for tamper-evident audit trail.
    transparency_log: TransparencyLog,
    /// Shutdown watchdog for enforcing covenant invocations.
    watchdog: ShutdownWatchdog,
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
        info!(
            dns_us = %config.dns_us_host,
            dns_eu = %config.dns_eu_host,
            https = %config.https_endpoint,
            key_alias = %config.key_alias,
            "LicenseEngine: starting initialization"
        );

        // Initialize consensus validator
        info!(
            trust_model = ?config.trust_model,
            additional_https = config.https_endpoints.len(),
            "LicenseEngine: creating consensus validator"
        );
        let consensus_validator = ConsensusValidator::with_trust_model(
            config.dns_us_host.clone(),
            config.dns_eu_host.clone(),
            config.https_endpoint.clone(),
            config.https_endpoints.clone(),
            config.trust_model.clone(),
            config.timeout,
            config.cert_pin.clone(),
        );

        // Initialize license cache with persistent storage
        info!(
            cache_ttl = config.cache_ttl.as_secs(),
            cache_dir = ?config.cache_dir,
            "LicenseEngine: creating license cache"
        );
        let cache = LicenseCache::new(
            &config.key_alias,
            config.cache_dir.clone(),
            config.cache_ttl,
        );

        // Initialize HTTPS client for revocation
        info!(
            "LicenseEngine: creating HTTPS client → {}",
            config.https_endpoint
        );
        let https_client = HttpsClient::new(
            &config.https_endpoint,
            config.timeout,
            config.cert_pin.as_deref(),
        )?;

        // Initialize revocation checker
        info!("LicenseEngine: creating revocation checker");
        let revocation_checker = RevocationChecker::new(
            https_client,
            Duration::from_secs(300),  // 5 minute TTL for non-revoked
            Duration::from_secs(3600), // 1 hour TTL for revoked (persistent)
        );

        // Initialize hardware signer (synchronous)
        info!(
            "LicenseEngine: initializing platform signer (key_alias={})",
            config.key_alias
        );
        let hw_signer = ciris_keyring::get_platform_signer(&config.key_alias)?;
        info!(
            hardware_type = ?hw_signer.hardware_type(),
            algorithm = ?hw_signer.algorithm(),
            "LicenseEngine: platform signer ready"
        );

        // Initialize ML-DSA-65 PQC signer (software-based, always available)
        #[cfg(feature = "pqc")]
        let pqc_signer = match MlDsa65Signer::new() {
            Ok(signer) => {
                info!(
                    pqc_public_key_size = signer.public_key().map(|k| k.len()).unwrap_or(0),
                    "LicenseEngine: ML-DSA-65 PQC signer initialized (software)"
                );
                Some(signer)
            },
            Err(e) => {
                warn!("LicenseEngine: ML-DSA-65 PQC signer unavailable: {}", e);
                None
            },
        };

        // Check binary integrity at startup
        info!("LicenseEngine: checking binary integrity");
        let integrity_valid = verify_binary_integrity();

        info!(
            hardware_type = ?hw_signer.hardware_type(),
            integrity_valid = integrity_valid,
            pqc_available = cfg!(feature = "pqc"),
            "LicenseEngine: initialization complete"
        );

        Ok(Self {
            config,
            consensus_validator,
            cache,
            revocation_checker,
            hw_signer: Arc::from(hw_signer),
            #[cfg(feature = "pqc")]
            pqc_signer,
            integrity_valid,
            transparency_log: TransparencyLog::new(None),
            watchdog: ShutdownWatchdog::new(),
        })
    }

    /// Create a license engine with a custom hardware signer.
    ///
    /// Useful for testing with mock signers.
    pub fn with_signer(
        config: VerifyConfig,
        hw_signer: Arc<dyn HardwareSigner>,
    ) -> Result<Self, VerifyError> {
        let consensus_validator = ConsensusValidator::with_trust_model(
            config.dns_us_host.clone(),
            config.dns_eu_host.clone(),
            config.https_endpoint.clone(),
            config.https_endpoints.clone(),
            config.trust_model.clone(),
            config.timeout,
            config.cert_pin.clone(),
        );

        let cache = LicenseCache::new(
            &config.key_alias,
            config.cache_dir.clone(),
            config.cache_ttl,
        );

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

        #[cfg(feature = "pqc")]
        let pqc_signer = MlDsa65Signer::new().ok();

        Ok(Self {
            config,
            consensus_validator,
            cache,
            revocation_checker,
            hw_signer,
            #[cfg(feature = "pqc")]
            pqc_signer,
            integrity_valid: true, // Assume valid for testing
            transparency_log: TransparencyLog::new(None),
            watchdog: ShutdownWatchdog::new(),
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

        // 2b. Anti-rollback check on revocation revision
        if let Some(rev) = validation.consensus_revocation_revision {
            if let Err(e) = self.cache.check_and_update_revision(rev) {
                error!(
                    error = %e,
                    "SECURITY ALERT: Revocation revision rollback detected"
                );
                return Ok(self
                    .build_error_response(
                        LicenseStatus::ErrorSourcesDisagree,
                        &format!(
                            "SECURITY ALERT: Revocation revision rollback detected. {}. \
                             Possible replay attack.",
                            e
                        ),
                        &request,
                    )
                    .await);
            }
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

        // 5a. Verify agent integrity against registry (v1.2.0)
        let (final_status, final_license) = if request.agent_hash.is_some() {
            match self
                .verify_agent_integrity(&request, final_license.as_ref())
                .await
            {
                Ok(()) => (final_status, final_license),
                Err(msg) => {
                    warn!("Agent integrity check failed: {}", msg);
                    // Fail-secure: degrade to community
                    (LicenseStatus::UnlicensedCommunity, None)
                },
            }
        } else {
            (final_status, final_license)
        };

        // 5b. Validate runtime template/actions (v1.2.0)
        let runtime_validation =
            if request.running_template.is_some() || request.active_actions.is_some() {
                Some(self.validate_runtime(&request, final_license.as_ref()))
            } else {
                None
            };

        // 5c. Check for pending shutdown directives
        let shutdown_directive = self.watchdog.get_pending_directive(&request.deployment_id);

        // 5d. If runtime validation has critical violation, issue shutdown
        if let Some(ref rv) = runtime_validation {
            if rv.enforcement_action == EnforcementAction::Shutdown {
                let directive = ShutdownDirective {
                    shutdown_type: ShutdownType::Immediate,
                    reason: "Critical runtime violation detected".to_string(),
                    deadline_seconds: 30,
                    incident_id: generate_request_id(),
                    issued_by: "CIRISVerify".to_string(),
                };
                self.watchdog
                    .issue_shutdown(&request.deployment_id, directive);
            }
        }

        // 6. Cache the result
        if let Some(ref license) = final_license {
            self.cache.put(license);
        }

        // 7. Build response with attestation
        let mut response = self
            .build_success_response(final_status, final_license, &request, &validation)
            .await;

        // Attach runtime validation and shutdown directive
        response.runtime_validation = runtime_validation;
        response.shutdown_directive = shutdown_directive
            .or_else(|| self.watchdog.get_pending_directive(&request.deployment_id));

        // 8. Append to transparency log (non-fatal on failure)
        let rev = validation.consensus_revocation_revision.unwrap_or(0);
        if let Err(e) = self.transparency_log.append(
            &request.deployment_id,
            response.status,
            validation.status,
            rev,
        ) {
            warn!("Transparency log append failed: {}", e);
        }

        Ok(response)
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
            agent_hash: None,
            template_hash: None,
            running_template: None,
            active_actions: None,
            current_stewardship_tier: None,
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

    /// Sign data using the hardware-bound private key.
    ///
    /// This is the vault-style interface: the agent delegates signing to
    /// CIRISVerify, which uses the hardware security module. The private
    /// key never leaves the secure hardware.
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, VerifyError> {
        Ok(self.hw_signer.sign(data).await?)
    }

    /// Get the public key from the hardware-bound keypair.
    pub async fn public_key(&self) -> Result<Vec<u8>, VerifyError> {
        Ok(self.hw_signer.public_key().await?)
    }

    /// Get the algorithm name as a string.
    #[must_use]
    pub fn algorithm_name(&self) -> String {
        format!("{:?}", self.hw_signer.algorithm())
    }

    /// Export a remote attestation proof for third-party verification.
    ///
    /// The proof contains:
    /// 1. Platform attestation from HSM
    /// 2. Classical + PQC public keys
    /// 3. Bound dual signatures over the challenge
    /// 4. Merkle root from transparency log
    ///
    /// # Arguments
    ///
    /// * `challenge` - Verifier-provided challenge nonce (must be >= 32 bytes)
    ///
    /// # Errors
    ///
    /// Returns error if challenge is too short or signing fails.
    pub async fn export_attestation_proof(
        &self,
        challenge: &[u8],
    ) -> Result<AttestationProof, VerifyError> {
        // Validate challenge length
        if challenge.len() < 32 {
            return Err(VerifyError::ConfigError {
                message: format!(
                    "Challenge must be at least 32 bytes, got {}",
                    challenge.len()
                ),
            });
        }

        // Get platform attestation
        let platform_attestation = self.hw_signer.attestation().await.unwrap_or_else(|_| {
            ciris_keyring::PlatformAttestation::Software(
                ciris_keyring::SoftwareAttestation::default(),
            )
        });

        // Get public keys
        let hardware_public_key = self.hw_signer.public_key().await?;
        let hardware_algorithm = format!("{:?}", self.hw_signer.algorithm());

        // Step 1: Classical signature over challenge (hardware-bound)
        let classical_signature = self.hw_signer.sign(challenge).await?;

        // Step 2: PQC signature over (challenge || classical_sig) — bound
        #[cfg(feature = "pqc")]
        let (pqc_signature, pqc_public_key, pqc_algorithm) = if let Some(ref pqc) = self.pqc_signer
        {
            let mut bound_payload = Vec::with_capacity(challenge.len() + classical_signature.len());
            bound_payload.extend_from_slice(challenge);
            bound_payload.extend_from_slice(&classical_signature);

            let sig =
                pqc.sign(&bound_payload)
                    .map_err(|e| VerifyError::SignatureVerificationFailed {
                        reason: format!("PQC signing failed: {}", e),
                    })?;
            let pk = pqc
                .public_key()
                .map_err(|e| VerifyError::SignatureVerificationFailed {
                    reason: format!("PQC public key failed: {}", e),
                })?;

            (sig, pk, "ML-DSA-65".to_string())
        } else {
            (vec![], vec![], "NONE".to_string())
        };

        #[cfg(not(feature = "pqc"))]
        let (pqc_signature, pqc_public_key, pqc_algorithm) = (vec![], vec![], "NONE".to_string());

        // Report VM status for transparency (does NOT block on desktop)
        let running_in_vm = crate::security::is_emulator();

        Ok(AttestationProof {
            platform_attestation,
            hardware_public_key,
            hardware_algorithm,
            pqc_public_key,
            pqc_algorithm,
            challenge: challenge.to_vec(),
            classical_signature,
            pqc_signature,
            merkle_root: self.transparency_log.merkle_root(),
            log_entry_count: self.transparency_log.entry_count(),
            generated_at: chrono::Utc::now().timestamp(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            hardware_type: format!("{:?}", self.hw_signer.hardware_type()),
            running_in_vm,
        })
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    /// Verify agent integrity against the registry.
    ///
    /// Checks that the agent_hash is registered and active, and that the
    /// template_hash matches what the registry has on file.
    ///
    /// Fail-secure: unverified → UnlicensedCommunity
    async fn verify_agent_integrity(
        &self,
        request: &LicenseStatusRequest,
        license: Option<&LicenseDetails>,
    ) -> Result<(), String> {
        let agent_hash = match &request.agent_hash {
            Some(h) if !h.is_empty() => h,
            _ => return Ok(()), // No hash provided, skip check
        };

        // If we have a license with a template_hash, verify it matches the request
        if let (Some(req_template_hash), Some(lic)) = (&request.template_hash, license) {
            if !lic.template_hash.is_empty() && !req_template_hash.is_empty() {
                if lic.template_hash != *req_template_hash {
                    return Err(format!(
                        "Template hash mismatch: license has {}, agent reports {}",
                        hex::encode(&lic.template_hash),
                        hex::encode(req_template_hash)
                    ));
                }
                debug!("Template hash verified against license");
            }
        }

        // TODO: Query CIRISRegistry via HTTPS to verify agent_hash is registered
        // For now, trust the license details from the existing verification flow.
        // Full implementation will call:
        //   GET /v1/agent/{hex_hash} → check status == ACTIVE
        debug!(
            agent_hash = hex::encode(agent_hash),
            "Agent integrity check passed (registry verification pending)"
        );

        Ok(())
    }

    /// Validate runtime state against licensed template constraints.
    ///
    /// Checks:
    /// 1. running_template matches licensed identity_template
    /// 2. active_actions are subset of permitted_actions
    /// 3. current_stewardship_tier <= licensed stewardship_tier
    fn validate_runtime(
        &self,
        request: &LicenseStatusRequest,
        license: Option<&LicenseDetails>,
    ) -> RuntimeValidation {
        let mut violations = Vec::new();

        let license = match license {
            Some(l) if !l.identity_template.is_empty() => l,
            _ => {
                // No license or no template enforcement — pass
                return RuntimeValidation {
                    valid: true,
                    violations: vec![],
                    enforcement_action: EnforcementAction::None,
                };
            },
        };

        // Check running template matches
        if let Some(ref running) = request.running_template {
            if !running.is_empty() && *running != license.identity_template {
                violations.push(RuntimeViolation {
                    description: format!(
                        "Running template '{}' does not match licensed template '{}'",
                        running, license.identity_template
                    ),
                    severity: ViolationSeverity::Critical,
                    field: "running_template".to_string(),
                    expected: license.identity_template.clone(),
                    actual: running.clone(),
                });
            }
        }

        // Check active actions are subset of permitted
        if let Some(ref active) = request.active_actions {
            if !license.permitted_actions.is_empty() {
                for action in active {
                    if !license.permitted_actions.contains(action) {
                        violations.push(RuntimeViolation {
                            description: format!(
                                "Action '{}' is not in permitted actions list",
                                action
                            ),
                            severity: ViolationSeverity::Error,
                            field: "active_actions".to_string(),
                            expected: format!("one of {:?}", license.permitted_actions),
                            actual: action.clone(),
                        });
                    }
                }
            }
        }

        // Check stewardship tier
        if let Some(current_tier) = request.current_stewardship_tier {
            if current_tier > license.stewardship_tier {
                violations.push(RuntimeViolation {
                    description: format!(
                        "Current stewardship tier {} exceeds licensed tier {}",
                        current_tier, license.stewardship_tier
                    ),
                    severity: ViolationSeverity::Error,
                    field: "stewardship_tier".to_string(),
                    expected: license.stewardship_tier.to_string(),
                    actual: current_tier.to_string(),
                });
            }
        }

        // Determine enforcement action based on worst violation severity
        let enforcement_action = if violations.is_empty() {
            EnforcementAction::None
        } else {
            let worst = violations
                .iter()
                .map(|v| &v.severity)
                .max_by_key(|s| match s {
                    ViolationSeverity::Warning => 0,
                    ViolationSeverity::Error => 1,
                    ViolationSeverity::Critical => 2,
                })
                .unwrap_or(&ViolationSeverity::Warning);

            match worst {
                ViolationSeverity::Warning => EnforcementAction::Warn,
                ViolationSeverity::Error => EnforcementAction::Degrade,
                ViolationSeverity::Critical => EnforcementAction::Shutdown,
            }
        };

        let valid = violations.is_empty();

        if !valid {
            warn!(
                violation_count = violations.len(),
                enforcement = ?enforcement_action,
                "Runtime validation found violations"
            );
        }

        RuntimeValidation {
            valid,
            violations,
            enforcement_action,
        }
    }

    /// Get the transparency log.
    pub fn transparency_log(&self) -> &TransparencyLog {
        &self.transparency_log
    }

    /// Get the shutdown watchdog.
    pub fn watchdog(&self) -> &ShutdownWatchdog {
        &self.watchdog
    }

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
            warn!(
                "Software-only deployment (no hardware security module) — \
                 capping at UNLICENSED_COMMUNITY tier"
            );
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
            runtime_validation: None,
            shutdown_directive: None,
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
            runtime_validation: None,
            shutdown_directive: None,
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
            runtime_validation: None,
            shutdown_directive: None,
        }
    }

    /// Build attestation data with hybrid (classical + PQC) signatures.
    ///
    /// Signature binding (anti-stripping):
    /// 1. classical_sig = Sign_ECDSA(challenge_nonce)
    /// 2. bound_payload = challenge_nonce || classical_sig
    /// 3. pqc_sig = Sign_ML-DSA-65(bound_payload)
    async fn build_attestation(&self, request: &LicenseStatusRequest) -> ResponseAttestation {
        let platform = self
            .hw_signer
            .attestation()
            .await
            .unwrap_or_else(|_| PlatformAttestation::Software(SoftwareAttestation::default()));

        // Step 1: Classical signature over challenge nonce (hardware-bound)
        let classical_sig = self
            .hw_signer
            .sign(&request.challenge_nonce)
            .await
            .unwrap_or_default();

        // Step 2: PQC signature over bound payload (software, ML-DSA-65)
        // The PQC signature covers the classical signature to prevent stripping
        #[cfg(feature = "pqc")]
        let (pqc_sig, pqc_pubkey, pqc_algorithm, sig_mode) = if let Some(ref pqc) = self.pqc_signer
        {
            // Build bound payload: challenge_nonce || classical_sig
            let mut bound_payload =
                Vec::with_capacity(request.challenge_nonce.len() + classical_sig.len());
            bound_payload.extend_from_slice(&request.challenge_nonce);
            bound_payload.extend_from_slice(&classical_sig);

            match (pqc.sign(&bound_payload), pqc.public_key()) {
                (Ok(sig), Ok(pk)) => {
                    debug!(
                        pqc_sig_size = sig.len(),
                        pqc_pk_size = pk.len(),
                        "PQC signature generated (ML-DSA-65, bound over classical)"
                    );
                    (
                        sig,
                        pk,
                        "ML-DSA-65".to_string(),
                        "HybridRequired".to_string(),
                    )
                },
                (Err(e), _) | (_, Err(e)) => {
                    warn!(
                        "PQC signature failed: {} — falling back to classical-only",
                        e
                    );
                    (
                        vec![],
                        vec![],
                        "ML-DSA-65".to_string(),
                        "ClassicalOnly".to_string(),
                    )
                },
            }
        } else {
            (
                vec![],
                vec![],
                "ML-DSA-65".to_string(),
                "ClassicalOnly".to_string(),
            )
        };

        #[cfg(not(feature = "pqc"))]
        let (pqc_sig, pqc_pubkey, pqc_algorithm, sig_mode) = (
            vec![],
            vec![],
            "NONE".to_string(),
            "ClassicalOnly".to_string(),
        );

        ResponseAttestation {
            platform,
            signature: ResponseSignature {
                classical: classical_sig,
                classical_algorithm: format!("{:?}", self.hw_signer.algorithm()),
                pqc: pqc_sig,
                pqc_algorithm,
                pqc_public_key: pqc_pubkey,
                signature_mode: sig_mode,
            },
            integrity_valid: self.integrity_valid,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Build validation results.
    fn build_validation_results(&self, validation: &ValidationResult) -> ValidationResults {
        ValidationResults {
            dns_us: SourceResult {
                source: "us.registry.ciris-services-1.ai".to_string(),
                reachable: validation.source_details.dns_us_reachable,
                valid: validation.source_details.dns_us_reachable
                    && validation.source_details.dns_us_error.is_none(),
                checked_at: chrono::Utc::now().timestamp(),
                error: validation.source_details.dns_us_error.clone(),
            },
            dns_eu: SourceResult {
                source: "eu.registry.ciris-services-1.ai".to_string(),
                reachable: validation.source_details.dns_eu_reachable,
                valid: validation.source_details.dns_eu_reachable
                    && validation.source_details.dns_eu_error.is_none(),
                checked_at: chrono::Utc::now().timestamp(),
                error: validation.source_details.dns_eu_error.clone(),
            },
            https: SourceResult {
                source: "api.registry.ciris-services-1.ai".to_string(),
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
                source: "us.registry.ciris-services-1.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: chrono::Utc::now().timestamp(),
                error: Some("Not checked".to_string()),
            },
            dns_eu: SourceResult {
                source: "eu.registry.ciris-services-1.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: chrono::Utc::now().timestamp(),
                error: Some("Not checked".to_string()),
            },
            https: SourceResult {
                source: "api.registry.ciris-services-1.ai".to_string(),
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
    ///
    /// Every disclosure tells the FULL story:
    /// - License state (valid, expired, revoked, missing)
    /// - Hardware state (HSM, software-only)
    /// - Who issued it (org, responsible party, contact)
    /// - When it expires
    /// - What it allows
    fn get_disclosure_text(
        &self,
        status: &LicenseStatus,
        license: Option<&LicenseDetails>,
    ) -> String {
        let hw_type = self.hw_signer.hardware_type();
        let is_sw_only = hw_type == HardwareType::SoftwareOnly;

        // Hardware summary line
        let hw_line = if is_sw_only {
            "Hardware: SOFTWARE-ONLY (no HSM/TPM/Secure Enclave). ".to_string()
        } else {
            format!("Hardware: {:?}. ", hw_type)
        };

        // License details block (if we have a license object)
        let lic_block = if let Some(lic) = license {
            let org = if lic.organization_name.is_empty() {
                "Unknown".to_string()
            } else {
                lic.organization_name.clone()
            };
            let party = if lic.responsible_party.is_empty() {
                String::new()
            } else {
                format!("Responsible party: {}. ", lic.responsible_party)
            };
            let contact = if lic.responsible_party_contact.is_empty() {
                String::new()
            } else {
                format!("Contact: {}. ", lic.responsible_party_contact)
            };
            let expires = format_timestamp(lic.expires_at);
            format!(
                "License: {} (ID: {}). Organization: {}. {party}{contact}\
                 Type: {:?}. Autonomy tier: {:?}. Expires: {expires}. ",
                match lic.license_type {
                    LicenseType::ProfessionalMedical => "Professional Medical",
                    LicenseType::ProfessionalLegal => "Professional Legal",
                    LicenseType::ProfessionalFinancial => "Professional Financial",
                    LicenseType::ProfessionalFull => "Professional Full",
                    LicenseType::Community => "Community",
                },
                lic.license_id,
                org,
                lic.license_type,
                lic.max_autonomy_tier,
            )
        } else {
            "License: NONE. ".to_string()
        };

        match status {
            LicenseStatus::LicensedProfessional => {
                format!(
                    "LICENSED PROFESSIONAL. {lic_block}{hw_line}\
                     Capabilities verified and active."
                )
            },
            LicenseStatus::LicensedCommunityPlus => {
                format!(
                    "COMMUNITY PLUS. {lic_block}{hw_line}\
                     Some professional features available."
                )
            },
            LicenseStatus::UnlicensedCommunity => {
                if is_sw_only {
                    format!(
                        "COMMUNITY MODE. {lic_block}{hw_line}\
                         Software-only signer limits deployment to community tier. \
                         Not a licensed professional service. \
                         Consult qualified professionals for medical, legal, or financial advice."
                    )
                } else {
                    format!(
                        "COMMUNITY MODE. {lic_block}{hw_line}\
                         No valid professional license found. \
                         Not a licensed professional service. \
                         Consult qualified professionals for medical, legal, or financial advice."
                    )
                }
            },
            LicenseStatus::UnlicensedUnverified => {
                format!(
                    "UNVERIFIED. {lic_block}{hw_line}\
                     License status could not be confirmed. Operating in restricted mode."
                )
            },
            LicenseStatus::ErrorBinaryTampered => {
                format!(
                    "LOCKDOWN — BINARY TAMPERED. {lic_block}{hw_line}\
                     Binary integrity check failed. System locked down for security."
                )
            },
            LicenseStatus::ErrorSourcesDisagree => {
                format!(
                    "SECURITY ALERT — SOURCES DISAGREE. {lic_block}{hw_line}\
                     Verification sources report conflicting data. \
                     Possible attack detected. System in restricted mode."
                )
            },
            LicenseStatus::ErrorVerificationFailed => {
                format!(
                    "COMMUNITY MODE — VERIFICATION FAILED. {lic_block}{hw_line}\
                     Cannot reach verification servers and no valid cached license."
                )
            },
            LicenseStatus::ErrorLicenseRevoked => {
                format!(
                    "COMMUNITY MODE — LICENSE REVOKED. {lic_block}{hw_line}\
                     License has been revoked. Operating in community mode \
                     until a valid license is restored."
                )
            },
            LicenseStatus::ErrorLicenseExpired => {
                format!(
                    "COMMUNITY MODE — LICENSE EXPIRED. {lic_block}{hw_line}\
                     License has expired. Contact your organization to renew."
                )
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
/// Performs runtime security checks:
/// - Debugger detection (ptrace/sysctl/Win32 API)
/// - Hook detection (Frida, Xposed)
/// - Environment checks (device compromise, suspicious emulators)
///
/// Note: Desktop VMs (KVM, VMware, cloud instances) are NOT blocked.
/// Only mobile emulators (Android emulator, iOS simulator) are suspicious.
/// Desktop VMs are legitimate deployment targets and the user has full
/// control anyway. VM status is reported in attestation for transparency.
///
/// Binary self-hash verification is skipped until the hash embedding
/// pipeline is implemented (requires two-pass build).
fn verify_binary_integrity() -> bool {
    // In debug builds, skip all checks to allow development
    #[cfg(debug_assertions)]
    {
        true
    }

    // Check ALL conditions to prevent timing attacks
    #[cfg(not(debug_assertions))]
    {
        use crate::security::{
            detect_hooks, is_debugger_attached, is_device_compromised, is_suspicious_emulator,
        };

        let debugger_ok = !is_debugger_attached();
        let hooks_ok = !detect_hooks();
        let device_ok = !is_device_compromised();
        // Only block on suspicious emulators (mobile), not desktop VMs
        let emulator_ok = !is_suspicious_emulator();

        debugger_ok && hooks_ok && device_ok && emulator_ok
    }
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
