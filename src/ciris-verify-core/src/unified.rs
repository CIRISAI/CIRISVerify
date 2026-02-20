//! Unified attestation engine.
//!
//! Provides a single entry point for running all verification checks:
//! - Key attestation (hardware/Portal key verification)
//! - File integrity (full + spot checks against registry manifest)
//! - Source validation (DNS US, DNS EU, HTTPS)
//! - Audit trail integrity (hash chain + signatures)

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::audit::{AuditEntry, AuditVerificationResult, AuditVerifier};
use crate::config::VerifyConfig;
use crate::error::VerifyError;
use crate::registry::RegistryClient;
use crate::security::file_integrity::{self, FileIntegrityResult};
use crate::validation::{ConsensusValidator, ValidationResult};

/// Request for full attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullAttestationRequest {
    /// Challenge nonce for attestation (>= 32 bytes).
    pub challenge: Vec<u8>,
    /// Agent version to verify against registry.
    #[serde(default)]
    pub agent_version: Option<String>,
    /// Agent root directory for file integrity checks.
    #[serde(default)]
    pub agent_root: Option<String>,
    /// Number of files for spot check (0 = skip spot check).
    #[serde(default)]
    pub spot_check_count: usize,
    /// Audit entries for verification (JSON array).
    #[serde(default)]
    pub audit_entries: Option<Vec<AuditEntry>>,
    /// Expected Portal key ID for audit signature verification.
    #[serde(default)]
    pub portal_key_id: Option<String>,
    /// Skip registry manifest fetch (use for offline operation).
    #[serde(default)]
    pub skip_registry: bool,
    /// Skip file integrity checks.
    #[serde(default)]
    pub skip_file_integrity: bool,
    /// Skip audit trail verification.
    #[serde(default)]
    pub skip_audit: bool,
}

/// Result of full attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullAttestationResult {
    /// Overall attestation valid.
    pub valid: bool,
    /// Attestation level (0-5 scale).
    pub level: u8,
    /// Key attestation proof.
    pub key_attestation: Option<KeyAttestationResult>,
    /// File integrity check results.
    pub file_integrity: Option<IntegrityCheckResult>,
    /// Source validation results.
    pub sources: SourceCheckResult,
    /// Audit trail verification result.
    pub audit_trail: Option<AuditVerificationResult>,
    /// Total checks passed.
    pub checks_passed: u32,
    /// Total checks run.
    pub checks_total: u32,
    /// Detailed diagnostics.
    pub diagnostics: String,
    /// Errors encountered.
    pub errors: Vec<String>,
    /// Verification timestamp.
    pub timestamp: i64,
}

/// Key attestation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttestationResult {
    /// Key type (portal or ephemeral).
    pub key_type: String,
    /// Hardware type.
    pub hardware_type: String,
    /// Has valid signature over challenge.
    pub has_valid_signature: bool,
    /// Binary version.
    pub binary_version: String,
    /// Running in VM.
    pub running_in_vm: bool,
    /// Classical signature (hex).
    #[serde(default)]
    pub classical_signature: String,
    /// PQC signature available.
    pub pqc_available: bool,
}

/// File integrity check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheckResult {
    /// Full check result (if run).
    pub full: Option<FileCheckSummary>,
    /// Spot check result (if run).
    pub spot: Option<FileCheckSummary>,
    /// Registry reachable.
    pub registry_reachable: bool,
    /// Manifest version from registry.
    pub manifest_version: Option<String>,
}

/// Summary of a file integrity check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCheckSummary {
    /// Whether integrity is valid.
    pub valid: bool,
    /// Total files in manifest.
    pub total_files: usize,
    /// Files checked.
    pub files_checked: usize,
    /// Files passed.
    pub files_passed: usize,
    /// Files failed.
    pub files_failed: usize,
    /// Files missing.
    pub files_missing: usize,
    /// Unexpected files found.
    pub files_unexpected: usize,
    /// Failure reason (if any).
    pub failure_reason: String,
}

impl From<FileIntegrityResult> for FileCheckSummary {
    fn from(r: FileIntegrityResult) -> Self {
        Self {
            valid: r.integrity_valid,
            total_files: r.total_files,
            files_checked: r.files_checked,
            files_passed: r.files_passed,
            files_failed: r.files_failed,
            files_missing: r.files_missing,
            files_unexpected: r.files_unexpected,
            failure_reason: r.failure_reason,
        }
    }
}

/// Source validation check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCheckResult {
    /// DNS US reachable.
    pub dns_us_reachable: bool,
    /// DNS US valid.
    pub dns_us_valid: bool,
    /// DNS US error (if any).
    pub dns_us_error: Option<String>,
    /// DNS EU reachable.
    pub dns_eu_reachable: bool,
    /// DNS EU valid.
    pub dns_eu_valid: bool,
    /// DNS EU error (if any).
    pub dns_eu_error: Option<String>,
    /// HTTPS reachable.
    pub https_reachable: bool,
    /// HTTPS valid.
    pub https_valid: bool,
    /// HTTPS error (if any).
    pub https_error: Option<String>,
    /// Overall validation status.
    pub validation_status: String,
}

impl From<&ValidationResult> for SourceCheckResult {
    fn from(v: &ValidationResult) -> Self {
        Self {
            dns_us_reachable: v.source_details.dns_us_reachable,
            dns_us_valid: v.source_details.dns_us_reachable
                && v.source_details.dns_us_error.is_none(),
            dns_us_error: v.source_details.dns_us_error.clone(),
            dns_eu_reachable: v.source_details.dns_eu_reachable,
            dns_eu_valid: v.source_details.dns_eu_reachable
                && v.source_details.dns_eu_error.is_none(),
            dns_eu_error: v.source_details.dns_eu_error.clone(),
            https_reachable: v.source_details.https_reachable,
            https_valid: v.source_details.https_reachable && v.source_details.https_error.is_none(),
            https_error: v.source_details.https_error.clone(),
            validation_status: format!("{:?}", v.status),
        }
    }
}

/// Unified attestation engine.
///
/// Runs all verification checks and returns a comprehensive result.
pub struct UnifiedAttestationEngine {
    /// Configuration (reserved for future use).
    #[allow(dead_code)]
    config: VerifyConfig,
    /// Consensus validator.
    consensus_validator: ConsensusValidator,
    /// Registry client.
    registry_client: Option<RegistryClient>,
}

impl UnifiedAttestationEngine {
    /// Create a new unified attestation engine.
    pub fn new(config: VerifyConfig) -> Result<Self, VerifyError> {
        let consensus_validator = ConsensusValidator::with_trust_model(
            config.dns_us_host.clone(),
            config.dns_eu_host.clone(),
            config.https_endpoint.clone(),
            config.https_endpoints.clone(),
            config.trust_model.clone(),
            config.timeout,
            config.cert_pin.clone(),
        );

        let registry_client = RegistryClient::new(&config.https_endpoint, config.timeout).ok();

        Ok(Self {
            config,
            consensus_validator,
            registry_client,
        })
    }

    /// Run full attestation.
    ///
    /// This is the main entry point for comprehensive verification.
    #[instrument(skip(self, request))]
    pub async fn run_attestation(
        &self,
        request: FullAttestationRequest,
    ) -> Result<FullAttestationResult, VerifyError> {
        let start = std::time::Instant::now();
        let mut errors = Vec::new();
        let mut checks_passed = 0u32;
        let mut checks_total = 0u32;
        let mut diagnostics = String::new();

        info!("Starting unified attestation");

        // 1. Source validation (always run)
        checks_total += 3; // DNS US, DNS EU, HTTPS
        let validation = self.consensus_validator.validate_steward_key().await;
        let sources = SourceCheckResult::from(&validation);

        if sources.dns_us_valid {
            checks_passed += 1;
        }
        if sources.dns_eu_valid {
            checks_passed += 1;
        }
        if sources.https_valid {
            checks_passed += 1;
        }

        diagnostics.push_str(&format!(
            "Sources: DNS_US={} DNS_EU={} HTTPS={}\n",
            if sources.dns_us_valid { "OK" } else { "FAIL" },
            if sources.dns_eu_valid { "OK" } else { "FAIL" },
            if sources.https_valid { "OK" } else { "FAIL" },
        ));

        // 2. File integrity checks (if requested)
        let file_integrity = if !request.skip_file_integrity {
            if let (Some(ref version), Some(ref agent_root)) =
                (&request.agent_version, &request.agent_root)
            {
                checks_total += 1; // Full check
                if request.spot_check_count > 0 {
                    checks_total += 1; // Spot check
                }

                match self
                    .run_file_integrity(version, agent_root, request.spot_check_count)
                    .await
                {
                    Ok(result) => {
                        if result.full.as_ref().map(|f| f.valid).unwrap_or(false) {
                            checks_passed += 1;
                        }
                        if result.spot.as_ref().map(|s| s.valid).unwrap_or(false) {
                            checks_passed += 1;
                        }
                        diagnostics.push_str(&format!(
                            "File integrity: full={} spot={}\n",
                            result
                                .full
                                .as_ref()
                                .map(|f| if f.valid { "OK" } else { "FAIL" })
                                .unwrap_or("SKIP"),
                            result
                                .spot
                                .as_ref()
                                .map(|s| if s.valid { "OK" } else { "FAIL" })
                                .unwrap_or("SKIP"),
                        ));
                        Some(result)
                    },
                    Err(e) => {
                        errors.push(format!("File integrity check failed: {}", e));
                        diagnostics.push_str(&format!("File integrity: ERROR ({})\n", e));
                        None
                    },
                }
            } else {
                diagnostics.push_str("File integrity: SKIP (no version/root provided)\n");
                None
            }
        } else {
            diagnostics.push_str("File integrity: SKIP (disabled)\n");
            None
        };

        // 3. Audit trail verification (if provided)
        let audit_trail = if !request.skip_audit {
            if let Some(ref entries) = request.audit_entries {
                checks_total += 1;

                let verifier = AuditVerifier::new(request.portal_key_id.clone());
                let result = verifier.verify_entries(entries, true);

                if result.valid {
                    checks_passed += 1;
                }

                diagnostics.push_str(&format!(
                    "Audit trail: {} ({} entries, chain={}, genesis={})\n",
                    if result.valid { "OK" } else { "FAIL" },
                    result.total_entries,
                    if result.hash_chain_valid {
                        "OK"
                    } else {
                        "BROKEN"
                    },
                    if result.genesis_valid {
                        "OK"
                    } else {
                        "INVALID"
                    },
                ));

                if !result.errors.is_empty() {
                    for err in &result.errors {
                        errors.push(format!("Audit: {}", err));
                    }
                }

                Some(result)
            } else {
                diagnostics.push_str("Audit trail: SKIP (no entries provided)\n");
                None
            }
        } else {
            diagnostics.push_str("Audit trail: SKIP (disabled)\n");
            None
        };

        // Calculate level (0-5 scale)
        let level = if checks_total > 0 {
            ((checks_passed as f32 / checks_total as f32) * 5.0).round() as u8
        } else {
            0
        };

        let valid = checks_passed == checks_total && errors.is_empty();

        diagnostics.push_str(&format!(
            "\nSummary: {}/{} checks passed, level={}/5\n",
            checks_passed, checks_total, level
        ));
        diagnostics.push_str(&format!("Time: {}ms\n", start.elapsed().as_millis()));

        info!(
            checks_passed,
            checks_total, level, valid, "Unified attestation complete"
        );

        Ok(FullAttestationResult {
            valid,
            level,
            key_attestation: None, // Filled by caller with HW signer
            file_integrity,
            sources,
            audit_trail,
            checks_passed,
            checks_total,
            diagnostics,
            errors,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Run file integrity checks against registry manifest.
    async fn run_file_integrity(
        &self,
        version: &str,
        agent_root: &str,
        spot_count: usize,
    ) -> Result<IntegrityCheckResult, VerifyError> {
        // Fetch manifest from registry
        let client = self
            .registry_client
            .as_ref()
            .ok_or_else(|| VerifyError::HttpsError {
                message: "Registry client not available".into(),
            })?;

        let build = client.get_build_by_version(version).await?;

        // Convert registry manifest to file_integrity manifest
        // Convert HashMap to BTreeMap for deterministic ordering
        let files_btree: BTreeMap<String, String> =
            build.file_manifest_json.files.into_iter().collect();

        let manifest = file_integrity::FileManifest {
            version: build.file_manifest_json.version.clone(),
            generated_at: String::new(),
            files: files_btree,
            manifest_hash: build.file_manifest_hash.clone(),
        };

        let agent_path = Path::new(agent_root);

        // Run full check
        let full_result = file_integrity::check_full(&manifest, agent_path);

        // Run spot check if requested
        let spot_result = if spot_count > 0 {
            Some(file_integrity::check_spot(
                &manifest, agent_path, spot_count,
            ))
        } else {
            None
        };

        Ok(IntegrityCheckResult {
            full: Some(full_result.into()),
            spot: spot_result.map(|r| r.into()),
            registry_reachable: true,
            manifest_version: Some(build.version),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ValidationStatus;

    #[test]
    fn test_source_check_result() {
        use crate::validation::SourceDetails;

        let validation = ValidationResult {
            status: ValidationStatus::AllSourcesAgree,
            consensus_key_classical: None,
            consensus_pqc_fingerprint: None,
            consensus_revocation_revision: Some(1),
            authoritative_source: None,
            source_details: SourceDetails {
                dns_us_reachable: true,
                dns_eu_reachable: true,
                https_reachable: true,
                dns_us_error: None,
                dns_eu_error: None,
                https_error: None,
            },
        };

        let result = SourceCheckResult::from(&validation);
        assert!(result.dns_us_valid);
        assert!(result.dns_eu_valid);
        assert!(result.https_valid);
    }

    #[test]
    fn test_file_check_summary() {
        let integrity = FileIntegrityResult {
            integrity_valid: true,
            total_files: 100,
            files_checked: 100,
            files_passed: 100,
            files_failed: 0,
            files_missing: 0,
            files_unexpected: 0,
            failure_reason: String::new(),
        };

        let summary: FileCheckSummary = integrity.into();
        assert!(summary.valid);
        assert_eq!(summary.total_files, 100);
    }
}
