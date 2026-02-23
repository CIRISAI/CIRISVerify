//! Unified attestation engine.
//!
//! Provides a single entry point for running all verification checks:
//! - Self-verification (binary hash + function integrity) - Level 1
//! - Key attestation (hardware/Portal key verification)
//! - File integrity (full + spot checks against registry manifest)
//! - Source validation (DNS US, DNS EU, HTTPS)
//! - Audit trail integrity (hash chain + signatures)

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{info, instrument, warn};

use crate::audit::{AuditEntry, AuditVerificationResult, AuditVerifier};
use crate::config::VerifyConfig;
use crate::error::VerifyError;
use crate::registry::{compute_self_hash, current_target, RegistryClient};
use crate::security::file_integrity::{self, FileIntegrityResult};
use crate::security::function_integrity;
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
    /// Use partial file integrity check (only verify files that exist on disk).
    /// Useful for mobile deployments where files are lazily extracted.
    #[serde(default)]
    pub partial_file_check: bool,
}

/// Result of full attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullAttestationResult {
    /// Overall attestation valid.
    pub valid: bool,
    /// Attestation level (0-5 scale).
    pub level: u8,
    /// Self-verification result (Level 1: binary + function integrity).
    pub self_verification: Option<SelfVerificationResult>,
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

/// Self-verification result (Level 1).
///
/// Recursive check: CIRISVerify verifies its own integrity before
/// verifying anything else ("who watches the watchmen").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfVerificationResult {
    /// Binary hash matches registry manifest.
    pub binary_valid: bool,
    /// Function integrity matches registry manifest.
    pub functions_valid: bool,
    /// Combined validity.
    pub valid: bool,
    /// Binary version being verified.
    pub binary_version: String,
    /// Target triple.
    pub target: String,
    /// Computed binary hash (SHA-256).
    pub binary_hash: String,
    /// Expected binary hash from registry.
    pub expected_hash: Option<String>,
    /// Number of functions verified.
    pub functions_checked: usize,
    /// Number of functions passed.
    pub functions_passed: usize,
    /// Registry reachable for manifest fetch.
    pub registry_reachable: bool,
    /// Error message if failed.
    pub error: Option<String>,
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
    /// Files found on disk (for partial checks, indicates coverage).
    pub files_found: usize,
    /// Whether this was a partial check (only available files).
    pub partial_check: bool,
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
            files_found: r.files_found,
            partial_check: r.partial_check,
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
    /// All three major checks run IN PARALLEL for maximum performance:
    /// - Self-verification (binary + function integrity)
    /// - Source validation (DNS US, DNS EU, HTTPS)
    /// - File integrity (agent files vs manifest)
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

        info!("Starting unified attestation (parallel checks)");

        // Prepare file integrity check params
        let should_run_file_integrity = !request.skip_file_integrity
            && request.agent_version.is_some()
            && request.agent_root.is_some();

        // Run all three checks IN PARALLEL
        let (self_verification, validation, file_integrity_result) = tokio::join!(
            // 0. Self-verification (Level 1: recursive check - "who watches the watchmen")
            self.run_self_verification(),

            // 1. Source validation (always run)
            self.consensus_validator.validate_steward_key(),

            // 2. File integrity (if requested and params available)
            async {
                if should_run_file_integrity {
                    let version = request.agent_version.as_ref().unwrap();
                    let agent_root = request.agent_root.as_ref().unwrap();
                    Some(
                        self.run_file_integrity(
                            version,
                            agent_root,
                            request.spot_check_count,
                            request.partial_file_check,
                        )
                        .await,
                    )
                } else {
                    None
                }
            }
        );

        // Process self-verification results
        checks_total += 2; // Binary hash + function integrity

        if self_verification.binary_valid {
            checks_passed += 1;
        }
        if self_verification.functions_valid {
            checks_passed += 1;
        }

        diagnostics.push_str(&format!(
            "Self-verification: binary={} functions={} ({})\n",
            if self_verification.binary_valid { "OK" } else { "FAIL" },
            if self_verification.functions_valid { "OK" } else { "FAIL" },
            self_verification.target,
        ));

        if !self_verification.valid {
            if let Some(ref err) = self_verification.error {
                errors.push(format!("Self-verification: {}", err));
            }
        }

        // Process source validation results
        checks_total += 3; // DNS US, DNS EU, HTTPS
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

        // Process file integrity results
        let file_integrity = if should_run_file_integrity {
            checks_total += 1; // Full check
            if request.spot_check_count > 0 {
                checks_total += 1; // Spot check
            }

            match file_integrity_result.unwrap() {
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
        } else if !request.skip_file_integrity {
            diagnostics.push_str("File integrity: SKIP (no version/root provided)\n");
            None
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
            self_verification: Some(self_verification),
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
    ///
    /// If `partial_check` is true, only files that exist on disk are verified.
    /// This is useful for mobile deployments where files are lazily extracted.
    async fn run_file_integrity(
        &self,
        version: &str,
        agent_root: &str,
        spot_count: usize,
        partial_check: bool,
    ) -> Result<IntegrityCheckResult, VerifyError> {
        info!(
            "run_file_integrity: version={}, agent_root={}, partial={}",
            version, agent_root, partial_check
        );

        // Fetch manifest from registry
        let client = self
            .registry_client
            .as_ref()
            .ok_or_else(|| VerifyError::HttpsError {
                message: "Registry client not available".into(),
            })?;

        info!("run_file_integrity: fetching build from registry");
        let build = match client.get_build_by_version(version).await {
            Ok(b) => {
                info!(
                    "run_file_integrity: got build, files={}, manifest_hash={}",
                    b.file_manifest_json.files().len(),
                    &b.file_manifest_hash[..std::cmp::min(16, b.file_manifest_hash.len())]
                );
                b
            }
            Err(e) => {
                warn!("run_file_integrity: failed to fetch build: {}", e);
                return Err(e);
            }
        };

        // Convert registry manifest to file_integrity manifest
        // Convert HashMap to BTreeMap for deterministic ordering
        let files_btree: BTreeMap<String, String> =
            build.file_manifest_json.files().iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        let manifest = file_integrity::FileManifest {
            version: build.file_manifest_json.version().to_string(),
            generated_at: String::new(),
            files: files_btree,
            manifest_hash: build.file_manifest_hash.clone(),
        };

        // Log first 3 file paths from manifest
        let sample_paths: Vec<_> = manifest.files.keys().take(3).collect();
        info!(
            "run_file_integrity: manifest has {} files, sample paths: {:?}",
            manifest.files.len(),
            sample_paths
        );

        let agent_path = Path::new(agent_root);
        info!(
            "run_file_integrity: agent_path={:?}, exists={}",
            agent_path,
            agent_path.exists()
        );

        // Run full or partial check based on mode
        let full_result = if partial_check {
            file_integrity::check_available(&manifest, agent_path)
        } else {
            file_integrity::check_full(&manifest, agent_path)
        };

        // Run spot check if requested (only for non-partial mode)
        let spot_result = if spot_count > 0 && !partial_check {
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

    /// Run self-verification (Level 1: recursive integrity check).
    ///
    /// Verifies CIRISVerify's own integrity before trusting any results.
    /// This is the "who watches the watchmen" check.
    ///
    /// Binary hash verification and function integrity verification run in parallel.
    async fn run_self_verification(&self) -> SelfVerificationResult {
        let version = env!("CARGO_PKG_VERSION");
        let target = current_target();

        // Compute our own binary hash
        let binary_hash = match compute_self_hash() {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to compute self hash: {}", e);
                return SelfVerificationResult {
                    binary_valid: false,
                    functions_valid: false,
                    valid: false,
                    binary_version: version.to_string(),
                    target: target.to_string(),
                    binary_hash: String::new(),
                    expected_hash: None,
                    functions_checked: 0,
                    functions_passed: 0,
                    registry_reachable: false,
                    error: Some(format!("Failed to compute self hash: {}", e)),
                };
            },
        };

        info!(
            "Self-verification: version={}, target={}, hash={}",
            version, target, &binary_hash[..16]
        );

        // Try to fetch binary manifest from registry
        let client = match &self.registry_client {
            Some(c) => c,
            None => {
                return SelfVerificationResult {
                    binary_valid: false,
                    functions_valid: false,
                    valid: false,
                    binary_version: version.to_string(),
                    target: target.to_string(),
                    binary_hash,
                    expected_hash: None,
                    functions_checked: 0,
                    functions_passed: 0,
                    registry_reachable: false,
                    error: Some("Registry client not available".to_string()),
                };
            },
        };

        // Run binary and function verification IN PARALLEL
        let binary_hash_clone = binary_hash.clone();
        let (binary_result, function_result) = tokio::join!(
            // Binary hash verification
            async {
                info!("Binary manifest check: fetching for version={}", version);
                match client.get_binary_manifest(version).await {
                    Ok(manifest) => {
                        info!(
                            "Binary manifest check: got manifest with {} targets: {:?}",
                            manifest.binaries.len(),
                            manifest.binaries.keys().collect::<Vec<_>>()
                        );
                        if let Some(expected) = manifest.binaries.get(target) {
                            // Strip "sha256:" prefix if present
                            let expected_clean = expected.strip_prefix("sha256:").unwrap_or(expected);
                            let matches = binary_hash_clone == expected_clean;
                            info!(
                                "Binary manifest check: target={}, expected={}, actual={}, matches={}",
                                target,
                                &expected_clean[..std::cmp::min(16, expected_clean.len())],
                                &binary_hash_clone[..std::cmp::min(16, binary_hash_clone.len())],
                                matches
                            );
                            matches
                        } else {
                            warn!(
                                "Binary manifest check: no hash for target={}, available={:?}",
                                target,
                                manifest.binaries.keys().collect::<Vec<_>>()
                            );
                            false
                        }
                    },
                    Err(e) => {
                        warn!("Binary manifest check: fetch failed: {}", e);
                        false
                    },
                }
            },
            // Function integrity verification
            async {
                info!("Function manifest check: fetching for version={}, target={}", version, target);
                match client.get_function_manifest(version, target).await {
                    Ok(manifest) => {
                        let result = function_integrity::verify_functions(&manifest);
                        info!(
                            "Function manifest check: {}/{} passed, valid={}",
                            result.functions_passed, result.functions_checked, result.integrity_valid
                        );
                        (
                            result.integrity_valid,
                            result.functions_checked,
                            result.functions_passed,
                        )
                    },
                    Err(e) => {
                        warn!("Function manifest check: fetch failed: {}", e);
                        (false, 0, 0)
                    },
                }
            }
        );

        let binary_valid = binary_result;
        let (functions_valid, functions_checked, functions_passed) = function_result;
        let valid = binary_valid && functions_valid;

        SelfVerificationResult {
            binary_valid,
            functions_valid,
            valid,
            binary_version: version.to_string(),
            target: target.to_string(),
            binary_hash,
            expected_hash: None, // Could be populated from manifest
            functions_checked,
            functions_passed,
            registry_reachable: true,
            error: if valid {
                None
            } else {
                Some("Self-verification failed".to_string())
            },
        }
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
            files_found: 100,
            partial_check: false,
        };

        let summary: FileCheckSummary = integrity.into();
        assert!(summary.valid);
        assert_eq!(summary.total_files, 100);
        assert_eq!(summary.files_found, 100);
        assert!(!summary.partial_check);
    }

    #[test]
    fn test_file_check_summary_partial() {
        let integrity = FileIntegrityResult {
            integrity_valid: true,
            total_files: 100,
            files_checked: 50,
            files_passed: 50,
            files_failed: 0,
            files_missing: 50,
            files_unexpected: 0,
            failure_reason: String::new(),
            files_found: 50,
            partial_check: true,
        };

        let summary: FileCheckSummary = integrity.into();
        assert!(summary.valid);
        assert_eq!(summary.total_files, 100);
        assert_eq!(summary.files_found, 50);
        assert_eq!(summary.files_missing, 50);
        assert!(summary.partial_check);
    }
}
