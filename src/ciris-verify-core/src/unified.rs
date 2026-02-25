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
    /// Ed25519 key fingerprint for registry verification (SHA-256 hex, 64 chars).
    /// If provided, verifies the key against CIRISRegistry.
    #[serde(default)]
    pub key_fingerprint: Option<String>,
    /// Use partial file integrity check (only verify files that exist on disk).
    /// Useful for mobile deployments where files are lazily extracted.
    #[serde(default)]
    pub partial_file_check: bool,
    /// Python module hashes for Android/mobile code integrity verification.
    /// If provided, verifies Python modules against expected hashes.
    #[serde(default)]
    pub python_hashes: Option<PythonModuleHashes>,
    /// Expected Python total hash (SHA-256 hex) from a trusted source.
    /// If provided along with python_hashes, verifies total_hash matches.
    #[serde(default)]
    pub expected_python_hash: Option<String>,
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
    /// Registry key verification status (if key_fingerprint was provided in request).
    /// One of: "active", "rotated", "revoked", "not_found", "not_checked", "error:..."
    #[serde(default)]
    pub registry_key_status: String,
    /// Device attestation result (L2: Play Integrity / App Attest).
    #[serde(default)]
    pub device_attestation: Option<DeviceAttestationCheckResult>,
    /// File integrity check results.
    pub file_integrity: Option<IntegrityCheckResult>,
    /// Python module integrity check results (Android/mobile).
    pub python_integrity: Option<PythonIntegrityResult>,
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
    /// Whether the key is hardware-backed (Android Keystore AES wrapper, Secure Enclave, TPM).
    #[serde(default)]
    pub hardware_backed: bool,
    /// Storage mode description (e.g., "Software", "HW-AES-256-GCM", "SecureEnclave", "TPM").
    #[serde(default)]
    pub storage_mode: String,
    /// Ed25519 public key fingerprint (SHA-256 hex, 64 chars).
    #[serde(default)]
    pub ed25519_fingerprint: String,
    /// ML-DSA-65 public key fingerprint (SHA-256 hex, 64 chars) if available.
    #[serde(default)]
    pub mldsa_fingerprint: Option<String>,
    /// Registry key verification status.
    /// One of: "active", "rotated", "revoked", "not_found", "not_checked", "error:..."
    #[serde(default)]
    pub registry_key_status: String,
}

/// Device attestation result (L2: Play Integrity on Android, App Attest on iOS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAttestationCheckResult {
    /// Platform that was checked ("android" or "ios").
    pub platform: String,
    /// Whether the device attestation passed.
    pub verified: bool,
    /// Summary of the verification result.
    #[serde(default)]
    pub summary: String,
    /// Error message if verification failed.
    #[serde(default)]
    pub error: Option<String>,
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

/// Python module hashes from Android/mobile agent.
///
/// Generated at startup by hashing all Python modules (ciris_engine, etc.).
/// Used for code integrity verification on mobile where Python is embedded in APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonModuleHashes {
    /// Total hash of all module hashes concatenated (SHA-256 hex).
    pub total_hash: String,
    /// Individual module hashes (module_name -> SHA-256 hex).
    #[serde(default)]
    pub module_hashes: std::collections::BTreeMap<String, String>,
    /// Number of modules hashed.
    pub module_count: usize,
    /// Agent version that generated these hashes.
    #[serde(default)]
    pub agent_version: String,
    /// Timestamp when hashes were computed (Unix seconds).
    #[serde(default)]
    pub computed_at: i64,
}

/// Result of Python module integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonIntegrityResult {
    /// Overall integrity valid.
    pub valid: bool,
    /// Total modules checked.
    pub modules_checked: usize,
    /// Modules that passed verification.
    pub modules_passed: usize,
    /// Modules that failed verification.
    pub modules_failed: usize,
    /// Whether the total_hash matched (quick verification).
    pub total_hash_valid: bool,
    /// Expected total hash from manifest (if available).
    #[serde(default)]
    pub expected_total_hash: Option<String>,
    /// Actual total hash from agent.
    pub actual_total_hash: String,
    /// Verification mode: "total_hash_only", "individual_modules", "both".
    pub verification_mode: String,
    /// List of modules that failed verification (path → reason).
    #[serde(default)]
    pub failed_modules: BTreeMap<String, String>,
    /// List of modules missing from manifest (in agent but not expected).
    #[serde(default)]
    pub unexpected_modules: Vec<String>,
    /// List of modules missing from agent (expected but not provided).
    #[serde(default)]
    pub missing_modules: Vec<String>,
    /// Error message if verification failed.
    #[serde(default)]
    pub error: Option<String>,
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
    /// Per-file check results (path → status: passed/failed/missing/unreadable).
    #[serde(default)]
    pub per_file_results: std::collections::BTreeMap<String, String>,
    /// List of unexpected files found (not in manifest, not exempt).
    #[serde(default)]
    pub unexpected_files: Vec<String>,
}

impl From<FileIntegrityResult> for FileCheckSummary {
    fn from(r: FileIntegrityResult) -> Self {
        // Convert FileCheckStatus enum to string for JSON serialization
        let per_file_results: std::collections::BTreeMap<String, String> = r
            .per_file_results
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();

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
            per_file_results,
            unexpected_files: r.unexpected_files,
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

        // Run all four checks IN PARALLEL
        let (self_verification, validation, file_integrity_result, key_verification_result): (
            SelfVerificationResult,
            ValidationResult,
            Option<Result<IntegrityCheckResult, VerifyError>>,
            String,
        ) = tokio::join!(
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
            },
            // 3. Registry key verification (if key_fingerprint provided)
            async {
                let result: String = if let Some(ref fingerprint) = request.key_fingerprint {
                    if let Some(ref client) = self.registry_client {
                        info!(
                            "Verifying key fingerprint against registry: {}",
                            fingerprint
                        );
                        match client.verify_key_by_fingerprint(fingerprint).await {
                            Ok(response) => {
                                let status = if response.is_valid_for_signing() {
                                    "active".to_string()
                                } else if response.is_valid_rotated() {
                                    "rotated".to_string()
                                } else if response.is_revoked() {
                                    "revoked".to_string()
                                } else if !response.found {
                                    "not_found".to_string()
                                } else {
                                    format!("unknown:{}", response.status)
                                };
                                info!("Registry key verification: {}", status);
                                status
                            },
                            Err(e) => {
                                warn!("Registry key verification failed: {}", e);
                                format!("error:{}", e)
                            },
                        }
                    } else {
                        warn!("Registry client not available for key verification");
                        "error:no_client".to_string()
                    }
                } else {
                    "not_checked".to_string()
                };
                result
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

        // Detailed self-verification diagnostics
        diagnostics.push_str("=== SELF-VERIFICATION (Level 1) ===\n");
        diagnostics.push_str(&format!(
            "  Target: {}\n  Version: {}\n",
            self_verification.target, self_verification.binary_version
        ));
        diagnostics.push_str(&format!(
            "  Binary: {} (registry={})\n",
            if self_verification.binary_valid {
                "✓ OK"
            } else {
                "✗ FAIL"
            },
            if self_verification.registry_reachable {
                "reachable"
            } else {
                "UNREACHABLE"
            }
        ));
        if !self_verification.binary_valid {
            diagnostics.push_str(&format!(
                "    └─ Computed hash: {}...\n",
                &self_verification.binary_hash
                    [..std::cmp::min(32, self_verification.binary_hash.len())]
            ));
            if let Some(ref expected) = self_verification.expected_hash {
                diagnostics.push_str(&format!(
                    "    └─ Expected hash: {}...\n",
                    &expected[..std::cmp::min(32, expected.len())]
                ));
            } else {
                diagnostics.push_str(
                    "    └─ Expected hash: NOT IN REGISTRY (target may not be registered)\n",
                );
            }
        }
        diagnostics.push_str(&format!(
            "  Functions: {} ({}/{} passed)\n",
            if self_verification.functions_valid {
                "✓ OK"
            } else {
                "✗ FAIL"
            },
            self_verification.functions_passed,
            self_verification.functions_checked
        ));
        if !self_verification.functions_valid && self_verification.functions_checked == 0 {
            diagnostics.push_str("    └─ No function manifest found for this target in registry\n");
        }
        if let Some(ref err) = self_verification.error {
            diagnostics.push_str(&format!("    └─ Error: {}\n", err));
        }
        diagnostics.push('\n');

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

        diagnostics.push_str("=== SOURCE VALIDATION ===\n");
        diagnostics.push_str(&format!(
            "  DNS US: {} (reachable={})\n",
            if sources.dns_us_valid {
                "✓ OK"
            } else {
                "✗ FAIL"
            },
            sources.dns_us_reachable
        ));
        if let Some(ref err) = sources.dns_us_error {
            diagnostics.push_str(&format!("    └─ Error: {}\n", err));
        }
        diagnostics.push_str(&format!(
            "  DNS EU: {} (reachable={})\n",
            if sources.dns_eu_valid {
                "✓ OK"
            } else {
                "✗ FAIL"
            },
            sources.dns_eu_reachable
        ));
        if let Some(ref err) = sources.dns_eu_error {
            diagnostics.push_str(&format!("    └─ Error: {}\n", err));
        }
        diagnostics.push_str(&format!(
            "  HTTPS:  {} (reachable={})\n",
            if sources.https_valid {
                "✓ OK"
            } else {
                "✗ FAIL"
            },
            sources.https_reachable
        ));
        if let Some(ref err) = sources.https_error {
            diagnostics.push_str(&format!("    └─ Error: {}\n", err));
        }
        diagnostics.push_str(&format!("  Status: {}\n\n", sources.validation_status));

        // Process file integrity results
        let file_integrity = if should_run_file_integrity {
            checks_total += 1; // Full check
            if request.spot_check_count > 0 {
                checks_total += 1; // Spot check
            }

            diagnostics.push_str("=== FILE INTEGRITY ===\n");
            match file_integrity_result.unwrap() {
                Ok(result) => {
                    if result.full.as_ref().map(|f| f.valid).unwrap_or(false) {
                        checks_passed += 1;
                    }
                    if result.spot.as_ref().map(|s| s.valid).unwrap_or(false) {
                        checks_passed += 1;
                    }

                    diagnostics.push_str(&format!(
                        "  Registry: {} (manifest v{})\n",
                        if result.registry_reachable {
                            "reachable"
                        } else {
                            "UNREACHABLE"
                        },
                        result.manifest_version.as_deref().unwrap_or("unknown")
                    ));

                    if let Some(ref full) = result.full {
                        diagnostics.push_str(&format!(
                            "  Full check: {} ({}/{} files passed)\n",
                            if full.valid { "✓ OK" } else { "✗ FAIL" },
                            full.files_passed,
                            full.total_files
                        ));
                        diagnostics.push_str(&format!(
                            "    └─ Checked: {}, Passed: {}, Failed: {}, Missing: {}, Unexpected: {}\n",
                            full.files_checked, full.files_passed, full.files_failed, full.files_missing, full.files_unexpected
                        ));
                        if full.files_checked == 0 && full.total_files > 0 {
                            diagnostics.push_str(
                                "    └─ ⚠️  MANIFEST HASH MISMATCH - no files were checked!\n",
                            );
                            diagnostics.push_str("    └─ This means: computed hash of file hashes ≠ stored manifest_hash\n");
                            diagnostics.push_str("    └─ Likely cause: registry computes manifest_hash differently\n");
                        }
                        if !full.failure_reason.is_empty() {
                            diagnostics.push_str(&format!(
                                "    └─ Failure reason: {}\n",
                                full.failure_reason
                            ));
                        }
                        if full.partial_check {
                            diagnostics.push_str(&format!(
                                "    └─ Partial mode: {}/{} files found on disk\n",
                                full.files_found, full.total_files
                            ));
                        }
                    }

                    if let Some(ref spot) = result.spot {
                        diagnostics.push_str(&format!(
                            "  Spot check: {} ({}/{} files passed)\n",
                            if spot.valid { "✓ OK" } else { "✗ FAIL" },
                            spot.files_passed,
                            spot.files_checked
                        ));
                    }
                    diagnostics.push('\n');
                    Some(result)
                },
                Err(e) => {
                    errors.push(format!("File integrity check failed: {}", e));
                    diagnostics.push_str(&format!("  ERROR: {}\n\n", e));
                    None
                },
            }
        } else if !request.skip_file_integrity {
            diagnostics.push_str("=== FILE INTEGRITY ===\n  SKIP (no version/root provided)\n\n");
            None
        } else {
            diagnostics.push_str("=== FILE INTEGRITY ===\n  SKIP (disabled)\n\n");
            None
        };

        // 3. Python module integrity (Android/mobile)
        let python_integrity = if let Some(ref hashes) = request.python_hashes {
            checks_total += 1;

            diagnostics.push_str("=== PYTHON INTEGRITY ===\n");
            diagnostics.push_str(&format!(
                "  Modules provided: {} (total_hash: {}...)\n",
                hashes.module_count,
                &hashes.total_hash[..std::cmp::min(16, hashes.total_hash.len())]
            ));

            // Fetch expected hashes from registry if we have agent_version
            let expected_hashes: Option<std::collections::HashMap<String, String>> =
                if let Some(ref version) = request.agent_version {
                    if let Some(ref client) = self.registry_client {
                        match client.get_build_by_version(version).await {
                            Ok(build) => {
                                diagnostics.push_str(&format!(
                                    "  Registry manifest: {} files (v{})\n",
                                    build.file_manifest_json.files().len(),
                                    build.version
                                ));
                                Some(build.file_manifest_json.files().clone())
                            },
                            Err(e) => {
                                diagnostics.push_str(&format!(
                                    "  Registry manifest: ✗ fetch failed ({})\n",
                                    e
                                ));
                                None
                            },
                        }
                    } else {
                        diagnostics.push_str("  Registry manifest: ✗ no client\n");
                        None
                    }
                } else {
                    diagnostics.push_str("  Registry manifest: ○ no agent_version provided\n");
                    None
                };

            // Verify total_hash if expected_python_hash provided
            let total_hash_valid = if let Some(ref expected) = request.expected_python_hash {
                let matches = hashes.total_hash == *expected;
                diagnostics.push_str(&format!(
                    "  Total hash: {} (expected: {}...)\n",
                    if matches { "✓ MATCH" } else { "✗ MISMATCH" },
                    &expected[..std::cmp::min(16, expected.len())]
                ));
                matches
            } else {
                diagnostics.push_str("  Total hash: ○ not verified (no expected_python_hash)\n");
                true // No expected hash means we can't fail on it
            };

            // Per-module validation
            let mut modules_passed = 0usize;
            let mut modules_failed = 0usize;
            let mut failed_modules: BTreeMap<String, String> = BTreeMap::new();
            let mut unexpected_modules: Vec<String> = Vec::new();
            let mut missing_modules: Vec<String> = Vec::new();

            if let Some(ref manifest_files) = expected_hashes {
                diagnostics.push_str("  Per-module verification:\n");

                // Log sample paths from both sides for debugging path format mismatches
                let agent_sample: Vec<_> = hashes.module_hashes.keys().take(3).collect();
                let manifest_sample: Vec<_> = manifest_files
                    .keys()
                    .filter(|p| p.ends_with(".py"))
                    .take(3)
                    .collect();
                info!(
                    "Python module path formats - agent: {:?}, manifest: {:?}",
                    agent_sample, manifest_sample
                );
                diagnostics.push_str(&format!("    Agent paths (sample): {:?}\n", agent_sample));
                diagnostics.push_str(&format!(
                    "    Manifest paths (sample): {:?}\n",
                    manifest_sample
                ));

                // Helper: find manifest entry that matches agent path (handles different bases)
                // Tries: exact match, then suffix match (manifest ends with /agent_path)
                let find_manifest_hash = |agent_path: &str| -> Option<(&String, &String)> {
                    // 1. Exact match
                    if let Some(hash) = manifest_files.get(agent_path) {
                        return Some((manifest_files.get_key_value(agent_path).unwrap().0, hash));
                    }

                    // 2. Suffix match: manifest path ends with /agent_path
                    // e.g., agent="ciris_engine/core.py" matches manifest="src/ciris_engine/core.py"
                    let suffix = format!("/{}", agent_path);
                    for (manifest_path, hash) in manifest_files.iter() {
                        if manifest_path.ends_with(&suffix) {
                            return Some((manifest_path, hash));
                        }
                    }

                    // 3. Try without leading directory (agent might have extra prefix)
                    // e.g., agent="python/ciris_engine/core.py" matches manifest="ciris_engine/core.py"
                    if let Some(slash_pos) = agent_path.find('/') {
                        let without_prefix = &agent_path[slash_pos + 1..];
                        if let Some(hash) = manifest_files.get(without_prefix) {
                            return Some((
                                manifest_files.get_key_value(without_prefix).unwrap().0,
                                hash,
                            ));
                        }
                    }

                    None
                };

                // Check each module provided by agent
                for (module_path, actual_hash) in &hashes.module_hashes {
                    if let Some((matched_path, expected_hash)) = find_manifest_hash(module_path) {
                        // Strip "sha256:" prefix if present
                        let expected_clean = expected_hash
                            .strip_prefix("sha256:")
                            .unwrap_or(expected_hash);

                        if actual_hash == expected_clean {
                            modules_passed += 1;
                        } else {
                            modules_failed += 1;
                            failed_modules.insert(
                                module_path.clone(),
                                format!(
                                    "hash mismatch (manifest: {}): got {}..., expected {}...",
                                    matched_path,
                                    &actual_hash[..std::cmp::min(16, actual_hash.len())],
                                    &expected_clean[..std::cmp::min(16, expected_clean.len())]
                                ),
                            );
                            diagnostics.push_str(&format!(
                                "    ✗ {}: MISMATCH\n      got:      {}...\n      expected: {}... (manifest: {})\n",
                                module_path,
                                &actual_hash[..std::cmp::min(32, actual_hash.len())],
                                &expected_clean[..std::cmp::min(32, expected_clean.len())],
                                matched_path
                            ));
                        }
                    } else {
                        // Module not in manifest - could be dynamically generated or unexpected
                        unexpected_modules.push(module_path.clone());
                        diagnostics.push_str(&format!(
                            "    ? {}: not in manifest (unexpected)\n",
                            module_path
                        ));
                    }
                }

                // Check for modules in manifest but not provided by agent
                // Only check Python files (.py) to avoid noise from other file types
                for manifest_path in manifest_files.keys() {
                    if manifest_path.ends_with(".py")
                        && !hashes.module_hashes.contains_key(manifest_path)
                    {
                        missing_modules.push(manifest_path.clone());
                    }
                }

                if !missing_modules.is_empty() && missing_modules.len() <= 10 {
                    diagnostics.push_str(&format!(
                        "    ⚠ {} Python modules in manifest but not provided by agent\n",
                        missing_modules.len()
                    ));
                    for path in missing_modules.iter().take(5) {
                        diagnostics.push_str(&format!("      └─ {}\n", path));
                    }
                    if missing_modules.len() > 5 {
                        diagnostics.push_str(&format!(
                            "      └─ ... and {} more\n",
                            missing_modules.len() - 5
                        ));
                    }
                }

                diagnostics.push_str(&format!(
                    "    Summary: {}/{} passed, {} failed, {} unexpected\n",
                    modules_passed,
                    hashes.module_hashes.len(),
                    modules_failed,
                    unexpected_modules.len()
                ));
            } else {
                // No manifest to compare against - record mode only
                modules_passed = hashes.module_count;
                diagnostics.push_str("  Per-module: ○ skipped (no manifest to compare)\n");
            }

            // Overall validity: all modules must pass AND total_hash must match (if provided)
            let all_modules_valid = modules_failed == 0;
            let valid = total_hash_valid && all_modules_valid;

            if valid {
                checks_passed += 1;
            } else {
                if !total_hash_valid {
                    errors.push("Python total_hash mismatch".to_string());
                }
                if !all_modules_valid {
                    errors.push(format!(
                        "Python module integrity: {} modules failed",
                        modules_failed
                    ));
                }
            }

            diagnostics.push_str(&format!(
                "  Agent version: {}\n",
                if hashes.agent_version.is_empty() {
                    "unknown"
                } else {
                    &hashes.agent_version
                }
            ));
            if hashes.computed_at > 0 {
                diagnostics.push_str(&format!("  Computed at: {} (Unix)\n", hashes.computed_at));
            }
            diagnostics.push('\n');

            Some(PythonIntegrityResult {
                valid,
                modules_checked: hashes.module_hashes.len(),
                modules_passed,
                modules_failed,
                total_hash_valid,
                expected_total_hash: request.expected_python_hash.clone(),
                actual_total_hash: hashes.total_hash.clone(),
                verification_mode: if expected_hashes.is_some() {
                    "individual_modules".to_string()
                } else if request.expected_python_hash.is_some() {
                    "total_hash_only".to_string()
                } else {
                    "record_only".to_string()
                },
                failed_modules,
                unexpected_modules,
                missing_modules,
                error: if valid {
                    None
                } else if !all_modules_valid {
                    Some(format!(
                        "{} modules failed hash verification",
                        modules_failed
                    ))
                } else {
                    Some("Total hash mismatch".to_string())
                },
            })
        } else {
            diagnostics.push_str("=== PYTHON INTEGRITY ===\n  SKIP (no hashes provided)\n\n");
            None
        };

        // 4. Audit trail verification (if provided)
        let audit_trail = if !request.skip_audit {
            if let Some(ref entries) = request.audit_entries {
                checks_total += 1;

                let verifier = AuditVerifier::new(request.portal_key_id.clone());
                let result = verifier.verify_entries(entries, true);

                if result.valid {
                    checks_passed += 1;
                }

                diagnostics.push_str("=== AUDIT TRAIL ===\n");
                diagnostics.push_str(&format!(
                    "  Status: {} ({} entries)\n",
                    if result.valid { "✓ OK" } else { "✗ FAIL" },
                    result.total_entries
                ));
                diagnostics.push_str(&format!(
                    "  Hash chain: {}\n",
                    if result.hash_chain_valid {
                        "✓ valid"
                    } else {
                        "✗ BROKEN"
                    }
                ));
                diagnostics.push_str(&format!(
                    "  Genesis: {}\n",
                    if result.genesis_valid {
                        "✓ valid"
                    } else {
                        "✗ INVALID"
                    }
                ));
                if result.portal_key_used {
                    diagnostics.push_str("  Portal key: ✓ used for signing\n");
                }
                if let Some(seq) = result.first_tampered_sequence {
                    diagnostics.push_str(&format!("  ⚠️  First tampered sequence: {}\n", seq));
                }
                if !result.errors.is_empty() {
                    for err in &result.errors {
                        diagnostics.push_str(&format!("    └─ Error: {}\n", err));
                        errors.push(format!("Audit: {}", err));
                    }
                }
                diagnostics.push('\n');

                Some(result)
            } else {
                diagnostics.push_str("=== AUDIT TRAIL ===\n  SKIP (no entries provided)\n\n");
                None
            }
        } else {
            diagnostics.push_str("=== AUDIT TRAIL ===\n  SKIP (disabled)\n\n");
            None
        };

        // 4. Registry key verification diagnostics
        diagnostics.push_str("=== REGISTRY KEY ===\n");
        if request.key_fingerprint.is_some() {
            checks_total += 1;
            let key_ok = key_verification_result == "active";
            if key_ok {
                checks_passed += 1;
            }
            let status_icon = match key_verification_result.as_str() {
                "active" => "✓ ACTIVE",
                "rotated" => "⚠️  ROTATED",
                "revoked" => "✗ REVOKED",
                "not_found" => "✗ NOT_FOUND",
                s if s.starts_with("error:") => "✗ ERROR",
                _ => "? UNKNOWN",
            };
            diagnostics.push_str(&format!("  Status: {}\n", status_icon));
            if let Some(err_msg) = key_verification_result.strip_prefix("error:") {
                diagnostics.push_str(&format!("    └─ {}\n", err_msg));
                errors.push(format!("Registry key: {}", err_msg));
            } else if key_verification_result == "revoked" {
                errors.push("Registry key: REVOKED".to_string());
            }
        } else {
            diagnostics.push_str("  Status: not_checked (no fingerprint provided)\n");
        }
        diagnostics.push('\n');

        // Calculate level as cascading tiers (any failure caps at prior level)
        // L1: Binary hash + function integrity
        let l1_pass = self_verification.binary_valid && self_verification.functions_valid;
        // L2: Device attestation is injected by FFI layer from cached results
        // (Play Integrity / App Attest verified via separate FFI calls before run_attestation).
        // At the engine level, L2 passes through from L1.
        let l2_pass = l1_pass;
        // L3: Registry cross-validation (at least 2/3 sources must agree)
        let sources_agreeing = u8::from(sources.dns_us_valid)
            + u8::from(sources.dns_eu_valid)
            + u8::from(sources.https_valid);
        let l3_pass = l2_pass && sources_agreeing >= 2;
        // L4: File integrity (if checked)
        let l4_pass = l3_pass
            && file_integrity
                .as_ref()
                .map(|fi| fi.full.as_ref().map(|f| f.valid).unwrap_or(true))
                .unwrap_or(true)
            && python_integrity.as_ref().map(|pi| pi.valid).unwrap_or(true);
        // L5: Audit trail + registry key
        let l5_pass = l4_pass
            && audit_trail.as_ref().map(|a| a.valid).unwrap_or(true)
            && (key_verification_result == "active" || key_verification_result == "not_checked");

        let level = if l5_pass {
            5
        } else if l4_pass {
            4
        } else if l3_pass {
            3
        } else if l2_pass {
            2
        } else if l1_pass {
            1
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
            registry_key_status: key_verification_result,
            device_attestation: None, // Injected by FFI layer from cached Play Integrity / App Attest results
            file_integrity,
            python_integrity,
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
            },
            Err(e) => {
                warn!("run_file_integrity: failed to fetch build: {}", e);
                return Err(e);
            },
        };

        // Convert registry manifest to file_integrity manifest
        // Convert HashMap to BTreeMap for deterministic ordering
        let files_btree: BTreeMap<String, String> = build
            .file_manifest_json
            .files()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        info!(
            "run_file_integrity: registry returned {} files, file_manifest_hash='{}'",
            build.file_manifest_json.files().len(),
            &build.file_manifest_hash
        );

        // Log if manifest is empty - this would cause 0 files checked
        if files_btree.is_empty() {
            warn!("run_file_integrity: WARNING - registry returned EMPTY file manifest!");
        }

        let manifest = file_integrity::FileManifest {
            version: build.file_manifest_json.version().to_string(),
            generated_at: String::new(),
            files: files_btree,
            manifest_hash: build.file_manifest_hash.clone(),
        };

        // Log first 3 file paths from manifest
        let sample_paths: Vec<_> = manifest.files.keys().take(3).collect();
        let sample_hashes: Vec<_> = manifest
            .files
            .values()
            .take(3)
            .map(|h| &h[..std::cmp::min(16, h.len())])
            .collect();
        info!(
            "run_file_integrity: constructed manifest with {} files, hash='{}'\n  sample paths: {:?}\n  sample hashes: {:?}",
            manifest.files.len(),
            &manifest.manifest_hash[..std::cmp::min(32, manifest.manifest_hash.len())],
            sample_paths,
            sample_hashes
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
            version,
            target,
            &binary_hash[..16]
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
            // Binary hash verification - returns (valid, expected_hash_opt, available_targets)
            async {
                info!("Binary manifest check: fetching for version={}", version);
                match client.get_binary_manifest(version).await {
                    Ok(manifest) => {
                        let available_targets: Vec<String> =
                            manifest.binaries.keys().cloned().collect();
                        info!(
                            "Binary manifest check: got manifest with {} targets: {:?}",
                            manifest.binaries.len(),
                            available_targets
                        );
                        if let Some(expected) = manifest.binaries.get(target) {
                            // Strip "sha256:" prefix if present
                            let expected_clean =
                                expected.strip_prefix("sha256:").unwrap_or(expected);
                            let matches = binary_hash_clone == expected_clean;
                            info!(
                                "Binary manifest check: target={}, expected={}, actual={}, matches={}",
                                target,
                                &expected_clean[..std::cmp::min(16, expected_clean.len())],
                                &binary_hash_clone[..std::cmp::min(16, binary_hash_clone.len())],
                                matches
                            );
                            (matches, Some(expected_clean.to_string()), available_targets)
                        } else {
                            warn!(
                                "Binary manifest check: no hash for target={}, available={:?}",
                                target, available_targets
                            );
                            (false, None, available_targets)
                        }
                    },
                    Err(e) => {
                        warn!(
                            "Binary manifest check: fetch FAILED for version={}, target={}: {}",
                            version, target, e
                        );
                        (false, None, vec![])
                    },
                }
            },
            // Function integrity verification
            async {
                info!(
                    "Function manifest check: fetching for version={}, target={}",
                    version, target
                );
                match client.get_function_manifest(version, target).await {
                    Ok(manifest) => {
                        let result = function_integrity::verify_functions(&manifest);
                        info!(
                            "Function manifest check: {}/{} passed, valid={}",
                            result.functions_passed,
                            result.functions_checked,
                            result.integrity_valid
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

        let (binary_valid, expected_hash, available_targets) = binary_result;
        let (functions_valid, functions_checked, functions_passed) = function_result;
        let valid = binary_valid && functions_valid;

        // Build detailed error message
        let error = if valid {
            None
        } else {
            let mut errors = Vec::new();
            if !binary_valid {
                if expected_hash.is_none() {
                    errors.push(format!(
                        "Binary hash not in registry for target '{}'. Available targets: {:?}",
                        target, available_targets
                    ));
                } else {
                    errors.push("Binary hash mismatch".to_string());
                }
            }
            if !functions_valid {
                if functions_checked == 0 {
                    errors.push(format!(
                        "No function manifest found for target '{}'",
                        target
                    ));
                } else {
                    errors.push(format!(
                        "Function integrity failed: {}/{} passed",
                        functions_passed, functions_checked
                    ));
                }
            }
            Some(errors.join("; "))
        };

        SelfVerificationResult {
            binary_valid,
            functions_valid,
            valid,
            binary_version: version.to_string(),
            target: target.to_string(),
            binary_hash,
            expected_hash,
            functions_checked,
            functions_passed,
            registry_reachable: true,
            error,
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
            per_file_results: std::collections::BTreeMap::new(),
            unexpected_files: Vec::new(),
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
            per_file_results: std::collections::BTreeMap::new(),
            unexpected_files: Vec::new(),
        };

        let summary: FileCheckSummary = integrity.into();
        assert!(summary.valid);
        assert_eq!(summary.total_files, 100);
        assert_eq!(summary.files_found, 50);
        assert_eq!(summary.files_missing, 50);
        assert!(summary.partial_check);
    }
}
