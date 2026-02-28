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
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, instrument, warn};

use crate::audit::{AuditEntry, AuditVerificationResult, AuditVerifier};
use crate::config::VerifyConfig;
use crate::error::VerifyError;
use crate::registry::{
    compute_self_hash, current_target, BinaryManifest, BuildRecord, ResilientRegistryClient,
    FALLBACK_REGISTRY_URLS,
};
use crate::security::file_integrity::{self, FileIntegrityResult};
use crate::security::function_integrity::{self, FunctionManifest};
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
    /// Whether level calculation is pending async checks (Play Integrity / App Attest).
    /// When true, the level may increase once platform-required checks complete.
    #[serde(default)]
    pub level_pending: bool,
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
    /// File integrity check results (legacy - use module_integrity instead).
    pub file_integrity: Option<IntegrityCheckResult>,
    /// Python module integrity check results (legacy - use module_integrity instead).
    pub python_integrity: Option<PythonIntegrityResult>,
    /// Unified module integrity (cross-validates disk, agent, and registry hashes).
    #[serde(default)]
    pub module_integrity: Option<ModuleIntegrityResult>,
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

/// Unified module integrity result combining disk and agent hash verification.
///
/// Cross-validates hashes from three sources:
/// - Registry manifest (expected)
/// - Disk (computed by CIRISVerify from agent_root)
/// - Agent-provided (sent at startup)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleIntegrityResult {
    /// Overall integrity valid.
    pub valid: bool,
    /// Total files in registry manifest.
    pub manifest_file_count: usize,
    /// Files verified from filesystem (disk hash == registry).
    pub filesystem_verified: Vec<String>,
    /// Files verified from agent hashes (agent hash == registry, not on disk).
    pub agent_verified: Vec<String>,
    /// Files cross-validated (disk == agent == registry - strongest).
    pub cross_validated: Vec<String>,
    /// Files where disk hash != agent hash (tampering or stale agent hashes).
    pub disk_agent_mismatch: BTreeMap<String, DiskAgentMismatch>,
    /// Files where hash != registry (path → details).
    pub registry_mismatch: BTreeMap<String, RegistryMismatch>,
    /// Files missing entirely (in manifest but not found anywhere).
    pub missing: Vec<String>,
    /// Files not in manifest (found but unexpected).
    pub unexpected: Vec<String>,
    /// Excluded files (non-Python on mobile, etc.).
    pub excluded: Vec<String>,
    /// Summary counts.
    pub summary: ModuleIntegritySummary,
    /// Registry manifest version.
    pub manifest_version: Option<String>,
    /// Error if verification failed.
    pub error: Option<String>,
}

/// Details of a disk vs agent hash mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskAgentMismatch {
    /// Hash computed from disk.
    pub disk_hash: String,
    /// Hash provided by agent.
    pub agent_hash: String,
    /// Registry expected hash.
    pub registry_hash: String,
    /// Which source matches registry (if any): "disk", "agent", "neither".
    pub registry_match: String,
}

/// Details of a registry hash mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMismatch {
    /// Hash from disk (if available).
    pub disk_hash: Option<String>,
    /// Hash from agent (if available).
    pub agent_hash: Option<String>,
    /// Expected hash from registry.
    pub registry_hash: String,
    /// Source of the mismatch: "disk", "agent", "both".
    pub source: String,
}

/// Summary counts for module integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleIntegritySummary {
    /// Total files in manifest.
    pub total_manifest: usize,
    /// Files successfully verified.
    pub verified: usize,
    /// Files with any mismatch.
    pub failed: usize,
    /// Files missing.
    pub missing: usize,
    /// Files excluded from check.
    pub excluded: usize,
    /// Files cross-validated (strongest verification).
    pub cross_validated: usize,
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
    /// Resilient registry client with failover.
    registry_client: Option<ResilientRegistryClient>,
}

/// End-to-end timeout for attestation (15 seconds max).
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(15);

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

        // Use resilient client with fallback endpoints
        let registry_client = ResilientRegistryClient::new(
            &config.https_endpoint,
            FALLBACK_REGISTRY_URLS,
            config.timeout,
        )
        .ok();

        Ok(Self {
            config,
            consensus_validator,
            registry_client,
        })
    }

    /// Run full attestation with 15-second timeout.
    ///
    /// This is the main entry point for comprehensive verification.
    /// All network fetches and verification run IN PARALLEL for maximum performance.
    /// Guaranteed to return within 15 seconds regardless of network conditions.
    #[instrument(skip(self, request))]
    pub async fn run_attestation(
        &self,
        request: FullAttestationRequest,
    ) -> Result<FullAttestationResult, VerifyError> {
        // Wrap entire attestation in 15-second timeout to guarantee return
        match tokio::time::timeout(ATTESTATION_TIMEOUT, self.run_attestation_inner(request)).await {
            Ok(result) => result,
            Err(_) => {
                warn!("Attestation timed out after {:?}", ATTESTATION_TIMEOUT);
                // Return partial result on timeout
                Ok(FullAttestationResult {
                    valid: false,
                    level: 0,
                    level_pending: true,
                    self_verification: None,
                    key_attestation: None,
                    registry_key_status: "timeout".to_string(),
                    device_attestation: None,
                    file_integrity: None,
                    python_integrity: None,
                    module_integrity: None,
                    sources: SourceCheckResult {
                        dns_us_reachable: false,
                        dns_us_valid: false,
                        dns_us_error: Some("timeout".to_string()),
                        dns_eu_reachable: false,
                        dns_eu_valid: false,
                        dns_eu_error: Some("timeout".to_string()),
                        https_reachable: false,
                        https_valid: false,
                        https_error: Some("timeout".to_string()),
                        validation_status: "Timeout".to_string(),
                    },
                    audit_trail: None,
                    checks_passed: 0,
                    checks_total: 0,
                    diagnostics: format!("Attestation timed out after {:?}", ATTESTATION_TIMEOUT),
                    errors: vec![format!("Timeout after {:?}", ATTESTATION_TIMEOUT)],
                    timestamp: chrono::Utc::now().timestamp(),
                })
            },
        }
    }

    /// Inner attestation logic (called with timeout wrapper).
    async fn run_attestation_inner(
        &self,
        request: FullAttestationRequest,
    ) -> Result<FullAttestationResult, VerifyError> {
        let start = std::time::Instant::now();
        let mut errors = Vec::new();
        let mut checks_passed = 0u32;
        let mut checks_total = 0u32;
        let mut diagnostics = String::new();

        info!("Starting unified attestation (parallel checks)");

        // Prepare check params
        let should_run_file_integrity = !request.skip_file_integrity
            && request.agent_version.is_some()
            && request.agent_root.is_some();
        let should_run_module_integrity = request.agent_version.is_some();
        let verify_version = env!("CARGO_PKG_VERSION");
        let target = crate::registry::current_target();

        // =======================================================================
        // PHASE 1: Fetch ALL manifests + run validations IN PARALLEL
        // Critical for mobile where each network call blocks the thread
        // =======================================================================
        info!("Phase 1: Parallel manifest fetch + validation");

        let (
            binary_manifest_result,
            function_manifest_result,
            agent_build_result,
            validation,
            key_verification_result,
        ) = tokio::join!(
            // 1. Binary manifest (verify version) - for self-verification
            async {
                if let Some(ref client) = self.registry_client {
                    match client.get_binary_manifest(verify_version).await {
                        Ok(m) => {
                            info!("Binary manifest: {} targets", m.binaries.len());
                            Some(m)
                        },
                        Err(e) => {
                            warn!("Binary manifest fetch failed: {}", e);
                            None
                        },
                    }
                } else {
                    None
                }
            },
            // 2. Function manifest (verify version + target) - for self-verification
            async {
                if let Some(ref client) = self.registry_client {
                    match client.get_function_manifest(verify_version, target).await {
                        Ok(m) => {
                            info!("Function manifest: {} functions", m.functions.len());
                            Some(m)
                        },
                        Err(e) => {
                            warn!("Function manifest fetch failed: {}", e);
                            None
                        },
                    }
                } else {
                    None
                }
            },
            // 3. Agent build record (agent version) - for file/module/python integrity
            async {
                if let Some(ref version) = request.agent_version {
                    if let Some(ref client) = self.registry_client {
                        match client.get_build_by_version(version).await {
                            Ok(b) => {
                                info!("Agent build: {} files", b.file_manifest_json.files().len());
                                Some(b)
                            },
                            Err(e) => {
                                warn!("Agent build fetch failed: {}", e);
                                None
                            },
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
            // 4. Source validation (DNS + HTTPS consensus)
            self.consensus_validator.validate_steward_key(),
            // 5. Registry key verification
            async {
                if let Some(ref fingerprint) = request.key_fingerprint {
                    if let Some(ref client) = self.registry_client {
                        info!("Verifying key fingerprint: {}", fingerprint);
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
                        "error:no_client".to_string()
                    }
                } else {
                    "not_checked".to_string()
                }
            }
        );

        info!("Phase 1 complete. Phase 2: Local verification using pre-fetched manifests");

        // =======================================================================
        // PHASE 2: Run verification logic using pre-fetched manifests (NO network)
        // =======================================================================

        // Self-verification using pre-fetched binary + function manifests
        let self_verification = self
            .run_self_verification_with_manifests(
                binary_manifest_result.as_ref(),
                function_manifest_result.as_ref(),
            )
            .await;

        // File integrity using pre-fetched agent build
        let file_integrity_result = if should_run_file_integrity {
            let agent_root = request.agent_root.as_ref().unwrap();
            Some(
                self.run_file_integrity_with_build(
                    agent_build_result.as_ref(),
                    agent_root,
                    request.spot_check_count,
                    request.partial_file_check,
                )
                .await,
            )
        } else {
            None
        };

        // Module integrity using pre-fetched agent build
        let module_integrity_result = if should_run_module_integrity {
            let agent_hashes = request.python_hashes.as_ref().map(|h| &h.module_hashes);
            Some(
                self.run_module_integrity_with_build(
                    agent_build_result.as_ref(),
                    request.agent_root.as_deref(),
                    agent_hashes,
                    &[],
                )
                .await,
            )
        } else {
            None
        };

        // Use pre-fetched build for Python integrity too
        let build_record_for_python = agent_build_result;

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

            // Use pre-fetched build record from parallel join (no sequential network call)
            let expected_hashes: Option<std::collections::HashMap<String, String>> =
                if let Some(ref build) = build_record_for_python {
                    diagnostics.push_str(&format!(
                        "  Registry manifest: {} files (v{})\n",
                        build.file_manifest_json.files().len(),
                        build.version
                    ));
                    Some(build.file_manifest_json.files().clone())
                } else if request.agent_version.is_some() {
                    diagnostics.push_str("  Registry manifest: ✗ fetch failed (parallel)\n");
                    None
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

        // 3b. Unified module integrity (use pre-fetched result from Phase 2)
        let module_integrity = if should_run_module_integrity {
            diagnostics.push_str("=== MODULE INTEGRITY (Unified) ===\n");

            match module_integrity_result.unwrap() {
                Ok(result) => {
                    checks_total += 1;
                    if result.valid {
                        checks_passed += 1;
                    }

                    diagnostics.push_str(&format!(
                        "  Manifest: {} files (v{})\n",
                        result.manifest_file_count,
                        result.manifest_version.as_deref().unwrap_or("unknown")
                    ));
                    diagnostics.push_str(&format!(
                        "  Cross-validated: {} (disk == agent == registry)\n",
                        result.cross_validated.len()
                    ));
                    diagnostics.push_str(&format!(
                        "  Filesystem verified: {} (disk == registry)\n",
                        result.filesystem_verified.len()
                    ));
                    diagnostics.push_str(&format!(
                        "  Agent verified: {} (agent == registry)\n",
                        result.agent_verified.len()
                    ));

                    if !result.disk_agent_mismatch.is_empty() {
                        diagnostics.push_str(&format!(
                            "  ⚠️  Disk/Agent mismatch: {} (tampering?)\n",
                            result.disk_agent_mismatch.len()
                        ));
                        for (path, mismatch) in result.disk_agent_mismatch.iter().take(5) {
                            diagnostics.push_str(&format!(
                                "    └─ {}: disk={}... agent={}... registry_match={}\n",
                                path,
                                &mismatch.disk_hash[..std::cmp::min(16, mismatch.disk_hash.len())],
                                &mismatch.agent_hash
                                    [..std::cmp::min(16, mismatch.agent_hash.len())],
                                mismatch.registry_match
                            ));
                        }
                        errors.push(format!(
                            "Module integrity: {} disk/agent mismatches",
                            result.disk_agent_mismatch.len()
                        ));
                    }

                    if !result.registry_mismatch.is_empty() {
                        diagnostics.push_str(&format!(
                            "  ✗ Registry mismatch: {}\n",
                            result.registry_mismatch.len()
                        ));
                        for (path, mismatch) in result.registry_mismatch.iter().take(5) {
                            diagnostics.push_str(&format!(
                                "    └─ {}: source={}\n",
                                path, mismatch.source
                            ));
                        }
                        errors.push(format!(
                            "Module integrity: {} registry mismatches",
                            result.registry_mismatch.len()
                        ));
                    }

                    if !result.missing.is_empty() {
                        diagnostics
                            .push_str(&format!("  ✗ Missing: {} files\n", result.missing.len()));
                    }

                    diagnostics.push_str(&format!(
                        "  Summary: {}/{} verified, {} failed\n\n",
                        result.summary.verified,
                        result.summary.total_manifest - result.summary.excluded,
                        result.summary.failed
                    ));

                    Some(result)
                },
                Err(e) => {
                    diagnostics.push_str(&format!("  ✗ Error: {}\n\n", e));
                    errors.push(format!("Module integrity error: {}", e));
                    None
                },
            }
        } else {
            diagnostics.push_str("=== MODULE INTEGRITY ===\n  SKIP (no agent_version)\n\n");
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
        // On iOS, function integrity always fails (Xcode code signing relocates addresses).
        // L1 stays yellow here; the FFI layer compensates when App Attest (L2) passes,
        // allowing L1 to pass with binary_valid alone (device attestation as trust signal).
        let l1_pass = self_verification.binary_valid && self_verification.functions_valid;
        // L2: Device attestation is injected by FFI layer from cached results
        // (Play Integrity / App Attest verified via separate FFI calls before run_attestation).
        // At the engine level, L2 does NOT pass - it requires explicit device attestation.
        // The FFI layer will set l2_pass = l1_pass && da.verified when device attestation exists.
        let l2_pass = false;
        // L3: Registry cross-validation (at least 2/3 sources must agree)
        let sources_agreeing = u8::from(sources.dns_us_valid)
            + u8::from(sources.dns_eu_valid)
            + u8::from(sources.https_valid);
        let l3_pass = l2_pass && sources_agreeing >= 2;
        // L4: File integrity (MUST be checked and valid - if not checked, level caps at L3)
        // Note: unwrap_or(false) means "if not checked, don't count as passing"
        let l4_pass = l3_pass
            && file_integrity
                .as_ref()
                .map(|fi| fi.full.as_ref().map(|f| f.valid).unwrap_or(false))
                .unwrap_or(false)
            && python_integrity
                .as_ref()
                .map(|pi| pi.valid)
                .unwrap_or(false);
        // L5: Audit trail (MUST be checked and valid) + registry key (must be active)
        let l5_pass = l4_pass
            && audit_trail.as_ref().map(|a| a.valid).unwrap_or(false)
            && key_verification_result == "active";

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
            level_pending: true, // FFI layer will set to false when platform checks complete
            self_verification: Some(self_verification),
            key_attestation: None, // Filled by caller with HW signer
            registry_key_status: key_verification_result,
            device_attestation: None, // Injected by FFI layer from cached Play Integrity / App Attest results
            file_integrity,
            python_integrity,
            module_integrity,
            sources,
            audit_trail,
            checks_passed,
            checks_total,
            diagnostics,
            errors,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    // =========================================================================
    // Functions that accept PRE-FETCHED data (no network calls)
    // Used by Phase 2 of run_attestation for maximum parallelism
    // =========================================================================

    /// Run self-verification using pre-fetched manifests (NO network calls).
    ///
    /// This is the fast path used after Phase 1 parallel fetch.
    async fn run_self_verification_with_manifests(
        &self,
        binary_manifest: Option<&BinaryManifest>,
        function_manifest: Option<&FunctionManifest>,
    ) -> SelfVerificationResult {
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
            "Self-verification (pre-fetched): version={}, target={}, hash={}...",
            version,
            target,
            &binary_hash[..std::cmp::min(16, binary_hash.len())]
        );

        // Binary hash verification using pre-fetched manifest
        let (binary_valid, expected_hash, available_targets) =
            if let Some(manifest) = binary_manifest {
                let available_targets: Vec<String> = manifest.binaries.keys().cloned().collect();
                if let Some(expected) = manifest.binaries.get(target) {
                    let expected_clean = expected.strip_prefix("sha256:").unwrap_or(expected);
                    let matches = binary_hash == expected_clean;
                    info!(
                        "Binary check (pre-fetched): target={}, matches={}",
                        target, matches
                    );
                    (matches, Some(expected_clean.to_string()), available_targets)
                } else {
                    warn!(
                        "Binary check (pre-fetched): no hash for target={}, available={:?}",
                        target, available_targets
                    );
                    (false, None, available_targets)
                }
            } else {
                warn!("Binary check (pre-fetched): no manifest available");
                (false, None, vec![])
            };

        // Function integrity verification using pre-fetched manifest
        let (functions_valid, functions_checked, functions_passed) =
            if let Some(manifest) = function_manifest {
                let result = function_integrity::verify_functions(manifest);
                info!(
                    "Function check (pre-fetched): {}/{} passed, valid={}",
                    result.functions_passed, result.functions_checked, result.integrity_valid
                );
                (
                    result.integrity_valid,
                    result.functions_checked,
                    result.functions_passed,
                )
            } else {
                warn!("Function check (pre-fetched): no manifest available");
                (false, 0, 0)
            };

        let valid = binary_valid && functions_valid;

        // Build detailed error message
        let error = if valid {
            None
        } else {
            let mut errors = Vec::new();
            if !binary_valid {
                if expected_hash.is_none() {
                    errors.push(format!(
                        "Binary hash not in registry for target '{}'. Available: {:?}",
                        target, available_targets
                    ));
                } else {
                    errors.push("Binary hash mismatch".to_string());
                }
            }
            if !functions_valid {
                if functions_checked == 0 {
                    errors.push(format!("No function manifest for target '{}'", target));
                } else {
                    errors.push(format!(
                        "Function integrity: {}/{} passed",
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
            registry_reachable: binary_manifest.is_some() || function_manifest.is_some(),
            error,
        }
    }

    /// Run file integrity check using pre-fetched build record (NO network calls).
    async fn run_file_integrity_with_build(
        &self,
        build: Option<&BuildRecord>,
        agent_root: &str,
        spot_count: usize,
        partial_check: bool,
    ) -> Result<IntegrityCheckResult, VerifyError> {
        let build = build.ok_or_else(|| VerifyError::HttpsError {
            message: "No build record available (pre-fetch failed)".into(),
        })?;

        info!(
            "run_file_integrity (pre-fetched): version={}, files={}, agent_root={}",
            build.version,
            build.file_manifest_json.files().len(),
            agent_root
        );

        // Convert registry manifest to file_integrity manifest
        let files_btree: BTreeMap<String, String> = build
            .file_manifest_json
            .files()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let manifest = file_integrity::FileManifest {
            version: build.file_manifest_json.version().to_string(),
            generated_at: String::new(),
            files: files_btree,
            manifest_hash: build.file_manifest_hash.clone(),
        };

        let agent_path = Path::new(agent_root);

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
            manifest_version: Some(build.version.clone()),
        })
    }

    /// Run module integrity check using pre-fetched build record (NO network calls).
    async fn run_module_integrity_with_build(
        &self,
        build: Option<&BuildRecord>,
        agent_root: Option<&str>,
        agent_hashes: Option<&BTreeMap<String, String>>,
        excluded_extensions: &[&str],
    ) -> Result<ModuleIntegrityResult, VerifyError> {
        use sha2::{Digest, Sha256};
        use std::collections::HashSet;

        let build = build.ok_or_else(|| VerifyError::HttpsError {
            message: "No build record available (pre-fetch failed)".into(),
        })?;

        let registry_files = build.file_manifest_json.files();

        info!(
            "run_module_integrity (pre-fetched): version={}, files={}, agent_hashes={}",
            build.version,
            registry_files.len(),
            agent_hashes.map(|h| h.len()).unwrap_or(0)
        );

        let mut filesystem_verified = Vec::new();
        let mut agent_verified = Vec::new();
        let mut cross_validated = Vec::new();
        let mut disk_agent_mismatch: BTreeMap<String, DiskAgentMismatch> = BTreeMap::new();
        let mut registry_mismatch: BTreeMap<String, RegistryMismatch> = BTreeMap::new();
        let mut missing = Vec::new();
        let mut unexpected = Vec::new();
        let mut excluded = Vec::new();

        let mut processed_agent_paths: HashSet<String> = HashSet::new();

        let normalize_path = |p: &str| -> String {
            p.trim_start_matches("./")
                .trim_start_matches('/')
                .to_string()
        };

        let find_agent_hash = |manifest_path: &str| -> Option<String> {
            let agent_hashes = agent_hashes?;
            let normalized = normalize_path(manifest_path);

            if let Some(h) = agent_hashes.get(&normalized) {
                return Some(h.clone());
            }
            if let Some(h) = agent_hashes.get(manifest_path) {
                return Some(h.clone());
            }

            let suffix = format!("/{}", normalized);
            for (agent_path, hash) in agent_hashes {
                if agent_path.ends_with(&suffix) || normalize_path(agent_path) == normalized {
                    return Some(hash.clone());
                }
            }

            None
        };

        let compute_disk_hash = |file_path: &Path| -> Option<String> {
            if !file_path.exists() {
                return None;
            }
            match std::fs::read(file_path) {
                Ok(contents) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&contents);
                    Some(hex::encode(hasher.finalize()))
                },
                Err(_) => None,
            }
        };

        for (manifest_path, registry_hash) in registry_files {
            if excluded_extensions
                .iter()
                .any(|ext| manifest_path.ends_with(ext))
            {
                excluded.push(manifest_path.clone());
                continue;
            }

            let registry_hash_clean = registry_hash
                .strip_prefix("sha256:")
                .unwrap_or(registry_hash);

            let disk_hash = agent_root.and_then(|root| {
                let file_path = Path::new(root).join(normalize_path(manifest_path));
                compute_disk_hash(&file_path)
            });

            let agent_hash = find_agent_hash(manifest_path);

            if agent_hash.is_some() {
                processed_agent_paths.insert(normalize_path(manifest_path));
            }

            match (disk_hash.as_ref(), agent_hash.as_ref()) {
                (Some(disk), Some(agent)) => {
                    let disk_matches_registry = disk == registry_hash_clean;
                    let agent_matches_registry = agent == registry_hash_clean;
                    let disk_matches_agent = disk == agent;

                    if disk_matches_registry && agent_matches_registry && disk_matches_agent {
                        cross_validated.push(manifest_path.clone());
                    } else if !disk_matches_agent {
                        disk_agent_mismatch.insert(
                            manifest_path.clone(),
                            DiskAgentMismatch {
                                disk_hash: disk.clone(),
                                agent_hash: agent.clone(),
                                registry_hash: registry_hash_clean.to_string(),
                                registry_match: if disk_matches_registry {
                                    "disk".to_string()
                                } else if agent_matches_registry {
                                    "agent".to_string()
                                } else {
                                    "neither".to_string()
                                },
                            },
                        );
                    } else if !disk_matches_registry {
                        registry_mismatch.insert(
                            manifest_path.clone(),
                            RegistryMismatch {
                                disk_hash: Some(disk.clone()),
                                agent_hash: Some(agent.clone()),
                                registry_hash: registry_hash_clean.to_string(),
                                source: "both".to_string(),
                            },
                        );
                    }
                },
                (Some(disk), None) => {
                    if disk == registry_hash_clean {
                        filesystem_verified.push(manifest_path.clone());
                    } else {
                        registry_mismatch.insert(
                            manifest_path.clone(),
                            RegistryMismatch {
                                disk_hash: Some(disk.clone()),
                                agent_hash: None,
                                registry_hash: registry_hash_clean.to_string(),
                                source: "disk".to_string(),
                            },
                        );
                    }
                },
                (None, Some(agent)) => {
                    if agent == registry_hash_clean {
                        agent_verified.push(manifest_path.clone());
                    } else {
                        registry_mismatch.insert(
                            manifest_path.clone(),
                            RegistryMismatch {
                                disk_hash: None,
                                agent_hash: Some(agent.clone()),
                                registry_hash: registry_hash_clean.to_string(),
                                source: "agent".to_string(),
                            },
                        );
                    }
                },
                (None, None) => {
                    missing.push(manifest_path.clone());
                },
            }
        }

        if let Some(agent_hashes) = agent_hashes {
            for agent_path in agent_hashes.keys() {
                let normalized = normalize_path(agent_path);
                if !processed_agent_paths.contains(&normalized) {
                    let in_manifest = registry_files.keys().any(|mp| {
                        normalize_path(mp) == normalized
                            || mp.ends_with(&format!("/{}", normalized))
                    });
                    if !in_manifest {
                        unexpected.push(agent_path.clone());
                    }
                }
            }
        }

        let verified_count =
            filesystem_verified.len() + agent_verified.len() + cross_validated.len();
        let failed_count = disk_agent_mismatch.len() + registry_mismatch.len();
        let valid = failed_count == 0 && missing.is_empty();

        let summary = ModuleIntegritySummary {
            total_manifest: registry_files.len(),
            verified: verified_count,
            failed: failed_count,
            missing: missing.len(),
            excluded: excluded.len(),
            cross_validated: cross_validated.len(),
        };

        info!(
            "run_module_integrity (pre-fetched): verified={}, failed={}, missing={}",
            verified_count,
            failed_count,
            missing.len()
        );

        let missing_count = missing.len();

        Ok(ModuleIntegrityResult {
            valid,
            manifest_file_count: registry_files.len(),
            filesystem_verified,
            agent_verified,
            cross_validated,
            disk_agent_mismatch,
            registry_mismatch,
            missing,
            unexpected,
            excluded,
            summary,
            manifest_version: Some(build.version.clone()),
            error: if valid {
                None
            } else {
                Some(format!(
                    "{} files failed, {} missing",
                    failed_count, missing_count
                ))
            },
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
