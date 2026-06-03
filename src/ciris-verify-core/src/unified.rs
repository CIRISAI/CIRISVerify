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
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

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

// =============================================================================
// MANIFEST CACHE — survives across FFI calls so intermittent network failures
// during periodic refresh don't cause L1/L2/L4 to fail and shut down the agent.
// =============================================================================

/// Cached manifests from a previous successful registry fetch.
struct ManifestCache {
    binary: Option<BinaryManifest>,
    function: Option<FunctionManifest>,
    build: Option<BuildRecord>,
    /// Baseline integrity snapshot from first successful attestation.
    /// Used to detect degradation: if a check was passing and now fails,
    /// something was tampered with (not a network issue).
    baseline: Option<IntegrityBaseline>,
}

/// Snapshot of integrity check results from first successful attestation.
#[derive(Debug, Clone)]
struct IntegrityBaseline {
    binary_valid: bool,
    functions_valid: bool,
    file_integrity_valid: bool,
    python_integrity_valid: bool,
}

/// Global manifest cache (populated on first successful fetch, used as fallback).
fn manifest_cache() -> &'static RwLock<ManifestCache> {
    static CACHE: OnceLock<RwLock<ManifestCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        RwLock::new(ManifestCache {
            binary: None,
            function: None,
            build: None,
            baseline: None,
        })
    })
}

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
    /// CIRIS primitive project under which the agent's build is registered.
    ///
    /// Independent of the engine's own configured project — the engine
    /// (typically `"ciris-verify"`) reads its own L1/L2 manifests under
    /// `engine.config.project`, and reads the agent's L4 build record
    /// under `agent_project`. v1.12.0 split (closes #10).
    ///
    /// Defaults to `"ciris-agent"` when None for backward compatibility
    /// with pre-v1.12.0 callers.
    #[serde(default)]
    pub agent_project: Option<String>,
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
    /// Platform OS (e.g., "macos", "ios", "android", "linux", "windows").
    #[serde(default)]
    pub platform_os: String,
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

// =============================================================================
// Strict time-budget hierarchy (v4.8.0, CIRISVerify#52)
// =============================================================================
//
// CIRISAgent's startup attestation budget is 15 seconds. Verify MUST
// return within that ceiling regardless of network conditions. The
// budget composes top-down — each inner layer's worst-case ≤ its
// outer layer's remaining budget:
//
//     ATTESTATION_TIMEOUT          (15s, HARD ceiling, outer wrapper)
//       ├─ NETWORK_PROBE_TIMEOUT   (2s, fast-fail probe before fan-out)
//       └─ run_attestation_inner   (≤ 13s after probe)
//            └─ PHASE 1: parallel manifest fetch + validation
//                 ├─ ResilientRegistryClient::RACE_BUDGET   (10s, per op)
//                 │    └─ per-endpoint connect_timeout      (≤ 3s)
//                 │    └─ per-endpoint total_timeout        (≤ 10s)
//                 │    └─ NotFound grace after first NF     (1s)
//                 └─ consensus_validator parallel join      (≤ 10s)
//            └─ PHASE 2: local verification (CPU-only, no budget)
//
// Composition check:
//   2s probe + max(10s manifest-race, 10s consensus) + ~1s tail
//     = 13s worst-case before outer 15s ceiling truncates → 2s slack.
//
// Heartbeat (`attest_heartbeat::HeartbeatGuard`) fires every 5s with
// elapsed_ms + current phase string so a hang is self-diagnosing in
// logcat / Console.app instead of producing 89.98s of silence (the
// S21U/Verizon scenario documented in #50/#52).

/// End-to-end timeout for attestation (15 seconds max).
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Network-unavailable fast-fail probe timeout (v4.7.0 / CIRISVerify#50).
///
/// Before launching the 5-call parallel manifest fetch, race a quick
/// DNS resolve + HTTPS HEAD against this 2s budget. If both fail,
/// short-circuit to a `network_unavailable` partial result without
/// committing to the full 10s-per-call fan-out. Closes the
/// CIRISAgent#843 budget-overshoot under CI parallel-load.
const NETWORK_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Network-unavailable fast-fail upper bound (v4.7.0).
///
/// Under any path, verify MUST return within this budget when the
/// network is unreachable. Composes with the 2s probe + a small
/// margin for the partial-result build.
const NETWORK_UNAVAILABLE_BUDGET: Duration = Duration::from_secs(10);

/// Single-endpoint reachability probe — platform-aware (v4.8.0, #52).
///
/// Desktop: uses the `http_client::ClientPurpose::Probe` factory
/// (2s connect + 2s total + tcp_keepalive + happy_eyeballs-when-
/// available). Mobile (Android/iOS): bypasses tokio's IO driver
/// via `mobile_http::check_status` on a `spawn_blocking` task so
/// JNI / iOS getaddrinfo quirks don't stall the probe.
///
/// Returns `true` if the endpoint answered at all within the probe
/// budget (any HTTP status — we just want signal that the network
/// path works). False on connect refused / timeout / DNS error.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn probe_single_endpoint(endpoint: String) -> bool {
    use crate::http_client::{build_async_http_client, ClientPurpose};
    let client = match build_async_http_client(ClientPurpose::Probe) {
        Ok(c) => c,
        Err(_) => return false,
    };
    matches!(
        tokio::time::timeout(NETWORK_PROBE_TIMEOUT, client.head(&endpoint).send()).await,
        Ok(Ok(_))
    )
}

#[cfg(any(target_os = "android", target_os = "ios"))]
async fn probe_single_endpoint(endpoint: String) -> bool {
    let result = tokio::time::timeout(
        NETWORK_PROBE_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            // mobile_http::check_status uses ureq's 3s timeout_connect
            // internally; that's clamped by the outer 2s probe budget.
            let agent = crate::mobile_http::create_tls_agent(NETWORK_PROBE_TIMEOUT).ok()?;
            crate::mobile_http::check_status(&agent, &endpoint).ok()
        }),
    )
    .await;
    matches!(result, Ok(Ok(Some(true))))
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

        // Use resilient client with fallback endpoints. Project is per-call
        // (v1.12.0+) — this single client serves both the engine's own
        // L1/L2 reads (config.project, typically "ciris-verify") AND the
        // agent's L4 build fetch (request.agent_project, typically
        // "ciris-agent"). See #10.
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

    /// Race a fast HEAD-probe across primary + all fallback registry
    /// endpoints within [`NETWORK_PROBE_TIMEOUT`]. Returns `true` if
    /// ANY endpoint responded within budget regardless of HTTP status.
    ///
    /// v4.8.0 — platform-aware AND multi-endpoint racing (#52):
    /// - Desktop: each probe uses [`crate::http_client::build_async_http_client`]
    ///   with `ClientPurpose::Probe` — connect_timeout + total_timeout +
    ///   tcp_keepalive + (happy_eyeballs when reqwest supports it).
    /// - Android/iOS: each probe goes through the blocking `mobile_http`
    ///   ureq agent on a `spawn_blocking` task — bypasses tokio IO
    ///   driver quirks under JNI / iOS getaddrinfo.
    ///
    /// Endpoints raced: primary `config.https_endpoint` plus every
    /// fallback in [`registry::FALLBACK_REGISTRY_URLS`]. So a single
    /// blackholed IP on primary doesn't falsely flag the entire
    /// network unavailable when us.* / eu.* are reachable.
    ///
    /// This is the "suspenders" half of the belt-and-suspenders budget
    /// model: probe fast-fails before the 5-call parallel manifest
    /// fan-out commits to its per-call 10s sub-budgets. The outer
    /// [`ATTESTATION_TIMEOUT`] hard ceiling is the belt.
    async fn probe_network_reachability(&self) -> bool {
        let targets: Vec<String> = if let Some(ref over) = self.config.probe_targets_override {
            over.clone()
        } else {
            let mut t: Vec<String> = vec![self.config.https_endpoint.clone()];
            for url in crate::registry::FALLBACK_REGISTRY_URLS {
                if *url != self.config.https_endpoint {
                    t.push((*url).to_string());
                }
            }
            t
        };

        let futures: Vec<_> = targets
            .into_iter()
            .map(|endpoint| Box::pin(probe_single_endpoint(endpoint)))
            .collect();

        // Race: first endpoint that responds (any HTTP status) wins.
        // Map Ok(true)→Ok(()), anything else→Err(()), then use the
        // parallel_race helper. If the budget expires with no Ok, the
        // empty/budget-exceeded sentinels both collapse to false.
        let race = crate::parallel_race::race_first_ok_within_budget::<_, (), ()>(
            futures
                .into_iter()
                .map(|f| async move {
                    if f.await {
                        Ok(())
                    } else {
                        Err(())
                    }
                })
                .collect(),
            NETWORK_PROBE_TIMEOUT,
            |_| (),
            || (),
        );

        race.await.is_ok()
    }

    /// Partial result emitted when the network-reachability probe
    /// short-circuits before the manifest fan-out (CIRISVerify#50).
    fn network_unavailable_result(&self, elapsed: Duration) -> FullAttestationResult {
        FullAttestationResult {
            valid: false,
            level: 0,
            level_pending: true,
            self_verification: None,
            key_attestation: None,
            registry_key_status: "network_unavailable".to_string(),
            device_attestation: None,
            file_integrity: None,
            python_integrity: None,
            module_integrity: None,
            sources: SourceCheckResult {
                dns_us_reachable: false,
                dns_us_valid: false,
                dns_us_error: Some("network_unavailable".to_string()),
                dns_eu_reachable: false,
                dns_eu_valid: false,
                dns_eu_error: Some("network_unavailable".to_string()),
                https_reachable: false,
                https_valid: false,
                https_error: Some("network_unavailable".to_string()),
                validation_status: "NetworkUnavailable".to_string(),
            },
            audit_trail: None,
            checks_passed: 0,
            checks_total: 0,
            diagnostics: format!(
                "Network unavailable - probe failed within {:?}",
                NETWORK_PROBE_TIMEOUT
            ),
            errors: vec![format!("Network unreachable (probe elapsed {:?})", elapsed)],
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Inner attestation logic (called with timeout wrapper).
    async fn run_attestation_inner(
        &self,
        request: FullAttestationRequest,
    ) -> Result<FullAttestationResult, VerifyError> {
        let start = std::time::Instant::now();

        // CIRISVerify#50: Network-unavailable fast-fail.
        //
        // Before committing to the 5-call manifest fan-out (each with
        // its own 10s sub-budget = ~10s wall-clock under failure),
        // race a 2s HEAD probe against the primary registry. If the
        // probe fails the inner returns immediately with a partial
        // `network_unavailable` result, keeping total wall-clock under
        // `NETWORK_UNAVAILABLE_BUDGET` instead of letting the outer
        // 15s ceiling truncate.
        //
        // Closes CIRISAgent#843 budget overshoot under CI parallel load.
        if !self.probe_network_reachability().await {
            let elapsed = start.elapsed();
            warn!(
                "VERIFY ATTESTATION FAST-FAIL: Network unreachable, partial result after {:?}",
                elapsed
            );
            debug_assert!(
                elapsed < NETWORK_UNAVAILABLE_BUDGET,
                "fast-fail exceeded NETWORK_UNAVAILABLE_BUDGET"
            );
            return Ok(self.network_unavailable_result(elapsed));
        }

        let mut errors = Vec::new();
        let mut checks_passed = 0u32;
        let mut checks_total = 0u32;
        let mut diagnostics = String::new();

        // CIRISVerify#52 v4.8.0: self-diagnosing heartbeat. Every 5s a
        // `warn!` line lands in tracing/logcat with elapsed_ms and the
        // current phase string. Dropped (and the background task
        // aborted) when this function returns. Without this, a long
        // hang produced zero log output until the outer 15s ceiling
        // truncated — see the S21U/Verizon 90s silence in #50.
        let hb = crate::attest_heartbeat::HeartbeatGuard::spawn("attestation");
        hb.set_phase("init");

        info!(
            "VERIFY ATTESTATION STARTING: Full attestation with {} checks",
            if request.skip_file_integrity {
                "network"
            } else {
                "network+integrity"
            }
        );

        // Prepare check params
        let should_run_file_integrity = !request.skip_file_integrity
            && request.agent_version.is_some()
            && request.agent_root.is_some();
        let should_run_module_integrity = request.agent_version.is_some();
        let verify_version = env!("CARGO_PKG_VERSION");
        let target = crate::registry::current_target();

        // Project routing (v1.12.0+, closes #10):
        // - L1/L2 self-attestation reads: engine's own configured project.
        // - L4 agent build record fetch: caller-supplied agent_project,
        //   defaulting to "ciris-agent" for backward compat.
        let engine_project = self.config.project.as_str();
        let agent_project: &str = request.agent_project.as_deref().unwrap_or("ciris-agent");

        // =======================================================================
        // PHASE 1: Fetch ALL manifests + run validations IN PARALLEL
        // Critical for mobile where each network call blocks the thread
        // =======================================================================
        hb.set_phase("phase 1/2: parallel manifest fetch + consensus validation");
        info!("VERIFY PHASE 1/2 STARTING: Parallel manifest fetch + validation (5 network calls)");

        let (
            binary_manifest_fresh,
            function_manifest_fresh,
            agent_build_fresh,
            validation,
            key_verification_result,
        ) = tokio::join!(
            // 1. Binary manifest (verify version) - for self-verification
            async {
                info!("VERIFY STEP 1/5 STARTING: Binary manifest fetch");
                if let Some(ref client) = self.registry_client {
                    match client
                        .get_binary_manifest(engine_project, verify_version)
                        .await
                    {
                        Ok(m) => {
                            info!(
                                "VERIFY STEP 1/5 COMPLETE: OK ({} targets)",
                                m.binaries.len()
                            );
                            Some(m)
                        },
                        Err(e) => {
                            warn!("VERIFY STEP 1/5 COMPLETE: FAILED ({})", e);
                            None
                        },
                    }
                } else {
                    info!("VERIFY STEP 1/5 COMPLETE: SKIP (no client)");
                    None
                }
            },
            // 2. Function manifest (verify version + target) - for self-verification
            async {
                info!("VERIFY STEP 2/5 STARTING: Function manifest fetch");
                if let Some(ref client) = self.registry_client {
                    match client
                        .get_function_manifest(engine_project, verify_version, target)
                        .await
                    {
                        Ok(m) => {
                            info!(
                                "VERIFY STEP 2/5 COMPLETE: OK ({} functions)",
                                m.functions.len()
                            );
                            Some(m)
                        },
                        Err(e) => {
                            warn!("VERIFY STEP 2/5 COMPLETE: FAILED ({})", e);
                            None
                        },
                    }
                } else {
                    info!("VERIFY STEP 2/5 COMPLETE: SKIP (no client)");
                    None
                }
            },
            // 3. Agent build record (agent version) - for file/module/python integrity.
            // CRITICAL: queries under `agent_project` (foreign project), NOT
            // engine_project (self project). Reusing the engine's own project
            // here is the v1.11.x bug closed by #10 in v1.12.0.
            async {
                info!(
                    "VERIFY STEP 3/5 STARTING: Agent build record fetch (project={})",
                    agent_project
                );
                if let Some(ref version) = request.agent_version {
                    if let Some(ref client) = self.registry_client {
                        match client.get_build_by_version(agent_project, version).await {
                            Ok(b) => {
                                info!(
                                    "VERIFY STEP 3/5 COMPLETE: OK ({} files)",
                                    b.file_manifest_json.files().len()
                                );
                                Some(b)
                            },
                            Err(e) => {
                                warn!("VERIFY STEP 3/5 COMPLETE: FAILED ({})", e);
                                None
                            },
                        }
                    } else {
                        info!("VERIFY STEP 3/5 COMPLETE: SKIP (no client)");
                        None
                    }
                } else {
                    info!("VERIFY STEP 3/5 COMPLETE: SKIP (no agent_version)");
                    None
                }
            },
            // 4. Source validation (DNS + HTTPS consensus)
            async {
                info!("VERIFY STEP 4/5 STARTING: Source validation (DNS US + EU + HTTPS)");
                let result = self.consensus_validator.validate_steward_key().await;
                let sources_ok = u8::from(result.source_details.dns_us_reachable)
                    + u8::from(result.source_details.dns_eu_reachable)
                    + u8::from(result.source_details.https_reachable);
                info!(
                    "VERIFY STEP 4/5 COMPLETE: {}/3 sources reachable",
                    sources_ok
                );
                result
            },
            // 5. Registry key verification
            async {
                info!("VERIFY STEP 5/5 STARTING: Registry key verification");
                if let Some(ref fingerprint) = request.key_fingerprint {
                    if let Some(ref client) = self.registry_client {
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
                                info!("VERIFY STEP 5/5 COMPLETE: {}", status);
                                status
                            },
                            Err(e) => {
                                warn!("VERIFY STEP 5/5 COMPLETE: FAILED ({})", e);
                                format!("error:{}", e)
                            },
                        }
                    } else {
                        info!("VERIFY STEP 5/5 COMPLETE: SKIP (no client)");
                        "error:no_client".to_string()
                    }
                } else {
                    info!("VERIFY STEP 5/5 COMPLETE: SKIP (no fingerprint)");
                    "not_checked".to_string()
                }
            }
        );

        info!("VERIFY PHASE 1/2 COMPLETE: All network fetches done");

        // =======================================================================
        // MANIFEST CACHE: Store fresh fetches, fall back to cache on failure.
        // This prevents intermittent network issues during periodic refresh
        // from causing L1/L2/L4 degradation and agent shutdown.
        // =======================================================================
        let (binary_manifest_result, function_manifest_result, agent_build_result) = {
            let mut cache = manifest_cache().write().await;

            // Update cache with any fresh results
            if let Some(ref m) = binary_manifest_fresh {
                cache.binary = Some(m.clone());
            }
            if let Some(ref m) = function_manifest_fresh {
                cache.function = Some(m.clone());
            }
            if let Some(ref b) = agent_build_fresh {
                cache.build = Some(b.clone());
            }

            // Use fresh if available, otherwise fall back to cached
            let binary = binary_manifest_fresh.or_else(|| {
                if let Some(ref cached) = cache.binary {
                    warn!(
                        "VERIFY MANIFEST_CACHE FALLBACK: Using cached binary manifest \
                         (version={}, generated_at={}) — registry unreachable",
                        cached.version, cached.generated_at
                    );
                    Some(cached.clone())
                } else {
                    error!(
                        "VERIFY MANIFEST_CACHE MISS: No cached binary manifest available \
                         and registry unreachable — L1 binary check will be skipped"
                    );
                    None
                }
            });
            let function = function_manifest_fresh.or_else(|| {
                if let Some(ref cached) = cache.function {
                    warn!(
                        "VERIFY MANIFEST_CACHE FALLBACK: Using cached function manifest \
                         (version={}, target={}) — registry unreachable",
                        cached.binary_version, cached.target
                    );
                    Some(cached.clone())
                } else {
                    error!(
                        "VERIFY MANIFEST_CACHE MISS: No cached function manifest available \
                         and registry unreachable — L1 function check will be skipped"
                    );
                    None
                }
            });
            let build = agent_build_fresh.or_else(|| {
                if let Some(ref cached) = cache.build {
                    warn!(
                        "VERIFY MANIFEST_CACHE FALLBACK: Using cached build record \
                         (version={}, {} files) — registry unreachable",
                        cached.version,
                        cached.file_manifest_json.files().len()
                    );
                    Some(cached.clone())
                } else {
                    error!(
                        "VERIFY MANIFEST_CACHE MISS: No cached build record available \
                         and registry unreachable — L4 file integrity will be skipped"
                    );
                    None
                }
            });

            (binary, function, build)
        };

        hb.set_phase("phase 2/2: local verification (integrity + binary self-check)");
        info!("VERIFY PHASE 2/2 STARTING: Local verification (6 checks)");

        // =======================================================================
        // PHASE 2: Run verification logic using pre-fetched manifests (NO network)
        // =======================================================================

        // Self-verification using pre-fetched binary + function manifests
        info!("VERIFY STEP 1/6 STARTING: Self-verification (binary + functions)");
        let self_verification = self
            .run_self_verification_with_manifests(
                binary_manifest_result.as_ref(),
                function_manifest_result.as_ref(),
            )
            .await;
        info!(
            "VERIFY STEP 1/6 COMPLETE: {} (binary={}, functions={}/{})",
            if self_verification.valid {
                "OK"
            } else {
                "FAILED"
            },
            if self_verification.binary_valid {
                "✓"
            } else {
                "✗"
            },
            self_verification.functions_passed,
            self_verification.functions_checked
        );

        // File integrity using pre-fetched agent build
        info!("VERIFY STEP 2/6 STARTING: File integrity check");
        let file_integrity_result = if should_run_file_integrity {
            let agent_root = request.agent_root.as_ref().unwrap();
            let result = self
                .run_file_integrity_with_build(
                    agent_build_result.as_ref(),
                    agent_root,
                    request.spot_check_count,
                    request.partial_file_check,
                )
                .await;
            match &result {
                Ok(r) => {
                    let valid = r.full.as_ref().map(|f| f.valid).unwrap_or(false);
                    let unexpected_count = r
                        .full
                        .as_ref()
                        .map(|f| f.unexpected_files.len())
                        .unwrap_or(0);
                    if unexpected_count > 0 {
                        warn!(
                            "VERIFY STEP 2/6 COMPLETE: FAILED (passed={}/{}, unexpected={})",
                            r.full.as_ref().map(|f| f.files_passed).unwrap_or(0),
                            r.full.as_ref().map(|f| f.total_files).unwrap_or(0),
                            unexpected_count
                        );
                    } else {
                        info!(
                            "VERIFY STEP 2/6 COMPLETE: {} (full={})",
                            if valid { "OK" } else { "FAILED" },
                            r.full
                                .as_ref()
                                .map(|f| format!("{}/{}", f.files_passed, f.total_files))
                                .unwrap_or_else(|| "n/a".to_string())
                        );
                    }
                },
                Err(e) => warn!("VERIFY STEP 2/6 COMPLETE: FAILED ({})", e),
            }
            Some(result)
        } else {
            info!("VERIFY STEP 2/6 COMPLETE: SKIP (disabled or no root)");
            None
        };

        // Module integrity using pre-fetched agent build
        info!("VERIFY STEP 3/6 STARTING: Module integrity check");
        let module_integrity_result = if should_run_module_integrity {
            let agent_hashes = request.python_hashes.as_ref().map(|h| &h.module_hashes);
            let result = self
                .run_module_integrity_with_build(
                    agent_build_result.as_ref(),
                    request.agent_root.as_deref(),
                    agent_hashes,
                    &[],
                )
                .await;
            match &result {
                Ok(r) => info!(
                    "VERIFY STEP 3/6 COMPLETE: {} ({}/{} verified)",
                    if r.valid { "OK" } else { "FAILED" },
                    r.summary.verified,
                    r.manifest_file_count
                ),
                Err(e) => warn!("VERIFY STEP 3/6 COMPLETE: FAILED ({})", e),
            }
            Some(result)
        } else {
            info!("VERIFY STEP 3/6 COMPLETE: SKIP (no agent_version)");
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
        info!("VERIFY STEP 4/6 STARTING: Source validation analysis");
        checks_total += 3; // DNS US, DNS EU, HTTPS
        let sources = SourceCheckResult::from(&validation);
        let sources_valid_count = u8::from(sources.dns_us_valid)
            + u8::from(sources.dns_eu_valid)
            + u8::from(sources.https_valid);
        info!(
            "VERIFY STEP 4/6 COMPLETE: {}/3 sources valid (status={})",
            sources_valid_count, sources.validation_status
        );

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
        // NOTE: When module_integrity is also run, we don't count file_integrity
        // toward checks_total/checks_passed because module_integrity supersedes it.
        // We still run file_integrity for diagnostics and backwards compatibility.
        let count_file_integrity = should_run_file_integrity && !should_run_module_integrity;
        let file_integrity = if should_run_file_integrity {
            if count_file_integrity {
                checks_total += 1; // Full check
                if request.spot_check_count > 0 {
                    checks_total += 1; // Spot check
                }
            }

            diagnostics.push_str("=== FILE INTEGRITY ===\n");
            match file_integrity_result.unwrap() {
                Ok(result) => {
                    if count_file_integrity {
                        if result.full.as_ref().map(|f| f.valid).unwrap_or(false) {
                            checks_passed += 1;
                        }
                        if result.spot.as_ref().map(|s| s.valid).unwrap_or(false) {
                            checks_passed += 1;
                        }
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
                        // List unexpected files (files on disk but not in manifest)
                        if !full.unexpected_files.is_empty() {
                            diagnostics.push_str(&format!(
                                "    └─ Unexpected files ({}):\n",
                                full.unexpected_files.len()
                            ));
                            // Show first 20 files, then summary
                            for (i, path) in full.unexpected_files.iter().enumerate() {
                                if i < 20 {
                                    diagnostics.push_str(&format!("       • {}\n", path));
                                } else if i == 20 {
                                    diagnostics.push_str(&format!(
                                        "       ... and {} more (see unexpected_files in JSON response)\n",
                                        full.unexpected_files.len() - 20
                                    ));
                                    break;
                                }
                            }
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
        // NOTE: When module_integrity is also run, we don't count python_integrity
        // toward checks_total/checks_passed because module_integrity supersedes it.
        // We still run python_integrity for diagnostics and backwards compatibility.
        info!("VERIFY STEP 5/6 STARTING: Python module integrity");

        // If the caller didn't supply python_hashes (no JSON producer on this
        // platform — e.g. desktop, server) but did supply agent_root, walk the
        // tree ourselves. Algorithm parity with mobile_main.py and
        // tools/dev/regenerate_python_hashes.py — see #12.
        let synthesized_python_hashes: Option<PythonModuleHashes> = if request
            .python_hashes
            .is_none()
        {
            request.agent_root.as_deref().and_then(|root| {
                    match synthesize_python_hashes_from_disk(
                        root,
                        request.agent_version.as_deref().unwrap_or(""),
                    ) {
                        Ok(h) if h.module_count > 0 => Some(h),
                        Ok(_) => {
                            warn!("Python tree-walk produced 0 modules under {} (expected ciris_engine/ and/or ciris_adapters/ packages)", root);
                            None
                        },
                        Err(e) => {
                            warn!("Python tree-walk of {} failed: {}", root, e);
                            None
                        },
                    }
                })
        } else {
            None
        };

        let python_hashes_source: &'static str = if request.python_hashes.is_some() {
            "agent-supplied"
        } else if synthesized_python_hashes.is_some() {
            "synthesized from agent_root"
        } else {
            "none"
        };

        let active_python_hashes: Option<&PythonModuleHashes> = request
            .python_hashes
            .as_ref()
            .or(synthesized_python_hashes.as_ref());

        let count_python_integrity = active_python_hashes.is_some() && !should_run_module_integrity;

        let python_integrity = if let Some(hashes) = active_python_hashes {
            if count_python_integrity {
                checks_total += 1;
            }

            diagnostics.push_str("=== PYTHON INTEGRITY ===\n");
            diagnostics.push_str(&format!("  Hashes source: {}\n", python_hashes_source));
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

            if count_python_integrity && valid {
                checks_passed += 1;
            }
            if !valid {
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

            let result = PythonIntegrityResult {
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
            };
            info!(
                "VERIFY STEP 5/6 COMPLETE: {} ({}/{} modules passed)",
                if result.valid { "OK" } else { "FAILED" },
                result.modules_passed,
                result.modules_checked
            );
            Some(result)
        } else {
            let skip_reason = if request.agent_root.is_none() {
                "no python_hashes and no agent_root"
            } else {
                "tree-walk found no python modules under agent_root"
            };
            diagnostics.push_str(&format!(
                "=== PYTHON INTEGRITY ===\n  SKIP ({})\n\n",
                skip_reason
            ));
            info!("VERIFY STEP 5/6 COMPLETE: SKIP ({})", skip_reason);
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
        info!("VERIFY STEP 6/6 STARTING: Audit trail verification");
        let audit_trail = if !request.skip_audit {
            if let Some(ref entries) = request.audit_entries {
                checks_total += 1;

                let verifier = AuditVerifier::new(request.portal_key_id.clone());
                let result = verifier.verify_entries(entries, true);

                if result.valid {
                    checks_passed += 1;
                }
                info!(
                    "VERIFY STEP 6/6 COMPLETE: {} ({} entries, chain={})",
                    if result.valid { "OK" } else { "FAILED" },
                    result.total_entries,
                    if result.hash_chain_valid {
                        "valid"
                    } else {
                        "broken"
                    }
                );

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
                info!("VERIFY STEP 6/6 COMPLETE: SKIP (no entries provided)");
                None
            }
        } else {
            diagnostics.push_str("=== AUDIT TRAIL ===\n  SKIP (disabled)\n\n");
            info!("VERIFY STEP 6/6 COMPLETE: SKIP (disabled)");
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
        // Use module_integrity (unified) which properly handles server-only files.
        // Falls back to legacy file_integrity if module_integrity not available.
        let module_integrity_valid = module_integrity
            .as_ref()
            .map(|mi| mi.valid)
            .unwrap_or(false);
        let legacy_file_integrity_valid = file_integrity
            .as_ref()
            .map(|fi| fi.full.as_ref().map(|f| f.valid).unwrap_or(false))
            .unwrap_or(false);
        // Prefer module_integrity (handles server-only exclusions), fall back to legacy.
        // When module_integrity is available, it replaces BOTH file_integrity AND python_integrity
        // because it already cross-validates agent Python files against disk and registry.
        let l4_pass = if module_integrity.is_some() {
            // Unified check: module_integrity covers everything
            l3_pass && module_integrity_valid
        } else {
            // Legacy fallback: require both file_integrity AND python_integrity
            let python_valid = python_integrity
                .as_ref()
                .map(|pi| pi.valid)
                .unwrap_or(false);
            l3_pass && legacy_file_integrity_valid && python_valid
        };
        // L5: Audit trail (MUST be checked and valid) + registry key (must be active)
        let audit_valid = audit_trail.as_ref().map(|a| a.valid).unwrap_or(false);
        let key_active = key_verification_result == "active";
        info!(
            "L5 calculation: l4_pass={}, audit_valid={}, audit_present={}, key_status='{}', key_active={}",
            l4_pass, audit_valid, audit_trail.is_some(), key_verification_result, key_active
        );
        let l5_pass = l4_pass && audit_valid && key_active;

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

        info!("VERIFY PHASE 2/2 COMPLETE: All local checks done");

        // =======================================================================
        // DEGRADATION DETECTION: Compare current results against startup baseline.
        // Only flags LOCAL integrity changes (binary tampered, HSM tampered,
        // agent files modified). Network fields are intentionally ignored.
        // =======================================================================
        // Prefer module_integrity (handles server-only exclusions properly)
        let file_integrity_valid = module_integrity
            .as_ref()
            .map(|mi| mi.valid)
            .or_else(|| {
                file_integrity
                    .as_ref()
                    .map(|fi| fi.full.as_ref().map(|f| f.valid).unwrap_or(false))
            })
            .unwrap_or(true); // true if not checked (no degradation)
        let python_integrity_valid = python_integrity.as_ref().map(|pi| pi.valid).unwrap_or(true); // true if not checked

        let current = IntegrityBaseline {
            binary_valid: self_verification.binary_valid,
            functions_valid: self_verification.functions_valid,
            file_integrity_valid,
            python_integrity_valid,
        };

        {
            let mut cache = manifest_cache().write().await;
            if let Some(ref baseline) = cache.baseline {
                // Compare against baseline — only flag if something was passing and now fails
                if baseline.binary_valid && !current.binary_valid {
                    error!(
                        "VERIFY DEGRADATION DETECTED: binary_valid was PASSING at startup, \
                         now FAILING — CIRISVerify binary may have been tampered with"
                    );
                }
                if baseline.functions_valid && !current.functions_valid {
                    error!(
                        "VERIFY DEGRADATION DETECTED: functions_valid was PASSING at startup, \
                         now FAILING — CIRISVerify FFI functions may have been tampered with"
                    );
                }
                if baseline.file_integrity_valid && !current.file_integrity_valid {
                    error!(
                        "VERIFY DEGRADATION DETECTED: file_integrity was PASSING at startup, \
                         now FAILING — agent Python files may have been modified"
                    );
                }
                if baseline.python_integrity_valid && !current.python_integrity_valid {
                    error!(
                        "VERIFY DEGRADATION DETECTED: python_integrity was PASSING at startup, \
                         now FAILING — agent Python modules may have been modified"
                    );
                }
            } else {
                // First attestation — store as baseline
                info!(
                    "VERIFY BASELINE SET: binary={}, functions={}, file_integrity={}, python={}",
                    current.binary_valid,
                    current.functions_valid,
                    current.file_integrity_valid,
                    current.python_integrity_valid,
                );
                cache.baseline = Some(current);
            }
        }

        info!(
            "VERIFY ATTESTATION COMPLETE: level={}, valid={}, checks={}/{}, time={}ms",
            level,
            valid,
            checks_passed,
            checks_total,
            start.elapsed().as_millis()
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
        // Missing files (server-only, not bundled in mobile) do NOT fail integrity.
        // Only actual hash mismatches (failed_count > 0) indicate tampering.
        let valid = failed_count == 0;

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
                Some(format!("{} files failed integrity check", failed_count))
            },
        })
    }
}

/// Walk `{agent_root}/{ciris_engine,ciris_adapters}` and produce a
/// `PythonModuleHashes` byte-for-byte equivalent to what mobile_main.py and
/// tools/dev/regenerate_python_hashes.py emit. Used as a fallback at Step 5/6
/// when the caller didn't pass `python_hashes` (no platform JSON producer)
/// but did pass `agent_root` — see CIRISVerify#12.
///
/// Algorithm:
///   for package in ["ciris_engine", "ciris_adapters"]:
///       for py_file in rglob "{agent_root}/{package}/**/*.py":
///           rel = py_file relative to agent_root, '/'-normalized
///           module_hashes[rel] = sha256(file_bytes).hex()
///   total_hash = sha256("\n".join(sorted("{rel}:{hash}" for rel, hash in module_hashes))).hex()
fn synthesize_python_hashes_from_disk(
    agent_root: &str,
    agent_version: &str,
) -> Result<PythonModuleHashes, std::io::Error> {
    use sha2::{Digest, Sha256};

    const PACKAGES: &[&str] = &["ciris_engine", "ciris_adapters"];

    let root = Path::new(agent_root);
    let mut module_hashes: BTreeMap<String, String> = BTreeMap::new();
    let mut all_hashes: Vec<String> = Vec::new();

    for package in PACKAGES {
        let package_path = root.join(package);
        if !package_path.is_dir() {
            // Mirrors mobile producer: missing optional package isn't fatal.
            continue;
        }
        walk_py_files(&package_path, root, &mut |rel_str: String, bytes: &[u8]| {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let file_hash = hex::encode(hasher.finalize());
            all_hashes.push(format!("{}:{}", rel_str, file_hash));
            module_hashes.insert(rel_str, file_hash);
        })?;
    }

    all_hashes.sort();
    let combined = all_hashes.join("\n");
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let total_hash = hex::encode(hasher.finalize());

    let module_count = module_hashes.len();
    let computed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(PythonModuleHashes {
        total_hash,
        module_hashes,
        module_count,
        agent_version: agent_version.to_string(),
        computed_at,
    })
}

fn walk_py_files(
    dir: &Path,
    root: &Path,
    visit: &mut dyn FnMut(String, &[u8]),
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            walk_py_files(&path, root, visit)?;
        } else if file_type.is_file() && path.extension().and_then(|e| e.to_str()) == Some("py") {
            let rel = path.strip_prefix(root).map_err(|_| {
                std::io::Error::other(format!(
                    "path {} not under root {}",
                    path.display(),
                    root.display()
                ))
            })?;
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("/");
            let bytes = std::fs::read(&path)?;
            visit(rel_str, &bytes);
        }
    }
    Ok(())
}

// =============================================================================
// FullAttestationResult → FederationProvenance (#33)
// =============================================================================

impl FullAttestationResult {
    /// Compose the existing per-measurement verification subresults
    /// into the scalar-attestation surface (`federation_provenance`,
    /// CIRISVerify#33). Per `MISSION.md` §1.4 verify *carries* the
    /// attestation list; the consumer composes a verdict.
    ///
    /// Emits one [`crate::federation_provenance::AttestationEntry`] per
    /// dimension the underlying check actually ran (an `Option::None`
    /// field is "not checked" — not implicitly passing). The dimensions
    /// follow FSD-002 §3.2: `attestation:self_verify` /
    /// `attestation:hardware_rooted` / `attestation:registry_consensus` /
    /// `attestation:license_validity` / `attestation:agent_integrity`,
    /// plus `hardware_custody:{platform}` and
    /// `transparency_log:inclusion`. v3.7.0+ dropped the L1/L2/L3/L4/L5
    /// numbering prefixes — that ladder is consumer policy, not
    /// verify-side framing.
    ///
    /// `attester` is the entity that performed the attestation — for
    /// verify-internal checks pass `"ciris-verify"`; for delegated
    /// checks pass the relevant `key_id` / steward id.
    #[must_use]
    pub fn to_federation_provenance(
        &self,
        attester: &str,
    ) -> crate::federation_provenance::FederationProvenance {
        use crate::federation_provenance::{dim, AttestationEntry, FederationProvenance, Score};

        let mut b = FederationProvenance::builder();

        // L1 — self-verification ("who watches the watchmen").
        if let Some(sv) = &self.self_verification {
            b = b.attestation(AttestationEntry::new(
                dim::SELF_VERIFY,
                if sv.valid { Score::PASS } else { Score::FAIL },
                attester,
            ));
        }

        // L2 — hardware attestation. The combined check requires the
        // hybrid signature over the challenge AND, if device-level
        // attestation (Play Integrity / App Attest) was also run, that
        // it verified.
        if let Some(ka) = &self.key_attestation {
            let l2_ok = ka.has_valid_signature
                && self.device_attestation.as_ref().is_none_or(|d| d.verified);
            b = b.attestation(AttestationEntry::new(
                dim::HARDWARE,
                if l2_ok { Score::PASS } else { Score::FAIL },
                attester,
            ));

            // hardware_custody:{platform} — declares where the seed
            // lives. The platform string is the lowercased
            // hardware_type; `software_fallback` is the one variant
            // that structurally caps at UNLICENSED_COMMUNITY.
            if !ka.hardware_type.is_empty() {
                let platform = ka.hardware_type.to_ascii_lowercase();
                let valid = !platform.contains("software");
                b = b.attestation(AttestationEntry::new(
                    dim::hardware_custody(&platform),
                    if valid { Score::PASS } else { Score::FAIL },
                    attester,
                ));
            }
        }

        // L3 — registry consensus. 2-of-3 is the canonical bar.
        let valid_sources = u8::from(self.sources.dns_us_valid)
            + u8::from(self.sources.dns_eu_valid)
            + u8::from(self.sources.https_valid);
        b = b.attestation(AttestationEntry::new(
            dim::REGISTRY_CONSENSUS,
            if valid_sources >= 2 {
                Score::PASS
            } else {
                Score::FAIL
            },
            attester,
        ));

        // L5 — agent integrity. Driven by the unified `module_integrity`
        // result. (Legacy `file_integrity` / `python_integrity` paths
        // pre-date the unified result; callers still on those won't
        // emit an L5 entry through this conversion until they migrate
        // — which v1.7.0+ consumers already have.)
        if let Some(mi) = &self.module_integrity {
            b = b.attestation(AttestationEntry::new(
                dim::AGENT_INTEGRITY,
                if mi.valid { Score::PASS } else { Score::FAIL },
                attester,
            ));
        }

        // Transparency-log inclusion — the audit-trail proof verifies.
        if let Some(audit) = &self.audit_trail {
            b = b.attestation(AttestationEntry::new(
                dim::TRANSPARENCY_LOG_INCLUSION,
                if audit.valid {
                    Score::PASS
                } else {
                    Score::FAIL
                },
                attester,
            ));
        }

        b.build()
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

    /// Algorithm parity check: synthesize_python_hashes_from_disk must produce
    /// the same module_hashes / total_hash that mobile_main.py:_save_hashes_to_file
    /// and tools/dev/regenerate_python_hashes.py emit for the same source tree.
    /// Reference algorithm:
    ///   for package in ["ciris_engine", "ciris_adapters"]:
    ///     for py_file in (root/package).rglob("*.py"):
    ///       rel = py_file.relative_to(root).replace("\\", "/")
    ///       module_hashes[rel] = sha256(file.read()).hexdigest()
    ///   total_hash = sha256("\n".join(sorted(f"{rel}:{h}" for rel,h in items))).hexdigest()
    #[test]
    fn synthesized_python_hashes_match_canonical_algorithm() {
        use sha2::{Digest, Sha256};
        use std::fs;

        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();

        let files: &[(&str, &[u8])] = &[
            ("ciris_engine/__init__.py", b"# engine init\n"),
            ("ciris_engine/core.py", b"def core():\n    return 42\n"),
            (
                "ciris_engine/logic/services.py",
                b"# nested module\nclass S: pass\n",
            ),
            ("ciris_adapters/__init__.py", b""),
            ("ciris_adapters/api.py", b"# adapter\n"),
            // Non-package files MUST be ignored (parity with mobile producer).
            ("README.md", b"# noise\n"),
            ("ciris_engine/notes.txt", b"text noise\n"),
            ("other_package/foo.py", b"# wrong package, ignore\n"),
        ];

        for (rel, contents) in files {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
        }

        let result = synthesize_python_hashes_from_disk(root.to_str().unwrap(), "test-1.2.3")
            .expect("synthesize ok");

        // Reference computation: only files under PACKAGES that end in .py.
        let mut expected_module_hashes: BTreeMap<String, String> = BTreeMap::new();
        let mut expected_all: Vec<String> = Vec::new();
        for (rel, contents) in files {
            let parts: Vec<&str> = rel.splitn(2, '/').collect();
            if parts.len() != 2 {
                continue;
            }
            let pkg = parts[0];
            if pkg != "ciris_engine" && pkg != "ciris_adapters" {
                continue;
            }
            if !rel.ends_with(".py") {
                continue;
            }
            let mut hasher = Sha256::new();
            hasher.update(contents);
            let h = hex::encode(hasher.finalize());
            expected_all.push(format!("{}:{}", rel, h));
            expected_module_hashes.insert(rel.to_string(), h);
        }
        expected_all.sort();
        let mut hasher = Sha256::new();
        hasher.update(expected_all.join("\n").as_bytes());
        let expected_total = hex::encode(hasher.finalize());

        assert_eq!(result.module_count, 5, "must hash 5 .py files in PACKAGES");
        assert_eq!(result.module_hashes.len(), 5);
        assert_eq!(result.module_hashes, expected_module_hashes);
        assert_eq!(
            result.total_hash, expected_total,
            "total_hash must match canonical algorithm byte-for-byte"
        );
        assert_eq!(result.agent_version, "test-1.2.3");
        assert!(result.computed_at > 0);

        // Non-package and non-.py files must be excluded.
        assert!(!result.module_hashes.contains_key("README.md"));
        assert!(!result.module_hashes.contains_key("ciris_engine/notes.txt"));
        assert!(!result.module_hashes.contains_key("other_package/foo.py"));
    }

    #[test]
    fn synthesize_returns_zero_modules_when_packages_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        // No ciris_engine/ or ciris_adapters/ directories at all.
        std::fs::write(root.join("README.md"), b"# nothing here\n").unwrap();

        let result = synthesize_python_hashes_from_disk(root.to_str().unwrap(), "v0")
            .expect("synthesize ok");

        assert_eq!(result.module_count, 0);
        assert!(result.module_hashes.is_empty());
        // Empty input → sha256("") → known constant.
        assert_eq!(
            result.total_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Cross-language parity: against a real CIRISAgent source tree, our synthesizer
    /// must produce the same total_hash and module count as the canonical Python
    /// producer (tools/dev/regenerate_python_hashes.py / mobile_main.py).
    ///
    /// Ignored by default (requires CIRISAgent checkout + python-precomputed JSON).
    /// Run with: `cargo test -p ciris-verify-core --lib unified::tests::cross_language_parity_against_real_agent_tree -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn cross_language_parity_against_real_agent_tree() {
        let agent_root = "/home/emoore/CIRISAgent";
        let json_path = "/home/emoore/CIRISAgent/startup_python_hashes.json";

        if !Path::new(agent_root).exists() || !Path::new(json_path).exists() {
            eprintln!("SKIP: requires {} and {}", agent_root, json_path);
            return;
        }

        let py_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(json_path).expect("read python json"))
                .expect("parse python json");
        let py_total = py_json["total_hash"].as_str().expect("python total_hash");
        let py_count = py_json["modules_hashed"]
            .as_u64()
            .expect("python modules_hashed") as usize;
        let py_modules = py_json["module_hashes"]
            .as_object()
            .expect("python module_hashes");

        let rust = synthesize_python_hashes_from_disk(agent_root, "parity-test")
            .expect("rust synthesize ok");

        eprintln!("python: total={} modules={}", py_total, py_count);
        eprintln!(
            "rust:   total={} modules={}",
            rust.total_hash, rust.module_count
        );

        assert_eq!(rust.module_count, py_count, "module count mismatch");
        assert_eq!(rust.total_hash, py_total, "total_hash mismatch");
        assert_eq!(rust.module_hashes.len(), py_modules.len());
        for (k, v) in py_modules {
            let py_hash = v.as_str().unwrap();
            let rust_hash = rust
                .module_hashes
                .get(k)
                .unwrap_or_else(|| panic!("rust missing module {}", k));
            assert_eq!(rust_hash, py_hash, "hash mismatch for {}", k);
        }
    }

    #[test]
    fn synthesize_handles_only_one_package() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let pkg = root.join("ciris_engine");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("a.py"), b"x = 1\n").unwrap();

        let result = synthesize_python_hashes_from_disk(root.to_str().unwrap(), "v1")
            .expect("synthesize ok");

        assert_eq!(result.module_count, 1);
        let mut hasher = Sha256::new();
        hasher.update(b"x = 1\n");
        let file_hash = hex::encode(hasher.finalize());
        assert_eq!(
            result.module_hashes.get("ciris_engine/a.py"),
            Some(&file_hash)
        );

        let mut th = Sha256::new();
        th.update(format!("ciris_engine/a.py:{}", file_hash).as_bytes());
        assert_eq!(result.total_hash, hex::encode(th.finalize()));
    }

    /// CIRISVerify#50/#52 v4.8.0: Probe must fast-fail on a refused
    /// connection so `run_attestation` returns well under
    /// `NETWORK_UNAVAILABLE_BUDGET` instead of waiting for the outer
    /// 15s ceiling. v4.8.0 uses `probe_targets_override` so the
    /// FALLBACK_REGISTRY_URLS don't accidentally make the probe
    /// pass via real internet endpoints in CI.
    #[tokio::test]
    async fn probe_returns_false_on_refused_connection_within_budget() {
        let config = VerifyConfig {
            // All targets unreachable - kernel returns ECONNREFUSED immediately.
            probe_targets_override: Some(vec!["http://127.0.0.1:1/".to_string()]),
            ..VerifyConfig::default()
        };
        let engine = UnifiedAttestationEngine::new(config).expect("engine ok");

        let start = std::time::Instant::now();
        let reachable = engine.probe_network_reachability().await;
        let elapsed = start.elapsed();

        assert!(!reachable, "loopback:1 must not be reachable");
        assert!(
            elapsed < NETWORK_PROBE_TIMEOUT + Duration::from_millis(500),
            "fast-fail must be near-instant on ECONNREFUSED, got {:?}",
            elapsed
        );
    }

    /// CIRISVerify#50/#52 v4.8.0: Probe must time out (not hang) when
    /// an endpoint silently drops packets - bounded by
    /// `NETWORK_PROBE_TIMEOUT`.
    #[tokio::test]
    async fn probe_returns_false_within_budget_on_blackhole() {
        let config = VerifyConfig {
            // TEST-NET-1 (RFC 5737) - never routes anywhere.
            probe_targets_override: Some(vec!["http://192.0.2.1/".to_string()]),
            ..VerifyConfig::default()
        };
        let engine = UnifiedAttestationEngine::new(config).expect("engine ok");

        let start = std::time::Instant::now();
        let reachable = engine.probe_network_reachability().await;
        let elapsed = start.elapsed();

        assert!(!reachable, "TEST-NET-1 must not be reachable");
        // Allow a small grace window above the probe budget for tokio
        // scheduler overhead under CI parallel load.
        assert!(
            elapsed < NETWORK_PROBE_TIMEOUT + Duration::from_secs(1),
            "probe must time-bound at NETWORK_PROBE_TIMEOUT, got {:?}",
            elapsed
        );
    }

    /// CIRISVerify#52 v4.8.0: When one target blackholes but another
    /// is reachable on loopback, the probe must return `true` well
    /// under the probe budget (parallel race wins on first success).
    /// This is the structural fix for the S21U/Verizon scenario where
    /// `api.registry.*`'s Vultr IP blackholes but us.* / eu.* are
    /// reachable.
    #[tokio::test]
    async fn probe_returns_true_when_one_of_many_targets_is_reachable() {
        use tokio::net::TcpListener;
        // Stand up a loopback listener (will refuse-but-respond to HEAD).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // One accept is enough — once the connection is opened the HEAD
        // probe sees it as "reachable" regardless of HTTP-level outcome.
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let config = VerifyConfig {
            probe_targets_override: Some(vec![
                "http://192.0.2.1/".to_string(),     // blackhole
                format!("http://127.0.0.1:{port}/"), // reachable
            ]),
            ..VerifyConfig::default()
        };
        let engine = UnifiedAttestationEngine::new(config).expect("engine ok");

        let start = std::time::Instant::now();
        let reachable = engine.probe_network_reachability().await;
        let elapsed = start.elapsed();

        assert!(
            reachable,
            "one reachable endpoint among many must win the race"
        );
        // Should win on the loopback responder long before the blackhole
        // even hits its 2s timeout.
        assert!(
            elapsed < Duration::from_millis(800),
            "race winner should resolve fast, got {:?}",
            elapsed
        );
    }

    /// CIRISVerify#50: The network_unavailable partial result must
    /// carry the canonical opaque-failure shape - same field names
    /// the timeout-fallback uses, distinct status string.
    #[test]
    fn network_unavailable_result_shape_is_canonical() {
        let engine = UnifiedAttestationEngine::new(VerifyConfig::default()).expect("engine ok");
        let result = engine.network_unavailable_result(Duration::from_millis(1234));

        assert!(!result.valid);
        assert_eq!(result.level, 0);
        assert!(result.level_pending);
        assert_eq!(result.registry_key_status, "network_unavailable");
        assert_eq!(result.sources.validation_status, "NetworkUnavailable");
        assert_eq!(
            result.sources.dns_us_error.as_deref(),
            Some("network_unavailable")
        );
        assert_eq!(
            result.sources.dns_eu_error.as_deref(),
            Some("network_unavailable")
        );
        assert_eq!(
            result.sources.https_error.as_deref(),
            Some("network_unavailable")
        );
        assert!(!result.sources.dns_us_reachable);
        assert!(!result.sources.dns_eu_reachable);
        assert!(!result.sources.https_reachable);
        assert_eq!(result.checks_passed, 0);
        assert_eq!(result.checks_total, 0);
        assert!(result.diagnostics.contains("Network unavailable"));
    }
}
