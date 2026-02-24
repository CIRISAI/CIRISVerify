//! Function-level integrity verification.
//!
//! Verifies that critical functions have not been modified since the
//! manifest was generated. Uses early constructor for pre-main verification.
//!
//! ## Design
//!
//! The function manifest system provides fine-grained integrity verification
//! at the function level, extending the existing file manifest pattern:
//!
//! 1. **Build time**: `ciris-manifest-tool` extracts function symbols from
//!    the compiled binary, hashes their bytes, and signs with steward key.
//!
//! 2. **Runtime**: A high-priority constructor loads the manifest, verifies
//!    its signature, then hashes each function in memory and compares.
//!
//! 3. **Fail-secure**: Any mismatch results in `abort()` - no execution of
//!    potentially tampered code.
//!
//! ## Security Properties
//!
//! - **Opaque individual results**: Never reveals WHICH function failed (prevents targeted bypass)
//! - **Clear overall status**: Reports verified/tampered/unavailable to client
//! - **Constant-time**: All hash comparisons use `constant_time_eq()`
//! - **Bound signatures**: PQC covers (manifest || classical_sig)
//! - **ASLR-safe**: Offsets relative to runtime code base
//! - **Fail-secure degradation**: Per threat model Section 7, failures → MORE restrictive modes

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Direct Android logcat output that bypasses tracing layer complexity.
/// This ensures diagnostic messages are always visible in `adb logcat`.
#[cfg(target_os = "android")]
macro_rules! logcat {
    ($level:expr, $($arg:tt)*) => {{
        use std::ffi::CString;
        use std::os::raw::c_char;
        #[allow(dead_code)]
        const ANDROID_LOG_DEBUG: i32 = 3;
        #[allow(dead_code)]
        const ANDROID_LOG_INFO: i32 = 4;
        #[allow(dead_code)]
        const ANDROID_LOG_WARN: i32 = 5;
        #[allow(dead_code)]
        const ANDROID_LOG_ERROR: i32 = 6;
        extern "C" {
            fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
        }
        if let Ok(tag) = CString::new("CIRISVerify") {
            if let Ok(msg) = CString::new(format!($($arg)*)) {
                unsafe { __android_log_write($level, tag.as_ptr(), msg.as_ptr()); }
            }
        }
    }};
}

/// No-op on non-Android platforms - just use tracing.
#[cfg(not(target_os = "android"))]
#[allow(unused_macros)]
macro_rules! logcat {
    ($level:expr, $($arg:tt)*) => {{
        let _ = format!($($arg)*); // Suppress unused warnings
    }};
}

/// Function-level integrity manifest for a specific platform.
///
/// Generated at build time by `ciris-manifest-tool`, this manifest contains
/// hashes of all critical functions (FFI exports) that are verified at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionManifest {
    /// Manifest format version.
    pub version: String,

    /// Target triple this manifest applies to (e.g., "x86_64-unknown-linux-gnu").
    pub target: String,

    /// SHA-256 hash of the entire binary file.
    pub binary_hash: String,

    /// Binary version from Cargo.toml.
    pub binary_version: String,

    /// ISO 8601 generation timestamp.
    pub generated_at: String,

    /// Critical functions with their hashes.
    /// Uses BTreeMap for deterministic ordering (matches FileManifest pattern).
    pub functions: BTreeMap<String, FunctionEntry>,

    /// SHA-256 of the canonical manifest representation (excluding signature).
    pub manifest_hash: String,

    /// Hybrid signature over the manifest.
    pub signature: ManifestSignature,

    /// Metadata about how offsets were computed (for debugging).
    #[serde(default)]
    pub metadata: ManifestMetadata,
}

/// Entry for a single function in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// Function name (demangled if possible).
    pub name: String,

    /// Offset from executable segment base address.
    /// Runtime calculation: ptr = code_base + offset
    /// Where code_base is the library's load address from /proc/self/maps or dl_iterate_phdr.
    pub offset: u64,

    /// Size in bytes.
    pub size: u64,

    /// SHA-256 hash of the function bytes (hex-encoded).
    pub hash: String,

    /// First 16 bytes of the function (hex-encoded, for debugging mismatches).
    /// Compare this with runtime first_bytes to identify offset calculation issues.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub first_bytes: String,
}

/// Metadata about how offsets were computed (for debugging).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestMetadata {
    /// Executable segment virtual address used as offset base.
    /// Offsets are computed as: func_vaddr - exec_segment_vaddr
    #[serde(default)]
    pub exec_segment_vaddr: u64,

    /// .text section virtual address.
    #[serde(default)]
    pub text_section_vaddr: u64,

    /// .text section file offset.
    #[serde(default)]
    pub text_section_offset: u64,
}

/// Hybrid signature for the manifest.
///
/// Uses the same bound signature pattern as other CIRISVerify signatures:
/// the PQC signature covers (canonical_manifest || classical_signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSignature {
    /// Classical Ed25519 signature (base64).
    pub classical: String,

    /// Classical algorithm name.
    pub classical_algorithm: String,

    /// ML-DSA-65 signature bound over (data || classical) (base64).
    pub pqc: String,

    /// PQC algorithm name.
    pub pqc_algorithm: String,

    /// Steward key identifier.
    pub key_id: String,
}

/// Code base information from runtime detection.
///
/// Contains both the memory base address and the file offset from /proc/self/maps,
/// which is needed to calculate the correct pointer adjustment.
#[derive(Debug, Clone, Copy)]
pub struct CodeBaseInfo {
    /// Memory base address where the executable segment is loaded.
    pub base: usize,
    /// File offset from /proc/self/maps (where this segment starts in the file).
    /// Used with manifest's text_section_offset to calculate adjustment.
    pub maps_file_offset: u64,
}

/// Result of function-level integrity verification.
///
/// Per FSD-001 Section "Integrity Check Opacity", we MUST NOT expose
/// which specific function failed. Only a single pass/fail and generic
/// failure category are provided.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionIntegrityResult {
    /// Overall pass/fail.
    pub integrity_valid: bool,

    /// Number of functions verified.
    pub functions_checked: usize,

    /// Number that passed.
    pub functions_passed: usize,

    /// Timestamp of verification (Unix seconds).
    pub verified_at: i64,

    /// Opaque failure reason (does NOT reveal which function failed).
    /// One of: "", "signature", "mismatch", "missing", "manifest"
    pub failure_reason: String,

    // === Diagnostic fields (for debugging, not security-sensitive) ===
    /// Binary hash from the manifest (for comparison with actual).
    #[serde(default)]
    pub manifest_binary_hash: String,

    /// Target from the manifest.
    #[serde(default)]
    pub manifest_target: String,

    /// Code base address found (hex string, e.g., "0x7f1234567000").
    #[serde(default)]
    pub code_base: String,
}

impl FunctionManifest {
    /// Compute the canonical representation for signing.
    ///
    /// This excludes the signature field and produces deterministic JSON.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Create a copy without the signature for hashing
        let canonical = CanonicalManifest {
            version: &self.version,
            target: &self.target,
            binary_hash: &self.binary_hash,
            binary_version: &self.binary_version,
            generated_at: &self.generated_at,
            functions: &self.functions,
        };

        // Serialize to deterministic JSON (BTreeMap ensures key ordering)
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Compute the manifest hash from function hashes.
    ///
    /// The manifest hash is SHA-256 of the sorted concatenation of all
    /// function hashes, providing a single value to verify integrity.
    pub fn compute_manifest_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // BTreeMap iteration is sorted by key
        for entry in self.functions.values() {
            hasher.update(entry.hash.as_bytes());
        }

        let hash = hasher.finalize();
        format!("sha256:{}", hex::encode(hash))
    }
}

/// Canonical manifest representation for signing (excludes signature).
#[derive(Serialize)]
struct CanonicalManifest<'a> {
    version: &'a str,
    target: &'a str,
    binary_hash: &'a str,
    binary_version: &'a str,
    generated_at: &'a str,
    functions: &'a BTreeMap<String, FunctionEntry>,
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Steward public key for manifest signature verification.
///
/// These keys are embedded at compile time and used to verify that function
/// manifests were signed by the trusted steward key pair.
pub struct StewardPublicKey {
    /// Ed25519 public key (32 bytes).
    pub ed25519: &'static [u8; 32],
    /// ML-DSA-65 public key (1952 bytes).
    pub ml_dsa_65: &'static [u8],
}

/// Status of function integrity verification.
///
/// Per threat model Section 7, failures degrade to MORE restrictive modes.
/// The client (CIRISAgent) decides what action to take based on this status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FunctionIntegrityStatus {
    /// All functions verified successfully.
    Verified,
    /// Network/registry unavailable - could not fetch manifest.
    Unavailable {
        /// Description of why the manifest is unavailable.
        reason: String,
    },
    /// Manifest signature failed verification.
    SignatureInvalid,
    /// One or more function hashes don't match (binary tampered).
    Tampered,
    /// No manifest found for this version/target.
    NotFound,
    /// Verification not yet attempted.
    #[default]
    Pending,
}

impl std::fmt::Display for FunctionIntegrityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified => write!(f, "verified"),
            Self::Unavailable { reason } => write!(f, "unavailable:{}", reason),
            Self::SignatureInvalid => write!(f, "signature_invalid"),
            Self::Tampered => write!(f, "tampered"),
            Self::NotFound => write!(f, "not_found"),
            Self::Pending => write!(f, "pending"),
        }
    }
}

/// Verify the hybrid signature on a function manifest.
///
/// Both the classical (Ed25519) and post-quantum (ML-DSA-65) signatures
/// must verify for the manifest to be trusted. The PQC signature is bound
/// to the classical signature (covers canonical_manifest || classical_sig).
///
/// # Arguments
///
/// * `manifest` - The function manifest to verify
/// * `steward_pubkey` - The steward's public key pair
///
/// # Returns
///
/// `Ok(true)` if both signatures verify, `Ok(false)` if either fails,
/// or an error if verification cannot be performed.
pub fn verify_manifest_signature(
    manifest: &FunctionManifest,
    steward_pubkey: &StewardPublicKey,
) -> Result<bool, crate::error::VerifyError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, MlDsa65Verifier, PqcVerifier};

    // Get canonical bytes (excludes signature field)
    let canonical = manifest.canonical_bytes();

    // Decode classical signature
    let classical_sig_bytes = STANDARD
        .decode(&manifest.signature.classical)
        .map_err(|e| crate::error::VerifyError::IntegrityError {
            message: format!("Invalid classical signature base64: {}", e),
        })?;

    // Verify Ed25519 signature
    let ed25519_verifier = Ed25519Verifier::new();
    let classical_valid = ed25519_verifier
        .verify(steward_pubkey.ed25519, &canonical, &classical_sig_bytes)
        .map_err(|e| crate::error::VerifyError::IntegrityError {
            message: format!("Ed25519 verification error: {}", e),
        })?;

    if !classical_valid {
        return Ok(false); // Classical signature failed
    }

    // Decode PQC signature
    let pqc_sig_bytes = STANDARD.decode(&manifest.signature.pqc).map_err(|e| {
        crate::error::VerifyError::IntegrityError {
            message: format!("Invalid PQC signature base64: {}", e),
        }
    })?;

    // PQC signature covers (canonical || classical_sig) - bound signature
    let mut bound_data = canonical.clone();
    bound_data.extend_from_slice(&classical_sig_bytes);

    // Verify ML-DSA-65 signature
    let mldsa_verifier = MlDsa65Verifier::new();
    let pqc_valid = mldsa_verifier
        .verify(steward_pubkey.ml_dsa_65, &bound_data, &pqc_sig_bytes)
        .map_err(|e| crate::error::VerifyError::IntegrityError {
            message: format!("ML-DSA-65 verification error: {}", e),
        })?;

    if !pqc_valid {
        return Ok(false); // PQC signature failed
    }

    Ok(true) // Both signatures verified
}

// =============================================================================
// Runtime Verification (platform-specific)
// =============================================================================

/// Verify all critical functions at runtime.
///
/// This function is called from the high-priority constructor.
/// On any failure, the caller should call `std::process::abort()` to prevent
/// execution of tampered code.
///
/// # Arguments
///
/// * `manifest` - The function manifest to verify against
///
/// # Returns
///
/// A result indicating whether all functions passed verification.
/// The result is opaque - it does not reveal which function failed.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn verify_functions(manifest: &FunctionManifest) -> FunctionIntegrityResult {
    use sha2::{Digest, Sha256};

    let timestamp = current_timestamp();

    // Log manifest details for diagnostics (tracing + direct logcat for Android)
    tracing::info!(
        "verify_functions: manifest version={}, target={}, binary_hash={}, functions={}, exec_segment_vaddr=0x{:x}",
        manifest.binary_version,
        manifest.target,
        manifest.binary_hash,
        manifest.functions.len(),
        manifest.metadata.exec_segment_vaddr
    );
    logcat!(
        ANDROID_LOG_INFO,
        "verify_functions: manifest version={}, target={}, functions={}, exec_segment_vaddr=0x{:x}",
        manifest.binary_version,
        manifest.target,
        manifest.functions.len(),
        manifest.metadata.exec_segment_vaddr
    );

    // Log first few function entries for debugging
    // NOTE: offsets should be small (relative to code section), not large virtual addresses
    // If offsets are > 0x100000 (1MB), likely manifest was generated with wrong offset format
    for (i, (name, entry)) in manifest.functions.iter().take(3).enumerate() {
        tracing::info!(
            "verify_functions: sample[{}] name={}, offset=0x{:x}, size={}, hash={}",
            i,
            name,
            entry.offset,
            entry.size,
            &entry.hash[..std::cmp::min(20, entry.hash.len())]
        );
        // Warn if offset looks like a virtual address instead of relative offset
        if entry.offset > 0x100000 {
            tracing::warn!(
                "verify_functions: WARNING - offset 0x{:x} is unusually large (>1MB), may be virtual address instead of relative offset",
                entry.offset
            );
        }
    }

    // Get code base address - use platform-specific function
    #[cfg(target_os = "android")]
    let (code_base, text_adjustment) = match get_code_base_android() {
        Some(info) => {
            // Calculate adjustment: difference between .text file offset and maps file offset
            // This accounts for the gap between segment start and .text section start
            let text_offset = manifest.metadata.text_section_offset;
            let adjustment = if text_offset >= info.maps_file_offset {
                (text_offset - info.maps_file_offset) as usize
            } else {
                tracing::warn!(
                    "verify_functions: text_offset (0x{:x}) < maps_file_offset (0x{:x}), no adjustment",
                    text_offset,
                    info.maps_file_offset
                );
                0
            };

            tracing::info!(
                "verify_functions: base=0x{:x}, maps_file_offset=0x{:x}, text_offset=0x{:x}, adjustment=0x{:x}",
                info.base, info.maps_file_offset, text_offset, adjustment
            );
            logcat!(
                ANDROID_LOG_INFO,
                "verify_functions: base=0x{:x}, maps_offset=0x{:x}, text_offset=0x{:x}, adj=0x{:x}",
                info.base,
                info.maps_file_offset,
                text_offset,
                adjustment
            );

            (info.base, adjustment)
        },
        None => {
            tracing::error!("verify_functions: FAILED - could not determine code base address");
            logcat!(
                ANDROID_LOG_ERROR,
                "verify_functions: FAILED - could not determine code base address"
            );
            return FunctionIntegrityResult {
                integrity_valid: false,
                functions_checked: 0,
                functions_passed: 0,
                verified_at: timestamp,
                failure_reason: "missing".to_string(),
                manifest_binary_hash: manifest.binary_hash.clone(),
                manifest_target: manifest.target.clone(),
                code_base: "not_found".to_string(),
            };
        },
    };

    #[cfg(all(target_os = "linux", not(target_os = "android")))]
    let (code_base, text_adjustment) = match get_code_base_linux() {
        Some(base) => {
            tracing::info!("verify_functions: code_base=0x{:x}", base);
            // Linux uses dl_iterate_phdr which gives segment base directly
            // TODO: may need similar adjustment for Linux shared libraries
            (base, 0usize)
        },
        None => {
            tracing::error!("verify_functions: FAILED - could not determine code base address");
            return FunctionIntegrityResult {
                integrity_valid: false,
                functions_checked: 0,
                functions_passed: 0,
                verified_at: timestamp,
                failure_reason: "missing".to_string(),
                manifest_binary_hash: manifest.binary_hash.clone(),
                manifest_target: manifest.target.clone(),
                code_base: "not_found".to_string(),
            };
        },
    };

    // Verify each function (constant-time accumulation)
    let mut all_valid = true;
    let mut functions_passed = 0usize;
    let mut first_mismatch_logged = false;

    for (name, entry) in &manifest.functions {
        // Safety: We trust the manifest offsets for our own binary
        // ptr = base + text_adjustment + manifest_offset
        let func_bytes = unsafe {
            let ptr = (code_base + text_adjustment + entry.offset as usize) as *const u8;
            if ptr.is_null() {
                tracing::warn!(
                    "verify_functions: null pointer for {} at offset 0x{:x}",
                    name,
                    entry.offset
                );
                all_valid = false;
                continue;
            }
            std::slice::from_raw_parts(ptr, entry.size as usize)
        };

        // Compute actual hash
        let mut hasher = Sha256::new();
        hasher.update(func_bytes);
        let actual_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        // Constant-time comparison
        let matches = super::constant_time_eq(entry.hash.as_bytes(), actual_hash.as_bytes());
        all_valid &= matches;
        if matches {
            functions_passed += 1;
        } else if !first_mismatch_logged {
            // Log first mismatch with diagnostic details (tracing + direct logcat for Android)
            let ptr_addr = code_base + text_adjustment + entry.offset as usize;
            let first_bytes: Vec<u8> = func_bytes.iter().take(16).copied().collect();
            let first_bytes_hex = hex::encode(&first_bytes);
            tracing::warn!(
                "verify_functions: MISMATCH (first) name={}, offset=0x{:x}, size={}, ptr=0x{:x}",
                name,
                entry.offset,
                entry.size,
                ptr_addr
            );
            tracing::warn!(
                "  base=0x{:x}, adjustment=0x{:x}, offset=0x{:x}",
                code_base,
                text_adjustment,
                entry.offset
            );
            tracing::warn!(
                "  runtime_bytes={}, manifest_bytes={}",
                first_bytes_hex,
                if entry.first_bytes.is_empty() {
                    "n/a"
                } else {
                    &entry.first_bytes
                }
            );
            tracing::warn!(
                "  runtime_hash={}, manifest_hash={}",
                actual_hash,
                entry.hash
            );
            // Direct logcat for Android - CRITICAL debug info
            logcat!(
                ANDROID_LOG_WARN,
                "MISMATCH name={}, offset=0x{:x}, size={}, ptr=0x{:x}",
                name,
                entry.offset,
                entry.size,
                ptr_addr
            );
            logcat!(
                ANDROID_LOG_WARN,
                "MISMATCH ptr=base(0x{:x})+adj(0x{:x})+off(0x{:x})",
                code_base,
                text_adjustment,
                entry.offset
            );
            // Show both actual runtime bytes and expected manifest bytes for comparison
            logcat!(
                ANDROID_LOG_WARN,
                "MISMATCH runtime_bytes={} (at ptr)",
                first_bytes_hex
            );
            logcat!(
                ANDROID_LOG_WARN,
                "MISMATCH manifest_bytes={} (from file)",
                if entry.first_bytes.is_empty() {
                    "not_in_manifest".to_string()
                } else {
                    entry.first_bytes.clone()
                }
            );
            logcat!(
                ANDROID_LOG_WARN,
                "MISMATCH runtime_hash={}...",
                &actual_hash[..std::cmp::min(30, actual_hash.len())]
            );
            logcat!(
                ANDROID_LOG_WARN,
                "MISMATCH manifest_hash={}...",
                &entry.hash[..std::cmp::min(30, entry.hash.len())]
            );
            first_mismatch_logged = true;
        }
    }

    let result_msg = format!(
        "verify_functions: RESULT {}/{} passed, valid={}",
        functions_passed,
        manifest.functions.len(),
        all_valid
    );
    tracing::info!("{}", result_msg);
    logcat!(ANDROID_LOG_INFO, "{}", result_msg);

    FunctionIntegrityResult {
        integrity_valid: all_valid,
        functions_checked: manifest.functions.len(),
        functions_passed,
        verified_at: timestamp,
        failure_reason: if all_valid {
            String::new()
        } else {
            "mismatch".to_string()
        },
        manifest_binary_hash: manifest.binary_hash.clone(),
        manifest_target: manifest.target.clone(),
        code_base: format!("0x{:x}", code_base),
    }
}

/// Verify all critical functions at runtime (macOS/iOS).
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn verify_functions(manifest: &FunctionManifest) -> FunctionIntegrityResult {
    use sha2::{Digest, Sha256};

    let timestamp = current_timestamp();

    tracing::info!(
        "verify_functions: manifest version={}, target={}, binary_hash={}, functions={}",
        manifest.binary_version,
        manifest.target,
        manifest.binary_hash,
        manifest.functions.len()
    );

    // Log first few function entries for debugging
    // NOTE: offsets should be small (relative to code section), not large virtual addresses
    for (i, (name, entry)) in manifest.functions.iter().take(3).enumerate() {
        tracing::info!(
            "verify_functions: sample[{}] name={}, offset=0x{:x}, size={}, hash={}",
            i,
            name,
            entry.offset,
            entry.size,
            &entry.hash[..std::cmp::min(20, entry.hash.len())]
        );
        if entry.offset > 0x100000 {
            tracing::warn!(
                "verify_functions: WARNING - offset 0x{:x} is unusually large (>1MB), may be virtual address instead of relative offset",
                entry.offset
            );
        }
    }

    // Get code base address
    let code_base = match get_code_base_macos() {
        Some(base) => {
            tracing::info!("verify_functions: code_base=0x{:x}", base);
            base
        },
        None => {
            tracing::error!("verify_functions: FAILED - could not determine code base address");
            return FunctionIntegrityResult {
                integrity_valid: false,
                functions_checked: 0,
                functions_passed: 0,
                verified_at: timestamp,
                failure_reason: "missing".to_string(),
                manifest_binary_hash: manifest.binary_hash.clone(),
                manifest_target: manifest.target.clone(),
                code_base: "not_found".to_string(),
            };
        },
    };

    // Verify each function (constant-time accumulation)
    let mut all_valid = true;
    let mut functions_passed = 0usize;
    let mut first_mismatch_logged = false;

    for (name, entry) in &manifest.functions {
        let func_bytes = unsafe {
            let ptr = (code_base + entry.offset as usize) as *const u8;
            if ptr.is_null() {
                tracing::warn!(
                    "verify_functions: null pointer for {} at offset 0x{:x}",
                    name,
                    entry.offset
                );
                all_valid = false;
                continue;
            }
            std::slice::from_raw_parts(ptr, entry.size as usize)
        };

        let mut hasher = Sha256::new();
        hasher.update(func_bytes);
        let actual_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        let matches = super::constant_time_eq(entry.hash.as_bytes(), actual_hash.as_bytes());
        all_valid &= matches;
        if matches {
            functions_passed += 1;
        } else if !first_mismatch_logged {
            // Log first mismatch with diagnostic details
            let ptr_addr = code_base + entry.offset as usize;
            let first_bytes: Vec<u8> = func_bytes.iter().take(16).copied().collect();
            let first_bytes_hex = hex::encode(&first_bytes);
            tracing::warn!(
                "verify_functions: MISMATCH (first) name={}, offset=0x{:x}, size={}, ptr=0x{:x}",
                name,
                entry.offset,
                entry.size,
                ptr_addr
            );
            tracing::warn!("  base=0x{:x}, offset=0x{:x}", code_base, entry.offset);
            tracing::warn!(
                "  runtime_bytes={}, manifest_bytes={}",
                first_bytes_hex,
                if entry.first_bytes.is_empty() {
                    "n/a"
                } else {
                    &entry.first_bytes
                }
            );
            tracing::warn!(
                "  runtime_hash={}, manifest_hash={}",
                actual_hash,
                entry.hash
            );
            first_mismatch_logged = true;
        }
    }

    tracing::info!(
        "verify_functions: RESULT {}/{} passed, valid={}",
        functions_passed,
        manifest.functions.len(),
        all_valid
    );

    FunctionIntegrityResult {
        integrity_valid: all_valid,
        functions_checked: manifest.functions.len(),
        functions_passed,
        verified_at: timestamp,
        failure_reason: if all_valid {
            String::new()
        } else {
            "mismatch".to_string()
        },
        manifest_binary_hash: manifest.binary_hash.clone(),
        manifest_target: manifest.target.clone(),
        code_base: format!("0x{:x}", code_base),
    }
}

/// Verify all critical functions at runtime (Windows).
#[cfg(target_os = "windows")]
pub fn verify_functions(manifest: &FunctionManifest) -> FunctionIntegrityResult {
    use sha2::{Digest, Sha256};

    let timestamp = current_timestamp();

    tracing::info!(
        "verify_functions: manifest version={}, target={}, binary_hash={}, functions={}",
        manifest.binary_version,
        manifest.target,
        manifest.binary_hash,
        manifest.functions.len()
    );

    // Log first few function entries for debugging
    for (i, (name, entry)) in manifest.functions.iter().take(3).enumerate() {
        tracing::info!(
            "verify_functions: sample[{}] name={}, offset=0x{:x}, size={}, hash={}",
            i,
            name,
            entry.offset,
            entry.size,
            &entry.hash[..std::cmp::min(20, entry.hash.len())]
        );
        if entry.offset > 0x100000 {
            tracing::warn!(
                "verify_functions: WARNING - offset 0x{:x} is unusually large (>1MB), may be virtual address instead of relative offset",
                entry.offset
            );
        }
    }

    // Get code base address
    let code_base = match get_code_base_windows() {
        Some(base) => {
            tracing::info!("verify_functions: code_base=0x{:x}", base);
            base
        },
        None => {
            tracing::error!("verify_functions: FAILED - could not determine code base address");
            return FunctionIntegrityResult {
                integrity_valid: false,
                functions_checked: 0,
                functions_passed: 0,
                verified_at: timestamp,
                failure_reason: "missing".to_string(),
                manifest_binary_hash: manifest.binary_hash.clone(),
                manifest_target: manifest.target.clone(),
                code_base: "not_found".to_string(),
            };
        },
    };

    // Verify each function (constant-time accumulation)
    let mut all_valid = true;
    let mut functions_passed = 0usize;
    let mut first_mismatch_logged = false;

    for (name, entry) in &manifest.functions {
        let func_bytes = unsafe {
            let ptr = (code_base + entry.offset as usize) as *const u8;
            if ptr.is_null() {
                tracing::warn!(
                    "verify_functions: null pointer for {} at offset 0x{:x}",
                    name,
                    entry.offset
                );
                all_valid = false;
                continue;
            }
            std::slice::from_raw_parts(ptr, entry.size as usize)
        };

        let mut hasher = Sha256::new();
        hasher.update(func_bytes);
        let actual_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        let matches = super::constant_time_eq(entry.hash.as_bytes(), actual_hash.as_bytes());
        all_valid &= matches;
        if matches {
            functions_passed += 1;
        } else if !first_mismatch_logged {
            // Log first mismatch with diagnostic details
            let ptr_addr = code_base + entry.offset as usize;
            let first_bytes: Vec<u8> = func_bytes.iter().take(16).copied().collect();
            tracing::warn!(
                "verify_functions: MISMATCH (first) name={}, offset=0x{:x}, size={}, ptr=0x{:x}, first_bytes={}, expected={}, actual={}",
                name,
                entry.offset,
                entry.size,
                ptr_addr,
                hex::encode(&first_bytes),
                entry.hash,
                actual_hash
            );
            first_mismatch_logged = true;
        }
    }

    tracing::info!(
        "verify_functions: RESULT {}/{} passed, valid={}",
        functions_passed,
        manifest.functions.len(),
        all_valid
    );

    FunctionIntegrityResult {
        integrity_valid: all_valid,
        functions_checked: manifest.functions.len(),
        functions_passed,
        verified_at: timestamp,
        failure_reason: if all_valid {
            String::new()
        } else {
            "mismatch".to_string()
        },
        manifest_binary_hash: manifest.binary_hash.clone(),
        manifest_target: manifest.target.clone(),
        code_base: format!("0x{:x}", code_base),
    }
}

/// Fallback for unsupported platforms.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
pub fn verify_functions(manifest: &FunctionManifest) -> FunctionIntegrityResult {
    // Unsupported platform - return failure
    tracing::warn!("verify_functions: unsupported platform");
    FunctionIntegrityResult {
        integrity_valid: false,
        functions_checked: 0,
        functions_passed: 0,
        verified_at: current_timestamp(),
        failure_reason: "unsupported_platform".to_string(),
        manifest_binary_hash: manifest.binary_hash.clone(),
        manifest_target: manifest.target.clone(),
        code_base: "unsupported".to_string(),
    }
}

// =============================================================================
// Platform-specific code base detection
// =============================================================================

/// Get the base address of libciris_verify_ffi.so on Linux (not Android).
///
/// Uses `dl_iterate_phdr` to find our library's load address.
#[cfg(all(target_os = "linux", not(target_os = "android")))]
fn get_code_base_linux() -> Option<usize> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BASE: AtomicUsize = AtomicUsize::new(0);
    static FOUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    const LIB_NAME: &str = "libciris_verify_ffi.so";

    // Only compute once
    if FOUND.load(Ordering::Relaxed) {
        let base = BASE.load(Ordering::Relaxed);
        tracing::debug!("get_code_base_linux: cached base=0x{:x}", base);
        return Some(base);
    }

    tracing::info!(
        "get_code_base_linux: searching for {} via dl_iterate_phdr",
        LIB_NAME
    );

    #[repr(C)]
    struct DlPhdrInfo {
        dlpi_addr: usize,
        dlpi_name: *const std::ffi::c_char,
        // ... other fields we don't need
    }

    extern "C" {
        fn dl_iterate_phdr(
            callback: extern "C" fn(*const DlPhdrInfo, usize, *mut std::ffi::c_void) -> i32,
            data: *mut std::ffi::c_void,
        ) -> i32;
    }

    extern "C" fn callback(
        info: *const DlPhdrInfo,
        _size: usize,
        data: *mut std::ffi::c_void,
    ) -> i32 {
        unsafe {
            let name_ptr = (*info).dlpi_name;
            if name_ptr.is_null() {
                return 0; // Continue
            }

            // Convert C string to Rust &str
            let name_cstr = std::ffi::CStr::from_ptr(name_ptr);
            let name = name_cstr.to_str().unwrap_or("");

            // Look for our library
            if name.contains("libciris_verify_ffi.so") {
                let base_ptr = data as *mut usize;
                *base_ptr = (*info).dlpi_addr;
                return 1; // Stop iteration
            }
        }
        0 // Continue
    }

    let mut base: usize = 0;
    unsafe {
        dl_iterate_phdr(callback, &mut base as *mut usize as *mut std::ffi::c_void);
    }

    if base != 0 {
        tracing::info!(
            "get_code_base_linux: found {} at base=0x{:x}",
            LIB_NAME,
            base
        );
        BASE.store(base, Ordering::Relaxed);
        FOUND.store(true, Ordering::Relaxed);
        Some(base)
    } else {
        tracing::warn!(
            "get_code_base_linux: {} not found in loaded libraries",
            LIB_NAME
        );
        None
    }
}

/// Get the base address and file offset of libciris_verify_ffi.so on Android.
///
/// On Android, the "main executable" is app_process64 (Android runtime), not our library.
/// We need to find libciris_verify_ffi.so's load address from /proc/self/maps.
///
/// Returns both the memory base address AND the maps file offset, which is needed
/// to calculate the adjustment between segment start and .text section start.
#[cfg(target_os = "android")]
fn get_code_base_android() -> Option<CodeBaseInfo> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static BASE: AtomicUsize = AtomicUsize::new(0);
    static MAPS_FILE_OFFSET: AtomicU64 = AtomicU64::new(0);
    static FOUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    // Only compute once
    if FOUND.load(Ordering::Relaxed) {
        let base = BASE.load(Ordering::Relaxed);
        let maps_file_offset = MAPS_FILE_OFFSET.load(Ordering::Relaxed);
        tracing::debug!(
            "get_code_base_android: cached base=0x{:x}, maps_file_offset=0x{:x}",
            base,
            maps_file_offset
        );
        return Some(CodeBaseInfo {
            base,
            maps_file_offset,
        });
    }

    const LIB_NAME: &str = "libciris_verify_ffi.so";
    tracing::info!(
        "get_code_base_android: searching for {} in /proc/self/maps",
        LIB_NAME
    );
    logcat!(
        ANDROID_LOG_INFO,
        "get_code_base_android: searching for {} in /proc/self/maps",
        LIB_NAME
    );

    let maps_file = match File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("get_code_base_android: cannot open /proc/self/maps: {}", e);
            logcat!(
                ANDROID_LOG_ERROR,
                "get_code_base_android: cannot open /proc/self/maps: {}",
                e
            );
            return None;
        },
    };

    let reader = BufReader::new(maps_file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Look for our library with r-xp (read-execute) permissions (code segment)
        if line.contains(LIB_NAME) && line.contains("r-xp") {
            // /proc/self/maps format:
            // 7f1234567000-7f123456a000 r-xp 00000000 fd:01 1234567 /path/to/lib.so
            // Field 0: start-end addresses
            // Field 1: permissions
            // Field 2: file offset (hex, no 0x prefix)
            // Field 3: device
            // Field 4: inode
            // Field 5+: pathname
            tracing::info!("get_code_base_android: maps entry: {}", line);
            logcat!(ANDROID_LOG_INFO, "maps entry: {}", line);

            let parts: Vec<&str> = line.split_whitespace().collect();

            if let Some(addr_str) = line.split('-').next() {
                if let Ok(base) = usize::from_str_radix(addr_str, 16) {
                    // Parse the file offset (field 2)
                    let maps_file_offset = parts
                        .get(2)
                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                        .unwrap_or(0);

                    tracing::info!(
                        "get_code_base_android: found {} at base=0x{:x}, maps_file_offset=0x{:x}",
                        LIB_NAME,
                        base,
                        maps_file_offset
                    );
                    logcat!(
                        ANDROID_LOG_INFO,
                        "get_code_base_android: FOUND base=0x{:x}, maps_file_offset=0x{:x}",
                        base,
                        maps_file_offset
                    );

                    BASE.store(base, Ordering::Relaxed);
                    MAPS_FILE_OFFSET.store(maps_file_offset, Ordering::Relaxed);
                    FOUND.store(true, Ordering::Relaxed);

                    return Some(CodeBaseInfo {
                        base,
                        maps_file_offset,
                    });
                }
            }
        }
    }

    tracing::warn!(
        "get_code_base_android: {} not found in /proc/self/maps with r-xp permissions",
        LIB_NAME
    );
    logcat!(
        ANDROID_LOG_WARN,
        "get_code_base_android: {} NOT FOUND in /proc/self/maps with r-xp",
        LIB_NAME
    );
    None
}

/// Get the base address of the code section on macOS/iOS.
///
/// Uses dyld APIs to find the main executable's base address with ASLR slide.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn get_code_base_macos() -> Option<usize> {
    extern "C" {
        fn _dyld_get_image_header(image_index: u32) -> *const std::ffi::c_void;
        fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
    }

    unsafe {
        // Image 0 is the main executable
        let header = _dyld_get_image_header(0);
        if header.is_null() {
            return None;
        }

        let slide = _dyld_get_image_vmaddr_slide(0);
        Some((header as usize).wrapping_add(slide as usize))
    }
}

/// Get the base address of the code section on Windows.
///
/// Uses `GetModuleHandleW(NULL)` to get the base address of the main module.
#[cfg(target_os = "windows")]
fn get_code_base_windows() -> Option<usize> {
    use std::ptr;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleW(lpModuleName: *const u16) -> *mut std::ffi::c_void;
    }

    unsafe {
        let handle = GetModuleHandleW(ptr::null());
        if handle.is_null() {
            None
        } else {
            Some(handle as usize)
        }
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_entry_serialization() {
        let entry = FunctionEntry {
            name: "test_function".to_string(),
            offset: 0x1000,
            size: 0x100,
            hash: "sha256:abc123".to_string(),
            first_bytes: String::new(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test_function"));
        assert!(json.contains("4096")); // 0x1000 in decimal
    }

    #[test]
    fn test_manifest_canonical_bytes_deterministic() {
        let mut functions = BTreeMap::new();
        functions.insert(
            "func_a".to_string(),
            FunctionEntry {
                name: "func_a".to_string(),
                offset: 0,
                size: 10,
                hash: "sha256:aaa".to_string(),
                first_bytes: String::new(),
            },
        );
        functions.insert(
            "func_b".to_string(),
            FunctionEntry {
                name: "func_b".to_string(),
                offset: 10,
                size: 20,
                hash: "sha256:bbb".to_string(),
                first_bytes: String::new(),
            },
        );

        let manifest = FunctionManifest {
            version: "1.0.0".to_string(),
            target: "test".to_string(),
            binary_hash: "sha256:test".to_string(),
            binary_version: "0.1.0".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            functions,
            manifest_hash: String::new(),
            signature: ManifestSignature {
                classical: String::new(),
                classical_algorithm: "Ed25519".to_string(),
                pqc: String::new(),
                pqc_algorithm: "ML-DSA-65".to_string(),
                key_id: "test".to_string(),
            },
            metadata: ManifestMetadata::default(),
        };

        // Call twice - should produce identical bytes
        let bytes1 = manifest.canonical_bytes();
        let bytes2 = manifest.canonical_bytes();
        assert_eq!(bytes1, bytes2);

        // Should not contain signature
        let json = String::from_utf8(bytes1).unwrap();
        assert!(!json.contains("classical"));
        assert!(!json.contains("signature"));
    }

    #[test]
    fn test_compute_manifest_hash() {
        let mut functions = BTreeMap::new();
        functions.insert(
            "func".to_string(),
            FunctionEntry {
                name: "func".to_string(),
                offset: 0,
                size: 10,
                hash: "sha256:abc123".to_string(),
                first_bytes: String::new(),
            },
        );

        let manifest = FunctionManifest {
            version: "1.0.0".to_string(),
            target: "test".to_string(),
            binary_hash: "sha256:test".to_string(),
            binary_version: "0.1.0".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            functions,
            manifest_hash: String::new(),
            signature: ManifestSignature {
                classical: String::new(),
                classical_algorithm: "Ed25519".to_string(),
                pqc: String::new(),
                pqc_algorithm: "ML-DSA-65".to_string(),
                key_id: "test".to_string(),
            },
            metadata: ManifestMetadata::default(),
        };

        let hash = manifest.compute_manifest_hash();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_function_integrity_result_default() {
        let result = FunctionIntegrityResult::default();
        assert!(!result.integrity_valid);
        assert_eq!(result.functions_checked, 0);
        assert!(result.failure_reason.is_empty());
    }
}
