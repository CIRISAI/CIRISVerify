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
    tracing::debug!(
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
        tracing::debug!(
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
            tracing::debug!("verify_functions: code_base=0x{:x}", base);
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
            tracing::debug!("verify_functions: code_base=0x{:x}", base);
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
///
/// On Windows, manifest offsets are RVAs from the **module base of the DLL**
/// that hosts CIRISVerify (resolved via `GetModuleHandleExW(FROM_ADDRESS, ...)`).
/// Every read is bounds-checked against `SizeOfImage` and probed with
/// `VirtualQuery` to avoid faulting/stalling on bogus offsets — historically a
/// manifest with absolute VAs would dereference into unmapped memory and hang
/// the worker forever.
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

    let module = match get_code_base_windows() {
        Some(m) => {
            tracing::debug!(
                "verify_functions: module base=0x{:x}, image_size=0x{:x}",
                m.base,
                m.image_size
            );
            m
        },
        None => {
            tracing::error!("verify_functions: FAILED - could not determine module base");
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

    // Without a known image size we cannot bounds-check; reject up-front rather
    // than risk faulting on a raw pointer read.
    if module.image_size == 0 {
        tracing::error!(
            "verify_functions: FAILED - module image size unknown, cannot bounds-check"
        );
        return FunctionIntegrityResult {
            integrity_valid: false,
            functions_checked: 0,
            functions_passed: 0,
            verified_at: timestamp,
            failure_reason: "missing".to_string(),
            manifest_binary_hash: manifest.binary_hash.clone(),
            manifest_target: manifest.target.clone(),
            code_base: format!("0x{:x}", module.base),
        };
    }

    // Log first few function entries for debugging.
    for (i, (name, entry)) in manifest.functions.iter().take(3).enumerate() {
        tracing::info!(
            "verify_functions: sample[{}] name={}, offset=0x{:x}, size={}, hash={}",
            i,
            name,
            entry.offset,
            entry.size,
            &entry.hash[..std::cmp::min(20, entry.hash.len())]
        );
    }

    // Verify each function (constant-time accumulation).
    let mut all_valid = true;
    let mut functions_passed = 0usize;
    let mut first_mismatch_logged = false;
    let mut out_of_bounds = 0usize;

    for (name, entry) in &manifest.functions {
        // Bounds-check against the mapped image. A manifest with absolute VAs
        // (rather than RVAs) trips this immediately and we fail closed instead
        // of dereferencing into unmapped memory.
        let end = (entry.offset as usize).checked_add(entry.size as usize);
        let in_image = match end {
            Some(e) => e <= module.image_size,
            None => false,
        };
        if !in_image {
            all_valid = false;
            out_of_bounds += 1;
            if !first_mismatch_logged {
                tracing::warn!(
                    "verify_functions: OUT OF BOUNDS name={}, offset=0x{:x}, size={}, image_size=0x{:x} (manifest likely encodes VAs, not RVAs)",
                    name,
                    entry.offset,
                    entry.size,
                    module.image_size
                );
                first_mismatch_logged = true;
            }
            continue;
        }

        let ptr_addr = module.base + entry.offset as usize;

        // Defense in depth: confirm every page in the range is committed and
        // readable before we touch it. Cheap insurance against ACL/PAGE_GUARD
        // surprises that would otherwise raise a structured exception inside
        // the tokio worker.
        if !windows_range_readable(ptr_addr, entry.size as usize) {
            all_valid = false;
            if !first_mismatch_logged {
                tracing::warn!(
                    "verify_functions: UNREADABLE name={}, ptr=0x{:x}, size={}",
                    name,
                    ptr_addr,
                    entry.size
                );
                first_mismatch_logged = true;
            }
            continue;
        }

        let func_bytes =
            unsafe { std::slice::from_raw_parts(ptr_addr as *const u8, entry.size as usize) };

        let mut hasher = Sha256::new();
        hasher.update(func_bytes);
        let actual_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        let matches = super::constant_time_eq(entry.hash.as_bytes(), actual_hash.as_bytes());
        all_valid &= matches;
        if matches {
            functions_passed += 1;
        } else if !first_mismatch_logged {
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

    let failure_reason = if all_valid {
        String::new()
    } else if out_of_bounds == manifest.functions.len() {
        // Every entry was out of bounds — the manifest doesn't match this
        // module at all (wrong format or wrong build). Surface as "manifest"
        // rather than "mismatch" so callers can distinguish.
        "manifest".to_string()
    } else {
        "mismatch".to_string()
    };

    tracing::info!(
        "verify_functions: RESULT {}/{} passed, valid={}, out_of_bounds={}, reason={}",
        functions_passed,
        manifest.functions.len(),
        all_valid,
        out_of_bounds,
        if failure_reason.is_empty() { "ok" } else { &failure_reason }
    );

    FunctionIntegrityResult {
        integrity_valid: all_valid,
        functions_checked: manifest.functions.len(),
        functions_passed,
        verified_at: timestamp,
        failure_reason,
        manifest_binary_hash: manifest.binary_hash.clone(),
        manifest_target: manifest.target.clone(),
        code_base: format!("0x{:x}", module.base),
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

    // ELF program header structure (64-bit)
    #[repr(C)]
    struct Elf64Phdr {
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_paddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_align: u64,
    }

    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1; // Execute permission

    // Full dl_phdr_info structure (must match system header)
    #[repr(C)]
    struct DlPhdrInfo {
        dlpi_addr: usize,
        dlpi_name: *const std::ffi::c_char,
        dlpi_phdr: *const Elf64Phdr,
        dlpi_phnum: u16,
        // Additional fields exist but we don't need them
    }

    // Result struct to pass both dlpi_addr and exec segment p_vaddr
    #[repr(C)]
    struct CallbackResult {
        dlpi_addr: usize,
        exec_segment_vaddr: usize,
        found: bool,
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
                let result_ptr = data as *mut CallbackResult;

                // Find the executable LOAD segment
                let phdr = (*info).dlpi_phdr;
                let phnum = (*info).dlpi_phnum as usize;

                let mut exec_vaddr: usize = 0;
                for i in 0..phnum {
                    let ph = &*phdr.add(i);
                    if ph.p_type == PT_LOAD && (ph.p_flags & PF_X) != 0 {
                        exec_vaddr = ph.p_vaddr as usize;
                        break;
                    }
                }

                (*result_ptr).dlpi_addr = (*info).dlpi_addr;
                (*result_ptr).exec_segment_vaddr = exec_vaddr;
                (*result_ptr).found = true;
                return 1; // Stop iteration
            }
        }
        0 // Continue
    }

    let mut result = CallbackResult {
        dlpi_addr: 0,
        exec_segment_vaddr: 0,
        found: false,
    };
    unsafe {
        dl_iterate_phdr(
            callback,
            &mut result as *mut CallbackResult as *mut std::ffi::c_void,
        );
    }

    if result.found {
        // The actual code base is dlpi_addr + exec_segment_vaddr
        // dlpi_addr is the offset applied to all segment vaddrs at load time
        // So runtime address of any symbol = dlpi_addr + symbol_vaddr
        // Since manifest stores offset = symbol_vaddr - segment_vaddr,
        // we need: runtime_addr = dlpi_addr + segment_vaddr + offset
        let code_base = result.dlpi_addr + result.exec_segment_vaddr;
        tracing::info!(
            "get_code_base_linux: found {} dlpi_addr=0x{:x}, exec_segment_vaddr=0x{:x}, code_base=0x{:x}",
            LIB_NAME,
            result.dlpi_addr,
            result.exec_segment_vaddr,
            code_base
        );
        BASE.store(code_base, Ordering::Relaxed);
        FOUND.store(true, Ordering::Relaxed);
        Some(code_base)
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

/// Get the base address of `libciris_verify_ffi` on macOS/iOS.
///
/// Iterates loaded dyld images to find our library. When loaded as a
/// framework/dylib, image 0 is the main executable (wrong base).
/// Falls back to image 0 if our library name isn't found (statically linked).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn get_code_base_macos() -> Option<usize> {
    extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_header(image_index: u32) -> *const std::ffi::c_void;
        fn _dyld_get_image_name(image_index: u32) -> *const std::ffi::c_char;
        fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
    }

    const LIB_NAME: &str = "libciris_verify_ffi";
    const FRAMEWORK_NAME: &str = "CIRISVerify";

    unsafe {
        let count = _dyld_image_count();
        tracing::info!(
            "get_code_base_macos: searching {} loaded images for {}",
            count,
            LIB_NAME
        );

        // First pass: find our library by name
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(name_ptr);
            let name_str = name.to_string_lossy();

            // Log first 5 images and any matching ones for diagnostics
            if i < 5 || name_str.contains(LIB_NAME) || name_str.contains(FRAMEWORK_NAME) {
                let header = _dyld_get_image_header(i);
                let slide = _dyld_get_image_vmaddr_slide(i);
                tracing::info!(
                    "get_code_base_macos: image[{}] header=0x{:x} slide=0x{:x} name={}",
                    i,
                    header as usize,
                    slide,
                    name_str
                );
            }

            if name_str.contains(LIB_NAME) || name_str.contains(FRAMEWORK_NAME) {
                let header = _dyld_get_image_header(i);
                if header.is_null() {
                    tracing::warn!(
                        "get_code_base_macos: found {} at image[{}] but header is null",
                        name_str,
                        i
                    );
                    continue;
                }
                let slide = _dyld_get_image_vmaddr_slide(i);
                // header IS the runtime address (vmaddr + slide), so use it directly.
                // Do NOT add slide again — that double-counts ASLR.
                let base = header as usize;
                tracing::info!(
                    "get_code_base_macos: FOUND at image[{}], base=0x{:x} (header=0x{:x}, slide=0x{:x})",
                    i, base, header as usize, slide
                );
                return Some(base);
            }
        }

        // Fallback: image 0 (statically linked into main executable)
        tracing::warn!(
            "get_code_base_macos: {} not found in {} images, falling back to image[0] (static linking)",
            LIB_NAME,
            count
        );
        let header = _dyld_get_image_header(0);
        if header.is_null() {
            return None;
        }
        // header already includes ASLR slide — do not add slide again
        let base = header as usize;
        tracing::info!("get_code_base_macos: fallback image[0] base=0x{:x}", base);
        Some(base)
    }
}

/// Module base + image size for Windows verification.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy)]
struct WindowsModuleInfo {
    /// Load address of the module containing CIRISVerify code (DLL or EXE).
    base: usize,
    /// Total mapped image size in bytes (0 if unavailable).
    image_size: usize,
}

/// Get the base address and image size of the module containing CIRISVerify.
///
/// Uses `GetModuleHandleExW` with `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` so we
/// resolve the **DLL** that hosts this code, not the calling executable. Manifest
/// offsets are RVAs from this base. `GetModuleInformation` then provides
/// `SizeOfImage` so callers can bounds-check every read against the mapped image.
#[cfg(target_os = "windows")]
fn get_code_base_windows() -> Option<WindowsModuleInfo> {
    use std::ptr;

    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x00000004;
    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x00000002;

    #[repr(C)]
    struct ModuleInfo {
        lp_base_of_dll: *mut std::ffi::c_void,
        size_of_image: u32,
        entry_point: *mut std::ffi::c_void,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleExW(
            dw_flags: u32,
            lp_module_name: *const u16,
            ph_module: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
    }

    #[link(name = "psapi")]
    extern "system" {
        fn GetModuleInformation(
            h_process: *mut std::ffi::c_void,
            h_module: *mut std::ffi::c_void,
            lpmodinfo: *mut ModuleInfo,
            cb: u32,
        ) -> i32;
    }

    unsafe {
        // Address inside our own module — `get_code_base_windows` itself is
        // guaranteed to live in the DLL/EXE that ships CIRISVerify.
        let addr_in_module = get_code_base_windows as *const () as *const u16;
        let mut handle: *mut std::ffi::c_void = ptr::null_mut();
        let ok = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            addr_in_module,
            &mut handle,
        );
        if ok == 0 || handle.is_null() {
            return None;
        }

        let mut info = ModuleInfo {
            lp_base_of_dll: ptr::null_mut(),
            size_of_image: 0,
            entry_point: ptr::null_mut(),
        };
        let got_info = GetModuleInformation(
            GetCurrentProcess(),
            handle,
            &mut info,
            std::mem::size_of::<ModuleInfo>() as u32,
        );
        if got_info == 0 || info.lp_base_of_dll.is_null() {
            // Fall back to the handle itself; image size unknown so reads will
            // be rejected by the bounds check.
            return Some(WindowsModuleInfo {
                base: handle as usize,
                image_size: 0,
            });
        }

        Some(WindowsModuleInfo {
            base: info.lp_base_of_dll as usize,
            image_size: info.size_of_image as usize,
        })
    }
}

/// Probe a memory range with `VirtualQuery` to confirm every page is committed
/// and readable. Returns false if any page in the range is uncommitted, guarded,
/// or has no read access. Used as a defense-in-depth crash guard before a raw
/// pointer read; complements the image-bounds check.
#[cfg(target_os = "windows")]
fn windows_range_readable(addr: usize, len: usize) -> bool {
    use std::mem;

    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    const MEM_COMMIT: u32 = 0x1000;
    const READABLE_MASK: u32 = 0x02 // PAGE_READONLY
        | 0x04   // PAGE_READWRITE
        | 0x20   // PAGE_EXECUTE_READ
        | 0x40   // PAGE_EXECUTE_READWRITE
        | 0x08   // PAGE_WRITECOPY
        | 0x80;  // PAGE_EXECUTE_WRITECOPY

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut std::ffi::c_void,
        allocation_base: *mut std::ffi::c_void,
        allocation_protect: u32,
        partition_id: u16,
        _pad: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualQuery(
            lp_address: *const std::ffi::c_void,
            lp_buffer: *mut MemoryBasicInformation,
            dw_length: usize,
        ) -> usize;
    }

    if len == 0 || addr == 0 {
        return false;
    }
    let end = match addr.checked_add(len) {
        Some(e) => e,
        None => return false,
    };

    let mut cursor = addr;
    while cursor < end {
        let mut mbi: MemoryBasicInformation = unsafe { mem::zeroed() };
        let ret = unsafe {
            VirtualQuery(
                cursor as *const std::ffi::c_void,
                &mut mbi,
                mem::size_of::<MemoryBasicInformation>(),
            )
        };
        if ret == 0 {
            return false;
        }
        if mbi.state != MEM_COMMIT
            || (mbi.protect & PAGE_NOACCESS) != 0
            || (mbi.protect & PAGE_GUARD) != 0
            || (mbi.protect & READABLE_MASK) == 0
        {
            return false;
        }
        let region_base = mbi.base_address as usize;
        let region_end = match region_base.checked_add(mbi.region_size) {
            Some(e) => e,
            None => return false,
        };
        if region_end <= cursor {
            return false;
        }
        cursor = region_end;
        // Defensive: bound iterations if VirtualQuery ever wraps.
        if cursor == 0 {
            return false;
        }
    }
    true
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

    // ===========================================================================
    // Windows-specific tests
    //
    // These exercise the bug fixed in v1.5.4: prior versions used
    // `GetModuleHandleW(NULL)` (which returns the EXE base, not the DLL hosting
    // CIRISVerify), then dereferenced `code_base + offset`. When the manifest
    // encoded RVAs from a different module, that read landed in unmapped memory
    // and faulted/stalled the tokio worker forever — the agent's
    // `has_key_sync` call would loop on -100 (ATTESTATION_IN_PROGRESS) until
    // the host process was killed.
    //
    // The fix has three parts and each gets a regression test below:
    //   1. `get_code_base_windows` resolves OUR module via FROM_ADDRESS.
    //   2. Every read is bounds-checked against `SizeOfImage`.
    //   3. Every read is probed with `VirtualQuery` first.
    // ===========================================================================

    #[cfg(target_os = "windows")]
    mod windows {
        use super::*;

        fn empty_signature() -> ManifestSignature {
            ManifestSignature {
                classical: String::new(),
                classical_algorithm: "Ed25519".to_string(),
                pqc: String::new(),
                pqc_algorithm: "ML-DSA-65".to_string(),
                key_id: "test".to_string(),
            }
        }

        fn manifest_with(functions: BTreeMap<String, FunctionEntry>) -> FunctionManifest {
            FunctionManifest {
                version: "1.0.0".to_string(),
                target: "x86_64-pc-windows-msvc".to_string(),
                binary_hash: "sha256:test".to_string(),
                binary_version: "1.5.4".to_string(),
                generated_at: "2026-04-14T00:00:00Z".to_string(),
                functions,
                manifest_hash: String::new(),
                signature: empty_signature(),
                metadata: ManifestMetadata::default(),
            }
        }

        #[test]
        fn get_code_base_windows_returns_our_module() {
            // Resolves the test binary itself, not the calling executable.
            let info =
                get_code_base_windows().expect("module info must be available in-process");
            assert!(info.base != 0, "module base should be non-zero");
            assert!(
                info.image_size > 0,
                "image size should be populated by GetModuleInformation"
            );

            // The address of `get_code_base_windows` itself MUST live inside
            // the reported module range — that's the whole point of using
            // FROM_ADDRESS. If this fails, we resolved the wrong module.
            let fn_addr = get_code_base_windows as *const () as usize;
            assert!(
                fn_addr >= info.base && fn_addr < info.base + info.image_size,
                "function address 0x{:x} must lie within module image \
                 [0x{:x}..0x{:x})",
                fn_addr,
                info.base,
                info.base + info.image_size,
            );
        }

        #[test]
        fn windows_range_readable_accepts_stack_memory() {
            let buf = [0u8; 64];
            let addr = buf.as_ptr() as usize;
            assert!(windows_range_readable(addr, buf.len()));
        }

        #[test]
        fn windows_range_readable_rejects_null_and_zero_len() {
            assert!(!windows_range_readable(0, 16));
            assert!(!windows_range_readable(0x1000, 0));
        }

        #[test]
        fn windows_range_readable_rejects_unmapped_address() {
            // A canonical low address that's reserved on Windows and not
            // committed for any normal process. `VirtualQuery` either reports
            // the region as MEM_FREE/MEM_RESERVE or fails outright.
            assert!(!windows_range_readable(0x0001_0000, 16));
        }

        #[test]
        fn windows_range_readable_rejects_address_space_overflow() {
            // addr + len wraps — must reject without dereferencing.
            assert!(!windows_range_readable(usize::MAX - 4, 16));
        }

        #[test]
        fn verify_functions_rejects_oob_offsets_without_hanging() {
            // Regression test for the v1.5.3 hang. A manifest whose offsets
            // are absolute VAs (not RVAs) used to slip through and trigger an
            // unbounded read at `code_base + 0x1574c0`. The fix: bounds-check
            // against image size and surface "manifest" failure.
            //
            // The real failure mode in v1.5.3 happened because
            // `GetModuleHandleW(NULL)` returned the EXE base, then
            // EXE_base + DLL_RVA fell inside the EXE's image only by
            // coincidence — and when it didn't, the read faulted and the
            // tokio worker stalled. Test EXEs built by `cargo test` are huge
            // (multiple MB), so we can't hard-code a "definitely OOB" offset
            // — derive it from the actual `image_size` so the test holds for
            // any future test-binary layout.
            let module = get_code_base_windows().expect("module info");
            let oob_base = (module.image_size as u64).saturating_add(0x1_0000);

            let mut functions = BTreeMap::new();
            for (i, name) in [
                "ciris_verify_app_attest",
                "ciris_verify_app_attest_assertion",
                "ciris_verify_audit_trail",
            ]
            .iter()
            .enumerate()
            {
                functions.insert(
                    name.to_string(),
                    FunctionEntry {
                        name: name.to_string(),
                        offset: oob_base + (i as u64 * 0x3000),
                        size: 256,
                        hash: format!("sha256:{:0>64x}", i),
                        first_bytes: String::new(),
                    },
                );
            }
            let manifest = manifest_with(functions);

            let start = std::time::Instant::now();
            let result = verify_functions(&manifest);
            let elapsed = start.elapsed();

            assert!(!result.integrity_valid);
            assert_eq!(result.functions_checked, 3);
            assert_eq!(result.functions_passed, 0);
            assert_eq!(
                result.failure_reason, "manifest",
                "all-OOB manifest must surface as 'manifest', not 'mismatch'"
            );
            assert!(
                elapsed.as_secs() < 2,
                "verify_functions took {:?} — bounds check should fail \
                 instantly, not stall on a fault",
                elapsed
            );
        }

        #[test]
        fn verify_functions_distinguishes_partial_oob_as_mismatch() {
            // One in-bounds entry (whose bytes won't hash-match anything
            // real) + one definitely-OOB entry. Failure reason must be
            // "mismatch", not "manifest" — the manifest format itself is
            // plausible; only one entry is bogus.
            let module = get_code_base_windows().expect("module info");
            // PE images on x86_64 always reserve at least the headers in the
            // first page; pick an offset well into the .text region.
            assert!(
                module.image_size > 0x2000,
                "test binary unexpectedly small"
            );
            let in_bounds_offset = 0x1000_u64;
            let oob_offset = (module.image_size as u64).saturating_add(0x10_0000);

            let mut functions = BTreeMap::new();
            functions.insert(
                "in_bounds_but_wrong_hash".to_string(),
                FunctionEntry {
                    name: "in_bounds_but_wrong_hash".to_string(),
                    offset: in_bounds_offset,
                    size: 16,
                    hash: format!("sha256:{:0>64}", "deadbeef"),
                    first_bytes: String::new(),
                },
            );
            functions.insert(
                "way_out_of_bounds".to_string(),
                FunctionEntry {
                    name: "way_out_of_bounds".to_string(),
                    offset: oob_offset,
                    size: 256,
                    hash: format!("sha256:{:0>64}", "feedface"),
                    first_bytes: String::new(),
                },
            );
            let manifest = manifest_with(functions);

            let result = verify_functions(&manifest);
            assert!(!result.integrity_valid);
            assert_eq!(
                result.failure_reason, "mismatch",
                "mixed pass/OOB must report 'mismatch' so callers can tell \
                 it apart from a wholesale-bogus manifest"
            );
        }

        #[test]
        fn verify_functions_handles_empty_manifest() {
            let result = verify_functions(&manifest_with(BTreeMap::new()));
            // Vacuously valid: no functions checked, none failed.
            assert!(result.integrity_valid);
            assert_eq!(result.functions_checked, 0);
            assert_eq!(result.functions_passed, 0);
            assert!(result.failure_reason.is_empty());
        }
    }
}
