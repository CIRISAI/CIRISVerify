//! # ciris-verify-ffi
//!
//! C-compatible FFI interface for CIRISVerify.
//!
//! This crate provides a stable C ABI for integrating CIRISVerify into
//! applications written in any language that can call C functions.
//!
//! ## Usage
//!
//! ```c
//! #include "ciris_verify.h"
//!
//! int main() {
//!     // Initialize
//!     CirisVerifyHandle handle = ciris_verify_init();
//!     if (!handle) {
//!         return 1;
//!     }
//!
//!     // Build request
//!     uint8_t nonce[32];
//!     // ... fill with random bytes ...
//!
//!     uint8_t* response_data = NULL;
//!     size_t response_len = 0;
//!
//!     // Get license status
//!     int result = ciris_verify_get_status(
//!         handle,
//!         request_data, request_len,
//!         &response_data, &response_len
//!     );
//!
//!     if (result == 0) {
//!         // Parse response (protobuf)
//!         // ...
//!         ciris_verify_free(response_data);
//!     }
//!
//!     // Cleanup
//!     ciris_verify_destroy(handle);
//!     return 0;
//! }
//! ```

#![allow(clippy::missing_safety_doc)] // FFI functions are inherently unsafe

mod constructor;

#[cfg(target_os = "android")]
mod android_sync;

use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Once};

use ciris_keyring::MutableEd25519Signer;
use ciris_verify_core::config::VerifyConfig;
use ciris_verify_core::license::LicenseStatus;
use ciris_verify_core::types::{
    DisclosureSeverity, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    ResponseAttestation, ResponseMetadata, ResponseSignature, SourceResult, ValidationResults,
    ValidationStatus,
};
use ciris_verify_core::unified::{
    FullAttestationRequest, FullAttestationResult, UnifiedAttestationEngine,
};
use ciris_verify_core::LicenseEngine;
use tokio::runtime::Runtime;

/// Get the default path to the agent signing key file.
///
/// Checks multiple locations in priority order:
/// 1. `$CIRIS_KEY_PATH` environment variable
/// 2. `./agent_signing.key` (current directory)
/// 3. `~/.ciris/agent_signing.key` (user home)
/// 4. `/etc/ciris/agent_signing.key` (system-wide on Unix)
fn find_agent_signing_key() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(path) = std::env::var("CIRIS_KEY_PATH") {
        let p = PathBuf::from(path);
        if p.exists() {
            tracing::info!("Found agent key at CIRIS_KEY_PATH: {}", p.display());
            return Some(p);
        }
    }

    // Check current directory
    let cwd = PathBuf::from("agent_signing.key");
    if cwd.exists() {
        tracing::info!("Found agent key in current directory: {}", cwd.display());
        return Some(cwd);
    }

    // Check user home directory
    if let Some(home) = dirs_home() {
        let user_key = home.join(".ciris").join("agent_signing.key");
        if user_key.exists() {
            tracing::info!("Found agent key in user home: {}", user_key.display());
            return Some(user_key);
        }
    }

    // Check system-wide location (Unix only)
    #[cfg(unix)]
    {
        let system_key = PathBuf::from("/etc/ciris/agent_signing.key");
        if system_key.exists() {
            tracing::info!("Found agent key in /etc/ciris: {}", system_key.display());
            return Some(system_key);
        }
    }

    tracing::debug!("No agent_signing.key found in any standard location");
    None
}

/// Get the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Try to auto-import the agent signing key from a file.
///
/// Reads the key file and imports it into the Ed25519 signer.
/// Supports both raw 32-byte keys and base64-encoded keys.
fn try_auto_import_key(signer: &MutableEd25519Signer, path: &PathBuf) -> bool {
    tracing::info!("Attempting to auto-import key from: {}", path.display());

    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to read key file {}: {}", path.display(), e);
            return false;
        },
    };

    // Try to parse as raw 32-byte key first
    if content.len() == 32 {
        match signer.import_key(&content) {
            Ok(()) => {
                tracing::info!("Auto-imported 32-byte raw Ed25519 key");
                return true;
            },
            Err(e) => {
                tracing::warn!("Failed to import raw key: {}", e);
            },
        }
    }

    // Try to parse as base64 (with optional newlines/whitespace)
    let cleaned: String = content
        .iter()
        .filter_map(|&b| {
            let c = b as char;
            if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
                Some(c)
            } else {
                None
            }
        })
        .collect();

    if let Ok(decoded) = base64_decode(&cleaned) {
        if decoded.len() == 32 {
            match signer.import_key(&decoded) {
                Ok(()) => {
                    tracing::info!("Auto-imported base64-encoded Ed25519 key");
                    return true;
                },
                Err(e) => {
                    tracing::warn!("Failed to import base64 key: {}", e);
                },
            }
        } else {
            tracing::warn!(
                "Base64 decoded key is {} bytes (expected 32)",
                decoded.len()
            );
        }
    }

    // Try hex format
    let hex_str: String = content
        .iter()
        .filter_map(|&b| {
            let c = b as char;
            if c.is_ascii_hexdigit() {
                Some(c.to_ascii_lowercase())
            } else {
                None
            }
        })
        .collect();

    if hex_str.len() == 64 {
        if let Ok(decoded) = hex::decode(&hex_str) {
            match signer.import_key(&decoded) {
                Ok(()) => {
                    tracing::info!("Auto-imported hex-encoded Ed25519 key");
                    return true;
                },
                Err(e) => {
                    tracing::warn!("Failed to import hex key: {}", e);
                },
            }
        }
    }

    tracing::warn!(
        "Could not parse key file {} (tried raw, base64, hex formats)",
        path.display()
    );
    false
}

/// Simple base64 decoder (avoiding additional dependencies).
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn char_to_val(c: char) -> Result<u8, &'static str> {
        if let Some(pos) = ALPHABET.iter().position(|&b| b as char == c) {
            Ok(pos as u8)
        } else if c == '=' {
            Ok(0) // Padding
        } else {
            Err("Invalid base64 character")
        }
    }

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let chars: Vec<char> = input.chars().collect();
    for chunk in chars.chunks(4) {
        let vals: Result<Vec<u8>, _> = chunk.iter().map(|&c| char_to_val(c)).collect();
        let vals = vals?;

        if vals.len() >= 2 {
            output.push((vals[0] << 2) | (vals[1] >> 4));
        }
        if vals.len() >= 3 {
            output.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if vals.len() >= 4 {
            output.push((vals[2] << 6) | vals[3]);
        }
    }

    Ok(output)
}

/// Ensure tracing is initialized exactly once.
static TRACING_INIT: Once = Once::new();

/// Opaque handle to the CIRISVerify instance.
#[repr(C)]
pub struct CirisVerifyHandle {
    runtime: Runtime,
    engine: Arc<LicenseEngine>,
    /// Optional Ed25519 signer for Portal-issued keys.
    /// This is separate from the hardware signer and used for agent identity.
    ed25519_signer: MutableEd25519Signer,
}

/// Error codes returned by FFI functions.
#[repr(C)]
pub enum CirisVerifyError {
    /// Success.
    Success = 0,
    /// Invalid argument.
    InvalidArgument = -1,
    /// Initialization failed.
    InitializationFailed = -2,
    /// Request failed.
    RequestFailed = -3,
    /// Serialization error.
    SerializationError = -4,
    /// Internal error.
    InternalError = -99,
}

/// Initialize the CIRISVerify module.
///
/// Returns a handle that must be passed to all other functions.
/// Returns NULL on failure.
///
/// # Safety
///
/// The returned handle must be freed with `ciris_verify_destroy`.
#[no_mangle]
pub extern "C" fn ciris_verify_init() -> *mut CirisVerifyHandle {
    // Initialize logging for the platform (exactly once)
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("CIRISVerify"),
        );
    }

    #[cfg(target_os = "ios")]
    {
        TRACING_INIT.call_once(|| {
            // On iOS, use oslog to write to the unified logging system (Console.app)
            oslog::OsLogger::new("ai.ciris.verify")
                .level_filter(log::LevelFilter::Info)
                .init()
                .ok();
        });
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        TRACING_INIT.call_once(|| {
            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .init();
        });
    }

    tracing::info!(
        "CIRISVerify FFI init starting (v{})",
        env!("CARGO_PKG_VERSION")
    );

    // Create tokio runtime
    // On Android, we MUST use current_thread runtime because:
    // 1. JNI threads have special characteristics
    // 2. Multi-threaded runtime spawns worker threads that aren't JNI-attached
    // 3. Those worker threads hang when trying to do I/O operations
    tracing::info!("Creating async runtime");
    #[cfg(target_os = "android")]
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("Failed to create tokio runtime: {}", e);
            return ptr::null_mut();
        },
    };
    #[cfg(not(target_os = "android"))]
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("Failed to create tokio runtime: {}", e);
            return ptr::null_mut();
        },
    };

    // Initialize the engine
    tracing::info!("Initializing license engine");
    let engine = match LicenseEngine::new() {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            tracing::error!("Failed to initialize license engine: {}", e);
            return ptr::null_mut();
        },
    };

    // Create Ed25519 signer for Portal-issued keys
    // Note: MutableEd25519Signer::new() automatically attempts to load persisted keys
    let ed25519_signer = MutableEd25519Signer::new("agent_signing");

    // Log comprehensive diagnostics for debugging key persistence issues
    tracing::info!("Ed25519 signer initialized");
    tracing::info!("{}", ed25519_signer.diagnostics());

    // Check if key was loaded from persistence
    if ed25519_signer.has_key() {
        tracing::info!(
            "✓ Portal key loaded from persistent storage at {:?}",
            ed25519_signer.current_storage_path()
        );
    } else {
        tracing::info!(
            "No persisted Portal key found. Key will be stored at {:?} after import.",
            ed25519_signer.current_storage_path().or_else(|| {
                // Trigger path calculation if not set
                let _ = ed25519_signer.diagnostics();
                ed25519_signer.current_storage_path()
            })
        );

        // Legacy auto-migration: try to import agent_signing.key if found in old locations
        if let Some(key_path) = find_agent_signing_key() {
            tracing::info!(
                "Found legacy agent_signing.key at {}, attempting migration...",
                key_path.display()
            );
            if try_auto_import_key(&ed25519_signer, &key_path) {
                tracing::info!(
                    "✓ Successfully migrated agent key from {} to new storage",
                    key_path.display()
                );
            } else {
                tracing::warn!(
                    "Failed to migrate agent_signing.key from {}",
                    key_path.display()
                );
            }
        }
    }

    tracing::info!("CIRISVerify FFI init complete — handle ready");
    let handle = Box::new(CirisVerifyHandle {
        runtime,
        engine,
        ed25519_signer,
    });
    Box::into_raw(handle)
}

/// Build a timeout response when the hard timeout fires.
///
/// Returns a valid LicenseStatusResponse with error details so the client
/// knows what happened instead of just getting a Python-level timeout.
fn build_timeout_response(_request: &LicenseStatusRequest) -> LicenseStatusResponse {
    use ciris_keyring::{PlatformAttestation, SoftwareAttestation};

    let now = chrono::Utc::now().timestamp();

    LicenseStatusResponse {
        status: LicenseStatus::ErrorVerificationFailed,
        license: None,
        mandatory_disclosure: MandatoryDisclosure {
            text: "License verification timed out. Network operations blocked for 15+ seconds. \
                   Operating in COMMUNITY MODE with restricted capabilities."
                .to_string(),
            severity: DisclosureSeverity::Warning,
            locale: "en".to_string(),
        },
        attestation: ResponseAttestation {
            platform: PlatformAttestation::Software(SoftwareAttestation {
                key_derivation: "none".to_string(),
                storage: "none".to_string(),
                security_warning: "Timeout - no attestation available".to_string(),
            }),
            signature: ResponseSignature {
                classical: Vec::new(),
                classical_algorithm: "none".to_string(),
                pqc: Vec::new(),
                pqc_algorithm: "none".to_string(),
                pqc_public_key: Vec::new(),
                signature_mode: "Unavailable".to_string(),
            },
            integrity_valid: false,
            timestamp: now,
        },
        validation: ValidationResults {
            dns_us: SourceResult {
                source: "us.registry.ciris-services-1.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: now,
                error: Some("Hard timeout: network stack blocked".to_string()),
                error_category: Some("hard_timeout".to_string()),
                error_details: Some(
                    "FFI layer 15s timeout fired - network operations blocked indefinitely"
                        .to_string(),
                ),
            },
            dns_eu: SourceResult {
                source: "eu.registry.ciris-services-1.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: now,
                error: Some("Hard timeout: network stack blocked".to_string()),
                error_category: Some("hard_timeout".to_string()),
                error_details: Some(
                    "FFI layer 15s timeout fired - network operations blocked indefinitely"
                        .to_string(),
                ),
            },
            https: SourceResult {
                source: "api.registry.ciris-services-1.ai".to_string(),
                reachable: false,
                valid: false,
                checked_at: now,
                error: Some("Hard timeout: network stack blocked".to_string()),
                error_category: Some("hard_timeout".to_string()),
                error_details: Some(
                    "FFI layer 15s timeout fired - network operations blocked indefinitely"
                        .to_string(),
                ),
            },
            overall: ValidationStatus::NoSourcesReachable,
        },
        metadata: ResponseMetadata {
            protocol_version: "2.0.0".to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: now,
            cache_ttl: 60, // Short TTL - retry soon
            request_id: format!("timeout-{}", now),
        },
        runtime_validation: None,
        shutdown_directive: None,
        function_integrity: None, // Will be filled in by caller
        binary_integrity: None,   // Timeout - no verification performed
    }
}

/// Get the current license status.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `request_data` - Serialized `LicenseStatusRequest` protobuf
/// * `request_len` - Length of request data
/// * `response_data` - Output pointer for response data (caller must free with `ciris_verify_free`)
/// * `response_len` - Output pointer for response length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `request_data` must point to valid memory of at least `request_len` bytes
/// - `response_data` and `response_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_status(
    handle: *mut CirisVerifyHandle,
    request_data: *const u8,
    request_len: usize,
    response_data: *mut *mut u8,
    response_len: *mut usize,
) -> i32 {
    tracing::debug!(
        "ciris_verify_get_status called (request_len={})",
        request_len
    );

    // Validate arguments
    if handle.is_null()
        || request_data.is_null()
        || response_data.is_null()
        || response_len.is_null()
    {
        tracing::error!("ciris_verify_get_status: invalid arguments (null pointer)");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let request_bytes = std::slice::from_raw_parts(request_data, request_len);

    // Deserialize request
    let request: ciris_verify_core::LicenseStatusRequest =
        match serde_json::from_slice(request_bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Failed to deserialize request: {}", e);
                return CirisVerifyError::SerializationError as i32;
            },
        };

    // Execute request with THREAD-BASED 15s timeout
    // Timeout handling differs by platform:
    // - Android: Run directly on JNI thread with tokio timeout (worker threads hang)
    // - Other platforms: Use worker thread for hard timeout (can interrupt blocking syscalls)
    tracing::info!("FFI: Starting get_license_status with 15s timeout");
    let start = std::time::Instant::now();

    #[cfg(target_os = "android")]
    let mut response = {
        // On Android, bypass tokio entirely and use blocking I/O.
        // Tokio's async I/O doesn't work on Android JNI threads because the
        // event loop/epoll doesn't poll correctly in the JNI context.
        tracing::info!("FFI (Android): Using blocking I/O (ureq) - bypassing tokio");
        let result = android_sync::get_license_status_blocking(
            &request,
            std::time::Duration::from_secs(10),
        );
        tracing::info!("FFI (Android): Blocking call completed in {:?}", start.elapsed());
        result
    };

    #[cfg(not(target_os = "android"))]
    let mut response = {
        // On non-Android platforms, use worker thread for hard timeout.
        // tokio::time::timeout can't interrupt blocking syscalls, so we use a real thread timeout.
        let (tx, rx) = std::sync::mpsc::channel();
        let request_clone = request.clone();

        // Convert pointer to usize for thread safety - SAFETY:
        // 1. The handle outlives this function call (it's from ciris_verify_init)
        // 2. We only read from it (no mutation)
        // 3. If timeout fires, worker thread continues but result is dropped
        // 4. The handle contains thread-safe internals (Runtime, Engine)
        let handle_addr = handle as *const CirisVerifyHandle as usize;

        // Spawn worker thread
        std::thread::spawn(move || {
            // SAFETY: handle_addr was valid when we captured it, and the handle
            // outlives this FFI call. We reconstruct the pointer here.
            let handle = unsafe { &*(handle_addr as *const CirisVerifyHandle) };

            tracing::info!("FFI worker thread: starting engine call");
            let result = handle
                .runtime
                .block_on(async { handle.engine.get_license_status(request_clone).await });
            tracing::info!("FFI worker thread: engine call complete");

            // Send result - if receiver is gone (timeout), this just fails silently
            let _ = tx.send(result);
        });

        // Wait for result with timeout
        match rx.recv_timeout(std::time::Duration::from_secs(15)) {
            Ok(Ok(r)) => {
                tracing::info!("FFI: get_license_status completed in {:?}", start.elapsed());
                r
            },
            Ok(Err(e)) => {
                tracing::error!("FFI: Request failed after {:?}: {}", start.elapsed(), e);
                return CirisVerifyError::RequestFailed as i32;
            },
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // THREAD-BASED timeout fired - the worker thread is abandoned
                tracing::error!(
                    "FFI: THREAD TIMEOUT after {:?} - worker thread abandoned",
                    start.elapsed()
                );
                build_timeout_response(&request)
            },
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Worker thread panicked or dropped sender
                tracing::error!("FFI: Worker thread died unexpectedly");
                build_timeout_response(&request)
            },
        }
    };

    // Add function integrity status (v0.6.0)
    response.function_integrity = Some(constructor::get_function_integrity_status().to_string());

    // Serialize response
    let response_bytes = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize response: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy response
    let len = response_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(response_bytes.as_ptr(), ptr, len);

    *response_data = ptr;
    *response_len = len;

    CirisVerifyError::Success as i32
}

/// Check if a specific capability is allowed.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `capability` - Capability identifier (null-terminated string)
/// * `action` - Action requiring the capability (null-terminated string)
/// * `required_tier` - Required autonomy tier (0-4)
/// * `allowed` - Output: 1 if allowed, 0 if denied
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_check_capability(
    handle: *mut CirisVerifyHandle,
    capability: *const libc::c_char,
    action: *const libc::c_char,
    required_tier: i32,
    allowed: *mut i32,
) -> i32 {
    tracing::debug!(
        "ciris_verify_check_capability called (tier={})",
        required_tier
    );

    if handle.is_null() || capability.is_null() || action.is_null() || allowed.is_null() {
        tracing::error!("ciris_verify_check_capability: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    let capability_str = match std::ffi::CStr::from_ptr(capability).to_str() {
        Ok(s) => s,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };

    let action_str = match std::ffi::CStr::from_ptr(action).to_str() {
        Ok(s) => s,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };

    let result = match handle.runtime.block_on(handle.engine.check_capability(
        capability_str,
        action_str,
        required_tier as u8,
    )) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Capability check failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    *allowed = if result.allowed { 1 } else { 0 };
    CirisVerifyError::Success as i32
}

/// Free memory allocated by CIRISVerify functions.
///
/// # Safety
///
/// `data` must be a pointer returned by a CIRISVerify function, or NULL.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_free(data: *mut c_void) {
    if !data.is_null() {
        libc::free(data);
    }
}

/// Destroy the CIRISVerify handle and release resources.
///
/// # Safety
///
/// `handle` must be a valid handle from `ciris_verify_init`.
/// After this call, the handle is invalid and must not be used.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_destroy(handle: *mut CirisVerifyHandle) {
    tracing::info!("ciris_verify_destroy called");
    if !handle.is_null() {
        drop(Box::from_raw(handle));
        tracing::info!("CIRISVerify handle destroyed");
    }
}

/// Check agent file integrity (Tripwire-style).
///
/// Validates that CIRISAgent Python files have not been modified since
/// the distribution was built. ANY unauthorized change triggers a forced
/// shutdown directive.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `manifest_data` - JSON-encoded file manifest
/// * `manifest_len` - Length of manifest data
/// * `agent_root` - Path to agent root directory (null-terminated string)
/// * `spot_check_count` - Number of files to spot-check (0 = full check)
/// * `response_data` - Output pointer for JSON response (caller must free with `ciris_verify_free`)
/// * `response_len` - Output pointer for response length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
/// Note: success means the check completed, NOT that integrity passed.
/// Check the `integrity_valid` field in the response.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `manifest_data` must point to valid memory of at least `manifest_len` bytes
/// - `agent_root` must be a valid null-terminated UTF-8 string
/// - `response_data` and `response_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_check_agent_integrity(
    handle: *mut CirisVerifyHandle,
    manifest_data: *const u8,
    manifest_len: usize,
    agent_root: *const libc::c_char,
    spot_check_count: u32,
    response_data: *mut *mut u8,
    response_len: *mut usize,
) -> i32 {
    tracing::debug!(
        "ciris_verify_check_agent_integrity called (manifest_len={}, spot_check={})",
        manifest_len,
        spot_check_count
    );

    if handle.is_null()
        || manifest_data.is_null()
        || agent_root.is_null()
        || response_data.is_null()
        || response_len.is_null()
    {
        tracing::error!("ciris_verify_check_agent_integrity: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let _handle = &*handle;
    let manifest_bytes = std::slice::from_raw_parts(manifest_data, manifest_len);

    // Parse manifest
    let manifest: ciris_verify_core::FileManifest = match serde_json::from_slice(manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to parse manifest: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Parse agent root path
    let root_str = match std::ffi::CStr::from_ptr(agent_root).to_str() {
        Ok(s) => s,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };
    let root_path = std::path::Path::new(root_str);

    // Perform check
    let result = if spot_check_count == 0 {
        ciris_verify_core::check_agent_integrity(&manifest, root_path)
    } else {
        ciris_verify_core::spot_check_agent_integrity(
            &manifest,
            root_path,
            spot_check_count as usize,
        )
    };

    // Serialize response
    let response_bytes = match serde_json::to_vec(&result) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize integrity result: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy response
    let len = response_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(response_bytes.as_ptr(), ptr, len);

    *response_data = ptr;
    *response_len = len;

    CirisVerifyError::Success as i32
}

/// Sign data using the hardware-bound private key.
///
/// This is the vault-style signing interface: the agent delegates signing
/// to CIRISVerify, which uses the hardware security module. The private
/// key never leaves the secure hardware.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `data` - Data to sign
/// * `data_len` - Length of data
/// * `signature_data` - Output pointer for signature (caller must free with `ciris_verify_free`)
/// * `signature_len` - Output pointer for signature length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `data` must point to valid memory of at least `data_len` bytes
/// - `signature_data` and `signature_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_sign(
    handle: *mut CirisVerifyHandle,
    data: *const u8,
    data_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_sign called (data_len={})", data_len);

    if handle.is_null() || data.is_null() || signature_data.is_null() || signature_len.is_null() {
        tracing::error!("ciris_verify_sign: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let data_bytes = std::slice::from_raw_parts(data, data_len);

    // Sign using the hardware signer
    let sig = match handle.runtime.block_on(handle.engine.sign(data_bytes)) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Signing failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Allocate and copy signature
    let len = sig.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(sig.as_ptr(), ptr, len);

    *signature_data = ptr;
    *signature_len = len;

    CirisVerifyError::Success as i32
}

/// Get the public key from the hardware-bound keypair.
///
/// Returns the public key bytes that can be registered with external
/// services for signature verification.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_data` - Output pointer for public key bytes (caller must free with `ciris_verify_free`)
/// * `key_len` - Output pointer for key length
/// * `algorithm` - Output pointer for algorithm name (caller must free with `ciris_verify_free`)
/// * `algorithm_len` - Output pointer for algorithm name length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - All output pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_public_key(
    handle: *mut CirisVerifyHandle,
    key_data: *mut *mut u8,
    key_len: *mut usize,
    algorithm: *mut *mut u8,
    algorithm_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_get_public_key called");

    if handle.is_null()
        || key_data.is_null()
        || key_len.is_null()
        || algorithm.is_null()
        || algorithm_len.is_null()
    {
        tracing::error!("ciris_verify_get_public_key: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    // Get public key
    let pubkey = match handle.runtime.block_on(handle.engine.public_key()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to get public key: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Get algorithm name
    let algo_str = handle.engine.algorithm_name();
    let algo_bytes = algo_str.as_bytes();

    // Allocate and copy public key
    let pk_len = pubkey.len();
    let pk_ptr = libc::malloc(pk_len) as *mut u8;
    if pk_ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }
    std::ptr::copy_nonoverlapping(pubkey.as_ptr(), pk_ptr, pk_len);

    // Allocate and copy algorithm name
    let al_len = algo_bytes.len();
    let al_ptr = libc::malloc(al_len) as *mut u8;
    if al_ptr.is_null() {
        libc::free(pk_ptr as *mut libc::c_void);
        return CirisVerifyError::InternalError as i32;
    }
    std::ptr::copy_nonoverlapping(algo_bytes.as_ptr(), al_ptr, al_len);

    *key_data = pk_ptr;
    *key_len = pk_len;
    *algorithm = al_ptr;
    *algorithm_len = al_len;

    CirisVerifyError::Success as i32
}

/// Export a remote attestation proof for third-party verification.
///
/// The proof contains Ed25519 signature over the challenge. This function
/// supports a two-phase attestation flow:
///
/// **Phase 1 (pre-key):** If no Portal key is loaded, generates an ephemeral
/// Ed25519 key and uses it for signing. The proof will have `key_type: "ephemeral"`.
///
/// **Phase 2 (post-key):** After importing a Portal-issued key via `import_key`,
/// uses that key for signing. The proof will have `key_type: "portal"`.
///
/// Portal uses the second attestation to create a tamper-evident binding between
/// the agent instance and its identity key. Key reuse across agents is forbidden
/// and results in immediate revocation.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `challenge` - Verifier-provided challenge nonce (must be >= 32 bytes)
/// * `challenge_len` - Length of challenge
/// * `proof_data` - Output pointer for JSON-encoded AttestationProof (caller must free with `ciris_verify_free`)
/// * `proof_len` - Output pointer for proof length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `challenge` must point to valid memory of at least `challenge_len` bytes
/// - `proof_data` and `proof_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_export_attestation(
    handle: *mut CirisVerifyHandle,
    challenge: *const u8,
    challenge_len: usize,
    proof_data: *mut *mut u8,
    proof_len: *mut usize,
) -> i32 {
    tracing::debug!(
        "ciris_verify_export_attestation called (challenge_len={})",
        challenge_len
    );

    if handle.is_null() || challenge.is_null() || proof_data.is_null() || proof_len.is_null() {
        tracing::error!("ciris_verify_export_attestation: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if challenge_len < 32 {
        tracing::error!(
            "ciris_verify_export_attestation: challenge too short ({} < 32)",
            challenge_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let challenge_bytes = std::slice::from_raw_parts(challenge, challenge_len);

    // Determine key type and ensure we have a key to sign with
    let (key_type, public_key) = if handle.ed25519_signer.has_key() {
        // Portal key is loaded - use it (Phase 2 attestation)
        tracing::info!("Using Portal-issued Ed25519 key for attestation");
        let pk = match handle.ed25519_signer.get_public_key() {
            Some(pk) => pk,
            None => {
                tracing::error!("Ed25519 key loaded but public key unavailable");
                return CirisVerifyError::InternalError as i32;
            },
        };
        ("portal".to_string(), pk)
    } else {
        // No Portal key yet - generate ephemeral key (Phase 1 attestation)
        tracing::info!(
            "No Portal key loaded, generating ephemeral Ed25519 key for initial attestation"
        );

        // Generate random 32-byte seed for ephemeral key
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap_or_else(|_| {
            // Fallback to less secure random if getrandom fails
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            for (i, byte) in seed.iter_mut().enumerate() {
                *byte = ((nanos >> (i % 16)) & 0xFF) as u8;
            }
        });

        // Import ephemeral key
        if let Err(e) = handle.ed25519_signer.import_key(&seed) {
            tracing::error!("Failed to generate ephemeral key: {}", e);
            return CirisVerifyError::InternalError as i32;
        }

        let pk = match handle.ed25519_signer.get_public_key() {
            Some(pk) => pk,
            None => {
                tracing::error!("Ephemeral key generated but public key unavailable");
                return CirisVerifyError::InternalError as i32;
            },
        };
        ("ephemeral".to_string(), pk)
    };

    // Sign the challenge with Ed25519 key
    let classical_signature = match handle.ed25519_signer.sign(challenge_bytes) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!("Ed25519 signing failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    tracing::info!(
        key_type = %key_type,
        pubkey_len = public_key.len(),
        sig_len = classical_signature.len(),
        "Attestation signature generated"
    );

    // Build simplified attestation proof using Ed25519 key
    // This bypasses the engine's hardware signer requirement
    let proof = serde_json::json!({
        "platform_attestation": {
            "Software": {
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            }
        },
        "hardware_public_key": hex::encode(&public_key),
        "hardware_algorithm": "Ed25519",
        "pqc_public_key": "",
        "pqc_algorithm": "NONE",
        "challenge": hex::encode(challenge_bytes),
        "classical_signature": hex::encode(&classical_signature),
        "pqc_signature": "",
        "merkle_root": hex::encode([0u8; 32]),
        "log_entry_count": 0,
        "generated_at": chrono::Utc::now().timestamp(),
        "binary_version": env!("CARGO_PKG_VERSION"),
        "hardware_type": "SoftwareOnly",
        "running_in_vm": false,
        "key_type": key_type,
    });

    // Serialize to JSON
    let proof_bytes = match serde_json::to_vec(&proof) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize attestation proof: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = proof_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(proof_bytes.as_ptr(), ptr, len);

    *proof_data = ptr;
    *proof_len = len;

    CirisVerifyError::Success as i32
}

/// Import an Ed25519 signing key from Portal.
///
/// This function imports a 32-byte Ed25519 seed/private key issued by CIRISPortal.
/// The key is stored in memory and used for agent identity signing.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_data` - 32-byte Ed25519 seed/private key
/// * `key_len` - Length of key data (must be 32)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `key_data` must point to valid memory of at least `key_len` bytes
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_import_key(
    handle: *mut CirisVerifyHandle,
    key_data: *const u8,
    key_len: usize,
) -> i32 {
    if handle.is_null() || key_data.is_null() {
        tracing::error!("import_key: null handle or key_data");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if key_len != 32 {
        tracing::error!("import_key: invalid key length {} (expected 32)", key_len);
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let key_bytes = std::slice::from_raw_parts(key_data, key_len);

    tracing::info!("Importing Ed25519 key ({} bytes)", key_len);

    match handle.ed25519_signer.import_key(key_bytes) {
        Ok(()) => {
            tracing::info!("Ed25519 key imported successfully");
            CirisVerifyError::Success as i32
        },
        Err(e) => {
            tracing::error!("Failed to import Ed25519 key: {}", e);
            CirisVerifyError::InvalidArgument as i32
        },
    }
}

/// Check if an Ed25519 signing key is loaded.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
///
/// # Returns
///
/// 1 if a key is loaded, 0 if no key is loaded, negative on error.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_has_key(handle: *mut CirisVerifyHandle) -> i32 {
    if handle.is_null() {
        tracing::error!("has_key: null handle");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let has_key = handle.ed25519_signer.has_key();

    tracing::debug!("has_key check: {}", has_key);

    if has_key {
        1
    } else {
        0
    }
}

/// Delete the Ed25519 signing key.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_delete_key(handle: *mut CirisVerifyHandle) -> i32 {
    if handle.is_null() {
        tracing::error!("delete_key: null handle");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    tracing::info!("Deleting Ed25519 key");

    match handle.ed25519_signer.clear_key() {
        Ok(()) => {
            tracing::info!("Ed25519 key deleted successfully");
            CirisVerifyError::Success as i32
        },
        Err(e) => {
            tracing::error!("Failed to delete Ed25519 key: {}", e);
            CirisVerifyError::InternalError as i32
        },
    }
}

/// Sign data using the imported Ed25519 key.
///
/// This signs with the Portal-issued Ed25519 key (if loaded), not the
/// hardware-bound key. Use `ciris_verify_sign` for hardware signing.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `data` - Data to sign
/// * `data_len` - Length of data
/// * `signature_data` - Output pointer for signature (caller must free with `ciris_verify_free`)
/// * `signature_len` - Output pointer for signature length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `data` must point to valid memory of at least `data_len` bytes
/// - `signature_data` and `signature_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_sign_ed25519(
    handle: *mut CirisVerifyHandle,
    data: *const u8,
    data_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    if handle.is_null() || data.is_null() || signature_data.is_null() || signature_len.is_null() {
        tracing::error!("sign_ed25519: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let data_bytes = std::slice::from_raw_parts(data, data_len);

    tracing::debug!("Signing {} bytes with Ed25519 key", data_len);

    let sig = match handle.ed25519_signer.sign(data_bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Ed25519 signing failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Allocate and copy signature
    let len = sig.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("sign_ed25519: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(sig.as_ptr(), ptr, len);

    *signature_data = ptr;
    *signature_len = len;

    tracing::debug!("Ed25519 signature generated ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Get the Ed25519 public key.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_data` - Output pointer for public key bytes (caller must free with `ciris_verify_free`)
/// * `key_len` - Output pointer for key length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `key_data` and `key_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_ed25519_public_key(
    handle: *mut CirisVerifyHandle,
    key_data: *mut *mut u8,
    key_len: *mut usize,
) -> i32 {
    if handle.is_null() || key_data.is_null() || key_len.is_null() {
        tracing::error!("get_ed25519_public_key: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    let pubkey = match handle.ed25519_signer.get_public_key() {
        Some(pk) => pk,
        None => {
            tracing::error!("get_ed25519_public_key: no key loaded");
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Allocate and copy public key
    let len = pubkey.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("get_ed25519_public_key: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(pubkey.as_ptr(), ptr, len);

    *key_data = ptr;
    *key_len = len;

    tracing::debug!("Ed25519 public key returned ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Get the library version.
///
/// Returns a static string with the version number.
#[no_mangle]
pub extern "C" fn ciris_verify_version() -> *const libc::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const libc::c_char
}

/// Get diagnostic information about the Ed25519 signer state.
///
/// Returns detailed diagnostic info including:
/// - Key alias
/// - Whether key is loaded in memory
/// - Storage path for persistence
/// - Environment variables affecting storage
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `diag_data` - Output pointer for diagnostic string (caller must free with `ciris_verify_free`)
/// * `diag_len` - Output pointer for string length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `diag_data` and `diag_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_diagnostics(
    handle: *mut CirisVerifyHandle,
    diag_data: *mut *mut u8,
    diag_len: *mut usize,
) -> i32 {
    if handle.is_null() || diag_data.is_null() || diag_len.is_null() {
        tracing::error!("get_diagnostics: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let diagnostics = handle.ed25519_signer.diagnostics();
    let bytes = diagnostics.as_bytes();

    // Allocate and copy diagnostics string
    let len = bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("get_diagnostics: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);

    *diag_data = ptr;
    *diag_len = len;

    tracing::debug!("Diagnostics returned ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Run unified attestation combining all verification checks.
///
/// This is the main entry point for comprehensive agent verification:
/// - Source validation (DNS US, DNS EU, HTTPS)
/// - File integrity (full + spot check against registry manifest)
/// - Audit trail integrity (hash chain + signatures)
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `request_json` - JSON-encoded FullAttestationRequest
/// * `request_len` - Length of request JSON
/// * `result_json` - Output pointer for JSON-encoded FullAttestationResult (caller must free with `ciris_verify_free`)
/// * `result_len` - Output pointer for result length
///
/// # Request JSON Format
///
/// ```json
/// {
///   "challenge": [/* 32+ bytes as array */],
///   "agent_version": "1.0.0",        // optional
///   "agent_root": "/path/to/agent",  // optional
///   "spot_check_count": 10,          // optional, default 0
///   "audit_entries": [...],          // optional
///   "portal_key_id": "key-id",       // optional
///   "skip_registry": false,          // optional
///   "skip_file_integrity": false,    // optional
///   "skip_audit": false              // optional
/// }
/// ```
///
/// # Result JSON Format
///
/// ```json
/// {
///   "valid": true,
///   "level": 5,
///   "checks_passed": 4,
///   "checks_total": 4,
///   "sources": { "dns_us_valid": true, ... },
///   "file_integrity": { ... },
///   "audit_trail": { ... },
///   "diagnostics": "...",
///   "errors": [],
///   "timestamp": 1234567890
/// }
/// ```
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `request_json` must point to valid UTF-8 JSON of at least `request_len` bytes
/// - `result_json` and `result_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_run_attestation(
    handle: *mut CirisVerifyHandle,
    request_json: *const u8,
    request_len: usize,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!(
        "ciris_verify_run_attestation called (request_len={})",
        request_len
    );

    if handle.is_null() || request_json.is_null() || result_json.is_null() || result_len.is_null() {
        tracing::error!("ciris_verify_run_attestation: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let request_bytes = std::slice::from_raw_parts(request_json, request_len);

    // Parse request JSON
    let request_str = match std::str::from_utf8(request_bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("ciris_verify_run_attestation: invalid UTF-8: {}", e);
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    let request: FullAttestationRequest = match serde_json::from_str(request_str) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("ciris_verify_run_attestation: invalid JSON: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Validate challenge
    if request.challenge.len() < 32 {
        tracing::error!(
            "ciris_verify_run_attestation: challenge too short ({} < 32)",
            request.challenge.len()
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    // Create attestation engine with default config
    let config = VerifyConfig::default();
    let engine = match UnifiedAttestationEngine::new(config) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(
                "ciris_verify_run_attestation: failed to create engine: {}",
                e
            );
            return CirisVerifyError::InitializationFailed as i32;
        },
    };

    // Run attestation
    let result: FullAttestationResult =
        match handle.runtime.block_on(engine.run_attestation(request)) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("ciris_verify_run_attestation: attestation failed: {}", e);
                return CirisVerifyError::RequestFailed as i32;
            },
        };

    tracing::info!(
        valid = result.valid,
        level = result.level,
        checks_passed = result.checks_passed,
        checks_total = result.checks_total,
        "Unified attestation complete"
    );

    // Serialize result to JSON
    let result_bytes = match serde_json::to_vec(&result) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "ciris_verify_run_attestation: failed to serialize result: {}",
                e
            );
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = result_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("ciris_verify_run_attestation: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), ptr, len);

    *result_json = ptr;
    *result_len = len;

    CirisVerifyError::Success as i32
}

/// Verify audit trail from SQLite database and/or JSONL file.
///
/// This function reads the agent's audit trail and verifies:
/// - Hash chain integrity (each entry links to previous)
/// - Hash validity (each entry's hash matches computed hash)
/// - Genesis validity (first entry has "genesis" as previous_hash)
/// - Signature presence (optional full verification)
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init` (can be null for standalone verification)
/// * `db_path` - Path to ciris_audit.db SQLite database (null-terminated C string)
/// * `jsonl_path` - Path to audit_logs.jsonl (null-terminated C string, can be null)
/// * `portal_key_id` - Expected Portal key ID (null-terminated C string, can be null)
/// * `result_json` - Output pointer for JSON-encoded AuditVerificationResult
/// * `result_len` - Output pointer for result length
///
/// # Result JSON Format
///
/// ```json
/// {
///   "valid": true,
///   "total_entries": 1234,
///   "entries_verified": 1234,
///   "hash_chain_valid": true,
///   "signatures_valid": true,
///   "genesis_valid": true,
///   "portal_key_used": true,
///   "first_tampered_sequence": null,
///   "errors": [],
///   "verification_time_ms": 42,
///   "chain_summary": {
///     "sequence_range": [1, 1234],
///     "current_sequence": 1234,
///     "current_hash": "abc123...",
///     "oldest_entry": "2025-01-01T00:00:00Z",
///     "newest_entry": "2025-01-15T12:00:00Z"
///   }
/// }
/// ```
///
/// # Returns
///
/// 0 on success (even if audit is invalid - check result JSON), negative error code on failure.
///
/// # Safety
///
/// - `db_path` must be a valid null-terminated UTF-8 string
/// - `result_json` and `result_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_audit_trail(
    _handle: *mut CirisVerifyHandle,
    db_path: *const libc::c_char,
    jsonl_path: *const libc::c_char,
    portal_key_id: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_audit_trail called");

    if db_path.is_null() || result_json.is_null() || result_len.is_null() {
        tracing::error!("ciris_verify_audit_trail: invalid arguments (db_path or result pointers null)");
        return CirisVerifyError::InvalidArgument as i32;
    }

    // Parse db_path
    let db_path_str = match std::ffi::CStr::from_ptr(db_path).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("ciris_verify_audit_trail: invalid db_path UTF-8: {}", e);
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Parse optional jsonl_path
    let jsonl_path_opt = if jsonl_path.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(jsonl_path).to_str() {
            Ok(s) if !s.is_empty() => Some(s.to_string()),
            Ok(_) => None,
            Err(e) => {
                tracing::error!("ciris_verify_audit_trail: invalid jsonl_path UTF-8: {}", e);
                return CirisVerifyError::InvalidArgument as i32;
            },
        }
    };

    // Parse optional portal_key_id
    let portal_key_opt = if portal_key_id.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(portal_key_id).to_str() {
            Ok(s) if !s.is_empty() => Some(s.to_string()),
            Ok(_) => None,
            Err(e) => {
                tracing::error!("ciris_verify_audit_trail: invalid portal_key_id UTF-8: {}", e);
                return CirisVerifyError::InvalidArgument as i32;
            },
        }
    };

    tracing::info!(
        "Verifying audit trail: db={}, jsonl={:?}, portal_key={:?}",
        db_path_str,
        jsonl_path_opt,
        portal_key_opt
    );

    // Perform verification
    let result = if let Some(ref jsonl) = jsonl_path_opt {
        ciris_verify_core::verify_audit_full(db_path_str, Some(jsonl.as_str()), portal_key_opt)
    } else {
        ciris_verify_core::verify_audit_database(db_path_str, portal_key_opt, true)
    };

    let verification_result = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("ciris_verify_audit_trail: verification failed: {}", e);
            // Return an error result instead of failing
            ciris_verify_core::AuditVerificationResult {
                valid: false,
                total_entries: 0,
                entries_verified: 0,
                hash_chain_valid: false,
                signatures_valid: false,
                genesis_valid: false,
                portal_key_used: false,
                first_tampered_sequence: None,
                errors: vec![format!("Verification error: {}", e)],
                verification_time_ms: 0,
                chain_summary: None,
            }
        },
    };

    // Serialize result to JSON
    let result_bytes = match serde_json::to_vec(&verification_result) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("ciris_verify_audit_trail: JSON serialization failed: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy result
    let len = result_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("ciris_verify_audit_trail: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), ptr, len);

    *result_json = ptr;
    *result_len = len;

    tracing::info!(
        "Audit verification complete: valid={}, entries={}",
        verification_result.valid,
        verification_result.total_entries
    );

    CirisVerifyError::Success as i32
}

// Android JNI bindings
#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JByteArray, JClass, JString};
    use jni::sys::{jint, jlong};
    use jni::JNIEnv;

    use super::*;

    #[no_mangle]
    pub extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeInit<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> jlong {
        let handle = ciris_verify_init();
        handle as jlong
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeDestroy<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) {
        tracing::debug!("JNI: nativeDestroy called");
        ciris_verify_destroy(handle as *mut CirisVerifyHandle);
    }

    /// Get license status (returns JSON string as byte array)
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeGetStatus<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        deployment_id: JString<'local>,
        challenge_nonce: JByteArray<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeGetStatus called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeGetStatus - null handle");
            return JByteArray::default();
        }

        // Get deployment ID string
        let deployment_id_str: String = match env.get_string(&deployment_id) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get deployment_id string: {}", e);
                return JByteArray::default();
            },
        };

        // Get challenge nonce bytes
        let nonce_bytes = match env.convert_byte_array(&challenge_nonce) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert challenge nonce: {}", e);
                return JByteArray::default();
            },
        };

        // Build request JSON
        let request = serde_json::json!({
            "deployment_id": deployment_id_str,
            "challenge_nonce": nonce_bytes,
        });
        let request_bytes = match serde_json::to_vec(&request) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to serialize request: {}", e);
                return JByteArray::default();
            },
        };

        let mut response_data: *mut u8 = std::ptr::null_mut();
        let mut response_len: usize = 0;

        let result = ciris_verify_get_status(
            handle,
            request_bytes.as_ptr(),
            request_bytes.len(),
            &mut response_data,
            &mut response_len,
        );

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeGetStatus failed with code {}", result);
            return JByteArray::default();
        }

        if response_data.is_null() {
            tracing::warn!("JNI: nativeGetStatus returned null response");
            return JByteArray::default();
        }

        // Convert to Java byte array
        let slice = std::slice::from_raw_parts(response_data, response_len);
        let jarray = match env.byte_array_from_slice(slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create byte array: {}", e);
                ciris_verify_free(response_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(response_data as *mut libc::c_void);
        jarray
    }

    /// Sign data with hardware-bound key
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeSign<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        data: JByteArray<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeSign called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeSign - null handle");
            return JByteArray::default();
        }

        let data_bytes = match env.convert_byte_array(&data) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert data: {}", e);
                return JByteArray::default();
            },
        };

        let mut signature_data: *mut u8 = std::ptr::null_mut();
        let mut signature_len: usize = 0;

        let result = ciris_verify_sign(
            handle,
            data_bytes.as_ptr(),
            data_bytes.len(),
            &mut signature_data,
            &mut signature_len,
        );

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeSign failed with code {}", result);
            return JByteArray::default();
        }

        if signature_data.is_null() {
            tracing::warn!("JNI: nativeSign returned null signature");
            return JByteArray::default();
        }

        let slice = std::slice::from_raw_parts(signature_data, signature_len);
        let jarray = match env.byte_array_from_slice(slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create signature byte array: {}", e);
                ciris_verify_free(signature_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(signature_data as *mut libc::c_void);
        jarray
    }

    /// Get public key
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeGetPublicKey<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeGetPublicKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeGetPublicKey - null handle");
            return JByteArray::default();
        }

        let mut key_data: *mut u8 = std::ptr::null_mut();
        let mut key_len: usize = 0;
        let mut algorithm: *mut u8 = std::ptr::null_mut();
        let mut algorithm_len: usize = 0;

        let result = ciris_verify_get_public_key(
            handle,
            &mut key_data,
            &mut key_len,
            &mut algorithm,
            &mut algorithm_len,
        );

        // Free algorithm string (we don't use it in JNI)
        if !algorithm.is_null() {
            ciris_verify_free(algorithm as *mut libc::c_void);
        }

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeGetPublicKey failed with code {}", result);
            return JByteArray::default();
        }

        if key_data.is_null() {
            tracing::warn!("JNI: nativeGetPublicKey returned null key");
            return JByteArray::default();
        }

        let slice = std::slice::from_raw_parts(key_data, key_len);
        let jarray = match env.byte_array_from_slice(slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create public key byte array: {}", e);
                ciris_verify_free(key_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(key_data as *mut libc::c_void);
        jarray
    }

    /// Export attestation proof (returns JSON as byte array)
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeExportAttestation<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        challenge: JByteArray<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeExportAttestation called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeExportAttestation - null handle");
            return JByteArray::default();
        }

        let challenge_bytes = match env.convert_byte_array(&challenge) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert challenge: {}", e);
                return JByteArray::default();
            },
        };

        let mut proof_data: *mut u8 = std::ptr::null_mut();
        let mut proof_len: usize = 0;

        let result = ciris_verify_export_attestation(
            handle,
            challenge_bytes.as_ptr(),
            challenge_bytes.len(),
            &mut proof_data,
            &mut proof_len,
        );

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeExportAttestation failed with code {}", result);
            return JByteArray::default();
        }

        if proof_data.is_null() {
            tracing::warn!("JNI: nativeExportAttestation returned null proof");
            return JByteArray::default();
        }

        let slice = std::slice::from_raw_parts(proof_data, proof_len);
        let jarray = match env.byte_array_from_slice(slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create attestation byte array: {}", e);
                ciris_verify_free(proof_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(proof_data as *mut libc::c_void);
        jarray
    }

    /// Run unified attestation (returns JSON as byte array)
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeRunAttestation<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        request_json: JByteArray<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeRunAttestation called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeRunAttestation - null handle");
            return JByteArray::default();
        }

        let request_bytes = match env.convert_byte_array(&request_json) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert request JSON: {}", e);
                return JByteArray::default();
            },
        };

        let mut result_data: *mut u8 = std::ptr::null_mut();
        let mut result_len: usize = 0;

        let result = ciris_verify_run_attestation(
            handle,
            request_bytes.as_ptr(),
            request_bytes.len(),
            &mut result_data,
            &mut result_len,
        );

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeRunAttestation failed with code {}", result);
            return JByteArray::default();
        }

        if result_data.is_null() {
            tracing::warn!("JNI: nativeRunAttestation returned null result");
            return JByteArray::default();
        }

        let slice = std::slice::from_raw_parts(result_data, result_len);
        let jarray = match env.byte_array_from_slice(slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create attestation result byte array: {}", e);
                ciris_verify_free(result_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(result_data as *mut libc::c_void);
        jarray
    }

    /// Import Ed25519 key from Portal
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeImportKey<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        key_bytes: JByteArray<'local>,
    ) -> jint {
        tracing::debug!("JNI: nativeImportKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeImportKey - null handle");
            return -1;
        }

        let key_data = match env.convert_byte_array(&key_bytes) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert key bytes: {}", e);
                return -1;
            },
        };

        ciris_verify_import_key(handle, key_data.as_ptr(), key_data.len())
    }

    /// Check if key is loaded
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeHasKey<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> jint {
        tracing::debug!("JNI: nativeHasKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeHasKey - null handle");
            return -1;
        }

        ciris_verify_has_key(handle)
    }

    /// Delete the loaded key
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeDeleteKey<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> jint {
        tracing::debug!("JNI: nativeDeleteKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeDeleteKey - null handle");
            return -1;
        }

        ciris_verify_delete_key(handle)
    }

    /// Sign with Ed25519 key
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeSignEd25519<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        data: JByteArray<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeSignEd25519 called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeSignEd25519 - null handle");
            return JByteArray::default();
        }

        let data_bytes = match env.convert_byte_array(&data) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert data for Ed25519 sign: {}", e);
                return JByteArray::default();
            },
        };

        let mut signature_data: *mut u8 = std::ptr::null_mut();
        let mut signature_len: usize = 0;

        let result = ciris_verify_sign_ed25519(
            handle,
            data_bytes.as_ptr(),
            data_bytes.len(),
            &mut signature_data,
            &mut signature_len,
        );

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeSignEd25519 failed with code {}", result);
            return JByteArray::default();
        }

        if signature_data.is_null() {
            tracing::warn!("JNI: nativeSignEd25519 returned null signature");
            return JByteArray::default();
        }

        let slice = std::slice::from_raw_parts(signature_data, signature_len);
        let jarray = match env.byte_array_from_slice(slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create Ed25519 signature byte array: {}", e);
                ciris_verify_free(signature_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(signature_data as *mut libc::c_void);
        jarray
    }

    /// Get Ed25519 public key
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeGetEd25519PublicKey<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeGetEd25519PublicKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeGetEd25519PublicKey - null handle");
            return JByteArray::default();
        }

        let mut key_data: *mut u8 = std::ptr::null_mut();
        let mut key_len: usize = 0;

        let result = ciris_verify_get_ed25519_public_key(handle, &mut key_data, &mut key_len);

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeGetEd25519PublicKey failed with code {}", result);
            return JByteArray::default();
        }

        if key_data.is_null() {
            tracing::warn!("JNI: nativeGetEd25519PublicKey returned null key");
            return JByteArray::default();
        }

        let slice = std::slice::from_raw_parts(key_data, key_len);
        let jarray = match env.byte_array_from_slice(slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create Ed25519 public key byte array: {}", e);
                ciris_verify_free(key_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(key_data as *mut libc::c_void);
        jarray
    }

    /// Get library version
    #[no_mangle]
    pub extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeVersion<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeVersion called");

        let version = ciris_verify_version();
        if version.is_null() {
            return JByteArray::default();
        }

        let version_str = unsafe { std::ffi::CStr::from_ptr(version) };
        let version_bytes = version_str.to_bytes();

        match env.byte_array_from_slice(version_bytes) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create version byte array: {}", e);
                JByteArray::default()
            },
        }
    }
}
