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

use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Once};

use ciris_keyring::MutableEd25519Signer;
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
    tracing::info!("Creating async runtime");
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
    let ed25519_signer = MutableEd25519Signer::new("agent_signing");
    tracing::info!("Ed25519 signer initialized (no key loaded yet)");

    // Auto-migration: try to import agent_signing.key if found
    if let Some(key_path) = find_agent_signing_key() {
        if try_auto_import_key(&ed25519_signer, &key_path) {
            tracing::info!("Auto-migrated agent key from {}", key_path.display());
        } else {
            tracing::warn!(
                "Found agent_signing.key at {} but failed to import",
                key_path.display()
            );
        }
    } else {
        tracing::debug!("No agent_signing.key found for auto-migration");
    }

    tracing::info!("CIRISVerify FFI init complete — handle ready");
    let handle = Box::new(CirisVerifyHandle {
        runtime,
        engine,
        ed25519_signer,
    });
    Box::into_raw(handle)
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
    // Validate arguments
    if handle.is_null()
        || request_data.is_null()
        || response_data.is_null()
        || response_len.is_null()
    {
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

    // Execute request
    let response = match handle
        .runtime
        .block_on(handle.engine.get_license_status(request))
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Request failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

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
    if handle.is_null() || capability.is_null() || action.is_null() || allowed.is_null() {
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
    if !handle.is_null() {
        drop(Box::from_raw(handle));
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
    if handle.is_null()
        || manifest_data.is_null()
        || agent_root.is_null()
        || response_data.is_null()
        || response_len.is_null()
    {
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
    if handle.is_null() || data.is_null() || signature_data.is_null() || signature_len.is_null() {
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
    if handle.is_null()
        || key_data.is_null()
        || key_len.is_null()
        || algorithm.is_null()
        || algorithm_len.is_null()
    {
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
/// The proof contains hardware attestation, dual (classical + PQC) signatures
/// over the challenge, and the Merkle root from the transparency log.
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
    if handle.is_null() || challenge.is_null() || proof_data.is_null() || proof_len.is_null() {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let challenge_bytes = std::slice::from_raw_parts(challenge, challenge_len);

    // Export attestation proof
    let proof = match handle
        .runtime
        .block_on(handle.engine.export_attestation_proof(challenge_bytes))
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Attestation export failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

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

// Android JNI bindings
#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JClass, JString};
    use jni::sys::{jbyteArray, jint, jlong};
    use jni::JNIEnv;

    use super::*;

    #[no_mangle]
    pub extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeInit(
        _env: JNIEnv,
        _class: JClass,
    ) -> jlong {
        let handle = ciris_verify_init();
        handle as jlong
    }

    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeDestroy(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) {
        ciris_verify_destroy(handle as *mut CirisVerifyHandle);
    }

    // TODO: Add more JNI bindings
}
