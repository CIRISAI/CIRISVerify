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
use std::ptr;
use std::sync::{Arc, Once};

use ciris_verify_core::LicenseEngine;
use tokio::runtime::Runtime;

/// Ensure tracing is initialized exactly once.
static TRACING_INIT: Once = Once::new();

/// Opaque handle to the CIRISVerify instance.
#[repr(C)]
pub struct CirisVerifyHandle {
    runtime: Runtime,
    engine: Arc<LicenseEngine>,
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

    #[cfg(not(target_os = "android"))]
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

    tracing::info!("CIRISVerify FFI init starting (v{})", env!("CARGO_PKG_VERSION"));

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

    tracing::info!("CIRISVerify FFI init complete — handle ready");
    let handle = Box::new(CirisVerifyHandle { runtime, engine });
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
        }
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
        ciris_verify_core::spot_check_agent_integrity(&manifest, root_path, spot_check_count as usize)
    };

    // Serialize response
    let response_bytes = match serde_json::to_vec(&result) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize integrity result: {}", e);
            return CirisVerifyError::SerializationError as i32;
        }
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
    if handle.is_null()
        || data.is_null()
        || signature_data.is_null()
        || signature_len.is_null()
    {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let data_bytes = std::slice::from_raw_parts(data, data_len);

    // Sign using the hardware signer
    let sig = match handle
        .runtime
        .block_on(handle.engine.sign(data_bytes))
    {
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
    let pubkey = match handle
        .runtime
        .block_on(handle.engine.public_key())
    {
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
