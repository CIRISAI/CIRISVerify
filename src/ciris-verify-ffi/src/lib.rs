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
use std::sync::Arc;

use tokio::runtime::Runtime;
use ciris_verify_core::LicenseEngine;

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
    // Initialize logging for the platform
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("CIRISVerify"),
        );
    }

    // Create tokio runtime
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("Failed to create runtime: {}", e);
            return ptr::null_mut();
        }
    };

    // Initialize the engine (synchronous)
    let engine = match LicenseEngine::new() {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            tracing::error!("Failed to initialize engine: {}", e);
            return ptr::null_mut();
        }
    };

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
    if handle.is_null() || request_data.is_null() || response_data.is_null() || response_len.is_null() {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let request_bytes = std::slice::from_raw_parts(request_data, request_len);

    // Deserialize request
    let request: ciris_verify_core::LicenseStatusRequest = match serde_json::from_slice(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to deserialize request: {}", e);
            return CirisVerifyError::SerializationError as i32;
        }
    };

    // Execute request
    let response = match handle.runtime.block_on(handle.engine.get_license_status(request)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Request failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        }
    };

    // Serialize response
    let response_bytes = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize response: {}", e);
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

    let result = match handle.runtime.block_on(
        handle.engine.check_capability(capability_str, action_str, required_tier as u8)
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Capability check failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        }
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
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::{jlong, jbyteArray, jint};

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
