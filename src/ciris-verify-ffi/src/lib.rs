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

#[cfg(target_os = "ios")]
mod ios_sync;

// Android logging: using tracing-log bridge to route tracing events -> log crate -> android_logger -> logcat

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};

// =============================================================================
// FFI Crash Guard Macro
// =============================================================================
//
// All FFI functions exposed via `extern "C"` must NOT allow panics to unwind
// across the FFI boundary. Per the Rustonomicon, unwinding into foreign code
// is undefined behavior. This macro wraps function bodies in catch_unwind.
//
// Usage:
//   ffi_guard!("function_name", { ... body returning i32 ... })
//
// Returns CirisVerifyError::InternalError on panic.

/// Wraps an FFI function body in catch_unwind for panic safety.
/// Logs panics with function name and returns InternalError code.
macro_rules! ffi_guard {
    ($fn_name:expr, $body:expr) => {{
        let result = catch_unwind(AssertUnwindSafe(|| $body));
        match result {
            Ok(code) => code,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!("PANIC in {}: {}", $fn_name, msg);
                CirisVerifyError::InternalError as i32
            },
        }
    }};
}

/// Wraps an FFI function that returns a raw pointer (returns null on panic).
#[allow(unused_macros)]
macro_rules! ffi_guard_ptr {
    ($fn_name:expr, $body:expr) => {{
        let result = catch_unwind(AssertUnwindSafe(|| $body));
        match result {
            Ok(ptr) => ptr,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!("PANIC in {}: {}", $fn_name, msg);
                std::ptr::null_mut()
            },
        }
    }};
}

use ciris_keyring::MutableEd25519Signer;
use ciris_verify_core::config::VerifyConfig;
use ciris_verify_core::license::LicenseStatus;
use ciris_verify_core::security::is_emulator;
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

// =============================================================================
// Log Callback Infrastructure
// =============================================================================

/// C-compatible log callback function pointer.
///
/// Parameters:
/// - `level`: 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG, 5=TRACE
/// - `target`: Null-terminated module path (e.g., "ciris_verify_core::engine")
/// - `message`: Null-terminated log message
///
/// The strings are only valid for the duration of the callback call.
/// The callback may be invoked from any thread.
pub type CirisLogCallback =
    unsafe extern "C" fn(level: i32, target: *const libc::c_char, message: *const libc::c_char);

/// Global atomic storage for the log callback function pointer.
/// 0 = no callback registered.
static LOG_CALLBACK: AtomicUsize = AtomicUsize::new(0);

/// Get the currently registered log callback, if any.
fn get_log_callback() -> Option<CirisLogCallback> {
    let ptr = LOG_CALLBACK.load(Ordering::Relaxed);
    if ptr == 0 {
        None
    } else {
        // SAFETY: We only store valid function pointers via set_log_callback.
        Some(unsafe { std::mem::transmute::<usize, CirisLogCallback>(ptr) })
    }
}

/// Tracing layer that forwards events to the registered C log callback.
///
/// Always installed during init. If no callback is registered, events
/// are silently ignored (zero overhead beyond the pointer check).
struct CallbackTracingLayer;

impl<S> tracing_subscriber::layer::Layer<S> for CallbackTracingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let callback = match get_log_callback() {
            Some(cb) => cb,
            None => return,
        };

        // Format the event fields
        let mut visitor = FfiLogVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        let level = match *event.metadata().level() {
            tracing::Level::ERROR => 1,
            tracing::Level::WARN => 2,
            tracing::Level::INFO => 3,
            tracing::Level::DEBUG => 4,
            tracing::Level::TRACE => 5,
        };

        // Convert to C strings (replacing interior nulls with \0 escape)
        let target = std::ffi::CString::new(event.metadata().target()).unwrap_or_default();
        let message = std::ffi::CString::new(visitor.message).unwrap_or_default();

        unsafe {
            callback(level, target.as_ptr(), message.as_ptr());
        }
    }
}

/// Visitor that formats tracing event fields into a single message string.
struct FfiLogVisitor {
    message: String,
}

impl tracing::field::Visit for FfiLogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            if !self.message.is_empty() {
                self.message.push_str(", ");
            }
            self.message
                .push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

/// Magic number to detect corrupted/freed handles.
const HANDLE_MAGIC: u64 = 0xC121_5BEE_FCAF_E000;

/// Sentinel value written to handle magic when freed (use-after-free detection).
const HANDLE_FREED: u64 = 0xDEAD_BEEF_DEAD_BEEF;

/// Opaque handle to the CIRISVerify instance.
#[repr(C)]
pub struct CirisVerifyHandle {
    /// Magic number for corruption detection. Must be HANDLE_MAGIC.
    magic: u64,
    runtime: Runtime,
    engine: Arc<LicenseEngine>,
    /// Optional Ed25519 signer for Portal-issued keys.
    /// This is separate from the hardware signer and used for agent identity.
    ed25519_signer: MutableEd25519Signer,
    /// Cached device attestation result (Play Integrity / App Attest).
    /// Populated automatically when ciris_verify_verify_integrity_token or
    /// ciris_verify_app_attest is called. Used by run_attestation for L2.
    device_attestation_cache:
        std::sync::Mutex<Option<ciris_verify_core::unified::DeviceAttestationCheckResult>>,
}

impl CirisVerifyHandle {
    /// Check if the handle's magic number is valid.
    #[allow(dead_code)]
    fn is_valid(&self) -> bool {
        self.magic == HANDLE_MAGIC
    }
}

/// Validate a handle pointer and return a reference if valid.
/// Returns InvalidArgument error code if handle is null or corrupted.
unsafe fn validate_handle(
    handle: *mut CirisVerifyHandle,
) -> Result<&'static CirisVerifyHandle, i32> {
    if handle.is_null() {
        tracing::error!("Handle is null");
        return Err(CirisVerifyError::InvalidArgument as i32);
    }

    // Read magic number carefully to avoid crash on corrupted pointer
    // First check if we can read the magic field at all
    let magic_ptr = handle as *const u64;

    // Try to read magic - this could still crash if handle points to unmapped memory
    // but at least we'll catch use-after-free where memory is zeroed
    let magic = *magic_ptr;

    if magic == HANDLE_FREED {
        tracing::error!("Handle has been freed (use-after-free detected) - magic is DEAD_BEEF");
        return Err(CirisVerifyError::InvalidArgument as i32);
    }

    if magic != HANDLE_MAGIC {
        tracing::error!(
            "Handle magic mismatch: expected {:x}, got {:x} - handle may be corrupted",
            HANDLE_MAGIC,
            magic
        );
        return Err(CirisVerifyError::InvalidArgument as i32);
    }

    Ok(&*handle)
}

/// Minimum valid pointer address.
/// Pointers below this are almost certainly invalid - either null, or an argument
/// shift bug where a length/count was passed instead of a pointer.
/// 64KB covers the null guard page on most platforms.
const MIN_VALID_PTR: usize = 0x10000;

/// Check if a pointer value looks valid (not null or suspiciously small).
/// Returns true if the pointer is likely valid, false otherwise.
#[inline]
#[allow(dead_code)]
fn is_valid_ptr<T>(ptr: *const T) -> bool {
    let addr = ptr as usize;
    addr >= MIN_VALID_PTR
}

/// Validate a pointer and return an error message if invalid.
/// Returns None if valid, Some(error_message) if invalid.
fn validate_ptr<T>(ptr: *const T, name: &str) -> Option<String> {
    let addr = ptr as usize;
    if addr == 0 {
        Some(format!("{} is null", name))
    } else if addr < MIN_VALID_PTR {
        Some(format!(
            "{} has invalid address {:#x} (below {:#x}, likely argument shift bug - check FFI call)",
            name, addr, MIN_VALID_PTR
        ))
    } else {
        None
    }
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
        use std::sync::Once;
        static ANDROID_LOGGING_INIT: Once = Once::new();

        ANDROID_LOGGING_INIT.call_once(|| {
            // Initialize android_logger for the log crate (used by dependencies)
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Debug)
                    .with_tag("CIRISVerify"),
            );

            // Direct logcat test to verify the mechanism works
            {
                use std::ffi::CString;
                use std::os::raw::c_char;
                const ANDROID_LOG_INFO: i32 = 4;
                extern "C" {
                    fn __android_log_write(
                        prio: i32,
                        tag: *const c_char,
                        text: *const c_char,
                    ) -> i32;
                }
                let tag = CString::new("CIRISVerify").unwrap();
                let msg =
                    CString::new("=== CIRISVerify FFI init starting (v0.7.16-log) ===").unwrap();
                unsafe {
                    __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), msg.as_ptr());
                }
            }

            // Custom tracing layer that outputs to Android log
            struct AndroidTracingLayer;

            impl<S> tracing_subscriber::layer::Layer<S> for AndroidTracingLayer
            where
                S: tracing::Subscriber,
            {
                fn on_event(
                    &self,
                    event: &tracing::Event<'_>,
                    _ctx: tracing_subscriber::layer::Context<'_, S>,
                ) {
                    // Format the event
                    let mut visitor = LogVisitor {
                        message: String::new(),
                    };
                    event.record(&mut visitor);

                    let level = event.metadata().level();
                    let target = event.metadata().target();
                    let msg = format!("[{}] {}: {}", level, target, visitor.message);

                    // Output via log crate which goes to android_logger
                    match *level {
                        tracing::Level::ERROR => log::error!("{}", msg),
                        tracing::Level::WARN => log::warn!("{}", msg),
                        tracing::Level::INFO => log::info!("{}", msg),
                        tracing::Level::DEBUG => log::debug!("{}", msg),
                        tracing::Level::TRACE => log::trace!("{}", msg),
                    }
                }
            }

            struct LogVisitor {
                message: String,
            }

            impl tracing::field::Visit for LogVisitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.message = format!("{:?}", value);
                    } else {
                        if !self.message.is_empty() {
                            self.message.push_str(", ");
                        }
                        self.message
                            .push_str(&format!("{}={:?}", field.name(), value));
                    }
                }
            }

            // Set up tracing subscriber with our custom layer
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;

            let _ = tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::DEBUG)
                .with(AndroidTracingLayer)
                .with(CallbackTracingLayer)
                .try_init();
        });
    }

    #[cfg(target_os = "ios")]
    {
        TRACING_INIT.call_once(|| {
            // Initialize oslog for the log crate (used by dependencies)
            oslog::OsLogger::new("ai.ciris.verify")
                .level_filter(log::LevelFilter::Info)
                .init()
                .ok();

            // Custom tracing layer that outputs to iOS unified logging via oslog
            struct IosTracingLayer;

            impl<S> tracing_subscriber::layer::Layer<S> for IosTracingLayer
            where
                S: tracing::Subscriber,
            {
                fn on_event(
                    &self,
                    event: &tracing::Event<'_>,
                    _ctx: tracing_subscriber::layer::Context<'_, S>,
                ) {
                    let mut visitor = LogVisitor {
                        message: String::new(),
                    };
                    event.record(&mut visitor);

                    let level = event.metadata().level();
                    let target = event.metadata().target();
                    let msg = format!("[{}] {}: {}", level, target, visitor.message);

                    // Output via log crate which goes to oslog
                    match *level {
                        tracing::Level::ERROR => log::error!("{}", msg),
                        tracing::Level::WARN => log::warn!("{}", msg),
                        tracing::Level::INFO => log::info!("{}", msg),
                        tracing::Level::DEBUG => log::debug!("{}", msg),
                        tracing::Level::TRACE => log::trace!("{}", msg),
                    }
                }
            }

            struct LogVisitor {
                message: String,
            }

            impl tracing::field::Visit for LogVisitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.message = format!("{:?}", value);
                    } else {
                        if !self.message.is_empty() {
                            self.message.push_str(", ");
                        }
                        self.message
                            .push_str(&format!("{}={:?}", field.name(), value));
                    }
                }
            }

            // Set up tracing subscriber with iOS layer + callback layer
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;

            let _ = tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::INFO)
                .with(IosTracingLayer)
                .with(CallbackTracingLayer)
                .try_init();
        });
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        TRACING_INIT.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;

            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_thread_ids(false)
                        .with_file(false)
                        .with_line_number(false),
                )
                .with(CallbackTracingLayer)
                .try_init();
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
        magic: HANDLE_MAGIC,
        runtime,
        engine,
        ed25519_signer,
        device_attestation_cache: std::sync::Mutex::new(None),
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
    ffi_guard!("ciris_verify_get_status", {
        get_status_inner(
            handle,
            request_data,
            request_len,
            response_data,
            response_len,
        )
    })
}

/// Inner implementation of get_status (can panic safely).
unsafe fn get_status_inner(
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

    // Validate handle with magic number check
    let handle = match validate_handle(handle) {
        Ok(h) => h,
        Err(code) => {
            tracing::error!("ciris_verify_get_status: invalid handle");
            return code;
        },
    };

    // Validate other pointers (catches argument shift bugs)
    if let Some(err) = validate_ptr(request_data, "request_data") {
        tracing::error!("ciris_verify_get_status: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(response_data, "response_data") {
        tracing::error!("ciris_verify_get_status: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(response_len, "response_len") {
        tracing::error!("ciris_verify_get_status: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
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
        let result =
            android_sync::get_license_status_blocking(&request, std::time::Duration::from_secs(10));
        tracing::info!(
            "FFI (Android): Blocking call completed in {:?}",
            start.elapsed()
        );
        result
    };

    #[cfg(target_os = "ios")]
    let mut response = {
        // On iOS, bypass tokio entirely and use blocking I/O.
        // getaddrinfo() hangs for 30s on iOS (IPv6 AAAA query timeout),
        // and hickory-resolver's DoH bootstrap triggers this hang.
        tracing::info!("FFI (iOS): Using blocking I/O (ureq) - bypassing tokio");
        let result =
            ios_sync::get_license_status_blocking(&request, std::time::Duration::from_secs(10));
        tracing::info!(
            "FFI (iOS): Blocking call completed in {:?}",
            start.elapsed()
        );
        result
    };

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
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
    ffi_guard!("ciris_verify_check_capability", {
        check_capability_inner(handle, capability, action, required_tier, allowed)
    })
}

/// Inner implementation of check_capability (can panic safely).
unsafe fn check_capability_inner(
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

    // Validate handle with magic number check
    let handle = match validate_handle(handle) {
        Ok(h) => h,
        Err(code) => {
            tracing::error!("ciris_verify_check_capability: invalid handle");
            return code;
        },
    };

    // Validate other pointers (catches argument shift bugs)
    if let Some(err) = validate_ptr(capability, "capability") {
        tracing::error!("ciris_verify_check_capability: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(action, "action") {
        tracing::error!("ciris_verify_check_capability: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(allowed, "allowed") {
        tracing::error!("ciris_verify_check_capability: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }

    let capability_str = match std::ffi::CStr::from_ptr(capability).to_str() {
        Ok(s) => s,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };

    let action_str = match std::ffi::CStr::from_ptr(action).to_str() {
        Ok(s) => s,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };

    let result = match handle
        .runtime
        .handle()
        .block_on(
            handle
                .engine
                .check_capability(capability_str, action_str, required_tier as u8),
        ) {
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
    // Note: We use ffi_guard but this function doesn't have a return value expectation
    // On panic, we return InternalError but the handle may be partially destroyed
    let _ = ffi_guard!("ciris_verify_destroy", {
        tracing::info!("ciris_verify_destroy called");
        if !handle.is_null() {
            // Mark as freed BEFORE dropping to detect use-after-free
            // Write the freed sentinel to the magic field
            let magic_ptr = handle as *mut u64;
            *magic_ptr = HANDLE_FREED;
            tracing::debug!("Handle magic set to FREED sentinel");

            drop(Box::from_raw(handle));
            tracing::info!("CIRISVerify handle destroyed");
        }
        CirisVerifyError::Success as i32
    });
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
    ffi_guard!("ciris_verify_check_agent_integrity", {
        check_agent_integrity_inner(
            handle,
            manifest_data,
            manifest_len,
            agent_root,
            spot_check_count,
            response_data,
            response_len,
        )
    })
}

/// Inner implementation of check_agent_integrity (can panic safely).
unsafe fn check_agent_integrity_inner(
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

/// Check agent file integrity with options for partial verification.
///
/// This version supports partial checking for mobile deployments where
/// files may be lazily extracted (e.g., Chaquopy on Android).
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `manifest_data` - JSON manifest bytes
/// * `manifest_len` - Length of manifest data
/// * `agent_root` - Path to agent root directory
/// * `partial_check` - If true, only check files that exist on disk
/// * `response_data` - Output pointer for JSON response (caller must free with `ciris_verify_free`)
/// * `response_len` - Output pointer for response length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Partial Check Mode
///
/// When `partial_check` is true:
/// - Only files that exist on disk are verified
/// - Missing files do NOT cause integrity failure
/// - Modified or unexpected files still cause failure
/// - Response includes `files_found` and `files_missing` for coverage reporting
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `manifest_data` must point to valid memory of at least `manifest_len` bytes
/// - `agent_root` must be a valid null-terminated UTF-8 string
/// - `response_data` and `response_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_check_agent_integrity_available(
    handle: *mut CirisVerifyHandle,
    manifest_data: *const u8,
    manifest_len: usize,
    agent_root: *const libc::c_char,
    partial_check: bool,
    response_data: *mut *mut u8,
    response_len: *mut usize,
) -> i32 {
    tracing::debug!(
        "ciris_verify_check_agent_integrity_available called (manifest_len={}, partial={})",
        manifest_len,
        partial_check
    );

    if handle.is_null()
        || manifest_data.is_null()
        || agent_root.is_null()
        || response_data.is_null()
        || response_len.is_null()
    {
        tracing::error!("ciris_verify_check_agent_integrity_available: invalid arguments");
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
    let result = if partial_check {
        ciris_verify_core::check_available_agent_integrity(&manifest, root_path)
    } else {
        ciris_verify_core::check_agent_integrity(&manifest, root_path)
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
    ffi_guard!("ciris_verify_sign", {
        sign_inner(handle, data, data_len, signature_data, signature_len)
    })
}

/// Inner implementation of sign (can panic safely).
unsafe fn sign_inner(
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
    let sig = match handle
        .runtime
        .handle()
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
    ffi_guard!("ciris_verify_get_public_key", {
        get_public_key_inner(handle, key_data, key_len, algorithm, algorithm_len)
    })
}

/// Inner implementation of get_public_key (can panic safely).
unsafe fn get_public_key_inner(
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
    let pubkey = match handle.runtime.handle().block_on(handle.engine.public_key()) {
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
    ffi_guard!("ciris_verify_export_attestation", {
        export_attestation_inner(handle, challenge, challenge_len, proof_data, proof_len)
    })
}

/// Inner implementation of export_attestation (can panic safely).
unsafe fn export_attestation_inner(
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
    // Note: This function doesn't contact registry, so we can't verify if key is portal-issued.
    // Use "persisted" for loaded keys, "generated" for newly created ones.
    // The full run_attestation flow will set proper key_type based on registry status.
    let (key_type, public_key) = if handle.ed25519_signer.has_key() {
        // Key loaded from persistent storage
        tracing::info!("Using persisted Ed25519 key for attestation");
        let pk = match handle.ed25519_signer.get_public_key() {
            Some(pk) => pk,
            None => {
                tracing::error!("Ed25519 key loaded but public key unavailable");
                return CirisVerifyError::InternalError as i32;
            },
        };
        ("persisted".to_string(), pk)
    } else {
        // No key yet - generate one for initial attestation
        tracing::info!("No persisted key found, generating Ed25519 key for initial attestation");

        // Generate random 32-byte seed
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

        // Import generated key (will be persisted to hardware-backed storage)
        if let Err(e) = handle.ed25519_signer.import_key(&seed) {
            tracing::error!("Failed to generate key: {}", e);
            return CirisVerifyError::InternalError as i32;
        }

        let pk = match handle.ed25519_signer.get_public_key() {
            Some(pk) => pk,
            None => {
                tracing::error!("Key generated but public key unavailable");
                return CirisVerifyError::InternalError as i32;
            },
        };
        ("generated".to_string(), pk)
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

    // Detect platform capabilities for accurate hardware_type reporting
    let capabilities = ciris_keyring::detect_hardware_type();
    let hardware_type_str = format!("{:?}", capabilities.hardware_type);
    // On emulators, even if KeyStore API is available, it's software-emulated (no TEE/SE)
    let running_in_vm = is_emulator();
    let hardware_backed = handle.ed25519_signer.is_hardware_backed() && !running_in_vm;

    // Build platform attestation based on actual hardware detection
    let platform_attestation = if capabilities.has_hardware {
        serde_json::json!({
            "type": hardware_type_str,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hardware_backed": hardware_backed,
        })
    } else {
        serde_json::json!({
            "type": "Software",
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hardware_backed": false,
        })
    };

    // Get transparency log state from engine
    let tlog = handle.engine.transparency_log();
    let merkle_root = tlog.merkle_root();
    let log_entry_count = tlog.entry_count();

    // PQC (ML-DSA-65) is always compiled in — it's a default feature of ciris-verify-core
    let pqc_available = true;

    // Platform integrity token status
    // Android: Play Integrity, iOS: App Attest, Others: N/A
    let platform_integrity = match std::env::consts::OS {
        "android" => serde_json::json!({
            "play_integrity_available": true,
            "play_integrity_ok": false,
            "note": "Play Integrity requires JNI callback - checked via run_attestation",
        }),
        "ios" => serde_json::json!({
            "app_attest_available": true,
            "app_attest_ok": false,
            "note": "App Attest requires DCAppAttestService - checked via run_attestation",
        }),
        _ => serde_json::json!({
            "platform_integrity": "not_applicable",
            "note": "Platform integrity tokens only available on mobile",
        }),
    };

    let proof = serde_json::json!({
        "platform_attestation": platform_attestation,
        "hardware_public_key": hex::encode(&public_key),
        "hardware_algorithm": "Ed25519",
        "pqc_public_key": "",
        "pqc_algorithm": if pqc_available { "ML-DSA-65" } else { "NONE" },
        "pqc_available": pqc_available,
        "challenge": hex::encode(challenge_bytes),
        "classical_signature": hex::encode(&classical_signature),
        "pqc_signature": "",
        "merkle_root": hex::encode(merkle_root),
        "log_entry_count": log_entry_count,
        "generated_at": chrono::Utc::now().timestamp(),
        "binary_version": env!("CARGO_PKG_VERSION"),
        "hardware_type": hardware_type_str,
        "hardware_backed": hardware_backed,
        "running_in_vm": running_in_vm,
        "key_type": key_type,
        "platform_integrity": platform_integrity,
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

    let handle_ref = &*handle;
    let key_bytes = std::slice::from_raw_parts(key_data, key_len);

    tracing::info!("Importing Ed25519 key ({} bytes)", key_len);

    match catch_unwind(AssertUnwindSafe(|| {
        handle_ref.ed25519_signer.import_key(key_bytes)
    })) {
        Ok(Ok(())) => {
            tracing::info!("Ed25519 key imported successfully");
            CirisVerifyError::Success as i32
        },
        Ok(Err(e)) => {
            tracing::error!("Failed to import Ed25519 key: {}", e);
            CirisVerifyError::InvalidArgument as i32
        },
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("import_key: panic caught: {}", msg);
            CirisVerifyError::InternalError as i32
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

    let handle_ref = &*handle;
    match catch_unwind(AssertUnwindSafe(|| handle_ref.ed25519_signer.has_key())) {
        Ok(has_key) => {
            tracing::debug!("has_key check: {}", has_key);
            if has_key {
                1
            } else {
                0
            }
        },
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("has_key: panic caught: {}", msg);
            CirisVerifyError::InternalError as i32
        },
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

    let handle_ref = &*handle;

    tracing::info!("Deleting Ed25519 key");

    match catch_unwind(AssertUnwindSafe(|| handle_ref.ed25519_signer.clear_key())) {
        Ok(Ok(())) => {
            tracing::info!("Ed25519 key deleted successfully");
            CirisVerifyError::Success as i32
        },
        Ok(Err(e)) => {
            tracing::error!("Failed to delete Ed25519 key: {}", e);
            CirisVerifyError::InternalError as i32
        },
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("delete_key: panic caught: {}", msg);
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

    let handle_ref = &*handle;
    let data_bytes = std::slice::from_raw_parts(data, data_len);

    tracing::debug!("Signing {} bytes with Ed25519 key", data_len);

    let sig = match catch_unwind(AssertUnwindSafe(|| {
        handle_ref.ed25519_signer.sign(data_bytes)
    })) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("Ed25519 signing failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("sign_ed25519: panic caught: {}", msg);
            return CirisVerifyError::InternalError as i32;
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

    let handle_ref = &*handle;

    let pubkey = match catch_unwind(AssertUnwindSafe(|| {
        handle_ref.ed25519_signer.get_public_key()
    })) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            tracing::error!("get_ed25519_public_key: no key loaded");
            return CirisVerifyError::RequestFailed as i32;
        },
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("get_ed25519_public_key: panic caught: {}", msg);
            return CirisVerifyError::InternalError as i32;
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
///   "skip_audit": false,             // optional
///   "partial_file_check": false      // optional, for mobile: only check files that exist
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
    ffi_guard!("ciris_verify_run_attestation", {
        run_attestation_inner(handle, request_json, request_len, result_json, result_len)
    })
}

/// Inner implementation of run_attestation (can panic safely).
unsafe fn run_attestation_inner(
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

    let mut request: FullAttestationRequest = match serde_json::from_str(request_str) {
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

    // Auto-populate key_fingerprint from ed25519_signer if not provided
    // This ensures the Portal key fingerprint is used for registry verification
    if request.key_fingerprint.is_none() && handle.ed25519_signer.has_key() {
        if let Some(pk) = handle.ed25519_signer.get_public_key() {
            let fingerprint = ciris_verify_core::registry::compute_ed25519_fingerprint(&pk);
            tracing::info!(
                "Auto-populating key_fingerprint from ed25519_signer: {}",
                fingerprint
            );
            request.key_fingerprint = Some(fingerprint);
        }
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

    // Run attestation with 10-second HARD CAP
    // This prevents network hangs from blocking indefinitely
    const ATTESTATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let mut result: FullAttestationResult = match handle.runtime.handle().block_on(async {
        tokio::time::timeout(ATTESTATION_TIMEOUT, engine.run_attestation(request)).await
    }) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::error!("ciris_verify_run_attestation: attestation failed: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
        Err(_timeout) => {
            tracing::error!(
                "ciris_verify_run_attestation: TIMEOUT after {}s - network unreachable",
                ATTESTATION_TIMEOUT.as_secs()
            );
            // Return a timeout result with partial data rather than blocking
            FullAttestationResult {
                valid: false,
                level: 0,
                level_pending: false,
                self_verification: None,
                key_attestation: None,
                registry_key_status: "timeout".to_string(),
                device_attestation: None,
                file_integrity: None,
                python_integrity: None,
                module_integrity: None,
                sources: ciris_verify_core::unified::SourceCheckResult {
                    dns_us_reachable: false,
                    dns_us_valid: false,
                    dns_us_error: Some("timeout".to_string()),
                    dns_eu_reachable: false,
                    dns_eu_valid: false,
                    dns_eu_error: Some("timeout".to_string()),
                    https_reachable: false,
                    https_valid: false,
                    https_error: Some("timeout".to_string()),
                    validation_status: "timeout".to_string(),
                },
                audit_trail: None,
                checks_passed: 0,
                checks_total: 0,
                diagnostics: format!(
                    "TIMEOUT: Attestation did not complete within {}s.\n\
                     This usually indicates the registry server is unreachable.\n\
                     Community mode enforced.",
                    ATTESTATION_TIMEOUT.as_secs()
                ),
                errors: vec!["Attestation timeout: network unreachable".to_string()],
                timestamp: chrono::Utc::now().timestamp(),
            }
        },
    };

    // Populate key_attestation with signer info
    let has_key = handle.ed25519_signer.has_key();

    // Determine key_type based on registry verification status (not just has_key)
    // - "portal": Key fingerprint verified as active in registry
    // - "local": Key exists but not found in registry (self-generated)
    // - "unverified": Key exists but registry couldn't be contacted
    // - "none": No key loaded
    let key_type = if !has_key {
        "none"
    } else {
        match result.registry_key_status.as_str() {
            "active" => "portal",          // Confirmed by registry
            "rotated" => "portal_rotated", // Was portal-issued but rotated
            "revoked" => "portal_revoked", // Was portal-issued but revoked
            "not_found" => "local",        // Key exists but not in registry
            "not_checked" => "unverified", // Registry check skipped
            status if status.starts_with("error") => "registry_unavailable",
            _ => "unverified",
        }
    };

    // Get public key and compute fingerprint
    let (ed25519_fingerprint, public_key_hex) = if has_key {
        match handle.ed25519_signer.get_public_key() {
            Some(pk) => {
                let fingerprint = ciris_verify_core::registry::compute_ed25519_fingerprint(&pk);
                (fingerprint, hex::encode(&pk))
            },
            None => (String::new(), String::new()),
        }
    } else {
        (String::new(), String::new())
    };

    // Detect hardware type and derive storage_mode from actual platform capabilities
    let capabilities = ciris_keyring::detect_hardware_type();
    let hw_type_str = format!("{:?}", capabilities.hardware_type);
    // On emulators, even if KeyStore API is available, it's software-emulated (no TEE/SE)
    let running_in_vm = is_emulator();
    let hardware_backed = handle.ed25519_signer.is_hardware_backed() && !running_in_vm;
    let storage_mode = match capabilities.hardware_type {
        ciris_keyring::HardwareType::AndroidKeystore => {
            "HW-AES-256-GCM (Android Keystore)".to_string()
        },
        ciris_keyring::HardwareType::IosSecureEnclave => "Secure Enclave".to_string(),
        ciris_keyring::HardwareType::TpmDiscrete | ciris_keyring::HardwareType::TpmFirmware => {
            "TPM".to_string()
        },
        _ => "Software".to_string(),
    };

    result.key_attestation = Some(ciris_verify_core::unified::KeyAttestationResult {
        key_type: key_type.to_string(),
        hardware_type: hw_type_str,
        has_valid_signature: has_key,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        running_in_vm,
        classical_signature: String::new(),
        pqc_available: true, // ML-DSA-65 compiled in via default pqc feature
        hardware_backed,
        storage_mode: storage_mode.clone(),
        ed25519_fingerprint: ed25519_fingerprint.clone(),
        mldsa_fingerprint: None,
        registry_key_status: result.registry_key_status.clone(),
    });

    // Inject cached device attestation result (from prior Play Integrity / App Attest call)
    // On mobile platforms, this is automatically populated; on desktop it's N/A.
    let device_attestation = handle
        .device_attestation_cache
        .lock()
        .ok()
        .and_then(|cache| cache.clone());

    if let Some(ref da) = device_attestation {
        // Add device attestation as a check
        result.checks_total += 1;
        if da.verified {
            result.checks_passed += 1;
        }
        result.device_attestation = Some(da.clone());

        // Recalculate level with device attestation factored into L2
        let l1_pass = result
            .self_verification
            .as_ref()
            .map(|sv| sv.binary_valid && sv.functions_valid)
            .unwrap_or(false);
        // L2 requires: L1 + device attestation + hardware platform + hardware-backed key
        let l2_pass = l1_pass && da.verified && !running_in_vm && hardware_backed;
        let sources_agreeing = u8::from(result.sources.dns_us_valid)
            + u8::from(result.sources.dns_eu_valid)
            + u8::from(result.sources.https_valid);
        let l3_pass = l2_pass && sources_agreeing >= 2;
        // L4: File integrity (MUST be checked and valid - if not checked, level caps at L3)
        let l4_pass = l3_pass
            && result
                .file_integrity
                .as_ref()
                .map(|fi| fi.full.as_ref().map(|f| f.valid).unwrap_or(false))
                .unwrap_or(false)
            && result
                .python_integrity
                .as_ref()
                .map(|pi| pi.valid)
                .unwrap_or(false);
        // L5: Audit trail (MUST be checked and valid) + registry key (must be active)
        let l5_pass = l4_pass
            && result
                .audit_trail
                .as_ref()
                .map(|a| a.valid)
                .unwrap_or(false)
            && result.registry_key_status == "active";

        result.level = if l5_pass {
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
        result.valid = result.checks_passed == result.checks_total && result.errors.is_empty();
        // Device attestation is present, so level is no longer pending
        result.level_pending = false;
    } else {
        // No device attestation cached yet
        // On mobile platforms, level is pending until Play Integrity / App Attest completes
        // On desktop platforms, device attestation is not required
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            result.level_pending = true;
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            result.level_pending = false;
        }
    }

    // Prepend key attestation info to diagnostics
    let key_diag = format!(
        "=== KEY ATTESTATION ===\n\
         Key type: {} ({})\n\
         Storage: {}\n\
         Ed25519 fingerprint: {}\n\
         Public key: {}...\n\n",
        key_type,
        if hardware_backed {
            "hardware-backed"
        } else {
            "software"
        },
        storage_mode,
        if ed25519_fingerprint.is_empty() {
            "N/A"
        } else {
            &ed25519_fingerprint
        },
        if public_key_hex.len() >= 16 {
            &public_key_hex[..16]
        } else {
            &public_key_hex
        }
    );
    result.diagnostics = format!("{}{}", key_diag, result.diagnostics);

    tracing::info!(
        valid = result.valid,
        level = result.level,
        level_pending = result.level_pending,
        checks_passed = result.checks_passed,
        checks_total = result.checks_total,
        key_type = %key_type,
        hardware_backed = hardware_backed,
        ed25519_fingerprint = %ed25519_fingerprint,
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
    handle: *mut CirisVerifyHandle,
    db_path: *const libc::c_char,
    jsonl_path: *const libc::c_char,
    portal_key_id: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_audit_trail", {
        audit_trail_inner(
            handle,
            db_path,
            jsonl_path,
            portal_key_id,
            result_json,
            result_len,
        )
    })
}

/// Inner implementation of audit_trail (can panic safely).
unsafe fn audit_trail_inner(
    _handle: *mut CirisVerifyHandle,
    db_path: *const libc::c_char,
    jsonl_path: *const libc::c_char,
    portal_key_id: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_audit_trail called");

    if db_path.is_null() || result_json.is_null() || result_len.is_null() {
        tracing::error!(
            "ciris_verify_audit_trail: invalid arguments (db_path or result pointers null)"
        );
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
                tracing::error!(
                    "ciris_verify_audit_trail: invalid portal_key_id UTF-8: {}",
                    e
                );
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

// =============================================================================
// Play Integrity API (Google Android Hardware Attestation)
// =============================================================================

/// Get a Play Integrity nonce from the registry.
///
/// This nonce should be passed to the Google Play Integrity API to request
/// an integrity token. The nonce is valid for a limited time (check expires_at).
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `nonce_json` - Output pointer for JSON-encoded IntegrityNonce (caller must free with `ciris_verify_free`)
/// * `nonce_len` - Output pointer for nonce length
///
/// # Result JSON Format
///
/// ```json
/// {
///   "nonce": "base64-url-encoded-nonce",
///   "expires_at": "2025-01-15T12:00:00Z"
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
/// - `nonce_json` and `nonce_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_integrity_nonce(
    handle: *mut CirisVerifyHandle,
    nonce_json: *mut *mut u8,
    nonce_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_get_integrity_nonce called");

    if handle.is_null() || nonce_json.is_null() || nonce_len.is_null() {
        tracing::error!("ciris_verify_get_integrity_nonce: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    // Create registry client and fetch nonce
    let result = handle.runtime.handle().block_on(async {
        let client = ciris_verify_core::RegistryClient::new(
            "https://api.registry.ciris-services-1.ai",
            std::time::Duration::from_secs(10),
        )?;
        client.get_integrity_nonce().await
    });

    let nonce = match result {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("Failed to get integrity nonce: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Serialize to JSON
    let nonce_bytes = match serde_json::to_vec(&nonce) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize nonce: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = nonce_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(nonce_bytes.as_ptr(), ptr, len);

    *nonce_json = ptr;
    *nonce_len = len;

    tracing::info!("Play Integrity nonce retrieved successfully");
    CirisVerifyError::Success as i32
}

/// Verify a Play Integrity token with the registry.
///
/// After receiving an integrity token from Google Play Integrity API,
/// call this function to verify it. The registry will decrypt the token
/// via Google's API and return the device/app integrity verdict.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `token` - The encrypted integrity token from Play Integrity API (null-terminated)
/// * `nonce` - The nonce used when requesting the token (null-terminated)
/// * `result_json` - Output pointer for JSON-encoded IntegrityVerifyResponse (caller must free with `ciris_verify_free`)
/// * `result_len` - Output pointer for result length
///
/// # Result JSON Format
///
/// ```json
/// {
///   "verified": true,
///   "device_integrity": {
///     "meets_strong_integrity": true,
///     "meets_device_integrity": true,
///     "meets_basic_integrity": true,
///     "verdicts": ["MEETS_STRONG_INTEGRITY", "MEETS_DEVICE_INTEGRITY"]
///   },
///   "app_integrity": {
///     "verdict": "PLAY_RECOGNIZED",
///     "package_name": "ai.ciris.mobile",
///     "version_code": 1
///   },
///   "account_details": {
///     "licensing_verdict": "LICENSED"
///   },
///   "error": null
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
/// - `token` and `nonce` must be valid null-terminated UTF-8 strings
/// - `result_json` and `result_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_verify_integrity_token(
    handle: *mut CirisVerifyHandle,
    token: *const libc::c_char,
    nonce: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // Wrap entire function in catch_unwind to prevent panics from crashing FFI
    let result = catch_unwind(AssertUnwindSafe(|| {
        verify_integrity_token_inner(handle, token, nonce, result_json, result_len)
    }));

    match result {
        Ok(code) => code,
        Err(e) => {
            // Extract panic message if possible
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("PANIC in verify_integrity_token: {}", msg);
            CirisVerifyError::InternalError as i32
        },
    }
}

/// Inner implementation with all the actual logic (can panic safely).
unsafe fn verify_integrity_token_inner(
    handle: *mut CirisVerifyHandle,
    token: *const libc::c_char,
    nonce: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_verify_integrity_token called");

    // Validate handle with magic number check
    let handle_ref = match validate_handle(handle) {
        Ok(h) => h,
        Err(code) => {
            tracing::error!("verify_integrity_token: invalid handle");
            return code;
        },
    };

    tracing::debug!("verify_integrity_token: handle validated");

    // Defensive pointer validation - check for null AND suspiciously small values
    // This catches argument shift bugs where a length/count is passed instead of a pointer
    tracing::debug!(
        "verify_integrity_token: ptr addresses - token={:#x}, nonce={:#x}, result_json={:#x}, result_len={:#x}",
        token as usize, nonce as usize, result_json as usize, result_len as usize
    );

    if let Some(err) = validate_ptr(token, "token") {
        tracing::error!("verify_integrity_token: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(nonce, "nonce") {
        tracing::error!("verify_integrity_token: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(result_json, "result_json") {
        tracing::error!("verify_integrity_token: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(result_len, "result_len") {
        tracing::error!("verify_integrity_token: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }

    tracing::debug!("verify_integrity_token: all pointers validated");

    // Safe C string parsing with length limits to prevent reading garbage memory
    // JWT tokens are typically 1-2KB, set reasonable max at 64KB
    const MAX_TOKEN_LEN: usize = 65536;
    const MAX_NONCE_LEN: usize = 256;

    tracing::debug!("verify_integrity_token: about to parse token string");
    tracing::debug!("verify_integrity_token: token ptr = {:p}", token);

    let token_str = match safe_cstr_to_str(token, MAX_TOKEN_LEN) {
        Ok(s) => {
            tracing::debug!("verify_integrity_token: token parsed, len={}", s.len());
            s
        },
        Err(e) => {
            tracing::error!("verify_integrity_token: invalid token string: {}", e);
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    tracing::debug!("verify_integrity_token: about to parse nonce string");
    tracing::debug!("verify_integrity_token: nonce ptr = {:p}", nonce);

    let nonce_str = match safe_cstr_to_str(nonce, MAX_NONCE_LEN) {
        Ok(s) => {
            tracing::debug!("verify_integrity_token: nonce parsed, len={}", s.len());
            s
        },
        Err(e) => {
            tracing::error!("verify_integrity_token: invalid nonce string: {}", e);
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Validate strings are not empty
    tracing::debug!("verify_integrity_token: checking if strings are empty");
    if token_str.is_empty() {
        tracing::error!("verify_integrity_token: empty token");
        return CirisVerifyError::InvalidArgument as i32;
    }
    if nonce_str.is_empty() {
        tracing::error!("verify_integrity_token: empty nonce");
        return CirisVerifyError::InvalidArgument as i32;
    }

    tracing::debug!("verify_integrity_token: strings validated, about to log info");
    tracing::info!(
        "Verifying Play Integrity token (len={}, nonce={}...)",
        token_str.len(),
        &nonce_str[..nonce_str.len().min(16)]
    );
    tracing::debug!("verify_integrity_token: info logged, proceeding to HTTP");

    // Use mobile blocking HTTP on Android/iOS to avoid tokio async I/O issues
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let result = {
        tracing::debug!("verify_integrity_token: calling mobile blocking HTTP");
        let res = verify_integrity_token_blocking(token_str, nonce_str);
        tracing::debug!("verify_integrity_token: mobile blocking HTTP returned");
        res
    };

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let result: Result<
        ciris_verify_core::play_integrity::IntegrityVerifyResponse,
        ciris_verify_core::VerifyError,
    > = {
        // Desktop: use async with timeout protection
        handle_ref.runtime.handle().block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                let client = ciris_verify_core::RegistryClient::new(
                    "https://api.registry.ciris-services-1.ai",
                    std::time::Duration::from_secs(15),
                )?;
                client.verify_integrity_token(token_str, nonce_str).await
            })
            .await
            .map_err(|_| ciris_verify_core::VerifyError::HttpsError {
                message: "Play Integrity verification timed out".to_string(),
            })?
        })
    };

    tracing::debug!("verify_integrity_token: unwrapping result");
    let response: ciris_verify_core::play_integrity::IntegrityVerifyResponse = match result {
        Ok(r) => {
            tracing::debug!("verify_integrity_token: got successful response");
            r
        },
        Err(e) => {
            tracing::error!("Failed to verify integrity token: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    tracing::debug!("verify_integrity_token: calling response.summary()");
    let summary_str = response.summary();
    tracing::info!("Play Integrity verification: {}", summary_str);

    // Cache result for run_attestation L2 (with mutex error handling)
    tracing::debug!("verify_integrity_token: about to access device_attestation_cache");
    tracing::debug!("verify_integrity_token: handle_ref ptr = {:p}", handle_ref);
    tracing::debug!(
        "verify_integrity_token: cache field addr = {:p}",
        &handle_ref.device_attestation_cache
    );

    match handle_ref.device_attestation_cache.lock() {
        Ok(mut cache) => {
            tracing::debug!("verify_integrity_token: got cache lock");
            let cache_entry = ciris_verify_core::unified::DeviceAttestationCheckResult {
                platform: "android".to_string(),
                verified: response.verified,
                summary: response.summary(),
                error: response.error.clone(),
            };
            tracing::debug!("verify_integrity_token: created cache entry");
            *cache = Some(cache_entry);
            tracing::debug!("verify_integrity_token: cache updated");
        },
        Err(e) => {
            tracing::warn!("Could not cache attestation result (mutex poisoned): {}", e);
            // Continue anyway - caching is optional
        },
    }

    // Serialize to JSON
    let result_bytes = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize verification result: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy with null check
    let len = result_bytes.len();
    if len == 0 {
        tracing::error!("verify_integrity_token: empty result");
        return CirisVerifyError::InternalError as i32;
    }

    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("verify_integrity_token: malloc failed for {} bytes", len);
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), ptr, len);

    *result_json = ptr;
    *result_len = len;

    CirisVerifyError::Success as i32
}

/// Mobile blocking implementation using ureq (avoids tokio async I/O issues on JNI/iOS).
#[cfg(any(target_os = "android", target_os = "ios"))]
fn verify_integrity_token_blocking(
    token: &str,
    nonce: &str,
) -> Result<
    ciris_verify_core::play_integrity::IntegrityVerifyResponse,
    ciris_verify_core::VerifyError,
> {
    use ciris_verify_core::mobile_http;

    tracing::debug!("verify_integrity_token_blocking: creating TLS agent");
    let agent = mobile_http::create_tls_agent(std::time::Duration::from_secs(15))?;
    tracing::debug!("verify_integrity_token_blocking: TLS agent created");

    let url = "https://api.registry.ciris-services-1.ai/v1/integrity/verify";

    tracing::debug!("Mobile Play Integrity verify: POST {}", url);

    let payload = serde_json::json!({
        "token": token,
        "nonce": nonce,
    });
    tracing::debug!("verify_integrity_token_blocking: payload created");

    tracing::debug!("verify_integrity_token_blocking: sending POST request");
    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_json(&payload)
        .map_err(|e| ciris_verify_core::VerifyError::HttpsError {
            message: format!("Play Integrity verify request failed: {}", e),
        })?;
    tracing::debug!(
        "verify_integrity_token_blocking: POST request completed, status={}",
        response.status()
    );

    if response.status() != 200 {
        return Err(ciris_verify_core::VerifyError::HttpsError {
            message: format!(
                "Play Integrity verify returned status {}",
                response.status()
            ),
        });
    }

    tracing::debug!("verify_integrity_token_blocking: parsing JSON response");
    let result: ciris_verify_core::play_integrity::IntegrityVerifyResponse =
        response
            .into_json()
            .map_err(|e| ciris_verify_core::VerifyError::HttpsError {
                message: format!("Failed to parse Play Integrity response: {}", e),
            })?;
    tracing::debug!("verify_integrity_token_blocking: JSON parsed successfully");

    tracing::info!("Mobile Play Integrity verify: success");
    Ok(result)
}

/// Safely convert a C string pointer to a Rust &str with length limit.
/// Returns error if string is too long, not valid UTF-8, or contains embedded nulls.
unsafe fn safe_cstr_to_str(
    ptr: *const libc::c_char,
    max_len: usize,
) -> Result<&'static str, &'static str> {
    if ptr.is_null() {
        return Err("null pointer");
    }

    // Scan for null terminator with length limit
    let mut len = 0;
    while len < max_len {
        if *ptr.add(len) == 0 {
            break;
        }
        len += 1;
    }

    if len == 0 {
        return Err("empty string");
    }

    if len >= max_len {
        return Err("string too long (no null terminator found)");
    }

    // Create slice from the validated memory
    let slice = std::slice::from_raw_parts(ptr as *const u8, len);

    // Validate UTF-8
    std::str::from_utf8(slice).map_err(|_| "invalid UTF-8")
}

// =============================================================================
// App Attest API (Apple iOS Hardware Attestation)
// =============================================================================

/// Get an App Attest nonce from the registry.
///
/// This nonce should be hashed (SHA-256) and passed to DCAppAttestService.attestKey()
/// as the clientDataHash. The nonce is valid for a limited time (check expires_at).
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `nonce_json` - Output pointer for JSON-encoded AppAttestNonce (caller must free with `ciris_verify_free`)
/// * `nonce_len` - Output pointer for nonce length
///
/// # Result JSON Format
///
/// ```json
/// {
///   "nonce": "base64-url-encoded-nonce",
///   "expires_at": "2025-01-15T12:00:00Z"
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
/// - `nonce_json` and `nonce_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_app_attest_nonce(
    handle: *mut CirisVerifyHandle,
    nonce_json: *mut *mut u8,
    nonce_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_get_app_attest_nonce called");

    if handle.is_null() || nonce_json.is_null() || nonce_len.is_null() {
        tracing::error!("ciris_verify_get_app_attest_nonce: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    // Create registry client and fetch nonce
    let result = handle.runtime.handle().block_on(async {
        let client = ciris_verify_core::RegistryClient::new(
            "https://api.registry.ciris-services-1.ai",
            std::time::Duration::from_secs(10),
        )?;
        client.get_app_attest_nonce().await
    });

    let nonce = match result {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("Failed to get App Attest nonce: {}", e);
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Serialize to JSON
    let nonce_bytes = match serde_json::to_vec(&nonce) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize App Attest nonce: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = nonce_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(nonce_bytes.as_ptr(), ptr, len);

    *nonce_json = ptr;
    *nonce_len = len;

    tracing::info!("App Attest nonce retrieved successfully");
    CirisVerifyError::Success as i32
}

/// Verify an App Attest attestation object from iOS.
///
/// The attestation object is the CBOR data returned by DCAppAttestService.attestKey().
/// This verifies the attestation against Apple's certificate chain.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `request_json` - JSON-encoded AppAttestVerifyRequest
/// * `request_len` - Length of request JSON
/// * `result_json` - Output pointer for JSON-encoded AppAttestVerifyResponse (caller must free)
/// * `result_len` - Output pointer for result length
///
/// # Request JSON Format
///
/// ```json
/// {
///   "attestation": "base64-encoded-cbor",
///   "key_id": "key-id-from-generateKey",
///   "nonce": "the-nonce-used"
/// }
/// ```
///
/// # Result JSON Format
///
/// ```json
/// {
///   "verified": true,
///   "device_environment": {
///     "environment": "production",
///     "is_genuine_device": true,
///     "is_unmodified_app": true
///   },
///   "app_identity": {
///     "app_id": "TEAMID.ai.ciris.mobile",
///     "team_id": "TEAMID",
///     "bundle_id": "ai.ciris.mobile"
///   },
///   "receipt": { ... },
///   "error": null
/// }
/// ```
///
/// # Returns
///
/// 0 on success (check result JSON for verification status), negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `request_json` must point to valid UTF-8 JSON of length `request_len`
/// - `result_json` and `result_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_app_attest(
    handle: *mut CirisVerifyHandle,
    request_json: *const u8,
    request_len: usize,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_app_attest called");

    if handle.is_null() || request_json.is_null() || result_json.is_null() || result_len.is_null() {
        tracing::error!("ciris_verify_app_attest: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    // Check if we already have a successful attestation cached.
    // Nonces are single-use — resubmitting a consumed nonce returns 409.
    // Return the cached result instead of hitting the API again.
    if let Ok(cache) = handle.device_attestation_cache.lock() {
        if let Some(ref cached) = *cache {
            if cached.verified {
                tracing::info!(
                    "App Attest: returning cached successful result (nonce already consumed)"
                );
                let cached_response = ciris_verify_core::app_attest::AppAttestVerifyResponse {
                    verified: true,
                    device_environment: None,
                    app_identity: None,
                    receipt: None,
                    error: None,
                };
                if let Ok(bytes) = serde_json::to_vec(&cached_response) {
                    let len = bytes.len();
                    let ptr = libc::malloc(len) as *mut u8;
                    if !ptr.is_null() {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
                        *result_json = ptr;
                        *result_len = len;
                        return CirisVerifyError::Success as i32;
                    }
                }
            }
        }
    }

    let request_bytes = std::slice::from_raw_parts(request_json, request_len);

    // Parse request JSON
    let request_str = match std::str::from_utf8(request_bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("ciris_verify_app_attest: invalid UTF-8: {}", e);
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    let request: ciris_verify_core::app_attest::AppAttestVerifyRequest =
        match serde_json::from_str(request_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("ciris_verify_app_attest: invalid JSON: {}", e);
                return CirisVerifyError::SerializationError as i32;
            },
        };

    tracing::info!(
        "Verifying App Attest attestation: key_id={}",
        &request.key_id[..std::cmp::min(16, request.key_id.len())]
    );

    // Call registry to verify attestation
    let result = handle.runtime.handle().block_on(async {
        let client = ciris_verify_core::RegistryClient::new(
            "https://api.registry.ciris-services-1.ai",
            std::time::Duration::from_secs(30),
        )?;
        client
            .verify_app_attest(&request.attestation, &request.key_id, &request.nonce)
            .await
    });

    let response = match result {
        Ok(r) => r,
        Err(e) => {
            let err_msg = format!("{}", e);
            tracing::error!("App Attest verification failed: {}", err_msg);
            // Return error response rather than error code
            ciris_verify_core::app_attest::AppAttestVerifyResponse {
                verified: false,
                device_environment: None,
                app_identity: None,
                receipt: None,
                error: Some(
                    if err_msg.contains("409")
                        || err_msg.contains("consumed")
                        || err_msg.contains("expired")
                    {
                        "nonce_expired: Nonce already consumed or expired. Get a fresh nonce and re-attest.".to_string()
                    } else {
                        format!("Verification failed: {}", err_msg)
                    },
                ),
            }
        },
    };

    tracing::info!("App Attest verification result: {}", response.summary());

    // Cache result for run_attestation L2
    if let Ok(mut cache) = handle.device_attestation_cache.lock() {
        *cache = Some(ciris_verify_core::unified::DeviceAttestationCheckResult {
            platform: "ios".to_string(),
            verified: response.verified,
            summary: response.summary(),
            error: response.error.clone(),
        });
    }

    // Serialize result
    let result_bytes = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("ciris_verify_app_attest: JSON serialization failed: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = result_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), ptr, len);

    *result_json = ptr;
    *result_len = len;

    CirisVerifyError::Success as i32
}

/// Verify an App Attest assertion (for ongoing requests after initial attestation).
///
/// Assertions are used after the initial attestation to verify ongoing requests.
/// Each assertion includes a monotonic counter to prevent replay attacks.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `request_json` - JSON-encoded AppAttestAssertionRequest
/// * `request_len` - Length of request JSON
/// * `result_json` - Output pointer for JSON-encoded AppAttestAssertionResponse (caller must free)
/// * `result_len` - Output pointer for result length
///
/// # Request JSON Format
///
/// ```json
/// {
///   "assertion": "base64-encoded-assertion",
///   "key_id": "key-id-from-attestation",
///   "client_data": "base64-encoded-data-that-was-signed",
///   "nonce": "fresh-nonce-for-this-assertion"
/// }
/// ```
///
/// # Result JSON Format
///
/// ```json
/// {
///   "verified": true,
///   "counter": 42,
///   "error": null
/// }
/// ```
///
/// # Returns
///
/// 0 on success (check result JSON for verification status), negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `request_json` must point to valid UTF-8 JSON of length `request_len`
/// - `result_json` and `result_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_app_attest_assertion(
    handle: *mut CirisVerifyHandle,
    request_json: *const u8,
    request_len: usize,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_app_attest_assertion called");

    if handle.is_null() || request_json.is_null() || result_json.is_null() || result_len.is_null() {
        tracing::error!("ciris_verify_app_attest_assertion: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;
    let request_bytes = std::slice::from_raw_parts(request_json, request_len);

    // Parse request JSON
    let request_str = match std::str::from_utf8(request_bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("ciris_verify_app_attest_assertion: invalid UTF-8: {}", e);
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    let request: ciris_verify_core::app_attest::AppAttestAssertionRequest =
        match serde_json::from_str(request_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("ciris_verify_app_attest_assertion: invalid JSON: {}", e);
                return CirisVerifyError::SerializationError as i32;
            },
        };

    tracing::info!(
        "Verifying App Attest assertion: key_id={}",
        &request.key_id[..std::cmp::min(16, request.key_id.len())]
    );

    // Call registry to verify assertion
    let result = handle.runtime.handle().block_on(async {
        let client = ciris_verify_core::RegistryClient::new(
            "https://api.registry.ciris-services-1.ai",
            std::time::Duration::from_secs(30),
        )?;
        client
            .verify_app_attest_assertion(
                &request.assertion,
                &request.key_id,
                &request.client_data,
                &request.nonce,
            )
            .await
    });

    let response = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("App Attest assertion verification failed: {}", e);
            ciris_verify_core::app_attest::AppAttestAssertionResponse {
                verified: false,
                counter: None,
                error: Some(format!("Assertion verification failed: {}", e)),
            }
        },
    };

    tracing::info!(
        "App Attest assertion result: verified={}, counter={:?}",
        response.verified,
        response.counter
    );

    // Serialize result
    let result_bytes = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "ciris_verify_app_attest_assertion: JSON serialization failed: {}",
                e
            );
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = result_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), ptr, len);

    *result_json = ptr;
    *result_len = len;

    CirisVerifyError::Success as i32
}

// =============================================================================
// Log Callback Registration
// =============================================================================

/// Register a callback function to receive all CIRISVerify log events.
///
/// The callback receives:
/// - `level`: 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG, 5=TRACE
/// - `target`: The module path (e.g. "ciris_verify_core::engine"), null-terminated UTF-8
/// - `message`: The log message, null-terminated UTF-8
///
/// Pass NULL to unregister the callback.
///
/// The callback may be invoked from any thread. The `target` and `message` pointers
/// are only valid for the duration of the callback invocation.
///
/// # Safety
///
/// If non-null, `callback` must point to a valid function with the expected signature.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_set_log_callback(callback: Option<CirisLogCallback>) {
    match callback {
        Some(cb) => {
            LOG_CALLBACK.store(cb as usize, Ordering::Relaxed);
            tracing::info!("Log callback registered");
        },
        None => {
            LOG_CALLBACK.store(0, Ordering::Relaxed);
            // Don't log here — the callback is already gone
        },
    }
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

        // Check for null JString parameters
        if deployment_id.is_null() {
            tracing::error!("JNI: nativeGetStatus - null deployment_id");
            return JByteArray::default();
        }
        if challenge_nonce.is_null() {
            tracing::error!("JNI: nativeGetStatus - null challenge_nonce");
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

    // =========================================================================
    // Play Integrity API (Google Android Hardware Attestation)
    // =========================================================================

    /// Get Play Integrity nonce from registry (returns JSON string)
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeGetIntegrityNonce<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> JString<'local> {
        tracing::debug!("JNI: nativeGetIntegrityNonce called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeGetIntegrityNonce - null handle");
            return JString::default();
        }

        let mut nonce_data: *mut u8 = std::ptr::null_mut();
        let mut nonce_len: usize = 0;

        let result = ciris_verify_get_integrity_nonce(handle, &mut nonce_data, &mut nonce_len);

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!("JNI: nativeGetIntegrityNonce failed with code {}", result);
            return JString::default();
        }

        if nonce_data.is_null() {
            tracing::warn!("JNI: nativeGetIntegrityNonce returned null");
            return JString::default();
        }

        let slice = std::slice::from_raw_parts(nonce_data, nonce_len);
        let json_str = match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: nonce response is not valid UTF-8: {}", e);
                ciris_verify_free(nonce_data as *mut libc::c_void);
                return JString::default();
            },
        };

        let jstring = match env.new_string(json_str) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: failed to create nonce string: {}", e);
                ciris_verify_free(nonce_data as *mut libc::c_void);
                return JString::default();
            },
        };

        ciris_verify_free(nonce_data as *mut libc::c_void);
        jstring
    }

    /// Verify Play Integrity token (returns JSON string)
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeVerifyIntegrityToken<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        token: JString<'local>,
        nonce: JString<'local>,
    ) -> JString<'local> {
        tracing::debug!("JNI: nativeVerifyIntegrityToken called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeVerifyIntegrityToken - null handle");
            return JString::default();
        }

        // Check for null JString parameters (Java can pass null)
        if token.is_null() {
            tracing::error!("JNI: nativeVerifyIntegrityToken - null token");
            return JString::default();
        }
        if nonce.is_null() {
            tracing::error!("JNI: nativeVerifyIntegrityToken - null nonce");
            return JString::default();
        }

        // Get token string
        let token_str: String = match env.get_string(&token) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get token string: {}", e);
                return JString::default();
            },
        };

        // Get nonce string
        let nonce_str: String = match env.get_string(&nonce) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get nonce string: {}", e);
                return JString::default();
            },
        };

        // Convert to C strings
        let token_cstr = match std::ffi::CString::new(token_str) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: failed to create token CString: {}", e);
                return JString::default();
            },
        };

        let nonce_cstr = match std::ffi::CString::new(nonce_str) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: failed to create nonce CString: {}", e);
                return JString::default();
            },
        };

        let mut result_data: *mut u8 = std::ptr::null_mut();
        let mut result_len: usize = 0;

        let result = ciris_verify_verify_integrity_token(
            handle,
            token_cstr.as_ptr(),
            nonce_cstr.as_ptr(),
            &mut result_data,
            &mut result_len,
        );

        if result != CirisVerifyError::Success as i32 {
            tracing::warn!(
                "JNI: nativeVerifyIntegrityToken failed with code {}",
                result
            );
            return JString::default();
        }

        if result_data.is_null() {
            tracing::warn!("JNI: nativeVerifyIntegrityToken returned null");
            return JString::default();
        }

        let slice = std::slice::from_raw_parts(result_data, result_len);
        let json_str = match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: integrity result is not valid UTF-8: {}", e);
                ciris_verify_free(result_data as *mut libc::c_void);
                return JString::default();
            },
        };

        let jstring = match env.new_string(json_str) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: failed to create integrity result string: {}", e);
                ciris_verify_free(result_data as *mut libc::c_void);
                return JString::default();
            },
        };

        ciris_verify_free(result_data as *mut libc::c_void);
        jstring
    }
}
