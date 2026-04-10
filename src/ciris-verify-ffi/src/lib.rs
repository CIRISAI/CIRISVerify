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

use std::ffi::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};

// =============================================================================
// Attestation Busy Flag
// =============================================================================
//
// Attestation can take 2+ seconds (network calls to registry). During this time,
// the Rust runtime may be blocked if called from FFI with block_on(). To prevent
// race conditions where other FFI calls (has_key, sign, etc.) are made during
// attestation, we use an atomic flag to track when attestation is running.
//
// Key operations check this flag and return CIRIS_ERROR_ATTESTATION_IN_PROGRESS
// (-100) if attestation is running, allowing callers to retry after a delay.

/// Global flag indicating attestation is currently running.
/// When true, key operations should return ATTESTATION_IN_PROGRESS.
static ATTESTATION_RUNNING: AtomicBool = AtomicBool::new(false);

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

use ciris_keyring::storage::{create_platform_storage, SecureBlobStorage};
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

/// Get the correct platform OS name.
///
/// On Android, `std::env::consts::OS` returns "linux" because Android
/// uses the Linux kernel. This function returns "android" on Android
/// for accurate platform reporting.
fn get_platform_os() -> String {
    #[cfg(target_os = "android")]
    {
        "android".to_string()
    }
    #[cfg(target_os = "ios")]
    {
        "ios".to_string()
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        std::env::consts::OS.to_string()
    }
}

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
    // Use SeqCst to ensure we see the most recent store from set_log_callback
    let ptr = LOG_CALLBACK.load(Ordering::SeqCst);
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

        // Wrap callback invocation in catch_unwind to prevent panics from unwinding
        // across FFI boundary (undefined behavior). SIGSEGV is not caught by this,
        // but panics from the Python callback mechanism are.
        let target_ptr = target.as_ptr();
        let message_ptr = message.as_ptr();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            callback(level, target_ptr, message_ptr);
        }));
        // Keep target and message alive until after callback returns
        drop(target);
        drop(message);
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
    /// Cached audit trail verification result.
    /// Populated when ciris_verify_audit_trail is called. Used by run_attestation for L5.
    audit_trail_cache: std::sync::Mutex<Option<ciris_verify_core::audit::AuditVerificationResult>>,
    /// Secure blob storage for named keys (WA signing, sessions, etc.)
    /// Lazily initialized on first use via get_or_init_named_storage().
    named_key_storage: std::sync::Mutex<Option<Box<dyn SecureBlobStorage>>>,
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
    /// No signing key available.
    NoKey = -5,
    /// Signing operation failed.
    SigningFailed = -6,
    /// IO error (file read/write).
    IoError = -7,
    /// Manifest cache not found.
    CacheNotFound = -8,
    /// Signature verification failed (possible tampering).
    SignatureInvalid = -9,
    /// Version or target mismatch.
    VersionMismatch = -10,
    /// Internal error.
    InternalError = -99,
    /// Attestation is currently running - retry after delay.
    ///
    /// This error is returned when key operations (has_key, get_public_key,
    /// sign, import_key) are called while attestation is in progress.
    /// The caller should wait ~500ms and retry.
    AttestationInProgress = -100,
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
    // Log environment before creating signer to trace key persistence path
    tracing::info!(
        ciris_data_dir = ?std::env::var("CIRIS_DATA_DIR").ok(),
        ciris_key_path = ?std::env::var("CIRIS_KEY_PATH").ok(),
        current_dir = ?std::env::current_dir().ok(),
        "VERIFY Creating Ed25519 signer - environment snapshot"
    );

    // Note: MutableEd25519Signer::new() automatically attempts to load persisted keys
    let ed25519_signer = MutableEd25519Signer::new("agent_signing");

    // Log comprehensive diagnostics for debugging key persistence issues
    tracing::info!("VERIFY Ed25519 signer initialized");
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
        audit_trail_cache: std::sync::Mutex::new(None),
        named_key_storage: std::sync::Mutex::new(None),
    });
    Box::into_raw(handle)
}

/// Get or initialize the named key storage.
///
/// Uses platform-specific hardware storage (TPM/Keystore/SecureEnclave) when available,
/// falling back to software storage. Storage is initialized lazily on first use.
fn get_or_init_named_storage(
    handle: &CirisVerifyHandle,
) -> Result<std::sync::MutexGuard<'_, Option<Box<dyn SecureBlobStorage>>>, i32> {
    let mut storage_guard = handle.named_key_storage.lock().map_err(|_| {
        tracing::error!("Failed to lock named_key_storage mutex");
        CirisVerifyError::InternalError as i32
    })?;

    if storage_guard.is_none() {
        // Get storage directory from environment or default
        let storage_dir = std::env::var("CIRIS_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                #[cfg(target_os = "android")]
                {
                    PathBuf::from(".")
                }
                #[cfg(target_os = "ios")]
                {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join("Documents/ciris-verify")
                }
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                {
                    dirs::data_local_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join("ciris-verify")
                }
            });

        tracing::info!(
            storage_dir = %storage_dir.display(),
            "Initializing named key storage"
        );

        let storage = create_platform_storage("named_keys", &storage_dir).map_err(|e| {
            tracing::error!("Failed to create named key storage: {}", e);
            CirisVerifyError::InternalError as i32
        })?;

        tracing::info!(
            hw_backed = storage.is_hardware_backed(),
            "Named key storage initialized"
        );

        *storage_guard = Some(storage);
    }

    Ok(storage_guard)
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
                source: "eu.registry.ciris-services-eu-1.com".to_string(),
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

/// Free a C string returned by CIRISVerify (e.g., from `ciris_verify_list_named_keys`).
///
/// # Safety
///
/// `str_ptr` must be a pointer returned by a CIRISVerify function that returns
/// a C string, or NULL.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_free_string(str_ptr: *mut c_char) {
    if !str_ptr.is_null() {
        // CString::from_raw takes ownership and deallocates when dropped
        let _ = std::ffi::CString::from_raw(str_ptr);
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

    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("sign: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)");
        return CirisVerifyError::AttestationInProgress as i32;
    }

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

    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!(
            "get_public_key: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)"
        );
        return CirisVerifyError::AttestationInProgress as i32;
    }

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
        // This will use hardware protection (TPM/Keystore/SE) if available
        tracing::info!(
            hardware_available = handle.ed25519_signer.is_hardware_backed(),
            "No persisted key found, generating Ed25519 key for initial attestation"
        );

        // Generate key (uses hardware if available, sets hardware marker)
        if let Err(e) = handle.ed25519_signer.generate_key() {
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
    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!(
            "import_key: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)"
        );
        return CirisVerifyError::AttestationInProgress as i32;
    }

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

/// Wait for key registration in registry after portal import.
///
/// Polls registry endpoints once per second for up to 5 seconds.
/// Returns JSON: `{"status": "active"|"pending"|"error", "fingerprint": "...", "elapsed_ms": N}`
///
/// - "active": Key confirmed in registry, ready for attestation with key_type="portal"
/// - "pending": Timeout (5s), attestation will have key_type="pending"
/// - "error": Registry unreachable or other error
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `result_out` - Pointer to receive JSON result string (caller must free with `ciris_verify_free_string`)
///
/// # Returns
///
/// 0 on success (check JSON status), negative on error.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `result_out` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_await_key_registration(
    handle: *mut CirisVerifyHandle,
    result_out: *mut *mut c_char,
) -> i32 {
    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("await_key_registration: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || result_out.is_null() {
        tracing::error!("await_key_registration: null handle or result_out");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;
    let start = std::time::Instant::now();

    // Get the current key's fingerprint
    let fingerprint = match handle_ref.ed25519_signer.get_public_key() {
        Some(pk) => ciris_verify_core::registry::compute_ed25519_fingerprint(&pk),
        None => {
            tracing::error!("await_key_registration: no key loaded");
            let json = r#"{"status": "error", "error": "no_key_loaded", "elapsed_ms": 0}"#;
            *result_out = std::ffi::CString::new(json).unwrap().into_raw();
            return CirisVerifyError::Success as i32;
        },
    };

    tracing::info!(
        fingerprint = %fingerprint,
        "Awaiting key registration in registry (max 5s)"
    );

    // Create runtime for async polling
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("await_key_registration: failed to create runtime: {}", e);
            let json = format!(
                r#"{{"status": "error", "error": "runtime_error", "fingerprint": "{}", "elapsed_ms": {}}}"#,
                fingerprint,
                start.elapsed().as_millis()
            );
            *result_out = std::ffi::CString::new(json).unwrap().into_raw();
            return CirisVerifyError::Success as i32;
        },
    };

    // Poll registry once per second for up to 5 seconds
    let result = rt.block_on(async {
        use ciris_verify_core::registry::{ResilientRegistryClient, FALLBACK_REGISTRY_URLS};

        let client = match ResilientRegistryClient::new(
            "https://api.registry.ciris-services-1.ai",
            FALLBACK_REGISTRY_URLS,
            std::time::Duration::from_secs(5),
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create registry client: {}", e);
                return format!(
                    r#"{{"status": "error", "error": "client_init_failed", "fingerprint": "{}", "elapsed_ms": {}}}"#,
                    fingerprint,
                    start.elapsed().as_millis()
                );
            },
        };

        let max_attempts = 5;

        for attempt in 1..=max_attempts {
            tracing::debug!(
                attempt = attempt,
                fingerprint = %fingerprint,
                "Checking registry for key"
            );

            match client.verify_key_by_fingerprint(&fingerprint).await {
                Ok(response) => {
                    tracing::info!(
                        attempt = attempt,
                        status = %response.status,
                        found = response.found,
                        fingerprint = %fingerprint,
                        elapsed_ms = start.elapsed().as_millis(),
                        "Registry key check result"
                    );

                    // Check if key is active (KEY_ACTIVE or status contains "active")
                    if response.found && (response.status == "KEY_ACTIVE" || response.status.to_lowercase().contains("active")) {
                        return format!(
                            r#"{{"status": "active", "fingerprint": "{}", "elapsed_ms": {}, "attempts": {}}}"#,
                            fingerprint,
                            start.elapsed().as_millis(),
                            attempt
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        attempt = attempt,
                        error = %e,
                        "Registry check failed, will retry"
                    );
                },
            }

            if attempt < max_attempts {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }

        // Timeout - return pending
        tracing::warn!(
            fingerprint = %fingerprint,
            elapsed_ms = start.elapsed().as_millis(),
            "Key registration timeout (5s), returning pending"
        );
        format!(
            r#"{{"status": "pending", "fingerprint": "{}", "elapsed_ms": {}, "attempts": {}}}"#,
            fingerprint,
            start.elapsed().as_millis(),
            max_attempts
        )
    });

    *result_out = std::ffi::CString::new(result).unwrap().into_raw();
    CirisVerifyError::Success as i32
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
    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!(
            "has_key: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)"
        );
        return CirisVerifyError::AttestationInProgress as i32;
    }

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
    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!(
            "delete_key: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)"
        );
        return CirisVerifyError::AttestationInProgress as i32;
    }

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

/// Generate a new Ed25519 signing key.
///
/// This creates an ephemeral key that can be used for attestation before
/// Portal issues a permanent key. The key is stored with hardware protection
/// (TPM/Keystore/Secure Enclave) if available.
///
/// Use cases:
/// - Initial attestation before Portal key activation
/// - Recovery after orphaned key cleanup
/// - Testing/development without Portal
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
///
/// # Returns
///
/// 0 on success, negative error code on failure.
/// Returns -100 (ATTESTATION_IN_PROGRESS) if attestation is running.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_generate_key(handle: *mut CirisVerifyHandle) -> i32 {
    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!(
            "generate_key: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)"
        );
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() {
        tracing::error!("generate_key: null handle");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Check if key already exists - wrap in catch_unwind since has_key()
    // on Android creates a tokio runtime and runs JNI code that can panic
    let key_exists = match catch_unwind(AssertUnwindSafe(|| handle_ref.ed25519_signer.has_key())) {
        Ok(exists) => exists,
        Err(e) => {
            // has_key() panicked - treat as "no key exists" and proceed to generate
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::warn!(
                "generate_key: has_key() panicked (JNI issue?): {} - proceeding to generate",
                msg
            );
            false
        },
    };

    if key_exists {
        tracing::warn!("generate_key: key already exists, delete first if you want a new one");
        // Return success - key exists, which is the goal
        return CirisVerifyError::Success as i32;
    }

    // Also wrap is_hardware_backed() in case of JNI issues
    let hardware_available = catch_unwind(AssertUnwindSafe(|| {
        handle_ref.ed25519_signer.is_hardware_backed()
    }))
    .unwrap_or(false);

    tracing::info!(
        hardware_available = hardware_available,
        "Generating new Ed25519 key (ephemeral)"
    );

    match catch_unwind(AssertUnwindSafe(|| {
        handle_ref.ed25519_signer.generate_key()
    })) {
        Ok(Ok(())) => {
            // Log the fingerprint for debugging - wrap in catch_unwind since
            // get_public_key() on Android involves JNI which could panic
            let _ = catch_unwind(AssertUnwindSafe(|| {
                if let Some(pk) = handle_ref.ed25519_signer.get_public_key() {
                    let fingerprint = ciris_verify_core::registry::compute_ed25519_fingerprint(&pk);
                    let hw_backed = handle_ref.ed25519_signer.is_hardware_backed();
                    tracing::info!(
                        fingerprint = %fingerprint,
                        hardware_backed = hw_backed,
                        "Ed25519 key generated successfully"
                    );
                }
            }));
            // Return success regardless - key was generated
            CirisVerifyError::Success as i32
        },
        Ok(Err(e)) => {
            tracing::error!("Failed to generate Ed25519 key: {}", e);
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
            tracing::error!("generate_key: panic caught: {}", msg);
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
    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!(
            "sign_ed25519: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)"
        );
        return CirisVerifyError::AttestationInProgress as i32;
    }

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
    // Check if attestation is running - if so, return busy status
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("get_ed25519_public_key: attestation in progress, returning ATTESTATION_IN_PROGRESS (-100)");
        return CirisVerifyError::AttestationInProgress as i32;
    }

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

    // Set attestation running flag to block concurrent key operations
    // This prevents race conditions when audit service calls has_key during attestation
    ATTESTATION_RUNNING.store(true, Ordering::SeqCst);
    tracing::info!("ATTESTATION_RUNNING flag set to true");

    // Use a guard to ensure the flag is cleared on all exit paths
    struct AttestationGuard;
    impl Drop for AttestationGuard {
        fn drop(&mut self) {
            ATTESTATION_RUNNING.store(false, Ordering::SeqCst);
            tracing::info!("ATTESTATION_RUNNING flag cleared");
        }
    }
    let _guard = AttestationGuard;

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
    // If no key exists, auto-generate an ephemeral one for attestation
    let (has_key, key_was_generated) = if !handle.ed25519_signer.has_key() {
        tracing::info!(
            hardware_available = handle.ed25519_signer.is_hardware_backed(),
            "No key found during attestation, generating ephemeral Ed25519 key"
        );
        match handle.ed25519_signer.generate_key() {
            Ok(()) => {
                if let Some(pk) = handle.ed25519_signer.get_public_key() {
                    let fingerprint = ciris_verify_core::registry::compute_ed25519_fingerprint(&pk);
                    tracing::info!(
                        fingerprint = %fingerprint,
                        "Ephemeral Ed25519 key generated for attestation"
                    );
                }
                (true, true)
            },
            Err(e) => {
                tracing::error!("Failed to generate ephemeral key: {}", e);
                (false, false)
            },
        }
    } else {
        (true, false)
    };

    // Determine key_type based on registry verification status (not just has_key)
    // - "portal": Key fingerprint verified as active in registry
    // - "pending": Key just imported, waiting for registry propagation
    // - "local": Key exists but not found in registry (self-generated)
    // - "ephemeral": Key was just generated for this attestation
    // - "unverified": Key exists but registry couldn't be contacted
    // - "none": No key loaded (generation failed)
    let key_type = if !has_key {
        "none"
    } else if key_was_generated {
        "ephemeral"
    } else {
        match result.registry_key_status.as_str() {
            "active" => "portal",          // Confirmed by registry
            "pending" => "pending",        // Just imported, awaiting registry propagation
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
    let signer_hw_backed = handle.ed25519_signer.is_hardware_backed();
    let hardware_backed = signer_hw_backed && !running_in_vm;

    tracing::info!(
        signer_hw_backed = signer_hw_backed,
        running_in_vm = running_in_vm,
        hardware_backed = hardware_backed,
        hardware_type = %hw_type_str,
        "Attestation hardware detection"
    );
    let storage_mode = match capabilities.hardware_type {
        ciris_keyring::HardwareType::AndroidKeystore => {
            "HW-AES-256-GCM (Android Keystore)".to_string()
        },
        ciris_keyring::HardwareType::IosSecureEnclave
        | ciris_keyring::HardwareType::MacOsSecureEnclave => "Secure Enclave".to_string(),
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
        platform_os: get_platform_os(),
    });

    // Inject cached device attestation result (from prior Play Integrity / App Attest call)
    // On mobile platforms, this is automatically populated; on desktop it's N/A.
    let device_attestation = handle
        .device_attestation_cache
        .lock()
        .ok()
        .and_then(|cache| cache.clone());

    // Inject cached audit trail result if not already present in the request
    // This allows ciris_verify_audit_trail to be called separately before run_attestation
    if result.audit_trail.is_none() {
        if let Ok(cache) = handle.audit_trail_cache.lock() {
            if let Some(ref cached_audit) = *cache {
                tracing::info!(
                    "Injecting cached audit trail for L5: valid={}, entries={}",
                    cached_audit.valid,
                    cached_audit.total_entries
                );
                result.audit_trail = Some(cached_audit.clone());
                // Add audit to check counts if not already counted
                result.checks_total += 1;
                if cached_audit.valid {
                    result.checks_passed += 1;
                }
            }
        }
    }

    if let Some(ref da) = device_attestation {
        // Add device attestation as a check
        result.checks_total += 1;
        if da.verified {
            result.checks_passed += 1;
        }
        result.device_attestation = Some(da.clone());

        // Recalculate level with device attestation factored in
        // On iOS, function integrity always fails (Xcode code signing relocates addresses).
        // App Attest (L2) acts as a compensating trust signal: when device attestation
        // is verified, L1 passes with binary_valid alone (function integrity forgiven).
        #[cfg(target_os = "ios")]
        let l1_pass = result
            .self_verification
            .as_ref()
            .map(|sv| sv.binary_valid)
            .unwrap_or(false);
        #[cfg(not(target_os = "ios"))]
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
        // Prefer module_integrity (handles server-only exclusions), fall back to legacy
        let l4_pass = if result.module_integrity.is_some() {
            // Unified check: module_integrity covers everything
            l3_pass
                && result
                    .module_integrity
                    .as_ref()
                    .map(|mi| mi.valid)
                    .unwrap_or(false)
        } else {
            // Legacy fallback: require both file_integrity AND python_integrity
            l3_pass
                && result
                    .file_integrity
                    .as_ref()
                    .map(|fi| fi.full.as_ref().map(|f| f.valid).unwrap_or(false))
                    .unwrap_or(false)
                && result
                    .python_integrity
                    .as_ref()
                    .map(|pi| pi.valid)
                    .unwrap_or(false)
        };
        // L5: Audit trail (MUST be checked and valid) + registry key (must be active)
        let audit_valid = result
            .audit_trail
            .as_ref()
            .map(|a| a.valid)
            .unwrap_or(false);
        let key_active = result.registry_key_status == "active";
        tracing::debug!(
            l4_pass = l4_pass,
            audit_valid = audit_valid,
            audit_present = result.audit_trail.is_some(),
            key_status = %result.registry_key_status,
            key_active = key_active,
            "L5 calculation inputs"
        );
        let l5_pass = l4_pass && audit_valid && key_active;

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
        // No device attestation cached yet - app hasn't attempted Play Integrity / App Attest.
        // Once attempted (success OR failure), the result gets cached and level_pending=false.
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            result.level_pending = true;
            tracing::info!("Mobile: no device attestation cached yet, level_pending=true");
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            // Desktop: L2 = hardware environment detected (TPM + hardware-backed key)
            // This is separate from TPM PCR attestation which adds confidence but isn't required
            let has_tpm = matches!(
                ciris_keyring::detect_hardware_type().hardware_type,
                ciris_keyring::HardwareType::TpmDiscrete | ciris_keyring::HardwareType::TpmFirmware
            );

            // Recalculate levels for desktop based on hardware detection
            let l1_pass = result
                .self_verification
                .as_ref()
                .map(|sv| sv.binary_valid && sv.functions_valid)
                .unwrap_or(false);
            // L2: Hardware environment detected (TPM + not VM + hardware-backed key)
            let l2_pass = l1_pass && has_tpm && !running_in_vm && hardware_backed;
            let sources_agreeing = u8::from(result.sources.dns_us_valid)
                + u8::from(result.sources.dns_eu_valid)
                + u8::from(result.sources.https_valid);
            let l3_pass = l2_pass && sources_agreeing >= 2;
            // L4: File integrity (MUST be checked and valid)
            // Prefer module_integrity (handles server-only exclusions), fall back to legacy
            let l4_pass = if result.module_integrity.is_some() {
                // Unified check: module_integrity covers everything
                l3_pass
                    && result
                        .module_integrity
                        .as_ref()
                        .map(|mi| mi.valid)
                        .unwrap_or(false)
            } else {
                // Legacy fallback: require both file_integrity AND python_integrity
                l3_pass
                    && result
                        .file_integrity
                        .as_ref()
                        .map(|fi| fi.full.as_ref().map(|f| f.valid).unwrap_or(false))
                        .unwrap_or(false)
                    && result
                        .python_integrity
                        .as_ref()
                        .map(|pi| pi.valid)
                        .unwrap_or(true) // Python integrity optional on desktop
            };
            // L5: Audit trail + registry key
            let audit_valid = result
                .audit_trail
                .as_ref()
                .map(|a| a.valid)
                .unwrap_or(false);
            let key_active = result.registry_key_status == "active";
            tracing::debug!(
                l4_pass = l4_pass,
                audit_valid = audit_valid,
                audit_present = result.audit_trail.is_some(),
                key_status = %result.registry_key_status,
                key_active = key_active,
                "L5 calculation inputs (desktop)"
            );
            let l5_pass = l4_pass && audit_valid && key_active;

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

            if has_tpm && hardware_backed {
                // TPM available - level calculation is complete, not pending
                result.level_pending = false;
                tracing::info!(
                    "Desktop level calculated: L1={}, L2={} (TPM), L3={} (sources={}), level={}",
                    l1_pass,
                    l2_pass,
                    l3_pass,
                    sources_agreeing,
                    result.level
                );
            } else {
                // No TPM or software-only key - L1 is max
                result.level_pending = false;
                tracing::info!(
                    "Desktop software-only: L1={}, level={}",
                    l1_pass,
                    result.level
                );
            }
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

// =============================================================================
// MANIFEST CACHE - Hardware-signed offline L1 verification
// =============================================================================

/// Save manifests to a hardware-signed cache for offline L1 verification.
///
/// After successful attestation with registry access, call this function to
/// cache the manifests locally with a hardware signature. When the registry
/// is unreachable, the cached manifest can be used for L1 self-verification.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `binary_manifest_json` - JSON-encoded BinaryManifest
/// * `binary_manifest_len` - Length of binary manifest JSON
/// * `function_manifest_json` - JSON-encoded FunctionManifest (can be null)
/// * `function_manifest_len` - Length of function manifest JSON (0 if null)
/// * `build_record_json` - JSON-encoded BuildRecord (can be null)
/// * `build_record_len` - Length of build record JSON (0 if null)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `binary_manifest_json` must be valid for `binary_manifest_len` bytes
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_save_manifest_cache(
    handle: *mut CirisVerifyHandle,
    binary_manifest_json: *const u8,
    binary_manifest_len: usize,
    function_manifest_json: *const u8,
    function_manifest_len: usize,
    build_record_json: *const u8,
    build_record_len: usize,
) -> i32 {
    ffi_guard!("ciris_verify_save_manifest_cache", {
        save_manifest_cache_inner(
            handle,
            binary_manifest_json,
            binary_manifest_len,
            function_manifest_json,
            function_manifest_len,
            build_record_json,
            build_record_len,
        )
    })
}

/// Inner implementation of save_manifest_cache.
unsafe fn save_manifest_cache_inner(
    handle: *mut CirisVerifyHandle,
    binary_manifest_json: *const u8,
    binary_manifest_len: usize,
    function_manifest_json: *const u8,
    function_manifest_len: usize,
    build_record_json: *const u8,
    build_record_len: usize,
) -> i32 {
    use ciris_verify_core::manifest_cache::SignedManifestCache;
    use ciris_verify_core::registry::BinaryManifest;
    use ciris_verify_core::security::function_integrity::FunctionManifest;

    tracing::info!("ciris_verify_save_manifest_cache: starting");

    if handle.is_null() || binary_manifest_json.is_null() {
        tracing::error!("ciris_verify_save_manifest_cache: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    // Check if we have a key to sign with
    if !handle.ed25519_signer.has_key() {
        tracing::error!("ciris_verify_save_manifest_cache: no signing key available");
        return CirisVerifyError::NoKey as i32;
    }

    // Get public key fingerprint
    let public_key = match handle.ed25519_signer.get_public_key() {
        Some(pk) => pk,
        None => {
            tracing::error!("ciris_verify_save_manifest_cache: failed to get public key");
            return CirisVerifyError::InternalError as i32;
        },
    };
    let fingerprint = ciris_verify_core::compute_ed25519_fingerprint(&public_key);

    // Parse binary manifest (required)
    let binary_slice = std::slice::from_raw_parts(binary_manifest_json, binary_manifest_len);
    let binary_str = match std::str::from_utf8(binary_slice) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_save_manifest_cache: invalid binary manifest UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };
    let binary_manifest: BinaryManifest = match serde_json::from_str(binary_str) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                "ciris_verify_save_manifest_cache: invalid binary manifest JSON: {}",
                e
            );
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Parse function manifest (optional)
    let function_manifest: Option<FunctionManifest> = if !function_manifest_json.is_null()
        && function_manifest_len > 0
    {
        let func_slice = std::slice::from_raw_parts(function_manifest_json, function_manifest_len);
        match std::str::from_utf8(func_slice) {
            Ok(func_str) => match serde_json::from_str(func_str) {
                Ok(m) => Some(m),
                Err(e) => {
                    tracing::warn!(
                        "ciris_verify_save_manifest_cache: invalid function manifest JSON: {}",
                        e
                    );
                    None
                },
            },
            Err(e) => {
                tracing::warn!(
                    "ciris_verify_save_manifest_cache: invalid function manifest UTF-8: {}",
                    e
                );
                None
            },
        }
    } else {
        None
    };

    // Parse build record (optional) - for file integrity
    let build_record: Option<ciris_verify_core::BuildRecord> =
        if !build_record_json.is_null() && build_record_len > 0 {
            let build_slice = std::slice::from_raw_parts(build_record_json, build_record_len);
            match std::str::from_utf8(build_slice) {
                Ok(build_str) => match serde_json::from_str(build_str) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        tracing::warn!(
                            "ciris_verify_save_manifest_cache: invalid build record JSON: {}",
                            e
                        );
                        None
                    },
                },
                Err(e) => {
                    tracing::warn!(
                        "ciris_verify_save_manifest_cache: invalid build record UTF-8: {}",
                        e
                    );
                    None
                },
            }
        } else {
            None
        };

    // Create unsigned cache
    let mut cache = SignedManifestCache::new(
        binary_manifest,
        function_manifest,
        build_record.as_ref(),
        fingerprint,
    );

    // Sign the cache
    let hash = cache.compute_signing_hash();
    let signature = match handle.ed25519_signer.sign(&hash) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!("ciris_verify_save_manifest_cache: signing failed: {}", e);
            return CirisVerifyError::SigningFailed as i32;
        },
    };
    cache.set_signature(signature);

    // Get cache directory
    let cache_dir = ciris_verify_core::VerifyConfig::default()
        .cache_dir
        .unwrap_or_else(|| std::env::temp_dir().join("ciris-verify-cache"));

    // Save to disk
    if let Err(e) = cache.save(&cache_dir) {
        tracing::error!("ciris_verify_save_manifest_cache: save failed: {}", e);
        return CirisVerifyError::IoError as i32;
    }

    tracing::info!(
        cache_dir = %cache_dir.display(),
        binaries = cache.binary_manifest.binaries.len(),
        has_functions = cache.function_manifest.is_some(),
        has_build = cache.build_record.is_some(),
        "ciris_verify_save_manifest_cache: saved signed manifest cache"
    );

    CirisVerifyError::Success as i32
}

/// Load and verify a cached manifest for offline L1 verification.
///
/// Returns the cached manifest as JSON if signature verification passes.
/// Use this when the registry is unreachable to still perform L1 self-verification.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `result_json` - Output pointer for JSON-encoded SignedManifestCache
/// * `result_len` - Output pointer for result length
///
/// # Result JSON Format
///
/// ```json
/// {
///   "binary_manifest": { "version": "1.0.0", "binaries": {...} },
///   "function_manifest": { ... },
///   "build_record": { "version": "...", "files": {...} },
///   "cached_at": 1234567890,
///   "verify_version": "1.2.0",
///   "target": "x86_64-unknown-linux-gnu",
///   "public_key_fingerprint": "abc123...",
///   "signature": "..."
/// }
/// ```
///
/// # Returns
///
/// 0 on success, negative error code on failure:
/// - `CirisVerifyError::NoKey` - No signing key available to verify
/// - `CirisVerifyError::CacheNotFound` - No cached manifest exists
/// - `CirisVerifyError::SignatureInvalid` - Signature verification failed (tampering?)
/// - `CirisVerifyError::VersionMismatch` - Cache is for different version/target
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `result_json` and `result_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_load_manifest_cache(
    handle: *mut CirisVerifyHandle,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_load_manifest_cache", {
        load_manifest_cache_inner(handle, result_json, result_len)
    })
}

/// Inner implementation of load_manifest_cache.
unsafe fn load_manifest_cache_inner(
    handle: *mut CirisVerifyHandle,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    use ciris_verify_core::manifest_cache::{load_and_verify, CacheLoadResult};

    tracing::info!("ciris_verify_load_manifest_cache: starting");

    if handle.is_null() || result_json.is_null() || result_len.is_null() {
        tracing::error!("ciris_verify_load_manifest_cache: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle = &*handle;

    // Get public key for verification
    let public_key = match handle.ed25519_signer.get_public_key() {
        Some(pk) => pk,
        None => {
            tracing::error!("ciris_verify_load_manifest_cache: no public key available");
            return CirisVerifyError::NoKey as i32;
        },
    };

    // Get cache directory
    let cache_dir = ciris_verify_core::VerifyConfig::default()
        .cache_dir
        .unwrap_or_else(|| std::env::temp_dir().join("ciris-verify-cache"));

    // Load and verify
    match load_and_verify(&cache_dir, &public_key) {
        CacheLoadResult::Valid(cache) => {
            tracing::info!(
                cached_at = cache.cached_at,
                verify_version = %cache.verify_version,
                target = %cache.target,
                binaries = cache.binary_manifest.binaries.len(),
                "ciris_verify_load_manifest_cache: loaded valid cache"
            );

            // Serialize to JSON
            let json = match serde_json::to_string(&cache) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(
                        "ciris_verify_load_manifest_cache: serialization failed: {}",
                        e
                    );
                    return CirisVerifyError::SerializationError as i32;
                },
            };

            // Allocate and copy
            let bytes = json.as_bytes();
            let len = bytes.len();
            let ptr = libc::malloc(len) as *mut u8;
            if ptr.is_null() {
                tracing::error!("ciris_verify_load_manifest_cache: malloc failed");
                return CirisVerifyError::InternalError as i32;
            }

            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
            *result_json = ptr;
            *result_len = len;

            CirisVerifyError::Success as i32
        },
        CacheLoadResult::NotFound => {
            tracing::info!("ciris_verify_load_manifest_cache: no cache found");
            CirisVerifyError::CacheNotFound as i32
        },
        CacheLoadResult::InvalidSignature => {
            tracing::error!(
                "ciris_verify_load_manifest_cache: SIGNATURE INVALID - possible tampering!"
            );
            CirisVerifyError::SignatureInvalid as i32
        },
        CacheLoadResult::VersionMismatch { cached, current } => {
            tracing::warn!(
                "ciris_verify_load_manifest_cache: version mismatch (cached={}, current={})",
                cached,
                current
            );
            CirisVerifyError::VersionMismatch as i32
        },
        CacheLoadResult::TargetMismatch { cached, current } => {
            tracing::warn!(
                "ciris_verify_load_manifest_cache: target mismatch (cached={}, current={})",
                cached,
                current
            );
            CirisVerifyError::VersionMismatch as i32
        },
        CacheLoadResult::Error(msg) => {
            tracing::error!("ciris_verify_load_manifest_cache: error: {}", msg);
            CirisVerifyError::IoError as i32
        },
    }
}

/// Check if a signed manifest cache exists.
///
/// Quick check without loading or verifying the cache.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init` (can be null for this check)
///
/// # Returns
///
/// 1 if cache exists, 0 if not found, negative on error.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_manifest_cache_exists(
    _handle: *mut CirisVerifyHandle,
) -> i32 {
    use ciris_verify_core::manifest_cache::SignedManifestCache;

    let cache_dir = ciris_verify_core::VerifyConfig::default()
        .cache_dir
        .unwrap_or_else(|| std::env::temp_dir().join("ciris-verify-cache"));

    if SignedManifestCache::exists(&cache_dir) {
        1
    } else {
        0
    }
}

// =============================================================================
// Hardware Information
// =============================================================================

/// Get hardware information and security limitations.
///
/// Detects platform-specific hardware characteristics that affect
/// attestation trust level:
/// - Emulator/VM detection (mobile emulators are suspicious)
/// - Rooted/jailbroken device detection
/// - SoC vulnerability detection (e.g., MediaTek CVE-2026-20435)
/// - TEE implementation identification
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init` (can be null for basic detection)
/// * `result_json` - Output pointer for JSON result
/// * `result_len` - Output pointer for result length
///
/// # Result JSON Format
///
/// ```json
/// {
///   "platform": "android",
///   "soc_manufacturer": "MediaTek",
///   "soc_model": "mt6878 (dimensity7300)",
///   "is_emulator": false,
///   "is_suspicious_emulator": false,
///   "is_rooted": false,
///   "tee_implementation": "Trustonic",
///   "security_patch_level": "2026-03-01",
///   "limitations": [
///     {
///       "VulnerableSoC": {
///         "manufacturer": "MediaTek",
///         "advisory": {
///           "cve": "CVE-2026-20435",
///           "title": "MediaTek Boot ROM EMFI vulnerability",
///           "impact": "Physical access can extract Keystore keys in <45 seconds",
///           "software_patchable": false,
///           "min_patch_level": null
///         }
///       }
///     }
///   ],
///   "hardware_trust_degraded": true,
///   "trust_degradation_reason": "MediaTek SoC affected by CVE-2026-20435..."
/// }
/// ```
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `result_json` and `result_len` must be valid pointers
/// - Result must be freed with `ciris_verify_free`
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_hardware_info(
    _handle: *mut CirisVerifyHandle,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_get_hardware_info", {
        get_hardware_info_inner(result_json, result_len)
    })
}

/// Inner implementation of get_hardware_info.
unsafe fn get_hardware_info_inner(result_json: *mut *mut u8, result_len: *mut usize) -> i32 {
    use ciris_verify_core::HardwareInfo;

    tracing::debug!("ciris_verify_get_hardware_info called");

    if result_json.is_null() || result_len.is_null() {
        tracing::error!("ciris_verify_get_hardware_info: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    // Detect hardware information
    let info = HardwareInfo::detect();

    tracing::info!(
        "Hardware detection: platform={}, emulator={}, suspicious={}, rooted={}, degraded={}",
        info.platform,
        info.is_emulator,
        info.is_suspicious_emulator,
        info.is_rooted,
        info.hardware_trust_degraded
    );

    // Serialize to JSON
    let json = match serde_json::to_string(&info) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info: serialization failed: {}",
                e
            );
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = json.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("ciris_verify_get_hardware_info: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(json.as_ptr(), ptr, len);
    *result_json = ptr;
    *result_len = len;

    CirisVerifyError::Success as i32
}

/// Update hardware info with Android-specific properties.
///
/// On Android, some hardware properties can only be read via JNI (Build.HARDWARE,
/// Build.FINGERPRINT, etc.). This function allows the Android app to pass these
/// properties to enhance detection.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init` (can be null)
/// * `hardware` - Build.HARDWARE value (null-terminated)
/// * `board` - Build.BOARD value (null-terminated)
/// * `manufacturer` - Build.MANUFACTURER value (null-terminated)
/// * `model` - Build.MODEL value (null-terminated)
/// * `security_patch` - Build.VERSION.SECURITY_PATCH value (null-terminated)
/// * `fingerprint` - Build.FINGERPRINT value (null-terminated)
/// * `result_json` - Output pointer for JSON result
/// * `result_len` - Output pointer for result length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// All string arguments must be valid null-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_hardware_info_android(
    _handle: *mut CirisVerifyHandle,
    hardware: *const libc::c_char,
    board: *const libc::c_char,
    manufacturer: *const libc::c_char,
    model: *const libc::c_char,
    security_patch: *const libc::c_char,
    fingerprint: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_get_hardware_info_android", {
        get_hardware_info_android_inner(
            hardware,
            board,
            manufacturer,
            model,
            security_patch,
            fingerprint,
            result_json,
            result_len,
        )
    })
}

/// Inner implementation of get_hardware_info_android.
#[allow(clippy::too_many_arguments)]
unsafe fn get_hardware_info_android_inner(
    hardware: *const libc::c_char,
    board: *const libc::c_char,
    manufacturer: *const libc::c_char,
    model: *const libc::c_char,
    security_patch: *const libc::c_char,
    fingerprint: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    use ciris_verify_core::HardwareInfo;

    tracing::debug!("ciris_verify_get_hardware_info_android called");

    if hardware.is_null()
        || board.is_null()
        || manufacturer.is_null()
        || model.is_null()
        || security_patch.is_null()
        || fingerprint.is_null()
        || result_json.is_null()
        || result_len.is_null()
    {
        tracing::error!("ciris_verify_get_hardware_info_android: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    // Parse strings
    let hardware_str = match std::ffi::CStr::from_ptr(hardware).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info_android: invalid hardware UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };
    let board_str = match std::ffi::CStr::from_ptr(board).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info_android: invalid board UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };
    let manufacturer_str = match std::ffi::CStr::from_ptr(manufacturer).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info_android: invalid manufacturer UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };
    let model_str = match std::ffi::CStr::from_ptr(model).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info_android: invalid model UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };
    let security_patch_str = match std::ffi::CStr::from_ptr(security_patch).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info_android: invalid security_patch UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };
    let fingerprint_str = match std::ffi::CStr::from_ptr(fingerprint).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info_android: invalid fingerprint UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Start with basic detection and enhance with Android properties
    let mut info = HardwareInfo::detect();
    info.update_from_android_properties(
        hardware_str,
        board_str,
        manufacturer_str,
        model_str,
        security_patch_str,
        fingerprint_str,
    );

    tracing::info!(
        "Android hardware: soc={:?}, tee={:?}, degraded={}, limitations={}",
        info.soc_manufacturer,
        info.tee_implementation,
        info.hardware_trust_degraded,
        info.limitations.len()
    );

    if info.hardware_trust_degraded {
        tracing::warn!(
            "Hardware trust degraded: {}",
            info.trust_degradation_reason
                .as_deref()
                .unwrap_or("unknown")
        );
    }

    // Serialize to JSON
    let json = match serde_json::to_string(&info) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(
                "ciris_verify_get_hardware_info_android: serialization failed: {}",
                e
            );
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = json.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("ciris_verify_get_hardware_info_android: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(json.as_ptr(), ptr, len);
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
    handle: *mut CirisVerifyHandle,
    db_path: *const libc::c_char,
    jsonl_path: *const libc::c_char,
    portal_key_id: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_audit_trail called");

    if handle.is_null() || db_path.is_null() || result_json.is_null() || result_len.is_null() {
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

    // Cache the audit result for use by run_attestation L5 calculation
    let handle_ref = &*handle;
    if let Ok(mut cache) = handle_ref.audit_trail_cache.lock() {
        *cache = Some(verification_result.clone());
        tracing::info!(
            "Audit trail cached for L5: valid={}, entries={}",
            verification_result.valid,
            verification_result.total_entries
        );
    }

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
            let error_msg = format!("Failed to verify integrity token: {}", e);
            tracing::error!("{}", error_msg);
            // Cache the failure so run_attestation knows device attestation was attempted
            // and failed (not just "not yet attempted"). This makes level_pending=false.
            if let Ok(mut cache) = handle_ref.device_attestation_cache.lock() {
                *cache = Some(ciris_verify_core::unified::DeviceAttestationCheckResult {
                    platform: "android".to_string(),
                    verified: false,
                    summary: "Play Integrity verification failed".to_string(),
                    error: Some(error_msg),
                });
                tracing::debug!("verify_integrity_token: cached failure result");
            }
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
        "integrity_token": token,
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

/// Report a device attestation failure (Play Integrity or App Attest).
///
/// Call this when Play Integrity token acquisition fails (e.g., error -16) or
/// App Attest attestation fails before reaching the verify endpoint. This caches
/// the failure so that `run_attestation` returns `level_pending=false`.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `platform` - Platform identifier: "android" or "ios"
/// * `error_code` - Platform-specific error code (e.g., -16 for Play Integrity)
/// * `error_message` - Human-readable error message (can be null)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `platform` must be a valid null-terminated string
/// - `error_message` can be null, otherwise must be null-terminated
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_device_attestation_failed(
    handle: *mut CirisVerifyHandle,
    platform: *const c_char,
    error_code: i32,
    error_message: *const c_char,
) -> i32 {
    tracing::debug!("ciris_verify_device_attestation_failed called");

    if handle.is_null() || platform.is_null() {
        tracing::error!("ciris_verify_device_attestation_failed: null handle or platform");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Parse platform string
    let platform_str = match std::ffi::CStr::from_ptr(platform).to_str() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "ciris_verify_device_attestation_failed: invalid platform UTF-8: {}",
                e
            );
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Validate platform
    if platform_str != "android" && platform_str != "ios" {
        tracing::error!("ciris_verify_device_attestation_failed: invalid platform '{}', expected 'android' or 'ios'", platform_str);
        return CirisVerifyError::InvalidArgument as i32;
    }

    // Parse optional error message
    let error_msg = if error_message.is_null() {
        format!("Device attestation failed with error code {}", error_code)
    } else {
        match std::ffi::CStr::from_ptr(error_message).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => format!("Device attestation failed with error code {}", error_code),
        }
    };

    tracing::info!(
        "Device attestation failure reported: platform={}, error_code={}, message={}",
        platform_str,
        error_code,
        error_msg
    );

    // Cache the failure result
    match handle_ref.device_attestation_cache.lock() {
        Ok(mut cache) => {
            *cache = Some(ciris_verify_core::unified::DeviceAttestationCheckResult {
                platform: platform_str.to_string(),
                verified: false,
                summary: format!("Token acquisition failed (error {})", error_code),
                error: Some(error_msg),
            });
            tracing::debug!("ciris_verify_device_attestation_failed: cached failure result");
        },
        Err(e) => {
            tracing::error!(
                "ciris_verify_device_attestation_failed: mutex poisoned: {}",
                e
            );
            return CirisVerifyError::InternalError as i32;
        },
    }

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
// TPM Attestation (Desktop L2)
// =============================================================================

/// Verify TPM attestation for desktop L2 (Linux/Windows).
///
/// This is the desktop equivalent of Play Integrity (Android) / App Attest (iOS).
/// Generates a PCR quote using the TPM, reads the EK certificate, and sends
/// both to the registry for verification. The result is cached for use by
/// run_attestation when computing attestation level.
///
/// # Arguments
///
/// - `handle`: Valid handle from `ciris_verify_init`
/// - `nonce`: Challenge nonce (base64-encoded, 32+ bytes recommended)
/// - `result_json`: Output pointer for result JSON
/// - `result_len`: Output pointer for result length
///
/// # Returns
///
/// - `0` (Success): TPM attestation completed (check `verified` field in result)
/// - `-3` (InvalidHandle): Handle is invalid or corrupted
/// - `-5` (InvalidArgument): Null or invalid arguments
/// - `-7` (RequestFailed): Registry verification failed
/// - `-8` (SerializationError): JSON serialization failed
/// - `-10` (InternalError): Unexpected error
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `nonce` must be a null-terminated UTF-8 string
/// - `result_json` and `result_len` must be valid pointers
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_tpm_attestation(
    handle: *mut CirisVerifyHandle,
    nonce: *const libc::c_char,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::info!("ciris_verify_tpm_attestation called");

    // Validate handle
    let handle_ref = match validate_handle(handle) {
        Ok(h) => h,
        Err(code) => {
            tracing::error!("tpm_attestation: invalid handle");
            return code;
        },
    };

    // Validate pointers
    if let Some(err) = validate_ptr(nonce, "nonce") {
        tracing::error!("tpm_attestation: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(result_json, "result_json") {
        tracing::error!("tpm_attestation: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }
    if let Some(err) = validate_ptr(result_len, "result_len") {
        tracing::error!("tpm_attestation: {}", err);
        return CirisVerifyError::InvalidArgument as i32;
    }

    // Parse nonce
    let nonce_str = match safe_cstr_to_str(nonce, 256) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("tpm_attestation: invalid nonce string: {}", e);
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    tracing::info!(
        "TPM attestation: generating quote with nonce (len={})",
        nonce_str.len()
    );

    // Decode nonce from base64
    let nonce_bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, nonce_str) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("tpm_attestation: invalid base64 nonce: {}", e);
                return CirisVerifyError::InvalidArgument as i32;
            },
        };

    // Generate TPM attestation (quote + EK cert)
    let attestation = handle_ref.runtime.handle().block_on(async {
        handle_ref
            .engine
            .hw_signer()
            .attestation_with_nonce(Some(&nonce_bytes))
            .await
    });

    let tpm_attest = match attestation {
        Ok(ciris_keyring::PlatformAttestation::Tpm(tpm)) => tpm,
        Ok(_) => {
            tracing::error!("tpm_attestation: not a TPM platform");
            return CirisVerifyError::RequestFailed as i32;
        },
        Err(e) => {
            tracing::error!("tpm_attestation: failed to generate attestation: {}", e);
            // Return a failed response instead of error code
            let response = ciris_verify_core::tpm_attest::TpmAttestVerifyResponse {
                verified: false,
                error: Some(format!("Failed to generate TPM attestation: {}", e)),
                ..Default::default()
            };
            return write_json_result(&response, result_json, result_len);
        },
    };

    tracing::info!(
        "TPM attestation: quote generated, manufacturer={}, discrete={}",
        tpm_attest.manufacturer,
        tpm_attest.discrete
    );

    // Build verification request
    let request = match build_tpm_verify_request(&tpm_attest, nonce_str) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("tpm_attestation: failed to build request: {}", e);
            let response = ciris_verify_core::tpm_attest::TpmAttestVerifyResponse {
                verified: false,
                error: Some(format!("Failed to build verification request: {}", e)),
                ..Default::default()
            };
            return write_json_result(&response, result_json, result_len);
        },
    };

    // Call registry to verify
    tracing::info!("TPM attestation: sending to registry for verification");
    let result = handle_ref.runtime.handle().block_on(async {
        let client = ciris_verify_core::RegistryClient::new(
            "https://api.registry.ciris-services-1.ai",
            std::time::Duration::from_secs(30),
        )?;
        client.verify_tpm_attestation(&request).await
    });

    let response = match result {
        Ok(r) => {
            tracing::info!(
                "TPM attestation: registry response: verified={}",
                r.verified
            );
            r
        },
        Err(e) => {
            tracing::warn!("TPM attestation: registry verification failed: {}", e);
            ciris_verify_core::tpm_attest::TpmAttestVerifyResponse {
                verified: false,
                error: Some(format!("Registry verification failed: {}", e)),
                ..Default::default()
            }
        },
    };

    // Cache result for run_attestation L2
    if let Ok(mut cache) = handle_ref.device_attestation_cache.lock() {
        *cache = Some(ciris_verify_core::unified::DeviceAttestationCheckResult {
            platform: "tpm".to_string(),
            verified: response.verified,
            summary: response.summary(),
            error: response.error.clone(),
        });
        tracing::info!(
            "TPM attestation: cached result for L2 (verified={})",
            response.verified
        );
    } else {
        tracing::warn!("TPM attestation: failed to cache result (mutex poisoned)");
    }

    write_json_result(&response, result_json, result_len)
}

/// Build TPM verification request from attestation data.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn build_tpm_verify_request(
    tpm: &ciris_keyring::TpmAttestation,
    nonce: &str,
) -> Result<ciris_verify_core::tpm_attest::TpmAttestVerifyRequest, String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let quote = tpm.quote.as_ref().ok_or("No quote data")?;
    let ak_pubkey = tpm.ak_public_key.as_ref().ok_or("No AK public key")?;

    Ok(ciris_verify_core::tpm_attest::TpmAttestVerifyRequest {
        quoted: b64.encode(&quote.quoted),
        signature: b64.encode(&quote.signature),
        pcr_selection: b64.encode(&quote.pcr_selection),
        nonce: nonce.to_string(),
        ak_public_key: b64.encode(ak_pubkey),
        ek_cert: tpm.ek_cert.as_ref().map(|c| b64.encode(c)),
        tpm_version: tpm.tpm_version.clone(),
        manufacturer: tpm.manufacturer.clone(),
        discrete: tpm.discrete,
    })
}

/// Helper to write JSON result to output pointers.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
unsafe fn write_json_result<T: serde::Serialize>(
    response: &T,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    let result_bytes = match serde_json::to_vec(response) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("JSON serialization failed: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

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
    // Wrap entire function in catch_unwind for FFI safety
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match callback {
            Some(cb) => {
                // Use SeqCst ordering to ensure visibility across all threads
                LOG_CALLBACK.store(cb as usize, Ordering::SeqCst);
                // Ensure the store is visible before we try to use the callback
                std::sync::atomic::fence(Ordering::SeqCst);
                tracing::info!("Log callback registered");
            },
            None => {
                LOG_CALLBACK.store(0, Ordering::SeqCst);
                // Don't log here — the callback is already gone
            },
        }
    }));
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

    /// Report device attestation failure (Play Integrity token acquisition failed).
    ///
    /// Call this when Play Integrity API returns an error (e.g., -16) before
    /// the verify endpoint can be called. This caches the failure so that
    /// `run_attestation` returns `level_pending=false`.
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeDeviceAttestationFailed<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        platform: JString<'local>,
        error_code: jint,
        error_message: JString<'local>,
    ) -> jint {
        tracing::debug!("JNI: nativeDeviceAttestationFailed called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() || platform.is_null() {
            tracing::error!("JNI: nativeDeviceAttestationFailed - null handle or platform");
            return CirisVerifyError::InvalidArgument as jint;
        }

        let platform_str: String = match env.get_string(&platform) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get platform string: {}", e);
                return CirisVerifyError::InvalidArgument as jint;
            },
        };

        let c_platform = match std::ffi::CString::new(platform_str) {
            Ok(cs) => cs,
            Err(_) => return CirisVerifyError::InvalidArgument as jint,
        };

        // error_message can be null
        let c_error_message = if error_message.is_null() {
            None
        } else {
            match env.get_string(&error_message) {
                Ok(s) => {
                    let s: String = s.into();
                    std::ffi::CString::new(s).ok()
                },
                Err(_) => None,
            }
        };

        let error_msg_ptr = c_error_message
            .as_ref()
            .map(|cs| cs.as_ptr())
            .unwrap_or(std::ptr::null());

        super::ciris_verify_device_attestation_failed(
            handle,
            c_platform.as_ptr(),
            error_code,
            error_msg_ptr,
        )
    }

    // ==========================================================================
    // Named Key Storage JNI Bindings (v1.5.0)
    // ==========================================================================

    /// Store a named Ed25519 key.
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeStoreNamedKey<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        key_id: JString<'local>,
        seed: JByteArray<'local>,
    ) -> jint {
        tracing::debug!("JNI: nativeStoreNamedKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() || key_id.is_null() || seed.is_null() {
            tracing::error!("JNI: nativeStoreNamedKey - null argument");
            return CirisVerifyError::InvalidArgument as jint;
        }

        let key_id_str: String = match env.get_string(&key_id) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get key_id string: {}", e);
                return CirisVerifyError::InvalidArgument as jint;
            },
        };

        let seed_bytes = match env.convert_byte_array(&seed) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert seed bytes: {}", e);
                return CirisVerifyError::InvalidArgument as jint;
            },
        };

        let c_key_id = match std::ffi::CString::new(key_id_str) {
            Ok(cs) => cs,
            Err(_) => return CirisVerifyError::InvalidArgument as jint,
        };

        ciris_verify_store_named_key(
            handle,
            c_key_id.as_ptr(),
            seed_bytes.as_ptr(),
            seed_bytes.len(),
        )
    }

    /// Sign data with a named key.
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeSignWithNamedKey<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        key_id: JString<'local>,
        data: JByteArray<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeSignWithNamedKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() || key_id.is_null() || data.is_null() {
            tracing::error!("JNI: nativeSignWithNamedKey - null argument");
            return JByteArray::default();
        }

        let key_id_str: String = match env.get_string(&key_id) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get key_id string: {}", e);
                return JByteArray::default();
            },
        };

        let data_bytes = match env.convert_byte_array(&data) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("JNI: failed to convert data bytes: {}", e);
                return JByteArray::default();
            },
        };

        let c_key_id = match std::ffi::CString::new(key_id_str) {
            Ok(cs) => cs,
            Err(_) => return JByteArray::default(),
        };

        let mut sig_data: *mut u8 = std::ptr::null_mut();
        let mut sig_len: usize = 0;

        let result = ciris_verify_sign_with_named_key(
            handle,
            c_key_id.as_ptr(),
            data_bytes.as_ptr(),
            data_bytes.len(),
            &mut sig_data,
            &mut sig_len,
        );

        if result != CirisVerifyError::Success as i32 || sig_data.is_null() {
            tracing::error!("JNI: nativeSignWithNamedKey failed with code {}", result);
            return JByteArray::default();
        }

        let sig_slice = std::slice::from_raw_parts(sig_data, sig_len);
        let jarray = match env.byte_array_from_slice(sig_slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create signature array: {}", e);
                ciris_verify_free(sig_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(sig_data as *mut libc::c_void);
        jarray
    }

    /// Check if a named key exists.
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeHasNamedKey<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        key_id: JString<'local>,
    ) -> jint {
        tracing::debug!("JNI: nativeHasNamedKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() || key_id.is_null() {
            tracing::error!("JNI: nativeHasNamedKey - null argument");
            return CirisVerifyError::InvalidArgument as jint;
        }

        let key_id_str: String = match env.get_string(&key_id) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get key_id string: {}", e);
                return CirisVerifyError::InvalidArgument as jint;
            },
        };

        let c_key_id = match std::ffi::CString::new(key_id_str) {
            Ok(cs) => cs,
            Err(_) => return CirisVerifyError::InvalidArgument as jint,
        };

        ciris_verify_has_named_key(handle, c_key_id.as_ptr())
    }

    /// Delete a named key.
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeDeleteNamedKey<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        key_id: JString<'local>,
    ) -> jint {
        tracing::debug!("JNI: nativeDeleteNamedKey called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() || key_id.is_null() {
            tracing::error!("JNI: nativeDeleteNamedKey - null argument");
            return CirisVerifyError::InvalidArgument as jint;
        }

        let key_id_str: String = match env.get_string(&key_id) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get key_id string: {}", e);
                return CirisVerifyError::InvalidArgument as jint;
            },
        };

        let c_key_id = match std::ffi::CString::new(key_id_str) {
            Ok(cs) => cs,
            Err(_) => return CirisVerifyError::InvalidArgument as jint,
        };

        ciris_verify_delete_named_key(handle, c_key_id.as_ptr())
    }

    /// Get public key for a named key.
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeGetNamedKeyPublic<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
        key_id: JString<'local>,
    ) -> JByteArray<'local> {
        tracing::debug!("JNI: nativeGetNamedKeyPublic called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() || key_id.is_null() {
            tracing::error!("JNI: nativeGetNamedKeyPublic - null argument");
            return JByteArray::default();
        }

        let key_id_str: String = match env.get_string(&key_id) {
            Ok(s) => s.into(),
            Err(e) => {
                tracing::error!("JNI: failed to get key_id string: {}", e);
                return JByteArray::default();
            },
        };

        let c_key_id = match std::ffi::CString::new(key_id_str) {
            Ok(cs) => cs,
            Err(_) => return JByteArray::default(),
        };

        let mut pk_data: *mut u8 = std::ptr::null_mut();
        let mut pk_len: usize = 0;

        let result =
            ciris_verify_get_named_key_public(handle, c_key_id.as_ptr(), &mut pk_data, &mut pk_len);

        if result != CirisVerifyError::Success as i32 || pk_data.is_null() {
            tracing::error!("JNI: nativeGetNamedKeyPublic failed with code {}", result);
            return JByteArray::default();
        }

        let pk_slice = std::slice::from_raw_parts(pk_data, pk_len);
        let jarray = match env.byte_array_from_slice(pk_slice) {
            Ok(arr) => arr,
            Err(e) => {
                tracing::error!("JNI: failed to create public key array: {}", e);
                ciris_verify_free(pk_data as *mut libc::c_void);
                return JByteArray::default();
            },
        };

        ciris_verify_free(pk_data as *mut libc::c_void);
        jarray
    }

    /// List all named keys.
    #[no_mangle]
    pub unsafe extern "system" fn Java_ai_ciris_verify_CirisVerify_nativeListNamedKeys<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        handle: jlong,
    ) -> JString<'local> {
        tracing::debug!("JNI: nativeListNamedKeys called");

        let handle = handle as *mut CirisVerifyHandle;
        if handle.is_null() {
            tracing::error!("JNI: nativeListNamedKeys - null handle");
            return JString::default();
        }

        let mut json_out: *mut std::ffi::c_char = std::ptr::null_mut();
        let result = ciris_verify_list_named_keys(handle, &mut json_out);

        if result != CirisVerifyError::Success as i32 || json_out.is_null() {
            tracing::error!("JNI: nativeListNamedKeys failed with code {}", result);
            return JString::default();
        }

        let c_str = std::ffi::CStr::from_ptr(json_out);
        let json_str = match c_str.to_str() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: invalid UTF-8 in list result: {}", e);
                super::ciris_verify_free_string(json_out);
                return JString::default();
            },
        };

        let jstring = match env.new_string(json_str) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("JNI: failed to create list string: {}", e);
                super::ciris_verify_free_string(json_out);
                return JString::default();
            },
        };

        super::ciris_verify_free_string(json_out);
        jstring
    }
}

// =============================================================================
// SECP256K1 WALLET SIGNING (v1.3.0)
// =============================================================================
//
// These functions provide EVM-compatible wallet signing capabilities.
// The secp256k1 key is deterministically derived from the Ed25519 root identity
// using HKDF, ensuring a single hardware-protected root key can generate
// consistent wallet addresses across sessions.

/// Derive a secp256k1 public key from the Ed25519 seed.
///
/// The derivation is deterministic: the same Ed25519 seed will always produce
/// the same secp256k1 public key. This is used for EVM wallet address derivation.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `pubkey_data` - Output pointer for 65-byte uncompressed public key (caller must free with `ciris_verify_free`)
/// * `pubkey_len` - Output pointer for key length (always 65)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `pubkey_data` and `pubkey_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_derive_secp256k1_pubkey(
    handle: *mut CirisVerifyHandle,
    pubkey_data: *mut *mut u8,
    pubkey_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_derive_secp256k1_pubkey", {
        derive_secp256k1_pubkey_inner(handle, pubkey_data, pubkey_len)
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn derive_secp256k1_pubkey_inner(
    handle: *mut CirisVerifyHandle,
    pubkey_data: *mut *mut u8,
    pubkey_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_derive_secp256k1_pubkey called");

    // Check if attestation is running
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("derive_secp256k1_pubkey: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || pubkey_data.is_null() || pubkey_len.is_null() {
        tracing::error!("derive_secp256k1_pubkey: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Get the wallet seed (stored separately, works with hardware-backed keys)
    let seed = match handle_ref.ed25519_signer.get_wallet_seed() {
        Some(s) => s,
        None => {
            tracing::error!("derive_secp256k1_pubkey: failed to get wallet seed");
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Derive secp256k1 public key
    let pubkey = ciris_crypto::secp256k1::derive_secp256k1_public_key(&seed);

    // Allocate and copy
    let len = pubkey.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(pubkey.as_ptr(), ptr, len);

    *pubkey_data = ptr;
    *pubkey_len = len;

    tracing::debug!("secp256k1 public key derived ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Get the EVM address from a secp256k1 public key.
///
/// The address is derived by taking keccak256 of the public key (without the 04 prefix)
/// and taking the last 20 bytes.
///
/// # Arguments
///
/// * `pubkey` - 65-byte uncompressed secp256k1 public key
/// * `pubkey_len` - Length of public key (must be 65)
/// * `address_data` - Output pointer for 20-byte EVM address (caller must free with `ciris_verify_free`)
/// * `address_len` - Output pointer for address length (always 20)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `pubkey` must point to valid memory of at least `pubkey_len` bytes
/// - `address_data` and `address_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_evm_address(
    pubkey: *const u8,
    pubkey_len: usize,
    address_data: *mut *mut u8,
    address_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_get_evm_address", {
        get_evm_address_inner(pubkey, pubkey_len, address_data, address_len)
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn get_evm_address_inner(
    pubkey: *const u8,
    pubkey_len: usize,
    address_data: *mut *mut u8,
    address_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_get_evm_address called");

    if pubkey.is_null() || address_data.is_null() || address_len.is_null() {
        tracing::error!("get_evm_address: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if pubkey_len != 65 {
        tracing::error!(
            "get_evm_address: pubkey must be 65 bytes, got {}",
            pubkey_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    let pubkey_bytes = std::slice::from_raw_parts(pubkey, pubkey_len);
    let mut pubkey_array = [0u8; 65];
    pubkey_array.copy_from_slice(pubkey_bytes);

    let address = ciris_crypto::secp256k1::get_evm_address(&pubkey_array);

    // Allocate and copy
    let len = address.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(address.as_ptr(), ptr, len);

    *address_data = ptr;
    *address_len = len;

    tracing::debug!("EVM address derived ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Get the checksummed EVM address string from a secp256k1 public key.
///
/// Implements EIP-55 checksum encoding.
///
/// # Arguments
///
/// * `pubkey` - 65-byte uncompressed secp256k1 public key
/// * `pubkey_len` - Length of public key (must be 65)
/// * `address_str` - Output pointer for null-terminated checksummed address (caller must free with `ciris_verify_free`)
/// * `address_str_len` - Output pointer for string length (including null terminator)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `pubkey` must point to valid memory of at least `pubkey_len` bytes
/// - `address_str` and `address_str_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_evm_address_checksummed(
    pubkey: *const u8,
    pubkey_len: usize,
    address_str: *mut *mut c_char,
    address_str_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_get_evm_address_checksummed", {
        get_evm_address_checksummed_inner(pubkey, pubkey_len, address_str, address_str_len)
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn get_evm_address_checksummed_inner(
    pubkey: *const u8,
    pubkey_len: usize,
    address_str: *mut *mut c_char,
    address_str_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_get_evm_address_checksummed called");

    if pubkey.is_null() || address_str.is_null() || address_str_len.is_null() {
        tracing::error!("get_evm_address_checksummed: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if pubkey_len != 65 {
        tracing::error!(
            "get_evm_address_checksummed: pubkey must be 65 bytes, got {}",
            pubkey_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    let pubkey_bytes = std::slice::from_raw_parts(pubkey, pubkey_len);
    let mut pubkey_array = [0u8; 65];
    pubkey_array.copy_from_slice(pubkey_bytes);

    let address = ciris_crypto::secp256k1::get_evm_address_checksummed(&pubkey_array);

    // Allocate and copy with null terminator
    let len = address.len() + 1;
    let ptr = libc::malloc(len) as *mut c_char;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(address.as_ptr() as *const c_char, ptr, address.len());
    *ptr.add(address.len()) = 0; // null terminator

    *address_str = ptr;
    *address_str_len = len;

    tracing::debug!("Checksummed EVM address: {}", address);
    CirisVerifyError::Success as i32
}

/// Sign a 32-byte message hash with the derived secp256k1 key.
///
/// The secp256k1 key is derived from the Ed25519 seed using HKDF.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `message_hash` - 32-byte hash to sign (typically keccak256)
/// * `hash_len` - Length of hash (must be 32)
/// * `signature_data` - Output pointer for 65-byte signature r||s||v (caller must free with `ciris_verify_free`)
/// * `signature_len` - Output pointer for signature length (always 65)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `message_hash` must point to valid memory of at least `hash_len` bytes
/// - `signature_data` and `signature_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_sign_secp256k1(
    handle: *mut CirisVerifyHandle,
    message_hash: *const u8,
    hash_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_sign_secp256k1", {
        sign_secp256k1_inner(
            handle,
            message_hash,
            hash_len,
            signature_data,
            signature_len,
        )
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn sign_secp256k1_inner(
    handle: *mut CirisVerifyHandle,
    message_hash: *const u8,
    hash_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_sign_secp256k1 called (hash_len={})", hash_len);

    // Check if attestation is running
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("sign_secp256k1: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null()
        || message_hash.is_null()
        || signature_data.is_null()
        || signature_len.is_null()
    {
        tracing::error!("sign_secp256k1: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if hash_len != 32 {
        tracing::error!("sign_secp256k1: hash must be 32 bytes, got {}", hash_len);
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Get the wallet seed (stored separately, works with hardware-backed keys)
    let seed = match handle_ref.ed25519_signer.get_wallet_seed() {
        Some(s) => s,
        None => {
            tracing::error!("sign_secp256k1: failed to get wallet seed");
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Derive secp256k1 keypair
    let (signing_key, _) = ciris_crypto::secp256k1::derive_wallet_keypair(&seed);

    // Parse message hash
    let hash_bytes = std::slice::from_raw_parts(message_hash, hash_len);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(hash_bytes);

    // Sign
    let signature = ciris_crypto::secp256k1::sign_message(&signing_key, &hash_array);

    // Allocate and copy
    let len = signature.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(signature.as_ptr(), ptr, len);

    *signature_data = ptr;
    *signature_len = len;

    tracing::debug!("secp256k1 signature generated ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Sign an EVM transaction hash with EIP-155 replay protection.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `tx_hash` - 32-byte transaction hash
/// * `hash_len` - Length of hash (must be 32)
/// * `chain_id` - EVM chain ID for replay protection
/// * `signature_data` - Output pointer for 65-byte signature (caller must free with `ciris_verify_free`)
/// * `signature_len` - Output pointer for signature length (always 65)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `tx_hash` must point to valid memory of at least `hash_len` bytes
/// - `signature_data` and `signature_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_sign_evm_transaction(
    handle: *mut CirisVerifyHandle,
    tx_hash: *const u8,
    hash_len: usize,
    chain_id: u64,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_sign_evm_transaction", {
        sign_evm_transaction_inner(
            handle,
            tx_hash,
            hash_len,
            chain_id,
            signature_data,
            signature_len,
        )
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn sign_evm_transaction_inner(
    handle: *mut CirisVerifyHandle,
    tx_hash: *const u8,
    hash_len: usize,
    chain_id: u64,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    tracing::debug!(
        "ciris_verify_sign_evm_transaction called (chain_id={})",
        chain_id
    );

    // Check if attestation is running
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("sign_evm_transaction: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || tx_hash.is_null() || signature_data.is_null() || signature_len.is_null()
    {
        tracing::error!("sign_evm_transaction: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if hash_len != 32 {
        tracing::error!(
            "sign_evm_transaction: hash must be 32 bytes, got {}",
            hash_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Get the wallet seed (stored separately, works with hardware-backed keys)
    let seed = match handle_ref.ed25519_signer.get_wallet_seed() {
        Some(s) => s,
        None => {
            tracing::error!("sign_evm_transaction: failed to get wallet seed");
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Derive secp256k1 keypair
    let (signing_key, _) = ciris_crypto::secp256k1::derive_wallet_keypair(&seed);

    // Parse transaction hash
    let hash_bytes = std::slice::from_raw_parts(tx_hash, hash_len);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(hash_bytes);

    // Sign with EIP-155
    let signature =
        ciris_crypto::secp256k1::sign_evm_transaction(&signing_key, &hash_array, chain_id);

    // Allocate and copy
    let len = signature.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(signature.as_ptr(), ptr, len);

    *signature_data = ptr;
    *signature_len = len;

    tracing::debug!("EVM transaction signature generated ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Sign EIP-712 typed data.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `domain_hash` - 32-byte domain separator hash
/// * `domain_len` - Length of domain hash (must be 32)
/// * `message_hash` - 32-byte struct hash
/// * `message_len` - Length of message hash (must be 32)
/// * `signature_data` - Output pointer for 65-byte signature (caller must free with `ciris_verify_free`)
/// * `signature_len` - Output pointer for signature length (always 65)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `domain_hash` and `message_hash` must point to valid memory
/// - `signature_data` and `signature_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_sign_typed_data(
    handle: *mut CirisVerifyHandle,
    domain_hash: *const u8,
    domain_len: usize,
    message_hash: *const u8,
    message_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_sign_typed_data", {
        sign_typed_data_inner(
            handle,
            domain_hash,
            domain_len,
            message_hash,
            message_len,
            signature_data,
            signature_len,
        )
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn sign_typed_data_inner(
    handle: *mut CirisVerifyHandle,
    domain_hash: *const u8,
    domain_len: usize,
    message_hash: *const u8,
    message_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_sign_typed_data called");

    // Check if attestation is running
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("sign_typed_data: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null()
        || domain_hash.is_null()
        || message_hash.is_null()
        || signature_data.is_null()
        || signature_len.is_null()
    {
        tracing::error!("sign_typed_data: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if domain_len != 32 {
        tracing::error!(
            "sign_typed_data: domain hash must be 32 bytes, got {}",
            domain_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    if message_len != 32 {
        tracing::error!(
            "sign_typed_data: message hash must be 32 bytes, got {}",
            message_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Get the wallet seed (stored separately, works with hardware-backed keys)
    let seed = match handle_ref.ed25519_signer.get_wallet_seed() {
        Some(s) => s,
        None => {
            tracing::error!("sign_typed_data: failed to get wallet seed");
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Derive secp256k1 keypair
    let (signing_key, _) = ciris_crypto::secp256k1::derive_wallet_keypair(&seed);

    // Parse hashes
    let domain_bytes = std::slice::from_raw_parts(domain_hash, domain_len);
    let mut domain_array = [0u8; 32];
    domain_array.copy_from_slice(domain_bytes);

    let message_bytes = std::slice::from_raw_parts(message_hash, message_len);
    let mut message_array = [0u8; 32];
    message_array.copy_from_slice(message_bytes);

    // Sign EIP-712 typed data
    let signature =
        ciris_crypto::secp256k1::sign_typed_data(&signing_key, &domain_array, &message_array);

    // Allocate and copy
    let len = signature.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(signature.as_ptr(), ptr, len);

    *signature_data = ptr;
    *signature_len = len;

    tracing::debug!("EIP-712 typed data signature generated ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Recover the signer's EVM address from a signature.
///
/// # Arguments
///
/// * `message_hash` - 32-byte hash that was signed
/// * `hash_len` - Length of hash (must be 32)
/// * `signature` - 65-byte signature (r || s || v)
/// * `signature_len` - Length of signature (must be 65)
/// * `address_data` - Output pointer for 20-byte recovered address (caller must free with `ciris_verify_free`)
/// * `address_len` - Output pointer for address length (always 20)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
/// Returns error if recovery fails (invalid signature).
///
/// # Safety
///
/// - `message_hash` must point to valid memory of at least `hash_len` bytes
/// - `signature` must point to valid memory of at least `signature_len` bytes
/// - `address_data` and `address_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_recover_evm_address(
    message_hash: *const u8,
    hash_len: usize,
    signature: *const u8,
    signature_len: usize,
    address_data: *mut *mut u8,
    address_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_recover_evm_address", {
        recover_evm_address_inner(
            message_hash,
            hash_len,
            signature,
            signature_len,
            address_data,
            address_len,
        )
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn recover_evm_address_inner(
    message_hash: *const u8,
    hash_len: usize,
    signature: *const u8,
    signature_len: usize,
    address_data: *mut *mut u8,
    address_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_recover_evm_address called");

    if message_hash.is_null()
        || signature.is_null()
        || address_data.is_null()
        || address_len.is_null()
    {
        tracing::error!("recover_evm_address: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if hash_len != 32 {
        tracing::error!(
            "recover_evm_address: hash must be 32 bytes, got {}",
            hash_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    if signature_len != 65 {
        tracing::error!(
            "recover_evm_address: signature must be 65 bytes, got {}",
            signature_len
        );
        return CirisVerifyError::InvalidArgument as i32;
    }

    let hash_bytes = std::slice::from_raw_parts(message_hash, hash_len);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(hash_bytes);

    let sig_bytes = std::slice::from_raw_parts(signature, signature_len);
    let mut sig_array = [0u8; 65];
    sig_array.copy_from_slice(sig_bytes);

    // Recover address
    let address = match ciris_crypto::secp256k1::recover_address(&hash_array, &sig_array) {
        Some(addr) => addr,
        None => {
            tracing::error!("recover_evm_address: recovery failed (invalid signature)");
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Allocate and copy
    let len = address.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(address.as_ptr(), ptr, len);

    *address_data = ptr;
    *address_len = len;

    tracing::debug!("EVM address recovered ({} bytes)", len);
    CirisVerifyError::Success as i32
}

/// Get wallet info JSON including derived secp256k1 public key and EVM address.
///
/// Returns a JSON object with wallet information for the current Ed25519 identity.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `result_json` - Output pointer for JSON wallet info (caller must free with `ciris_verify_free`)
/// * `result_len` - Output pointer for result length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # JSON Format
///
/// ```json
/// {
///   "secp256k1_public_key": "04...",  // 65-byte uncompressed pubkey as hex
///   "evm_address": "0x...",           // 20-byte address as checksummed hex
///   "derivation_path": "HKDF-SHA256(ed25519_seed, 'CIRIS-wallet-v1', 'secp256k1-evm-signing-key')"
/// }
/// ```
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `result_json` and `result_len` must be valid pointers
#[cfg(feature = "secp256k1")]
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_wallet_info(
    handle: *mut CirisVerifyHandle,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_get_wallet_info", {
        get_wallet_info_inner(handle, result_json, result_len)
    })
}

#[cfg(feature = "secp256k1")]
unsafe fn get_wallet_info_inner(
    handle: *mut CirisVerifyHandle,
    result_json: *mut *mut u8,
    result_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_get_wallet_info called");

    // Check if attestation is running
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("get_wallet_info: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || result_json.is_null() || result_len.is_null() {
        tracing::error!("get_wallet_info: invalid arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Get the wallet seed (stored separately, works with hardware-backed keys)
    let seed = match handle_ref.ed25519_signer.get_wallet_seed() {
        Some(s) => s,
        None => {
            tracing::error!("get_wallet_info: failed to get wallet seed");
            return CirisVerifyError::RequestFailed as i32;
        },
    };

    // Derive secp256k1 public key
    let pubkey = ciris_crypto::secp256k1::derive_secp256k1_public_key(&seed);
    let evm_address = ciris_crypto::secp256k1::get_evm_address_checksummed(&pubkey);

    let wallet_info = serde_json::json!({
        "secp256k1_public_key": hex::encode(pubkey),
        "evm_address": evm_address,
        "derivation_path": "HKDF-SHA256(ed25519_seed, 'CIRIS-wallet-v1', 'secp256k1-evm-signing-key')"
    });

    // Serialize to JSON
    let json_bytes = match serde_json::to_vec(&wallet_info) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("get_wallet_info: failed to serialize: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Allocate and copy
    let len = json_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(json_bytes.as_ptr(), ptr, len);

    *result_json = ptr;
    *result_len = len;

    tracing::info!("Wallet info: {}", evm_address);
    CirisVerifyError::Success as i32
}

// =============================================================================
// Named Key Storage FFI
// =============================================================================
//
// These functions allow storing and signing with multiple Ed25519 keys,
// identified by a key_id string. Use cases include:
// - WA (Wallet Address) signing keys: key_id = "wa:{wa_id}"
// - Session keys: key_id = "session:{session_id}"
// - Backup keys: key_id = "backup:{timestamp}"
//
// Keys are stored with hardware protection (TPM/Keystore/SecureEnclave)
// when available, using the SecureBlobStorage infrastructure.

/// Store a named Ed25519 key.
///
/// Stores a 32-byte Ed25519 seed under the given key_id. The key is stored
/// with hardware protection when available.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_id` - Null-terminated key identifier (e.g., "wa:0x1234...")
/// * `seed` - 32-byte Ed25519 seed
/// * `seed_len` - Length of seed (must be 32)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `key_id` must be a valid null-terminated UTF-8 string
/// - `seed` must point to valid memory of at least `seed_len` bytes
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_store_named_key(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
    seed: *const u8,
    seed_len: usize,
) -> i32 {
    ffi_guard!("ciris_verify_store_named_key", {
        store_named_key_inner(handle, key_id, seed, seed_len)
    })
}

unsafe fn store_named_key_inner(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
    seed: *const u8,
    seed_len: usize,
) -> i32 {
    tracing::debug!("ciris_verify_store_named_key called");

    // Check attestation flag
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("store_named_key: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    // Validate arguments
    if handle.is_null() || key_id.is_null() || seed.is_null() {
        tracing::error!("store_named_key: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    if seed_len != 32 {
        tracing::error!("store_named_key: seed must be 32 bytes, got {}", seed_len);
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Parse key_id
    let key_id_str = match std::ffi::CStr::from_ptr(key_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("store_named_key: invalid key_id string");
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Validate key_id (non-empty, reasonable length)
    if key_id_str.is_empty() || key_id_str.len() > 256 {
        tracing::error!("store_named_key: key_id length invalid");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let seed_bytes = std::slice::from_raw_parts(seed, seed_len);

    // Get or init storage
    let storage_guard = match get_or_init_named_storage(handle_ref) {
        Ok(g) => g,
        Err(code) => return code,
    };

    let storage = match storage_guard.as_ref() {
        Some(s) => s,
        None => {
            tracing::error!("store_named_key: storage not initialized");
            return CirisVerifyError::InternalError as i32;
        },
    };

    // Store with "named." prefix to avoid collisions
    let storage_key = format!("named.{}", key_id_str);
    if let Err(e) = storage.store(&storage_key, seed_bytes) {
        tracing::error!("store_named_key: storage failed: {}", e);
        return CirisVerifyError::InternalError as i32;
    }

    tracing::info!(
        key_id = %key_id_str,
        hw_backed = storage.is_hardware_backed(),
        "Named key stored successfully"
    );
    CirisVerifyError::Success as i32
}

/// Sign data using a named Ed25519 key.
///
/// Loads the key seed, creates an ephemeral signer, signs the data, and
/// returns a 64-byte Ed25519 signature.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_id` - Null-terminated key identifier
/// * `data` - Data to sign
/// * `data_len` - Length of data
/// * `signature_data` - Output pointer for 64-byte signature (caller must free with `ciris_verify_free`)
/// * `signature_len` - Output pointer for signature length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `key_id` must be a valid null-terminated UTF-8 string
/// - `data` must point to valid memory of at least `data_len` bytes
/// - `signature_data` and `signature_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_sign_with_named_key(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
    data: *const u8,
    data_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_sign_with_named_key", {
        sign_with_named_key_inner(
            handle,
            key_id,
            data,
            data_len,
            signature_data,
            signature_len,
        )
    })
}

unsafe fn sign_with_named_key_inner(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
    data: *const u8,
    data_len: usize,
    signature_data: *mut *mut u8,
    signature_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_sign_with_named_key called");

    // Check attestation flag
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("sign_with_named_key: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    // Validate arguments
    if handle.is_null()
        || key_id.is_null()
        || data.is_null()
        || signature_data.is_null()
        || signature_len.is_null()
    {
        tracing::error!("sign_with_named_key: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Parse key_id
    let key_id_str = match std::ffi::CStr::from_ptr(key_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("sign_with_named_key: invalid key_id string");
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    let data_bytes = std::slice::from_raw_parts(data, data_len);

    // Get storage
    let storage_guard = match get_or_init_named_storage(handle_ref) {
        Ok(g) => g,
        Err(code) => return code,
    };

    let storage = match storage_guard.as_ref() {
        Some(s) => s,
        None => {
            tracing::error!("sign_with_named_key: storage not initialized");
            return CirisVerifyError::InternalError as i32;
        },
    };

    // Load seed
    let storage_key = format!("named.{}", key_id_str);
    let seed = match storage.load(&storage_key) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("sign_with_named_key: key not found: {}", e);
            return CirisVerifyError::NoKey as i32;
        },
    };

    if seed.len() != 32 {
        tracing::error!(
            "sign_with_named_key: stored seed has wrong length: {}",
            seed.len()
        );
        return CirisVerifyError::InternalError as i32;
    }

    // Create ephemeral signer and sign
    use ed25519_dalek::{Signer, SigningKey};
    let seed_array: [u8; 32] = match seed.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            tracing::error!("sign_with_named_key: seed conversion failed");
            return CirisVerifyError::InternalError as i32;
        },
    };
    let signing_key = SigningKey::from_bytes(&seed_array);
    let signature = signing_key.sign(data_bytes);
    let sig_bytes = signature.to_bytes();

    // Allocate and copy
    let len = sig_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("sign_with_named_key: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), ptr, len);

    *signature_data = ptr;
    *signature_len = len;

    tracing::debug!(
        key_id = %key_id_str,
        data_len = data_len,
        "Named key signed successfully"
    );
    CirisVerifyError::Success as i32
}

/// Check if a named key exists.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_id` - Null-terminated key identifier
///
/// # Returns
///
/// 1 if key exists, 0 if not found, negative on error.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `key_id` must be a valid null-terminated UTF-8 string
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_has_named_key(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
) -> i32 {
    ffi_guard!("ciris_verify_has_named_key", {
        has_named_key_inner(handle, key_id)
    })
}

unsafe fn has_named_key_inner(handle: *mut CirisVerifyHandle, key_id: *const c_char) -> i32 {
    tracing::debug!("ciris_verify_has_named_key called");

    // Check attestation flag
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("has_named_key: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || key_id.is_null() {
        tracing::error!("has_named_key: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Parse key_id
    let key_id_str = match std::ffi::CStr::from_ptr(key_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("has_named_key: invalid key_id string");
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Get storage
    let storage_guard = match get_or_init_named_storage(handle_ref) {
        Ok(g) => g,
        Err(code) => return code,
    };

    let storage = match storage_guard.as_ref() {
        Some(s) => s,
        None => {
            tracing::error!("has_named_key: storage not initialized");
            return CirisVerifyError::InternalError as i32;
        },
    };

    let storage_key = format!("named.{}", key_id_str);
    if storage.exists(&storage_key) {
        tracing::debug!(key_id = %key_id_str, "Named key exists");
        1
    } else {
        tracing::debug!(key_id = %key_id_str, "Named key not found");
        0
    }
}

/// Delete a named key.
///
/// Removes the key from secure storage. Use for key revocation.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_id` - Null-terminated key identifier
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `key_id` must be a valid null-terminated UTF-8 string
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_delete_named_key(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
) -> i32 {
    ffi_guard!("ciris_verify_delete_named_key", {
        delete_named_key_inner(handle, key_id)
    })
}

unsafe fn delete_named_key_inner(handle: *mut CirisVerifyHandle, key_id: *const c_char) -> i32 {
    tracing::debug!("ciris_verify_delete_named_key called");

    // Check attestation flag
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("delete_named_key: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || key_id.is_null() {
        tracing::error!("delete_named_key: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Parse key_id
    let key_id_str = match std::ffi::CStr::from_ptr(key_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("delete_named_key: invalid key_id string");
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Get storage
    let storage_guard = match get_or_init_named_storage(handle_ref) {
        Ok(g) => g,
        Err(code) => return code,
    };

    let storage = match storage_guard.as_ref() {
        Some(s) => s,
        None => {
            tracing::error!("delete_named_key: storage not initialized");
            return CirisVerifyError::InternalError as i32;
        },
    };

    let storage_key = format!("named.{}", key_id_str);
    if let Err(e) = storage.delete(&storage_key) {
        tracing::error!("delete_named_key: delete failed: {}", e);
        return CirisVerifyError::InternalError as i32;
    }

    tracing::info!(key_id = %key_id_str, "Named key deleted");
    CirisVerifyError::Success as i32
}

/// Get the public key for a named Ed25519 key.
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `key_id` - Null-terminated key identifier
/// * `pubkey_data` - Output pointer for 32-byte public key (caller must free with `ciris_verify_free`)
/// * `pubkey_len` - Output pointer for key length
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `key_id` must be a valid null-terminated UTF-8 string
/// - `pubkey_data` and `pubkey_len` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_get_named_key_public(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
    pubkey_data: *mut *mut u8,
    pubkey_len: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_get_named_key_public", {
        get_named_key_public_inner(handle, key_id, pubkey_data, pubkey_len)
    })
}

unsafe fn get_named_key_public_inner(
    handle: *mut CirisVerifyHandle,
    key_id: *const c_char,
    pubkey_data: *mut *mut u8,
    pubkey_len: *mut usize,
) -> i32 {
    tracing::debug!("ciris_verify_get_named_key_public called");

    // Check attestation flag
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("get_named_key_public: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || key_id.is_null() || pubkey_data.is_null() || pubkey_len.is_null() {
        tracing::error!("get_named_key_public: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Parse key_id
    let key_id_str = match std::ffi::CStr::from_ptr(key_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("get_named_key_public: invalid key_id string");
            return CirisVerifyError::InvalidArgument as i32;
        },
    };

    // Get storage
    let storage_guard = match get_or_init_named_storage(handle_ref) {
        Ok(g) => g,
        Err(code) => return code,
    };

    let storage = match storage_guard.as_ref() {
        Some(s) => s,
        None => {
            tracing::error!("get_named_key_public: storage not initialized");
            return CirisVerifyError::InternalError as i32;
        },
    };

    // Load seed
    let storage_key = format!("named.{}", key_id_str);
    let seed = match storage.load(&storage_key) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_named_key_public: key not found: {}", e);
            return CirisVerifyError::NoKey as i32;
        },
    };

    if seed.len() != 32 {
        tracing::error!(
            "get_named_key_public: stored seed has wrong length: {}",
            seed.len()
        );
        return CirisVerifyError::InternalError as i32;
    }

    // Create signing key and get public key
    use ed25519_dalek::SigningKey;
    let seed_array: [u8; 32] = match seed.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            tracing::error!("get_named_key_public: seed conversion failed");
            return CirisVerifyError::InternalError as i32;
        },
    };
    let signing_key = SigningKey::from_bytes(&seed_array);
    let public_key = signing_key.verifying_key();
    let pk_bytes = public_key.to_bytes();

    // Allocate and copy
    let len = pk_bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        tracing::error!("get_named_key_public: malloc failed");
        return CirisVerifyError::InternalError as i32;
    }

    std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), ptr, len);

    *pubkey_data = ptr;
    *pubkey_len = len;

    tracing::debug!(key_id = %key_id_str, "Named key public key returned");
    CirisVerifyError::Success as i32
}

/// List all named keys.
///
/// Returns a JSON array of key IDs (without the "named." prefix).
///
/// # Arguments
///
/// * `handle` - Handle from `ciris_verify_init`
/// * `json_out` - Output pointer for JSON string (caller must free with `ciris_verify_free_string`)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
///
/// # JSON Format
///
/// ```json
/// ["wa:0x1234...", "session:abc123", "backup:1234567890"]
/// ```
///
/// # Safety
///
/// - `handle` must be a valid handle from `ciris_verify_init`
/// - `json_out` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_list_named_keys(
    handle: *mut CirisVerifyHandle,
    json_out: *mut *mut c_char,
) -> i32 {
    ffi_guard!("ciris_verify_list_named_keys", {
        list_named_keys_inner(handle, json_out)
    })
}

unsafe fn list_named_keys_inner(handle: *mut CirisVerifyHandle, json_out: *mut *mut c_char) -> i32 {
    tracing::debug!("ciris_verify_list_named_keys called");

    // Check attestation flag
    if ATTESTATION_RUNNING.load(Ordering::SeqCst) {
        tracing::warn!("list_named_keys: attestation in progress");
        return CirisVerifyError::AttestationInProgress as i32;
    }

    if handle.is_null() || json_out.is_null() {
        tracing::error!("list_named_keys: null arguments");
        return CirisVerifyError::InvalidArgument as i32;
    }

    let handle_ref = &*handle;

    // Get storage
    let storage_guard = match get_or_init_named_storage(handle_ref) {
        Ok(g) => g,
        Err(code) => return code,
    };

    let storage = match storage_guard.as_ref() {
        Some(s) => s,
        None => {
            tracing::error!("list_named_keys: storage not initialized");
            return CirisVerifyError::InternalError as i32;
        },
    };

    // List all keys
    let all_keys = match storage.list_keys() {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!("list_named_keys: list failed: {}", e);
            return CirisVerifyError::InternalError as i32;
        },
    };

    // Filter for "named." prefix and strip it
    let named_keys: Vec<String> = all_keys
        .into_iter()
        .filter_map(|k| k.strip_prefix("named.").map(String::from))
        .collect();

    tracing::debug!("Found {} named keys", named_keys.len());

    // Serialize to JSON
    let json = match serde_json::to_string(&named_keys) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("list_named_keys: serialization failed: {}", e);
            return CirisVerifyError::SerializationError as i32;
        },
    };

    // Convert to C string
    let c_string = match std::ffi::CString::new(json) {
        Ok(cs) => cs,
        Err(e) => {
            tracing::error!("list_named_keys: CString creation failed: {}", e);
            return CirisVerifyError::InternalError as i32;
        },
    };

    *json_out = c_string.into_raw();
    CirisVerifyError::Success as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_get_hardware_info_returns_valid_json() {
        unsafe {
            let mut result_json: *mut u8 = std::ptr::null_mut();
            let mut result_len: usize = 0;

            let ret = ciris_verify_get_hardware_info(
                std::ptr::null_mut(),
                &mut result_json,
                &mut result_len,
            );

            assert_eq!(ret, CirisVerifyError::Success as i32);
            assert!(!result_json.is_null());
            assert!(result_len > 0);

            // Parse the JSON
            let slice = std::slice::from_raw_parts(result_json, result_len);
            let json_str = std::str::from_utf8(slice).expect("Invalid UTF-8");
            let info: serde_json::Value = serde_json::from_str(json_str).expect("Invalid JSON");

            // Check required fields exist
            assert!(info.get("platform").is_some());
            assert!(info.get("is_emulator").is_some());
            assert!(info.get("hardware_trust_degraded").is_some());
            assert!(info.get("limitations").is_some());

            ciris_verify_free(result_json as *mut libc::c_void);
        }
    }

    #[test]
    fn test_get_hardware_info_null_args() {
        unsafe {
            // Null result_json
            let mut result_len: usize = 0;
            let ret = ciris_verify_get_hardware_info(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut result_len,
            );
            assert_eq!(ret, CirisVerifyError::InvalidArgument as i32);

            // Null result_len
            let mut result_json: *mut u8 = std::ptr::null_mut();
            let ret = ciris_verify_get_hardware_info(
                std::ptr::null_mut(),
                &mut result_json,
                std::ptr::null_mut(),
            );
            assert_eq!(ret, CirisVerifyError::InvalidArgument as i32);
        }
    }

    #[test]
    fn test_get_hardware_info_android_mediatek_vulnerable() {
        unsafe {
            let hardware = CString::new("mt6893").unwrap();
            let board = CString::new("k6893v1_64").unwrap();
            let manufacturer = CString::new("Xiaomi").unwrap();
            let model = CString::new("Redmi Note 11 Pro").unwrap();
            let security_patch = CString::new("2026-01-01").unwrap();
            let fingerprint = CString::new("xiaomi/test/test:12/SKQ1.211006.001").unwrap();

            let mut result_json: *mut u8 = std::ptr::null_mut();
            let mut result_len: usize = 0;

            let ret = ciris_verify_get_hardware_info_android(
                std::ptr::null_mut(),
                hardware.as_ptr(),
                board.as_ptr(),
                manufacturer.as_ptr(),
                model.as_ptr(),
                security_patch.as_ptr(),
                fingerprint.as_ptr(),
                &mut result_json,
                &mut result_len,
            );

            assert_eq!(ret, CirisVerifyError::Success as i32);
            assert!(!result_json.is_null());

            let slice = std::slice::from_raw_parts(result_json, result_len);
            let json_str = std::str::from_utf8(slice).expect("Invalid UTF-8");
            let info: serde_json::Value = serde_json::from_str(json_str).expect("Invalid JSON");

            // MediaTek mt6893 should be flagged as vulnerable
            assert_eq!(info["hardware_trust_degraded"], true);
            assert!(info["soc_manufacturer"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains("mediatek"));

            ciris_verify_free(result_json as *mut libc::c_void);
        }
    }

    #[test]
    fn test_get_hardware_info_android_qualcomm_patched() {
        unsafe {
            let hardware = CString::new("qcom").unwrap();
            let board = CString::new("sm8550").unwrap();
            let manufacturer = CString::new("Samsung").unwrap();
            let model = CString::new("SM-S918B").unwrap();
            // Patch level AFTER the fix (2026-03-01)
            let security_patch = CString::new("2026-03-05").unwrap();
            let fingerprint = CString::new("samsung/test/test:14/UP1A.231005.007").unwrap();

            let mut result_json: *mut u8 = std::ptr::null_mut();
            let mut result_len: usize = 0;

            let ret = ciris_verify_get_hardware_info_android(
                std::ptr::null_mut(),
                hardware.as_ptr(),
                board.as_ptr(),
                manufacturer.as_ptr(),
                model.as_ptr(),
                security_patch.as_ptr(),
                fingerprint.as_ptr(),
                &mut result_json,
                &mut result_len,
            );

            assert_eq!(ret, CirisVerifyError::Success as i32);
            assert!(!result_json.is_null());

            let slice = std::slice::from_raw_parts(result_json, result_len);
            let json_str = std::str::from_utf8(slice).expect("Invalid UTF-8");
            let info: serde_json::Value = serde_json::from_str(json_str).expect("Invalid JSON");

            // Qualcomm with March 2026+ patch should NOT be flagged
            assert_eq!(info["hardware_trust_degraded"], false);

            ciris_verify_free(result_json as *mut libc::c_void);
        }
    }

    #[test]
    fn test_get_hardware_info_android_emulator() {
        unsafe {
            let hardware = CString::new("goldfish").unwrap();
            let board = CString::new("goldfish_x86_64").unwrap();
            let manufacturer = CString::new("Google").unwrap();
            let model = CString::new("sdk_gphone64_x86_64").unwrap();
            let security_patch = CString::new("2026-03-01").unwrap();
            let fingerprint =
                CString::new("google/sdk_gphone64_x86_64/emulator64_x86_64:14").unwrap();

            let mut result_json: *mut u8 = std::ptr::null_mut();
            let mut result_len: usize = 0;

            let ret = ciris_verify_get_hardware_info_android(
                std::ptr::null_mut(),
                hardware.as_ptr(),
                board.as_ptr(),
                manufacturer.as_ptr(),
                model.as_ptr(),
                security_patch.as_ptr(),
                fingerprint.as_ptr(),
                &mut result_json,
                &mut result_len,
            );

            assert_eq!(ret, CirisVerifyError::Success as i32);

            let slice = std::slice::from_raw_parts(result_json, result_len);
            let json_str = std::str::from_utf8(slice).expect("Invalid UTF-8");
            let info: serde_json::Value = serde_json::from_str(json_str).expect("Invalid JSON");

            // Emulator should be detected and trust degraded
            assert_eq!(info["is_emulator"], true);
            assert_eq!(info["hardware_trust_degraded"], true);

            ciris_verify_free(result_json as *mut libc::c_void);
        }
    }

    #[test]
    fn test_version_returns_valid_string() {
        unsafe {
            let version_ptr = ciris_verify_version();
            assert!(!version_ptr.is_null());

            let version_cstr = std::ffi::CStr::from_ptr(version_ptr);
            let version = version_cstr.to_str().expect("Invalid UTF-8");

            // Should be semver format
            assert!(
                version.contains('.'),
                "Version should contain dots: {}",
                version
            );
        }
    }
}
