//! Runtime client for the **`ciris-tpm-plugin`** dylib (CIRISVerify#130, stage 3).
//!
//! `dlopen`s `libciris_tpm_plugin.{so,dylib,dll}` via [`libloading`], checks its
//! ABI version, and exposes safe `available` / `seal` / `unseal` over the
//! plugin's C ABI. This is what lets the keyring use TPM **without** linking
//! `tss-esapi` itself — so it builds on every target (incl. musl) and the wheel
//! cdylib carries no `libtss2` dependency. TPM is opportunistic: if the plugin
//! `.so` + libtss2 are present at runtime, sealing is hardware-backed; if not,
//! [`load`] returns [`KeyringError::NotSupported`] and the caller falls back to
//! software, exactly as before.
//!
//! ## Loading
//!
//! [`plugin_path`] resolves the dylib from (in order): the `CIRIS_TPM_PLUGIN`
//! env var (an explicit path), then the platform library name (so the dynamic
//! loader searches `LD_LIBRARY_PATH` / the exe directory / system paths). The
//! plugin ships alongside the main library wherever TPM is wanted.
//!
//! ## ABI safety
//!
//! On load we call `ciris_tpm_plugin_abi_version` and **refuse** any version we
//! don't recognize (fail-closed: an unrecognized plugin is treated as "no TPM",
//! not blindly invoked). The resolved C function pointers are stored alongside
//! the owning [`libloading::Library`] in [`TpmPlugin`], so they stay valid for
//! the loader's lifetime and are dropped together.

#![cfg(feature = "tpm-plugin")]

use std::ffi::OsString;
use std::path::PathBuf;

use libloading::{Library, Symbol};

use crate::error::KeyringError;

/// The ABI version this client speaks. Must match the plugin's
/// `CIRIS_TPM_ABI_VERSION`.
const EXPECTED_ABI_VERSION: u32 = 1;

/// Plugin C ABI return codes (mirror `ciris-tpm-plugin`).
const CIRIS_TPM_OK: i32 = 0;

type AbiVersionFn = unsafe extern "C" fn() -> u32;
type AvailableFn = unsafe extern "C" fn() -> i32;
type BlobOpFn = unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32;
type FreeFn = unsafe extern "C" fn(*mut u8, usize);

fn err(reason: impl std::fmt::Display) -> KeyringError {
    KeyringError::HardwareError {
        reason: reason.to_string(),
    }
}

fn not_supported(reason: impl Into<String>) -> KeyringError {
    KeyringError::NotSupported {
        operation: reason.into(),
    }
}

/// The dylib base name for the current platform.
fn plugin_lib_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "ciris_tpm_plugin.dll"
    }
    #[cfg(target_os = "macos")]
    {
        "libciris_tpm_plugin.dylib"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "libciris_tpm_plugin.so"
    }
}

/// Resolve where to load the plugin from: `CIRIS_TPM_PLUGIN` (explicit path) if
/// set, else the bare platform library name (the dynamic loader searches its
/// standard paths + `LD_LIBRARY_PATH` + the executable directory).
pub fn plugin_path() -> OsString {
    if let Some(p) = std::env::var_os("CIRIS_TPM_PLUGIN") {
        return p;
    }
    OsString::from(plugin_lib_name())
}

/// A loaded `ciris-tpm-plugin` instance — the resolved C ABI behind a safe API.
pub struct TpmPlugin {
    // The owning library: the resolved fn pointers below are valid only while it
    // is loaded, so it must outlive them — kept in the same struct, dropped last.
    _lib: Library,
    available: AvailableFn,
    seal: BlobOpFn,
    unseal: BlobOpFn,
    free: FreeFn,
}

impl TpmPlugin {
    /// `dlopen` the plugin and verify its ABI version.
    ///
    /// # Errors
    /// [`KeyringError::NotSupported`] if the plugin dylib is absent / unloadable
    /// (the expected "no TPM plugin here" case — the caller falls back to
    /// software), or its ABI version is unrecognized;
    /// [`KeyringError::HardwareError`] if a required symbol is missing.
    pub fn load() -> Result<Self, KeyringError> {
        Self::load_from(plugin_path())
    }

    /// `dlopen` the plugin at an explicit path (the [`Self::load`] core; lets
    /// tests point at a known path without mutating the process-global env).
    ///
    /// # Errors
    /// As [`Self::load`].
    pub fn load_from(path: impl AsRef<std::ffi::OsStr>) -> Result<Self, KeyringError> {
        let path = path.as_ref();
        // SAFETY: loading a trusted, version-checked plugin. The library is kept
        // alive in the returned struct.
        let lib = unsafe { Library::new(path) }.map_err(|e| {
            not_supported(format!(
                "ciris-tpm-plugin not loadable ({}): {e}",
                PathBuf::from(path).display()
            ))
        })?;

        // Resolve + copy out the fn pointers (fn pointers are Copy; they remain
        // valid for `lib`'s lifetime, which the struct owns).
        let abi_version = unsafe {
            let s: Symbol<AbiVersionFn> = lib
                .get(b"ciris_tpm_plugin_abi_version\0")
                .map_err(|e| err(format!("plugin missing abi_version symbol: {e}")))?;
            *s
        };
        let version = unsafe { abi_version() };
        if version != EXPECTED_ABI_VERSION {
            return Err(not_supported(format!(
                "ciris-tpm-plugin ABI v{version} unrecognized (this build speaks v{EXPECTED_ABI_VERSION})"
            )));
        }

        let available = unsafe {
            *lib.get::<AvailableFn>(b"ciris_tpm_available\0")
                .map_err(|e| err(format!("plugin missing available symbol: {e}")))?
        };
        let seal = unsafe {
            *lib.get::<BlobOpFn>(b"ciris_tpm_seal\0")
                .map_err(|e| err(format!("plugin missing seal symbol: {e}")))?
        };
        let unseal = unsafe {
            *lib.get::<BlobOpFn>(b"ciris_tpm_unseal\0")
                .map_err(|e| err(format!("plugin missing unseal symbol: {e}")))?
        };
        let free = unsafe {
            *lib.get::<FreeFn>(b"ciris_tpm_free\0")
                .map_err(|e| err(format!("plugin missing free symbol: {e}")))?
        };

        Ok(Self {
            _lib: lib,
            available,
            seal,
            unseal,
            free,
        })
    }

    /// Whether the plugin reports a usable TPM device at runtime.
    #[must_use]
    pub fn available(&self) -> bool {
        // SAFETY: resolved, version-checked C fn taking no args.
        unsafe { (self.available)() == 1 }
    }

    /// Seal `input` under the TPM SRK; returns the opaque sealed blob.
    ///
    /// # Errors
    /// [`KeyringError::HardwareError`] if the TPM op fails.
    pub fn seal(&self, input: &[u8]) -> Result<Vec<u8>, KeyringError> {
        self.blob_op(self.seal, input, "seal")
    }

    /// Unseal a blob produced by [`Self::seal`]; returns the plaintext.
    ///
    /// # Errors
    /// [`KeyringError::HardwareError`] if the TPM op fails.
    pub fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, KeyringError> {
        self.blob_op(self.unseal, blob, "unseal")
    }

    fn blob_op(&self, op: BlobOpFn, input: &[u8], what: &str) -> Result<Vec<u8>, KeyringError> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        // SAFETY: `input` is a valid slice; `out`/`out_len` are valid out-params;
        // a successful op hands back a plugin-owned buffer we free via `free`.
        let rc = unsafe { op(input.as_ptr(), input.len(), &mut out, &mut out_len) };
        if rc != CIRIS_TPM_OK {
            return Err(err(format!("ciris-tpm-plugin {what} failed (code {rc})")));
        }
        let result = if out_len == 0 || out.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(out, out_len).to_vec() }
        };
        if !out.is_null() && out_len != 0 {
            unsafe { (self.free)(out, out_len) };
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_plugin_is_not_supported_not_a_crash() {
        // A path that doesn't resolve → load() must degrade to NotSupported (the
        // software-fallback signal), never panic. Uses load_from (no global env
        // mutation) so it can't race other tests in this binary.
        let err = TpmPlugin::load_from("/nonexistent/libciris_tpm_plugin.so").err();
        assert!(
            matches!(err, Some(KeyringError::NotSupported { .. })),
            "missing plugin must be NotSupported, got {err:?}"
        );
    }

    #[test]
    fn plugin_path_default_is_platform_lib_name() {
        // With no override set, the default is the bare platform library name.
        // (The env-override branch is exercised via the FFI/integration path,
        // not here — mutating CIRIS_TPM_PLUGIN would race parallel tests.)
        if std::env::var_os("CIRIS_TPM_PLUGIN").is_none() {
            assert_eq!(plugin_path(), OsString::from(plugin_lib_name()));
        }
    }
}
