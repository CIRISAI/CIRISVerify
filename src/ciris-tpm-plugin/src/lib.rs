//! Runtime-loaded TPM 2.0 backend for `ciris-keyring` (CIRISVerify#125 / #127).
//!
//! # Why this crate exists
//!
//! `ciris-keyring`'s TPM path used `tss-esapi`, whose `-sys` crate **link-binds**
//! the system `tss2` C libraries. That made libtss2 a hard dependency at two
//! points where it shouldn't be:
//!
//! - **build (#127):** cross-compiling the keyring to `aarch64-unknown-linux-musl`
//!   (Alpine / Home Assistant) hard-failed — no musl libtss2, no cross sysroot.
//! - **load (#125):** the published wheel's cdylib `DT_NEEDED`'d
//!   `libtss2-tctildr.so.0`, so it failed to load on any host without the TPM2
//!   runtime — even for pure-crypto surfaces.
//!
//! v7.5.0 took TPM off the keyring's link graph (glibc-gated), which **builds**
//! everywhere but **loses** TPM on musl + the wheel. This crate is the *ideal*
//! restoration: the keyring `dlopen`s this plugin at runtime via a small,
//! stable **C ABI** and holds **zero** `tss-esapi` in its own link graph. TPM is
//! then available wherever the plugin `.so` + libtss2 happen to be present at
//! runtime; absent → the keyring's existing `NotSupported` fallback.
//!
//! # Status — staged
//!
//! **Stage 1 (this):** the C ABI surface + the `available`/version vertical
//! slice. The seal / unseal / sign / quote operations are declared and return
//! [`CIRIS_TPM_NOT_IMPLEMENTED`] until staged in (they port the existing
//! `ciris_keyring::platform::tpm` / `storage::tpm` logic into the plugin behind
//! this ABI). The keyring `dlopen` client is a later stage.
//!
//! # ABI discipline
//!
//! Every exported symbol is `extern "C"` + `#[no_mangle]`. The ABI is versioned
//! by [`ciris_tpm_plugin_abi_version`]; the keyring checks it on load and refuses
//! a mismatch. Byte buffers are caller-allocated out-pointers (`*mut *mut u8` +
//! `*mut usize`), freed via [`ciris_tpm_free`] — the same ownership shape as the
//! `ciris-verify-ffi` wheel surface.

#![allow(clippy::missing_safety_doc)]

/// ABI version. Bump on any breaking change to an exported signature; the
/// keyring refuses to load a plugin whose version it doesn't recognize.
pub const CIRIS_TPM_ABI_VERSION: u32 = 1;

/// Operation succeeded.
pub const CIRIS_TPM_OK: i32 = 0;
/// Operation is declared but not yet implemented in this plugin build.
pub const CIRIS_TPM_NOT_IMPLEMENTED: i32 = -100;
/// A TPM/tss2 error occurred (the real backend was reached but failed).
pub const CIRIS_TPM_ERROR: i32 = -1;
/// This plugin was built without the `real` backend (no `tss-esapi`).
pub const CIRIS_TPM_UNAVAILABLE: i32 = -2;

/// The ABI version this plugin exports. The keyring checks this on `dlopen` and
/// refuses a mismatch (fail-closed: an unrecognized plugin is "no TPM").
#[no_mangle]
pub extern "C" fn ciris_tpm_plugin_abi_version() -> u32 {
    CIRIS_TPM_ABI_VERSION
}

/// Probe for a usable TPM 2.0 device.
///
/// Returns `1` if a TPM is present and an ESYS context opens, `0` if no TPM is
/// reachable, [`CIRIS_TPM_UNAVAILABLE`] if this plugin has no real backend
/// compiled in, or [`CIRIS_TPM_ERROR`] on an unexpected backend fault.
#[no_mangle]
pub extern "C" fn ciris_tpm_available() -> i32 {
    backend::available()
}

/// Free a buffer returned by a plugin op (caller-allocated on the plugin heap).
///
/// # Safety
/// `ptr` must be a pointer returned by this plugin (or null), freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

// ── Staged operations (declared; implemented in later stages) ─────────────
// Each ports the corresponding ciris_keyring::platform::tpm / storage::tpm op
// into the plugin behind this ABI: seal/unseal (master-key blob under the SRK),
// sign (slot key), quote (attestation). Until then they fail closed.

/// Seal `input` under the TPM SRK → sealed blob in `out`/`out_len`. (Stage 2.)
///
/// # Safety
/// Pointers must be valid; `out`/`out_len` receive a `ciris_tpm_free`-able buffer.
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_seal(
    _input: *const u8,
    _input_len: usize,
    _out: *mut *mut u8,
    _out_len: *mut usize,
) -> i32 {
    CIRIS_TPM_NOT_IMPLEMENTED
}

/// Unseal a blob produced by [`ciris_tpm_seal`]. (Stage 2.)
///
/// # Safety
/// Pointers must be valid; `out`/`out_len` receive a `ciris_tpm_free`-able buffer.
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_unseal(
    _sealed: *const u8,
    _sealed_len: usize,
    _out: *mut *mut u8,
    _out_len: *mut usize,
) -> i32 {
    CIRIS_TPM_NOT_IMPLEMENTED
}

/// The real (tss-esapi) backend, gated to where it can link; otherwise a stub
/// that honestly reports "unavailable".
mod backend {
    #[cfg(all(
        feature = "real",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
    ))]
    pub fn available() -> i32 {
        // A usable TPM = an ESYS context opens over the default TCTI.
        match tss_esapi::Context::new(
            tss_esapi::TctiNameConf::from_environment_variable()
                .unwrap_or(tss_esapi::TctiNameConf::Tabrmd(Default::default())),
        ) {
            Ok(_) => 1,
            Err(e) => {
                tracing::debug!("ciris-tpm-plugin: no usable TPM ({e})");
                0
            },
        }
    }

    #[cfg(not(all(
        feature = "real",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "windows")
    )))]
    pub fn available() -> i32 {
        super::CIRIS_TPM_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(ciris_tpm_plugin_abi_version(), CIRIS_TPM_ABI_VERSION);
    }

    #[test]
    fn staged_ops_fail_closed_until_implemented() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe { ciris_tpm_seal(std::ptr::null(), 0, &mut out, &mut out_len) };
        assert_eq!(rc, CIRIS_TPM_NOT_IMPLEMENTED);
    }

    #[test]
    fn available_is_defined_without_a_real_backend() {
        // Default build (no `real`) must report unavailable, never crash.
        #[cfg(not(feature = "real"))]
        assert_eq!(ciris_tpm_available(), CIRIS_TPM_UNAVAILABLE);
    }
}
