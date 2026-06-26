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
//! - **Stage 1:** the C ABI surface + ABI version + the `available` detection
//!   vertical slice.
//! - **Stage 2 (this):** `seal` / `unseal` implemented in the `real` backend —
//!   a pure (no-file-I/O) port of `ciris_keyring::storage::tpm`'s SRK-parented
//!   `KeyedHash` sealing (see `backend.rs`). The sealed blob is opaque.
//! - **Later:** `sign` / `quote` (the native `TpmSigner` path — they will use
//!   [`CIRIS_TPM_NOT_IMPLEMENTED`] until staged in), then the keyring `dlopen`
//!   client, then the flip that removes `tss-esapi` from the keyring entirely.
//!
//! # ABI discipline
//!
//! Every exported symbol is `extern "C"` + `#[no_mangle]`. The ABI is versioned
//! by [`ciris_tpm_plugin_abi_version`]; the keyring checks it on load and refuses
//! a mismatch. Byte buffers are caller-allocated out-pointers (`*mut *mut u8` +
//! `*mut usize`), freed via [`ciris_tpm_free`] — the same ownership shape as the
//! `ciris-verify-ffi` wheel surface.

#![allow(clippy::missing_safety_doc)]

/// ABI version. Bump on any **additive** revision so a client can detect which
/// ops exist; the keyring accepts any version in its supported range and
/// resolves newer ops lazily (fail-closed if a symbol is absent).
///
/// - **v1:** `available` / `seal` / `unseal` / `free`.
/// - **v2 (#141):** adds the signer path — `signer_create` / `signer_public` /
///   `signer_sign` (ECDSA P-256, stateless blob-based).
pub const CIRIS_TPM_ABI_VERSION: u32 = 2;

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

/// Allocate `bytes` on the plugin heap and hand ownership out via the
/// out-pointers (freed by [`ciris_tpm_free`]).
unsafe fn emit(bytes: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) {
    let mut boxed = bytes.into_boxed_slice();
    *out_len = boxed.len();
    *out = boxed.as_mut_ptr();
    std::mem::forget(boxed);
}

/// Seal `input` under the TPM SRK → sealed blob in `out`/`out_len` (stage 2).
///
/// The blob is opaque (`u32_le(private_len) ‖ private ‖ public`); only the same
/// TPM can unseal it. Returns [`CIRIS_TPM_OK`], [`CIRIS_TPM_UNAVAILABLE`] (no
/// real backend), or [`CIRIS_TPM_ERROR`] (a TPM fault).
///
/// # Safety
/// `input` valid for `input_len` (or null iff `input_len == 0`); `out`/`out_len`
/// valid. The returned buffer is freed via [`ciris_tpm_free`].
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_seal(
    input: *const u8,
    input_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() || (input.is_null() && input_len != 0) {
        return CIRIS_TPM_ERROR;
    }
    let data = if input_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(input, input_len)
    };
    match backend::seal(data) {
        Ok(blob) => {
            emit(blob, out, out_len);
            CIRIS_TPM_OK
        },
        Err(e) => {
            tracing::error!("ciris_tpm_seal: {e}");
            CIRIS_TPM_ERROR
        },
    }
}

/// Unseal a blob produced by [`ciris_tpm_seal`] → plaintext in `out`/`out_len`.
///
/// # Safety
/// `sealed` valid for `sealed_len`; `out`/`out_len` valid. The returned buffer
/// is freed via [`ciris_tpm_free`].
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_unseal(
    sealed: *const u8,
    sealed_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if sealed.is_null() || out.is_null() || out_len.is_null() {
        return CIRIS_TPM_ERROR;
    }
    let blob = std::slice::from_raw_parts(sealed, sealed_len);
    match backend::unseal(blob) {
        Ok(plain) => {
            emit(plain, out, out_len);
            CIRIS_TPM_OK
        },
        Err(e) => {
            tracing::error!("ciris_tpm_unseal: {e}");
            CIRIS_TPM_ERROR
        },
    }
}

/// Create an ECDSA P-256 signing key in the TPM → its persistable key blob in
/// `out`/`out_len` (ABI v2, #141).
///
/// The blob is opaque (`u32_le(private_len) ‖ private ‖ public`) and bound to
/// this TPM (only it can load + sign with it). The keyring stores the blob and
/// passes it back to [`ciris_tpm_signer_public`] / [`ciris_tpm_signer_sign`].
/// Returns [`CIRIS_TPM_OK`], [`CIRIS_TPM_UNAVAILABLE`], or [`CIRIS_TPM_ERROR`].
///
/// # Safety
/// `out`/`out_len` valid; the returned buffer is freed via [`ciris_tpm_free`].
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_signer_create(out: *mut *mut u8, out_len: *mut usize) -> i32 {
    if out.is_null() || out_len.is_null() {
        return CIRIS_TPM_ERROR;
    }
    match backend::signer_create() {
        Ok(blob) => {
            emit(blob, out, out_len);
            CIRIS_TPM_OK
        },
        Err(e) => {
            tracing::error!("ciris_tpm_signer_create: {e}");
            CIRIS_TPM_ERROR
        },
    }
}

/// Load a signer blob from [`ciris_tpm_signer_create`] → its SEC1-uncompressed
/// public key (`0x04 ‖ X(32) ‖ Y(32)`, 65 bytes) in `out`/`out_len`.
///
/// # Safety
/// `blob` valid for `blob_len`; `out`/`out_len` valid. Buffer freed via
/// [`ciris_tpm_free`].
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_signer_public(
    blob: *const u8,
    blob_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if blob.is_null() || out.is_null() || out_len.is_null() {
        return CIRIS_TPM_ERROR;
    }
    let blob = std::slice::from_raw_parts(blob, blob_len);
    match backend::signer_public(blob) {
        Ok(pk) => {
            emit(pk, out, out_len);
            CIRIS_TPM_OK
        },
        Err(e) => {
            tracing::error!("ciris_tpm_signer_public: {e}");
            CIRIS_TPM_ERROR
        },
    }
}

/// Load a signer blob, SHA-256-hash `data`, and ECDSA-sign it → raw
/// `r(32) ‖ s(32)` (64 bytes) in `out`/`out_len`.
///
/// # Safety
/// `blob` valid for `blob_len`; `data` valid for `data_len` (or null iff
/// `data_len == 0`); `out`/`out_len` valid. Buffer freed via [`ciris_tpm_free`].
#[no_mangle]
pub unsafe extern "C" fn ciris_tpm_signer_sign(
    blob: *const u8,
    blob_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if blob.is_null() || out.is_null() || out_len.is_null() || (data.is_null() && data_len != 0) {
        return CIRIS_TPM_ERROR;
    }
    let blob = std::slice::from_raw_parts(blob, blob_len);
    let data = if data_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(data, data_len)
    };
    match backend::signer_sign(blob, data) {
        Ok(sig) => {
            emit(sig, out, out_len);
            CIRIS_TPM_OK
        },
        Err(e) => {
            tracing::error!("ciris_tpm_signer_sign: {e}");
            CIRIS_TPM_ERROR
        },
    }
}

/// The TPM backend — real (`tss-esapi`, gnu/win) or stub. See `backend.rs`.
mod backend;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(ciris_tpm_plugin_abi_version(), CIRIS_TPM_ABI_VERSION);
    }

    #[test]
    fn seal_fails_closed_without_a_tpm() {
        // No test environment has a TPM (stub build: no backend; real build: no
        // device), so seal must never report success here — it fails closed.
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let data = [1u8, 2, 3];
        let rc = unsafe { ciris_tpm_seal(data.as_ptr(), data.len(), &mut out, &mut out_len) };
        assert_ne!(rc, CIRIS_TPM_OK, "seal must fail closed with no usable TPM");
    }

    #[test]
    fn null_pointers_are_rejected_not_dereferenced() {
        let rc = unsafe {
            ciris_tpm_seal(
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, CIRIS_TPM_ERROR);
    }

    #[test]
    fn available_is_defined_without_a_real_backend() {
        // Default build (no `real`) must report unavailable, never crash.
        #[cfg(not(feature = "real"))]
        assert_eq!(ciris_tpm_available(), CIRIS_TPM_UNAVAILABLE);
    }

    #[test]
    fn abi_version_advertises_v2_signer() {
        // The signer path (#141) is ABI v2; the version must advertise it so a
        // client can resolve the signer symbols.
        assert!(ciris_tpm_plugin_abi_version() >= 2);
    }

    #[test]
    fn signer_create_fails_closed_without_a_tpm() {
        // No TPM in any test env → signer_create must never report success.
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe { ciris_tpm_signer_create(&mut out, &mut out_len) };
        assert_ne!(rc, CIRIS_TPM_OK, "signer_create must fail closed");
    }

    #[test]
    fn signer_null_pointers_are_rejected() {
        let rc = unsafe { ciris_tpm_signer_create(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rc, CIRIS_TPM_ERROR);
        let rc = unsafe {
            ciris_tpm_signer_sign(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, CIRIS_TPM_ERROR);
    }
}
