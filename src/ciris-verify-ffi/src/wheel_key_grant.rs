//! Wheel surface for the v4.4.0 `key_grant` HPKE-shape wrap/unwrap
//! primitive (CIRISVerify#44, exposed for Python wheel consumers per
//! CIRISVerify#50 / v4.7.0 wheel-surface work).
//!
//! Eric's principle: "if it ain't on the wheel, it doesn't exist."
//! The Rust crate at `ciris_crypto::key_grant` ships
//! `wrap_dek_for_recipient` / `unwrap_dek` for the
//! `x25519-aes256-gcm-hkdf-sha256` algorithm — but the Python wheel
//! has no access without this FFI layer.
//!
//! ## FFI shape
//!
//! Two `#[no_mangle] extern "C"` functions:
//!
//! - `ciris_verify_wrap_dek_for_recipient(recipient_pub[32],
//!   dek[32], result_out, result_len_out) -> i32` — JSON output is
//!   the serialized `KeyGrantWrap`:
//!   `{"ephemeral_public_key": [..32..], "nonce": [..12..],
//!   "ciphertext": [..bytes..]}`.
//! - `ciris_verify_unwrap_dek(recipient_priv[32], wrap_json+len,
//!   result_out, result_len_out) -> i32` — JSON output is
//!   `{"dek": [..32 bytes..]}` on success, or
//!   `{"error": {"code": "WRAP_UNVERIFIED", "message": "..."}}`
//!   on the opaque AEAD failure case.
//!
//! Both allocate the result via `libc::malloc` so the Python wheel
//! caller frees via `ciris_verify_free` (the existing crate-root
//! free fn).
//!
//! ## Panic safety
//!
//! Each FFI fn wraps its body in `catch_unwind` directly (the
//! `ffi_guard!` macro at the crate root is not visible to submodules
//! because `mod wheel_key_grant;` is declared at lib.rs before the
//! macro definition — this is the same pattern the v4.2.0
//! conformance fns sidestep by living in lib.rs itself). Either
//! shape is wire-equivalent: panic → `InternalError as i32`.
//!
//! ## Opaque-failure discipline
//!
//! The wrap/unwrap primitive deliberately conflates wrong-key,
//! tampered-ciphertext, swapped-ephemeral-pub, and tampered-nonce
//! into a single `WrapUnverified` AEAD-tag-mismatch. The FFI surface
//! preserves that discipline: a failed unwrap returns success (0) at
//! the FFI level with a JSON `error.code = "WRAP_UNVERIFIED"`
//! payload — never distinguishing failure mode in the error code.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_crypto::key_grant::{unwrap_dek, wrap_dek_for_recipient, KeyGrantError, KeyGrantWrap};

use crate::CirisVerifyError;

/// Allocate `bytes` via `libc::malloc` and write them out for the
/// caller (who frees via `ciris_verify_free`). Returns the success
/// code, or `InternalError` if malloc fails.
///
/// # Safety
///
/// `result_out` and `result_len_out` must be valid non-null pointers.
unsafe fn write_owned_bytes(
    bytes: &[u8],
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    let len = bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
    *result_out = ptr;
    *result_len_out = len;
    CirisVerifyError::Success as i32
}

/// Wrap a 32-byte DEK for a recipient identified by a 32-byte X25519
/// public key (CIRISVerify#44 / MEDIA_SHARING.md §6.3 v4.4.0+
/// `wrap_algorithm: v1` = `x25519-aes256-gcm-hkdf-sha256`).
///
/// # Output JSON shape
///
/// On success: the serialized `KeyGrantWrap`:
/// `{"ephemeral_public_key": [..32 ints..], "nonce": [..12 ints..],
/// "ciphertext": [..bytes..]}`. The caller must free `*result_out`
/// via `ciris_verify_free`.
///
/// # Safety
///
/// `recipient_pub` must point to exactly 32 bytes. `dek` must point
/// to exactly 32 bytes. `result_out` and `result_len_out` must be
/// valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_wrap_dek_for_recipient(
    recipient_pub: *const u8,
    dek: *const u8,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if recipient_pub.is_null()
            || dek.is_null()
            || result_out.is_null()
            || result_len_out.is_null()
        {
            return CirisVerifyError::InvalidArgument as i32;
        }

        // Copy the two fixed-size byte arrays out of the raw pointers.
        let recipient_pub_arr: [u8; 32] =
            match std::slice::from_raw_parts(recipient_pub, 32).try_into() {
                Ok(a) => a,
                Err(_) => return CirisVerifyError::InvalidArgument as i32,
            };
        let dek_arr: [u8; 32] = match std::slice::from_raw_parts(dek, 32).try_into() {
            Ok(a) => a,
            Err(_) => return CirisVerifyError::InvalidArgument as i32,
        };

        let wrap = match wrap_dek_for_recipient(&recipient_pub_arr, &dek_arr) {
            Ok(w) => w,
            Err(_) => return CirisVerifyError::InternalError as i32,
        };

        let json = match serde_json::to_vec(&wrap) {
            Ok(j) => j,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };

        write_owned_bytes(&json, result_out, result_len_out)
    }));
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
            tracing::error!("PANIC in ciris_verify_wrap_dek_for_recipient: {msg}");
            CirisVerifyError::InternalError as i32
        },
    }
}

/// Unwrap a `KeyGrantWrap` (passed as serialized JSON) using a
/// 32-byte X25519 private key. Returns the 32-byte DEK on success.
///
/// # Output JSON shape
///
/// On success: `{"dek": [..32 ints..]}`. On the opaque AEAD-failure
/// case (wrong recipient key, tampered ciphertext, swapped ephemeral
/// pub, or tampered nonce): the FFI returns success (`Success` = 0)
/// with a JSON envelope
/// `{"error": {"code": "WRAP_UNVERIFIED", "message": "..."}}` —
/// preserving the opaque-failure discipline. A non-32-byte unwrapped
/// plaintext returns `{"error": {"code":
/// "UNEXPECTED_PLAINTEXT_LENGTH", "message": "..."}}`. The caller
/// must free `*result_out` via `ciris_verify_free`.
///
/// # Safety
///
/// `recipient_priv` must point to exactly 32 bytes. `wrap_json` must
/// point to `wrap_json_len` bytes of valid UTF-8 JSON. `result_out`
/// and `result_len_out` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_unwrap_dek(
    recipient_priv: *const u8,
    wrap_json: *const u8,
    wrap_json_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if recipient_priv.is_null()
            || wrap_json.is_null()
            || result_out.is_null()
            || result_len_out.is_null()
        {
            return CirisVerifyError::InvalidArgument as i32;
        }

        let recipient_priv_arr: [u8; 32] =
            match std::slice::from_raw_parts(recipient_priv, 32).try_into() {
                Ok(a) => a,
                Err(_) => return CirisVerifyError::InvalidArgument as i32,
            };

        let wrap_bytes = std::slice::from_raw_parts(wrap_json, wrap_json_len);
        let wrap: KeyGrantWrap = match serde_json::from_slice(wrap_bytes) {
            Ok(w) => w,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };

        // The opaque-failure discipline: wrong key / tampered
        // ciphertext / swapped ephemeral_pub / tampered nonce all
        // surface as `WrapUnverified`. We carry that through to a
        // JSON error envelope rather than an FFI status code so the
        // Python caller can distinguish "the call ran" from "the
        // call failed at the FFI layer".
        let env = match unwrap_dek(&recipient_priv_arr, &wrap) {
            Ok(dek) => serde_json::json!({ "dek": dek.to_vec() }),
            Err(KeyGrantError::WrapUnverified) => serde_json::json!({
                "error": {
                    "code": "WRAP_UNVERIFIED",
                    "message": "key_grant unwrap: AEAD tag mismatch \
                                (wrong recipient key, tampered ciphertext, \
                                or mismatched ephemeral_public_key)"
                }
            }),
            Err(KeyGrantError::UnexpectedPlaintextLength { actual }) => serde_json::json!({
                "error": {
                    "code": "UNEXPECTED_PLAINTEXT_LENGTH",
                    "message": format!(
                        "key_grant unwrap: expected 32-byte DEK, got {actual} bytes"
                    )
                }
            }),
            Err(KeyGrantError::Crypto(_)) => serde_json::json!({
                "error": {
                    "code": "CRYPTO_FAILURE",
                    "message": "key_grant unwrap: underlying crypto operation failed"
                }
            }),
        };

        let json = match serde_json::to_vec(&env) {
            Ok(j) => j,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };

        write_owned_bytes(&json, result_out, result_len_out)
    }));
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
            tracing::error!("PANIC in ciris_verify_unwrap_dek: {msg}");
            CirisVerifyError::InternalError as i32
        },
    }
}

#[cfg(test)]
mod tests {
    //! Tests round-trip through the FFI ABI itself (raw pointers +
    //! malloc'd outputs), not the Rust API — the Rust API is already
    //! tested in `ciris_crypto::key_grant`. These tests catch FFI
    //! marshalling regressions (JSON shape, fixed-size byte
    //! handling, opaque-failure envelope).
    use super::*;
    use ciris_crypto::x25519;

    /// Free a pointer returned by `write_owned_bytes` — mirrors what
    /// the Python wheel does via `ciris_verify_free`.
    unsafe fn free_owned(ptr: *mut u8) {
        if !ptr.is_null() {
            libc::free(ptr as *mut libc::c_void);
        }
    }

    fn fresh_keypair() -> ([u8; 32], [u8; 32]) {
        x25519::generate_ephemeral_keypair().unwrap()
    }

    /// Round-trip: wrap → unwrap via the FFI pointer ABI returns the
    /// original DEK byte-for-byte.
    #[test]
    fn ffi_round_trip_returns_original_dek() {
        let (recipient_sk, recipient_pk) = fresh_keypair();
        let dek: [u8; 32] = [0x42; 32];

        // ---- wrap ----
        let mut wrap_ptr: *mut u8 = std::ptr::null_mut();
        let mut wrap_len: usize = 0;
        let rc = unsafe {
            ciris_verify_wrap_dek_for_recipient(
                recipient_pk.as_ptr(),
                dek.as_ptr(),
                &mut wrap_ptr,
                &mut wrap_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::Success as i32, "wrap rc must succeed");
        assert!(!wrap_ptr.is_null());
        assert!(wrap_len > 0);

        let wrap_json = unsafe { std::slice::from_raw_parts(wrap_ptr, wrap_len) }.to_vec();
        unsafe { free_owned(wrap_ptr) };

        // ---- unwrap ----
        let mut unwrap_ptr: *mut u8 = std::ptr::null_mut();
        let mut unwrap_len: usize = 0;
        let rc = unsafe {
            ciris_verify_unwrap_dek(
                recipient_sk.as_ptr(),
                wrap_json.as_ptr(),
                wrap_json.len(),
                &mut unwrap_ptr,
                &mut unwrap_len,
            )
        };
        assert_eq!(
            rc,
            CirisVerifyError::Success as i32,
            "unwrap rc must succeed"
        );
        let unwrap_json = unsafe { std::slice::from_raw_parts(unwrap_ptr, unwrap_len) }.to_vec();
        unsafe { free_owned(unwrap_ptr) };

        let env: serde_json::Value =
            serde_json::from_slice(&unwrap_json).expect("unwrap output must be JSON");
        let dek_arr = env
            .get("dek")
            .and_then(|v| v.as_array())
            .expect("success envelope must carry `dek` array");
        assert_eq!(dek_arr.len(), 32, "DEK must be 32 bytes");
        let got: Vec<u8> = dek_arr.iter().map(|v| v.as_u64().unwrap() as u8).collect();
        assert_eq!(got, dek.to_vec(), "round-trip must return original DEK");
    }

    /// Wrong recipient secret → opaque `WRAP_UNVERIFIED` envelope.
    /// The FFI still returns `Success` (0) — the wrap-failure path
    /// is carried in the JSON, not the status code, so the Python
    /// caller can distinguish "FFI broke" from "AEAD said no".
    #[test]
    fn ffi_wrong_recipient_yields_opaque_wrap_unverified() {
        let (_legitimate_sk, recipient_pk) = fresh_keypair();
        let (wrong_sk, _) = fresh_keypair();
        let dek: [u8; 32] = [0x55; 32];

        let mut wrap_ptr: *mut u8 = std::ptr::null_mut();
        let mut wrap_len: usize = 0;
        let rc = unsafe {
            ciris_verify_wrap_dek_for_recipient(
                recipient_pk.as_ptr(),
                dek.as_ptr(),
                &mut wrap_ptr,
                &mut wrap_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::Success as i32);
        let wrap_json = unsafe { std::slice::from_raw_parts(wrap_ptr, wrap_len) }.to_vec();
        unsafe { free_owned(wrap_ptr) };

        let mut unwrap_ptr: *mut u8 = std::ptr::null_mut();
        let mut unwrap_len: usize = 0;
        let rc = unsafe {
            ciris_verify_unwrap_dek(
                wrong_sk.as_ptr(),
                wrap_json.as_ptr(),
                wrap_json.len(),
                &mut unwrap_ptr,
                &mut unwrap_len,
            )
        };
        assert_eq!(
            rc,
            CirisVerifyError::Success as i32,
            "FFI status is Success — the AEAD-failure travels in JSON, not the rc"
        );
        let unwrap_json = unsafe { std::slice::from_raw_parts(unwrap_ptr, unwrap_len) }.to_vec();
        unsafe { free_owned(unwrap_ptr) };

        let env: serde_json::Value = serde_json::from_slice(&unwrap_json).unwrap();
        assert!(
            env.get("dek").is_none(),
            "wrong-key path must NOT carry a dek field"
        );
        let code = env["error"]["code"].as_str().unwrap();
        assert_eq!(
            code, "WRAP_UNVERIFIED",
            "wrong recipient must surface as opaque WRAP_UNVERIFIED"
        );
    }

    /// JSON wire shape stability: wrap output MUST be the
    /// `KeyGrantWrap` serde shape (`ephemeral_public_key`, `nonce`,
    /// `ciphertext`), and unwrap success MUST be `{"dek": [..]}`.
    /// Both are downstream-contract surfaces (CIRISPersist Engine,
    /// CIRISNodeCore MEDIA_SHARING.md §6.3) so drift here breaks
    /// every consumer.
    #[test]
    fn ffi_json_shape_is_stable() {
        let (recipient_sk, recipient_pk) = fresh_keypair();
        let dek: [u8; 32] = [0x77; 32];

        let mut wrap_ptr: *mut u8 = std::ptr::null_mut();
        let mut wrap_len: usize = 0;
        let rc = unsafe {
            ciris_verify_wrap_dek_for_recipient(
                recipient_pk.as_ptr(),
                dek.as_ptr(),
                &mut wrap_ptr,
                &mut wrap_len,
            )
        };
        assert_eq!(rc, 0);
        let wrap_json = unsafe { std::slice::from_raw_parts(wrap_ptr, wrap_len) }.to_vec();
        unsafe { free_owned(wrap_ptr) };

        let wrap_val: serde_json::Value = serde_json::from_slice(&wrap_json).unwrap();
        // Required fields.
        let eph = wrap_val["ephemeral_public_key"].as_array().unwrap();
        assert_eq!(
            eph.len(),
            32,
            "ephemeral_public_key must serialize as 32-byte array"
        );
        let nonce = wrap_val["nonce"].as_array().unwrap();
        assert_eq!(nonce.len(), 12, "nonce must serialize as 12-byte array");
        let ct = wrap_val["ciphertext"].as_array().unwrap();
        assert_eq!(ct.len(), 32 + 16, "ciphertext = 32B DEK + 16B AES-GCM tag");

        // Unwrap returns `{"dek": [..32..]}` — also stable.
        let mut unwrap_ptr: *mut u8 = std::ptr::null_mut();
        let mut unwrap_len: usize = 0;
        let rc = unsafe {
            ciris_verify_unwrap_dek(
                recipient_sk.as_ptr(),
                wrap_json.as_ptr(),
                wrap_json.len(),
                &mut unwrap_ptr,
                &mut unwrap_len,
            )
        };
        assert_eq!(rc, 0);
        let unwrap_json = unsafe { std::slice::from_raw_parts(unwrap_ptr, unwrap_len) }.to_vec();
        unsafe { free_owned(unwrap_ptr) };
        let unwrap_val: serde_json::Value = serde_json::from_slice(&unwrap_json).unwrap();
        assert!(unwrap_val["dek"].is_array());
        assert_eq!(unwrap_val["dek"].as_array().unwrap().len(), 32);
        assert!(
            unwrap_val.get("error").is_none(),
            "success envelope must NOT carry an error field"
        );
    }

    /// Null-pointer inputs surface as `InvalidArgument`, not panic
    /// or UB. This is the defensive contract for every FFI surface.
    #[test]
    fn ffi_null_inputs_yield_invalid_argument() {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        // wrap: every null surface returns InvalidArgument.
        let rc = unsafe {
            ciris_verify_wrap_dek_for_recipient(
                std::ptr::null(),
                [0u8; 32].as_ptr(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);

        // unwrap: null recipient_priv.
        let bogus_json = b"{}";
        let rc = unsafe {
            ciris_verify_unwrap_dek(
                std::ptr::null(),
                bogus_json.as_ptr(),
                bogus_json.len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);

        // unwrap: malformed JSON → SerializationError.
        let rc = unsafe {
            ciris_verify_unwrap_dek(
                [0u8; 32].as_ptr(),
                b"not json".as_ptr(),
                b"not json".len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
    }
}
