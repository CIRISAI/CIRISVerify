//! RNS `destination_hash` recompute FFI surface for the Python wheel
//! (CIRISVerify#28 lift — CEG 1.0-RC6 §5.6.8.8.1.1).
//!
//! Wraps [`ciris_verify_core::transport_binding::compute_destination_hash`] —
//! the one blessed two-stage RNS destination-hash construction — so a Python
//! consumer (and CIRISConformance's `test_150_rns_dest_hash.py` cross-check) can
//! recompute `destination_hash` and verify it byte-for-byte against the pinned
//! algorithm, rather than the surface being Rust-only. This is the last
//! verify-side remainder of the #28 transport-binding waterfall: the recompute
//! shipped in v5.6.0 (`DestinationHashCheck` lifted off `Unsupported`) but was
//! never exposed on the wheel, so the conformance cross-check stayed `xfail`.
//!
//! ## Wire shape
//!
//! `ciris_verify_rns_destination_hash` takes the UTF-8 bytes of a JSON document
//! `{"app_name": str, "aspects": [str], "x25519_pubkey": [u8], "ed25519_pubkey":
//! [u8]}` and returns the **raw** 16-byte destination hash (NOT a JSON envelope).
//! On a malformed request — bad JSON, or an aspect containing `.` (illegal per
//! §5.6.8.8.1.1, which would alter the name preimage split) — returns a typed
//! error code.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::transport_binding::compute_destination_hash;
use serde::Deserialize;

use crate::CirisVerifyError;

macro_rules! ffi_guard {
    ($fn_name:expr, $body:expr) => {{
        let result = catch_unwind(AssertUnwindSafe(|| $body));
        match result {
            Ok(code) => code,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    (*s).to_string()
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

/// Allocate a raw-bytes output buffer on the C heap (caller frees via
/// `ciris_verify_free`).
unsafe fn emit_bytes(bytes: &[u8], result_out: *mut *mut u8, result_len_out: *mut usize) -> i32 {
    let len = bytes.len();
    if len == 0 {
        *result_out = std::ptr::NonNull::dangling().as_ptr();
        *result_len_out = 0;
        return CirisVerifyError::Success as i32;
    }
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
    *result_out = ptr;
    *result_len_out = len;
    CirisVerifyError::Success as i32
}

#[derive(Deserialize)]
struct DestHashRequest {
    app_name: String,
    aspects: Vec<String>,
    x25519_pubkey: Vec<u8>,
    ed25519_pubkey: Vec<u8>,
}

/// Recompute the RNS `destination_hash` per CEG §5.6.8.8.1.1
/// (CIRISVerify#28 lift).
///
/// `input_json` is the UTF-8 bytes of `{"app_name": str, "aspects": [str],
/// "x25519_pubkey": [u8], "ed25519_pubkey": [u8]}`. On success `result_out` /
/// `result_len_out` receive the raw 16-byte destination hash (caller frees via
/// `ciris_verify_free`). Returns:
/// - `Success` (0) on success;
/// - `InvalidArgument` on a null pointer;
/// - `SerializationError` if `input_json` is not valid JSON, or the
///   construction is rejected (an aspect containing `.`).
///
/// # Safety
///
/// `input_json` must point to valid memory of at least `input_len` bytes.
/// `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_rns_destination_hash(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_rns_destination_hash", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: DestHashRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        match compute_destination_hash(
            &req.app_name,
            &req.aspects,
            &req.x25519_pubkey,
            &req.ed25519_pubkey,
        ) {
            Some(hash) => emit_bytes(&hash, result_out, result_len_out),
            // None == an aspect contained '.' (illegal per §5.6.8.8.1.1).
            None => CirisVerifyError::SerializationError as i32,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn ffi_dest_hash(json: &str) -> Result<Vec<u8>, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc =
            ciris_verify_rns_destination_hash(json.as_ptr(), json.len(), &mut out, &mut out_len);
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        if out_len != 0 {
            libc::free(out as *mut libc::c_void);
        }
        Ok(bytes)
    }

    /// The CIRISConformance §5.6.8.8.1.1 golden vector (test_150_rns_dest_hash.py):
    /// x25519 = 00..1f, ed25519 = 20..3f, app "ciris.federation", aspect
    /// "transport" → dest hash 98baa5d17abd7d940741d2f7b850577c. The wheel
    /// recompute MUST match this byte-for-byte (this is the #28-lift gate).
    #[test]
    fn ffi_matches_conformance_golden_vector() {
        let x25519: Vec<u8> = (0u8..32).collect();
        let ed25519: Vec<u8> = (32u8..64).collect();
        let json = serde_json::json!({
            "app_name": "ciris.federation",
            "aspects": ["transport"],
            "x25519_pubkey": x25519,
            "ed25519_pubkey": ed25519,
        })
        .to_string();
        let got = unsafe { ffi_dest_hash(&json) }.unwrap();
        assert_eq!(hex::encode(&got), "98baa5d17abd7d940741d2f7b850577c");
        assert_eq!(got.len(), 16);
    }

    #[test]
    fn ffi_rejects_dotted_aspect() {
        let x25519: Vec<u8> = (0u8..32).collect();
        let ed25519: Vec<u8> = (32u8..64).collect();
        let json = serde_json::json!({
            "app_name": "ciris.federation",
            "aspects": ["bad.aspect"],
            "x25519_pubkey": x25519,
            "ed25519_pubkey": ed25519,
        })
        .to_string();
        assert_eq!(
            unsafe { ffi_dest_hash(&json) }.unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
    }

    #[test]
    fn ffi_bad_json_is_serialization_error() {
        assert_eq!(
            unsafe { ffi_dest_hash("not json") }.unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
    }
}
