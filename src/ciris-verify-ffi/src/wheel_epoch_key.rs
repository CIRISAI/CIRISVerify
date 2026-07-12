//! CC 5.1 `CLM-epoch-keying` derivation FFI surface (CIRISVerify#193).
//!
//! Exposes `ciris_crypto::epoch_key` — the per-`(stream_id, epoch)` DEK +
//! stream-nonce HKDF derivation (the epoch-keyed counterpart of
//! `derive_symbol_key`) — so the CIRISConformance harness (which drives Python)
//! can byte-check CC 5.1 `CLM-epoch-keying`, and CIRISPersist#432's `(stream_id,
//! epoch)` key-grant writer derives against the one canonical formula.
//!
//! ## Wire shape (`op`-tagged JSON in → raw bytes out)
//!
//! ```text
//! {"op":"epoch_key",          "stream_root":[u8;32], "stream_id":"…", "epoch":u64}  -> 32 raw bytes
//! {"op":"epoch_stream_nonce", "stream_root":[u8;32], "stream_id":"…", "epoch":u64}  -> 24 raw bytes
//! ```
//!
//! A malformed request (bad JSON, `stream_root` not exactly 32 bytes) returns a
//! typed error code — fail-closed.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_crypto::epoch_key::{derive_epoch_key, derive_epoch_stream_nonce};
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
#[serde(tag = "op")]
enum EpochRequest {
    #[serde(rename = "epoch_key")]
    EpochKey {
        stream_root: Vec<u8>,
        stream_id: String,
        epoch: u64,
    },
    #[serde(rename = "epoch_stream_nonce")]
    EpochStreamNonce {
        stream_root: Vec<u8>,
        stream_id: String,
        epoch: u64,
    },
}

/// Compute the requested derivation, or `None` on a malformed `stream_root`
/// (must be exactly 32 bytes) — fail-closed.
fn dispatch(req: &EpochRequest) -> Option<Vec<u8>> {
    Some(match req {
        EpochRequest::EpochKey {
            stream_root,
            stream_id,
            epoch,
        } => derive_epoch_key(
            &<[u8; 32]>::try_from(stream_root.as_slice()).ok()?,
            stream_id,
            *epoch,
        )
        .to_vec(),
        EpochRequest::EpochStreamNonce {
            stream_root,
            stream_id,
            epoch,
        } => derive_epoch_stream_nonce(
            &<[u8; 32]>::try_from(stream_root.as_slice()).ok()?,
            stream_id,
            *epoch,
        )
        .to_vec(),
    })
}

/// Compute a CC 5.1 epoch derivation (CIRISVerify#193).
///
/// `input_json` is the UTF-8 bytes of an `op`-tagged request (see module docs).
/// On success `result_out` / `result_len_out` receive the raw derived bytes —
/// **32** for `epoch_key`, **24** for `epoch_stream_nonce` (caller frees via
/// `ciris_verify_free`). Returns:
/// - `Success` (0) on success;
/// - `InvalidArgument` on a null pointer;
/// - `SerializationError` if `input_json` is not a valid request or
///   `stream_root` is not exactly 32 bytes.
///
/// # Safety
///
/// `input_json` must point to valid memory of at least `input_len` bytes.
/// `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_epoch_key_derive(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_epoch_key_derive", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: EpochRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        match dispatch(&req) {
            Some(out) => emit_bytes(&out, result_out, result_len_out),
            None => CirisVerifyError::SerializationError as i32,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn ffi(json: &str) -> Result<Vec<u8>, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_epoch_key_derive(json.as_ptr(), json.len(), &mut out, &mut out_len);
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        libc::free(out as *mut libc::c_void);
        Ok(bytes)
    }

    #[test]
    fn ffi_matches_the_core_derivation_and_lengths() {
        let root: Vec<u8> = vec![0x42; 32];
        let k = unsafe {
            ffi(&serde_json::json!({"op":"epoch_key","stream_root":root,"stream_id":"stream-1","epoch":7}).to_string())
        }
        .unwrap();
        let n = unsafe {
            ffi(&serde_json::json!({"op":"epoch_stream_nonce","stream_root":root,"stream_id":"stream-1","epoch":7}).to_string())
        }
        .unwrap();
        assert_eq!(k.len(), 32);
        assert_eq!(n.len(), 24);
        // Byte-identical to the Rust core (one derivation, no second impl).
        let arr = <[u8; 32]>::try_from(root.as_slice()).unwrap();
        assert_eq!(k, derive_epoch_key(&arr, "stream-1", 7).to_vec());
        assert_eq!(n, derive_epoch_stream_nonce(&arr, "stream-1", 7).to_vec());
    }

    /// The FFI must reproduce the pinned cross-impl golden (CC 5.1).
    #[test]
    fn ffi_matches_cross_impl_golden() {
        use sha2::{Digest, Sha256};
        let root: Vec<u8> = vec![0x42; 32];
        let k = unsafe {
            ffi(&serde_json::json!({"op":"epoch_key","stream_root":root,"stream_id":"stream-1","epoch":7}).to_string())
        }
        .unwrap();
        let n = unsafe {
            ffi(&serde_json::json!({"op":"epoch_stream_nonce","stream_root":root,"stream_id":"stream-1","epoch":7}).to_string())
        }
        .unwrap();
        let mut h = Sha256::new();
        h.update(&k);
        h.update(&n);
        assert_eq!(
            hex::encode(h.finalize()),
            "38091aeb6cd2cce8ae7225cfd9614f35128a9c2c5f482847dc4ceedee69f61f0"
        );
    }

    #[test]
    fn ffi_rejects_wrong_length_root_and_bad_json() {
        let short: Vec<u8> = vec![0x42; 31];
        assert_eq!(
            unsafe {
                ffi(&serde_json::json!({"op":"epoch_key","stream_root":short,"stream_id":"s","epoch":1}).to_string())
            }
            .unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
        assert_eq!(
            unsafe { ffi("{\"op\":\"nope\"}") }.unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
    }
}
