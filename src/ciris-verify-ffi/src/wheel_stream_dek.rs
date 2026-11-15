//! CC 5.1 per-stream call DEK FFI surface (CIRISVerify#308).
//!
//! Exposes `ciris_crypto::stream_dek::stream_dek`, the HKDF step that binds a
//! stream and epoch to the MLS exporter secret, so edge, persist and every
//! client derive one DEK per `(stream_id, epoch)` from the one implementation.
//!
//! ## Wire shape (JSON in → 32 raw bytes out)
//!
//! ```text
//! {"exporter_secret":[u8;32], "stream_id":"av-{64 lowercase hex}", "epoch":u64}
//! ```
//!
//! `exporter_secret` is the caller's `MLS-Exporter("ciris-stream-dek/v1", "",
//! 32)` output for the group at `epoch`; verify does no MLS.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_crypto::stream_dek::{stream_dek, STREAM_DEK_LEN};
use serde::Deserialize;

use crate::CirisVerifyError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamDekRequest {
    exporter_secret: Vec<u8>,
    stream_id: String,
    epoch: u64,
}

/// Derive the CC 5.1 per-stream call DEK (CIRISVerify#308).
///
/// `input_json` is the UTF-8 bytes of a request (see module docs). On success
/// `result_out` / `result_len_out` receive the 32-byte DEK (caller frees via
/// `ciris_verify_free`). Returns:
/// - `Success` (0) on success;
/// - `InvalidArgument` on a null pointer, or a `stream_id` that is not
///   `av-{64 lowercase hex}`;
/// - `SerializationError` if `input_json` is not a valid request or
///   `exporter_secret` is not exactly 32 bytes.
///
/// # Safety
///
/// `input_json` must point to valid memory of at least `input_len` bytes.
/// `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_stream_dek_derive(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let Ok(req) = serde_json::from_slice::<StreamDekRequest>(input) else {
            return CirisVerifyError::SerializationError as i32;
        };
        let Ok(secret) = <[u8; STREAM_DEK_LEN]>::try_from(req.exporter_secret.as_slice()) else {
            return CirisVerifyError::SerializationError as i32;
        };
        let Ok(dek) = stream_dek(&secret, &req.stream_id, req.epoch) else {
            return CirisVerifyError::InvalidArgument as i32;
        };
        let ptr = libc::malloc(STREAM_DEK_LEN) as *mut u8;
        if ptr.is_null() {
            return CirisVerifyError::InternalError as i32;
        }
        std::ptr::copy_nonoverlapping(dek.as_ptr(), ptr, STREAM_DEK_LEN);
        *result_out = ptr;
        *result_len_out = STREAM_DEK_LEN;
        CirisVerifyError::Success as i32
    }));
    result.unwrap_or_else(|_| {
        tracing::error!("PANIC in ciris_verify_stream_dek_derive");
        CirisVerifyError::InternalError as i32
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn ffi(json: &str) -> Result<Vec<u8>, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_stream_dek_derive(json.as_ptr(), json.len(), &mut out, &mut out_len);
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        libc::free(out as *mut libc::c_void);
        Ok(bytes)
    }

    /// The `epoch_zero` case of `ciris-crypto`'s independently generated
    /// `stream_dek_vectors.json`.
    #[test]
    fn ffi_reproduces_the_known_answer() {
        let secret: Vec<u8> = vec![0x42; 32];
        let sid = "av-b97c9419b25a92735174ec8d44d66efa6d2bf758d09934bf7129c6a8e77a2c4b";
        let req = serde_json::json!({"exporter_secret": secret, "stream_id": sid, "epoch": 0});
        let got = unsafe { ffi(&req.to_string()) }.unwrap();
        assert_eq!(
            hex::encode(got),
            "cf6aa74dcccfda58ec2c5ae8e943133c8b4dba4a73ed67b20650ed3301a205c5"
        );
    }

    #[test]
    fn ffi_refuses_malformed_input() {
        let ok_sid = format!("av-{}", "ab".repeat(32));
        let cases = [
            (
                serde_json::json!({"exporter_secret": vec![0x42u8; 31], "stream_id": ok_sid, "epoch": 0}),
                CirisVerifyError::SerializationError,
            ),
            (
                serde_json::json!({"exporter_secret": vec![0x42u8; 32], "stream_id": "ab".repeat(32), "epoch": 0}),
                CirisVerifyError::InvalidArgument,
            ),
            (
                serde_json::json!({"exporter_secret": vec![0x42u8; 32], "stream_id": ok_sid, "epoch": 0, "extra": 1}),
                CirisVerifyError::SerializationError,
            ),
        ];
        for (req, want) in cases {
            assert_eq!(unsafe { ffi(&req.to_string()) }.unwrap_err(), want as i32);
        }
        assert_eq!(
            unsafe { ffi("not json") }.unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
    }
}
