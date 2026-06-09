//! JCS (RFC 8785) canonicalization FFI surface for the Python wheel
//! (CIRISVerify#61, v5.0.0+).
//!
//! Wraps [`ciris_verify_core::jcs::canonicalize`] so the CIRISAgent
//! producer — and any other wheel consumer — can canonicalize a JSON
//! value to its RFC 8785 byte sequence **byte-identically** to the Rust
//! verifiers. This is the load-bearing piece of the CEG §0.9 JCS
//! cutover (the 2.9.6 substrate triple): there is exactly one blessed
//! JCS implementation, and the Python side must reach it rather than
//! hand-roll a second one (Python's `json.dumps` is not JCS and diverges
//! on all non-ASCII).
//!
//! ## Wire shape
//!
//! `ciris_verify_jcs_canonicalize` takes the UTF-8 bytes of a JSON
//! document and returns the **raw** RFC 8785 canonical byte sequence
//! (NOT wrapped in a JSON envelope — the caller wants the literal bytes
//! to sign). On parse failure returns a typed error code.
//!
//! ## Why byte-identity is guaranteed
//!
//! The Python binding does **zero** canonicalization — it serializes the
//! value to *any* valid JSON encoding and hands it here; this function
//! parses it into a `serde_json::Value` and runs the same
//! `ciris_verify_core::jcs::canonicalize` the verifiers use. JCS
//! canonicalizes by value, so the transport encoding is irrelevant and
//! the output is identical to the Rust path by construction.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::jcs;

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
    // libc::malloc(0) may return NULL legitimately; guard the zero case so
    // an empty canonical output (not reachable for JSON, but defensive)
    // doesn't read as an allocation failure.
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

/// Canonicalize a JSON document to its RFC 8785 (JCS) byte sequence
/// (CIRISVerify#61, v5.0.0+).
///
/// `input_json` is the UTF-8 bytes of any valid JSON value. On success
/// `result_out` / `result_len_out` receive the raw canonical bytes
/// (caller frees via `ciris_verify_free`). Returns:
/// - `Success` (0) on success;
/// - `InvalidArgument` on a null pointer;
/// - `SerializationError` if `input_json` is not valid JSON or cannot be
///   canonicalized (e.g. a non-finite float).
///
/// # Safety
///
/// `input_json` must point to valid memory of at least `input_len`
/// bytes. `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_jcs_canonicalize(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_jcs_canonicalize", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let value: serde_json::Value = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        match jcs::canonicalize(&value) {
            Ok(bytes) => emit_bytes(&bytes, result_out, result_len_out),
            Err(_) => CirisVerifyError::SerializationError as i32,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the FFI exactly as the Python binding will, then compare to
    /// the in-process `jcs::canonicalize` — they must be byte-identical
    /// (same code path).
    unsafe fn ffi_canonicalize(json: &str) -> Result<Vec<u8>, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_jcs_canonicalize(json.as_ptr(), json.len(), &mut out, &mut out_len);
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        if out_len != 0 {
            libc::free(out as *mut libc::c_void);
        }
        Ok(bytes)
    }

    #[test]
    fn ffi_matches_core_canonicalize() {
        let inputs = [
            r#"{"b":2,"a":1}"#,
            r#"{"score":0.95,"dimension":"x"}"#,
            r#"[3,2,1]"#,
            r#"{"nested":{"y":2,"x":1},"k":null}"#,
        ];
        for input in inputs {
            let value: serde_json::Value = serde_json::from_str(input).unwrap();
            let core = jcs::canonicalize(&value).unwrap();
            let ffi = unsafe { ffi_canonicalize(input) }.unwrap();
            assert_eq!(ffi, core, "FFI must match core for {input}");
        }
    }

    /// Multilingual + the ⚠️ disclosure emoji — the exact vectors the
    /// agent measured `json.dumps` breaking on. Through this binding they
    /// canonicalize identically because the canonicalization is Rust-side.
    #[test]
    fn multilingual_and_emoji_canonicalize() {
        // Non-ASCII keys + values + the disclosure emoji.
        let input =
            r#"{"rationale":"理由","thought_content":"café ☕","disclosure":"⚠️ community"}"#;
        let value: serde_json::Value = serde_json::from_str(input).unwrap();
        let core = jcs::canonicalize(&value).unwrap();
        let ffi = unsafe { ffi_canonicalize(input) }.unwrap();
        assert_eq!(ffi, core);
        // Non-ASCII is preserved as literal UTF-8 (JCS does NOT \u-escape it).
        let s = String::from_utf8(ffi).unwrap();
        assert!(s.contains("理由"), "CJK preserved literally");
        assert!(s.contains("⚠️"), "disclosure emoji preserved literally");
        assert!(s.contains("café ☕"));
    }

    /// Key reordering at the input produces identical canonical bytes —
    /// the property a producer relies on.
    #[test]
    fn key_order_independent() {
        let a = unsafe { ffi_canonicalize(r#"{"a":1,"b":2,"c":3}"#) }.unwrap();
        let b = unsafe { ffi_canonicalize(r#"{"c":3,"a":1,"b":2}"#) }.unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn invalid_json_returns_serialization_error() {
        let rc = unsafe { ffi_canonicalize("{not valid json") }.unwrap_err();
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
    }

    #[test]
    fn null_input_returns_invalid_argument() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc =
            unsafe { ciris_verify_jcs_canonicalize(std::ptr::null(), 0, &mut out, &mut out_len) };
        assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);
    }
}
