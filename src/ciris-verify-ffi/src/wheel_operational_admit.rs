//! Delegation scope-split FFI surface for the Python wheel (CIRISVerify#77).
//!
//! Wraps [`ciris_verify_core::operational_admit::verify_delegation_scope_split`]
//! as `ciris_verify_delegation_scope_split`, JSON-in/JSON-out. A rejection is a
//! successful call returning `{"ok": false, "error": ...}`; only malformed
//! input yields a `SerializationError` code.
//!
//! `ciris_verify_resolve_role_authority` and
//! `ciris_verify_partner_record_quorum` checked the pair-signed
//! `organization` / `org_membership` / `partner_record` rows, which CC 3.3.9
//! retired; they were removed in 23.3.3.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::operational_admit::verify_delegation_scope_split;
use serde::{Deserialize, Serialize};

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
/// `ciris_verify_free`). Mirrors `wheel_jcs::emit_bytes`.
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
struct ScopeSplitRequest {
    attested_identity_type: String,
    #[serde(default)]
    delegated_scope: Vec<String>,
}

#[derive(Serialize)]
struct ScopeSplitVerdict {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Enforce the CEG §8.1.12.7.1 / §5.6.8.10 `infra:*` / `agency:*` delegation
/// scope split — the wire-checkable form of §1.3 "infrastructure must not have
/// agency" (CIRISRegistry#83).
///
/// `input_json` is a JSON object:
/// ```json
/// {
///   "attested_identity_type": "node" | "agent" | "node,agent" | ...,
///   "delegated_scope": ["infra:serve", "agency:act_on_behalf", ...]
/// }
/// ```
/// `attested_identity_type` is the caller-resolved §7.0.1 `identity_type` SET
/// of the delegation's `attested_key_id`. On success `result_out` receives
/// `{ "ok": true }`; on rejection `{ "ok": false, "error": "..." }` (a
/// node-only delegate carrying agency, or an unrecognized scope — fail-closed).
/// Returns `Success` (0), `InvalidArgument` on a null pointer, or
/// `SerializationError` on malformed input.
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_delegation_scope_split(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_delegation_scope_split", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: ScopeSplitRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        let verdict = match verify_delegation_scope_split(
            &req.attested_identity_type,
            &req.delegated_scope,
        ) {
            Ok(()) => ScopeSplitVerdict {
                ok: true,
                error: None,
            },
            Err(e) => ScopeSplitVerdict {
                ok: false,
                error: Some(e.to_string()),
            },
        };
        match serde_json::to_vec(&verdict) {
            Ok(bytes) => emit_bytes(&bytes, result_out, result_len_out),
            Err(_) => CirisVerifyError::SerializationError as i32,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    unsafe fn call(
        f: unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32,
        req: &serde_json::Value,
    ) -> Result<serde_json::Value, i32> {
        let body = serde_json::to_vec(req).unwrap();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = f(body.as_ptr(), body.len(), &mut out, &mut out_len);
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        if out_len != 0 {
            libc::free(out as *mut libc::c_void);
        }
        Ok(serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn malformed_input_is_serialization_error() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let bad = b"{not json";
        let rc = unsafe {
            ciris_verify_delegation_scope_split(bad.as_ptr(), bad.len(), &mut out, &mut out_len)
        };
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
    }

    #[test]
    fn scope_split_node_with_agency_rejected_via_ffi() {
        let req = json!({
            "attested_identity_type": "node",
            "delegated_scope": ["infra:serve", "agency:act_on_behalf"],
        });
        let v = unsafe { call(ciris_verify_delegation_scope_split, &req) }.unwrap();
        assert_eq!(v["ok"], json!(false));
        assert!(v["error"].as_str().unwrap().contains("agency"));
    }

    #[test]
    fn scope_split_agent_with_agency_ok_via_ffi() {
        let req = json!({
            "attested_identity_type": "node,agent",
            "delegated_scope": ["agency:decide", "infra:serve"],
        });
        let v = unsafe { call(ciris_verify_delegation_scope_split, &req) }.unwrap();
        assert_eq!(v["ok"], json!(true));
    }
}
