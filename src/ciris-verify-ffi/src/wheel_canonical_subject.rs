//! CC 2.3.2.1 canonical-hash **subject** codec FFI surface (CIRISVerify#201).
//!
//! Exposes [`ciris_verify_core::canonical_subject`] to the Python wheel so
//! CIRISConformance can drive CC 2.3.2.1 and any producer can build/validate a
//! `canonical:sha256:<hex>` subject through the one blessed implementation
//! instead of hand-rolling the tag.
//!
//! The load-bearing property is the **reject** direction: a bare 64-hex subject
//! is format-indistinguishable from a `key_id`, so admitting one silently
//! conflates a content-hash subject with a key subject. This surface reports
//! that case distinctly (`kind: "bare_hex"`) so a gate can refuse it with an
//! actionable reason.
//!
//! ## Wire shape (JSON in → JSON out)
//!
//! Encode:
//! ```json
//! {"op":"encode","platform":"discord","entity_kind":"user","id":"12345"}
//! → {"ok":true,"subject":"canonical:sha256:<64hex>"}
//! ```
//! Encode from a joined triple (splits on the first two colons, so `id` may
//! contain colons):
//! ```json
//! {"op":"encode_triple","triple":"matrix:room:!abc:server.tld"}
//! → {"ok":true,"subject":"canonical:sha256:<64hex>"}
//! ```
//! Validate / classify:
//! ```json
//! {"op":"parse","subject":"canonical:sha256:<64hex>"}
//! → {"ok":true,"kind":"canonical_hash","digest_hex":"<64hex>"}
//! {"op":"parse","subject":"<bare 64 hex>"}
//! → {"ok":false,"kind":"bare_hex","error":"bare hex subject is not admissible …"}
//! ```
//! A malformed request returns `InvalidArgument`; a *rejected subject* is a
//! successful call returning `ok:false` (fail-closed by verdict, not by error).

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::canonical_subject::{
    canonical_subject, canonical_subject_from_triple, parse_canonical_subject, SubjectError,
    SubjectKind,
};
use serde_json::{json, Value};

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

/// Stable machine-readable tag for the rejected/By-kind cases.
fn kind_tag(kind: &SubjectKind) -> &'static str {
    match kind {
        SubjectKind::CanonicalHash { .. } => "canonical_hash",
        SubjectKind::BareHex => "bare_hex",
        SubjectKind::Other => "other",
    }
}

/// Build the JSON response for a parse attempt.
fn parse_response(subject: &str) -> Value {
    match parse_canonical_subject(subject) {
        Ok(digest) => json!({
            "ok": true,
            "kind": "canonical_hash",
            "digest_hex": hex::encode(digest),
        }),
        Err(e) => {
            let kind = match &e {
                SubjectError::NotTagged { kind } => kind_tag(kind),
                _ => "other",
            };
            json!({ "ok": false, "kind": kind, "error": e.to_string() })
        },
    }
}

fn str_arg<'a>(req: &'a Value, key: &str) -> Option<&'a str> {
    req.get(key).and_then(Value::as_str)
}

/// Canonical-hash subject codec — construct and validate CC 2.3.2.1 subjects.
///
/// See the module docs for the JSON wire shape. On success `result_out` /
/// `result_len_out` receive the UTF-8 JSON response (caller frees via
/// `ciris_verify_free`). Returns `InvalidArgument` for a null pointer, invalid
/// JSON, or an unknown/missing `op`; a *rejected subject* is still `Success`
/// with `ok:false` in the body.
///
/// # Safety
///
/// `input_json` must point to valid memory of at least `input_len` bytes.
/// `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_canonical_subject(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_canonical_subject", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let Ok(req) = serde_json::from_slice::<Value>(input) else {
            return CirisVerifyError::InvalidArgument as i32;
        };

        let response = match str_arg(&req, "op") {
            Some("encode") => {
                let (Some(platform), Some(entity_kind), Some(id)) = (
                    str_arg(&req, "platform"),
                    str_arg(&req, "entity_kind"),
                    str_arg(&req, "id"),
                ) else {
                    return CirisVerifyError::InvalidArgument as i32;
                };
                match canonical_subject(platform, entity_kind, id) {
                    Ok(subject) => json!({ "ok": true, "subject": subject }),
                    Err(e) => json!({ "ok": false, "error": e.to_string() }),
                }
            },
            Some("encode_triple") => {
                let Some(triple) = str_arg(&req, "triple") else {
                    return CirisVerifyError::InvalidArgument as i32;
                };
                match canonical_subject_from_triple(triple) {
                    Ok(subject) => json!({ "ok": true, "subject": subject }),
                    Err(e) => json!({ "ok": false, "error": e.to_string() }),
                }
            },
            Some("parse") => {
                let Some(subject) = str_arg(&req, "subject") else {
                    return CirisVerifyError::InvalidArgument as i32;
                };
                parse_response(subject)
            },
            _ => return CirisVerifyError::InvalidArgument as i32,
        };

        let Ok(bytes) = serde_json::to_vec(&response) else {
            return CirisVerifyError::SerializationError as i32;
        };
        emit_bytes(&bytes, result_out, result_len_out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the FFI exactly as the Python binding will.
    fn call(req: &Value) -> Value {
        let input = serde_json::to_vec(req).unwrap();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            ciris_verify_canonical_subject(input.as_ptr(), input.len(), &mut out, &mut out_len)
        };
        assert_eq!(rc, CirisVerifyError::Success as i32, "req={req}");
        let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
        unsafe { libc::free(out.cast()) };
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn encode_then_parse_round_trips() {
        let enc =
            call(&json!({"op":"encode","platform":"discord","entity_kind":"user","id":"12345"}));
        assert_eq!(enc["ok"], true);
        let subject = enc["subject"].as_str().unwrap().to_string();
        assert!(subject.starts_with("canonical:sha256:"));

        let parsed = call(&json!({"op":"parse","subject":subject}));
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["kind"], "canonical_hash");
        assert_eq!(parsed["digest_hex"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn encode_triple_matches_encode() {
        let a = call(&json!({"op":"encode_triple","triple":"matrix:room:!abc:server.tld"}));
        let b = call(&json!({
            "op":"encode","platform":"matrix","entity_kind":"room","id":"!abc:server.tld"
        }));
        assert_eq!(a["subject"], b["subject"]);
    }

    /// The CC 2.3.2.1 gate over the FFI: bare hex is refused AND identified.
    #[test]
    fn bare_hex_is_rejected_with_its_own_kind() {
        let bare = "a".repeat(64);
        let out = call(&json!({"op":"parse","subject":bare}));
        assert_eq!(out["ok"], false);
        assert_eq!(out["kind"], "bare_hex");
        assert!(out["error"].as_str().unwrap().contains("key_id"));
    }

    #[test]
    fn bad_algorithm_and_key_id_classify_distinctly() {
        let bad_alg =
            call(&json!({"op":"parse","subject":format!("canonical:md5:{}", "a".repeat(32))}));
        assert_eq!(bad_alg["ok"], false);
        assert_eq!(bad_alg["kind"], "other");

        let key_id = call(&json!({"op":"parse","subject":"ciris-canonical-1"}));
        assert_eq!(key_id["ok"], false);
        assert_eq!(key_id["kind"], "other");
    }

    #[test]
    fn malformed_requests_are_invalid_argument() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        // Unknown op.
        let bad = serde_json::to_vec(&json!({"op":"nope"})).unwrap();
        let rc = unsafe {
            ciris_verify_canonical_subject(bad.as_ptr(), bad.len(), &mut out, &mut out_len)
        };
        assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);
        // Not JSON.
        let bad = b"{not json";
        let rc = unsafe {
            ciris_verify_canonical_subject(bad.as_ptr(), bad.len(), &mut out, &mut out_len)
        };
        assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);
    }
}
