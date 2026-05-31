//! `SkillImportManifest` FFI surface for the Python wheel
//! (CIRISVerify#50, v4.7.0+).
//!
//! Wraps [`ciris_verify_core::skill_import::verify_skill_import_manifest`]
//! so wheel consumers can drive CEG-0.2 §3.2.1.1 / §5.2.1 community-skill
//! import provenance verification from Python. Surface principle: "if it
//! ain't on the wheel, it doesn't exist."
//!
//! ## Static-pubkey leak strategy
//!
//! Upstream [`ciris_verify_core::security::function_integrity::StewardPublicKey`]
//! carries `&'static` slices because the canonical use is steward keys
//! baked into the binary via `include_bytes!` (the bootstrap keyset).
//! For the cross-wheel FFI seam the caller supplies the pubkey as JSON
//! per-call, which we materialize into static memory via `Box::leak`.
//!
//! This leak is **structurally fine, not a bug**: trusted-pubkey JSONs
//! supplied through this FFI are long-lived per-process and the leak
//! is bounded by the number of distinct steward keys a wheel consumer
//! ever submits — typically a handful (one per source-type per
//! federation), never per-verification. The leak is the price of
//! preserving the upstream `&'static` invariant without rewriting the
//! core type. Callers that want zero-leak hot rotation can hold a
//! handle on the Python side and reuse one pubkey JSON.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::security::function_integrity::StewardPublicKey;
use ciris_verify_core::skill_import::verify_skill_import_manifest;
use serde::Deserialize;

use crate::CirisVerifyError;

// ---------------------------------------------------------------------------
// Local panic-guard macro
//
// `lib.rs`'s `ffi_guard!` is `macro_rules!` and not exported to submodules
// without `#[macro_export]`. Duplicating the small wrapper here keeps this
// surface self-contained and avoids touching `lib.rs`.
// ---------------------------------------------------------------------------

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

/// Wire shape for a `StewardPublicKey` supplied per-call from Python.
///
/// The two byte arrays are leaked into `'static` memory inside
/// `into_static()` — see the module doc for why this is structurally
/// acceptable on the wheel surface.
#[derive(Debug, Deserialize)]
struct WirePubkey {
    /// Ed25519 public key bytes (exactly 32).
    ed25519: Vec<u8>,
    /// ML-DSA-65 public key bytes (variable; spec-typical 1952).
    ml_dsa_65: Vec<u8>,
}

impl WirePubkey {
    /// Materialize into a `StewardPublicKey` whose `'static` slices live
    /// for the remainder of the process — see module doc.
    fn into_static(self) -> Result<StewardPublicKey, String> {
        if self.ed25519.len() != 32 {
            return Err(format!(
                "trusted_pubkey.ed25519: expected 32 bytes, got {}",
                self.ed25519.len()
            ));
        }
        // Convert Vec<u8> → Box<[u8; 32]> → &'static [u8; 32] via Box::leak.
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&self.ed25519);
        let ed_static: &'static [u8; 32] = Box::leak(Box::new(ed));

        let ml_static: &'static [u8] = Box::leak(self.ml_dsa_65.into_boxed_slice());

        Ok(StewardPublicKey {
            ed25519: ed_static,
            ml_dsa_65: ml_static,
        })
    }
}

/// Allocate a JSON-bytes output buffer on the C heap (caller frees via
/// `ciris_verify_free`).
unsafe fn emit_json(json: &str, result_out: *mut *mut u8, result_len_out: *mut usize) -> i32 {
    let len = json.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }
    std::ptr::copy_nonoverlapping(json.as_ptr(), ptr, len);
    *result_out = ptr;
    *result_len_out = len;
    CirisVerifyError::Success as i32
}

/// Emit a typed-error JSON envelope, matching the §10.0.1 shape used
/// elsewhere on the v4.2.0 conformance FFI surface.
unsafe fn emit_error_envelope(
    code: &str,
    message: &str,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    let env = serde_json::json!({
        "error": {
            "code": code,
            "message": message,
        }
    });
    emit_json(&env.to_string(), result_out, result_len_out)
}

/// CEG 0.2 §3.2.1.1 / §5.2.1 `SkillImportManifest` verification
/// (CIRISVerify#50, v4.7.0+).
///
/// Verifies the hybrid Ed25519 + ML-DSA-65 signature on a
/// `SkillImportManifest` JSON payload against the caller-supplied
/// trusted-pubkey JSON. On success emits the parsed manifest JSON
/// (round-trip), so the Python caller gets a structured view of what
/// was signed. On failure emits a `{"error": {"code", "message"}}`
/// envelope.
///
/// The trusted-pubkey JSON shape is:
///
/// ```json
/// {"ed25519": [..32 bytes..], "ml_dsa_65": [..bytes..]}
/// ```
///
/// **Pubkey-key-selection is consumer policy.** This function does
/// not select the trusted pubkey based on the manifest's `source`
/// prefix — the caller picks. See the upstream module doc for the
/// rationale.
///
/// # Safety
///
/// All `*const u8` inputs must point to valid memory of at least
/// the declared length. `result_out` and `result_len_out` must be
/// valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_skill_import_manifest_verify(
    manifest_json: *const u8,
    manifest_len: usize,
    trusted_pubkey_json: *const u8,
    trusted_pubkey_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_skill_import_manifest_verify", {
        skill_import_manifest_verify_inner(
            manifest_json,
            manifest_len,
            trusted_pubkey_json,
            trusted_pubkey_len,
            result_out,
            result_len_out,
        )
    })
}

unsafe fn skill_import_manifest_verify_inner(
    manifest_json: *const u8,
    manifest_len: usize,
    trusted_pubkey_json: *const u8,
    trusted_pubkey_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if manifest_json.is_null()
        || trusted_pubkey_json.is_null()
        || result_out.is_null()
        || result_len_out.is_null()
    {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let manifest_bytes = std::slice::from_raw_parts(manifest_json, manifest_len);
    let pubkey_bytes = std::slice::from_raw_parts(trusted_pubkey_json, trusted_pubkey_len);

    let wire_pubkey: WirePubkey = match serde_json::from_slice(pubkey_bytes) {
        Ok(p) => p,
        Err(e) => {
            return emit_error_envelope(
                "INVALID_PUBKEY_JSON",
                &format!("trusted_pubkey JSON parse failed: {e}"),
                result_out,
                result_len_out,
            );
        },
    };

    let pubkey = match wire_pubkey.into_static() {
        Ok(p) => p,
        Err(e) => {
            return emit_error_envelope("INVALID_PUBKEY_SHAPE", &e, result_out, result_len_out);
        },
    };

    match verify_skill_import_manifest(manifest_bytes, &pubkey) {
        Ok(manifest) => match serde_json::to_string(&manifest) {
            Ok(json) => emit_json(&json, result_out, result_len_out),
            Err(_) => CirisVerifyError::SerializationError as i32,
        },
        Err(e) => emit_error_envelope(
            "SIGNATURE_VERIFICATION_FAILED",
            &format!("{e}"),
            result_out,
            result_len_out,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::security::function_integrity::ManifestSignature;
    use ciris_verify_core::skill_import::SkillImportManifest;

    fn minimal_manifest() -> SkillImportManifest {
        SkillImportManifest {
            source: "registry:ciris-registry-us".into(),
            skill_manifest_sha256: "a".repeat(64),
            signer_identity: "registry-steward-us".into(),
            import_timestamp: "2026-05-28T17:30:00.000Z".into(),
            capability_declaration: vec!["domain:medical:triage".into()],
            valid_until: Some("2026-08-28T17:30:00.000Z".into()),
            signature: ManifestSignature {
                classical: "ZmFrZQ==".into(),
                classical_algorithm: String::new(),
                pqc: String::new(),
                pqc_algorithm: String::new(),
                key_id: String::new(),
            },
        }
    }

    /// Helper: drive the FFI fn, return the (status, response_json) pair.
    unsafe fn invoke(manifest_json: &[u8], pubkey_json: &[u8]) -> (i32, Option<String>) {
        let mut result_ptr: *mut u8 = std::ptr::null_mut();
        let mut result_len: usize = 0;
        let status = ciris_verify_skill_import_manifest_verify(
            manifest_json.as_ptr(),
            manifest_json.len(),
            pubkey_json.as_ptr(),
            pubkey_json.len(),
            &mut result_ptr,
            &mut result_len,
        );
        let body = if !result_ptr.is_null() && result_len > 0 {
            let s = std::slice::from_raw_parts(result_ptr, result_len);
            let owned = String::from_utf8_lossy(s).into_owned();
            libc::free(result_ptr as *mut libc::c_void);
            Some(owned)
        } else {
            None
        };
        (status, body)
    }

    #[test]
    fn null_inputs_return_invalid_argument() {
        unsafe {
            let mut result_ptr: *mut u8 = std::ptr::null_mut();
            let mut result_len: usize = 0;
            let status = ciris_verify_skill_import_manifest_verify(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                &mut result_ptr,
                &mut result_len,
            );
            assert_eq!(status, CirisVerifyError::InvalidArgument as i32);
        }
    }

    #[test]
    fn malformed_pubkey_json_returns_typed_error_envelope() {
        let manifest_bytes = serde_json::to_vec(&minimal_manifest()).unwrap();
        let bad_pubkey = b"{not valid json";
        unsafe {
            let (status, body) = invoke(&manifest_bytes, bad_pubkey);
            // Soft failure: success status, error envelope in body.
            assert_eq!(status, CirisVerifyError::Success as i32);
            let body = body.expect("error envelope emitted");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"]["code"], "INVALID_PUBKEY_JSON");
        }
    }

    #[test]
    fn wrong_length_ed25519_pubkey_returns_invalid_shape_envelope() {
        let manifest_bytes = serde_json::to_vec(&minimal_manifest()).unwrap();
        // ed25519 must be exactly 32 bytes.
        let pubkey = serde_json::json!({
            "ed25519": vec![0u8; 16],
            "ml_dsa_65": Vec::<u8>::new(),
        })
        .to_string();
        unsafe {
            let (status, body) = invoke(&manifest_bytes, pubkey.as_bytes());
            assert_eq!(status, CirisVerifyError::Success as i32);
            let body = body.expect("error envelope emitted");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"]["code"], "INVALID_PUBKEY_SHAPE");
            assert!(v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("expected 32"));
        }
    }

    #[test]
    fn bad_signature_returns_signature_verification_failed_envelope() {
        // Construct a well-shaped pubkey (zeros) and a manifest whose
        // signature won't verify — verify_skill_import_manifest will
        // reject it, and we surface a SIGNATURE_VERIFICATION_FAILED
        // envelope.
        let manifest_bytes = serde_json::to_vec(&minimal_manifest()).unwrap();
        let pubkey = serde_json::json!({
            "ed25519": vec![0u8; 32],
            "ml_dsa_65": Vec::<u8>::new(),
        })
        .to_string();
        unsafe {
            let (status, body) = invoke(&manifest_bytes, pubkey.as_bytes());
            assert_eq!(status, CirisVerifyError::Success as i32);
            let body = body.expect("error envelope emitted");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"]["code"], "SIGNATURE_VERIFICATION_FAILED");
        }
    }
}
