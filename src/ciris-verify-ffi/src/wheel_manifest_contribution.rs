//! Build-manifest Contribution verification FFI surface for the Python wheel
//! (CIRISVerify#25, v6.2.0+).
//!
//! Wraps [`ciris_verify_core::manifest_contribution::verify_build_manifest_contribution`]
//! — the **consumer** of the pipeline-as-delegated-attester model — so a wheel
//! consumer (CIRISServer's outbox drain, registry tooling) runs the *exact same*
//! authority walk the Rust verifier runs: pipeline signature → human's
//! delegation grant → §1.3 scope split → trusted-build-authority decision. No
//! reimplemented chain walk, no bespoke `/v1/builds` trust path.
//!
//! ## Wire shape
//!
//! Takes the UTF-8 bytes of a JSON request object and returns the UTF-8 bytes of
//! a JSON verdict (NUL-free, NOT NUL-terminated; the caller has the length). A
//! *rejection* is a successful call returning `{ "trusted": false, "reason":
//! "..." }` — only malformed input yields a `SerializationError` code. This
//! keeps the fail-closed contract: the caller reads the verdict, and the absence
//! of `trusted: true` is rejection.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::manifest_contribution::verify_build_manifest_contribution;
use ciris_verify_core::self_at_login::SignedEnvelope;
use ciris_verify_core::threshold::ThresholdMember;
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
/// `ciris_verify_free`). Mirrors `wheel_operational_admit::emit_bytes`.
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
struct ManifestRequest {
    /// The `build_manifest_contribution` object as drained from the outbox.
    object: SignedCegObject,
    /// Pinned pubkeys of the pipeline `node` (resolved by the caller from its
    /// key directory by `attesting_key_id` — never taken from the object).
    pipeline_member: ThresholdMember,
    /// The `delegates_to(human → pipeline, infra:attest)` grant.
    grant: SignedEnvelope,
    /// Pinned pubkeys of the human granter (resolved by the caller by the
    /// grant's `attesting_key_id`).
    granter_member: ThresholdMember,
    /// The trio's "builders I trust" set. Empty → verify the chain *without* the
    /// trust decision (surfaces who it roots in).
    #[serde(default)]
    trusted_build_authorities: Vec<String>,
}

#[derive(Serialize)]
struct ManifestVerdict {
    /// Whether the full chain verified *and* rooted in a trusted human.
    trusted: bool,
    /// The pipeline key_id that signed (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    attested_by: Option<String>,
    /// The accountable human the chain roots in (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    on_behalf_of: Option<String>,
    /// Rust target triple (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    /// The build identifier (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    build_id: Option<String>,
    /// SHA-256 of the built binary, hex (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_hash: Option<String>,
    /// The binary's version string (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_version: Option<String>,
    /// SHA-256 of the canonical file manifest, hex (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_hash: Option<String>,
    /// The first failing step (present on rejection).
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Verify a build-manifest Contribution end-to-end (CIRISVerify#25).
///
/// `input_json` is a JSON object:
/// ```json
/// {
///   "object": { ...the build_manifest_contribution SignedCegObject... },
///   "pipeline_member": { "member_id": "...", "ed25519_public_key_base64": "...",
///                        "mldsa65_public_key_base64": "..." },
///   "grant": { "signed_envelope": {...}, "ed25519_signature_base64": "...",
///              "mldsa65_signature_base64": "..." },
///   "granter_member": { "member_id": "...", "ed25519_public_key_base64": "...",
///                       "mldsa65_public_key_base64": "..." },
///   "trusted_build_authorities": ["human-key-id", ...]
/// }
/// ```
/// On success `result_out` receives the verified build facts
/// (`{ "trusted": true, "attested_by": ..., "on_behalf_of": ..., "target": ...,
/// "build_id": ..., "binary_hash": ..., "binary_version": ...,
/// "manifest_hash": ... }`); on rejection `{ "trusted": false, "reason": "..." }`.
/// Returns `Success` (0), `InvalidArgument` on a null pointer, or
/// `SerializationError` on malformed input.
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_build_manifest_contribution(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_build_manifest_contribution", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: ManifestRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        let verdict = match verify_build_manifest_contribution(
            &req.object,
            &req.pipeline_member,
            &req.grant,
            &req.granter_member,
            &req.trusted_build_authorities,
        ) {
            Ok(v) => ManifestVerdict {
                trusted: true,
                attested_by: Some(v.attested_by),
                on_behalf_of: Some(v.on_behalf_of),
                target: Some(v.target),
                build_id: Some(v.build_id),
                binary_hash: Some(v.binary_hash),
                binary_version: Some(v.binary_version),
                manifest_hash: Some(v.manifest_hash),
                reason: None,
            },
            Err(e) => ManifestVerdict {
                trusted: false,
                attested_by: None,
                on_behalf_of: None,
                target: None,
                build_id: None,
                binary_hash: None,
                binary_version: None,
                manifest_hash: None,
                reason: Some(e.to_string()),
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
    use ciris_verify_core::manifest_contribution::{
        sign_build_manifest_contribution, BuildAttestation,
    };
    use ciris_verify_core::self_at_login::{sign_delegation_grant, HybridSigningIdentity};
    use serde_json::json;

    const HUMAN: &str = "eric-moore-6qg6wdx2dq";
    const PIPELINE: &str = "ciris-verify-build-pipeline";
    const TS: &str = "2026-06-18T00:00:00Z";

    async fn valid_request() -> serde_json::Value {
        let human = HybridSigningIdentity::generate(HUMAN).unwrap();
        let pipeline = HybridSigningIdentity::generate(PIPELINE).unwrap();
        let grant =
            sign_delegation_grant(&human, PIPELINE, &["infra:attest".to_string()], TS).unwrap();
        let bh = "ab".repeat(32);
        let mh = "cd".repeat(32);
        let b = BuildAttestation {
            target: "x86_64-unknown-linux-gnu",
            binary_hash: &bh,
            build_id: "ciris-verify@6.2.0",
            binary_version: "6.2.0",
            manifest_hash: &mh,
        };
        let obj = sign_build_manifest_contribution(
            &pipeline,
            &b,
            HUMAN,
            "delegation:infra-attest:abc123",
            TS,
        )
        .await
        .unwrap();
        json!({
            "object": obj,
            "pipeline_member": pipeline.directory_member().unwrap(),
            "grant": grant,
            "granter_member": human.directory_member().unwrap(),
            "trusted_build_authorities": [HUMAN],
        })
    }

    unsafe fn call(req: &serde_json::Value) -> Result<serde_json::Value, i32> {
        let body = serde_json::to_vec(req).unwrap();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_build_manifest_contribution(
            body.as_ptr(),
            body.len(),
            &mut out,
            &mut out_len,
        );
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        if out_len != 0 {
            libc::free(out as *mut libc::c_void);
        }
        Ok(serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn valid_chain_trusted_via_ffi() {
        let req = valid_request().await;
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["trusted"], json!(true));
        assert_eq!(v["on_behalf_of"], json!(HUMAN));
        assert_eq!(v["attested_by"], json!(PIPELINE));
        assert_eq!(v["binary_version"], json!("6.2.0"));
    }

    #[tokio::test]
    async fn untrusted_human_rejected_via_ffi() {
        let mut req = valid_request().await;
        req["trusted_build_authorities"] = json!(["someone-else"]);
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["trusted"], json!(false));
        assert!(v["reason"].as_str().unwrap().contains("not trusted"));
    }

    #[tokio::test]
    async fn tampered_object_rejected_via_ffi() {
        let mut req = valid_request().await;
        req["object"]["body"]["signed_envelope"]["build"]["binary_hash"] = json!("00".repeat(32));
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["trusted"], json!(false));
    }

    #[test]
    fn malformed_input_is_serialization_error() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let bad = b"{not json";
        let rc = unsafe {
            ciris_verify_build_manifest_contribution(
                bad.as_ptr(),
                bad.len(),
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
    }
}
