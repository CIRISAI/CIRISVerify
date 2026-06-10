//! Operational-data admission FFI surface for the Python wheel
//! (CIRISVerify#65, v5.1.0+).
//!
//! Wraps [`ciris_verify_core::operational_admit`] — the CEG 1.0-RC2
//! §5.6.8.13 admit-verification surface — so a wheel consumer can run
//! the *exact same* admission checks the Rust verifiers run, rather than
//! reimplement the role-chain walk or the steward-quorum count (RC2
//! §5.6.8.13 forbids a third bespoke path). Two JSON-in/JSON-out
//! functions, mirroring the two §5.6.8.13 admission shapes:
//!
//! - `ciris_verify_resolve_role_authority` — the §8.1.12.7.1
//!   `delegates_to` role-chain resolver for `organization` /
//!   `org_membership`.
//! - `ciris_verify_partner_record_quorum` — the M-of-N steward quorum
//!   for `partner_record` (reuses CIRISVerify#31).
//!
//! ## Wire shape
//!
//! Both take the UTF-8 bytes of a JSON request object and return the
//! UTF-8 bytes of a JSON verdict object (NUL-free, NOT NUL-terminated;
//! the caller has the length). A *negative admission* (unauthorized /
//! quorum-not-met) is a successful call returning a verdict with
//! `authorized:false` / `admitted:false` — only malformed input yields a
//! `SerializationError` code. This keeps the fail-closed contract: the
//! caller reads the verdict, and the absence of a positive verdict is
//! rejection.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::operational_admit::{
    resolve_role_authority, verify_partner_record_quorum, MembershipGrant, OrgRole,
    RoleAuthorization,
};
use ciris_verify_core::threshold::{ThresholdMember, ThresholdSignature};
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

// ---- role-chain resolver ------------------------------------------

#[derive(Deserialize)]
struct ResolveRequest {
    actor_key_id: String,
    org_id: String,
    required_role: OrgRole,
    #[serde(default)]
    current_memberships: Vec<MembershipGrant>,
    #[serde(default)]
    key_directory: Vec<ThresholdMember>,
    #[serde(default)]
    root_stewards: Vec<String>,
}

/// Resolve `organization` / `org_membership` role-gated admission
/// (CEG 1.0-RC2 §5.6.8.13, the §8.1.12.7.1 resolver; CIRISVerify#65).
///
/// `input_json` is a JSON object:
/// ```json
/// {
///   "actor_key_id": "...",
///   "org_id": "...",
///   "required_role": "org_admin" | "key_manager" | "operator" | "viewer",
///   "current_memberships": [ { "signed_envelope": {...},
///                             "ed25519_signature_base64": "...",
///                             "mldsa65_signature_base64": "..." }, ... ],
///   "key_directory": [ { "member_id": "...",
///                        "ed25519_public_key_base64": "...",
///                        "mldsa65_public_key_base64": "..." }, ... ],
///   "root_stewards": [ "steward-key-id", ... ]
/// }
/// ```
/// On success `result_out` / `result_len_out` receive the JSON bytes of
/// a [`RoleAuthorization`] (`authorized`, `established_by`,
/// `root_anchored`, `reason`). Returns `Success` (0), `InvalidArgument`
/// on a null pointer, or `SerializationError` on malformed input.
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_resolve_role_authority(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_resolve_role_authority", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: ResolveRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        let verdict: RoleAuthorization = resolve_role_authority(
            &req.actor_key_id,
            &req.org_id,
            req.required_role,
            &req.current_memberships,
            &req.key_directory,
            &req.root_stewards,
        );
        match serde_json::to_vec(&verdict) {
            Ok(bytes) => emit_bytes(&bytes, result_out, result_len_out),
            Err(_) => CirisVerifyError::SerializationError as i32,
        }
    })
}

// ---- partner_record steward quorum --------------------------------

#[derive(Deserialize)]
struct QuorumRequest {
    partner_record: serde_json::Value,
    #[serde(default)]
    steward_roster: Vec<ThresholdMember>,
    #[serde(default)]
    signatures: Vec<ThresholdSignature>,
    threshold: usize,
}

#[derive(Serialize)]
struct QuorumVerdict {
    /// Whether the M-of-N steward quorum was met.
    admitted: bool,
    /// Number of distinct valid steward signatures counted.
    valid_count: usize,
    /// Diagnostic message when not admitted (`None` on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Verify the `partner_record` M-of-N steward quorum (CEG 1.0-RC2
/// §5.6.8.13 / §5.6.8.10; CIRISVerify#31 / #65).
///
/// `input_json` is a JSON object:
/// ```json
/// {
///   "partner_record": { ...the signed envelope... },
///   "steward_roster": [ { "member_id": "...",
///                        "ed25519_public_key_base64": "...",
///                        "mldsa65_public_key_base64": "...",
///                        "role": "founder" }, ... ],
///   "signatures": [ { "member_id": "...",
///                    "ed25519_signature_base64": "...",
///                    "mldsa65_signature_base64": "..." }, ... ],
///   "threshold": 2
/// }
/// ```
/// **Precondition:** set-semantics arrays in `partner_record`
/// (`capabilities_granted` etc.) MUST already be lexicographically
/// sorted (§0.9.2.1 rule 1) — JCS preserves array order. On success
/// `result_out` receives JSON `{ "admitted": bool, "valid_count": n }`.
/// Returns `Success` (0), `InvalidArgument` on a null pointer, or
/// `SerializationError` on malformed input.
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_partner_record_quorum(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_partner_record_quorum", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: QuorumRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        let verdict = match verify_partner_record_quorum(
            &req.partner_record,
            &req.steward_roster,
            &req.signatures,
            req.threshold,
        ) {
            Ok(count) => QuorumVerdict {
                admitted: true,
                valid_count: count,
                error: None,
            },
            Err(e) => QuorumVerdict {
                admitted: false,
                valid_count: 0,
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
    use base64::Engine;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
    use ciris_verify_core::jcs;
    use serde_json::json;

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    struct Id {
        key_id: String,
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }
    impl Id {
        fn new(id: &str) -> Self {
            Self {
                key_id: id.to_string(),
                ed: Ed25519Signer::random(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }
        fn member(&self, founder: bool) -> serde_json::Value {
            json!({
                "member_id": self.key_id,
                "ed25519_public_key_base64": b64().encode(self.ed.public_key().unwrap()),
                "mldsa65_public_key_base64": b64().encode(self.mldsa.public_key().unwrap()),
                "role": if founder { Some("founder") } else { None::<&str> },
            })
        }
        fn sign(&self, bytes: &[u8]) -> (String, String) {
            let ed_sig = self.ed.sign(bytes).unwrap();
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&ed_sig);
            (
                b64().encode(&ed_sig),
                b64().encode(self.mldsa.sign(&bound).unwrap()),
            )
        }
    }

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
    fn resolve_authorizes_direct_steward_grant() {
        let steward = Id::new("steward-1");
        let admin = Id::new("admin-1");
        let envelope = json!({
            "user_id": "admin-1", "org_id": "org-x",
            "role": "org_admin", "status": "active",
            "attesting_key_id": "steward-1",
        });
        let bytes = jcs::canonicalize(&envelope).unwrap();
        let (ed, mldsa) = steward.sign(&bytes);
        let req = json!({
            "actor_key_id": "admin-1",
            "org_id": "org-x",
            "required_role": "org_admin",
            "current_memberships": [
                { "signed_envelope": envelope,
                  "ed25519_signature_base64": ed,
                  "mldsa65_signature_base64": mldsa }
            ],
            "key_directory": [ steward.member(false), admin.member(false) ],
            "root_stewards": ["steward-1"],
        });
        let v = unsafe { call(ciris_verify_resolve_role_authority, &req) }.unwrap();
        assert_eq!(v["authorized"], json!(true));
        assert_eq!(v["established_by"], json!("steward-1"));
        assert_eq!(v["reason"], json!("authorized"));
    }

    #[test]
    fn resolve_denies_unknown_actor() {
        let req = json!({
            "actor_key_id": "nobody",
            "org_id": "org-x",
            "required_role": "viewer",
            "current_memberships": [],
            "key_directory": [],
            "root_stewards": ["steward-1"],
        });
        let v = unsafe { call(ciris_verify_resolve_role_authority, &req) }.unwrap();
        assert_eq!(v["authorized"], json!(false));
        assert_eq!(v["reason"], json!("no_qualifying_grant"));
    }

    #[test]
    fn quorum_admits_two_of_three() {
        let s1 = Id::new("s1");
        let s2 = Id::new("s2");
        let s3 = Id::new("s3");
        let pr = json!({
            "license_id": "lic-1",
            "capabilities_granted": ["billing.read", "billing.write"],
            "status": "active", "revision": 1,
        });
        let bytes = jcs::canonicalize(&pr).unwrap();
        let (e1, m1) = s1.sign(&bytes);
        let (e2, m2) = s2.sign(&bytes);
        let req = json!({
            "partner_record": pr,
            "steward_roster": [ s1.member(true), s2.member(true), s3.member(true) ],
            "signatures": [
                { "member_id": "s1", "ed25519_signature_base64": e1, "mldsa65_signature_base64": m1 },
                { "member_id": "s2", "ed25519_signature_base64": e2, "mldsa65_signature_base64": m2 },
            ],
            "threshold": 2,
        });
        let v = unsafe { call(ciris_verify_partner_record_quorum, &req) }.unwrap();
        assert_eq!(v["admitted"], json!(true));
        assert_eq!(v["valid_count"], json!(2));
    }

    #[test]
    fn quorum_rejects_insufficient() {
        let s1 = Id::new("s1");
        let s2 = Id::new("s2");
        let pr = json!({ "license_id": "lic-1", "status": "active", "revision": 1 });
        let bytes = jcs::canonicalize(&pr).unwrap();
        let (e1, m1) = s1.sign(&bytes);
        let req = json!({
            "partner_record": pr,
            "steward_roster": [ s1.member(true), s2.member(true) ],
            "signatures": [
                { "member_id": "s1", "ed25519_signature_base64": e1, "mldsa65_signature_base64": m1 },
            ],
            "threshold": 2,
        });
        let v = unsafe { call(ciris_verify_partner_record_quorum, &req) }.unwrap();
        assert_eq!(v["admitted"], json!(false));
        assert_eq!(v["valid_count"], json!(0));
        assert!(v["error"].is_string());
    }

    #[test]
    fn malformed_input_is_serialization_error() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let bad = b"{not json";
        let rc = unsafe {
            ciris_verify_resolve_role_authority(bad.as_ptr(), bad.len(), &mut out, &mut out_len)
        };
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
    }
}
