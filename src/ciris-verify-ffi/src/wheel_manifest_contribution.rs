//! Build-manifest Contribution verification FFI surface for the Python wheel
//! (CIRISVerify#25; reshaped 19.0.0 for FSD-006 / CIRISVerify#299).
//!
//! Wraps [`ciris_verify_core::manifest_contribution::verify_build_manifest_contribution`]:
//! the pipeline's signature, persist's signed `row` mirror, the `:v1` dimension,
//! scope, `asserted_at` and `evidence_refs` — everything a Contribution can prove
//! about itself.
//!
//! **Standing is not checked here, and cannot be.** Whether the pipeline holds
//! `infra:attest` from a root the caller trusts is persist's capability walk
//! over the caller's directory. The caller passes the walk's answer as
//! `blessing`, and this surface checks that it names the pipeline that signed.
//! The verdict says `verified`, not `trusted`, for that reason.
//!
//! ## Wire shape
//!
//! Takes the UTF-8 bytes of a JSON request object and returns the UTF-8 bytes of
//! a JSON verdict (NUL-free, NOT NUL-terminated; the caller has the length). A
//! *rejection* is a successful call returning `{ "verified": false, "reason":
//! "..." }` — only malformed input yields a `SerializationError` code. The
//! absence of `verified: true` is rejection.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::manifest_contribution::{
    verify_build_manifest_contribution, PipelineBlessing, PipelineStanding, VerifiedManifest,
    WalkPlane,
};
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
#[serde(deny_unknown_fields)]
struct BlessingIn {
    pipeline_key_id: String,
    /// `delegation` | `family_quorum` (persist's capability walk) |
    /// `accord_role` (persist's `is_infra_attest_effective`).
    standing: String,
    /// Required for `delegation` / `family_quorum`; refused for `accord_role`.
    #[serde(default)]
    root_key_id: Option<String>,
    /// Required for `delegation` / `family_quorum`; refused for `accord_role`.
    #[serde(default)]
    grant_attestation_id: Option<String>,
}

impl BlessingIn {
    /// Fail-closed: an unknown standing, or a grant field present where it
    /// cannot apply (or absent where it must), is a malformed request rather
    /// than a guessed blessing.
    fn into_blessing(self) -> Option<PipelineBlessing> {
        let plane = match self.standing.as_str() {
            "delegation" => Some(WalkPlane::Delegation),
            "family_quorum" => Some(WalkPlane::FamilyQuorum),
            "accord_role" => None,
            _ => return None,
        };
        match (plane, self.root_key_id, self.grant_attestation_id) {
            (Some(plane), Some(root), Some(grant)) => Some(PipelineBlessing::conferred(
                self.pipeline_key_id,
                root,
                grant,
                plane,
            )),
            (None, None, None) => Some(PipelineBlessing::accord_role(self.pipeline_key_id)),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct ManifestRequest {
    /// The `build_manifest_contribution` object.
    object: SignedCegObject,
    /// Pinned pubkeys of the pipeline `node`, resolved by the caller from its
    /// key directory — never taken from the object.
    pipeline_member: ThresholdMember,
    /// The caller's capability walk's answer for the pipeline (persist's
    /// `TrustedGrant`): `{pipeline_key_id, root_key_id, grant_attestation_id}`.
    blessing: BlessingIn,
}

/// The verified facts — every member of [`VerifiedManifest`], by name.
#[derive(Serialize)]
struct Facts {
    attested_by: String,
    standing: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    conferred_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_attestation_id: Option<String>,
    attestation_id: String,
    asserted_at: String,
    target: String,
    build_id: String,
    binary_hash: String,
    binary_version: String,
    manifest_hash: String,
    manifest_size: u64,
    evidence_refs: Vec<String>,
}

impl From<VerifiedManifest> for Facts {
    fn from(v: VerifiedManifest) -> Self {
        // Exhaustive destructure: a field added to VerifiedManifest fails to
        // compile here instead of silently never reaching the wheel (the
        // v14.1.0 hand-serialized-response gap class).
        let VerifiedManifest {
            attested_by,
            standing,
            attestation_id,
            asserted_at,
            target,
            build_id,
            binary_hash,
            binary_version,
            manifest_hash,
            manifest_size,
            evidence_refs,
        } = v;
        let (conferred_by, grant_attestation_id) = match &standing {
            PipelineStanding::Conferred {
                root_key_id,
                grant_attestation_id,
                ..
            } => (
                Some(root_key_id.clone()),
                Some(grant_attestation_id.clone()),
            ),
            PipelineStanding::AccordRole => (None, None),
        };
        Self {
            attested_by,
            standing: standing.plane_str(),
            conferred_by,
            grant_attestation_id,
            attestation_id,
            asserted_at,
            target,
            build_id,
            binary_hash,
            binary_version,
            manifest_hash,
            manifest_size,
            evidence_refs,
        }
    }
}

#[derive(Serialize)]
struct ManifestVerdict {
    /// The Contribution verified and the blessing names its pipeline.
    verified: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    facts: Option<Facts>,
    /// The first failing step (present on rejection).
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Verify a build-manifest Contribution (FSD-006).
///
/// `input_json` is a JSON object:
/// ```json
/// {
///   "object": { ...the build_manifest_contribution SignedCegObject... },
///   "pipeline_member": { "member_id": "...", "ed25519_public_key_base64": "...",
///                        "mldsa65_public_key_base64": "..." },
///   "blessing": { "pipeline_key_id": "...",
///                 "standing": "delegation" | "family_quorum" | "accord_role",
///                 "root_key_id": "...",            // walk standings only
///                 "grant_attestation_id": "..." }  // walk standings only
/// }
/// ```
/// On success `result_out` receives `{ "verified": true, "attested_by": ...,
/// "standing": ..., "conferred_by"?: ..., "grant_attestation_id"?: ..., "attestation_id": ...,
/// "asserted_at": ..., "target": ..., "build_id": ..., "binary_hash": ...,
/// "binary_version": ..., "manifest_hash": ..., "manifest_size": ...,
/// "evidence_refs": [...] }`; on
/// rejection `{ "verified": false, "reason": "..." }`.
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
        let Some(blessing) = req.blessing.into_blessing() else {
            return CirisVerifyError::SerializationError as i32;
        };
        let verdict = match verify_build_manifest_contribution(
            &req.object,
            &req.pipeline_member,
            &blessing,
        ) {
            Ok(v) => ManifestVerdict {
                verified: true,
                facts: Some(v.into()),
                reason: None,
            },
            Err(e) => ManifestVerdict {
                verified: false,
                facts: None,
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
    use ciris_verify_core::self_at_login::HybridSigningIdentity;
    use serde_json::json;

    const PIPELINE: &str = "ciris-verify-build-pipeline";

    async fn valid_request() -> serde_json::Value {
        let pipeline = HybridSigningIdentity::generate(PIPELINE).unwrap();
        let bh = "ab".repeat(32);
        let mh = "cd".repeat(32);
        let obj = sign_build_manifest_contribution(
            &pipeline,
            &BuildAttestation {
                target: "x86_64-unknown-linux-gnu",
                binary_hash: &bh,
                build_id: "ciris-verify@19.0.0",
                binary_version: "19.0.0",
                manifest_hash: &mh,
                manifest_size: 4096,
            },
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        json!({
            "object": obj,
            "pipeline_member": pipeline.directory_member().unwrap(),
            "blessing": {
                "pipeline_key_id": PIPELINE,
                "standing": "delegation",
                "root_key_id": "humanity-accord",
                "grant_attestation_id": "grant-1",
            },
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
    async fn valid_contribution_verifies_via_ffi() {
        let req = valid_request().await;
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["verified"], json!(true));
        assert_eq!(v["attested_by"], json!(PIPELINE));
        assert_eq!(v["conferred_by"], json!("humanity-accord"));
        assert_eq!(v["grant_attestation_id"], json!("grant-1"));
        assert_eq!(v["standing"], json!("delegation"));
        assert_eq!(v["binary_version"], json!("19.0.0"));
        assert_eq!(v["evidence_refs"], json!(["cd".repeat(32)]));
        assert_eq!(v["manifest_size"], json!(4096));
        assert!(v["attestation_id"].as_str().is_some_and(|s| s.len() == 36));
        assert!(
            v.get("trusted").is_none(),
            "the old key is gone, not aliased"
        );
    }

    #[tokio::test]
    async fn blessing_for_another_pipeline_rejected_via_ffi() {
        let mut req = valid_request().await;
        req["blessing"]["pipeline_key_id"] = json!("someone-else");
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["verified"], json!(false));
        assert!(v["reason"].as_str().unwrap().contains("blessing"));
        assert!(v.get("attested_by").is_none());
    }

    #[tokio::test]
    async fn tampered_object_rejected_via_ffi() {
        let mut req = valid_request().await;
        req["object"]["body"]["signed_envelope"]["build"]["binary_hash"] = json!("00".repeat(32));
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["verified"], json!(false));
    }

    /// Production's path: the accord ci-key ceremony's role, no grant.
    #[tokio::test]
    async fn accord_role_standing_verifies_via_ffi() {
        let mut req = valid_request().await;
        req["blessing"] = json!({"pipeline_key_id": PIPELINE, "standing": "accord_role"});
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["verified"], json!(true));
        assert_eq!(v["standing"], json!("accord_role"));
        assert!(v.get("conferred_by").is_none());
        assert!(v.get("grant_attestation_id").is_none());
    }

    /// Every incoherent blessing is a malformed request, never a guess.
    #[tokio::test]
    async fn incoherent_blessings_are_serialization_errors() {
        for blessing in [
            json!({"pipeline_key_id": PIPELINE, "standing": "Delegation",
                   "root_key_id": "r", "grant_attestation_id": "g"}),
            json!({"pipeline_key_id": PIPELINE, "standing": "accord_co_scrub"}),
            json!({"pipeline_key_id": PIPELINE, "standing": "delegation"}),
            json!({"pipeline_key_id": PIPELINE, "standing": "accord_role",
                   "root_key_id": "humanity-accord"}),
            json!({"pipeline_key_id": PIPELINE, "standing": "accord_role", "extra": 1}),
        ] {
            let mut req = valid_request().await;
            req["blessing"] = blessing.clone();
            assert_eq!(
                unsafe { call(&req) }.unwrap_err(),
                CirisVerifyError::SerializationError as i32,
                "{blessing}"
            );
        }
    }

    #[tokio::test]
    async fn missing_blessing_is_serialization_error() {
        let mut req = valid_request().await;
        req.as_object_mut().unwrap().remove("blessing");
        assert_eq!(
            unsafe { call(&req) }.unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
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
