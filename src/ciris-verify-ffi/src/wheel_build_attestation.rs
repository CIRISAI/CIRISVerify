//! Presenter path for a running build (CIRISVerify#315), for the Python
//! wheel and other FFI callers.
//!
//! An occurrence presents that it runs a build as an
//! `attestation:self_verify` / `attestation:agent_integrity` claim citing the
//! pipeline's manifest Contribution (CC 3.1.2.1). These three calls are that
//! path:
//!
//! - [`ciris_verify_build_attestation_bundle_envelope`]: the presenter's
//!   unsigned bundle envelope and its JCS signing bytes, for a presenter whose
//!   key signs outside verify.
//! - [`ciris_verify_build_attestation_bundle_assemble`]: attach the evidence to
//!   the presenter-signed envelope.
//! - [`ciris_verify_build_attestation_bundle_verify`]: verify a bundle and
//!   return the verdict with the verified manifest hash.
//!
//! Wire discipline matches [`crate::wheel_manifest_contribution`]: UTF-8 JSON
//! in, UTF-8 JSON out (NUL-free, not NUL-terminated). A rejection is a
//! successful call returning `{"verified": false, "reason": ...}`; only
//! malformed input returns `SerializationError`.
//!
//! **Standing.** A bundle's pipeline standing is the caller's own directory
//! answer (`pipeline_member` + `blessing`, as in
//! `ciris_verify_build_manifest_contribution`).

use std::panic::{catch_unwind, AssertUnwindSafe};

use base64::Engine as _;
use ciris_verify_core::build_attestation_bundle::{
    assemble_build_attestation_bundle, build_attestation_bundle_envelope,
    verify_build_attestation_bundle, BundleInputs, PresentedBuild, TransparencyCheck,
};
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::self_at_login::SignedEnvelope;
use ciris_verify_core::threshold::ThresholdMember;
use ciris_verify_core::transparency::MerkleProof;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::wheel_manifest_contribution::{BlessingIn, Facts};
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

unsafe fn emit_json<T: Serialize>(
    value: &T,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    match serde_json::to_vec(value) {
        Ok(bytes) => emit_bytes(&bytes, result_out, result_len_out),
        Err(_) => CirisVerifyError::SerializationError as i32,
    }
}

/// Read the request, or the error code to return.
unsafe fn read_request<T: for<'de> Deserialize<'de>>(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> Result<T, i32> {
    if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
        return Err(CirisVerifyError::InvalidArgument as i32);
    }
    let input = std::slice::from_raw_parts(input_json, input_len);
    serde_json::from_slice(input).map_err(|_| CirisVerifyError::SerializationError as i32)
}

fn presents_from(d: &str) -> Option<PresentedBuild> {
    PresentedBuild::from_dimension(d)
}

const fn transparency_str(t: TransparencyCheck) -> &'static str {
    match t {
        TransparencyCheck::Absent => "absent",
        TransparencyCheck::Verified => "verified",
        TransparencyCheck::Invalid => "invalid",
    }
}

// --------------------------------------------------------------------------
// ciris_verify_build_attestation_bundle_envelope / _assemble
// --------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeRequest {
    /// `attestation:self_verify` or `attestation:agent_integrity`.
    presents: String,
    /// The presenter's federation key_id.
    presenter_key_id: String,
    /// The pipeline's `build_manifest_contribution` outbox object.
    manifest_contribution: SignedCegObject,
    /// Optional RFC 6962 inclusion proof for the manifest.
    #[serde(default)]
    inclusion_proof: Option<MerkleProof>,
    /// RFC 3339; defaults to now.
    #[serde(default)]
    asserted_at: Option<String>,
}

#[derive(Serialize)]
struct EnvelopeOut {
    /// The unsigned envelope.
    envelope: Value,
    /// `JCS(envelope)`, base64: the bytes to bound-hybrid sign.
    signing_bytes_base64: String,
}

/// Build the presenter's unsigned bundle envelope.
///
/// `input_json`: `{"presents": "attestation:self_verify" |
/// "attestation:agent_integrity", "presenter_key_id": "...",
/// "manifest_contribution": {...}, "inclusion_proof"?: {...},
/// "asserted_at"?: "RFC 3339"}`.
///
/// Result: `{"envelope": {...}, "signing_bytes_base64": "..."}`. Sign the
/// bytes bound-hybrid (Ed25519, then ML-DSA-65 over `bytes || ed25519_sig`) and
/// pass `{signed_envelope: envelope, ed25519_signature_base64,
/// mldsa65_signature_base64}` to `ciris_verify_build_attestation_bundle_assemble`.
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_build_attestation_bundle_envelope(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_build_attestation_bundle_envelope", {
        let req: EnvelopeRequest =
            match read_request(input_json, input_len, result_out, result_len_out) {
                Ok(r) => r,
                Err(code) => return code,
            };
        let Some(presents) = presents_from(&req.presents) else {
            return CirisVerifyError::SerializationError as i32;
        };
        let asserted_at = match req.asserted_at.as_deref() {
            None => chrono::Utc::now(),
            Some(t) => match chrono::DateTime::parse_from_rfc3339(t) {
                Ok(t) => t.with_timezone(&chrono::Utc),
                Err(_) => return CirisVerifyError::SerializationError as i32,
            },
        };
        let inputs = BundleInputs {
            presents,
            manifest_contribution: &req.manifest_contribution,
            inclusion: req.inclusion_proof.as_ref(),
        };
        let Ok(envelope) =
            build_attestation_bundle_envelope(&req.presenter_key_id, &inputs, asserted_at)
        else {
            return CirisVerifyError::SerializationError as i32;
        };
        let Ok(bytes) = ciris_verify_core::jcs::canonicalize(&envelope) else {
            return CirisVerifyError::SerializationError as i32;
        };
        let out = EnvelopeOut {
            envelope,
            signing_bytes_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        emit_json(&out, result_out, result_len_out)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssembleRequest {
    /// The presenter-signed envelope.
    signed: SignedEnvelope,
    /// The same Contribution the envelope was built over.
    manifest_contribution: SignedCegObject,
    /// The same inclusion proof, if one was used.
    #[serde(default)]
    inclusion_proof: Option<MerkleProof>,
}

/// Attach the evidence to a presenter-signed bundle envelope.
///
/// `input_json`: `{"signed": {"signed_envelope", "ed25519_signature_base64",
/// "mldsa65_signature_base64"}, "manifest_contribution": {...},
/// "inclusion_proof"?: {...}}`. Result: the `build_attestation_bundle` object.
/// Nothing is verified here; `ciris_verify_build_attestation_bundle_verify` is
/// the check.
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_build_attestation_bundle_assemble(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_build_attestation_bundle_assemble", {
        let req: AssembleRequest =
            match read_request(input_json, input_len, result_out, result_len_out) {
                Ok(r) => r,
                Err(code) => return code,
            };
        let Some(presents) = req
            .signed
            .signed_envelope
            .get("dimension")
            .and_then(Value::as_str)
            .and_then(presents_from)
        else {
            return CirisVerifyError::SerializationError as i32;
        };
        let inputs = BundleInputs {
            presents,
            manifest_contribution: &req.manifest_contribution,
            inclusion: req.inclusion_proof.as_ref(),
        };
        match assemble_build_attestation_bundle(&req.signed, &inputs) {
            Ok(bundle) => emit_json(&bundle, result_out, result_len_out),
            Err(_) => CirisVerifyError::SerializationError as i32,
        }
    })
}

// --------------------------------------------------------------------------
// ciris_verify_build_attestation_bundle_verify
// --------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleVerifyRequest {
    bundle: SignedCegObject,
    /// The presenter's pinned pubkeys, from the caller's directory.
    presenter_member: ThresholdMember,
    /// The pipeline's pinned pubkeys, from the caller's directory.
    pipeline_member: ThresholdMember,
    /// The caller's authority's answer for the pipeline's standing.
    blessing: BlessingIn,
    /// Attester name for `attestation_entries`; defaults to `ciris-verify`.
    #[serde(default)]
    attester: Option<String>,
}

#[derive(Serialize)]
struct BundleVerdictOut {
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    presenter_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presents: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transparency: Option<&'static str>,
    /// The verified build: `manifest_hash`, `attestation_id`, ….
    #[serde(skip_serializing_if = "Option::is_none")]
    build: Option<Facts>,
    /// The ladder entries the verdict scores (they cite the build).
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_entries: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl BundleVerdictOut {
    fn rejected(reason: impl Into<String>) -> Self {
        Self {
            verified: false,
            presenter_key_id: None,
            presents: None,
            transparency: None,
            build: None,
            attestation_entries: None,
            reason: Some(reason.into()),
        }
    }
}

/// Verify a build-attestation bundle and return the verdict with the verified
/// manifest hash.
///
/// `input_json`: `{"bundle": {...}, "presenter_member": {...},
/// "pipeline_member": {...}, "blessing": {...}}` and optionally `"attester"`.
///
/// Result: `{"verified": true, "presenter_key_id", "presents",
/// "transparency": "absent"|"verified"|"invalid", "build": {"manifest_hash",
/// "attestation_id", ...}, "attestation_entries": [...]}` or `{"verified":
/// false, "reason"}`.
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_build_attestation_bundle_verify(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_build_attestation_bundle_verify", {
        let req: BundleVerifyRequest =
            match read_request(input_json, input_len, result_out, result_len_out) {
                Ok(r) => r,
                Err(code) => return code,
            };
        let Some(blessing) = req.blessing.into_blessing() else {
            return CirisVerifyError::SerializationError as i32;
        };
        let out = match verify_build_attestation_bundle(
            &req.bundle,
            &req.presenter_member,
            &req.pipeline_member,
            &blessing,
        ) {
            Err(e) => BundleVerdictOut::rejected(e.to_string()),
            Ok(v) => {
                let attester = req.attester.as_deref().unwrap_or("ciris-verify");
                let entries = serde_json::to_value(v.to_attestation_entries(attester)).ok();
                BundleVerdictOut {
                    verified: true,
                    presenter_key_id: Some(v.presenter_key_id.clone()),
                    presents: Some(v.presents.dimension()),
                    transparency: Some(transparency_str(v.transparency)),
                    build: Some(v.build.into()),
                    attestation_entries: entries,
                    reason: None,
                }
            },
        };
        emit_json(&out, result_out, result_len_out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::manifest_contribution::{
        sign_build_manifest_contribution, BuildAttestation,
    };
    use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner};

    unsafe fn call(
        f: unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32,
        req: &Value,
    ) -> (i32, Value) {
        let body = serde_json::to_vec(req).unwrap();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut len = 0usize;
        let rc = f(body.as_ptr(), body.len(), &mut out, &mut len);
        if rc != 0 {
            return (rc, Value::Null);
        }
        let bytes = std::slice::from_raw_parts(out, len).to_vec();
        if len > 0 {
            libc::free(out.cast());
        }
        (rc, serde_json::from_slice(&bytes).unwrap())
    }

    async fn manifest(pipeline: &HybridSigningIdentity) -> SignedCegObject {
        sign_build_manifest_contribution(
            pipeline,
            &BuildAttestation {
                target: "python-source-tree",
                binary_hash: &"ab".repeat(32),
                build_id: "agent@2.9.0",
                binary_version: "2.9.0",
                manifest_hash: &"cd".repeat(32),
                manifest_size: 10,
            },
            chrono::Utc::now(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn presenter_round_trip_names_the_build() {
        let presenter = HybridSigningIdentity::generate("agent-occurrence").unwrap();
        let pipeline = HybridSigningIdentity::generate("ci-pipeline").unwrap();
        let contribution = manifest(&pipeline).await;
        let row_id = contribution.body["signed_envelope"]["row"]["attestation_id"].clone();

        let (rc, env) = unsafe {
            call(
                ciris_verify_build_attestation_bundle_envelope,
                &serde_json::json!({
                    "presents": "attestation:agent_integrity",
                    "presenter_key_id": "agent-occurrence",
                    "manifest_contribution": contribution,
                }),
            )
        };
        assert_eq!(rc, 0);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(env["signing_bytes_base64"].as_str().unwrap())
            .unwrap();
        // The agent signs with its own key, outside verify.
        let (ed, mldsa) = presenter.sign_bound(&bytes).await.unwrap();

        let (rc, bundle) = unsafe {
            call(
                ciris_verify_build_attestation_bundle_assemble,
                &serde_json::json!({
                    "signed": {
                        "signed_envelope": env["envelope"],
                        "ed25519_signature_base64": ed,
                        "mldsa65_signature_base64": mldsa,
                    },
                    "manifest_contribution": contribution,
                }),
            )
        };
        assert_eq!(rc, 0);

        let (rc, verdict) = unsafe {
            call(
                ciris_verify_build_attestation_bundle_verify,
                &serde_json::json!({
                    "bundle": bundle,
                    "presenter_member": presenter.directory_member().unwrap(),
                    "pipeline_member": pipeline.directory_member().unwrap(),
                    "blessing": {"pipeline_key_id": "ci-pipeline", "standing": "accord_role"},
                }),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(verdict["verified"], true, "{verdict}");
        assert_eq!(verdict["presents"], "attestation:agent_integrity");
        assert_eq!(verdict["build"]["manifest_hash"], "cd".repeat(32));
        assert_eq!(verdict["build"]["attestation_id"], row_id);
        let entry = &verdict["attestation_entries"][0];
        assert_eq!(entry["evidence_refs"][0], "cd".repeat(32));
        assert_eq!(entry["references_attestation_id"], row_id);

        // Another presenter's pinned key refuses the same bundle.
        let other = HybridSigningIdentity::generate("agent-occurrence").unwrap();
        let (_, verdict) = unsafe {
            call(
                ciris_verify_build_attestation_bundle_verify,
                &serde_json::json!({
                    "bundle": bundle,
                    "presenter_member": other.directory_member().unwrap(),
                    "pipeline_member": pipeline.directory_member().unwrap(),
                    "blessing": {"pipeline_key_id": "ci-pipeline", "standing": "accord_role"},
                }),
            )
        };
        assert_eq!(verdict["verified"], false);
    }

    #[tokio::test]
    async fn a_bundle_without_directory_standing_is_malformed() {
        let presenter = HybridSigningIdentity::generate("agent-occurrence").unwrap();
        let pipeline = HybridSigningIdentity::generate("ci-pipeline").unwrap();
        let contribution = manifest(&pipeline).await;
        let bundle = ciris_verify_core::build_attestation_bundle::produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                presents: PresentedBuild::SelfVerify,
                manifest_contribution: &contribution,
                inclusion: None,
            },
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        // No pipeline_member / blessing: no standing to judge, so malformed.
        let (rc, _) = unsafe {
            call(
                ciris_verify_build_attestation_bundle_verify,
                &serde_json::json!({
                    "bundle": bundle,
                    "presenter_member": presenter.directory_member().unwrap(),
                }),
            )
        };
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
        // A standing the blessing vocabulary does not name is malformed too.
        let (rc, _) = unsafe {
            call(
                ciris_verify_build_attestation_bundle_verify,
                &serde_json::json!({
                    "bundle": bundle,
                    "presenter_member": presenter.directory_member().unwrap(),
                    "pipeline_member": pipeline.directory_member().unwrap(),
                    "blessing": {"pipeline_key_id": "ci-pipeline", "standing": "ceremony"},
                }),
            )
        };
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
    }
}
