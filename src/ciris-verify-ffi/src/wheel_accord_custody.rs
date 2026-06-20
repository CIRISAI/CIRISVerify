//! Accord-holder custody-attestation FFI surface (CIRISVerify#91, the
//! CIRISServer#41 safe-mesh floor).
//!
//! Wraps [`ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation`]
//! so the CIRISServer admission gate — Rust or a wheel consumer — runs the
//! *exact* hardware-unforgeable custody check verify runs, rather than
//! reimplement the YubiKey PIV chain walk. A holder is admitted to the accord
//! kill-switch roster only when this returns a positive verdict: the bundle is
//! holder-signed, the 9c attestation chains to the **pinned Yubico root**, the
//! attested key is the holder's federation Ed25519 key, and the
//! FIPS + touch=always floor is met.
//!
//! ## Wire shape
//!
//! One JSON-in/JSON-out function. A *negative admission* (chain invalid, floor
//! not met, wrong attested key) is a **successful call** returning a verdict
//! with `admitted:false` + a `reason` — only malformed input yields a
//! `SerializationError` code. Fail-closed: the caller admits only on
//! `admitted:true`, and the absence of a positive verdict is rejection.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::accord_custody_attestation::{
    verify_accord_custody_attestation, CustodyVerdict,
};
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::threshold::ThresholdMember;
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
struct CustodyRequest {
    /// The signed `accord_holder_custody_attestation` CEG object.
    attestation_object: SignedCegObject,
    /// The holder's pinned pubkeys, resolved by the caller from its directory.
    holder_member: ThresholdMember,
    /// The pinned Yubico PIV attestation root, hex-encoded DER.
    yubico_root_der_hex: String,
}

/// The JSON verdict shape (a flat success/reason envelope around
/// [`CustodyVerdict`]).
#[derive(serde::Serialize)]
struct CustodyVerdictJson {
    /// Whether the holder met the full custody floor (admit only on `true`).
    admitted: bool,
    /// The §9.4 hardware class on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_class: Option<String>,
    /// The custody tier asserted by the bundle on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    custody_tier: Option<String>,
    /// YubiKey firmware `major.minor.patch` on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    firmware: Option<String>,
    /// YubiKey serial, when the attestation carried it.
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<u32>,
    /// FIPS-certified flag on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    fips_certified: Option<bool>,
    /// Touch-always flag on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    touch_always: Option<bool>,
    /// The first failing check when not admitted (`None` on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl From<CustodyVerdict> for CustodyVerdictJson {
    fn from(v: CustodyVerdict) -> Self {
        Self {
            admitted: true,
            hardware_class: Some(v.hardware_class),
            custody_tier: Some(v.custody_tier),
            firmware: Some(v.firmware),
            serial: v.serial,
            fips_certified: Some(v.fips_certified),
            touch_always: Some(v.touch_always),
            reason: None,
        }
    }
}

/// Verify an accord-holder custody attestation end-to-end (CIRISVerify#91). The
/// CIRISServer admission gate calls this and admits the holder to the accord
/// kill-switch roster only when the verdict is `admitted:true`.
///
/// `input_json` is a JSON object:
/// ```json
/// {
///   "attestation_object": { ...the signed accord_holder_custody_attestation... },
///   "holder_member": { "member_id": "...",
///                      "ed25519_public_key_base64": "...",
///                      "mldsa65_public_key_base64": "..." },
///   "yubico_root_der_hex": "3082..."
/// }
/// ```
/// On success `result_out` / `result_len_out` receive the JSON bytes of the
/// verdict (`admitted`, `hardware_class`, `custody_tier`, `firmware`, `serial`,
/// `fips_certified`, `touch_always`); on rejection
/// `{ "admitted": false, "reason": "..." }`. Returns `Success` (0),
/// `InvalidArgument` on a null pointer, or `SerializationError` on malformed
/// input (incl. a non-hex `yubico_root_der_hex`).
///
/// # Safety
/// `input_json` must point to `input_len` valid bytes; `result_out` and
/// `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_accord_custody_attestation(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_accord_custody_attestation", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: CustodyRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        let root_der = match hex::decode(&req.yubico_root_der_hex) {
            Ok(b) => b,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        let verdict = match verify_accord_custody_attestation(
            &req.attestation_object,
            &req.holder_member,
            &root_der,
        ) {
            Ok(v) => CustodyVerdictJson::from(v),
            Err(e) => CustodyVerdictJson {
                admitted: false,
                hardware_class: None,
                custody_tier: None,
                firmware: None,
                serial: None,
                fips_certified: None,
                touch_always: None,
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
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
    use ciris_verify_core::accord_custody_attestation::{
        produce_accord_custody_attestation, CUSTODY_TIER_PORTABLE_2FA,
    };
    use ciris_verify_core::self_at_login::HybridSigningIdentity;
    use rcgen::{
        CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, PKCS_ED25519,
    };
    use serde_json::json;

    const TOUCH_ALWAYS: u8 = 0x02;

    fn params(cn: &str) -> CertificateParams {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        p.distinguished_name = dn;
        p
    }

    /// rcgen mock chain 9c → f9 → root attesting `leaf_kp`; returns (9c, f9, root) DER.
    fn mock_chain(leaf_kp: &KeyPair) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("Yubico PIV Root (test)")
            .self_signed(&root_kp)
            .unwrap();
        let f9_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut f9_params = params("YubiKey f9 (test)");
        // FIPS `.10` rides the factory f9 cert (presence = FIPS-certified).
        f9_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 41482, 3, 10],
            vec![],
        )];
        let f9 = f9_params.signed_by(&f9_kp, &root, &root_kp).unwrap();
        let mut leaf = params("YubiKey 9c (test)");
        leaf.custom_extensions = vec![
            // DER OCTET STRING-wrapped firmware + [pin, touch], as a real key emits.
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 3],
                vec![0x04, 0x03, 5, 7, 4],
            ),
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 8],
                vec![0x04, 0x02, 0x01, TOUCH_ALWAYS],
            ),
        ];
        let cert_9c = leaf.signed_by(leaf_kp, &f9, &f9_kp).unwrap();
        (
            cert_9c.der().to_vec(),
            f9.der().to_vec(),
            root.der().to_vec(),
        )
    }

    fn ed25519_pkcs8_pem(seed: &[u8; 32]) -> KeyPair {
        use base64::Engine;
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(seed);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
        KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_ED25519).unwrap()
    }

    unsafe fn call(req: &serde_json::Value) -> Result<serde_json::Value, i32> {
        let body = serde_json::to_vec(req).unwrap();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_accord_custody_attestation(
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
    async fn ffi_admits_a_valid_holder_bundle() {
        let seed = [7u8; 32];
        let leaf_kp = ed25519_pkcs8_pem(&seed);
        let (c9, f9, root) = mock_chain(&leaf_kp);
        let holder = HybridSigningIdentity::new(
            "accord-holder-a1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let member = holder.directory_member().unwrap();
        let obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();

        let req = json!({
            "attestation_object": obj,
            "holder_member": member,
            "yubico_root_der_hex": hex::encode(&root),
        });
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["admitted"], json!(true));
        assert_eq!(v["hardware_class"], json!("YubiKey_5_FIPS"));
        assert_eq!(v["custody_tier"], json!(CUSTODY_TIER_PORTABLE_2FA));
        assert_eq!(v["touch_always"], json!(true));
    }

    #[tokio::test]
    async fn ffi_rejects_wrong_root_as_negative_verdict() {
        let seed = [3u8; 32];
        let leaf_kp = ed25519_pkcs8_pem(&seed);
        let (c9, f9, _root) = mock_chain(&leaf_kp);
        let holder = HybridSigningIdentity::new(
            "accord-holder-b1",
            Ed25519Signer::from_seed(&seed).unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let member = holder.directory_member().unwrap();
        let obj = produce_accord_custody_attestation(
            &holder,
            &c9,
            &[f9.as_slice()],
            CUSTODY_TIER_PORTABLE_2FA,
            "2026-06-20T00:00:00Z",
        )
        .await
        .unwrap();
        // An attacker-chosen root the f9 does not chain to.
        let other_root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let other_root = params("attacker root").self_signed(&other_root_kp).unwrap();

        let req = json!({
            "attestation_object": obj,
            "holder_member": member,
            "yubico_root_der_hex": hex::encode(other_root.der()),
        });
        let v = unsafe { call(&req) }.unwrap();
        assert_eq!(v["admitted"], json!(false));
        assert!(v["reason"].as_str().unwrap().contains("chain"));
    }

    #[test]
    fn ffi_malformed_input_is_serialization_error() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let bad = b"{not json";
        let rc = unsafe {
            ciris_verify_accord_custody_attestation(bad.as_ptr(), bad.len(), &mut out, &mut out_len)
        };
        assert_eq!(rc, CirisVerifyError::SerializationError as i32);
    }
}
