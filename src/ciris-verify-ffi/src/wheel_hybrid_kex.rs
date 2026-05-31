//! Hybrid X25519 + ML-KEM-768 KEX — Python wheel surface
//! (CIRISVerify#50, v4.7.0+).
//!
//! Exposes the v4.6.0 [`ciris_crypto::hybrid_kex`] primitives to
//! cross-wheel callers (notably the `ciris-verify` PyPI wheel) so
//! federation peers can drive harvest-now-decrypt-later-resistant
//! handshakes from Python without reaching into the Rust crate
//! directly.
//!
//! See [`ciris_crypto::hybrid_kex`] for protocol/algorithm details —
//! this module is a stateless JSON-in/JSON-out marshalling seam over
//! that surface, identical in shape to the v4.2.0 conformance FFI
//! triad ([`crate::ciris_verify_admit_attestation`] et al.).
//!
//! ## Wire shapes
//!
//! Hybrid initiate output:
//! ```json
//! {
//!   "algorithm": "hybrid-x25519-mlkem768-hkdf-sha256-v1",
//!   "x25519_ephemeral_pub": [..32 bytes..],
//!   "mlkem768_ciphertext":  [..1088 bytes..],
//!   "session_key":          [..32 bytes..]
//! }
//! ```
//!
//! Respond output (both modes):
//! ```json
//! {"session_key": [..32 bytes..]}
//! ```
//!
//! Error output (respond modes only — initiate cannot fail on adversary
//! input):
//! ```json
//! {"error": {"code": "ALGORITHM_MISMATCH", "message": "..."}}
//! ```
//!
//! ## Opaque-failure discipline
//!
//! Per [`ciris_crypto::hybrid_kex`] §"Opaque-failure discipline":
//! tampered ciphertexts / swapped pubkeys / wrong keys do NOT surface
//! as `KexError` — they produce a different `session_key` and the AEAD
//! layer above this KEX detects the mismatch as a tag failure. This
//! module preserves that discipline: only `AlgorithmMismatch` and
//! `MlKemOnlyRejected` ever return an error envelope; everything else
//! returns a (possibly diverged) session key.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_crypto::hybrid_kex::{
    initiate_classical, initiate_hybrid, respond_classical, respond_hybrid_with_public,
    ClassicalHandshakeMsg, HybridHandshakeMsg, KexError,
};

use crate::CirisVerifyError;

// `ffi_guard!` from `lib.rs` is declared after the `mod ...;` lines so
// it isn't visible inside submodules. Inline an equivalent local
// macro here to preserve the panic-safety discipline.
macro_rules! wheel_guard {
    ($fn_name:expr, $body:expr) => {{
        let result = catch_unwind(AssertUnwindSafe(|| $body));
        match result {
            Ok(code) => code,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
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

/// Write `bytes` into a newly-malloced buffer; populate `result_out` /
/// `result_len_out`. Returns `Success` on success, `InternalError` on
/// allocation failure.
///
/// Caller is responsible for freeing the buffer with `ciris_verify_free`.
unsafe fn write_out_bytes(
    bytes: &[u8],
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    let len = bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return CirisVerifyError::InternalError as i32;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
    *result_out = ptr;
    *result_len_out = len;
    CirisVerifyError::Success as i32
}

/// Map a `KexError` to a typed `{"error": {"code", "message"}}` envelope.
fn kex_error_envelope(e: &KexError) -> serde_json::Value {
    let code = match e {
        KexError::AlgorithmMismatch { .. } => "ALGORITHM_MISMATCH",
        KexError::MlKemOnlyRejected => "MLKEM_ONLY_REJECTED",
        KexError::Crypto(_) => "CRYPTO_ERROR",
    };
    serde_json::json!({
        "error": {
            "code": code,
            "message": e.to_string(),
        }
    })
}

// =============================================================================
// Hybrid mode
// =============================================================================

/// Initiate side: hybrid X25519 + ML-KEM-768 KEX.
///
/// On success returns JSON:
/// `{"algorithm", "x25519_ephemeral_pub", "mlkem768_ciphertext", "session_key"}`
/// — all byte fields are JSON arrays of `u8`.
///
/// # Safety
///
/// `recipient_x25519_pub` MUST point to at least 32 bytes.
/// `recipient_mlkem768_pub` MUST point to at least `recipient_mlkem768_pub_len`
/// bytes. `result_out` and `result_len_out` MUST be valid out-pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_kex_initiate_hybrid(
    recipient_x25519_pub: *const u8,
    recipient_mlkem768_pub: *const u8,
    recipient_mlkem768_pub_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    wheel_guard!("ciris_verify_kex_initiate_hybrid", {
        kex_initiate_hybrid_inner(
            recipient_x25519_pub,
            recipient_mlkem768_pub,
            recipient_mlkem768_pub_len,
            result_out,
            result_len_out,
        )
    })
}

unsafe fn kex_initiate_hybrid_inner(
    recipient_x25519_pub: *const u8,
    recipient_mlkem768_pub: *const u8,
    recipient_mlkem768_pub_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if recipient_x25519_pub.is_null()
        || recipient_mlkem768_pub.is_null()
        || result_out.is_null()
        || result_len_out.is_null()
    {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let x_pub_slice = std::slice::from_raw_parts(recipient_x25519_pub, 32);
    let x_pub: [u8; 32] = match <[u8; 32]>::try_from(x_pub_slice) {
        Ok(a) => a,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };
    let mlkem_pub = std::slice::from_raw_parts(recipient_mlkem768_pub, recipient_mlkem768_pub_len);

    let (msg, session_key) = match initiate_hybrid(&x_pub, mlkem_pub) {
        Ok(v) => v,
        Err(_) => return CirisVerifyError::InternalError as i32,
    };

    let out = serde_json::json!({
        "algorithm": msg.algorithm,
        "x25519_ephemeral_pub": msg.x25519_ephemeral_pub.to_vec(),
        "mlkem768_ciphertext": msg.mlkem768_ciphertext,
        "session_key": session_key.to_vec(),
    });
    let bytes = match serde_json::to_vec(&out) {
        Ok(b) => b,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };
    write_out_bytes(&bytes, result_out, result_len_out)
}

/// Respond side: hybrid X25519 + ML-KEM-768 KEX.
///
/// `msg_json` is a serialized [`HybridHandshakeMsg`] (the wire shape
/// emitted by [`ciris_verify_kex_initiate_hybrid`]'s `x25519_ephemeral_pub`
/// / `mlkem768_ciphertext` / `algorithm` fields combined into a single
/// JSON object).
///
/// Returns `{"session_key": [..32 bytes..]}` on success, or
/// `{"error": {"code", "message"}}` on a typed `KexError`. Wrong-key
/// / tampered-ciphertext cases produce a (diverged) session key — see
/// the opaque-failure discipline note at the top of this module.
///
/// # Safety
///
/// All `*const u8` pointers MUST point to at least their declared
/// lengths (X25519 priv is implicitly 32 bytes). Out-pointers MUST be
/// valid.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ciris_verify_kex_respond_hybrid_with_public(
    recipient_x25519_priv: *const u8,
    recipient_mlkem768_priv: *const u8,
    recipient_mlkem768_priv_len: usize,
    recipient_mlkem768_pub: *const u8,
    recipient_mlkem768_pub_len: usize,
    msg_json: *const u8,
    msg_json_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    wheel_guard!("ciris_verify_kex_respond_hybrid_with_public", {
        kex_respond_hybrid_with_public_inner(
            recipient_x25519_priv,
            recipient_mlkem768_priv,
            recipient_mlkem768_priv_len,
            recipient_mlkem768_pub,
            recipient_mlkem768_pub_len,
            msg_json,
            msg_json_len,
            result_out,
            result_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn kex_respond_hybrid_with_public_inner(
    recipient_x25519_priv: *const u8,
    recipient_mlkem768_priv: *const u8,
    recipient_mlkem768_priv_len: usize,
    recipient_mlkem768_pub: *const u8,
    recipient_mlkem768_pub_len: usize,
    msg_json: *const u8,
    msg_json_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if recipient_x25519_priv.is_null()
        || recipient_mlkem768_priv.is_null()
        || recipient_mlkem768_pub.is_null()
        || msg_json.is_null()
        || result_out.is_null()
        || result_len_out.is_null()
    {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let x_priv_slice = std::slice::from_raw_parts(recipient_x25519_priv, 32);
    let x_priv: [u8; 32] = match <[u8; 32]>::try_from(x_priv_slice) {
        Ok(a) => a,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };
    let mlkem_priv =
        std::slice::from_raw_parts(recipient_mlkem768_priv, recipient_mlkem768_priv_len);
    let mlkem_pub = std::slice::from_raw_parts(recipient_mlkem768_pub, recipient_mlkem768_pub_len);
    let msg_bytes = std::slice::from_raw_parts(msg_json, msg_json_len);

    let msg: HybridHandshakeMsg = match serde_json::from_slice(msg_bytes) {
        Ok(m) => m,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };

    let envelope = match respond_hybrid_with_public(&x_priv, mlkem_priv, mlkem_pub, &msg) {
        Ok(session_key) => serde_json::json!({"session_key": session_key.to_vec()}),
        Err(e) => kex_error_envelope(&e),
    };
    let bytes = match serde_json::to_vec(&envelope) {
        Ok(b) => b,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };
    write_out_bytes(&bytes, result_out, result_len_out)
}

// =============================================================================
// Classical fallback mode
// =============================================================================

/// Initiate side: classical X25519-only KEX fallback.
///
/// On success returns JSON:
/// `{"algorithm", "x25519_ephemeral_pub", "session_key"}`.
///
/// # Safety
///
/// `recipient_x25519_pub` MUST point to at least 32 bytes. Out-pointers
/// MUST be valid.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_kex_initiate_classical(
    recipient_x25519_pub: *const u8,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    wheel_guard!("ciris_verify_kex_initiate_classical", {
        kex_initiate_classical_inner(recipient_x25519_pub, result_out, result_len_out)
    })
}

unsafe fn kex_initiate_classical_inner(
    recipient_x25519_pub: *const u8,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if recipient_x25519_pub.is_null() || result_out.is_null() || result_len_out.is_null() {
        return CirisVerifyError::InvalidArgument as i32;
    }
    let x_pub_slice = std::slice::from_raw_parts(recipient_x25519_pub, 32);
    let x_pub: [u8; 32] = match <[u8; 32]>::try_from(x_pub_slice) {
        Ok(a) => a,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };

    let (msg, session_key) = match initiate_classical(&x_pub) {
        Ok(v) => v,
        Err(_) => return CirisVerifyError::InternalError as i32,
    };
    let out = serde_json::json!({
        "algorithm": msg.algorithm,
        "x25519_ephemeral_pub": msg.x25519_ephemeral_pub.to_vec(),
        "session_key": session_key.to_vec(),
    });
    let bytes = match serde_json::to_vec(&out) {
        Ok(b) => b,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };
    write_out_bytes(&bytes, result_out, result_len_out)
}

/// Respond side: classical X25519-only KEX fallback.
///
/// Returns `{"session_key": [..32 bytes..]}` on success, or
/// `{"error": {"code", "message"}}` on `AlgorithmMismatch`.
///
/// # Safety
///
/// `recipient_x25519_priv` MUST point to at least 32 bytes. `msg_json`
/// MUST point to at least `msg_json_len` bytes. Out-pointers MUST be
/// valid.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_kex_respond_classical(
    recipient_x25519_priv: *const u8,
    msg_json: *const u8,
    msg_json_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    wheel_guard!("ciris_verify_kex_respond_classical", {
        kex_respond_classical_inner(
            recipient_x25519_priv,
            msg_json,
            msg_json_len,
            result_out,
            result_len_out,
        )
    })
}

unsafe fn kex_respond_classical_inner(
    recipient_x25519_priv: *const u8,
    msg_json: *const u8,
    msg_json_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if recipient_x25519_priv.is_null()
        || msg_json.is_null()
        || result_out.is_null()
        || result_len_out.is_null()
    {
        return CirisVerifyError::InvalidArgument as i32;
    }
    let x_priv_slice = std::slice::from_raw_parts(recipient_x25519_priv, 32);
    let x_priv: [u8; 32] = match <[u8; 32]>::try_from(x_priv_slice) {
        Ok(a) => a,
        Err(_) => return CirisVerifyError::InvalidArgument as i32,
    };
    let msg_bytes = std::slice::from_raw_parts(msg_json, msg_json_len);
    let msg: ClassicalHandshakeMsg = match serde_json::from_slice(msg_bytes) {
        Ok(m) => m,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };

    let envelope = match respond_classical(&x_priv, &msg) {
        Ok(session_key) => serde_json::json!({"session_key": session_key.to_vec()}),
        Err(e) => kex_error_envelope(&e),
    };
    let bytes = match serde_json::to_vec(&envelope) {
        Ok(b) => b,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };
    write_out_bytes(&bytes, result_out, result_len_out)
}

// =============================================================================
// Tests
// =============================================================================
//
// Each test drives the FFI exactly as a wheel caller would: marshal
// JSON-in / JSON-out across pointer + length, free with libc::free,
// and decode back to compare. This catches any drift in the
// marshalling layer separate from the Rust-native round-trips already
// covered by `ciris_crypto::hybrid_kex::tests`.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Helper: read out the malloc'd JSON buffer the FFI returned and
    /// free it via `libc::free` (matching the wheel caller's
    /// `ciris_verify_free` shape — which is also `libc::free`).
    unsafe fn take_json(ptr: *mut u8, len: usize) -> Value {
        let slice = std::slice::from_raw_parts(ptr, len);
        let v: Value = serde_json::from_slice(slice).expect("FFI output is valid JSON");
        libc::free(ptr as *mut libc::c_void);
        v
    }

    /// Helper: extract a `Vec<u8>` from a JSON array of u8.
    fn json_bytes(v: &Value) -> Vec<u8> {
        v.as_array()
            .expect("expected JSON array")
            .iter()
            .map(|n| u8::try_from(n.as_u64().expect("expected u64")).expect("u8 in range"))
            .collect()
    }

    /// Headline: drive an end-to-end hybrid handshake through the FFI.
    /// Initiator and responder MUST land on the same `session_key`.
    #[test]
    fn ffi_hybrid_round_trip_through_byte_path() {
        // Recipient long-term keys (generated via the Rust crate to
        // avoid duplicating its keygen surface here).
        let (rx_x_sk, rx_x_pk) =
            ciris_crypto::x25519::generate_ephemeral_keypair().expect("x25519 keygen");
        let (rx_mlkem_sk, rx_mlkem_pk) =
            ciris_crypto::ml_kem::generate_keypair().expect("ml-kem keygen");

        // --- Initiate side via FFI.
        let mut init_out: *mut u8 = std::ptr::null_mut();
        let mut init_len: usize = 0;
        let rc = unsafe {
            ciris_verify_kex_initiate_hybrid(
                rx_x_pk.as_ptr(),
                rx_mlkem_pk.as_ptr(),
                rx_mlkem_pk.len(),
                &mut init_out,
                &mut init_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::Success as i32);
        let init_json = unsafe { take_json(init_out, init_len) };

        assert_eq!(
            init_json["algorithm"].as_str().unwrap(),
            "hybrid-x25519-mlkem768-hkdf-sha256-v1"
        );
        let init_session_key = json_bytes(&init_json["session_key"]);
        assert_eq!(init_session_key.len(), 32);

        // Reconstruct the wire `HybridHandshakeMsg` JSON the responder
        // expects (algorithm + x25519_ephemeral_pub + mlkem768_ciphertext).
        let msg_for_responder = serde_json::json!({
            "algorithm": init_json["algorithm"],
            "x25519_ephemeral_pub": init_json["x25519_ephemeral_pub"],
            "mlkem768_ciphertext": init_json["mlkem768_ciphertext"],
        });
        let msg_bytes = serde_json::to_vec(&msg_for_responder).unwrap();

        // --- Respond side via FFI.
        let mut resp_out: *mut u8 = std::ptr::null_mut();
        let mut resp_len: usize = 0;
        let rc = unsafe {
            ciris_verify_kex_respond_hybrid_with_public(
                rx_x_sk.as_ptr(),
                rx_mlkem_sk.as_ptr(),
                rx_mlkem_sk.len(),
                rx_mlkem_pk.as_ptr(),
                rx_mlkem_pk.len(),
                msg_bytes.as_ptr(),
                msg_bytes.len(),
                &mut resp_out,
                &mut resp_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::Success as i32);
        let resp_json = unsafe { take_json(resp_out, resp_len) };
        assert!(
            resp_json.get("error").is_none(),
            "unexpected error: {resp_json}"
        );
        let resp_session_key = json_bytes(&resp_json["session_key"]);

        assert_eq!(
            init_session_key, resp_session_key,
            "initiator + responder MUST derive identical session keys"
        );
    }

    /// Algorithm-identifier mismatch on the respond path surfaces as a
    /// typed error envelope, NOT a successful (diverged) session key —
    /// that's the one case `KexError` is allowed to be observable
    /// across the FFI.
    #[test]
    fn ffi_hybrid_algorithm_mismatch_yields_error_envelope() {
        let (rx_x_sk, rx_x_pk) = ciris_crypto::x25519::generate_ephemeral_keypair().unwrap();
        let (rx_mlkem_sk, rx_mlkem_pk) = ciris_crypto::ml_kem::generate_keypair().unwrap();

        let mut init_out: *mut u8 = std::ptr::null_mut();
        let mut init_len: usize = 0;
        let rc = unsafe {
            ciris_verify_kex_initiate_hybrid(
                rx_x_pk.as_ptr(),
                rx_mlkem_pk.as_ptr(),
                rx_mlkem_pk.len(),
                &mut init_out,
                &mut init_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::Success as i32);
        let init_json = unsafe { take_json(init_out, init_len) };

        // Tamper algorithm field to the classical identifier.
        let msg_for_responder = serde_json::json!({
            "algorithm": "classical-x25519-hkdf-sha256-v1",
            "x25519_ephemeral_pub": init_json["x25519_ephemeral_pub"],
            "mlkem768_ciphertext": init_json["mlkem768_ciphertext"],
        });
        let msg_bytes = serde_json::to_vec(&msg_for_responder).unwrap();

        let mut resp_out: *mut u8 = std::ptr::null_mut();
        let mut resp_len: usize = 0;
        let rc = unsafe {
            ciris_verify_kex_respond_hybrid_with_public(
                rx_x_sk.as_ptr(),
                rx_mlkem_sk.as_ptr(),
                rx_mlkem_sk.len(),
                rx_mlkem_pk.as_ptr(),
                rx_mlkem_pk.len(),
                msg_bytes.as_ptr(),
                msg_bytes.len(),
                &mut resp_out,
                &mut resp_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::Success as i32);
        let resp_json = unsafe { take_json(resp_out, resp_len) };
        let err = resp_json
            .get("error")
            .expect("algorithm mismatch MUST surface as error envelope");
        assert_eq!(err["code"].as_str().unwrap(), "ALGORITHM_MISMATCH");
    }

    /// Classical fallback: end-to-end round-trip through the FFI.
    #[test]
    fn ffi_classical_round_trip_through_byte_path() {
        let (rx_x_sk, rx_x_pk) = ciris_crypto::x25519::generate_ephemeral_keypair().unwrap();

        let mut init_out: *mut u8 = std::ptr::null_mut();
        let mut init_len: usize = 0;
        let rc = unsafe {
            ciris_verify_kex_initiate_classical(rx_x_pk.as_ptr(), &mut init_out, &mut init_len)
        };
        assert_eq!(rc, CirisVerifyError::Success as i32);
        let init_json = unsafe { take_json(init_out, init_len) };
        assert_eq!(
            init_json["algorithm"].as_str().unwrap(),
            "classical-x25519-hkdf-sha256-v1"
        );
        let init_session_key = json_bytes(&init_json["session_key"]);

        let msg_for_responder = serde_json::json!({
            "algorithm": init_json["algorithm"],
            "x25519_ephemeral_pub": init_json["x25519_ephemeral_pub"],
        });
        let msg_bytes = serde_json::to_vec(&msg_for_responder).unwrap();

        let mut resp_out: *mut u8 = std::ptr::null_mut();
        let mut resp_len: usize = 0;
        let rc = unsafe {
            ciris_verify_kex_respond_classical(
                rx_x_sk.as_ptr(),
                msg_bytes.as_ptr(),
                msg_bytes.len(),
                &mut resp_out,
                &mut resp_len,
            )
        };
        assert_eq!(rc, CirisVerifyError::Success as i32);
        let resp_json = unsafe { take_json(resp_out, resp_len) };
        assert!(resp_json.get("error").is_none());
        let resp_session_key = json_bytes(&resp_json["session_key"]);
        assert_eq!(init_session_key, resp_session_key);
    }

    /// Null-pointer inputs are rejected with `InvalidArgument`, NOT a
    /// crash. (FFI safety invariant.)
    #[test]
    fn ffi_rejects_null_inputs() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let rc = unsafe {
            ciris_verify_kex_initiate_hybrid(
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut out,
                &mut len,
            )
        };
        assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);

        let rc =
            unsafe { ciris_verify_kex_initiate_classical(std::ptr::null(), &mut out, &mut len) };
        assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);
    }
}
