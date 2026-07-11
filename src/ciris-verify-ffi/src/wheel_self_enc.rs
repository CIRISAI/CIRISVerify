//! Self content-encryption keypair derivation FFI surface for the Python wheel
//! (CIRISVerify#151).
//!
//! Exposes `ciris_crypto::self_enc` — deterministic derivation of the two
//! content-encryption keypairs (X25519 + ML-KEM-768) from the Ed25519 base seed
//! — so the **server mint path** can populate enc pubkeys at user-identity mint
//! and the **KMP client** can derive + register an occurrence's enc pubkeys. The
//! derivation is byte-identical to the Rust impl (one source), pinned by the
//! `self_enc` golden vector.
//!
//! ## Wire shape
//!
//! `ciris_verify_self_enc_derive` takes a JSON request carrying the 32-byte
//! Ed25519 seed and returns a **JSON envelope** (UTF-8) with base64 fields —
//! both halves, so the caller can custody the private locally and publish the
//! public:
//!
//! ```text
//! in:  {"ed25519_seed":[u8;32]}
//! out: {
//!   "x25519_secret_base64":        "..",   // 32 B
//!   "x25519_public_base64":        "..",   // 32 B   -> pubkey_x25519_base64
//!   "ml_kem_768_dk_seed_base64":   "..",   // 64 B   (FIPS 203 d||z)
//!   "ml_kem_768_ek_public_base64": ".."    // 1184 B -> pubkey_ml_kem_768_base64
//! }
//! ```
//!
//! The public fields are exactly what `federation_identity_occurrences.
//! pubkey_x25519_base64 / pubkey_ml_kem_768_base64` expect (CIRISPersist V069).
//! The private halves stay in-process — the consumer keeps them in its enclave
//! and only the public halves cross the wire.
//!
//! A malformed request (bad JSON, seed of the wrong length) returns a typed
//! error code.

use std::panic::{catch_unwind, AssertUnwindSafe};

use base64::Engine;
use ciris_crypto::self_enc::{derive_self_enc_mlkem768, derive_self_enc_x25519};
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
struct DeriveRequest {
    ed25519_seed: Vec<u8>,
}

/// Build the base64 JSON envelope from a 32-byte seed, or `None` on a malformed
/// seed length / unreachable ML-KEM keygen error — fail-closed.
fn derive_envelope(seed: &[u8; 32]) -> Option<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let (x_secret, x_public) = derive_self_enc_x25519(seed);
    let (dk_seed, ek_public) = derive_self_enc_mlkem768(seed).ok()?;
    Some(
        serde_json::json!({
            "x25519_secret_base64": b64.encode(x_secret),
            "x25519_public_base64": b64.encode(x_public),
            "ml_kem_768_dk_seed_base64": b64.encode(&dk_seed),
            "ml_kem_768_ek_public_base64": b64.encode(&ek_public),
        })
        .to_string(),
    )
}

/// Derive the self content-encryption keypairs (CIRISVerify#151).
///
/// **Mint-time only (CIRISVerify#183).** This entry takes a raw seed and
/// returns the raw **secret** halves — legitimate only where the seed already
/// exists in hand (the portable-user mint path). It MUST NOT be the
/// node-identity path: a sealed identity has no plaintext seed to pass, and a
/// software one should not export its privs. Use the by-alias
/// [`ciris_verify_self_enc_pubkeys`] / [`ciris_verify_self_enc_respond`]
/// custody surface instead — no private byte crosses the boundary either way.
///
/// `input_json` is the UTF-8 bytes of `{"ed25519_seed":[u8;32]}`. On success
/// `result_out` / `result_len_out` receive the UTF-8 bytes of the base64 JSON
/// envelope (see module docs; caller frees via `ciris_verify_free`). Returns:
/// - `Success` (0) on success;
/// - `InvalidArgument` on a null pointer;
/// - `SerializationError` if `input_json` is not a valid request or the seed is
///   not exactly 32 bytes.
///
/// # Safety
///
/// `input_json` must point to valid memory of at least `input_len` bytes.
/// `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_self_enc_derive(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_self_enc_derive", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: DeriveRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        let seed: [u8; 32] = match <[u8; 32]>::try_from(req.ed25519_seed.as_slice()) {
            Ok(s) => s,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        match derive_envelope(&seed) {
            Some(json) => emit_bytes(json.as_bytes(), result_out, result_len_out),
            None => CirisVerifyError::InternalError as i32,
        }
    })
}

/// By-alias content-enc config: the SAME `{alias, seed_dir}` shape the other
/// by-alias FFI entries take. Resolves the sealed Ed25519 identity seed.
#[derive(Deserialize)]
struct SelfEncConfig {
    alias: String,
    seed_dir: String,
}

/// Open the content-enc custody capability over a sealed identity seed, mapping
/// keyring errors to FFI codes: a missing seal is [`CirisVerifyError::NoKey`].
fn open_self_enc(input: &[u8]) -> Result<ciris_keyring::self_enc_keys::SelfEncKeys, i32> {
    let cfg: SelfEncConfig =
        serde_json::from_slice(input).map_err(|_| CirisVerifyError::SerializationError as i32)?;
    ciris_keyring::self_enc_keys::SelfEncKeys::open(cfg.alias, cfg.seed_dir).map_err(|e| match e {
        ciris_keyring::KeyringError::KeyNotFound { .. } => CirisVerifyError::NoKey as i32,
        _ => CirisVerifyError::InternalError as i32,
    })
}

/// Content-enc PUBLIC keys by alias, from inside custody (CIRISVerify#183).
///
/// `config_json` is the UTF-8 bytes of `{"alias":"..","seed_dir":".."}` (the
/// sealed Ed25519 identity seed). On success `result_out` / `result_len_out`
/// receive the UTF-8 bytes of `{"x25519_base64":"..","ml_kem_768_base64":".."}`
/// (persist `encryption_pubkeys` field names — drops straight into an
/// occurrence). **No private key material crosses the boundary.** Caller frees
/// via `ciris_verify_free`. Returns `Success`; `InvalidArgument` on a null
/// pointer; `SerializationError` on bad config; `NoKey` if no seed is sealed
/// under the alias; `InternalError` otherwise.
///
/// # Safety
/// `config_json` must point to `config_len` valid bytes; the out-pointers must
/// be valid.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_self_enc_pubkeys(
    config_json: *const u8,
    config_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_self_enc_pubkeys", {
        if config_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let config = std::slice::from_raw_parts(config_json, config_len);
        let keys = match open_self_enc(config) {
            Ok(k) => k,
            Err(code) => return code,
        };
        let pubs = match keys.enc_pubkeys() {
            Ok(p) => p,
            Err(_) => return CirisVerifyError::InternalError as i32,
        };
        let json = serde_json::json!({
            "x25519_base64": pubs.x25519_base64,
            "ml_kem_768_base64": pubs.ml_kem_768_base64,
        })
        .to_string();
        emit_bytes(json.as_bytes(), result_out, result_len_out)
    })
}

/// KEX **respond** by alias, from inside custody (CIRISVerify#183).
///
/// `config_json` = `{"alias":"..","seed_dir":".."}`; `handshake_json` = the
/// initiator's wire handshake (its `algorithm` selects hybrid vs classical).
/// The private halves are derived in-process from the sealed seed, the respond
/// runs inside keyring, the privs are scrubbed, and **only** the 32-byte
/// session key is returned: `{"session_key_base64":".."}`. Caller frees via
/// `ciris_verify_free`. Returns `Success`; `InvalidArgument` on a null pointer;
/// `SerializationError` on bad config/handshake; `NoKey` if unsealed;
/// `InternalError` on a KEX fault.
///
/// # Safety
/// `config_json`/`handshake_json` must point to `*_len` valid bytes; the
/// out-pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_self_enc_respond(
    config_json: *const u8,
    config_len: usize,
    handshake_json: *const u8,
    handshake_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_self_enc_respond", {
        if config_json.is_null()
            || handshake_json.is_null()
            || result_out.is_null()
            || result_len_out.is_null()
        {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let config = std::slice::from_raw_parts(config_json, config_len);
        let handshake = std::slice::from_raw_parts(handshake_json, handshake_len);
        let keys = match open_self_enc(config) {
            Ok(k) => k,
            Err(code) => return code,
        };
        let session_key = match keys.kex_respond(handshake) {
            Ok(k) => k,
            Err(ciris_keyring::KeyringError::InvalidKey { .. }) => {
                return CirisVerifyError::SerializationError as i32
            },
            Err(_) => return CirisVerifyError::InternalError as i32,
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let json = serde_json::json!({ "session_key_base64": b64.encode(session_key) }).to_string();
        emit_bytes(json.as_bytes(), result_out, result_len_out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn ffi_derive(json: &str) -> Result<serde_json::Value, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_self_enc_derive(json.as_ptr(), json.len(), &mut out, &mut out_len);
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
    fn ffi_derives_correctly_shaped_keys_deterministically() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let seed: Vec<u8> = vec![0x42; 32];
        let req = serde_json::json!({ "ed25519_seed": seed }).to_string();
        let v1 = unsafe { ffi_derive(&req) }.unwrap();
        let v2 = unsafe { ffi_derive(&req) }.unwrap();
        assert_eq!(v1, v2, "deterministic for a fixed seed");

        let x_pub = b64
            .decode(v1["x25519_public_base64"].as_str().unwrap())
            .unwrap();
        let ek_pub = b64
            .decode(v1["ml_kem_768_ek_public_base64"].as_str().unwrap())
            .unwrap();
        let x_sec = b64
            .decode(v1["x25519_secret_base64"].as_str().unwrap())
            .unwrap();
        let dk_seed = b64
            .decode(v1["ml_kem_768_dk_seed_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(x_pub.len(), 32);
        assert_eq!(x_sec.len(), 32);
        assert_eq!(dk_seed.len(), 64);
        assert_eq!(ek_pub.len(), 1184);
    }

    /// The FFI envelope MUST carry the same public halves the core golden pins
    /// (SHA-256 over x25519_pub ‖ ml-kem ek for seed [0x42; 32]).
    #[test]
    fn ffi_matches_core_golden() {
        use sha2::{Digest, Sha256};
        let b64 = base64::engine::general_purpose::STANDARD;
        let seed: Vec<u8> = vec![0x42; 32];
        let v = unsafe { ffi_derive(&serde_json::json!({ "ed25519_seed": seed }).to_string()) }
            .unwrap();
        let x_pub = b64
            .decode(v["x25519_public_base64"].as_str().unwrap())
            .unwrap();
        let ek_pub = b64
            .decode(v["ml_kem_768_ek_public_base64"].as_str().unwrap())
            .unwrap();
        let mut h = Sha256::new();
        h.update(&x_pub);
        h.update(&ek_pub);
        assert_eq!(
            hex::encode(h.finalize()),
            "93a8018292b9b71cdda0fb93803567007aa316000245fbd0fb64dba053526789"
        );
    }

    #[test]
    fn ffi_rejects_wrong_length_seed() {
        let short: Vec<u8> = vec![0x42; 31];
        assert_eq!(
            unsafe { ffi_derive(&serde_json::json!({ "ed25519_seed": short }).to_string()) }
                .unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
    }

    // ---- by-alias custody surface (#183) --------------------------------

    unsafe fn ffi_pubkeys(config: &str) -> Result<serde_json::Value, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc =
            ciris_verify_self_enc_pubkeys(config.as_ptr(), config.len(), &mut out, &mut out_len);
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        libc::free(out as *mut libc::c_void);
        Ok(serde_json::from_slice(&bytes).unwrap())
    }

    unsafe fn ffi_respond(config: &str, handshake: &str) -> Result<serde_json::Value, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_self_enc_respond(
            config.as_ptr(),
            config.len(),
            handshake.as_ptr(),
            handshake.len(),
            &mut out,
            &mut out_len,
        );
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        libc::free(out as *mut libc::c_void);
        Ok(serde_json::from_slice(&bytes).unwrap())
    }

    fn seal_and_config(seed: &[u8; 32]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        ciris_keyring::sealed_ed25519::SealedEd25519Signer::open_or_create(
            "id",
            dir.path().to_path_buf(),
            Some(seed),
        )
        .unwrap();
        let cfg = serde_json::json!({
            "alias": "id",
            "seed_dir": dir.path().to_string_lossy(),
        })
        .to_string();
        (dir, cfg)
    }

    #[test]
    fn by_alias_pubkeys_are_public_only_and_match_the_derivation() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let seed = [0x42u8; 32];
        let (_dir, cfg) = seal_and_config(&seed);

        let v = unsafe { ffi_pubkeys(&cfg) }.unwrap();
        // ONLY public fields — no secret/dk_seed ever.
        assert!(v.get("x25519_base64").is_some());
        assert!(v.get("ml_kem_768_base64").is_some());
        assert!(v.as_object().unwrap().len() == 2);
        assert!(!v.to_string().contains("secret"));
        assert!(!v.to_string().contains("dk_seed"));

        let (_s, x_pub) = derive_self_enc_x25519(&seed);
        let (_d, ek) = derive_self_enc_mlkem768(&seed).unwrap();
        assert_eq!(v["x25519_base64"].as_str().unwrap(), b64.encode(x_pub));
        assert_eq!(v["ml_kem_768_base64"].as_str().unwrap(), b64.encode(&ek));
    }

    #[test]
    fn by_alias_hybrid_kex_roundtrips_without_exporting_privs() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let (_dir, cfg) = seal_and_config(&[0x7u8; 32]);

        let pubs = unsafe { ffi_pubkeys(&cfg) }.unwrap();
        let x_pub: [u8; 32] = b64
            .decode(pubs["x25519_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let ek = b64
            .decode(pubs["ml_kem_768_base64"].as_str().unwrap())
            .unwrap();

        let (msg, initiator_key) = ciris_crypto::hybrid_kex::initiate_hybrid(&x_pub, &ek).unwrap();
        let handshake = serde_json::to_string(&msg).unwrap();
        let resp = unsafe { ffi_respond(&cfg, &handshake) }.unwrap();
        let session = b64
            .decode(resp["session_key_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(session, initiator_key.to_vec(), "session keys must agree");
    }

    #[test]
    fn by_alias_missing_seed_is_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = serde_json::json!({
            "alias": "absent",
            "seed_dir": dir.path().to_string_lossy(),
        })
        .to_string();
        assert_eq!(
            unsafe { ffi_pubkeys(&cfg) }.unwrap_err(),
            CirisVerifyError::NoKey as i32
        );
    }
}
