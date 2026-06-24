//! Scope-native privacy derivation FFI surface for the Python wheel
//! (CIRISVerify#82, CEWP `SCOPE_PRIVACY.md` — CC 1.13.3 anonymous tier).
//!
//! Exposes the `ciris_crypto::scope_privacy` FSD §2.2/§2.4/§3.4 derivation
//! helpers on the wheel so a Python consumer (and the cross-cdylib conformance
//! cross-check) can reproduce a `record_id` / `symbol_key` / witness cover-leaf
//! **byte-identically** to the Rust verifiers — the discipline-layer surface
//! #82 calls for. The canonical bytes (incl. the RFC 8949 §4.2.1 deterministic
//! CBOR `record_id` preimage and the pinned `RecordType` integers) come from the
//! one Rust impl, so there is no second implementation to drift.
//!
//! ## Wire shape
//!
//! `ciris_verify_scope_privacy_derive` takes a JSON request tagged by `op` and
//! returns the **raw 32-byte** derivation output (NOT a JSON envelope):
//!
//! - `{"op":"k_record_id","exporter_secret":[u8;32]}`
//! - `{"op":"k_symbol","exporter_secret":[u8;32]}`
//! - `{"op":"record_id","k_record_id":[u8;32],"internal_id":[u8],
//!    "record_type":"self|family|community|federation","mls_group_epoch":u64}`
//! - `{"op":"symbol_key","k_symbol":[u8;32],"record_id":[u8;32],"symbol_index":u16}`
//! - `{"op":"witness_cover_leaf","witness_signing_key":[u8],"leaf_position":u32,
//!    "federation_epoch_id":u64}`
//!
//! A malformed request — bad JSON, a 32-byte field of the wrong length, or an
//! unknown `record_type` — returns a typed error code.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_crypto::scope_privacy::{
    derive_record_id, derive_symbol_key, k_record_id, k_symbol, witness_cover_leaf, RecordType,
};
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
#[serde(tag = "op")]
enum DeriveRequest {
    #[serde(rename = "k_record_id")]
    KRecordId { exporter_secret: Vec<u8> },
    #[serde(rename = "k_symbol")]
    KSymbol { exporter_secret: Vec<u8> },
    #[serde(rename = "record_id")]
    RecordId {
        k_record_id: Vec<u8>,
        internal_id: Vec<u8>,
        record_type: String,
        mls_group_epoch: u64,
    },
    #[serde(rename = "symbol_key")]
    SymbolKey {
        k_symbol: Vec<u8>,
        record_id: Vec<u8>,
        symbol_index: u16,
    },
    #[serde(rename = "witness_cover_leaf")]
    WitnessCoverLeaf {
        witness_signing_key: Vec<u8>,
        leaf_position: u32,
        federation_epoch_id: u64,
    },
}

/// Exactly-32-byte view of a request field, or `None` if the length is wrong.
fn arr32(v: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v).ok()
}

fn record_type_of(s: &str) -> Option<RecordType> {
    match s {
        "self" => Some(RecordType::SelfRecord),
        "family" => Some(RecordType::FamilyRecord),
        "community" => Some(RecordType::CommunityRecord),
        "federation" => Some(RecordType::FederationRecord),
        _ => None,
    }
}

/// Compute the requested 32-byte derivation, or `None` on a malformed field
/// (wrong-length key / unknown record_type) — fail-closed.
fn dispatch(req: &DeriveRequest) -> Option<[u8; 32]> {
    Some(match req {
        DeriveRequest::KRecordId { exporter_secret } => k_record_id(&arr32(exporter_secret)?),
        DeriveRequest::KSymbol { exporter_secret } => k_symbol(&arr32(exporter_secret)?),
        DeriveRequest::RecordId {
            k_record_id: krid,
            internal_id,
            record_type,
            mls_group_epoch,
        } => derive_record_id(
            &arr32(krid)?,
            internal_id,
            record_type_of(record_type)?,
            *mls_group_epoch,
        ),
        DeriveRequest::SymbolKey {
            k_symbol: ks,
            record_id,
            symbol_index,
        } => derive_symbol_key(&arr32(ks)?, &arr32(record_id)?, *symbol_index),
        DeriveRequest::WitnessCoverLeaf {
            witness_signing_key,
            leaf_position,
            federation_epoch_id,
        } => witness_cover_leaf(witness_signing_key, *leaf_position, *federation_epoch_id),
    })
}

/// Compute a scope-native privacy derivation (CIRISVerify#82, §2.2/§2.4/§3.4).
///
/// `input_json` is the UTF-8 bytes of an `op`-tagged request (see module docs).
/// On success `result_out` / `result_len_out` receive the raw 32-byte output
/// (caller frees via `ciris_verify_free`). Returns:
/// - `Success` (0) on success;
/// - `InvalidArgument` on a null pointer;
/// - `SerializationError` if `input_json` is not a valid request, a 32-byte
///   field has the wrong length, or `record_type` is unknown.
///
/// # Safety
///
/// `input_json` must point to valid memory of at least `input_len` bytes.
/// `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_scope_privacy_derive(
    input_json: *const u8,
    input_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_scope_privacy_derive", {
        if input_json.is_null() || result_out.is_null() || result_len_out.is_null() {
            return CirisVerifyError::InvalidArgument as i32;
        }
        let input = std::slice::from_raw_parts(input_json, input_len);
        let req: DeriveRequest = match serde_json::from_slice(input) {
            Ok(v) => v,
            Err(_) => return CirisVerifyError::SerializationError as i32,
        };
        match dispatch(&req) {
            Some(out) => emit_bytes(&out, result_out, result_len_out),
            None => CirisVerifyError::SerializationError as i32,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn ffi_derive(json: &str) -> Result<Vec<u8>, i32> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc =
            ciris_verify_scope_privacy_derive(json.as_ptr(), json.len(), &mut out, &mut out_len);
        if rc != CirisVerifyError::Success as i32 {
            return Err(rc);
        }
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        if out_len != 0 {
            libc::free(out as *mut libc::c_void);
        }
        Ok(bytes)
    }

    /// The §9 cross-impl conformance vectors (Python-derived, pinned in
    /// scope_privacy.rs) MUST come back identical through the FFI dispatch.
    #[test]
    fn ffi_matches_cross_impl_vectors() {
        // k_record_id / k_symbol over exporter [0x42; 32].
        let exporter: Vec<u8> = vec![0x42; 32];
        let krid = unsafe {
            ffi_derive(
                &serde_json::json!({"op":"k_record_id","exporter_secret":exporter}).to_string(),
            )
        }
        .unwrap();
        assert_eq!(
            hex::encode(&krid),
            "49209926b0439f10d73d63317758b9ec19492429368c6aa67e33232da586af99"
        );
        let ksym = unsafe {
            ffi_derive(&serde_json::json!({"op":"k_symbol","exporter_secret":exporter}).to_string())
        }
        .unwrap();
        assert_eq!(
            hex::encode(&ksym),
            "3c973c828a218053dc909c51337ae256164437353bde347ee4bac6874888450f"
        );

        // record_id: k_record_id=[0x11;32], "record-0001", community(typ=3), epoch=7.
        let k_rec: Vec<u8> = vec![0x11; 32];
        let rid = unsafe {
            ffi_derive(
                &serde_json::json!({
                    "op":"record_id","k_record_id":k_rec,
                    "internal_id": b"record-0001".to_vec(),
                    "record_type":"community","mls_group_epoch":7
                })
                .to_string(),
            )
        }
        .unwrap();
        assert_eq!(
            hex::encode(&rid),
            "5428ddb514a8f8692cc4f254f3550ea75790f5069673e42afb6ef318517a0b21"
        );
        assert_eq!(rid.len(), 32);
    }

    #[test]
    fn ffi_symbol_key_and_witness_are_32_bytes() {
        let ks: Vec<u8> = vec![0x22; 32];
        let rid: Vec<u8> = vec![0x33; 32];
        let sk = unsafe {
            ffi_derive(
                &serde_json::json!({"op":"symbol_key","k_symbol":ks,"record_id":rid,"symbol_index":0})
                    .to_string(),
            )
        }
        .unwrap();
        assert_eq!(sk.len(), 32);
        let key: Vec<u8> = vec![0x55; 32];
        let leaf = unsafe {
            ffi_derive(
                &serde_json::json!({"op":"witness_cover_leaf","witness_signing_key":key,"leaf_position":7,"federation_epoch_id":99})
                    .to_string(),
            )
        }
        .unwrap();
        assert_eq!(leaf.len(), 32);
    }

    #[test]
    fn ffi_rejects_wrong_length_key_and_unknown_type() {
        // 31-byte exporter.
        let short: Vec<u8> = vec![0x42; 31];
        assert_eq!(
            unsafe {
                ffi_derive(
                    &serde_json::json!({"op":"k_record_id","exporter_secret":short}).to_string(),
                )
            }
            .unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
        // Unknown record_type.
        let k_rec: Vec<u8> = vec![0x11; 32];
        assert_eq!(
            unsafe {
                ffi_derive(
                    &serde_json::json!({
                        "op":"record_id","k_record_id":k_rec,"internal_id":[1,2,3],
                        "record_type":"galactic","mls_group_epoch":7
                    })
                    .to_string(),
                )
            }
            .unwrap_err(),
            CirisVerifyError::SerializationError as i32
        );
    }
}
