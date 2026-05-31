//! Per-locale Merkle root + inclusion-proof FFI surface for the Python
//! wheel (CIRISVerify#50, v4.7.0+).
//!
//! Wraps [`ciris_verify_core::locale_merkle::merkle_root`] and
//! [`ciris_verify_core::locale_merkle::verify_locale_inclusion`] so
//! wheel consumers can drive RFC 6962 Merkle composition + inclusion
//! verification for the `provenance:build_manifest:{target}` per-locale
//! sub-tree from Python.
//!
//! Surface principle: "if it ain't on the wheel, it doesn't exist."
//!
//! ## Wire shape
//!
//! - `ciris_verify_locale_merkle_root` takes a JSON array of 32-byte
//!   arrays — `[[u8; 32], [u8; 32], ...]` — and returns
//!   `{"root": [..32 bytes..]}`.
//! - `ciris_verify_locale_inclusion_verify` takes a `LocaleLeaf` JSON,
//!   a `LocaleInclusionProof` JSON, and a 32-byte expected-root buffer;
//!   returns `{"verified": true}` or
//!   `{"verified": false, "error": {"code", "message"}}`.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::locale_merkle::{
    merkle_root, verify_locale_inclusion, LocaleInclusionProof, LocaleLeaf,
};

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

/// RFC 6962 Merkle root over a fully-built leaf set with last-leaf
/// duplication padding (CIRISVerify#50, v4.7.0+).
///
/// Takes a JSON array of 32-byte arrays — `[[u8; 32], [u8; 32], ...]`
/// — and returns `{"root": [..32 bytes..]}` on success. On JSON-parse
/// failure or empty leaf set, returns a typed error code.
///
/// # Safety
///
/// All `*const u8` inputs must point to valid memory of at least the
/// declared length. `result_out` and `result_len_out` must be valid
/// pointers.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_locale_merkle_root(
    leaves_json: *const u8,
    leaves_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_locale_merkle_root", {
        locale_merkle_root_inner(leaves_json, leaves_len, result_out, result_len_out)
    })
}

unsafe fn locale_merkle_root_inner(
    leaves_json: *const u8,
    leaves_len: usize,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if leaves_json.is_null() || result_out.is_null() || result_len_out.is_null() {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let leaves_bytes = std::slice::from_raw_parts(leaves_json, leaves_len);
    let leaves: Vec<[u8; 32]> = match serde_json::from_slice(leaves_bytes) {
        Ok(l) => l,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };

    match merkle_root(&leaves) {
        Ok(root) => {
            let env = serde_json::json!({ "root": root.to_vec() });
            emit_json(&env.to_string(), result_out, result_len_out)
        },
        Err(_) => CirisVerifyError::InvalidArgument as i32,
    }
}

/// RFC 6962 locale inclusion-proof verification
/// (CIRISVerify#50, v4.7.0+).
///
/// Walks the inclusion proof from leaf → root, reconstructs the
/// claimed parent root, and compares against `expected_root`. Returns
/// `{"verified": true}` on full match; `{"verified": false, "error":
/// {"code", "message"}}` on any mismatch (leaf-hash, lang_code,
/// tree-size, sibling-count, reconstructed root).
///
/// `expected_root` is 32 raw bytes (not hex).
///
/// # Safety
///
/// All `*const u8` inputs must point to valid memory of at least the
/// declared length. `expected_root` must point to at least 32 bytes.
/// `result_out` and `result_len_out` must be valid pointers.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ciris_verify_locale_inclusion_verify(
    leaf_json: *const u8,
    leaf_len: usize,
    proof_json: *const u8,
    proof_len: usize,
    expected_root: *const u8,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_locale_inclusion_verify", {
        locale_inclusion_verify_inner(
            leaf_json,
            leaf_len,
            proof_json,
            proof_len,
            expected_root,
            result_out,
            result_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn locale_inclusion_verify_inner(
    leaf_json: *const u8,
    leaf_len: usize,
    proof_json: *const u8,
    proof_len: usize,
    expected_root: *const u8,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if leaf_json.is_null()
        || proof_json.is_null()
        || expected_root.is_null()
        || result_out.is_null()
        || result_len_out.is_null()
    {
        return CirisVerifyError::InvalidArgument as i32;
    }

    let leaf_bytes = std::slice::from_raw_parts(leaf_json, leaf_len);
    let proof_bytes = std::slice::from_raw_parts(proof_json, proof_len);
    let leaf: LocaleLeaf = match serde_json::from_slice(leaf_bytes) {
        Ok(l) => l,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };
    let proof: LocaleInclusionProof = match serde_json::from_slice(proof_bytes) {
        Ok(p) => p,
        Err(_) => return CirisVerifyError::SerializationError as i32,
    };

    let mut root_buf = [0u8; 32];
    let root_slice = std::slice::from_raw_parts(expected_root, 32);
    root_buf.copy_from_slice(root_slice);

    let env = match verify_locale_inclusion(&leaf, &proof, &root_buf) {
        Ok(()) => serde_json::json!({ "verified": true }),
        Err(e) => serde_json::json!({
            "verified": false,
            "error": {
                "code": "INCLUSION_PROOF_INVALID",
                "message": format!("{e}"),
            }
        }),
    };
    emit_json(&env.to_string(), result_out, result_len_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::locale_merkle::{merkle_root as core_merkle_root, parent_hash};

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn sample_leaf(target: &str, lang: &str) -> LocaleLeaf {
        LocaleLeaf {
            target: target.into(),
            lang_code: lang.into(),
            files_root: format!("{:0>64}", lang),
            build_id: "01HQK3M9F0X2Y4Z6T8R9W1V5N3".into(),
            signer_identity: "verify-steward-2026".into(),
        }
    }

    unsafe fn read_and_free(ptr: *mut u8, len: usize) -> String {
        let slice = std::slice::from_raw_parts(ptr, len);
        let owned = String::from_utf8_lossy(slice).into_owned();
        libc::free(ptr as *mut libc::c_void);
        owned
    }

    #[test]
    fn merkle_root_matches_core_implementation_for_4_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
        let leaves_json = serde_json::to_vec(&leaves).unwrap();

        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        unsafe {
            let status = ciris_verify_locale_merkle_root(
                leaves_json.as_ptr(),
                leaves_json.len(),
                &mut ptr,
                &mut len,
            );
            assert_eq!(status, CirisVerifyError::Success as i32);
            let body = read_and_free(ptr, len);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let root_arr: Vec<u8> = v["root"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as u8)
                .collect();
            let expected = core_merkle_root(&leaves).unwrap();
            assert_eq!(root_arr.as_slice(), &expected);
        }
    }

    #[test]
    fn merkle_root_empty_leaves_rejected() {
        let leaves: Vec<[u8; 32]> = vec![];
        let leaves_json = serde_json::to_vec(&leaves).unwrap();
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        unsafe {
            let status = ciris_verify_locale_merkle_root(
                leaves_json.as_ptr(),
                leaves_json.len(),
                &mut ptr,
                &mut len,
            );
            assert_eq!(status, CirisVerifyError::InvalidArgument as i32);
        }
    }

    #[test]
    fn merkle_root_malformed_json_returns_serialization_error() {
        let bad = b"{not an array";
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        unsafe {
            let status =
                ciris_verify_locale_merkle_root(bad.as_ptr(), bad.len(), &mut ptr, &mut len);
            assert_eq!(status, CirisVerifyError::SerializationError as i32);
        }
    }

    #[test]
    fn inclusion_proof_round_trip_succeeds() {
        // 4 locale leaves; prove inclusion of index 1.
        let leaves: Vec<LocaleLeaf> = ["en", "id", "my", "th"]
            .iter()
            .map(|l| sample_leaf("ios-mobile-bundle", l))
            .collect();
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(LocaleLeaf::leaf_hash).collect();
        let root = core_merkle_root(&leaf_hashes).unwrap();

        // Build the proof for leaf index 1 (id).
        let sibling_0 = leaf_hashes[0];
        let parent_23 = parent_hash(&leaf_hashes[2], &leaf_hashes[3]);

        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf_hashes[1]),
            lang_code: "id".into(),
            sibling_hashes: vec![hex_encode(&sibling_0), hex_encode(&parent_23)],
            leaf_index: 1,
            tree_size: 4,
        };

        let leaf_json = serde_json::to_vec(&leaves[1]).unwrap();
        let proof_json = serde_json::to_vec(&proof).unwrap();

        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        unsafe {
            let status = ciris_verify_locale_inclusion_verify(
                leaf_json.as_ptr(),
                leaf_json.len(),
                proof_json.as_ptr(),
                proof_json.len(),
                root.as_ptr(),
                &mut ptr,
                &mut len,
            );
            assert_eq!(status, CirisVerifyError::Success as i32);
            let body = read_and_free(ptr, len);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["verified"], true);
        }
    }

    #[test]
    fn inclusion_proof_lang_code_mismatch_returns_typed_envelope() {
        let leaves: Vec<LocaleLeaf> = ["en", "id", "my", "th"]
            .iter()
            .map(|l| sample_leaf("ios-mobile-bundle", l))
            .collect();
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(LocaleLeaf::leaf_hash).collect();
        let root = core_merkle_root(&leaf_hashes).unwrap();

        let sibling_0 = leaf_hashes[0];
        let parent_23 = parent_hash(&leaf_hashes[2], &leaf_hashes[3]);

        // Proof says lang_code=my, leaf is for id — mismatch.
        let proof = LocaleInclusionProof {
            leaf_hash: hex_encode(&leaf_hashes[1]),
            lang_code: "my".into(),
            sibling_hashes: vec![hex_encode(&sibling_0), hex_encode(&parent_23)],
            leaf_index: 1,
            tree_size: 4,
        };

        let leaf_json = serde_json::to_vec(&leaves[1]).unwrap(); // lang=id
        let proof_json = serde_json::to_vec(&proof).unwrap();

        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        unsafe {
            let status = ciris_verify_locale_inclusion_verify(
                leaf_json.as_ptr(),
                leaf_json.len(),
                proof_json.as_ptr(),
                proof_json.len(),
                root.as_ptr(),
                &mut ptr,
                &mut len,
            );
            assert_eq!(status, CirisVerifyError::Success as i32);
            let body = read_and_free(ptr, len);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["verified"], false);
            assert_eq!(v["error"]["code"], "INCLUSION_PROOF_INVALID");
            assert!(v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("lang_code"));
        }
    }

    #[test]
    fn inclusion_verify_null_inputs_return_invalid_argument() {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        unsafe {
            let status = ciris_verify_locale_inclusion_verify(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                &mut ptr,
                &mut len,
            );
            assert_eq!(status, CirisVerifyError::InvalidArgument as i32);
        }
    }
}
