//! HMAC-SHA256 + constant-time equality (CIRISVerify#7, v2.0.0+).
//!
//! Used for `EncryptedSecretRecord.edge_hmac` integrity check
//! (CIRISPersist#19): edge computes HMAC over `canonical(SecretRecord)`
//! before submitting the row to persist; persist verifies before insert
//! so a compromised edge can't write a record with a tampered nonce/salt.
//!
//! Constant-time MAC compare via [`util::ct_eq`] is **mandatory** for
//! the verification path — naive `==` on MAC bytes is a timing
//! side-channel.

use ::hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::Sha3_256;

type HmacSha256 = Hmac<Sha256>;
type HmacSha3_256 = Hmac<Sha3_256>;

/// HMAC-SHA256.
///
/// Returns the 32-byte tag. Key length is unrestricted (HMAC handles
/// any length internally per RFC 2104). Empty key is permitted but
/// useless — caller's responsibility to use a real key.
#[must_use]
pub fn sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // `Hmac::new_from_slice` accepts any key length per the HMAC spec.
    // The `expect` is safe — Hmac<Sha256> never rejects a slice key.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA3-256.
///
/// The SHA3 sibling of [`sha256`] — returns the 32-byte tag, accepts any
/// key length (RFC 2104). Added for the scope-native privacy surface
/// (CIRISVerify#82, CEWP SCOPE_PRIVACY.md): the §2.4 `record_id =
/// HMAC-SHA3-256(K_record_id, CBOR_dCE(..))` and the §3.4 witness
/// cover-leaf `HMAC-SHA3-256(witness_signing_key, leaf_position ||
/// epoch_id)`. SHA3 (Keccak) is structurally length-extension-free, the
/// property the witness cover-leaf indistinguishability argument leans on.
#[must_use]
pub fn sha3_256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha3_256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality + timing-safe utilities.
///
/// Re-exported here under the spec'd name `util::ct_eq` (CIRISVerify#7).
/// Backed by the same `subtle::ConstantTimeEq` impl as the crate-level
/// `constant_time_eq`.
pub mod util {
    /// Constant-time byte-slice equality. Use this for ALL MAC and
    /// signature comparisons. Returns `true` iff the slices have equal
    /// length AND equal contents.
    ///
    /// The length check still returns early — length is treated as
    /// non-secret. For cases where length is itself secret, callers
    /// pad to a fixed length first.
    #[must_use]
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        crate::constant_time_eq(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 Test Case 1 — locks the algorithm.
    ///
    /// Key  = 0x0b0b…0b (20 bytes)
    /// Data = "Hi There"
    /// HMAC = 0xb0344c61d8db38535ca8afceaf0bf12b
    ///        881dc200c9833da726e9376c2e32cff7
    #[test]
    fn rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let expected: [u8; 32] =
            hex_literal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(sha256(&key, msg), expected);
    }

    /// RFC 4231 Test Case 2 — short key + ASCII message.
    ///
    /// Key  = "Jefe"
    /// Data = "what do ya want for nothing?"
    /// HMAC = 0x5bdcc146bf60754e6a042426089575c7
    ///        5a003f089d2739839dec58b964ec3843
    #[test]
    fn rfc4231_test_case_2() {
        let expected: [u8; 32] =
            hex_literal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(sha256(b"Jefe", b"what do ya want for nothing?"), expected);
    }

    /// RFC 4231 Test Case 4 — longer key, longer data, locks 32-byte
    /// tag length and end-of-message handling.
    ///
    /// Key  = 0x0102030405060708090a0b0c0d0e0f10111213141516171819
    /// Data = 0xcd repeated 50 times
    /// HMAC = 0x82558a389a443c0ea4cc819899f2083a
    ///        85f0faa3e578f8077a2e3ff46729665b
    #[test]
    fn rfc4231_test_case_4() {
        let key = hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
        let msg = vec![0xcdu8; 50];
        let expected: [u8; 32] =
            hex_literal("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
        assert_eq!(sha256(&key, &msg), expected);
    }

    /// HMAC-SHA3-256 known-answer vectors — the published NIST HMAC-SHA3-256
    /// test vectors (same key/message inputs as RFC 4231 TC1/TC2/TC4, SHA3-256
    /// MAC). Locks the algorithm across `hmac`/`sha3` crate bumps.
    #[test]
    fn hmac_sha3_256_kat_tc1() {
        let expected: [u8; 32] =
            hex_literal("ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb");
        assert_eq!(sha3_256(&[0x0bu8; 20], b"Hi There"), expected);
    }

    #[test]
    fn hmac_sha3_256_kat_tc2() {
        let expected: [u8; 32] =
            hex_literal("c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5");
        assert_eq!(sha3_256(b"Jefe", b"what do ya want for nothing?"), expected);
    }

    #[test]
    fn hmac_sha3_256_kat_tc4() {
        let key = hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
        let msg = vec![0xcdu8; 50];
        let expected: [u8; 32] =
            hex_literal("57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7");
        assert_eq!(sha3_256(&key, &msg), expected);
    }

    /// SHA3 and SHA256 HMAC must differ for identical inputs (domain
    /// separation is real, not accidental).
    #[test]
    fn hmac_sha3_differs_from_sha256() {
        let key = [7u8; 32];
        let msg = b"same message, different hash";
        assert_ne!(sha3_256(&key, msg), sha256(&key, msg));
    }

    /// Determinism — same inputs always → same output.
    #[test]
    fn determinism() {
        let key = [9u8; 32];
        let msg = b"deterministic message";
        assert_eq!(sha256(&key, msg), sha256(&key, msg));
    }

    /// Different keys produce different tags.
    #[test]
    fn key_sensitivity() {
        let msg = b"same message";
        assert_ne!(sha256(&[1u8; 32], msg), sha256(&[2u8; 32], msg));
    }

    /// `util::ct_eq` agrees with `==` for the success/fail cases that
    /// matter. (Timing properties are tested by `subtle`'s own suite;
    /// we just confirm correctness of the wrapping.)
    #[test]
    fn ct_eq_correctness() {
        assert!(util::ct_eq(b"abc", b"abc"));
        assert!(!util::ct_eq(b"abc", b"abd"));
        assert!(!util::ct_eq(b"abc", b"abcd"));
        assert!(util::ct_eq(b"", b""));
    }

    fn hex_literal<const N: usize>(s: &str) -> [u8; N] {
        let bytes = hex::decode(s).expect("valid hex");
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }
}
