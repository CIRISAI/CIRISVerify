//! Scope-native privacy derivation helpers (CIRISVerify#82, v6.3.0+).
//!
//! The §2.2 / §2.4 / §3.4 key-derivation surface of CEWP SCOPE_PRIVACY.md.
//! Verify is the **first conformant impl**, so it authors the cross-impl
//! `record_id` reproducibility vectors (the §9 acceptance criterion);
//! CIRISEdge reproduces them.
//!
//! ## §2.2 MLS-exporter subkeys
//!
//! Two group-and-epoch-bound 32-byte subkeys, domain-separated by label:
//!
//! ```text
//! K_record_id = MLS_Exporter("ciris-edge/scope-privacy/record-id/v1", "", 32)
//! K_symbol    = MLS_Exporter("ciris-edge/scope-privacy/symbol/v1",    "", 32)
//! ```
//!
//! **⚠ CROSS-IMPL WARNING — NOT RFC 9420 ExpandWithLabel / NOT the MLS
//! exporter.** FSD §2.2 writes `MLS_Exporter(label, "", 32)`, which reads
//! like RFC 9420 `ExpandWithLabel` (the MLS KDF-label structure). This module
//! does **NOT** implement that. The `label → subkey` step here is a
//! **deliberate, Verify-authored** construction:
//!
//! ```text
//! K = HKDF-SHA256-Expand(PRK = raw group exporter_secret, info = ASCII label, L = 32)
//! ```
//!
//! — bare HKDF-Expand, **no Extract**, **no MLS KDF-label framing** (no
//! `RFC9420 ` prefix, no length/label header). ciris-crypto owns this step
//! ([`k_record_id`] / [`k_symbol`]); the caller (CIRISEdge) supplies the
//! group's raw MLS `exporter_secret` and **MUST reproduce THIS construction**
//! — it MUST **NOT** call openmls's `export_secret` for these labels, and MUST
//! NOT substitute `ExpandWithLabel`, or the two impls diverge silently.
//! Pending **CEWP / CEG §11 ratification** before the wire value is frozen.
//!
//! ## §2.4 per-record / per-symbol diversification
//!
//! ```text
//! record_id  = HMAC-SHA3-256(K_record_id, CBOR_dCE({v,iid,typ,epc}))   // RFC 8949 §4.2.1
//! symbol_key = HKDF-SHA3-256(salt = record_id, ikm = K_symbol,
//!                            info = "ciris-edge/scope-privacy/symbol/v1" || u16_be(idx), 32)
//! ```
//!
//! ## §3.4 witness cover-leaf
//!
//! ```text
//! cover_leaf = HMAC-SHA3-256(witness_signing_key, u32_be(leaf_position) || u64_be(epoch_id))
//! ```
//! Indistinguishable from a real Merkle root under HMAC-SHA3 IND.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::hmac;
use crate::kdf::hkdf_sha3_256;

/// §2.2 domain-separation label for the record-id subkey.
pub const LABEL_RECORD_ID: &str = "ciris-edge/scope-privacy/record-id/v1";

/// §2.2 domain-separation label for the symbol subkey.
pub const LABEL_SYMBOL: &str = "ciris-edge/scope-privacy/symbol/v1";

/// The kind of record committed (the CBOR `"typ"` field of `record_id_input`).
///
/// **Cross-impl flag:** the FSD does not enumerate these; the integer
/// encoding ([`RecordType::as_cbor_uint`]) is pinned here for CEWP/CIRISEdge
/// cross-confirmation. `0` is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordType {
    /// Self-scope (journaling-grade) record.
    SelfRecord,
    /// Family-scope record.
    FamilyRecord,
    /// Community-scope record.
    CommunityRecord,
    /// Federation-scope record.
    FederationRecord,
}

impl RecordType {
    /// The pinned CBOR unsigned-integer value for the `"typ"` field.
    ///
    /// **Cross-impl flag (CEWP/CIRISEdge):** these integer values are pinned
    /// by Verify as the first conformant impl. `0` is reserved. CIRISEdge MUST
    /// reproduce this mapping byte-for-byte.
    #[must_use]
    pub fn as_cbor_uint(self) -> u64 {
        match self {
            RecordType::SelfRecord => 1,
            RecordType::FamilyRecord => 2,
            RecordType::CommunityRecord => 3,
            RecordType::FederationRecord => 4,
        }
    }
}

/// HKDF-SHA256 Expand-only over a 32-byte PRK with `label` as `info`.
///
/// The §2.2 labeled-expand step shared by [`k_record_id`] / [`k_symbol`].
///
/// **⚠ NOT RFC 9420 `ExpandWithLabel` / NOT the MLS exporter.** Despite the
/// FSD §2.2 `MLS_Exporter(...)` spelling, this is bare
/// `HKDF-SHA256-Expand(PRK = raw exporter_secret, info = ASCII label, L = 32)`
/// — **no Extract**, **no MLS KDF-label framing**. Deliberate, Verify-authored;
/// CIRISEdge MUST reproduce THIS, not `export_secret` / `ExpandWithLabel`. See
/// the module-level warning. Pending CEWP / CEG §11 ratification.
///
/// `exporter_secret` is already a 32-byte PRK (SHA256 output length), so we
/// skip Extract and call `from_prk` directly. `from_prk` only fails when the
/// PRK is shorter than the hash length; a `[u8; 32]` PRK is always valid for
/// HKDF-SHA256, so the `expect` is unreachable.
#[must_use]
fn expander_subkey(exporter_secret: &[u8; 32], label: &str) -> [u8; 32] {
    let hk =
        Hkdf::<Sha256>::from_prk(exporter_secret).expect("32-byte PRK is valid for HKDF-SHA256");
    let mut out = [0u8; 32];
    hk.expand(label.as_bytes(), &mut out)
        .expect("32-byte HKDF-SHA256 expand is within the RFC 5869 cap");
    out
}

/// §2.2 — derive `K_record_id` from the group's MLS `exporter_secret`.
#[must_use]
pub fn k_record_id(exporter_secret: &[u8; 32]) -> [u8; 32] {
    expander_subkey(exporter_secret, LABEL_RECORD_ID)
}

/// §2.2 — derive `K_symbol` from the group's MLS `exporter_secret`.
#[must_use]
pub fn k_symbol(exporter_secret: &[u8; 32]) -> [u8; 32] {
    expander_subkey(exporter_secret, LABEL_SYMBOL)
}

/// Append the minimal-length CBOR header for `major`/`value` (RFC 8949 §3).
///
/// `0..=23` inline in the type byte, else `0x18`+u8 / `0x19`+u16_be /
/// `0x1a`+u32_be / `0x1b`+u64_be. Definite length only.
fn push_cbor_head(buf: &mut Vec<u8>, major: u8, value: u64) {
    let mt = major << 5;
    if value <= 23 {
        buf.push(mt | (value as u8));
    } else if value <= u64::from(u8::MAX) {
        buf.push(mt | 0x18);
        buf.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        buf.push(mt | 0x19);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        buf.push(mt | 0x1a);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push(mt | 0x1b);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Build the RFC 8949 §4.2.1 core-deterministic CBOR for the `record_id`
/// preimage map `{v, epc, iid, typ}`.
///
/// Canonical key order is by encoded-key bytes (shorter-first, then
/// lexicographic) ⇒ `"v"`, `"epc"`, `"iid"`, `"typ"`. The text keys are
/// emitted as major-type-3 strings via [`push_cbor_head`] + their bytes;
/// uints are major 0; `internal_id` is a major-2 byte string.
#[must_use]
fn record_id_cbor(internal_id: &[u8], record_type: RecordType, mls_group_epoch: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    // map header: 4 pairs
    push_cbor_head(&mut buf, 5, 4);
    // "v" -> uint 1
    push_cbor_head(&mut buf, 3, 1);
    buf.extend_from_slice(b"v");
    push_cbor_head(&mut buf, 0, 1);
    // "epc" -> uint mls_group_epoch
    push_cbor_head(&mut buf, 3, 3);
    buf.extend_from_slice(b"epc");
    push_cbor_head(&mut buf, 0, mls_group_epoch);
    // "iid" -> byte string internal_id
    push_cbor_head(&mut buf, 3, 3);
    buf.extend_from_slice(b"iid");
    push_cbor_head(&mut buf, 2, internal_id.len() as u64);
    buf.extend_from_slice(internal_id);
    // "typ" -> uint record_type
    push_cbor_head(&mut buf, 3, 3);
    buf.extend_from_slice(b"typ");
    push_cbor_head(&mut buf, 0, record_type.as_cbor_uint());
    buf
}

/// §2.4 — `record_id = HMAC-SHA3-256(K_record_id, CBOR_dCE({v,iid,typ,epc}))`.
#[must_use]
pub fn derive_record_id(
    k_record_id: &[u8; 32],
    internal_id: &[u8],
    record_type: RecordType,
    mls_group_epoch: u64,
) -> [u8; 32] {
    let cbor = record_id_cbor(internal_id, record_type, mls_group_epoch);
    hmac::sha3_256(k_record_id, &cbor)
}

/// §2.4 — `symbol_key = HKDF-SHA3-256(salt = record_id, ikm = K_symbol, info = label || u16_be(idx))`.
#[must_use]
pub fn derive_symbol_key(k_symbol: &[u8; 32], record_id: &[u8; 32], symbol_index: u16) -> [u8; 32] {
    // LABEL_SYMBOL is DELIBERATELY reused here as the §2.4 info-prefix even
    // though it is also the §2.2 subkey label — safe because the two uses sit
    // at distinct KDF stages over distinct PRKs (§2.2 PRK = exporter_secret;
    // here PRK = k_symbol, salt = record_id). This matches FSD §2.2/§2.4; do
    // NOT "fix" it to a different string or the impls diverge.
    let mut info = Vec::with_capacity(LABEL_SYMBOL.len() + 2);
    info.extend_from_slice(LABEL_SYMBOL.as_bytes());
    info.extend_from_slice(&symbol_index.to_be_bytes());
    let out = hkdf_sha3_256(k_symbol, record_id, &info, 32)
        .expect("32-byte HKDF-SHA3-256 expand is within the RFC 5869 cap");
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// §3.4 — witness cover-leaf `HMAC-SHA3-256(key, u32_be(pos) || u64_be(epoch))`.
#[must_use]
pub fn witness_cover_leaf(
    witness_signing_key: &[u8],
    leaf_position: u32,
    federation_epoch_id: u64,
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(4 + 8);
    msg.extend_from_slice(&leaf_position.to_be_bytes());
    msg.extend_from_slice(&federation_epoch_id.to_be_bytes());
    hmac::sha3_256(witness_signing_key, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ---- §9 cross-impl conformance vectors — CIRISEdge MUST reproduce ----
    //
    // Fixed inputs: k_record_id = [0x11; 32]. The expected CBOR preimage and
    // record_id below were independently derived in Python (hashlib.sha3_256 +
    // a hand HKDF / hand CBOR) and pinned here. Both impls must agree on the
    // exact CBOR bytes AND the resulting HMAC-SHA3-256 record_id.

    const K_REC: [u8; 32] = [0x11; 32];

    /// Vector 1: CommunityRecord (typ=3), epoch=7, single-byte uints.
    #[test]
    fn conformance_vector_1_small() {
        let cbor = record_id_cbor(b"record-0001", RecordType::CommunityRecord, 7);
        assert_eq!(
            hex(&cbor),
            "a46176016365706307636969644b7265636f72642d303030316374797003",
            "CBOR preimage (cross-impl)"
        );
        let rid = derive_record_id(&K_REC, b"record-0001", RecordType::CommunityRecord, 7);
        assert_eq!(
            hex(&rid),
            "5428ddb514a8f8692cc4f254f3550ea75790f5069673e42afb6ef318517a0b21",
            "record_id (cross-impl)"
        );
    }

    /// Vector 2: FederationRecord (typ=4), epoch=300 — forces a 0x19 u16 epoch
    /// header (`0x19 0x01 0x2c`), exercising multi-byte minimal-int encoding.
    #[test]
    fn conformance_vector_2_u16_epoch() {
        let cbor = record_id_cbor(b"record-0002", RecordType::FederationRecord, 300);
        assert_eq!(
            hex(&cbor),
            "a46176016365706319012c636969644b7265636f72642d303030326374797004",
            "CBOR preimage (cross-impl)"
        );
        // 0x19 0x01 0x2c == uint 300 in the epc position.
        assert_eq!(&cbor[8..11], &[0x19, 0x01, 0x2c]);
        let rid = derive_record_id(&K_REC, b"record-0002", RecordType::FederationRecord, 300);
        assert_eq!(
            hex(&rid),
            "04eebeee4d5b83f2fdd0012a205781e6c05fe9a587377e6161b347629a189ff2",
            "record_id (cross-impl)"
        );
    }

    /// Vector 3: SelfRecord (typ=1), epoch=16909060 (0x01020304) — forces a
    /// 0x1a u32 epoch header, exercising the 4-byte minimal-int path.
    #[test]
    fn conformance_vector_3_u32_epoch() {
        let cbor = record_id_cbor(b"x", RecordType::SelfRecord, 16_909_060);
        assert_eq!(
            hex(&cbor),
            "a4617601636570631a010203046369696441786374797001",
            "CBOR preimage (cross-impl)"
        );
        assert_eq!(&cbor[8..13], &[0x1a, 0x01, 0x02, 0x03, 0x04]);
        let rid = derive_record_id(&K_REC, b"x", RecordType::SelfRecord, 16_909_060);
        assert_eq!(
            hex(&rid),
            "79bee8b3f1e815a1df03ca9d83427dc5ab474e184f34e3876d3ef3c36559d6a3",
            "record_id (cross-impl)"
        );
    }

    #[test]
    fn record_type_encoding_pinned() {
        assert_eq!(RecordType::SelfRecord.as_cbor_uint(), 1);
        assert_eq!(RecordType::FamilyRecord.as_cbor_uint(), 2);
        assert_eq!(RecordType::CommunityRecord.as_cbor_uint(), 3);
        assert_eq!(RecordType::FederationRecord.as_cbor_uint(), 4);
    }

    #[test]
    fn cbor_minimal_int_inline_boundary() {
        // 23 inline, 24 -> 0x18 0x18 (the §3 boundary).
        let mut b = Vec::new();
        push_cbor_head(&mut b, 0, 23);
        assert_eq!(b, vec![0x17]);
        let mut b = Vec::new();
        push_cbor_head(&mut b, 0, 24);
        assert_eq!(b, vec![0x18, 0x18]);
        // u64 path.
        let mut b = Vec::new();
        push_cbor_head(&mut b, 0, u64::from(u32::MAX) + 1);
        assert_eq!(b, vec![0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
    }

    /// §2.2 subkey KAT — cross-impl conformance vector (CIRISEdge MUST
    /// reproduce). Expected bytes independently derived via Python
    /// HKDF-SHA256-Expand (PRK = exporter = [0x42; 32], info = ASCII label,
    /// L = 32). Pins the bare-Expand-not-ExpandWithLabel construction.
    #[test]
    fn subkey_kat() {
        let exporter = [0x42u8; 32];
        assert_eq!(
            hex(&k_record_id(&exporter)),
            "49209926b0439f10d73d63317758b9ec19492429368c6aa67e33232da586af99",
            "k_record_id subkey (cross-impl)"
        );
        assert_eq!(
            hex(&k_symbol(&exporter)),
            "3c973c828a218053dc909c51337ae256164437353bde347ee4bac6874888450f",
            "k_symbol subkey (cross-impl)"
        );
    }

    #[test]
    fn k_record_id_ne_k_symbol() {
        // Label domain separation: same exporter_secret, different subkeys.
        let exporter = [0x42u8; 32];
        assert_ne!(k_record_id(&exporter), k_symbol(&exporter));
    }

    #[test]
    fn subkeys_deterministic() {
        let exporter = [0x42u8; 32];
        assert_eq!(k_record_id(&exporter), k_record_id(&exporter));
        assert_eq!(k_symbol(&exporter), k_symbol(&exporter));
    }

    #[test]
    fn symbol_key_deterministic_and_sensitive() {
        let ks = [0x22u8; 32];
        let rid = [0x33u8; 32];
        let base = derive_symbol_key(&ks, &rid, 0);
        // Deterministic.
        assert_eq!(base, derive_symbol_key(&ks, &rid, 0));
        // symbol_index sensitivity.
        assert_ne!(base, derive_symbol_key(&ks, &rid, 1));
        // record_id (salt) sensitivity.
        let mut rid2 = rid;
        rid2[0] ^= 0x01;
        assert_ne!(base, derive_symbol_key(&ks, &rid2, 0));
        // k_symbol (ikm) sensitivity.
        let mut ks2 = ks;
        ks2[0] ^= 0x01;
        assert_ne!(base, derive_symbol_key(&ks2, &rid, 0));
    }

    #[test]
    fn witness_cover_leaf_deterministic_and_sensitive() {
        let key = [0x55u8; 32];
        let base = witness_cover_leaf(&key, 7, 99);
        // Deterministic.
        assert_eq!(base, witness_cover_leaf(&key, 7, 99));
        // leaf_position sensitivity.
        assert_ne!(base, witness_cover_leaf(&key, 8, 99));
        // epoch sensitivity.
        assert_ne!(base, witness_cover_leaf(&key, 7, 100));
        // key sensitivity.
        let mut key2 = key;
        key2[0] ^= 0x01;
        assert_ne!(base, witness_cover_leaf(&key2, 7, 99));
    }

    #[test]
    fn witness_cover_leaf_message_layout() {
        // u32_be(pos) || u64_be(epoch) — exact 12-byte preimage shape.
        let key = b"k";
        // pos = 0x01020304, epoch = 0x0506070809000000
        let got = witness_cover_leaf(key, 0x0102_0304, 0x0506_0708_0900_0000);
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        msg.extend_from_slice(&0x0506_0708_0900_0000u64.to_be_bytes());
        assert_eq!(msg.len(), 12);
        assert_eq!(got, hmac::sha3_256(key, &msg));
    }
}
