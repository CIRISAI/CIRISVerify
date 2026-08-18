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
//! ([`k_record_id`] / [`k_symbol`] / [`k_destination`]) and MUST NOT be
//! substituted with `ExpandWithLabel`, or the two impls diverge silently.
//! Pending **CEWP / CEG §11 ratification** before the wire value is frozen.
//!
//! ## Where the 32-byte input comes from — **also a wire fact** (#259)
//!
//! Until v13.5.0 this module said the caller supplies "the group's **raw**
//! MLS `exporter_secret`" and MUST NOT call `export_secret`. That was
//! **underspecified to the point of being unimplementable**, and CIRISEdge
//! caught it while building against the spec:
//!
//! RFC 9420 §8.5's exporter is a **labelled** KDF —
//! `MlsGroup::export_secret(crypto, label, context, len)` — and openmls
//! exposes no accessor for the bare key-schedule secret. So "the exporter
//! secret" is only well-defined once `(label, context, length)` is fixed, and
//! **two members agree only if they export under the same label**. That makes
//! the label as wire-affecting as the derivation itself.
//!
//! Pinned here, as the first conformant impl:
//!
//! ```text
//! S_record  = MLS-Exporter(RECORD_EXPORTER_LABEL,      "", 32)   // → k_record_id, k_symbol
//! S_dest    = MLS-Exporter(DESTINATION_EXPORTER_LABEL, "", 32)   // → k_destination
//! ```
//!
//! **The derivations themselves are unchanged** — every golden vector
//! published for v13.4.0 still holds byte-for-byte. What v13.5.0 pins is
//! *where the caller's 32 bytes must come from*.
//!
//! ### Why the destination gets its OWN exporter label
//!
//! The two secrets go to **different subsystems**: `S_record` reaches the
//! record/storage layer (persisted, passed around, potentially logged);
//! `S_dest` reaches the transport layer. Sharing one PRK would mean that any
//! compromise yielding `S_record` **retroactively deanonymizes all routing** —
//! an adversary recomputes and links every address the node ever presented,
//! collapsing exactly the unlinkability the destination work exists to buy.
//!
//! Independent per-label secrets are what §8.5 is *for*, and the cost is one
//! extra `export_secret` per epoch boundary — a cold path (epoch advance, not
//! per packet). So the separation is taken.
//!
//! This composes with, and does not contradict, the second-stage label reuse
//! documented on [`derive_destination`]: the **PRKs** are separated here, and
//! *within* each PRK the two KDF stages reuse one family label, matching
//! [`derive_symbol_key`].
//!
//! ### Explicitly refused: a DEK-seed label
//!
//! CIRISEdge's existing exporter call is
//! `"ciris-realtime-av-epoch-dek-seed-v1"`, and feeding its output here is
//! **wrong** — on the record, so it is refused rather than rediscovered. It is
//! a **DEK seed**: deriving a routing identifier that appears in the clear on
//! the wire from the material that seeds the content key converts two
//! independent secrets into one, and the DEK protects payload confidentiality
//! rather than metadata. No label defined here may be an encryption-key seed.
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

/// **MLS-Exporter label producing the input to [`k_record_id`] / [`k_symbol`]**
/// (CIRISVerify#259).
///
/// ```text
/// S_record = MlsGroup::export_secret(crypto, RECORD_EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
/// ```
///
/// **Wire-affecting.** Two members compute the same `record_id` only if they
/// export under this exact label — RFC 9420 §8.5's exporter is a *labelled*
/// KDF, so "the group's exporter secret" is not a single value.
pub const RECORD_EXPORTER_LABEL: &str = "ciris-scope-record-v1";

/// **MLS-Exporter label producing the input to [`k_destination`]**
/// (CIRISVerify#259).
///
/// ```text
/// S_dest = MlsGroup::export_secret(crypto, DESTINATION_EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
/// ```
///
/// **Deliberately distinct from [`RECORD_EXPORTER_LABEL`]** — see the
/// module-level rationale. In one line: a compromise that yields the record
/// layer's secret must not retroactively deanonymize routing.
///
/// **MUST NOT** be an encryption-key seed. Edge's
/// `"ciris-realtime-av-epoch-dek-seed-v1"` is explicitly refused for this
/// input.
pub const DESTINATION_EXPORTER_LABEL: &str = "ciris-scope-destination-v1";

/// The MLS-Exporter `context` for every label defined here: **empty**.
///
/// The group and epoch binding already comes from the exporter itself, so the
/// context adds nothing and an empty value is one less thing to diverge on.
pub const EXPORTER_CONTEXT: &[u8] = b"";

/// The MLS-Exporter output length for every label defined here: 32 bytes —
/// the PRK width the `expander_subkey` stage requires.
pub const EXPORTER_LENGTH: usize = 32;

/// §2.x domain-separation label for the **destination** subkey
/// (CIRISVerify#259 / CIRISEdge#499).
///
/// Distinct from [`LABEL_RECORD_ID`] and [`LABEL_SYMBOL`], so `K_destination`
/// is not reachable from either and vice versa. That separation is
/// load-bearing in a way the other two are not: a destination hash is the one
/// derived value that appears **in the clear on the wire**, so it is the
/// natural pivot for a cross-context attack on the record layer.
pub const LABEL_DESTINATION: &str = "ciris-edge/scope-privacy/destination/v1";

/// Reticulum `TRUNCATED_HASHLENGTH` in bytes — the width of a destination
/// hash. Pinned here because it is a **wire** width, not a choice: RNS
/// addresses are 16 bytes and a different length is simply not routable.
pub const DESTINATION_HASH_LEN: usize = 16;

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

/// §2.2 — derive `K_record_id` from `S_record`.
///
/// `exporter_secret` MUST be
/// `MLS-Exporter(`[`RECORD_EXPORTER_LABEL`]`, `[`EXPORTER_CONTEXT`]`, 32)` —
/// the label is wire-affecting (#259).
#[must_use]
pub fn k_record_id(exporter_secret: &[u8; 32]) -> [u8; 32] {
    expander_subkey(exporter_secret, LABEL_RECORD_ID)
}

/// §2.2 — derive `K_symbol` from `S_record`.
///
/// Same input as [`k_record_id`]: `MLS-Exporter(`[`RECORD_EXPORTER_LABEL`]`,
/// `[`EXPORTER_CONTEXT`]`, 32)`.
#[must_use]
pub fn k_symbol(exporter_secret: &[u8; 32]) -> [u8; 32] {
    expander_subkey(exporter_secret, LABEL_SYMBOL)
}

/// §2.x — derive `K_destination` from `S_dest` (CIRISVerify#259).
///
/// `exporter_secret` MUST be
/// `MLS-Exporter(`[`DESTINATION_EXPORTER_LABEL`]`, `[`EXPORTER_CONTEXT`]`, 32)`
/// — **a different exporter label from the record layer**, so a compromise of
/// the record secret cannot retroactively deanonymize routing. Never a
/// DEK-seed export.
///
/// Same labeled-expand stage as [`k_record_id`] / [`k_symbol`], under a
/// distinct label — so the same cross-impl warning applies verbatim: this is
/// bare `HKDF-SHA256-Expand`, **not** RFC 9420 `ExpandWithLabel` and **not**
/// openmls `export_secret`.
#[must_use]
pub fn k_destination(exporter_secret: &[u8; 32]) -> [u8; 32] {
    expander_subkey(exporter_secret, LABEL_DESTINATION)
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

/// §2.x — the scoped RNS destination hash for **one member** of one group
/// (CIRISVerify#259 / CIRISEdge#499 / CC 5.4).
///
/// ```text
/// destination = HKDF-SHA3-256(
///     ikm  = K_destination,
///     salt = "",                                    // K_destination is already a PRK
///     info = LABEL_DESTINATION || u32_be(len(member_key_id)) || utf8(member_key_id),
///     L    = 16)                                    // Reticulum TRUNCATED_HASHLENGTH
/// ```
///
/// ## Per-member, never a shared group hash
///
/// Each member gets its **own** address in each group. A single shared hash
/// would put N nodes under one RNS routing entry, which is unicast-ambiguous
/// — leviculum v0.19 added a `register_destination` warning for exactly that
/// displacement, so it is a known hazard, not a theoretical one.
///
/// Per-member is also what buys the unlinkability that motivates the feature:
/// one node presents an unrelated address in every group, and nothing
/// correlates them without the group secret. A non-member cannot derive any of
/// them, and (since leviculum v0.19 makes never-announce structural for
/// caller-supplied hashes) cannot learn them from the air either.
///
/// ## The label is deliberately reused at this second stage
///
/// [`LABEL_DESTINATION`] is both the §2.2 subkey label and the info-prefix
/// here — **the same deliberate reuse as [`derive_symbol_key`]**, and safe for
/// the same reason: the two uses sit at distinct KDF stages over distinct PRKs
/// (stage 1 PRK = `exporter_secret`; stage 2 PRK = `k_destination`).
///
/// The alternative — a second, destination-only label — was considered and
/// rejected. It buys nothing cryptographically (PRK separation already
/// domain-separates the stages) and costs the thing that actually goes wrong
/// cross-impl: **one convention per derived-value family**. Symbol reuses its
/// label; if destination did not, an implementor reproducing this module would
/// have to remember which family follows which rule. That is the kind of
/// asymmetry that produces a silent divergence.
///
/// ## Why `member_key_id` is length-prefixed
///
/// `u32_be(len)` before the id, matching `epoch_key`'s treatment of
/// `stream_id`. With the id last a bare concatenation happens to be
/// unambiguous today, but the prefix is what keeps it unambiguous when a
/// future field is appended — and appending without noticing is precisely how
/// concatenation ambiguity gets introduced.
///
/// ## The output IS the address (ratified, CIRISConstitution#91)
///
/// CIRISEdge asked whether this should instead seed a **per-group RNS
/// identity**, letting RNS compute the address natively so a scoped
/// destination becomes announceable and therefore multi-hop
/// (CIRISVerify#262). That would have demoted this function from *address* to
/// *name*.
///
/// **Ruled against: CC 5.4.6's announce prohibition binds the emission, not
/// the addressing mode**, so a targeted announce iterated over a roster
/// inherits it rather than escaping it. The derived value therefore remains
/// the destination hash. See `ciris_verify_core::announce_policy` for the
/// ruling's three legs.
///
/// The practical consequence for callers: a scoped destination is **one hop by
/// construction** — unprobeable and unannounceable, and reachable only over a
/// direct link or a relay-blinded path. That is a deliberate posture, not a
/// gap. Multi-hop scoped reach stays open on the amendment plane with a stated
/// bar: no outsider-observable emission, no outsider-retained path state, no
/// epoch-correlated wave.
///
/// ## Rotation
///
/// The hash is bound to the group secret, so it moves when the MLS epoch
/// moves. Callers derive once per `(group, epoch)` at membership/epoch change
/// — **never per packet** — and rotate with an install-next → activate → seal
/// pattern, so an epoch bump cannot silently deafen a group.
///
/// **Epoch rotation is free precisely because nothing is announced.** Members
/// re-derive from the directory and the new epoch secret, and a removed member
/// loses addressing at the next epoch — the rebind discipline holds on the
/// addressing plane with no emission. Under the rejected announceable reading
/// the same epoch-binding would have forced a synchronized roster-wide
/// re-announce **wave** on every Add/Remove, leaking cardinality, timing and
/// membership churn. The property is a feature here and a defect there.
#[must_use]
pub fn derive_destination(
    k_destination: &[u8; 32],
    member_key_id: &str,
) -> [u8; DESTINATION_HASH_LEN] {
    let id = member_key_id.as_bytes();
    let mut info = Vec::with_capacity(LABEL_DESTINATION.len() + 4 + id.len());
    info.extend_from_slice(LABEL_DESTINATION.as_bytes());
    // u32-length-prefix the member id — see the doc note above.
    info.extend_from_slice(&(id.len() as u32).to_be_bytes());
    info.extend_from_slice(id);
    let out = hkdf_sha3_256(k_destination, &[], &info, DESTINATION_HASH_LEN)
        .expect("16-byte HKDF-SHA3-256 expand is within the RFC 5869 cap");
    let mut hash = [0u8; DESTINATION_HASH_LEN];
    hash.copy_from_slice(&out);
    hash
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

/// Scoped-destination derivation (CIRISVerify#259 / CIRISEdge#499).
///
/// These pin the two properties the ask required be decided in the spec
/// rather than by an implementor, plus the cross-impl golden vector.
#[cfg(test)]
mod destination {
    use super::*;

    const EXPORTER: [u8; 32] = [0x42u8; 32];

    /// **Domain separation.** `K_destination` must not be reachable from
    /// `K_record_id` / `K_symbol` or vice versa — the destination hash is the
    /// one derived value that appears in the clear on the wire.
    #[test]
    fn destination_subkey_is_separated_from_the_record_layer() {
        let kd = k_destination(&EXPORTER);
        assert_ne!(kd, k_record_id(&EXPORTER));
        assert_ne!(kd, k_symbol(&EXPORTER));
    }

    /// **Per-member, never shared.** Two members of the SAME group at the same
    /// epoch get different addresses — otherwise N nodes collide onto one RNS
    /// routing entry (unicast-ambiguous), and the unlinkability the feature
    /// exists for is gone.
    #[test]
    fn each_member_gets_its_own_address_in_a_group() {
        let kd = k_destination(&EXPORTER);
        let a = derive_destination(&kd, "node-a");
        let b = derive_destination(&kd, "node-b");
        assert_ne!(a, b, "a shared group hash is unicast-ambiguous in RNS");
    }

    /// **Unlinkability across groups.** The same member in two different
    /// groups presents unrelated addresses; nothing correlates them without
    /// the group secret.
    #[test]
    fn the_same_member_is_unlinkable_across_groups() {
        let g1 = k_destination(&EXPORTER);
        let g2 = k_destination(&[0x43u8; 32]);
        assert_ne!(
            derive_destination(&g1, "node-a"),
            derive_destination(&g2, "node-a")
        );
    }

    /// A non-member cannot derive the address: it is a function of the group
    /// secret, so a wrong secret yields an unrelated hash rather than a near
    /// miss.
    #[test]
    fn the_address_is_unprobeable_without_the_group_secret() {
        let real = derive_destination(&k_destination(&EXPORTER), "node-a");
        let guess = derive_destination(&k_destination(&[0u8; 32]), "node-a");
        assert_ne!(real, guess);
    }

    /// The width is a wire fact, not a preference — RNS addresses are 16 bytes.
    #[test]
    fn the_hash_is_reticulum_truncated_hashlength() {
        assert_eq!(DESTINATION_HASH_LEN, 16);
        assert_eq!(derive_destination(&k_destination(&EXPORTER), "n").len(), 16);
    }

    /// Deterministic — a member re-derives its own address every epoch without
    /// storing it.
    #[test]
    fn derivation_is_deterministic() {
        let kd = k_destination(&EXPORTER);
        assert_eq!(
            derive_destination(&kd, "node-a"),
            derive_destination(&kd, "node-a")
        );
    }

    /// The length prefix closes concatenation ambiguity. Without it a future
    /// appended field could let one (id, field) pair impersonate another; this
    /// pins that ids differing only by a boundary do not collide.
    #[test]
    fn the_member_id_is_length_prefixed() {
        let kd = k_destination(&EXPORTER);
        assert_ne!(derive_destination(&kd, "ab"), derive_destination(&kd, "a"));
        // An empty id is still a distinct, well-defined input.
        assert_ne!(derive_destination(&kd, ""), derive_destination(&kd, "a"));
    }

    /// **Cross-impl golden vector.** CIRISEdge reproduces this byte-for-byte
    /// (FSD §9). A change here is a wire break: two members of one group would
    /// simply never find each other.
    #[test]
    fn cross_impl_golden_vector() {
        let kd = k_destination(&EXPORTER);
        assert_eq!(
            hex::encode(kd),
            "3d854734e268842395e65c84d13a5ce74ddac1e5c51e70f2e0a5455e7293c2fb",
            "K_destination for exporter_secret = [0x42; 32]"
        );
        assert_eq!(
            hex::encode(derive_destination(&kd, "ciris-node-1")),
            "944a30ea6ea5c07fbfd0ece7a0779a29",
            "destination for member `ciris-node-1`"
        );
    }
}

/// The MLS-Exporter provenance of the 32-byte inputs (CIRISVerify#259).
///
/// These constants are **wire facts**: two members agree only if they export
/// under the same label, so a change here is a wire break exactly like a
/// change to a derivation.
#[cfg(test)]
mod exporter_provenance {
    use super::*;

    /// Pinned strings, so a rename cannot pass CI silently.
    #[test]
    fn exporter_labels_are_pinned() {
        assert_eq!(RECORD_EXPORTER_LABEL, "ciris-scope-record-v1");
        assert_eq!(DESTINATION_EXPORTER_LABEL, "ciris-scope-destination-v1");
        assert_eq!(EXPORTER_CONTEXT, b"");
        assert_eq!(EXPORTER_LENGTH, 32);
    }

    /// **The separation that matters.** The record layer and the transport
    /// layer must not export the same secret: a compromise yielding the
    /// record secret would otherwise let an adversary recompute and link
    /// every routing address the node ever presented.
    #[test]
    fn destination_exports_under_a_different_label_than_the_record_layer() {
        assert_ne!(RECORD_EXPORTER_LABEL, DESTINATION_EXPORTER_LABEL);
    }

    /// **Refused on the record (#259).** No label here may be an
    /// encryption-key seed — deriving a cleartext routing id from the material
    /// that seeds the content key collapses two secrets the exporter exists to
    /// keep apart. Edge's DEK-seed label is named explicitly so a future
    /// "obvious" rewiring to it fails here.
    #[test]
    fn no_exporter_label_is_a_dek_seed() {
        const EDGE_DEK_SEED: &str = "ciris-realtime-av-epoch-dek-seed-v1";
        for label in [RECORD_EXPORTER_LABEL, DESTINATION_EXPORTER_LABEL] {
            assert_ne!(label, EDGE_DEK_SEED);
            assert!(
                !label.contains("dek") && !label.contains("secret-seed"),
                "{label} looks like key-seed material; scope-privacy inputs must not be"
            );
        }
    }

    /// Distinct exporter labels yield distinct PRKs, so the subkeys derived
    /// from them cannot collide even though both stages reuse a family label.
    #[test]
    fn the_two_exporter_secrets_yield_disjoint_subkeys() {
        // Stand-ins for two different MLS-Exporter outputs.
        let s_record = [0x11u8; 32];
        let s_dest = [0x22u8; 32];
        assert_ne!(k_record_id(&s_record), k_destination(&s_dest));
        assert_ne!(k_symbol(&s_record), k_destination(&s_dest));
    }
}
