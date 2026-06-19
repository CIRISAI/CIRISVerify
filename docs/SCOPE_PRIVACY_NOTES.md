# Scope-Native Privacy — ciris-crypto surface notes (#82)

The **first cut** of the cross-cdylib lockstep cascade for CEWP
[`FSD/SCOPE_PRIVACY.md`](https://github.com/CIRISAI/CEWP/blob/main/FSD/SCOPE_PRIVACY.md)
(CC 1.13.3 anonymous-tier opt-in). `ciris-crypto` v6.3.0 ships the public crypto
surface; CIRISPersist / CIRISEdge / CIRISRegistry / CIRISConformance pin this
release and build on it. This doc is the authoritative reference for the
**cross-impl agreements** the construction depends on — the things a second
implementation must match byte-for-byte.

## What shipped (`ciris-crypto`)

| Surface | Feature | Spec |
|---------|---------|------|
| `hkdf_sha3_256` | `kdf` | RFC 5869 construction, SHA3-256 hash |
| `hmac::sha3_256` | `hmac` | HMAC-SHA3-256 (NIST KAT-locked) |
| `xchacha::{seal,open}` | `xchacha` | XChaCha20-Poly1305, 24-byte nonce (§2.4 symbol envelope, §3.1 framing) |
| `hpke::{seal_base,open_base,encap_signing_bytes}` | `hpke` | RFC 9180 mode_base over the X-Wing hybrid KEM (§3.3 Welcome wrap) |
| `scope_privacy::{k_record_id,k_symbol,derive_record_id,derive_symbol_key,witness_cover_leaf}` | `scope-privacy` | §2.2 / §2.4 / §3.4 derivations |

ML-DSA-65 application-tier sign/verify is the existing `pqc-ml-dsa` re-export
(`MlDsa65Signer`/`MlDsa65Verifier`); HPKE sender authentication is **caller-
composed** — sign `hpke::encap_signing_bytes(&sealed.encapsulation)` — because
X-Wing structurally has no AuthEncap (draft-connolly-cfrg-xwing-kem;
draft-ietf-hpke-pq §7.2).

## Verification evidence

- **HMAC-SHA3-256** — published NIST HMAC-SHA3-256 test vectors.
- **HKDF-SHA3-256** — independent Python (`hmac`+`hashlib.sha3_256`) cross-impl vector.
- **XChaCha20-Poly1305** — draft-irtf-cfrg-xchacha-03 §A.3.1 KAT, plus an
  empty-AAD full-output lock independently verified via libsodium
  (`crypto_aead_xchacha20poly1305_ietf`).
- **HPKE key schedule** — the RFC 9180 §4 labeled schedule was independently
  re-implemented in Python and produces the **same `key`/`base_nonce`** as the
  Rust for a pinned `(shared_secret, info)` (`hpke::tests::key_schedule_kat_independent_python`).
- **`record_id` / subkeys** — pinned conformance vectors with the exact CBOR
  preimage bytes asserted; subkey KATs independently recomputed in Python.

## ⚠ Cross-impl ratification flags (MUST agree before the wire format freezes)

A second implementation (CIRISEdge) **must reproduce these exactly**. Each is a
deliberate, pinned choice by Verify (the first conformant impl, authoring the
vectors per the §19.7 precedent), flagged here for CEWP/CEG §11 sign-off.

1. **MLS-exporter subkeys are a bare HKDF-Expand — NOT RFC 9420
   `ExpandWithLabel`.** FSD §2.2's `MLS_Exporter(label,"",32)` notation reads as
   the RFC 9420 MLS exporter, but `k_record_id`/`k_symbol` are defined as:
   ```
   K = HKDF-SHA256-Expand(PRK = raw group exporter_secret, info = ASCII label, L = 32)
   ```
   No HKDF-Extract, no MLS structured KDF-label, no `DeriveSecret("exporter")`
   step. **CIRISEdge MUST pass the group's raw `exporter_secret` to these helpers
   and MUST NOT call openmls `export_secret` for these labels** — the labeled
   expand lives in `ciris-crypto` so the two impls cannot drift. The reason for
   not reproducing the full RFC 9420 exporter: ciphersuite 0x004D is a custom
   X-Wing suite whose KDF is not pinned by RFC 9420, so chasing openmls internals
   would itself be a guess. The FSD should be amended to state this concrete
   construction rather than the `MLS_Exporter()` shorthand.

2. **`HPKE_SUITE_ID`** = ASCII `b"HPKE-xwing-hkdf-sha256-aes256gcm-v1"`. X-Wing
   has no IANA KEM-id, so this is a private-use suite-id string used consistently
   in every RFC 9180 `LabeledExtract`/`LabeledExpand`. It is a pure domain
   separator (cannot make the schedule *wrong*), but both sides must use the
   identical bytes. `encap_signing_bytes` =
   `x25519_ephemeral_pub(32) ‖ u32_be(len) ‖ mlkem768_ciphertext` (the
   `algorithm` field is deliberately excluded; length-delimited).

3. **`RecordType` CBOR `"typ"` integer encoding** — `SelfRecord=1`,
   `FamilyRecord=2`, `CommunityRecord=3`, `FederationRecord=4` (`0` reserved).
   Not enumerated by the FSD; pinned here.

## Conformance: `record_id` canonical CBOR

`derive_record_id` builds the §2.4 preimage as RFC 8949 §4.2.1 **core
deterministic** CBOR, 4-entry map, canonical key order `v, epc, iid, typ`
(shorter-encoded-key first, then lexicographic), minimal-length integers,
definite lengths only. The pinned vectors in `scope_privacy::tests` assert the
exact preimage bytes **and** the resulting `record_id`; CIRISConformance's
cross-impl `record_id` reproducibility test (§9) verifies CIRISEdge matches them.
