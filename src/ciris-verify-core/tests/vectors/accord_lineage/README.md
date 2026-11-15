# Accord lineage vector

`accord_lineage_v1.json` is CIRISPersist's cross-implementation vector for the
accord roster lineage (CC 3.2 T6, annex 8.11). It is vendored byte for byte from
CIRISPersist, branch `vec-accord-lineage`, commit `e943482e`
(`tests/vectors/accord_lineage/accord_lineage_v1.json`, produced by
`src/federation/accord_lineage_vector.rs`). Do not edit it here; regenerate it
in persist and copy it over.

**The vector is synthetic.** Every key is a deterministic test signer (seed =
the key id's bytes over a `[0x11; 32]` overlay) and every instant is fixed.
Nothing in it comes from the baked HUMANITY_ACCORD genesis.

## What it holds

Three versions of one family record, each admitted by persist's real doors:

| Version | Kind | Door |
|---------|------|------|
| v1 | genesis | `put_family_local` |
| v2 | roster change adding `vec-holder-d` | `verify_accord_roster_change` |
| v3 | holder recovery `vec-holder-a` → `vec-holder-a2` | `recover_accord_holder` |

Each version carries the offered and stored family record, the
`canonical_bytes` (`utf8` and `hex`) its `persist_row_hash` hashes, the hash and
its `prev_head_digest`. v2 and v3 also carry the change envelope, its signing
bytes, the quorum signatures and the charter digest. `keys` lists every public
key. `canonicalizer_rules` holds the canonicalizer probes (non-ASCII, non-BMP,
escapes, key order, floats, integer extremes), the instant truncations and the
omitted-Option rule.

## What pins it

`tests/accord_lineage_vectors.rs` reproduces every `canonical_bytes` byte for
byte through `ciris_verify_core::persist_canonical`, every `persist_row_hash`,
every probe and instant, rebuilds v2's and v3's change envelopes, offered
records and signing bytes from v1 plus the vector's inputs, and verifies the
roster change and the recovery with the vector's signatures and keys.

## The recovery refusals (verify-authored)

`accord_recovery_refusals_v1.json` is **verify's** file, built on top of
`accord_lineage_v1.json`. It is made by `tests/accord_recovery_refusals.rs`,
which rebuilds it from scratch and fails on any difference
(`CIRIS_ACCORD_REFUSALS_REGENERATE=1` rewrites it). Each case is a recovery of
`vec-holder-a` under `vec-holder-a-recovery`, against a lineage taken from
persist's versions, that CC 4.2.6 (rc20) refuses:

| Case | Refusal (`LiveQuorumError`) |
|------|-----------------------------|
| `next_commitment_reused` | `RecoveryReusesCommitment` |
| `same_signing_key` | `RecoveryReusesSigningKey` |
| `recovery_key_as_signing_key` | `RecoveryKeyAsSigningKey` |
| `lineage_not_from_genesis` | `LineageIncomplete` |
| `lineage_gap` | `LineageIncomplete` |

Every recovery signature is genuine, made by persist's deterministic signer
for the recovery key and checked in the test, so a door that verifies
signatures first still reaches the refusal under test. Cases that follow
charter versions (a spent commitment re-listed by a later charter; a missing
charter row) need persist's charter rows and are not in v1.
