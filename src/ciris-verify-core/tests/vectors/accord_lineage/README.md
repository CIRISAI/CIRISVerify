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
charter versions are in v2, below.

# Accord lineage vector v2 (persist's charter rows)

`accord_lineage_v2.json` is CIRISPersist's v2 vector, vendored byte for byte
from persist commit `864b038` (`tests/vectors/accord_lineage/accord_lineage_v2.json`,
produced by `src/federation/accord_lineage_vector.rs`). That commit is on an
unpushed persist branch and is to ship in persist v62. **Pending:** re-vendor
it from persist's v62 tag; the file must keep SHA-256
`d3ace82cbf7fe3749e51601125efa0012f2af46a27ef542166fa127dec607191`
(LF line endings), which the harness pins. Do not edit it here.

It adds to v1:

| Version | Kind | Door |
|---------|------|------|
| v4 | charter version: removes `vec-holder-d`, adopts a new charter that re-lists, for `vec-holder-a2`, the commitment v3 spent | `verify_accord_roster_change` |

and `charters`, the three charter rows as persist stores them (the
`Attestation`, with the commitments at
`attestation_envelope.recovery_commitments`), each named by its own
`persist_row_hash`: v1 adopts the first, v2 (kept by v3) the second, v4 the
third. v1–v3 are v1's versions unchanged. `expected` names the commitment in
force at the head for each seated holder and the commitments spent.

`tests/accord_lineage_v2_vectors.rs` pins the file's digest, reproduces every
version's canonical bytes, row hash and link and every charter row's hash,
rebuilds v4 byte for byte and accepts it, accepts v3's recovery over the
charter rows, and replays `expected` through
`recovery_commitment_in_force_with_charters` (the spent commitment is in force
for no one at v3 or v4, though v4's charter re-lists it).

## The recovery refusals v2 (verify-authored)

`accord_recovery_refusals_v2.json` is verify's, built on
`accord_lineage_v2.json` and made by `tests/accord_recovery_refusals_v2.rs`
(same drift check, same `CIRIS_ACCORD_REFUSALS_REGENERATE=1`). Both cases stand
at persist's v4 and offer a recovery of `vec-holder-a2` to `vec-holder-a3`
through `verify_holder_recovery_with_charters`, with `charter_rows` naming
which of persist's charter rows the reader is given. The keys the cases add
(`vec-holder-a2-recovery`, `vec-holder-a3`, `vec-holder-a3-recovery`) are in
`added_keys`, from the same seed rule; `vec-holder-a2-recovery` is the key v3's
`next_recovery_commitment` commits to.

| Case | Recovery key | Charter rows | Refusal (`LiveQuorumError`) | With every row |
|------|--------------|--------------|-----------------------------|----------------|
| `spent_commitment_relisted` | `vec-holder-a-recovery` (spent by v3, re-listed by v4's charter) | all three | `RecoveryKeySpent` | `RecoveryKeySpent` |
| `charter_missing` | `vec-holder-a2-recovery` (in force) | v4's withheld | `CharterMissing` (index 3) | accepted |

CC 4.2.6 cites these: a commitment once spent never returns, even when a
later charter re-lists it, and a charter row the walk needs and is not given
fails closed rather than being skipped. Signatures are genuine and checked in
the test.
