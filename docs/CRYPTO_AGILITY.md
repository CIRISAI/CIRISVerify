# Cryptographic Agility & Algorithm Migration

How CIRISVerify retires a signature algorithm and adopts a successor
without a wire-format break (`THREAT_MODEL.md` §10, PQC algorithm agility).

## The schema is already agile

No "third algorithm slot" is needed — the hybrid schema (`src/ciris-crypto/src/types.rs`) is already algorithm-agile:

- **`crypto_kind: [u8; 4]`** — a four-character whole-system identifier
  (Veilid pattern), `CRYPTO_KIND_CIRIS_V1 = b"CIR1"`. A wholesale
  cryptosystem change bumps this.
- **`ClassicalAlgorithm`** — a tagged enum: `EcdsaP256`, `Ed25519`,
  `EcdsaP384`. The signature carries its own algorithm tag.
- **`PqcAlgorithm`** — a tagged enum already enumerating five
  algorithms: `MlDsa44`, `MlDsa65`, `MlDsa87`, `SlhDsaSha2_128s`,
  `SlhDsaSha2_256s`. A successor to ML-DSA-65 is *already nameable*.
- **`SignatureMode`** — `ClassicalOnly` / `HybridRequired` / `PqcOnly`,
  so a future PQC-only posture is already expressible.

Because every signature is **self-describing** (it carries its
`crypto_kind`, both algorithm tags, and its mode), a verifier dispatches
on the tag. Adopting a successor algorithm is therefore **not** a
schema change — it is an enum variant plus a policy decision.

## The single agility gate

`HybridSignature::meets_federation_policy()` is the one place that
decides which of the schema's nameable algorithms are *currently
acceptable*. Today it requires:

1. `mode == HybridRequired` — both halves present.
2. `pqc.algorithm.meets_minimum_requirement()` — ML-DSA-44 rejected.

**An algorithm transition tightens this method. It does not touch the
schema, the canonical bytes, or any signed structure.** The schema
carries every algorithm; policy carries the verdict.

## Migration protocol — retiring a PQC algorithm

When ML-DSA-65 must be retired in favour of a successor `NEW` (already
an enum variant, or one added to `PqcAlgorithm`):

**Phase A — `NEW` accepted (additive, no break).**
Verifiers learn to verify `NEW`; `meets_federation_policy()` accepts
both `MlDsa65` and `NEW`. Signers still emit `MlDsa65`. Old and new
verifiers interoperate. No flag day.

**Phase B — `NEW` emitted.**
Once the fleet floor version verifies `NEW`, signers switch to emitting
it. Signatures already in the transparency log under `MlDsa65` keep
verifying — they are historical, and `MlDsa65` stays *accepted* even
after it stops being *emitted*.

**Phase C — `MlDsa65` retired.**
After a stated window, `meets_federation_policy()` is tightened to
reject `MlDsa65` for *new* signatures. Historical log entries remain
verifiable via the transparency log's append-only history (a retired
algorithm is still a *correct* algorithm for bytes signed while it was
current); only fresh signatures are rejected. This mirrors the
revocation-key rotation rule in `THREAT_MODEL.md` §9.2.

A transition window where a single signature must satisfy *both*
generations of verifier is handled by `crypto_kind`: a `CIR2` kind can
define a three-component layout if ever genuinely needed. It is not
needed for an enum-variant swap — Phases A–C cover that with the
two-slot schema intact.

## Classical-side and whole-system changes

- A **classical** algorithm change (e.g. `Ed25519` → `EcdsaP384`)
  follows the identical A/B/C protocol on `ClassicalAlgorithm`.
- A **structural** change to hybrid binding (how the PQC signature
  covers the classical one) bumps `crypto_kind` (`CIR1` → `CIR2`).
  `crypto_kind` mismatch is a hard verifier error
  (`CryptoError::CryptoKindMismatch`), never a silent downgrade.

## Invariants that never bend during a migration

- The PQC signature always covers the classical signature (no-strip
  binding) — true for every `crypto_kind`.
- A signature is verified against the algorithm in *its own tag*, never
  against a verifier-assumed default — no downgrade by omission.
- `meets_federation_policy()` is the only gate; no per-call-site
  algorithm allowlist may diverge from it.
- Retiring an algorithm never invalidates transparency-log history
  signed while that algorithm was current.

## Status

The agility schema and the policy gate (`meets_federation_policy`) are
implemented, and this document is the migration plan. No successor migration is in progress; ML-DSA-65 +
Ed25519 under `CIR1` remains the federation default.
