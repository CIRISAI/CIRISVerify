# HUMANITY_ACCORD ceremony artifacts (real, for baking)

These are the **real outbox artifacts** produced by an end-to-end HUMANITY_ACCORD
genesis ceremony: a 3-holder trio (6 keys — 3 primary SEATS + 3 vaulted spares) on
**FIPS YubiKey 5.7.4, PIV slot 9c Ed25519**, with the holders physically present and
touching their tokens. Every cryptographic step succeeded; only the
register/entrench step is deferred (see the gap issues below). They are provided so
verify can **bake the no-TOFU genesis recognition root** and use them as fixtures.

## Contents

- `humanity_accord_genesis.json` — the assembled family genesis carrying the
  **2-of-3 founder cosignatures** (`founder_signatures`, 3 collected) over the
  family envelope. This is the seed for `humanity_accord_genesis()` /
  `HUMANITY_ACCORD_GENESIS_JSON` (accord_genesis.rs). This is the **full
  founder-signed `SignedCegObject`** (`kind: accord_family_genesis`, `key_id:
  humanity-accord`, 3 founder cosignatures) — **directly pasteable** into
  `HUMANITY_ACCORD_GENESIS_JSON` to bake `humanity_accord_genesis()`.
- `holders/{A1,A2,B1,B2,C1,C2}.json` — per-key bundles: `{ key_id, holder_record
  (SignedKeyRecord), custody_attestation (SignedCegObject) }`.
- `custody_attestations/{A1,A2,B1,B2,C1,C2}.json` — the `portable_2fa` custody
  attestations as standalone CEG objects (the FIPS-YubiKey PIV chain proofs).

## What these unblock / the open gaps

- **Bake** `humanity_accord_genesis()` from `humanity_accord_genesis.json` (the
  pinned, no-TOFU kill-switch recognition root).
- **#116** — custody attestation embedded the full ML-DSA-65 pubkey → oversized
  hardware-Ed25519 preimage (fixed locally by hash-committing; these artifacts were
  produced with that fix).
- **#117** — no path from a YubiKey custody attestation → persist
  `attestation_evidence`; these custody attestations are the fixtures for that
  wrapper + the new `PlatformAttestation` variant.
- **CIRISPersist#268** — the `accord_holder` admission gate has no YubiKey/external-SE
  variant, so these holders can't be registered/entrenched yet (no humans needed —
  it's a non-interactive wrap + admit).

## Provenance

Produced on the CIRISServer fabric node (loopback `/v1/accord/provision-holder`,
`/family/cosign`, `/genesis/assemble`) against CIRISVerify v6.13.0 + the #116 local
fix; ykcs11/yubico-piv-tool 2.7.3; YubiKey 5.7.4 FIPS.
