# HUMANITY_ACCORD ceremony artifacts — the auditable custody trail

These are the **real outbox artifacts** produced by an end-to-end HUMANITY_ACCORD
genesis ceremony: a 3-holder trio (6 keys — 3 primary SEATS + 3 vaulted spares) on
**FIPS YubiKey 5.7.4, PIV slot 9c Ed25519**, with the holders physically present and
touching their tokens.

The constitutional kill-switch's legitimacy depends on **anyone being able to
verify — not trust — that its keys live on real, FIPS-certified, touch-required
hardware.** These artifacts are that public proof, and the proof is
**machine-checked in CI** (see "Verify it yourself" below), not just asserted.

## Verify it yourself

```bash
cargo test -p ciris-verify-core --test accord_ceremony_custody -- --nocapture
```

That test re-runs the exact CIRISServer admission-gate verifier
(`verify_accord_custody_attestation`) over all 6 custody attestations here,
against the pinned **Yubico Attestation Root 1** (`yubico-attestation-root-1.pem`,
SHA-256 `62760C6A6EF91679F454C8902B80FD009825B3F25DA90F1FBACE2EC6586CD5A8`), and
asserts for every key: the 9c PIV attestation chains `9c → f9 → … → root`, the
attested key equals the holder's federation Ed25519 key, the FIPS-certified
extension is present, and the touch policy is "always" → `hardware_class:
YubiKey_5_FIPS`. All 6 pass (fw 5.7.4, FIPS ✓, touch=always ✓). CI failing this
test is a loud signal the audit trail no longer verifies.

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
- `yubico-attestation-root-1.pem` — the pinned Yubico trust anchor
  (`developers.yubico.com/PKI/yubico-ca-1.pem`), committed so verification needs
  no network. This is the durable **root**, not the rotating intermediate.

## Status (all shipped)

- **Genesis baked (v7.2.0).** `humanity_accord_genesis.json` here is semantically
  identical to the pinned `src/ciris-verify-core/src/genesis/humanity_accord_genesis.json`
  that `humanity_accord_genesis()` / `HUMANITY_ACCORD_GENESIS_JSON` returns — the
  no-TOFU kill-switch recognition root. The seated roster is the 3 primaries
  (A1/B1/C1), `quorum:2/3`; the 3 spares (A2/B2/C2) are vaulted, not seated.
- **#116** (hash-commit the ML-DSA-65 pubkey — these artifacts were produced with
  that fix) and **#117** (custody attestation → persist `attestation_evidence`
  bridge) are both shipped (v6.13.0/7.0.0, v7.1.0).
- **CIRISPersist#268** — the `accord_holder` admission gate's YubiKey/external-SE
  variant is the remaining registration/entrenchment step (downstream; these
  custody attestations are its fixtures).

## Safety

All material here is **public**: Ed25519 / ML-DSA-65 **public** keys, signed
records, and X.509 attestation certificate chains. No private key material —
the 9c signing keys are non-extractable on the YubiKeys and never left them.

## Provenance

Produced on the CIRISServer fabric node (loopback `/v1/accord/provision-holder`,
`/family/cosign`, `/genesis/assemble`) against CIRISVerify v6.13.0 + the #116 local
fix; ykcs11/yubico-piv-tool 2.7.3; YubiKey 5.7.4 FIPS.
