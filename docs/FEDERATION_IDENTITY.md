# Federation Identity Provisioning Runbook (single hardware-rooted identity)

**Status:** DRAFT (2026-06-18). Operator walkthrough for the 6.0 `ciris-verify
identity create` flow. Provisions **one** hardware-rooted federation identity
on a YubiKey **PIV** key. The wire shape is **not yet frozen** — the
`registration_envelope` `purpose` and a few field names are pending
CIRISServer / CIRISPersist cross-confirmation (see the code comments in
`federation_self_record.rs`). Where this runbook and the CLI `--help` /
runtime errors disagree, trust the binary.

---

## 1. What this is, in one paragraph

You are creating a **single** hardware-rooted federation key — one identity, one
`KeyRecord`. This is **not** the multi-founder HUMANITY_ACCORD ceremony (see
[`ACCORD_KEY_GENESIS_RUNBOOK.md`](ACCORD_KEY_GENESIS_RUNBOOK.md) for that; the
two are deliberately different — §9 below). The identity is a **hybrid keypair**:
Ed25519 (classical) rooted on a **YubiKey PIV key** (PIV / PKCS#11 — **not** the
OpenPGP applet the ACCORD runbook uses) **+** a **software ML-DSA-65** half (no
YubiKey has a PQC applet in 2026). The output is a **self-signed genesis
`KeyRecord`** dropped into the CEG outbox at
`~/ciris/ceg/outbox/federation_key_record/<key_id>.json`. **CIRISServer** drains
that outbox and relays the record to Persist `federation_keys` via `register_key`.

**Verify cannot complete the federation ID by itself.** It produces and signs the
object offline — it is offline crypto. **CIRISServer broadcasts it over CEG.**
Until the server drains the outbox, your identity exists only as a signed file on
disk.

## 2. Prerequisites

- **YubiKey firmware ≥ 5.7** — Ed25519 in the PIV applet requires 5.7+. Confirm
  with `ykman info`. (Pre-5.7 firmware has no Ed25519 PIV support; this flow will
  not work on it.)
- **`ykman`** (YubiKey Manager CLI) to provision the PIV key.
- **A PKCS#11 module** that exposes the PIV applet — either `libykcs11.so` (ships
  with `yubico-piv-tool`) or `opensc-pkcs11.so` (OpenSC). Paths below assume
  `/usr/lib/x86_64-linux-gnu/libykcs11.so`; adjust for your platform.
- **A `ciris-verify` build with the `pkcs11` feature**:
  ```
  cargo build --release -p ciris-verify-core --features pkcs11
  ```
  (Without `--features pkcs11`, the `token` and `identity` subcommands are not
  compiled in.)
- **CIRISServer running against the same `~/ciris` root** — it must see the same
  `~/ciris/ceg/outbox/` directory this tool writes to. If you override the root
  with `$CIRIS_HOME`, the server must use the same value.

## 3. Provision the Ed25519 PIV key

Generate the Ed25519 signing key **on the device** (it never leaves the token),
and populate the slot's certificate so PKCS#11 enumerates it. Slot **9c** (PIV
"Digital Signature") is the conventional choice for a signing key.

```
ykman info                          # confirm firmware >= 5.7
ykman piv keys generate --algorithm ED25519 --pin-policy ONCE --touch-policy ALWAYS 9c piv_pub.pem
ykman piv certificates generate --subject "CN=ciris-federation" 9c piv_pub.pem   # populate the slot
```

- `--touch-policy ALWAYS` is the "a human was physically present for this
  signature" property. Every owner-binding signature will require a touch.
- `--pin-policy ONCE` caches the PIN for the session after first use; choose
  `ALWAYS` instead if you want a PIN prompt on every operation.
- The certificate step is **not** cosmetic — PKCS#11 discovery (step 4) keys off
  the certificate object in the slot. A slot with a key but no cert may not
  enumerate.

## 4. Discover the key handle

```
ciris-verify token probe --module /usr/lib/x86_64-linux-gnu/libykcs11.so --pin
```

Enter the PIV PIN when prompted. The probe lists the objects on the token; look
for the line marked **Ed25519 ✅ federation owner-binding** — that is the key you
just generated. **Copy its label / id** (the value you pass as `--key-label` in
the next steps). Keys that are not Ed25519 are listed but are not eligible to be
the federation owner-binding key.

## 5. Prove the token can sign (optional but recommended)

```
ciris-verify token sign-test --module /usr/lib/x86_64-linux-gnu/libykcs11.so --key-label "<label-from-probe>" --pin
```

This does an **on-token sign + verify** round-trip: it asks the YubiKey to sign a
test message and verifies the result against the slot's public key. Tap the token
when it blinks. Expect **on-token verify ✅** and **federation key ✅ Ed25519**. If
this fails, fix the token (wrong label, missing cert, wrong PIN, or a non-Ed25519
key) **before** running `identity create` — `create` performs a real signature and
will fail the same way.

## 6. Create the identity

```
ciris-verify identity create --module /usr/lib/x86_64-linux-gnu/libykcs11.so --key-label "<label-from-probe>" --identity-type user --pin
```

**Tap the YubiKey when it blinks** — the Ed25519 half is touch-gated
(`--touch-policy ALWAYS`), so the signature will not complete without a physical
touch. What happens:

1. The tool derives / loads the software ML-DSA-65 half (see the caveat in §8
   about where the seed lives).
2. It builds the genesis `KeyRecord` and computes the signing bytes as
   `JCS(registration_envelope)`.
3. It produces the **bound hybrid self-signature** (Ed25519 on the token +
   ML-DSA-65 in software; the PQC half covers the classical signature, per
   `ciris_crypto::HybridSigner` discipline).
4. It writes the signed record to:
   ```
   ~/ciris/ceg/outbox/federation_key_record/<key_id>.json
   ```

`--identity-type user` tags the record as a user identity; use the identity-type
the CLI `--help` lists for your case.

## 7. What CIRISServer does (the relay)

You don't run this — CIRISServer does, against the same `~/ciris` root:

1. **Drains** `~/ciris/ceg/outbox/federation_key_record/`.
2. **Verifies** the bound hybrid self-signature over `JCS(registration_envelope)`
   — both halves must verify.
3. **Calls `register_key`**, which writes the record through Registry's policy
   layer into Persist `federation_keys`.
4. **Moves the file** to `~/ciris/ceg/sent/...`.

**Confirm success via the `sent/` path:** once the file has moved from
`outbox/federation_key_record/` to `sent/`, the server has accepted and relayed
it. If it lingers in `outbox/`, the server either isn't running against this root
or rejected the record (check its logs).

## 8. Security caveats (read before you treat this key as "hardware-protected")

- **Ed25519 is hardware-non-extractable + touch-gated.** Good — the classical half
  genuinely lives on the token and requires a physical touch per signature.
- **The ML-DSA-65 seed is sealed at rest** under `~/ciris/keys` (#71
  `get_platform_sealed_mldsa65_signer`): **TPM-sealed** when you build
  `--features tpm` on a TPM host, Secure Enclave / StrongBox on mobile, or a
  software AES-GCM-sealed blob (derived key) as the fallback — **never a plaintext
  file.** The honest boundary that remains: ML-DSA-65 *signing* is software (no
  token/TPM/SE can sign PQC yet), so the seed is unsealed into process memory to
  sign — a much higher bar than reading a file at rest. **A TPM-sealed seed is
  bound to that machine's TPM** and cannot be unsealed elsewhere, so it is *not*
  portable: enroll a second device's key (OR-of-N redundancy) rather than copying
  the seed. Build the desktop CLI with `--features pkcs11,tpm` to get TPM sealing
  (without `tpm` you get the software-sealed fallback). See `THREAT_MODEL.md`
  AV-44 for the full disclosure.
- **`$CIRIS_HOME` overrides the root.** If you set it, set it consistently for both
  this tool and CIRISServer, or the server will drain a different outbox than the
  one you wrote to.
- **`CIRIS_PKCS11_PIN` supplies the PIN non-interactively** — convenient for
  scripting, but the value is **`/proc`-visible** (environment of a running
  process). **Prefer the interactive `--pin` prompt** for anything but throwaway
  test tokens.
- **The wire shape is not frozen.** The `registration_envelope` `purpose` and field
  layout are pending CIRISServer / Persist cross-confirmation (see the comments in
  `federation_self_record.rs`). A future server may reject records produced by an
  older binary if the shape changes — don't mass-provision against an unconfirmed
  wire shape.

## 9. Relation to the other identity docs

- [`ACCORD_KEY_GENESIS_RUNBOOK.md`](ACCORD_KEY_GENESIS_RUNBOOK.md) — the
  **multi-founder HUMANITY_ACCORD** ceremony (6 keys, 3 humans, entrenched
  **family** `quorum:2/3`).

The differences are **deliberate**, not incidental:

| | This runbook (`identity create`) | ACCORD runbook |
|---|---|---|
| **Classical-half custody** | YubiKey **PIV** applet (PKCS#11) | YubiKey **OpenPGP** applet (GnuPG) |
| **Scope** | a **single** genesis identity | an **entrenched family quorum** (3 founders) |
| **Output** | one self-signed `KeyRecord` → CEG outbox | 6 `federation_keys` rows + the `humanity-accord` family Contribution |
| **Tooling** | one command (`identity create`) | manual ceremony (no single command) |

Both produce **bound hybrid Ed25519 + ML-DSA-65** identities with the same
soft-underbelly PQC-half-in-software reality — but the PIV-vs-OpenPGP applet
choice and the single-identity-vs-family-quorum scope are the load-bearing
distinctions. Don't conflate them.
