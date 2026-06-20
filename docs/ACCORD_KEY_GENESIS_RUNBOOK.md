# HUMANITY_ACCORD Key Genesis Provisioning Runbook

**Status:** DRAFT (2026-06-09). Genesis ceremony for the 3 HUMANITY_ACCORD
holders, 6 keys total. Scoped for the nascent-project genesis — proportionate
security, not a full production HSM ceremony. Production-hardening notes are
marked **[harden]**.

**Authoritative spec:** CEG 0.15 §9 (`CIRISRegistry/FSD/CEG/.../ceg-0.15.tex`).
This runbook is the operational counterpart; where it and the spec disagree,
the spec wins.

---

## 0. What you're provisioning, in one paragraph

Three named humans (Eric Moore, Eric Kudzin, Haley Bradley — CEG §9.1) each get
**two** accord-holder identities: a **primary** (goes in the live
`humanity-accord` roster) and a **cold-spare** (vaulted, swapped in only via the
replacement ceremony). 3 × 2 = **6 identities**. Each identity is a **hybrid
keypair**: Ed25519 (classical) **+** ML-DSA-65 (post-quantum), per CEG §5.2.1.
The `humanity-accord` structure is an entrenched **`family`** (`quorum:2/3`,
`consensus_protocol_entrenched: true`) — *not* a community (that's
`ciris-canonical`; don't conflate them).

## 1. The load-bearing hardware reality (read this first)

The accord signature is a **bound hybrid** Ed25519 + ML-DSA-65 over the same
canonical bytes (CEG §9.2.1) — **both halves required** to produce a valid
`accord:invoke:*`. But:

| Half | Where it lives | Extractable? | Touch-gated? |
|---|---|---|---|
| **Ed25519** | YubiKey 5 FIPS (OpenPGP applet) | **No** (hardware-bound) | Yes (`fixed`) |
| **ML-DSA-65** | **Software** (no YubiKey has a PQC applet, 2026) | Yes — so it MUST be protected at rest | No |

Consequence: "hardware-backed accord key" = **classical half in hardware,
PQC half in software.** The ML-DSA-65 private key is the soft underbelly — it
is a file. Its protection (air-gapped generation, encryption at rest, vaulting)
is the security-critical part of this ceremony. Don't let the YubiKey's nice
properties lull you into treating the whole key as hardware-protected.

Because the YubiKey Ed25519 key is non-extractable, **primary and spare are
different identities** (different Ed25519 pubkey → different `federation_keys`
row). They are not copies of one key.

## 2. Hardware + materials

- **6 × YubiKey 5 FIPS, FIPS 140-3 (firmware 5.7.4+).** The §9.4 `hardware_class`
  is `YubiKey_5_FIPS` (trust-multiplier 0.95). 140-3 is required so Ed25519 runs
  in FIPS Approved Mode (140-2 cannot — EdDSA wasn't approved pre-FIPS-186-5).
  USB-C (5C NFC) recommended. *(Sold out widely as of June 2026; expect end-of-June.)*
- **1 air-gapped machine** for ML-DSA-65 key generation (never network-connected
  during keygen; `[harden]` a dedicated live-USB on hardware that never touches
  the internet again).
- **3 regional steward keys available** (us / eu / apac) for cross-attestation
  (§9.3) — can be remote, they sign over published bytes.
- The three humans physically present (or in a synchronous secure session) — each
  must touch their own YubiKey and enter their own PINs. **No human provisions
  another's key.**
- `ykman` (YubiKey Manager CLI), GnuPG (OpenPGP/Ed25519 on the key), and the CIRIS
  tooling that wraps `ciris_crypto` hybrid signing + `jcs::canonicalize` (see §7).
- A secure vault for the 3 spares (sealed envelopes / safe / split-custody per
  your operational preference).

## 3. Pre-flight (per YubiKey, before any keygen)

For each of the 6 keys:

1. Confirm firmware ≥ 5.7.4 and FIPS: `ykman info` → check firmware + FIPS line.
2. **Set FIPS Approved Mode** if not already (so Ed25519 is in-boundary). Verify
   X25519 is *blocked* in approved mode — that's expected and fine (accord keys
   sign only; they never do key exchange).
3. Set a strong OpenPGP **PIN + Admin PIN** (the holder sets their own; on-device
   where the applet allows). Record nothing in plaintext.
4. Reset the OpenPGP applet to a known-clean state before generating the key.

## 4. Per-identity key generation (×6: 3 humans × {primary, spare})

Do this **once per YubiKey**, owned by that human, air-gapped for step 4.2.

### 4.1 Ed25519 on the YubiKey (classical half)

- Generate the Ed25519 signing key **on the device** (OpenPGP applet) — it never
  leaves the key. `gpg --edit-card` → `admin` → `generate` → choose ECC / Ed25519
  for the signing slot. **Do not** allow off-device generation + import.
- Set **touch policy `fixed`** for the signing key (`ykman openpgp keys set-touch sig fixed`)
  — touch required every signature, and `fixed` means it can never be downgraded
  to off. This is the "a specific human was physically present" property.
- Export the **public** key: `gpg --export --armor <fpr>` → `ed25519_pub` (and the
  raw 32-byte pubkey for the `federation_keys` row).

### 4.2 ML-DSA-65 in software (PQC half) — air-gapped

- On the **air-gapped** machine, generate an ML-DSA-65 keypair via `ciris_crypto`
  (`MlDsa65Signer::new()` → `public_key()`); FIPS 204 final, byte-compatible with
  the verifiers.
- **Encrypt the private key at rest immediately.** Minimum: AES-256-GCM under a
  passphrase the holder controls. `[harden]` wrap it to the holder's YubiKey
  (OpenPGP decryption subkey) so the software key can only be decrypted with the
  physical token present — re-coupling the PQC half to the hardware presence.
  **Tooled since v6.6.0 — the portable mode** (`accord … --portable-usb <dir>`,
  `ciris_keyring::usb_wrapped_mldsa65`): the ML-DSA-65 seed is AES-256-GCM-wrapped
  on a USB key under a key derived from the YubiKey's deterministic Ed25519
  *signature* (so the YubiKey stays signing-only — no decrypt capability added),
  requiring **both** the USB and the YubiKey + PIN + touch to unwrap, and making
  the identity **portable** rather than machine-TPM-bound. Provision it during §5
  (`accord holder --portable-usb …`).
- Export the **public** key → `mldsa65_pub` (1952 bytes).
- The encrypted ML-DSA-65 private key is this identity's most sensitive artifact.
  For a **primary**, it lives on the holder's signing machine (encrypted). For a
  **spare**, it goes into the vault *with* the spare YubiKey.

### 4.3 The identity = the pubkey pair

This identity is `(ed25519_pub, mldsa65_pub)`. Record both pubkeys + the
`hardware_class: "YubiKey_5_FIPS"` + a stable `key_id`
(e.g. `accord-eric-moore-primary`, `accord-eric-moore-spare`, …).

## 5. Build the `federation_keys` accord-holder rows (×6)

Each identity becomes a Persist `federation_keys` row, `identity_type=accord_holder`
(§9.3). The row is **self-signed at provisioning** (the holder signs the row's
canonical bytes with their own hybrid key — Ed25519 touch + ML-DSA-65) to prove
control of both halves.

- Canonical bytes for the row sign via **JCS / RFC 8785** (CEG §0.9) — use
  `ciris_verify_core::jcs::canonicalize` (or the `jcs_canonicalize` Python binding)
  so the bytes are byte-identical to what every verifier recomputes. **Do not**
  hand-roll the encoding.
- The hybrid signature: Ed25519 half via the YubiKey (touch), ML-DSA-65 half via
  the (decrypted-in-memory) software key, bound per `ciris_crypto::HybridSigner`
  discipline (PQC covers `bytes ‖ classical_sig`).

Row fields (confirm exact schema against CIRISPersist `federation_keys`):
`key_id`, `identity_type="accord_holder"`, `ed25519_public_key`,
`mldsa65_public_key`, `hardware_class="YubiKey_5_FIPS"`, `valid_from`,
self-signature.

## 6. Cross-attestation by the 3 regional stewards (§9.3)

Each of the 6 rows is cross-attested by **all three** regional stewards (us / eu /
apac). Each steward verifies the self-signature, confirms out-of-band that the
pubkey pair belongs to the named human (video call + read-back of the fingerprint
is fine for genesis), and signs an attestation over the row's JCS canonical bytes.
This is the recursive-provenance chain that lets a cold-start consumer trust the
accord pubkeys via `GET /v1/accord-holders` (§10.2) without TOFU.

`[harden]` require the fingerprint read-back over a second channel (not the same
video call) to resist a live MitM on the call itself.

## 7. Build + sign the `humanity-accord` entrenched-family Contribution

The **3 primaries** form the live roster (the 3 spares are NOT in it). The family
object (CEG §9.1):

```json
{
  "family_key_id": "humanity-accord",
  "family_name": "Humanity Accord",
  "members": [
    {"key_id": "accord-eric-moore-primary",    "role": "founder"},
    {"key_id": "accord-eric-kudzin-primary",   "role": "founder"},
    {"key_id": "accord-haley-bradley-primary", "role": "founder"}
  ],
  "consensus_protocol": "quorum:2/3",
  "consensus_protocol_entrenched": true
}
```

- Compute the signing bytes via **`jcs::canonicalize`** (CEG §0.9). Honor the
  omit-vs-materialize rule — sign exactly these members, don't inject defaults.
- The founders sign those bytes (each Ed25519-touch + ML-DSA-65). The
  consensus_protocol is `quorum:2/3`, so genesis is authorized by a **2-of-3
  quorum of distinct founder keys** — the *same* threshold the accord uses for
  everything. Genesis is **not** unanimous: founding must not require every
  holder present (that would defeat the fault-tolerance 2/3 exists for), and any
  2-of-3 is a trusted quorum under the accord's own model. Having all three sign
  at the ceremony is **recommended** (clean record of all-founder consent) but
  not required. *(Earlier drafts said "all 3 sign / `Ok(3)`"; corrected to 2/3 in
  v6.4.1 — unanimity was an inconsistency + a bootstrapping single-point-of-failure.)*
- Verify before publishing: `threshold::verify_founder_quorum(bytes, members, sigs, 2)`
  must return `Ok(n)` with `n ≥ 2`. The roster (`members`) is the full 3 founders;
  2-of-3 *of them* must validly sign. `consensus_protocol_entrenched: true` means
  the substrate will reject any future `supersedes` that weakens the protocol or
  moves admission off the founders — that's the entrenchment gate (#31).
- Roster integrity at genesis is the **distinct-key gate** (no key may fill two
  seats — `assemble_accord_family_genesis` enforces distinct Ed25519/ML-DSA
  pubkeys, since a single key could otherwise meet 2/3 alone) **plus** the §6
  steward cross-attestation (key↔human binding) — not unanimity.

## 8. Vault the 3 spares

For each human's spare identity: seal **{spare YubiKey + the encrypted ML-DSA-65
private key + its key_id and pubkeys}** into the vault. The spare is already
provisioned (§4–6, attested by the 3 stewards) but **not** in the live roster, so
it can be swapped in fast without re-running attestation. `[harden]` split the
ML-DSA-65 decryption secret across two custodians.

## 9. Acceptance test (before declaring genesis complete)

1. **Drill invocation.** Have 2 of the 3 primaries sign an `accord:invoke:drill`
   over the §9.2.1 canonical bytes (use `humanity_accord::Invocation::canonical_bytes`).
   Confirm `humanity_accord::verify_invocation` returns valid with **exactly 2**
   holder signatures, and that the same signature does **not** verify against a
   `CONSTITUTIONAL` or `notify` discriminator (cross-replay rejection — the whole
   point of §9.2.1).
2. **Quorum floor.** Confirm **1** signature is rejected (insufficient).
3. **Touch proof.** Confirm each signature required a physical touch (no signature
   without it → touch policy `fixed` is live).
4. **Round-trip the family.** Re-fetch the published `humanity-accord` Contribution,
   re-canonicalize with `jcs::canonicalize`, re-verify the 3 founder signatures.
   Byte-identical or it didn't land.
5. **Cold-start path.** From a clean consumer, `GET /v1/accord-holders`, verify the
   3 primary pubkeys against the steward cross-attestations, confirm they pin.

Mark genesis complete only when 1–5 pass. Use `drill`, never `CONSTITUTIONAL`, for
testing — and per §9.2.2 any human-visible surface MUST show `[DRILL]`.

## 10. Replacement / spare-swap (post-genesis, for reference)

If a primary key is lost/compromised, swap its spare in via the entrenched-family
replacement ceremony — **CEG §9.2 / `CIRISNodeCore/FSD/FEDERATION_ANNOUNCEMENT.md`
§4.5.3**. Because the family is entrenched, replacement is the *only* path to
change the roster, and it requires the existing quorum (2-of-3) to sign the
`supersedes` that swaps `…-primary` for `…-spare`. The spare is pre-attested
(§8), so the swap is a roster `supersedes`, not a fresh provisioning.

## 11. What's tooled vs. manual today (honest status)

- **Tooled (CIRISVerify ships it):** hybrid sign/verify (`ciris_crypto`),
  `jcs::canonicalize` (+ `jcs_canonicalize` Python binding) for the Contribution
  signing bytes, `threshold::verify_founder_quorum`, `humanity_accord::{Invocation,
  verify_invocation, InvocationDedup}` for §9.2.1, the `boundary_degraded` /
  hardware attestation surface, **and — since v6.4.0 — the producer side:
  `ciris_verify_core::accord_genesis` (`produce_accord_holder_record`,
  `build_accord_family_envelope`, `co_sign_accord_family`,
  `assemble_accord_family_genesis`) + the `ciris-verify accord` CLI, which wraps
  §5–§7 of this runbook** (the "future ceremony tool" called out below). The
  assembler verifies the accord's **2/3** founder quorum of distinct keys before
  anything reaches the outbox — the producer round-trips through
  `verify_founder_quorum`.
- **Persist/Registry side:** the `federation_keys` accord_holder row storage +
  the `GET /v1/accord-holders` endpoint + the 2-of-3 role-recognition RPC live in
  CIRISPersist (key material) + ciris-registry-core (verifier logic) per §9.3.
- **Manual ceremony (this runbook):** YubiKey Ed25519 generation + touch policy,
  air-gapped ML-DSA-65 generation + encryption, the steward cross-attestation
  read-back, vaulting. The CLI tools the *signing + assembly* (§5/§7); the
  hardware/air-gap/vault steps remain hands-on by design.

### 11.1 CLI — the `ciris-verify accord` ceremony commands (v6.4.0+)

```bash
# §5 — each holder, on their own machine, produces their accord_holder genesis
#       record (YubiKey via --module, else platform-sealed). → CEG outbox.
ciris-verify accord holder --key-id accord-eric-moore-primary \
    --module /usr/lib/.../libykcs11.so --key-label "…" --pin

# §7 step 1 — a coordinator builds the canonical family envelope (the 3 PRIMARIES,
#             roster order). No signing.
ciris-verify accord family-envelope \
    --member accord-eric-moore-primary \
    --member accord-eric-kudzin-primary \
    --member accord-haley-bradley-primary \
    --out family.json

# §7 step 2 — EACH founder co-signs family.json on THEIR token → a {signature,member}
#             bundle. No human signs another's key.
ciris-verify accord co-sign --envelope family.json --key-id accord-eric-moore-primary \
    --module … --key-label "…" --pin --out cosign-moore.json

# §7 step 3 — the coordinator assembles. Verifies the accord's 2/3 quorum of
#             DISTINCT founder keys; writes the genesis to the outbox only if it holds.
ciris-verify accord assemble --envelope family.json \
    --cosign cosign-moore.json --cosign cosign-kudzin.json --cosign cosign-bradley.json
```

`--module` omitted → the platform-sealed Ed25519 key (`~/ciris/keys`); the
ML-DSA-65 half is always the sealed software seed. Assembly is offline + tokenless.

> No single "provision-accord-genesis" command exists yet; this is the script
> humans run. A future ceremony tool could wrap §4–§7. — *partially done: §5–§7
> signing + assembly are now `ciris-verify accord` (§11.1). §4 keygen
> (YubiKey/air-gap) stays manual.*

## 12. Security non-negotiables (the short list)

1. **Touch policy `fixed`** on every Ed25519 signing key — non-downgradeable.
2. **ML-DSA-65 private keys generated air-gapped, encrypted at rest, never
   plaintext on a networked machine.** `[harden]` YubiKey-wrap them.
3. **No human provisions another's key**; each touches their own + sets their own PIN.
4. **All 6 rows cross-attested by all 3 stewards** with out-of-band fingerprint
   read-back.
5. **`jcs::canonicalize` for every signed-bytes computation** — never hand-roll JSON.
6. **Test with `drill` only**; `CONSTITUTIONAL` is real kill-switch authority.
7. Spares stay **out of the live roster** until a §9.2 replacement ceremony.
