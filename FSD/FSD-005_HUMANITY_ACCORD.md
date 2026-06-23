# FSD-005 — The Humanity Accord: What & Why

**Status:** DESCRIPTIVE — documents shipped behaviour as of **CIRISVerify v7.2.0**
(2026-06-23). This FSD specifies the *what and why* of the HUMANITY_ACCORD: the
constitutional kill-switch whose authority to halt a CIRIS agent is rooted in
hardware-attested human custody. The recognition root, custody attestation, and
invocation-concurrence mechanisms described here are **implemented and released**
(see §9 status table); the recovery-under-decimation behaviour is specified
separately in **FSD-004** and is not yet implemented.

**Tracks:** CIRISVerify#91 (custody), #95/#104 (growable M-of-N), #107 (baked
recognition root), #116 (real-hardware custody), #117 (registration bridge).
**Builds on:** FSD-001 (protocol), FSD-003 (federation identity codes).
**Constitutional grounding:** CIRIS Constitution §9.1 (entrenched `family`),
CC 4.2.1 (invocation concurrence), CEG §9.1/§9.2/§9.4. **Extended by:** FSD-004
(live-quorum operation & recovery under decimation).

---

## 1. Purpose — what the Humanity Accord is

The **HUMANITY_ACCORD** is the last-resort, constitutionally-grounded ability of
**accountable humans** to halt a CIRIS agent — and, critically, an ability whose
**custody is cryptographically provable rather than asserted.**

Concretely, as shipped:

- A fixed set of **human holders** (genesis: three people, six FIPS hardware
  tokens — three primary keys `A1`/`B1`/`C1` + three cold spares `A2`/`B2`/`C2`).
- Each holder's signing key lives on a **genuine FIPS YubiKey**, and that fact is
  **proven by hardware attestation**, not claimed.
- The roster + the rule for exercising it (an **M-of-N quorum**, genesis `2/3`)
  are **baked into the verify binary at genesis** as a *no-trust-on-first-use*
  recognition root — every node recognizes who the holders are from cold start,
  **without asking a peer, a server, or the operator.**
- A holder quorum can **co-sign a constitutional invocation** (halt / notify /
  drill) that the federation verifies against that pinned root.

The one-sentence framing, stated so every clause survives a hostile read of the
source (§7 makes each clause checkable):

> An AI agent's halt authority, carried from genesis as a hardware-attested human
> quorum — post-quantum-signed at the authority layer, verifiable by the agent
> itself with no operator and no server in the loop.

## 2. Why it exists — the threat the Accord answers

The CIRIS mission permits autonomous agents to act in the world. The bounding
safety property is that **a misaligned or compromised agent must remain haltable
by accountable humans** — and that this off-switch must not be silently
defeatable by the party most motivated to defeat it: *whoever runs the code.*

Every weaker design fails one of these:

- **Operator-controlled runtime kill (the common "AI kill switch").** Trusts the
  operator and the running binary. A compromised, coerced, or self-interested
  operator — or a patched binary — simply doesn't fire. The authority is a
  promise.
- **Server-issued revocation.** Trusts a central service that can be seized,
  censored, or coerced, and that an agent off the network can't reach.
- **A single human with a key.** A stolen, lost, or coerced single token is a
  single point of failure in both directions (can't fire / forged fire).

The Accord's answer is **distributed human custody you can verify:**

1. **Distributed** — no single holder can fire (genesis `2/3`), and no single
   compromise forges a fire.
2. **Human** — the authority is named, accountable people, not a service account.
3. **Hardware-rooted** — a holder's key is proven to live on genuine FIPS
   hardware under PIN + touch, so "a specific authorized human was physically
   present" is a checkable fact.
4. **No-TOFU** — the roster is pinned at genesis in the binary; it cannot be
   silently relocated to a different set of "holders" by swapping a peer's answer
   or an operator's config.
5. **Post-quantum at the authority layer** — the genesis cosign and invocations
   are hybrid-signed (Ed25519 + ML-DSA-65) and *both halves are verified*, so the
   authority survives a cryptographically-relevant quantum computer (CRQC).

## 3. Constitutional grounding

The Accord is **not** a service trust root. It is the canonical **entrenched
`family`** instance under CIRIS Constitution §9.1 / CEG §5.6.8.9:

- `family_key_id: "humanity-accord"`, `family_name: "HUMANITY_ACCORD"`.
- `consensus_protocol: "quorum:2/3"`, `consensus_protocol_entrenched: true` — the
  entrenched flag may never be *lifted* by a later supersede (a roster change can
  grow/shrink/rotate members but cannot weaken the family below strict majority or
  drop entrenchment).
- **Structural invisibility:** holder key_ids are name-free (`A1`/`B1`/`C1` …),
  decoupling the cryptographic roster from the humans' identities.

This is deliberately distinct from `ciris-canonical`, which is an
`infrastructure` **community** (the service/registry trust root, founder-quorum,
federates publicly). The Accord's key material lives in CIRISPersist
`federation_keys` (`identity_type = accord_holder`); verify's job is the
hybrid-signature + custody + quorum checks, never the storage.

> **Reading discipline.** `family` (entrenched, §9.1, the Accord) vs `community`
> (`infrastructure`, the service root) are easy to conflate and are *different
> kinds of thing*. See CLAUDE.md "family vs community."

## 4. Architecture — three layers

The Accord is three cooperating mechanisms. Each is a separate signed CEG object
so the layers compose without coupling.

### 4.1 The recognition root — *who can fire* (no-TOFU)

`ciris_verify_core::accord_genesis`.

The genesis ceremony produces an entrenched-family `accord_family_genesis` object:
each holder emits a hardware-rooted `accord_holder` record
(`produce_accord_holder_record`), a coordinator builds the canonical family
envelope (`build_accord_family_envelope`), each founder **co-signs on their own
token** (`co_sign_accord_family` — no human ever signs another's key), and the
coordinator assembles the genesis after the quorum verifies
(`assemble_accord_family_genesis` → `verify_founder_quorum`, **2-of-3 of distinct
keys**, hybrid-required).

That genesis object is then **baked** into the verify binary
(`humanity_accord_genesis() -> Option<&'static SignedCegObject>`, #107). The
function returns `None` until a real ceremony genesis is pinned (no-TOFU: absence
means "not yet pinned", **never** "fetch it from a peer" — fetching would be
trust-on-first-use). As of v7.2.0 it returns the real genesis. A consumer resolves
the roster (`accord_roster_from_family`) and threshold
(`accord_quorum_from_family`) from this **pinned** object only.

### 4.2 The custody attestation — *the holders hold genuine hardware*

`ciris_verify_core::accord_custody_attestation` (#91).

A holder cannot merely *claim* its key is on a FIPS YubiKey — a patched verify
could forge that. So each holder ships a separate signed object
(`accord_holder_custody_attestation`) carrying the YubiKey **PIV slot-9c
attestation certificate**, signed inside the token by its factory slot-f9 key,
chaining `9c → f9 → …intermediates… → ` the **pinned Yubico attestation root**.

`verify_accord_custody_attestation` proves: (1) the bundle is holder-hybrid-signed;
(2) the 9c cert chains to the pinned root (variable-length path — Yubico's 2024-12
PKI is 5 levels); (3) the **attested key equals the holder's federation Ed25519
key**; (4) the Yubico extensions show **FIPS-certified + touch=always** →
`hardware_class: YubiKey_5_FIPS`. Fail-closed. Validated end-to-end against a
physical **YubiKey 5 FIPS fw 5.7.4** (v6.7.1).

`custody_attestation_to_platform_attestation` (#117) bridges a *verified* custody
attestation into a `ciris_keyring::PlatformAttestation::ExternalSecureElement`, so
the downstream substrate can admit/entrench a holder **non-interactively** once the
ceremony is done.

### 4.3 The invocation — *exercising the switch*

`ciris_verify_core::humanity_accord` (CC 4.2.1, #86).

One holder builds and signs an invocation of a **closed-vocabulary** kind, ships
it, and another holder concurs to reach `2/3`
(`co_sign_invocation` / `concur_accord_invocation` / `accord_invocation_status` /
`verify_invocation` — kind-agnostic, distinct-key, identity-bound). The vocabulary
is deliberately closed:

| `InvocationKind` | Wire | Meaning |
|------------------|------|---------|
| `Constitutional` | `accord:invoke` | the halt — `EmergencyShutdown CONSTITUTIONAL` |
| `Notify` | `accord:invoke` | a non-halting holder notification |
| `Drill` | `accord:invoke` | a rehearsal, non-binding |
| `LifecycleActive` | `lifecycle:active` | the *only* sanctioned resumption after a constitutional halt |

The `accord:invoke` preimage is normatively closed to `{Constitutional, Notify,
Drill}` (CC §4.2.1.1); `LifecycleActive` is therefore **wire- and
scope-isolated** — it signs a *distinct* canonical-bytes domain
(`LIFECYCLE_DOMAIN_PREFIX = "ciris.accord_lifecycle.v1\n"`), so no signature ever
crosses the invoke↔lifecycle boundary even with identical id/nonce/payload.

### 4.4 Portable high-secure custody (optional)

`ciris_keyring::usb_wrapped_mldsa65` (#88). The ML-DSA-65 seed can be
AES-256-GCM-wrapped onto a USB key under a key derived from the YubiKey's
deterministic Ed25519 signature over a domain-separated challenge — so **both** the
USB (ciphertext) **and** the YubiKey + PIN + touch are required to unwrap. The
YubiKey stays signing-only (no decrypt/KEX added). Portable, not machine-bound.

## 5. Cryptography — stated precisely (robust against prior art)

The Accord's defensibility depends on using **exact** terms. Two layers, with
*different* post-quantum properties:

- **Authority layer (the genesis cosign + invocations): fully post-quantum.**
  `verify_founder_quorum` checks **both halves — Ed25519 *and* ML-DSA-65 — of
  every founder signature** (hybrid-required since v5.7.0). So *who can fire* and
  *the act of firing* survive a CRQC.
- **Custody proof (the hardware-rootedness): classical-strength.** The YubiKey 9c
  attestation chains an **Ed25519** key to genuine FIPS hardware. **No shipping
  YubiKey performs ML-DSA**, so the PQC half is software-resident (sealed at rest,
  optionally USB-wrapped per §4.4) and is bound to the holder by directory record
  + the holder's own hybrid signature — **not** by an independent hardware
  attestation.

This is the correct hybrid threat model, not a gap: PQC covers the long-lived
authority against harvest-now-decrypt-later; the live-custody proof is a
present-tense hardware fact where Ed25519 is sufficient. **Do not** describe the
PQC half as hardware-attested — it isn't on the token.

**It is M-of-N authorization, not threshold cryptography.** Three *distinct*
hardware-held keys each produce a *distinct* hybrid signature; the policy is a
quorum over distinct signatures. It is **not** a Shamir-split single key jointly
computing one ML-DSA signature. Call it **"M-of-N quorum custody,"** never
"threshold ML-DSA" (that term belongs to the threshold-PQC research line).

**The quorum rule.** One rule everywhere a quorum is declared: valid iff
`2·M > N` (strict majority), `1 ≤ M ≤ N`, **no `1/2` escape hatch** and no `M==1`
single-point-of-compromise. Genesis is `2/3`; the family is growable
(`build_accord_family_envelope` derives `quorum:M/N` for the member count) and
rosters change through an entrenchment-preserving `supersedes` authorized by the
**prior** roster's quorum (#95/#104).

## 6. Honest boundaries

Stated plainly so no consumer or reader over-claims:

1. **Custody is Ed25519-strength.** §5 — the hardware proof covers the classical
   key; the PQC half rides by directory + signature.
2. **Enforcement is downstream.** Verify ships the *authority + custody + signed-
   invocation verification*. The agent actually **halting** on a verified `2/3`
   `Constitutional` invocation is the CIRISServer / WiseBus enforcement layer
   (`PROHIBITED_CAPABILITIES`). This FSD does not claim end-to-end actuation.
3. **Recovery under decimation is unspecified-as-shipped.** The standing-roster
   quorum **deadlocks** if most holders are lost. FSD-004 respecifies this as a
   live quorum; it is RATIFIED but **not implemented**.
4. **The hardware-class taxonomy and Yubico encodings are pinned to observed
   reality** (validated on fw 5.7.4) but a vendor PKI change is a deliberate
   re-pin, not an automatic follow.
5. **Legitimate-channel hardware is load-bearing.** A counterfeit token could ship
   a forgeable attestation; the custody guarantee assumes genuine-Yubico-via-
   legitimate-channels acquisition.

## 7. Verifiable claims — the receipts

Each public claim maps to a checkable artifact, so "prove it" gets specifics:

| Claim | Where it's proven |
|-------|-------------------|
| The genesis quorum verifies **both** hybrid halves | `accord_genesis::tests::humanity_accord_genesis_is_baked_and_quorum_valid` (re-verifies the 2-of-3 hybrid quorum, `count == 3`) |
| Verification is **offline / peer-free** | `humanity_accord_genesis()` is `include_str!`-baked into the binary; resolution uses only the pinned object |
| Custody chains to genuine FIPS hardware | `verify_yubikey_piv_attestation` (9c→f9→pinned Yubico root) + the `examples/validate_yubikey_attestation` real-key run |
| The roster is **named humans on real tokens** | the #118 ceremony artifacts: 6 holder records + 6 custody attestations + the 2-of-3-cosigned genesis |
| No single holder can fire / forge | strict-majority `2·M>N`, distinct-key gate (`reject_duplicate_member_keys`), identity binding |

## 8. Prior art — concede the territory, claim the delta

The **primitives are all established** and a sharp reviewer will name them:

- **M-of-N quorum over hardware tokens / witnessed key ceremonies:** the DNSSEC
  root KSK ceremony (distributed humans, physical keys, witnessed quorum, since
  2010), HSM crypto-officer quorums.
- **Hardware key attestation chaining to a pinned vendor root:** YubiKey PIV,
  Android KeyMint, Apple App Attest, FIDO2.
- **Threshold custody of a root of authority:** Shamir / CA-root ceremonies,
  crypto-asset cold storage.
- **Post-quantum threshold/multi-party signatures:** JPMorgan, PQShield, the NIST
  Multi-Party Threshold Cryptography track (this is *threshold* crypto — a
  different thing from the Accord's M-of-N multisig).

The **delta** — referent and composition, not primitive — is: every prior-art
quorum gates *a signing key or a transaction*; the Accord's quorum gates **the
cold-start recognition root that names which humans can halt an autonomous agent,
verifiable by the agent's own embedded verifier with no operator and no server.**
That application held up under adversarial search; a defensible public claim is
therefore **"the first open-source AI agent to ship"** this composition —
application-first, scoped to a verifiable public artifact — and **never** an
unscoped "first PQC/threshold/kill-switch" superlative (each of which prior art
defeats).

## 9. Status — shipped vs designed

| Capability | Module | Shipped |
|------------|--------|---------|
| HUMANITY_ACCORD genesis producer (entrenched family, 2/3) | `accord_genesis` | v6.4.0 |
| Invocation concurrence (CC 4.2.1, closed vocab) | `humanity_accord` | v6.5.0 |
| Portable USB-wrapped ML-DSA custody | `usb_wrapped_mldsa65` | v6.6.0 |
| Custody attestation (YubiKey PIV → pinned root) | `accord_custody_attestation` | v6.7.0 |
| Real-hardware validation (fw 5.7.4) | `examples/validate_yubikey_attestation` | v6.7.1 |
| Growable M-of-N + membership-change `supersedes` | `accord_genesis` | v6.8.0 |
| `accord:lifecycle:active` resumption scope | `humanity_accord` | v6.10.0 |
| Pinned no-TOFU genesis accessor (empty) | `accord_genesis` | v6.11.0 |
| Custody attestation produces on real hardware (#116) | `accord_custody_attestation` | **v7.0.0** |
| Custody → persist `attestation_evidence` bridge (#117) | `accord_custody_attestation` | **v7.1.0** |
| **Genesis BAKED — recognition root live (#107)** | `accord_genesis` | **v7.2.0** |
| Live-quorum operation & recovery under decimation | — | **FSD-004, not implemented** |
| Agent-halts-on-fire enforcement | CIRISServer / WiseBus | downstream |
| Client ceremony / invocation UI | CIRISAgent/client (KMP) | downstream |

## 10. Relationship to other documents

- **FSD-001** — the CIRISVerify protocol this rides on.
- **FSD-003** — federation identity codes (the `accord_holder` identity type, §9.3).
- **FSD-004** — live-quorum operation & recovery under decimation; the natural
  extension of §6.3 here. RATIFIED, not implemented.
- **CLAUDE.md** — current implementation status, module map, family-vs-community
  reading discipline.
- **docs/ACCORD_KEY_GENESIS_RUNBOOK.md** — the operator procedure for the genesis
  ceremony and per-key provisioning.
- **MISSION.md §1.7** — the kill-switch pillar in the mission framing.
