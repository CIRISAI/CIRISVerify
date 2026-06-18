# FSD-002: Federation Identity Codes (`fedcode`) & Identity Onboarding

**Status**: Draft
**Author**: Eric Moore, CIRIS L3C
**Created**: 2026-06-18
**Owns**: `ciris_verify_core::fedcode`, `ciris_verify_core::federation_identity`
**Consumed by**: CIRISServer, CIRISAgent (KMP client), CIRISRegistry, CIRISPersist
**Grounds in**: CIRIS Constitution 0.1.5 (cited as **CC §x**)

---

## 1. Purpose

A **fedcode** is the one compact, user-shareable encoding of a federation
entity's identity — a QR / text string (`CIRIS-V2-XXXX-XXXX-…`) carrying a
`key_id`, an Ed25519 public key, and small display/transport hints, **tagged
with the entity's kind** so any consumer applies the correct rules from the code
alone. It generalizes the v1 `NodeCode` from "a node's peering business card"
into the federation's universal identity/onboarding primitive.

This FSD locks down three things that were previously implicit or ad-hoc:

1. **The `key_id` format** — collision-free, verifiable, human-readable.
2. **The `fedcode` wire format** — kind-tagged, byte-exact, cross-impl.
3. **The usercode → owner onboarding flow** — "drop my usercode in a server's
   config and it becomes mine" without a PIN/QR handshake.

CIRISVerify owns the reference implementation (`ciris_verify_core::fedcode`);
every other component consumes it through the verify wheel / FFI so there is
**one codec**, never a second to keep in lockstep.

---

## 2. The entity taxonomy (from the Constitution)

Two orthogonal axes already exist in CC; fedcode names points on them.

### 2.1 `identity_type` — what a key *is* (CC §3.4.7.1)

| kind | `identity_type` | multiplicity | owner-binding |
|------|-----------------|--------------|---------------|
| **user** | `user` | **self-multiplicity** — one self across N device keys (CC §3.3.6 `identity_occurrence` + OR-of-N) | IS the accountable human; root of all binding |
| **agent** | `agent` | **occurrence-multiplicity** — one key across N runtime occurrences (`occurrence_id`/`occurrence_count`/`occurrence_role`, CC §2.1) | MUST be owner-bound to a `user` |
| **node** | `node` | one fabric node | MUST be owner-bound (except `infrastructure` trust-and-serve, CC §2.5.0.7) |

**Owner-binding (CC §1.13.2 / §2.5.0.7)** is the spine:

> `is_owner_bound(K)` ≔ a live, unrevoked path from `K` to a `federation_keys`
> identity `U` with **`user ∈ U.identity_type`**, where each step is: `K` *is*
> `U`; `K` is an admitted `identity_occurrence` of `U` (CC §3.3.6); or a live
> `delegates_to(U → K)` (CC §2.4.1).

Authority always roots in an **accountable human** (`user`-role). A bare
node/agent is *canonical-trust-and-serve only* until owned.

### 2.2 `subject_kind` — rostered groups (CC §3.2 / §3.3.4)

| kind | `subject_kind` | carries | semantics |
|------|----------------|---------|-----------|
| **family** | `family` (CC §3.3.4) | `family_key_id` | intimate roster; structural-invisibility (CC §5.2) |
| **community** | `community` (CC §3.2) | `community_key_id` | larger roster; admission-gated; provenance-visible |

One identity MAY belong to multiple families/communities (CC §4.4.3.4 Policy L);
the group code carries the group's `*_key_id` so the consumer resolves the right
roster + DEK + `consensus_protocol` admission.

### 2.3 The five kinds

```
FedKind ∈ { user, agent, node, family, community }
```

This is the complete set and it adds **no new structural primitive** — the kind
is a 1-byte payload discriminator (the same discipline as `subject_kind` riding
the single `scores` shape, CC §3.3.2). A consumer reading a code knows
immediately: *is this a self (user, self-multiplicity), an agent (occurrence
multiplicity, needs an owner), a node, or a rostered group?* — and applies the
matching rules.

---

## 3. `fedcode` wire format (v2)

A strict **superset of v1 `NodeCode`**: a `kind` byte after the version, a
trailing `group_key_id` hint, under a bumped `CIRIS-V2-` prefix. **v1 codes
still decode** (as `kind: node`) so existing node-codes keep working.

### 3.1 Binary payload

```text
version(1) = 0x02
kind(1)              # 1=user 2=agent 3=node 4=family 5=community
sha256(key_id)(32)   # integrity binding of the display key_id
ed25519_pubkey(32)   # raw
LP(key_id)           # 1-byte length prefix + UTF-8 bytes
hint(transport_hint) # 0x00 absent, else LP
hint(alias_hint)     # 0x00 absent, else LP   (display name only — NOT signed PII)
hint(group_key_id)   # 0x00 absent, else LP   (family/community only)
```

Then **CRC-16-CCITT** (poly `0x1021`, init `0xFFFF`) over the payload, appended
as 2 bytes **big-endian**. Then **RFC-4648 base32, no padding** (alphabet
`A–Z2–7`). Display form: prefix `CIRIS-V2-` + the base32 grouped into **4-char**
dash-separated chunks. QR form: the same, ungrouped. Decoders normalize
(drop whitespace, uppercase, strip dashes) and accept the undashed prefix.

All string fields ≤ 255 bytes. The `sha256(key_id)` field binds the display
`key_id` into the CRC-protected payload (a corrupted/edited display key_id flips
the CRC).

### 3.2 Reference implementation

`ciris_verify_core::fedcode`:

```rust
pub enum FedKind { User, Agent, Node, Family, Community }
pub struct FedCode { kind, key_id, pubkey_ed25519_base64,
                     transport_hint, alias_hint, group_key_id }
pub fn encode(&FedCode) -> Result<String, FedCodeError>      // CIRIS-V2-…
pub fn encode_qr(&FedCode) -> Result<String, FedCodeError>   // ungrouped
pub fn decode(&str) -> Result<FedCode, FedCodeError>         // v2 + legacy v1→node
```

CRC / base32 / hint-encoding / grouping are **byte-identical** with the v1
`node_code_codec.py` (CIRISAgent) and `nodecode.rs` (CIRISServer). The v2
superset MUST be implemented identically in both — see §7.

---

## 4. `key_id` format — `label-fingerprint`

A federation `key_id` is an entity's **federation address** (CC: the
human-readable Ed25519 `signer_key_id`, e.g. `ciris-registry-main-v1`). To make
it **conflict-free, verifiable, and friendly**:

```
key_id = "<label>-<fingerprint>"
fingerprint = first 10 base32 chars of sha256(ed25519_pubkey), lowercased
```

`ciris_verify_core::fedcode::derive_key_id(label, ed25519_pubkey)`.

- **Collision-free by construction** — the suffix is bound to the key, so two
  entities choosing the same `label` never collide. No registry round-trip is
  needed to avoid collisions.
- **Verifiable** — anyone recomputes the suffix from the pubkey and confirms the
  `key_id` belongs to that key (a random UUID cannot do this — you could claim
  someone else's UUID).
- **Friendly** — `eric-moore-k7f3qd2pza` reads as a name, not a hash.

The `label` is lowercased and reduced to `[a-z0-9-]` (cosmetic); the fingerprint
is the cryptographic anchor. Registry global-uniqueness remains a backstop, but
correctness does not depend on it. **10 base32 chars = 50 bits**; a deployment
expecting >2³² identities under one label SHOULD raise
`KEY_ID_FINGERPRINT_LEN`.

This supersedes the interim `sha256(pubkey)`-hex default (an unfriendly
full-hash) — `identity create` now takes `--label` and derives the `key_id`.

---

## 5. Identity onboarding — usercode → owner (the "it just shows up" flow)

Goal: *"Put my usercode in a node/server's config and it becomes one of my
devices — no PIN, no QR handshake."* The honest constraint (CC §1.13.2):
owner-binding MUST be a **user-signed** `delegates_to` — the node cannot make
itself owned merely by reading your pubkey. So:

### 5.1 Flow (constitution-clean; **the chosen model**)

1. **Config.** The node's config carries the owner's **usercode**
   (`kind: user`, the owner's `key_id` + Ed25519 pubkey).
2. **Self-register.** On boot the node decodes the usercode, learns its intended
   owner `U`, and self-registers as a **pending `identity_occurrence` of `U`** —
   emitting its own side (the occurrence key, `device_class`, transport binding)
   addressed to `U`. It is *trust-and-serve only* until owned (CC §2.5.0.7).
3. **Appears in the device list.** `U`'s client lists pending occurrences that
   name `U` as owner.
4. **One-tap owner-binding.** `U` taps approve; their YubiKey-rooted key signs
   the `delegates_to(U → node)` grant (the existing `self_at_login` /
   `sign_delegation` producer). `is_owner_bound(node)` now holds.

No PIN, no QR exchange — the only human action is one approval tap, which is
exactly where CC wants the human signature. The pending-until-approved window is
the safety property: a stolen usercode (it is **public** — just a pubkey) lets a
node *request* ownership, never *obtain* it, because approval is a hardware
signature by `U`.

> **Rejected alternative (model 2): pre-authorized capability.** The usercode
> could embed a short-lived, scope-limited signed delegation so the node binds
> with no tap. More automatic, but it is a **bearer credential** (theft = silent
> ownership), so it is NOT the default. If ever added, it MUST be
> expiring + scope-limited + revocable, and is out of scope for this FSD.

### 5.2 What each component does

| step | component |
|------|-----------|
| derive `key_id`, produce usercode, sign the genesis `KeyRecord` | **CIRISVerify** (`fedcode` + `federation_identity`) |
| read usercode from config, self-register the pending occurrence | **CIRISServer** / the node |
| list pending occurrences, drive the one-tap approval | **CIRISAgent** (KMP client) |
| verify the `delegates_to` signature, write the binding | **CIRISServer** (verify wheel) → **CIRISPersist** |

---

## 6. The verify consume surface (easy to consume)

`ciris_verify_core::fedcode` — Rust:
`FedKind`, `FedCode`, `encode`, `encode_qr`, `decode`, `derive_key_id`,
`KEY_ID_FINGERPRINT_LEN`.

**Shipping now:** the Rust API above; and `ciris_verify_create_federation_identity`
(C FFI + Python) already returns the entity's `code` alongside the `key_id` +
CEG object, so the create flow is consumable end-to-end. `identity create
--label <handle>` derives the `key_id`, seals the hybrid key (YubiKey Ed25519 +
TPM/SE-sealed ML-DSA-65), emits the self-signed genesis `KeyRecord` to the CEG
outbox, and prints the owner's **usercode** (to copy into a node config).

**Fast-follow (consume surface):** standalone codec FFI — `ciris_verify_fedcode_encode`
/ `_decode` / `_derive_key_id` (JSON in/out) + the `ciris_verify` Python bindings —
so a consumer that only needs to *decode* a scanned code (the KMP client's device
list; a server reading a config usercode) reaches the same codec without the full
create flow. Tracked on the cross-repo issues (§7).

---

## 7. Cross-impl obligations

The codec is wire-shared. To keep "one codec":

- **CIRISVerify** (this FSD): reference impl + FFI. **Done.**
- **CIRISServer**: implement v2 in `nodecode.rs` (or consume verify's via FFI);
  add usercode-in-config → self-register-pending-occurrence; the one-tap
  `delegates_to` verify path. *(Issue.)*
- **CIRISAgent**: implement v2 in `node_code_codec.py` (or consume verify's wheel);
  the `agentcode` / `usercode` kinds; the pending-occurrence device list +
  one-tap approval UI. *(Issue.)*
- **CIRISRegistry**: accept `label-fingerprint` `key_id`s; enforce global
  uniqueness as a backstop. *(Tracked.)*

**Conformance:** the §3.1 byte layout + the §4 `key_id` derivation are the
contract; a second implementation is judged byte-for-byte against
`ciris_verify_core::fedcode`.

---

## 8. Security & privacy notes

- A fedcode is **public** — `key_id` + pubkey + non-authoritative hints. It is
  not a secret and confers no authority by itself (§5.1).
- `alias_hint` is a **display name only**, never signed, never PII-bearing. Real
  name / email do **not** belong in a fedcode or a `KeyRecord` (CC
  data-minimization; the federation identity is cryptographic). PII lives in the
  consent-gated app/portal layer, keyed by `key_id`.
- The `key_id` fingerprint binds the address to the key; the `sha256(key_id)`
  field + CRC bind the display form into the code. Neither replaces a signature —
  admission/owner-binding still require the hybrid signatures (FSD-001).

---

## 9. Open items

- `KEY_ID_FINGERPRINT_LEN` (50 bits) — confirm adequate for the largest expected
  single-label population; raise if needed (wire-compatible — it only changes the
  derived string, not the codec).
- Group codes (`family`/`community`): the roster-admission handshake beyond
  carrying `group_key_id` is CC §3.2/§3.3.4 + Registry admission — specified
  there, referenced here.
- Model-2 pre-authorized capability (§5.1) — deferred.
