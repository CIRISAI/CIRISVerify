# FSD-004 — Accord Live-Quorum Operation & Recovery Under Decimation

**Status:** Normative. Tracks CIRIS Constitution **1.0-rc19, CC 4.2.6** (`live-quorum`, entrenched),
with CC 4.2.1 (invocation, halt fuse, resumption), CC 2.7.4 (a count is over the members at the head
its row names) and CC 3.2 T3 (the recovery-key commitment). Implemented in
`ciris_verify_core::accord_live_quorum` (roster changes and holder recovery), `humanity_accord`
(invocations) and `accord_halt_latch` (the halt latch). Server-side authoritative recompute is
CIRISServer's.

**Builds on:** FSD-001 (protocol), FSD-005 (the accord), the growable M-of-N accord family and
membership-change `supersedes` in `ciris_verify_core::accord_genesis`.

**Summary of the rules.**

| Action | Who | Mechanism |
|---|---|---|
| **Halt** (`constitutional`) | **one** holder | a self-contained, pre-signable invocation row; pauses agents on receipt. No proposal, window, vote, decision object or server-issued nonce |
| **Confirm a halt** (`lifecycle:confirmed`) | strict majority of the standing roster | names the halt (`confirms_halt_id`); a lone halt not confirmed lapses `halt_fuse_secs` after this node's receipt (default 86 400) |
| **Resume** (`lifecycle:active`) | strict majority of the standing roster | names the halt it ends (`resumes_halt_id`); ends any halt, confirmed or not |
| **Roster change** (add / remove / swap) | strict majority of the **standing roster** in yes-votes, `2·yes > N_standing` | `accord_proposal` → `accord_participation` (proof-of-life + vote) within `W` → `accord_decision`, with a proposer-minted nonce. Absence neither blocks nor helps |
| **Holder recovery** | the holder alone, under their pre-committed recovery key | a new roster version changing only that holder's seat (signing key + next recovery commitment); no quorum |

The fuse counts from receipt, never from the signed `asserted_at`, so a pre-signed halt is not dead
on arrival and a future-dated one cannot pause agents indefinitely. The per-kind thresholds live in
one function, `InvocationKind::required_signatures`.

### What changed (rc19, verify 23.0.0)

The earlier text of this FSD (ratified against CC 0.3 §4.2.6, implemented in verify 8.2.0) took a
roster change by a strict majority of the **live set** `L`, added a 2-of-3 regional-steward co-sign
when `|L| < L_FLOOR` (3), required a removed member to be in `L` (removal continuity), and let the
steward quorum restore a logged known-good roster over a captured one (H7,
`verify_recovery_supersede`). CC 4.2.6 as of rc19 (first amended in rc7, CIRISConstitution#139;
CIRISVerify#302) replaces all of that:

- **The denominator is the standing roster.** A roster change carries iff `2·yes > N_standing`,
  where `N_standing` is every member at the roster head the change names (CC 2.7.4). "Absence
  neither blocks nor helps, it is simply not a yes." `L` survives only as the record of the votes.
- **No second roster.** There is no steward backstop and no `L_FLOOR`.
- **No removal-continuity check.** A removal needs no vote from the member removed; a holder named
  for removal keeps fire authority through the lame-duck window instead (§4.4).
- **No restore and no contest.** "A removal that passes has, by construction, a majority of the
  whole roster behind it." The domain labels `ciris.accord_contest.v1` and
  `ciris.accord_restore.v1` are retired and MUST NOT be reused. `verify_recovery_supersede` was the
  H7 steward restore and is removed.
- **Pre-committed recovery keys** (new). A holder who lost signing-key material rotates their own
  seat under a recovery key committed in the charter (§4.6, `verify_holder_recovery`).
- **A fire is never a proposal.** `AccordAction` is `roster_change` only; `fire` / `resume` no
  longer parse, and `verify_fire_by_live_quorum` / `verify_resume_by_live_quorum` are removed.

---

## 1. Purpose

The HUMANITY_ACCORD kill-switch is the last-resort human ability to constitutionally
halt a CIRIS agent. Its trust rests on **distributed human custody**. A quorum taken
over the standing roster for *firing* would **deadlock under catastrophic loss**: if
most holders are gone, the switch becomes inoperable exactly when it matters most.

This FSD specifies how the accord **operates as holders are lost and regained**,
without a separate exceptional "recovery" protocol. Firing needs no quorum at all: one
holder halts. The roster is the capture vector, so it is changed only by a strict
majority of the **standing** roster, and it *stalls rather than yields* when too many
holders are gone (CC 4.2.6: "The firing decision never deadlocks; a roster decision
may"). Lost hardware, as opposed to a lost holder, is healed by the holder's own
pre-committed recovery key.

## 2. Threat model — adversarial-AGI first strike

The design target is the worst case the accord exists for: a misaligned
superintelligence executes a **first strike against its own off-switch** — the
human holders — before or while it acts against humanity.

**Scale.** The accord is assumed to have **grown** (growable M-of-N) to be
robust — e.g. **N = 21 holders, standing quorum 11-of-21** — and the strike reduces
the **reachable, key-capable** holders to **1 or 2**.

**Adversary capabilities (assume all at once):** kill/incapacitate holders
(keys permanently or temporarily unavailable); coerce/seize keys (signatures under
duress — worse than loss); **censor communications** (suppress a holder's "I am
alive," partition survivors — *under a first strike this is the expected condition,
not an edge case*); impersonate non-cryptographic signals; and race any window the
protocol introduces.

**What must survive:** the surviving human(s), however few, can still **fire** the
kill-switch. The adversary cannot forge a hybrid signature over a pinned key — so it
cannot *manufacture* a holder; it can only *remove* (kill/censor) or *compromise*
(coerce) existing ones.

**Non-goals.** Agent-side enforcement of an admitted invocation (CIRISServer /
WiseBus); physical security of the holders; recovery of a dead holder's private
*key*.

## 3. Design principle — minimize the missed fire

The accord exists to prevent **one** terminal failure: a rogue AI survives because
the humans **could not fire**.

- A **missed fire** is **terminal** — unrecoverable.
- A **false fire** (an agent halted in error) is a **recoverable** governance
  nuisance — the agent resumes (`lifecycle:active`, or the fuse).

The bias gradient is **fire (one live survivor) ≤ roster change (a majority of the
standing roster)** (CC 4.2.6):

- **Firing leans easiest of all.** One holder's `constitutional` row halts, at any
  roster size, with no window, and no rule here gates it.
- **The roster is counted over the standing roster.** Changing the roster is how the
  halt would be captured and is not needed to fire, so it may stall.
- **Un-firing takes a majority.** Confirming or ending a halt takes a strict majority of
  the standing roster. A lone halt that no majority confirms lapses after the fuse.

## 4. The roster mechanism

There is **no separate recovery protocol.** "Decimation" is simply the case where few
holders are reachable.

### 4.1 The participation window and the count

Every roster change is a **proposal** that opens a bounded **participation window**
`W`. Within `W`, each holder may respond with a **proof-of-life + vote** (§4.2). When
`W` closes:

- the **live set** `L` = the holders who proved life within `W` (always a subset of
  the standing roster — only real, pinned members count; an incoming member has no
  vote on its own seating);
- the change **counts its yes-votes against the standing roster**: it carries iff
  `2·yes > N_standing`, `N_standing` being every member at the head the change
  supersedes.

Absence is not a veto and not a yes: a holder who does not respond casts no vote and
**stays in the denominator**. The change carries or stalls on the yes-votes alone.

### 4.2 Proof-of-life records a vote — it is not a veto

A holder participates by signing a fresh **proof-of-life** over the proposal's
nonce (minted by the proposer, never a server), **bundled with their vote**. A
presumed-dead holder who resurfaces does **not unilaterally defeat** a proposal: they
rejoin, their vote is counted, and the proposal still carries if a strict majority of
the standing roster voted yes. *A living, reachable holder cannot be erased from a
decision without being counted and given a vote*, yet the family is never hostage to a
single absent signature. The nonce in the signed bytes stops a replayed signature
from manufacturing a phantom participant.

### 4.3 Thresholds

| Action | Threshold | Rationale |
|---|---|---|
| **Halt** (`constitutional`) | **1** holder, no window | missed fire is terminal, false fire recoverable |
| **Confirm / resume** (`lifecycle:confirmed` / `lifecycle:active`) | strict majority of the standing roster | the quorum sits on the recoverable act |
| **Roster change** (the `supersedes`) | **`2·yes > N_standing`** within `W` | seizure needs ⌊N/2⌋ + 1 coerced holders; censorship buys nothing |
| **Holder recovery** | the holder's recovery key alone | a roster change by that holder about themselves (§4.6) |

Under a majority of the *live* set, one coerced holder plus censorship of every honest
holder removes honest holders and seats puppets at any roster size. Under a majority
of the *standing* roster, censorship buys nothing and seating a puppet costs the same
majority as a removal (CC 4.2.6, "No second roster").

### 4.4 Removal cannot silence a firer (lame duck)

A holder named for removal keeps full fire authority until the removal's `W` has
closed and the decision is recorded; until then a valid `accord:invoke` row from them
fires. Verify enforces this by construction: a halt verifies against the roster the
consumer has pinned, and `verify_membership_change_by_live_quorum` only reports a
verdict — the caller pins the new roster once the decision is recorded. Nothing
requires the removed member to vote or to be in `L`.

### 4.5 Return and reinstatement (Enoch Arden)

A holder who proves life **after** a decision missed that vote and is re-enrolled
going forward. Past actions validly decided by the votes cast within their window
stand; the returnee simply rejoins.

### 4.6 Pre-committed recovery keys

Every holder carries a **recovery key**, committed in the accord's charter at seating
as `recovery_commitments` (`{holder_key_id: commitment}`), held offline and apart from
the signing key. The commitment is the CC 3.2 T3 form over a one-element array:
`lowercase_hex(SHA-256(JCS([{key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64}])))`,
binding key material, never a name. It states no end, and neither the recovery key's
record nor a holder's key record carries `valid_until`.

A **recovery** is a new version of the accord's roster record, **signed under the
recovery key alone**, changing **only** the rotating holder's own seat: the signing key
it names and that holder's **next** recovery commitment, which rides in the recovery
version (pre-rotation). The charter is not re-scrubbed. The commitment **in force** for
a holder is the one named by the latest recovery version that seated their current key,
else their charter entry. A recovery version that changes anything else — another seat,
the threshold, the charter — concludes nothing, and so does one whose recovery key does
not hash to the commitment in force.

In verify, the recovery version carries the next commitment on the holder's seat as
`recovery_commitment`, and its `supersedes` names the standing members, the standing
`consensus_protocol` and `recovery_of: <holder_key_id>`
(`accord_live_quorum::build_holder_recovery`). `recovery_commitment_in_force` reads the
seat's commitment, else the charter's.

When more than half the holders are lost the roster freezes: each survivor can still
fire, but no majority remains to confirm, so every halt is a lone one that lapses at its
fuse until fired afresh. Recovery keys shrink that case to deaths and incapacity rather
than lost hardware. A captured majority is answered by each node's own un-trust lever
(CC 3.2 T3) and re-rooting, not by any rule over the same holders.

### 4.7 The proof-of-life physical channel — reaching a relay without satellites

The whole mechanism rests on a holder being able to **get a signed proof-of-life
to a relaying node**. Under the §2 threat model the convenient channels are gone:
**assume satellites are down** (no Starlink/Iridium/GPS), grid power is unreliable,
and the internet is partitioned or hostile. Proof-of-life is a *tiny* payload (a
hybrid signature + vote, a few hundred bytes), so the requirement is not bandwidth
— it is **reach with no infrastructure.** That rules out the obvious mesh radio and
points squarely at **HF (shortwave) skywave**.

**Band selection (why not LoRa, why not VLF):**

- **LoRa / UHF mesh (433–915 MHz)** — Reticulum's usual `RNode` radio. Line-of-sight
  + modest NLOS, tens of km. Excellent as the **last hop** to a *local* relay, but it
  **cannot bridge continents** without standing infrastructure. Insufficient alone.
- **HF / shortwave (3–30 MHz)** — **the answer.** Ionospheric **skywave** gives
  **intercontinental** reach (thousands of km) and **NVIS** (near-vertical-incidence,
  ~2–10 MHz) fills the 0–~400 mi regional skip zone — both **requiring no satellites,
  repeaters, or internet** (the ionosphere is the "satellite"). This is the
  battle-tested grid-down / military / EmComm channel.
  ([NVIS overview](https://www.qsl.net/wb5ude/nvis/), [Skywave](https://en.wikipedia.org/wiki/Skywave))
- **VLF / ULF (< 30 kHz)** — *longer* range still and earth/water-penetrating, but
  **transmit** requires miles-long antennas and megawatt plants (national submarine-
  comms infrastructure). VLF *reception* is cheap; VLF *transmission* is **not
  buildable at any holder budget** — out of scope. (Receive-only VLF/MF as a
  one-way command backstop is a possible future note, not a proof-of-life path.)

**The mode is the relay: JS8Call over HF.** The payload rides a **weak-signal**
digital mode so it punches through globally at minimal power, and — critically —
the mode itself provides the **"node that repeats."** [JS8Call](https://js8call.com/)
(derived from FT8) decodes down to **−24 dB SNR on 5–25 W and a simple antenna**,
and its **store-and-forward** `@ALLCALL` inbox means *"any JS8Call station that hears
the message relays it… building a distributed message relay network"* until it
reaches its destination — exactly the repeat-toward-a-gateway behavior this design
needs, with no central server.
([JS8Call guide](https://www.hamradiobase.com/ham-radio-digital-js8call/))
VARA HF / Winlink is the higher-throughput alternative when conditions allow.

**The chain:** holder's HF station → JS8Call weak-signal beacon (NVIS for regional,
skywave/long-path for intercontinental) → **store-and-forward relay** across any
hearing JS8Call station → an **HF↔Reticulum gateway** (a Transport Node running a
KISS/VARA TNC bridging HF into RNS) → the mesh → CIRISServer live-quorum tally. The
signed proof-of-life is verifiable end-to-end regardless of how many untrusted RF
hops it traversed (the hybrid signature is the trust, not the path).

**A ~$50k resilient station (satellites-gone, off-grid):** an HF transceiver
(≈ $1–3k, e.g. IC-7300 / IC-7610) + a ~1 kW solid-state linear amplifier (≈ $4–6k)
+ a dual antenna system (an **NVIS** low-dipole for regional + a **directional
beam/vertical** for long-haul, with mast/tuner; ≈ $8–18k) + **fully off-grid power**
(solar + LiFePO₄ bank + generator; ≈ $8–12k) + a ruggedized controller (Raspberry
Pi running JS8Call + the Reticulum gateway; ≈ $1k) + **EMP/Carrington hardening**
(Faraday-stored spare transceiver + Pi + controller — because "satellites gone"
plausibly implies a kinetic/cyber/EMP event) + spares and a secondary site. $50k
comfortably funds a serious station *or* 2–3 redundant simpler ones for
geographic + failure diversity. **Time without GPS:** the proposal nonce is
minted by the proposer and relayed in (it does not depend on GPS); HF time standards
(WWV/WWVH/CHU) give coarse wall-clock if needed. A halt needs no round trip at all:
it is a pre-signable row carried in by the same channel.

> **Deployment note:** the **relay/gateway backbone** — the set of always-listening
> HF↔RNS Transport Nodes that carry proof-of-life into the mesh — is itself
> infrastructure an adversary will target. It must be **geographically distributed,
> off-grid, and EMP-hardened**. Under the standing-roster count, censoring it delays a
> roster change but cannot pass one.

## 5. Prior art

- **Ethereum inactivity leak (Casper FFG)** — measures the quorum against
  participants and lets the absent drop out of the denominator. This FSD's earlier
  text adopted that; rc19 deliberately does **not**: under a first strike the
  adversary chooses who is absent, so absence must not shrink the denominator of the
  capture vector. It survives only for firing, which needs one holder and no count.
  ([eth2book](https://eth2book.info/latest/part2/incentives/inactivity/),
  [Casper FFG paper](https://arxiv.org/pdf/1710.09437))
- **Social-recovery wallets (Argent / Safe / ERC-4337)** — guardian proposals + a
  **timelock window**; the window is our `W`. (Our proof-of-life is not the
  owner-veto of those systems — see §4.2; it is a counted vote, not a cancel.)
  ([overview](https://university.mitosis.org/intro-to-social-recovery-wallets-safe-argent-and-erc-4337/))
- **Pre-rotation (KERI)** — each key event commits to the next key's digest, so a
  rotation is authorised by a key that was never exposed. The recovery commitment and
  its successor (§4.6) are this, per holder.
- **Enoch Arden / rebuttable presumption of death** — the returning are reinstated
  going forward (§4.5).
  ([Cornell LII](https://www.law.cornell.edu/wex/enoch_arden_doctrine))

## 6. Protocol — CEG objects

All hybrid-signed (Ed25519 + ML-DSA-65, bound). None exists on the fire path.

- **`accord_proposal`** — `{ family_key_id, action: roster_change, nonce,
  window_until, prior_family_digest, payload_sha256 }`, line-format preimage under
  `ciris.accord_proposal.v1`. `payload_sha256` is the digest of the proposed
  membership-change envelope; `prior_family_digest` the digest of the standing head.
  The nonce is proposer-minted.
- **`accord_participation`** — `{ family_key_id, proposal_digest, member_id,
  proof_of_life: true, vote: <yes|no|abstain>, window_until, signed_at, signature }`
  under `ciris.accord_participation.v1`. Entering `L` and voting are the same act.
- **`accord_decision`** — the proposal, the participations collected in `W`, the tally
  and whether it carried. No steward attestation.
- **Recovery version** — the roster envelope (JCS) with one seat rotated, signed by the
  holder's recovery key alone (§4.6). It is a roster version, not a fourth object.

## 7. Verification logic

All **fail-closed**.

1. `accord_live_quorum::tally_live_quorum` — each participation resolves to a member of
   the standing roster in the pinned directory, its signature verifies over its
   canonical bytes bound to the proposal digest, a member counts once; `L` = distinct
   valid participants; votes tallied.
2. `accord_live_quorum::verify_membership_change_by_live_quorum(proposal,
   participations, prior_envelope, new_envelope, directory)` — the `supersedes` passes
   `accord_genesis::validate_membership_change_structure` (entrenchment, strict-majority
   `quorum:M/N`, distinct-pubkey gate, anti-replay anchor); the proposal binds the new
   envelope and the standing head; signers resolve only among the members at the
   standing head; the new roster has ≥ 2 members. `authorized = 2·yes > N_standing`
   (`roster_change_carries`), reported with `standing_count`.
3. `accord_live_quorum::verify_holder_recovery(standing, recovery, holder_key_id,
   commitment_in_force, recovery_key, signatures, directory)` — structure as in (2);
   only the holder's seat changes (key and `recovery_commitment`), every other seat and
   every other record member identical, `supersedes` names the standing head and the
   seat; a well-formed next commitment is installed; the recovery key hashes to the
   commitment in force (constant time); exactly one signature, by the recovery key,
   hybrid, over the recovery version's JCS bytes.
4. `accord_live_quorum::decisions_equivocate` — two decisions off one standing head
   into different rosters are a fork (CC 3.2 T6).
5. `humanity_accord::verify_invocation` — verifies a `constitutional` / `notify` /
   `drill` / `lifecycle:confirmed` / `lifecycle:active` row at
   `InvocationKind::required_signatures`.
6. `accord_halt_latch::HaltLatch` — the halt state machine (pause, idempotent second
   halt that does not reset the fuse, confirm-before-lapse, resume-by-name, lapse),
   fed only a `VerifiedInvocation` minted by `verify_for_latch`. Exposed on the FFI
   (`ciris_verify_accord_invocation_verify` / `_latch_apply` / `_latch_status`) and the
   wheel.

The roster-change and recovery verifiers have no FFI, wheel or CLI surface yet. The
**authoritative** tally is CIRISServer recomputing over pinned `federation_keys`; the
local objects are advisory. The window gate (arrival within `W`) is the caller's.

## 8. Security analysis

- **Fire.** A lone *false* or coerced fire is **cheap** (recoverable): it pauses
  agents and lapses after the fuse unless a majority confirms it. *Suppressing* a fire
  needs **total, sustained censorship of every honest holder on every channel**; a
  halt row is a publishable signature, not a round trip.
- **Roster change.** Removing an honest holder — the only way to strip a firer — needs
  yes-votes from a strict majority of the standing roster. An adversary that coerces
  fewer than half the holders cannot remove anyone however many honest holders it kills
  or censors, and the lame-duck window keeps a named holder's fire authority alive
  through `W`.
- **Recovery.** A recovery key confers nothing on anyone else: it can rotate only its
  holder's own seat, cannot touch the threshold or another seat, and adds no person to
  coerce.

Named residuals (CC 4.2.6): **coercion/duress** is bounded by the number of holders an
adversary must coerce, which is why the accord is meant to grow across jurisdictions;
**a coerced majority captures the roster**, answered by each node's un-trust lever;
**when more than half the holders are lost the roster freezes** — it can fire but
cannot replace anyone, and a new accord is formed by instantiation.

## 9. Parameters

| Parameter | Meaning | Setting |
|---|---|---|
| halt threshold | signatures for a `constitutional` halt | **1** |
| fire window | challenge window for a halt | **none** |
| `halt_fuse_secs` | time after receipt that an unconfirmed lone halt lapses | **86 400** (charter may override) |
| confirm / resume threshold | `lifecycle:confirmed` / `lifecycle:active` | strict majority of the standing roster |
| roster window `W` | participation window for a roster change | **72 h** (CC 2.6.7); under a declared severe-degradation state `window_until` MAY reach 7 d |
| roster threshold | yes-votes for a roster change | `2·yes > N_standing` |
| recovery | authority for a holder's own seat rotation | the committed recovery key alone |
| `N_min` | smallest roster a change may produce | 2 (verify-side, H5) |

## 10. Deployment

The always-listening, off-grid, EMP-hardened, geographically distributed HF↔RNS
Transport Nodes that bridge proof-of-life into the mesh (§4.7) belong in a deployment
spec. Each holder's recovery key is held offline and apart from the signing key.

## 11. Relationship to existing modules

- **Reuses** `accord_genesis::validate_membership_change_structure` and all its
  invariants for both the roster change and the recovery; only the authorization
  differs (standing-roster yes-votes, or the recovery key, instead of cosignatures).
- **Does not** add an invocation verb: decimation is a quorum-computation rule over
  the existing `CONSTITUTIONAL` kind (CC 4.2.6).
- **Removed in 23.0.0:** `verify_fire_by_live_quorum`, `FireVerdict`,
  `verify_resume_by_live_quorum`, `ResumeVerdict`, `L_FLOOR`, the steward parameters
  and `used_steward_backstop`, the removal-continuity check (`RemovedAbsentMember`),
  `verify_recovery_supersede` (H7 restore) and its `RecoveryNotKnownGood`,
  `AccordAction::{Fire, Resume}`, `WrongAction`, `HaltMismatch`.
