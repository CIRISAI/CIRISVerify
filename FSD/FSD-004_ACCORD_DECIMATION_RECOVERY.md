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
| **Holder recovery** | the holder alone, under their pre-committed recovery key | a new roster version changing only that holder's seat (its signing key), carried by a recovery statement naming the next recovery commitment; no quorum |

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
- **No minimum roster size.** CC 4.2.6 states none: a roster change may leave one member, and a
  shrunken roster freezes but can still fire. The verify-side `N_min = 2` (H5) and
  `LiveQuorumError::RosterTooSmall` are removed.
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
it names. The holder's **next** recovery commitment rides in the recovery statement that
carries the version (pre-rotation). The charter is not re-scrubbed. The commitment **in force** for
a holder is the one named by the latest recovery version that seated their current key,
else their charter entry. A recovery version that changes anything else — another seat,
the threshold, the charter — concludes nothing, and so does one whose recovery key does
not hash to the commitment in force.

**The link is `persist_row_hash`** (CC 3.2 T6, annex 8.11 in rc20). A roster version is
CIRISPersist's `Family` record (`accord_live_quorum::FamilyRecord`), and every version
names its predecessor by `prev_head_digest` = the predecessor's **`persist_row_hash`**,
empty (absent) at genesis. `persist_row_hash` is persist's row identity, enforced at every
persist door (`accord_roster_change_unbound`, `accord_recovery_statement_unbound`):
lowercase-hex SHA-256 over the stored record's serde value without `persist_row_hash` and
`consent_role`, every instant truncated to microseconds, written in persist's Python
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` form
(`ciris_verify_core::persist_canonical`). It is **not** the SHA-256 of the record's JCS
bytes: the two differ on any non-ASCII character, on key order above U+FFFF and on
sub-microsecond instants. `roster_version_digest` returns it, and an `accord_proposal`'s
`prior_family_digest` is the standing head's.

The change that carries a version is persist's shape, and its signers sign its JCS bytes:

- a **roster change** (`accord_genesis::build_membership_change` /
  `verify_membership_change`) is `{kind: "ciris.accord_roster_change.v1", family_key_id,
  prior_persist_row_hash, next_persist_row_hash, changes: [{remove, add: [{key_id,
  role}], decision}]}`, each change naming the digest of the authorized decision whose
  `payload_sha256` is the change's `seat_change_digest`; the offered version keeps every
  member but the seats, the `charter_digest` it names and the head link; a strict majority
  of the standing roster cosigns;
- a **recovery** (`accord_live_quorum::build_holder_recovery` / `verify_holder_recovery`)
  is the statement `{kind: "ciris.accord_recovery.v1", family_key_id,
  prior_persist_row_hash, next_persist_row_hash, old_holder_key_id, new_holder_key_id,
  recovery_key_id, next_recovery_commitment}`, signed by the recovery key alone over
  persist's `ceg_produce_canonicalize(statement)`, which is verify's `jcs::canonicalize`;
  the offered version swaps the old seat for `{new key, joined_at, the seat's role}`.

`prior_persist_row_hash` and the offered `prev_head_digest` are the standing version's
`persist_row_hash`, `next_persist_row_hash` the offered version's. The persist vector
`src/ciris-verify-core/tests/vectors/accord_lineage/accord_lineage_v1.json` (persist commit
`e943482e`) pins the hash, both envelopes and their bytes. Four rulings on CC 4.2.6 apply:

- **(a) The commitment in force is found by walking the lineage.** A later roster version
  need not repeat a seat's `recovery_commitment`. Where the holder's current key was seated
  by a recovery, the charter entry is the commitment that recovery *spent*, so falling back
  to it would be wrong. `recovery_commitment_in_force(charter, lineage, holder_key_id)`
  takes the stored roster versions oldest first (genesis to standing head), each with the
  change envelope that admitted it, and checks every link: each version's
  `prev_head_digest` is its predecessor's `persist_row_hash`, its envelope's
  `prior_persist_row_hash` / `next_persist_row_hash` bind the same pair, and each stored
  `persist_row_hash` recomputes. It walks back from the head while the key stays seated. The
  version that newly seated the key supplies the answer: if a recovery statement seated
  it, that statement's `next_recovery_commitment`; if an ordinary roster change or genesis
  did, the charter's `recovery_commitments` entry. An incomplete lineage (empty, not
  starting at genesis, a missing or wrong link, a version without its envelope) fails
  closed with `LineageIncomplete`; it never falls back to the charter. `verify_holder_recovery` resolves the commitment itself from
  `charter` and `lineage`, so a caller cannot pass the spent one.
- **(b) No minimum roster size**, on recoveries and on ordinary roster changes (above).
- **(c) A recovery whose next commitment equals the commitment it spends concludes
  nothing** (`RecoveryReusesCommitment`).
- **(d) A recovery naming the signing key already seated concludes nothing**
  (`RecoveryReusesSigningKey`), whether built (`build_holder_recovery`) or presented.

As at persist's door, a recovery key that already rotated a seat in the lineage is spent
(`RecoveryKeySpent`). Persist also bounds a recovery's commitment to the charter in force
when it was made (a version naming a new charter commits every seat afresh); verify's walk
does not, and reads the recovery's commitment until the key is reseated.

A recovery version that changes anything else concludes nothing, as above.

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
  `ciris.accord_proposal.v1`. `payload_sha256` is the `seat_change_digest` of the
  proposed seat change; `prior_family_digest` the standing head's `persist_row_hash`.
  The nonce is proposer-minted.
- **`accord_participation`** — `{ family_key_id, proposal_digest, member_id,
  proof_of_life: true, vote: <yes|no|abstain>, window_until, signed_at, signature }`
  under `ciris.accord_participation.v1`. Entering `L` and voting are the same act.
- **`accord_decision`** — the proposal, the participations collected in `W`, the tally
  and whether it carried. No steward attestation.
- **Roster change envelope** — `ciris.accord_roster_change.v1` (§4.6), cosigned over its
  JCS bytes by a strict majority of the standing roster; it carries the new roster version.
- **Recovery statement** — `ciris.accord_recovery.v1` (§4.6), signed over its JCS bytes by
  the holder's recovery key alone; it carries a roster version with one seat rotated. Both
  carry roster versions; neither is a fourth object.

## 7. Verification logic

All **fail-closed**.

1. `accord_live_quorum::tally_live_quorum` — each participation resolves to a member of
   the standing roster in the pinned directory, its signature verifies over its
   canonical bytes bound to the proposal digest, a member counts once; `L` = distinct
   valid participants; votes tallied.
2. `accord_live_quorum::verify_membership_change_by_live_quorum(proposal,
   participations, standing, change, directory)` — the proposal binds the seat change
   (`payload_sha256 = seat_change_digest`) and the standing head (`prior_family_digest =`
   its `persist_row_hash`); the change applies to the standing roster; signers resolve
   only among the members at the standing head; no minimum roster size applies.
   `authorized = 2·yes > N_standing` (`roster_change_carries`), reported with
   `standing_count`.
3. `accord_genesis::verify_membership_change(standing, offered, change_envelope,
   quorum_signatures, decisions, directory, now)` — persist's roster-change door: the
   envelope binds the family, the standing head and the offered version by
   `persist_row_hash`; the offered record changes only the seats, the charter it names and
   the head link; each change is covered by a distinct authorized, closed decision on the
   standing head binding exactly it, and applied in order they give the offered roster;
   a strict majority of the standing roster cosigned the envelope's JCS bytes; the offered
   roster resolves to distinct pubkeys. Returns the seated keys.
4. `accord_live_quorum::verify_holder_recovery(charter, lineage, offered, statement,
   recovery_key, signatures, directory)` — the statement binds the family, the head of
   `lineage` and the offered version by `persist_row_hash`; the old key is seated, the new
   key is a different, unseated, registered key with its own pubkey (d); the offered record
   is the standing one with only that seat swapped; a well-formed next commitment; the
   commitment in force is resolved by `recovery_commitment_in_force` over `lineage` (a);
   the next commitment differs from it (c); the recovery key hashes to it (constant time)
   and is unspent; exactly one signature, by the recovery key, hybrid, over the
   statement's JCS bytes.
5. `accord_live_quorum::decisions_equivocate` — two decisions off one standing head
   into different rosters are a fork (CC 3.2 T6).
6. `humanity_accord::verify_invocation` — verifies a `constitutional` / `notify` /
   `drill` / `lifecycle:confirmed` / `lifecycle:active` row at
   `InvocationKind::required_signatures`.
7. `accord_halt_latch::HaltLatch` — the halt state machine (pause, idempotent second
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
| `N_min` | smallest roster a change may produce | **none** (CC 4.2.6 states no minimum) |

## 10. Deployment

The always-listening, off-grid, EMP-hardened, geographically distributed HF↔RNS
Transport Nodes that bridge proof-of-life into the mesh (§4.7) belong in a deployment
spec. Each holder's recovery key is held offline and apart from the signing key.

## 11. Relationship to existing modules

- **Records are CIRISPersist's.** The roster version is persist's `Family`
  (`accord_live_quorum::FamilyRecord`), its identity `persist_row_hash`
  (`persist_canonical`), and the roster-change envelope and recovery statement are
  persist's shapes (§4.6). `accord_genesis::validate_membership_change_structure`, the
  `supersedes`-envelope builders `build_accord_membership_change` /
  `verify_accord_membership_change` and the seat `recovery_commitment` /
  `supersedes.recovery_of` members are removed in 23.0.0.
- **Does not** add an invocation verb: decimation is a quorum-computation rule over
  the existing `CONSTITUTIONAL` kind (CC 4.2.6).
- **Removed in 23.0.0:** `verify_fire_by_live_quorum`, `FireVerdict`,
  `verify_resume_by_live_quorum`, `ResumeVerdict`, `L_FLOOR`, the steward parameters
  and `used_steward_backstop`, the removal-continuity check (`RemovedAbsentMember`),
  `verify_recovery_supersede` (H7 restore) and its `RecoveryNotKnownGood`,
  `AccordAction::{Fire, Resume}`, `WrongAction`, `HaltMismatch`.
