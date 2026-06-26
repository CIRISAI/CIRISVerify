# FSD-004 — Accord Live-Quorum Operation & Recovery Under Decimation

**Status:** RATIFIED + EXPANDED (constitutional grounding landed and generalized) — **not yet implemented.**
Changing how the kill-switch quorum is computed is a §9 governance change; nothing
here ships without (a) constitutional grounding in CEG §9 / the CIRIS Constitution —
**DONE: ratified in [CC 0.3 §4.2.6 `live-quorum`](https://github.com/CIRISAI/CIRISRegistry/blob/main/FSD/CIRIS_Constitution/part_4_composition_governance.md)** (CIRISRegistry `c27d794`, issue #108; ratified by the founder under the CC 4.5.1 maturity gate) — and (b) an adversarial review on par with #91/#95. Phase 0 is therefore complete on the constitutional axis; Phases 1–3 (implementation) are unblocked. (Originally DRAFT 2026-06-21; rewritten to the live-quorum model 2026-06-21.)

**Constitutional expansions since ratification (synced to CC 0.5, CIRISRegistry `19fb3d2`):**
- **CC 0.4 (`2fb7a2c`, §4.2.1.3) — the bias gradient + the resumption direction.** §4.2.6 firing is the *easy* end of an explicit gradient **`fire ≤ roster-change ≤ standing`**: firing leans easiest (floor = 1, a missed fire is terminal) and **un-firing leans hardest**. CC 0.4 ratifies the resumption verb `accord:lifecycle:active` (the *opposite* of a fire — resuming from a CONSTITUTIONAL halt) and pins it to **no less than the roster-change threshold — strict majority of the live set `L`, never a lone signature**, with the §4.2.6 steward backstop when `|L|` is small. This refines this FSD's §3 "always lean toward firing": the no-asymmetry rule is for the *fire* direction; *resumption* is deliberately asymmetric the other way. **⚠ Verify code gap:** CC 0.4 ratifies the v6.10.0 lifecycle:active layout **with one addition the implementation flagged open (its sub-Q1): the mandatory `resumes_halt_id` field** binding a resumption to the single halt it ends (anti-stockpile / anti-replay). `humanity_accord::canonical_bytes` does **not** yet emit `resumes_halt_id` — a one-field preimage change, tracked for the §4.2.1.3 / #109 lifecycle path (adjacent to this FSD).
- **CC 0.5 (`19fb3d2`, §4.5.13 `reverse-quorum`) — §4.2.6 generalized.** The live-quorum is no longer a one-off kill-switch rule; CC 0.5 ratifies it as the federation's **general governance shape** — *"presence is authority, absence forfeits it, a timer decides."* This FSD's accord live-quorum is now the **constitutional instance**; community-scope moderation is the **first community instance** (lone-survivor-fires ↔ lone-steward-acts; live-quorum-over-`L` ↔ live-majority-over-present-members; Enoch-Arden return ↔ merit re-auto-promotion). Same mechanism, two scopes. (CC 0.5's "stewardship reframe" also renamed the federation's `owner_bound` → `steward_bound` terminology throughout §4.5; the accord §4.2.6 surface is unchanged by it.)

**Tracks:** CIRISVerify#98. **Builds on:** FSD-001 (protocol), the v6.8.0 growable
M-of-N accord family + membership-change `supersedes` (`ciris_verify_core::
accord_genesis`), CEG §9.1/§9.2.

---

## 1. Purpose

The HUMANITY_ACCORD kill-switch is the last-resort human ability to constitutionally
halt a CIRIS agent. Its trust rests on **distributed human custody** — an M-of-N
strict-majority quorum of holders. As specified today that quorum is taken over the
**standing roster**, which makes it **deadlock under catastrophic loss**: if most
holders are gone, the standing quorum is unreachable, and the switch becomes
inoperable exactly when it matters most.

This FSD respecifies the quorum so the accord **operates continuously as holders
are lost and regained**, rather than treating "recovery" as a separate exceptional
protocol. The mechanism is a **live quorum**: every decision is taken over the set
of holders who actually show up, and *being reachable is how you participate*.

## 2. Threat model — adversarial-AGI first strike

The design target is the worst case the accord exists for: a misaligned
superintelligence executes a **first strike against its own off-switch** — the
human holders — before or while it acts against humanity.

**Scale.** The accord is assumed to have **grown** (v6.8.0 growable M-of-N) to be
robust — e.g. **N = 21 holders, standing quorum 11-of-21** — and the strike reduces
the **reachable, key-capable** holders to **1 or 2**.

**Adversary capabilities (assume all at once):** kill/incapacitate holders
(keys permanently or temporarily unavailable); coerce/seize keys (signatures under
duress — worse than loss); **censor communications** (suppress a holder's "I am
alive," partition survivors — *under a first strike this is the expected condition,
not an edge case*); impersonate non-cryptographic signals; and race any window the
protocol introduces.

**What must survive:** (1) the surviving human(s), however few, can still **fire**
the kill-switch; (2) the roster can be **reconstituted** so the accord remains
operable afterward. The adversary cannot forge a hybrid signature over a pinned key
— so it cannot *manufacture* a holder; it can only *remove* (kill/censor) or
*compromise* (coerce) existing ones.

**Non-goals.** Agent-side enforcement of an admitted invocation (CIRISServer /
WiseBus); physical security of the holders; recovery of a dead holder's private
*key* (gone — this is about the *roster*, not the key).

## 3. Design principle — minimize the missed fire (one direction, no asymmetry)

The accord exists to prevent **one** terminal failure: a rogue AI survives because
the humans **could not fire**. Among the error modes:

- A **missed fire** (the adversary decapitated everyone who could pull the plug) is
  **terminal** — unrecoverable.
- A **false fire** (an agent halted in error) is a **recoverable** governance
  nuisance — an agent can be re-licensed; humanity cannot be un-extincted.

Therefore **every lever is set to minimize the probability of a missed fire.** This
is a *single* optimization direction — there is no countervailing "make it harder"
force to balance, because the thing a brake would protect against (a false fire, or
a roster "coup") is either cheap-and-recoverable or is not actually mitigated by a
brake (§8). Concretely:

- **Firing leans easiest of all.** In deep decimation a constitutional kill is
  admissible on the smallest viable live set — down to a lone reachable survivor.
- **Reconstitution leans easy too**, not hard: a decimated-but-honest survivor set
  must be able to *rebuild a firing-capable roster*. Making reconstitution slow or
  high-bar would only help a suppressor (whose aim is to keep the switch
  un-fireable) — the exact opposite of the goal.
- The bias gradient is: **fire ≤ roster-change ≤ (former) standing quorum**, all
  taken over the *live* set, never over the absent standing roster.

(An earlier draft of this FSD posited a "failure-direction asymmetry" — fire easy,
reconstitution hard. That was wrong: it set a brake against a coup, but a coup's
worst act is either a recoverable false fire or a suppression that requires
majority capture *regardless* of reconstitution speed. The brake only handicapped
the honest survivors. This rewrite removes it.)

## 4. The mechanism — one live quorum

There is **no separate recovery protocol.** There is one mechanism — the live
quorum — and "decimation" is simply the case where the live set is small.

### 4.1 The live set and the floating quorum

Every accord decision (fire, roster change, or both) is a **proposal** that opens a
bounded **participation window** `W`. Within `W`, each holder may respond with a
**proof-of-life + vote** (§4.2). When `W` closes:

- the **live set** `L` = the holders who proved life within `W` (always a subset of
  the standing roster — only real, pinned members count);
- the decision is tallied **over `L`**, at a per-action threshold (§4.3).

Absence is self-correcting: a holder who does not respond is simply **not in the
denominator** for that decision — they cannot block by being gone. Presence is
self-asserting: showing up puts you in `L` with a vote. This is the **inactivity-
leak dynamic** (Casper FFG, §5) made into the accord's *standing* rule rather than
an emergency exception.

### 4.2 Proof-of-life *modifies the quorum and carries a vote* — it is not a veto

A holder participates by signing a fresh **proof-of-life** over the proposal's
server-issued nonce, **bundled with their vote** on the proposal. This does two
things:

1. **Modifies the quorum** — the signer enters `L`, so the live denominator (and
   thus the strict-majority threshold) *floats up* to include them. If 21 → 2
   reachable and three more prove life mid-window, `|L|` becomes 5 and the
   roster-change bar becomes 3-of-5.
2. **Carries a vote** — the same signature records yes/no on the proposal.

A presumed-dead holder who resurfaces therefore does **not unilaterally defeat** a
proposal — they **rejoin and are counted**, and the proposal still succeeds if the
live majority supports it. The protection this buys is the correct one: *a living,
reachable holder cannot be erased from a decision without being counted and given a
vote* — but the family can still act by its live majority (it is not hostage to a
single signature). The freshness nonce prevents a replayed signature from a truly-
absent holder manufacturing a phantom participant.

### 4.3 Per-action thresholds (the firing bias)

All thresholds are taken **over `L`**, never over the absent standing roster.

| Action | Threshold over `L` | Rationale |
|---|---|---|
| **Fire** (CONSTITUTIONAL kill, §9.2.1) | **floor = 1** — a **single reachable survivor** may fire (Q1 resolved) | missed fire is terminal, false fire recoverable → lean easiest |
| **Roster change** (add / remove / swap; the `supersedes`) | **strict majority of `L`** (`2·M > \|L\|`) | the live set governs its own membership |
| **Standing-quorum acts** (non-emergency) | strict majority of the standing roster (unchanged) | normal operation when not decimated |

**The fire floor is one (Q1 resolved).** A single reachable, key-capable holder
can fire the constitutional kill. This is the deliberate maximum lean toward
firing: in the limit of a first strike that leaves *one* survivor, that survivor
can still pull the plug. The cost of the only thing this admits — a lone *coerced*
key firing falsely — is a recoverable halt (governance re-licenses the agent),
whereas the failure it prevents — the adversary reduces the holders below any
higher floor and the switch goes dead — is terminal. The firing floor sitting
**below** the roster-change threshold is the whole point: even a partially-captured
live set's honest minority (down to one) can still fire (§8). **Firing has no
challenge window** — it is immediate on a fresh survivor signature; the window
(§9) applies only to roster changes.

### 4.4 Steward floor when `L` is tiny

When `|L|` falls below a floor `L_floor` (e.g. `< 3`, certainly `= 1`), a **roster
change** additionally requires a quorum of the regional **stewards** (us/eu/apac —
the §6 cross-attestation root the accord is already upstream-rooted in) to co-sign.
This removes the pure self-attestation of the most capturable case (a lone or
near-lone survivor reconstituting the roster) without inventing a new principal.
**Firing is not gated this way** — firing leans easy in all states.

### 4.5 Return and reinstatement (Enoch Arden)

A holder who proves life **after** a decision missed that vote, but is **re-enrolled
in the standing roster going forward** — modifying the quorum for subsequent
decisions. Past actions validly decided by the then-live set stand; the returnee
simply rejoins. This is the legal rebuttable-presumption-of-death pattern: the
absent are presumed gone so the present may act, and the returning are reinstated.

### 4.6 The proof-of-life physical channel — reaching a relay without satellites

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
geographic + failure diversity. **Time without GPS:** the freshness nonce is
server-issued and relayed in (it does not depend on GPS); HF time standards
(WWV/WWVH/CHU) give coarse wall-clock if needed.

> **Note (Q6, new):** the **relay/gateway backbone** — the set of always-listening
> HF↔RNS Transport Nodes that carry proof-of-life into the mesh — is itself
> infrastructure an adversary will target. It must be **geographically distributed,
> off-grid, and EMP-hardened**, and ideally co-located with the steward sites
> (§4.4). This is the physical complement to the steward backstop and belongs in
> the deployment spec.

## 5. Prior art

- **Ethereum inactivity leak (Casper FFG)** — *the* model: designed for "recover
  finality when over one-third of validators go offline," it measures the quorum
  against **participants**, lets the absent set drop out of the denominator, and
  **re-includes a returning validator.** Our live quorum is the discrete-governance
  form, battle-tested on mainnet (May 2023).
  ([eth2book](https://eth2book.info/latest/part2/incentives/inactivity/),
  [Casper FFG paper](https://arxiv.org/pdf/1710.09437))
- **Social-recovery wallets (Argent / Safe / ERC-4337)** — guardian proposals + a
  **timelock window**; the window is our `W`. (Our proof-of-life is not the
  owner-veto of those systems — see §4.2; it's a counted vote, not a cancel.)
  ([overview](https://university.mitosis.org/intro-to-social-recovery-wallets-safe-argent-and-erc-4337/))
- **Enoch Arden / rebuttable presumption of death** — the absent are presumed gone
  so others may act, **rebuttably**: a returning person is reinstated and can
  reclaim standing. Exactly §4.5.
  ([Cornell LII](https://www.law.cornell.edu/wex/enoch_arden_doctrine),
  [Presumption of death](https://en.wikipedia.org/wiki/Presumption_of_death))
- **BFT participation/quorum-over-responders + failure detectors** — quorum taken
  over reachable participants, with the well-studied caveat that a partition can
  make honest nodes disagree on who is present — our §8 residual.
  ([BFT survey](https://arxiv.org/html/2407.19863v3))

## 6. Protocol — CEG objects (sketch)

All hybrid-signed (Ed25519 + ML-DSA-65, bound) over JCS canonical bytes (CEG §0.9),
same discipline as `accord_genesis`.

- **`accord_proposal`** — `{ family_key_id, prior_family_digest, action: <fire |
  membership-change envelope | both>, nonce, window_until }`. The thing voted on.
- **`accord_participation`** — `{ family_key_id, refers_to: <proposal nonce/digest>,
  proof_of_life: true, vote: <yes|no|abstain>, signed_at, signature }`. The
  proof-of-life **+ vote** in one signed object; entering `L` and voting are the
  same act (§4.2).
- **`accord_decision`** — the terminal object: the proposal + the set of
  `accord_participation` objects collected in `W` + the tally + (for roster change)
  the resulting `supersedes`, and the steward attestations if `|L| < L_floor`. The
  proof-of-participation bundle stands in for the (now meaningless) standing-roster
  signature requirement.

## 7. Verification logic (verify-side obligations)

New surface in `ciris_verify_core` (an `accord_recovery` / `accord_live_quorum`
sibling of `accord_genesis`), all **fail-closed**:

1. `tally_live_quorum` — over the collected `accord_participation` objects: each
   resolves to a **current roster member** in the pinned directory, each signature
   verifies over the proposal nonce (freshness — no replay), dedup by member_id;
   `L` = distinct valid participants; tally votes; compare to the §4.3 threshold for
   the action.
2. `verify_membership_change_by_live_quorum` — when the action is a roster change,
   the resulting `supersedes` must pass **all** existing
   `verify_accord_membership_change` invariants (entrenchment, strict-majority,
   distinct-pubkey gate, anti-replay) — the **only** substitution is that the
   authorizing quorum is the **live set `L`** (strict majority of `L`) rather than
   the standing roster, plus the §4.4 steward backstop when `|L| < L_floor`.
3. `verify_fire_by_live_quorum` — admits a `CONSTITUTIONAL` invocation at the low
   firing floor over `L`; reuses `humanity_accord::Invocation`.

The **authoritative** tally (as with invocation, FSD-001) is CIRISServer recomputing
over pinned `federation_keys`; the local objects are advisory.

## 8. Security analysis — the residual is seize-and-suppress, not false-fire

Because the quorum floats over responders, the adversary's lever is **shrinking `L`
to a subset it controls**: censor the honest holders so they never enter `L`, and
include its captured/coerced members. The adversary still cannot *forge* a member
(signatures are over pinned keys) — it can only remove or coerce real ones. The
consequences, by action:

- **Fire.** A captured small `L` *firing falsely* is **cheap** (recoverable) — we do
  not defend against it. A captured `L` *suppressing* a fire is **hard**: the firing
  floor is low, so an honest minority that reaches *any* channel and enters `L` can
  fire over the adversary's objection. Censorship would have to be **total and
  sustained against every honest holder on every channel** — and proof-of-life is a
  publishable signature, not a network round-trip. This is the case the design most
  protects, and correctly so.
- **Roster change.** A captured-`L` *reconstitution* is the real residual — the
  adversary shrinks `L` to its captured subset and votes itself a roster. Bounded
  by: (a) the **strict majority of `L`** — honest holders who reach any channel
  enter `L` and dilute the captured share; (b) the **steward floor** at small `|L|`
  — the most capturable case additionally requires subverting an independent steward
  quorum on separate channels; (c) **transparency** — every `accord_decision` is
  append-only logged, so a contested reconstitution leaves an immutable trail that
  is the basis for *post-hoc* governance reversal even if the live tally was fooled.

**Coercion / duress** is the irreducible hard part: a coerced living holder can be
made to sign a proof-of-life-with-vote the adversary chooses. Proof-of-life proves
*presence*, not *willingness*. This is bounded — not solved — by the steward floor,
the live majority, and transparency, and is called out as an open problem (Q3); a
duress canary is a candidate but out of scope here.

**What we do not claim:** unconditional recoverability under an omnipotent
adversary. We claim that recovery is **possible** whenever honest survivors reach
*any* channel, that **firing survives** all but total sustained censorship, and that
a **false reconstitution** requires capturing a live majority *and* subverting the
steward floor — a materially higher bar than the deadlock it replaces, with the
honest case made *easy* rather than braked.

## 9. Parameters to pin

| Parameter | Meaning | Setting | Open |
|---|---|---|---|
| **fire floor** | min live participants to admit a `CONSTITUTIONAL` fire | **1** (a single reachable survivor) — **Q1 resolved** | — |
| fire window | challenge window for a fire | **none** — immediate on a fresh survivor signature | — |
| roster window `W` | participation window for a roster change | **72 h** baseline (extensible to 7 d under a declared severe-degradation state); anchored to the 24–72 h social-recovery norm, lengthened for HF store-and-forward relay latency (§4.6) | Q2 |
| roster threshold | quorum for a roster change over `L` | strict majority of `\|L\|` | — |
| `L_floor` | `\|L\|` below which a roster change needs the steward backstop | `3` (always for `1`) | Q2 |
| steward quorum | M-of-N of the 3 regional stewards | `2-of-3` | — |
| recursion floor | smallest roster a change may produce | ≥ 1, never to attacker-only | Q4 |

The asymmetry in the table is deliberate and is the whole design: **firing is
floor-1 and window-0** (a lone survivor fires *now*), while a **roster change** is
strict-majority-of-`L` over a multi-day window — because a missed fire is terminal
but a false reconstitution is the thing the steward floor + window + transparency
exist to bound.

## 10. Open questions (must resolve before build)

- **Q1 — Fire floor — RESOLVED: floor = 1.** A single reachable survivor may fire
  (§4.3). A false fire is recoverable; a higher floor would let the adversary kill
  the switch by reducing holders below it. Settled by the maintainer.
- **Q2 — Roster-window calibration.** `W = 72 h` baseline is set; the open part is
  the extension policy (when/who declares severe-degradation to stretch toward 7 d)
  and whether `W` should scale with `|L|`. Long enough for HF store-and-forward
  (§4.6) to carry an honest proof-of-life in; short enough to recover before the
  adversary consolidates.
- **Q3 — Coercion / duress.** Proof-of-life cannot detect a gun-to-the-head
  signature. Is steward floor + live majority + transparency + post-hoc reversal
  sufficient, or is a duress canary warranted?
- **Q4 — Recursion termination / minimum viable accord.** Below some `\|L\|`, does
  the accord enter a steward-custodied regime rather than a 1-of-1?
- **Q5 — Constitutional grounding — RESOLVED + EXPANDED.** Ratified in **CC 0.3 §4.2.6**
  (CIRISRegistry `c27d794`, issue #108). The live quorum is grounded in CC §4.2 /
  CEG §9; the *restores-not-seizes* proof (live quorum restores operability, cannot
  forge or seize the accord beyond the §8 seize-and-suppress residual) is the
  entrenchment-proof paragraph of §4.2.6. Ratified by the founder under the
  CC 4.5.1 maturity gate (pre-maturity authority over the entrenched §4.2 surface).
  **Expanded since:** CC 0.4 §4.2.1.3 (the `fire ≤ roster-change ≤ standing` bias
  gradient + the resumption direction at the roster-change threshold) and CC 0.5
  §4.5.13 (§4.2.6 ratified as the general `reverse-quorum` governance pattern) —
  see the Status header. §4.2.6 itself reads (line ~210): *"The verify-side
  construction is staged in CIRISVerify FSD-004; the constitutional grounding it
  required (its Q5) is this section."* — i.e. this FSD and CC §4.2.6 cite each other.
- **Q6 — HF↔RNS relay/gateway backbone (deployment).** The always-listening,
  off-grid, EMP-hardened, geographically-distributed Transport Nodes that bridge HF
  proof-of-life into the mesh (§4.6) are infrastructure the adversary will target —
  the physical complement to the steward floor. Belongs in a deployment spec,
  ideally co-located with the steward sites.

## 11. Relationship to existing modules

- **Reuses** `accord_genesis::build_accord_membership_change` /
  `verify_accord_membership_change` and all its invariants — the live-quorum roster
  change only swaps the authorizing quorum (standing roster → live set `L`); every
  other gate (entrenchment, strict-majority, distinct-pubkey, anti-replay) is
  unchanged.
- **Reuses** `threshold::verify_founder_quorum` for the live tally and the steward
  backstop, and `humanity_accord::Invocation` for the fire.
- **Generalizes** `accord_quorum_from_family`: the threshold is now taken over the
  live set `L`, not the standing `members` — the standing roster defines *who may
  participate*, `L` defines *who did*.
- **Does not** add a new §9.2.1 invocation verb; DECIMATION is a quorum-computation
  rule over the existing `CONSTITUTIONAL` kind, not a new vocabulary entry.

## 12. Implementation phases (when grounded + reviewed)

1. **Phase 0 — ratify.** Q1 resolved (fire floor = 1); **Q5 resolved (constitutional
   grounding — CC 0.3 §4.2.6)**. Remaining before code: Q2 (window calibration),
   Q3 (duress), Q4 (recursion floor), and the threat-model sign-off / adversarial
   review. *No code until those close.*
2. **Phase 1 — live-quorum tally + roster change.** `accord_proposal` /
   `accord_participation` / `accord_decision` objects + `tally_live_quorum` +
   `verify_membership_change_by_live_quorum`, reusing the membership-change core.
   Adversarial review (≥ #91/#95 rigor).
3. **Phase 2 — live-quorum fire.** The low-floor `CONSTITUTIONAL` fire over `L`,
   gated on Q1's floor.
4. **Phase 3 — server + ceremony.** CIRISServer authoritative recompute (#41/#61),
   the holder participation flow, the steward backstop wiring.

---

*Authored from the maintainer's live-quorum correction: proof-of-life **modifies
the quorum and carries a vote** (it is not a veto), and the system **always leans
toward firing** (there is no failure-direction asymmetry). Design of record for
CIRISVerify#98.*
