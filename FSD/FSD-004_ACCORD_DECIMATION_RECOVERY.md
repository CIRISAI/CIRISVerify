# FSD-004 — Accord Live-Quorum Operation & Recovery Under Decimation

**Status:** DRAFT (2026-06-21; rewritten to the live-quorum model 2026-06-21).
Design specification — **not yet ratified, not yet implemented.** Changing how the
kill-switch quorum is computed is a §9 governance change; nothing here ships
without (a) constitutional grounding in CEG §9 / the CIRIS Constitution and (b) an
adversarial review on par with #91/#95.

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
| **Fire** (CONSTITUTIONAL kill, §9.2.1) | a **low floor** — a small fraction of `L`, down to **1** in deep decimation | missed fire is terminal, false fire recoverable → lean easiest |
| **Roster change** (add / remove / swap; the `supersedes`) | **strict majority of `L`** (`2·M > \|L\|`) | the live set governs its own membership |
| **Standing-quorum acts** (non-emergency) | strict majority of the standing roster (unchanged) | normal operation when not decimated |

The firing floor sitting **below** the roster-change threshold is the whole point:
even a partially-captured live set's honest minority can still fire (§8).

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

| Parameter | Meaning | Candidate | Open |
|---|---|---|---|
| `W` | participation window per proposal (may differ fire vs roster) | hours (fire) / days (roster) | Q2 |
| fire floor | min live participants to admit a `CONSTITUTIONAL` fire | a small fraction, ≥ 1 | Q1, Q2 |
| roster threshold | quorum for a roster change over `L` | strict majority of `\|L\|` | — |
| `L_floor` | `\|L\|` below which a roster change needs the steward backstop | `3` (always for `1`) | Q2 |
| steward quorum | M-of-N of the 3 regional stewards | `2-of-3` | — |
| recursion floor | smallest roster a change may produce | ≥ 1, never to attacker-only | Q4 |

## 10. Open questions (must resolve before build)

- **Q1 — How low is the fire floor?** "Lean easiest" vs. a minimum that resists a
  trivially-captured single coerced key firing. (Note: a false fire is recoverable,
  which argues for a very low floor.)
- **Q2 — Window / floor calibration.** `W` long enough to let honest holders enter
  `L` against censorship, short enough to fire/recover before the adversary
  consolidates. Needs explicit modeling.
- **Q3 — Coercion / duress.** Proof-of-life cannot detect a gun-to-the-head
  signature. Is steward floor + live majority + transparency + post-hoc reversal
  sufficient, or is a duress canary warranted?
- **Q4 — Recursion termination / minimum viable accord.** Below some `\|L\|`, does
  the accord enter a steward-custodied regime rather than a 1-of-1?
- **Q5 — Constitutional grounding.** This redefines the §9 quorum (standing-roster →
  live set). It needs an explicit basis in the Constitution / CEG §9 plus a proof
  that the live quorum *restores* the accord and cannot be used to *weaken* or
  *seize* it beyond the §8 residual.

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

1. **Phase 0 — ratify.** Resolve Q1–Q5; constitutional grounding; threat-model
   sign-off. *No code.*
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
