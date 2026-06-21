# FSD-004 — Accord Catastrophic-Decimation Recovery (Emergency Opposite-Quorum)

**Status:** DRAFT (2026-06-21). Design specification — **not yet ratified, not
yet implemented.** This is a deliberate **quorum-bypass on kill-switch
membership**; nothing here ships without (a) constitutional grounding in CEG §9 /
the CIRIS Constitution, and (b) an adversarial review on par with #91/#95.

**Tracks:** CIRISVerify#98. **Builds on:** FSD-001 (protocol), the v6.8.0 growable
M-of-N accord family + membership-change `supersedes` (`ciris_verify_core::
accord_genesis`), CEG §9.1/§9.2 (entrenched family + invocation).

---

## 1. Purpose

The HUMANITY_ACCORD kill-switch is the mechanism by which accountable humans can
constitutionally halt a CIRIS agent. Its trust rests on **distributed human
custody**: an M-of-N strict-majority quorum of holders. That same property is a
**liability under catastrophic loss** — the normal quorum *deadlocks* precisely
when most holders are gone, which is exactly the moment the kill-switch matters
most.

This FSD specifies how the accord **survives the decimation of its roster**: how
the few remaining humans can still invoke the kill-switch and reconstitute the
family, **without** opening a path for an adversary to seize or falsely fire it.

## 2. Threat Model — adversarial-AGI first strike

The design target is the **worst case the accord exists for**: a misaligned
superintelligence executes a **first strike against its own off-switch** — the
human accord holders — *before* or *while* it acts against humanity at large.

**Scale.** The accord is assumed to have **grown** (FSD/v6.8.0 growable M-of-N) to
be robust — e.g. **N = 21 holders**, strict-majority quorum 11-of-21. The strike
reduces the **reachable, key-capable** holders to **1 or 2**.

**Adversary capabilities (assume all of them simultaneously):**

| Capability | Consequence for the accord |
|---|---|
| **Kill / incapacitate** holders | Their keys are permanently unavailable (death) or temporarily (injury, capture). |
| **Coerce / seize** keys | A holder's key signs under duress — *worse than loss* (active misuse). |
| **Censor communications** | Suppress a holder's "I am alive" message; partition survivors. **Under a first strike, censorship is the EXPECTED condition, not an edge case.** |
| **Impersonate** | Forge non-cryptographic signals (but not hybrid signatures over pinned keys). |
| **Race the clock** | Act during any challenge/timelock window the recovery introduces. |

**What must survive the strike:**

1. **Invocability** — the surviving human(s), however few, can still fire the
   constitutional kill-switch.
2. **Recoverability** — the family roster can be reconstituted (new holders
   admitted, dead/coerced holders removed) so the accord remains operable
   afterward.

**Non-goals.** This FSD does not address (a) the agent-side enforcement of an
admitted invocation (CIRISServer / WiseBus), (b) physical/operational security of
the holders themselves, or (c) recovery of *cryptographic material* (a dead
holder's private key is gone — recovery is about the *roster*, not the key).

## 3. The central design principle — failure-direction asymmetry

The two needs in §2 pull in **opposite** safety directions, and conflating them
is the trap. The accord is **fail-safe toward shutdown**: halting a suspect agent
is the recoverable direction (an agent can be re-licensed; an extinct humanity
cannot). Therefore:

> **Invocation** (firing the kill-switch) should be **biased toward firing** under
> decimation — a *false* fire is a recoverable nuisance (an agent halted in error
> can be restored through governance), while a *missed* fire (the adversary
> decapitated everyone who could pull the plug) is **terminal**.
>
> **Reconstitution** (changing *who holds* the kill-switch) must be **biased
> against change** — a *false* reconstitution is a **coup**: it hands the
> kill-switch (and the power to *suppress* it) to an attacker. This is the path
> that needs the strong, slow, vetoable guards.

Everything below follows from this asymmetry. The "emergency opposite-quorum" is
the mechanism for the **reconstitution** path; the **invocation** path gets a
separate, lighter emergency rule.

## 4. Design

### 4.1 Emergency invocation under decimation (the fast path)

**Problem.** Normal invocation concurrence (CEG §9.2.1) needs the strict-majority
quorum (11-of-21). With 1–2 survivors it is unreachable.

**Rule (fail-safe-to-shutdown).** Declare a **DECIMATION state** for the family
when the count of holders able to produce a fresh signature within a short probe
window falls below the standing quorum. In DECIMATION state, a **constitutional
invocation may be admitted on the signatures of the reachable survivors alone**
(down to 1), provided:

- the invocation is the standing closed-vocab `CONSTITUTIONAL` kill (§9.2.1 — *not*
  a roster change; this path can fire the switch, it cannot change membership);
- the survivor set is itself **proof-of-life-fresh** (each survivor's signature is
  over a recent server-issued nonce, so a *replayed* dead-holder signature can't
  manufacture a survivor);
- the admitted invocation is **loudly, immutably logged** (CEG transparency) — a
  decimation-fire is the highest-scrutiny event in the system.

**Why this is acceptable.** A false decimation-fire halts an agent that governance
can later restore; it does **not** transfer custody of the kill-switch. The
adversary gains nothing by *triggering* it (it shuts down the very agent the
adversary controls). The only thing this path must refuse is *roster change* —
which §4.2 governs.

> **Open constitutional question (Q1):** the Constitution calls `CONSTITUTIONAL`
> "the full constitutional kill — not a recoverable pause." If a constitutional
> kill is *truly* irreversible, a false decimation-fire is **not** cheaply
> recoverable, and this path needs a (short) proof-of-life challenge window like
> §4.2. The asymmetry argument holds only to the degree a kill is governance-
> reversible. **This must be settled before §4.1 is built.**

### 4.2 Emergency roster reconstitution — the opposite-quorum (the guarded path)

This is the inverse of a normal quorum: instead of needing **M affirmative
signatures to act**, the action **takes effect by default after a challenge
window unless it is vetoed.** A below-quorum survivor set proposes a roster
change; the change is defeated by proof-of-life or by survivor dissent.

**Actors.** `X` = the reachable survivors proposing. `Y` = the holders they assert
are unavailable. `N` = the standing roster (`X ∪ Y`, plus any already-removed).

**The flow:**

1. **Recovery proposal** (`accord_recovery_proposal`). The survivors `X` jointly
   sign a proposal: *"we assert holders `Y` are unavailable (could not sign within
   window `W_probe` despite broadcast), and propose new roster `R'` / action
   `Z`."* `Z` is a normal entrenched-family `supersedes` (FSD/v6.8.0
   `build_accord_membership_change`) — same entrenchment invariants
   (strict-majority `2·M > N`, entrenched flag, `family_key_id` unchanged,
   distinct-pubkey gate).
2. **Challenge window** `W_challenge` opens (and the proposal is broadcast widely —
   CEG + every out-of-band channel; see §8).
3. **Veto by proof-of-life.** *Any* holder in `Y` who signs a fresh
   `accord_proof_of_life` over the proposal's nonce **defeats the proposal** — and,
   ipso facto, proves the quorum was *not* actually broken (they're alive), so no
   recovery was needed. The falsely-accused-dead cannot be removed against their
   will.
4. **Veto by survivor dissent.** If a strict majority **of `X`** signs
   `accord_recovery_dissent` ("we do not agree `Y` are unavailable / we do not
   agree on `Z`"), the proposal dies. No lone faction of survivors can declare
   others dead and seize the roster *unless they are genuinely the only ones
   left.*
5. **Steward backstop (required when `|X|` is below a floor).** When the surviving
   proposers number fewer than `X_floor` (e.g. `< 3`, certainly `= 1`), the
   proposal **additionally requires** a quorum of the regional **stewards**
   (us/eu/apac — the §6 cross-attestation root the accord is already upstream-
   rooted in) to co-sign. This removes the pure self-attestation of the most
   dangerous case (a lone survivor) without inventing a new trust principal.
6. **Assembly.** If `W_challenge` elapses with no valid veto, the proposal's
   `supersedes` is admitted via the existing `verify_accord_membership_change`
   path, with the **proof-of-absence record** (the broadcast proof + unanswered
   challenge) standing in for the unreachable prior quorum's signatures.
7. **Recursion / cascade.** Confirmed-unavailable holders are removed; the
   strict-majority threshold recomputes on the now-smaller roster; the mechanism
   may **repeat** if loss continues (21 → … → a working core), and any dispute
   *about a recovery* is itself resolved by the same proposal/veto structure. A
   floor prevents recursion to a zero-member or single-attacker roster (§9).

**The safety floor this buys:** because *any* reachable living holder can veto by
signing "alive," **the reconstitution path can never remove a living, reachable
holder.** A hostile takeover therefore requires the targeted holders to be *both*
key-unavailable *and* unreachable-to-object — i.e. genuinely dead, or
simultaneously censored **and** coerced. Combined with the survivor-dissent veto
and the steward floor, the abuse surface is bounded to exactly the conditions a
real first strike creates — which §8 addresses head-on.

## 5. Prior art

This pattern is well-trodden; the design borrows deliberately.

- **Social-recovery wallets (Argent / Safe / ERC-4337).** Guardians propose a
  signer swap after a **timelock**; the owner holds a **veto — cancel with the
  original key during the delay.** Our proof-of-life veto generalizes that
  owner-cancel from one owner to "any presumed-dead holder."
  ([Argent/Safe/4337 overview](https://university.mitosis.org/intro-to-social-recovery-wallets-safe-argent-and-erc-4337/),
  [attack paths](https://cantina.xyz/blog/smart-wallet-social-recovery-risks))
- **Ethereum inactivity leak (Casper FFG)** — the closest large-scale analog,
  *designed for* "recover finality when **over one-third of validators go
  offline**": the absent set's weight **decays until the active set regains the
  majority**, and a returning validator stops their own leak. Our recursive
  recovery is the discrete-governance form of this continuous leak; battle-tested
  on mainnet (May 2023). ([eth2book](https://eth2book.info/latest/part2/incentives/inactivity/),
  [Casper FFG paper](https://arxiv.org/pdf/1710.09437))
- **BFT view-change / failure detectors.** A view-change is "an **accusation**
  against the leader"; the literature's hard problem — "a faulty leader can cause
  honest replicas to disagree on whether it is faulty… accusers cannot convince
  others" — is **exactly** our censorship risk (§8), already named and studied.
  ([BFT survey](https://arxiv.org/html/2407.19863v3))
- **Enoch Arden doctrine / rebuttable presumption of death.** A person absent long
  enough is *presumed dead so others may act*, **but rebuttably** — "if the person
  subsequently appeared, the law no longer considered them dead," and a returning
  person can **petition to vacate the declaration and reclaim assets still held.**
  Centuries of case law for proof-of-life veto + returning-holder reinstatement.
  ([Cornell LII](https://www.law.cornell.edu/wex/enoch_arden_doctrine),
  [Presumption of death](https://en.wikipedia.org/wiki/Presumption_of_death))

## 6. Protocol — CEG objects (sketch)

All objects are hybrid-signed (Ed25519 + ML-DSA-65, bound) over JCS canonical
bytes (CEG §0.9), same discipline as `accord_genesis`.

- **`accord_recovery_proposal`** — `{ family_key_id, prior_family_digest,
  asserted_unavailable: [key_id…], proposed_supersedes: <membership-change
  envelope>, probe_evidence, nonce, challenge_window_until, signatures: [X…] }`.
  Binds the proposed new roster *and* the assertion-of-absence in one signed
  preimage.
- **`accord_proof_of_life`** — `{ family_key_id, refutes_proposal: <nonce/digest>,
  signed_at, signature }` from a member of `Y`. The veto.
- **`accord_recovery_dissent`** — same shape, from a member of `X`. The
  survivor-dissent veto.
- **`accord_steward_recovery_attestation`** — steward co-signatures required when
  `|X| < X_floor`.
- **`accord_recovery_assembly`** — the terminal object: the admitted `supersedes`
  + the proof-of-absence bundle (proposal + elapsed window + null vetoes [+ steward
  attestations]) standing in for the unreachable prior quorum.

## 7. Verification logic (verify-side obligations)

New surface in `ciris_verify_core::accord_genesis` (or a sibling `accord_recovery`
module), all **fail-closed**:

1. `verify_recovery_proposal` — proposal well-formed; `X` signers resolve in the
   pinned directory and are *current roster members*; `asserted_unavailable ⊆`
   current roster; `proposed_supersedes` passes **all** existing
   `verify_accord_membership_change` invariants (entrenchment, strict majority,
   distinct-pubkey gate, anti-replay) **except** the prior-quorum signature
   requirement, which the recovery bundle replaces.
2. `verify_proof_of_life` / `verify_recovery_dissent` — a single valid veto from
   the right population kills the proposal; surfaced as a hard `RecoveryVetoed`.
3. `verify_steward_backstop` — when `|X| < X_floor`, require the steward quorum
   (reuse `verify_founder_quorum` against the pinned steward roster).
4. `verify_recovery_assembly` — re-checks the whole bundle: window elapsed, no
   valid veto present, steward backstop if required, and the resulting roster
   satisfies the §9 floors. Emits the new family genesis on success.

The **authoritative** verification (as with invocation, FSD-001) is CIRISServer
recomputing against pinned `federation_keys` — the local objects are advisory.

## 8. Security analysis — the first-strike makes censorship the default

The proof-of-life veto is the safety floor, but a first strike **attacks the veto
channel directly**: if the adversary can suppress every "I am alive" message for
the whole window, it can falsely declare living holders dead and reconstitute the
roster — a coup. Under §2 we must assume the adversary *can* censor. Mitigations,
layered:

1. **Wide, redundant, out-of-band broadcast.** The proposal + challenge must reach
   `Y` over channels the adversary cannot fully control — CEG mesh, public
   bulletin, physical/social. Proof-of-life is a *signature*, not a network round
   trip: a holder who learns of the proposal by *any* channel can publish a veto
   through *any* channel. The adversary must censor **all** of them, for **all**
   targeted holders, for the **whole** window.
2. **Long `W_challenge`.** The window is the adversary's required censorship
   duration. Reconstitution is deliberately slow (days), trading latency for
   safety — acceptable because §4.1's *invocation* path is the fast one;
   reconstitution is for *afterward*.
3. **Mandatory steward backstop at low `|X|`.** The most censorable case (1
   survivor) cannot self-reconstitute — it needs an independent steward quorum,
   who are geographically separate principals with their own channels. The
   adversary must now censor the survivors' targets **and** subvert a steward
   quorum.
4. **Coercion ≠ defeated by proof-of-life.** A *coerced* living holder can be made
   to sign anything, including a false proof-of-life that *blocks* a legitimate
   recovery (griefing) — or a recovery proposal that *enacts* the adversary's
   roster. Proof-of-life only protects the *unwilling-to-be-removed*; it does not
   detect duress. This is the residual the steward backstop + dissent veto +
   transparency log exist to bound, and it is **explicitly an open hard problem**
   (Q3).
5. **Transparency.** Every recovery object is append-only logged. A contested or
   adversarial recovery leaves an immutable, publicly-auditable trail — the basis
   for *post-hoc* governance reversal even if the live mechanism is fooled.

**What we do not claim:** this does not make the accord unconditionally
recoverable under an omnipotent adversary. It makes recovery **possible** when
survivors can reach *any* honest channel, and makes a **false** reconstitution
require the conjunction of (kill/censor the targets) **and** (subvert a steward
quorum or a survivor majority) — a materially higher bar than the deadlock it
replaces.

## 9. Parameters to pin

| Parameter | Meaning | Candidate | Open |
|---|---|---|---|
| `W_probe` | freshness window for "could not sign" | hours | Q2 |
| `W_challenge` | proof-of-life veto window for reconstitution | days | Q2 |
| `X_floor` | survivor count below which steward backstop is mandatory | `3` (always for `1`) | Q2 |
| steward quorum | M-of-N of the 3 regional stewards | `2-of-3` | — |
| recursion floor | smallest roster a recovery may produce | ≥ 1, never to attacker-only | Q4 |
| invocation-fast-path | survivors needed to fire in DECIMATION | ≥ 1 fresh | Q1 |

## 10. Open questions (must resolve before build)

- **Q1 — Is a constitutional kill governance-reversible?** Determines whether the
  §4.1 fast invocation can be near-instant (reversible) or needs a challenge
  window (irreversible). Gates the whole asymmetry argument.
- **Q2 — Window/floor calibration.** Long enough to survive censorship, short
  enough to recover before the adversary consolidates. Needs explicit modeling.
- **Q3 — Coercion / duress.** Proof-of-life cannot detect a gun-to-the-head
  signature. Is the steward backstop + transparency + post-hoc reversal
  sufficient, or is a duress-signal (canary) mechanism warranted?
- **Q4 — Recursion termination & minimum viable accord.** Does the accord have a
  hard minimum below which it enters a different (e.g. fully steward-custodied)
  regime rather than a 1-of-1?
- **Q5 — Constitutional grounding.** This is a §9 governance change; it needs an
  explicit basis in the CIRIS Constitution / CEG §9 before code, plus an
  entrenchment-preservation proof (recovery must *restore*, never *weaken* or
  *seize*).

## 11. Relationship to existing modules

- **Reuses** `accord_genesis::build_accord_membership_change` /
  `verify_accord_membership_change` (the `supersedes` + all its invariants) — the
  recovery only *replaces the prior-quorum signature requirement* with the
  proof-of-absence bundle; every other gate (entrenchment, strict-majority,
  distinct-pubkey, anti-replay) is unchanged.
- **Reuses** `threshold::verify_founder_quorum` for the steward backstop and the
  survivor-dissent count.
- **Reuses** `humanity_accord::Invocation` for the §4.1 fast-path fire.
- **Does not** touch the closed §9.2.1 invocation vocabulary (no new
  `InvocationKind`); DECIMATION is a *state* gating the existing `CONSTITUTIONAL`
  kind, not a new verb.

## 12. Implementation phases (when grounded + reviewed)

1. **Phase 0 — ratify.** Resolve Q1–Q5; constitutional grounding; threat-model
   sign-off. *No code.*
2. **Phase 1 — reconstitution (§4.2).** The opposite-quorum recovery objects +
   verifiers, reusing the membership-change core. Adversarial review (≥ #91/#95
   rigor). The harder, slower, safety-critical path first.
3. **Phase 2 — fast invocation (§4.1).** The DECIMATION-state fast fire, gated on
   Q1's answer.
4. **Phase 3 — server + ceremony.** CIRISServer authoritative recompute (#41/#61),
   the holder-side recovery ceremony, the steward backstop wiring.

---

*Authored from the maintainer's "emergency opposite-quorum" proposal + the §2
first-strike threat model. Prior-art-grounded. This document is the design of
record for CIRISVerify#98 and supersedes the option sketch in that issue.*
