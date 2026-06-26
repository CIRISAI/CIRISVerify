# FSD-004 Adversarial Review — Accord Live-Quorum (pre-implementation gate)

**Status:** COMPLETE. This review is the threat-model sign-off that FSD-004 §12
Phase 0 requires before any live-quorum code lands. It red-teams the **design**
(FSD-004 + the ratified CC §4.2.6 / §4.2.1.3) and the **existing reused
primitives** (`accord_genesis`, `humanity_accord`, `threshold`). Method: four
independent red-team passes, each attacking one dimension, then synthesis.
Rigor target: ≥ the #91/#95 accord work.

**Verdict:** the design is *sound in its constitutional shape* but **under-specified
at exactly the points an adversary attacks** — the participation preimage, the
window-membership predicate, and which roster the authorizing quorum binds to.
None of the findings invalidate the model; all are **concrete build obligations**
that Phase 1 MUST satisfy. They are listed below as the normative build spec.

The reused primitives (`verify_threshold_signatures` / `verify_founder_quorum`,
the membership-change invariants) are **correct** and already stop several
seizure shapes (one-key-quorum, double-seating-via-spare, lifting entrenchment,
`1/2` split-brain, replay-against-a-different-prior). They are not re-litigated.

---

## Resolution status — verify-core machinery IMPLEMENTED

The stateless verify-core obligations are built in `ciris_verify_core::accord_live_quorum`
(`AccordProposal` / `AccordParticipation` / `AccordDecision`, `tally_live_quorum`,
`verify_fire_by_live_quorum`, `verify_membership_change_by_live_quorum`,
`verify_resume_by_live_quorum`, `verify_recovery_supersede`, `decisions_equivocate`),
each tested:

| Finding | Status |
|---|---|
| C1 vote/proposal/family/window in the preimage | ✅ implemented + tested |
| C2 window in signed bytes; `signed_at` advisory (server-arrival is authoritative) | ✅ verify-core part; the arrival clock is Phase-3 server |
| C3 anti-replay anchor on the standing roster | ✅ |
| H1 resumption at roster-change threshold, never fire floor | ✅ (one-yes-fires-but-doesn't-un-fire proven) |
| H2 resumption binds the active halt | ✅ (`HaltMismatch`) |
| H3 equivocation gate | ✅ (`decisions_equivocate`) |
| H5 `N_min` + removal-continuity | ✅ |
| H6 steward backstop (independent set, server-recomputed `\|L\|`) | ✅ |
| **H7 reversal** | ✅ **bounded steward roll-back** (`verify_recovery_supersede`) — stewards may **restore a known-good logged snapshot, never install a novel roster**; ⚠ **MUST be CC-cross-confirmed** (it bends the entrenchment rule for the captured-roster case) |
| M1 fire floor pinned to 1 | ✅ |
| M2 frozen-`L` snapshot | ✅ (`AccordDecision`) |
| M3 directory-only resolution, dedup by pinned member | ✅ |
| M5 `family_key_id` bound | ✅ |

**Remaining (Phase 3 — CIRISServer state, not verify-core):** the authoritative
window/arrival clock (C2), proposal coalescing + rate-limit (H4), the active-halt
state (H2 enforcement point), the issued-nonce set + signed-proposal origin (M4),
durable dedup (M6), and the HF↔RNS relay backbone (Q6).

---

## Severity-ranked findings → Phase-1 obligations

### CRITICAL

**C1 — `accord_participation` has no canonical-bytes spec; the vote may not be in the signed bytes (vote-flip) and `refers_to` may be a bare nonce (cross-proposal replay).**
Unlike `Invocation::canonical_bytes` (which binds kind/payload/etc.), the
proof-of-life-plus-vote object is described only as a JSON object with sibling
`vote`/`signature` fields and the loose obligation "verifies over the proposal
nonce." If the implementer signs nonce-only, a relay/server can flip a recorded
`vote` (no→yes) or replay a benign-proposal participation into a different
proposal — both keep the honest holder *in* the denominator while counting them
for the adversary.
**Obligation:** define `accord_participation` canonical bytes with a dedicated
domain prefix and **the vote, the full proposal digest, the member id, and the
window inside the signed preimage**:
```
sha256(
  "ciris.accord_participation.v1\n" ||
  "family_key_id=" || fkid || "\n" ||
  "proposal_digest=" || sha256_hex(JCS(accord_proposal)) || "\n" ||
  "member_id=" || id || "\n" ||
  "proof_of_life=true\n" ||
  "vote=" || ("yes"|"no"|"abstain") || "\n" ||
  "window_until=" || rfc3339 || "\n" ||
  "signed_at=" || rfc3339
)
```
`tally_live_quorum` MUST recompute these bytes from the *claimed* fields and drop
(fail-closed) any participation whose recomputed bytes don't verify — so no vote,
proposal, family, seat, or window can be altered post-signature. `refers_to` is
the **full proposal digest**, never the bare nonce.

**C2 — The window-membership predicate is undefined; trusting the holder's self-asserted `signed_at` hands the adversary edge-of-window denominator control.**
`window_until` is proposer-set and `signed_at` is holder-set; neither FSD-004 nor
CC §4.2.6 says *which clock* decides "within W." A coerced holder backdates
`signed_at` to slip a late signature inside a closed window; conversely an honest
HF store-and-forward survivor's late packet is dropped as "outside W."
**Obligation:** `L` membership is decided by **server-observed arrival time at the
authoritative tally, against a server-issued, server-clocked nonce window**
`W = [nonce_issue_time, window_until]`. `signed_at` is **advisory display only and
MUST NOT gate `L`**. To protect honest survivors against relay latency, arrival is
stamped at *first ingress to any honest relay/gateway*, not the final server hop;
the 72 h window exists for exactly this latency budget.

**C3 — The anti-replay / authorization anchor must stay the STANDING pinned roster, never `L`.**
The existing `verify_membership_change` binds `supersedes.prior_member_key_ids`
to the standing prior envelope and authorizes at the prior roster's strict
majority — that is the whole anti-replay guarantee. FSD-004 §7.2's "the only
substitution is that the authorizing quorum is the live set `L`" is dangerous if
read as "resolve the authorizing roster + threshold from `L`": `L` is exactly the
adversary-shrinkable set, so `2·M > |L|` over a censored `|L|=2` lets **2 captured
keys** install an all-adversary roster.
**Obligation:** keep two roles strictly separate — (a) `supersedes.prior_member_key_ids`
anti-replay binds to the **standing pinned roster** (`humanity_accord_genesis()` /
`federation_keys`), unchanged; (b) `L` only narrows *which signers count*, and
**only after each participant is proven a subset of that standing roster** via the
pinned directory. Invariant test: a `supersedes` whose prior set is the live set
(not the standing roster) is rejected.

### HIGH

**H1 — Resumption (`lifecycle:active`) is currently admitted at the same 2/3 as everything else; the CC §4.2.1.3 "never at the fire floor; at the roster-change threshold + steward backstop" asymmetry is NOT implemented.**
`verify_invocation` hardcodes threshold `2` for all kinds; `reactivate_lifecycle_reaches_two_of_three`
even asserts it. *In today's fixed-3-holder model this is benign* (strict-majority
of 3 = 2 = the roster-change threshold, and the fire-floor-of-1 doesn't exist
yet). But the moment Phase-1 live-quorum lands the fire floor at 1, resumption
MUST NOT follow it down.
**Obligation:** when live-quorum lands, `verify` branches on kind: `LifecycleActive`
admits at **strict-majority-of-`L` + the `L_floor` steward 2-of-3 co-sign when
`|L| < 3`**, never the fire floor; the `reactivate_*` test is inverted to assert a
resumption at the fire floor (or bare 2/3 below the live majority, no steward sig)
is **rejected**.

**H2 — No "currently-active halt" check on resumption.** `resumes_halt_id` is in
the signed bytes (stops *re-pointing* one signature — good) but nothing verifies
it equals the halt actually in force. CC §4.2.1.3: "the substrate MUST reject a
`lifecycle:active` whose `resumes_halt_id` does not match the currently-active
CONSTITUTIONAL halt." This is a server-state obligation.
**Obligation:** the authoritative resumption path takes the active halt id as
input and rejects any `lifecycle:active` whose `resumes_halt_id != active_halt_id`;
once halt-X is resumed, X is no longer active, so a later resumption of X fails
this check regardless of the dedup window. Expose a verify helper that accepts the
expected active halt; CIRISServer holds the state.

**H3 — Federation split-brain: "authoritative server" is singular in prose, plural in deployment → two valid `L` for one proposal.** Two partitioned servers
recompute different `L` over the same pinned keys and each emit a valid
`accord_decision` (a roster seizure on one side, honest on the other). For *fire*
this is benign (any server that sees a survivor sig fires — correct). For
*roster change* it's a fork.
**Obligation:** two `accord_decision`s superseding the **same `prior_family_digest`**
are a hard **equivocation conflict — both rejected pending steward reconciliation**
(reuse the §19.1 equivocation-detection shape already in the codebase). The
`prior_family_digest` MUST be in the *signed* `supersedes`.

**H4 — Proposal re-roll / window-fishing.** A captured holder re-issues the *same*
roster-change action as fresh proposals (new nonce ⇒ new W) until a window closes
with only the captured `L`. The existing anti-replay stops replaying a *decided*
state, not re-proposing against the *current* state. Also a griefing vector
(honest holders forced to re-prove life on every spam proposal).
**Obligation:** proposals for the same `(action, prior_family_digest)` **coalesce**
— participations across concurrent windows for the same prior digest accumulate
into one tally, so an honest holder who proved life once stays counted. Add a
per-proposer **rate-limit/cooldown** on roster-change proposals. **Firing stays
unthrottled** (fail-toward-firing).

**H5 — Removal-under-cover-of-absence + no minimum roster size → shrink-to-seize.**
The strict-majority gate validates the *new* envelope's self-consistency but has
no floor on N and no continuity check: an adversary supersedes 21→2 (or 21→1,
which `2·M>N` passes) by dropping censored honest holders as "not live," yielding
a tiny adversary roster that — because **fire is floor-1 and never steward-gated**
— now owns the kill-switch outright.
**Obligation:** enforce `N_min > 1` (reject a `1/1` rebuild — mirror the existing
"no `M==1` escape hatch"); **removal of a standing member requires that member to
be in `L` and vote their own removal, OR the full standing-roster strict majority**
— never the live-set majority alone. (Resolves FSD-004 Q4's "never to attacker-only"
floor.)

**H6 — The steward backstop principal is the accord's own attestation root (correlated capture).** CC §4.2.6 roots the small-`L` backstop in the us/eu/apac
stewards — the *same* keys that cross-attest the holders at admission. Under the
first-strike threat model the steward HSMs are always-on infrastructure that may
fall *before* scattered humans, so the backstop can collapse exactly at `|L|<3`.
**Obligation:** the rebuild-authorizing steward quorum MUST be a **key-independent
trust domain** from the holder-attestation root (pinned separately), and the
`|L| < L_floor` trigger MUST be computed on the **server-recomputed `L`**, never the
bundle-claimed `L` (else the adversary inflates `L≥3` with coerced keys to *escape*
the steward floor). Flag for CC cross-confirmation that "independent steward floor"
means key-independent, not merely role-labeled.

**H7 — A seized entrenched roster has no in-protocol reversal path, yet the design relies on "post-hoc reversal."** The only roster-mutation path is authorized by
the *prior* (now-seized) roster's quorum; entrenchment forbids lifting the flag or
changing `family_key_id`. So the honest side cannot supersede the adversary's
roster. The append-only log proves *what happened* but confers no *authority to
undo it*.
**Obligation:** make reversal **expressible** before relying on it — an explicit
recovery-supersede authorized by a body the seized roster does *not* control
(steward quorum **plus** any honest standing holder who later proves life, binding
to the standing-roster snapshot at seizure time from the append-only log), or a
founder/CC-4.5.1 maturity-gate override. **Until that path exists and is tested,
FSD-004 downgrades its claim to "detectable but not in-protocol reversible."**

### MEDIUM

**M1 — Fire floor must be hard-pinned to 1 in the live-quorum path**, never
`strict_majority(|L|)` (else inflating `L` with captured keys raises the fire bar —
a suppression lever). Test: a fire with large `|L|` but one *yes* still fires.

**M2 — Frozen-`L` snapshot in the decision (Enoch-Arden no retroactive recompute).**
Each `accord_decision` carries the immutable server-attested `L` snapshot + `W`
bounds; a closed decision's `L` is final. Re-enrollment changes the *standing
roster going forward*, never a past decision's denominator. Transparency-log it.

**M3 — Holder identity in the preimage + directory-only resolution.** Include
`member_id` (+ a hash of the Ed25519 pubkey) in the participation preimage; dedup
`L` by **pinned pubkey**, not the plaintext `member_id` string; resolve signers
**only** against pinned `federation_keys`, never a bundle-embedded roster.

**M4 — Proposal origin authentication.** `accord_proposal` MUST be **signed by an
authenticated quorum authority** (CIRISServer steward key or the family) and the
holder's station + tally MUST verify that signature + that the nonce is one the
server actually issued (server keeps the issued-nonce set); a participation
referencing an unknown nonce is rejected fail-closed. A holder MUST NOT sign a
participation for a proposal whose origin it cannot verify.

**M5 — `family_key_id` in the signed participation preimage** (today the invocation
preimage also omits it — flagged in `accord_genesis`). Low risk while
HUMANITY_ACCORD is the only family; bind it now so a participation is
non-transferable across families by construction. Fold into the same preimage
spec as C1.

**M6 — Resumption dedup is in-memory/per-process and per-`valid_until`.** Not the
anti-replay boundary — H2's active-halt state is. Persist dedup on the
authoritative server or document it as advisory with the active-halt invariant
load-bearing.

---

## What the existing primitives already guarantee (not re-litigated)

`reject_duplicate_member_keys` / `require_distinct_keys` (one key can't meet
quorum, one human can't double-seat via a spare); `2·M > N` everywhere (no `1/2`
split-brain); entrenchment-flag + `family_key_id` immutability on supersede;
anti-replay bind to the standing prior envelope; per-member signature over
canonical bytes resolved against the pinned directory. `verify_threshold_signatures`
verifies over whatever bytes the caller supplies — sound, but it cannot
compensate for an under-specified preimage (hence C1).

---

## Build sequencing (Phase 1, informed by this review)

1. **Object preimages first (C1, C2, M3, M5):** `accord_proposal` (JCS, signed by an
   authority, carries `nonce`/`window_until`/`prior_family_digest`),
   `accord_participation` (the domain-prefixed preimage above), `accord_decision`
   (frozen `L` snapshot + tally + `prior_family_digest` + steward sigs when
   `|L|<3`). Server-clocked window membership (C2). Conformance + scope-isolation
   tests mirroring `lifecycle_scope_is_wire_isolated_from_invoke`.
2. **`tally_live_quorum` + `verify_membership_change_by_live_quorum` (C3, H5, H6, M1, M2):**
   anti-replay anchored to the standing roster; `L` ⊆ standing roster; fire floor
   hard-pinned to 1; roster-change at strict-majority-of-`L`; `N_min>1`;
   removal-continuity; the server-recomputed `L_floor` steward backstop; frozen-`L`.
3. **Equivocation + anti-griefing (H3, H4):** conflict on two decisions over one
   `prior_family_digest`; proposal coalescing + roster-change rate-limit.
4. **Resumption asymmetry + active-halt (H1, H2):** branch resumption to the
   roster-change threshold; the active-halt-match verify helper.
5. **Reversal (H7):** the recovery-supersede path, or the explicit doc downgrade.
6. **Server + ceremony (Phase 3):** authoritative single-point recompute (or
   steward-cosigned canonical `L`), holder participation flow, the HF↔RNS gateway
   backbone (deployment, FSD-004 Q6).

Every verify obligation above is **fail-closed**.

---

*Review conducted pre-implementation per FSD-004 §12 Phase 0. The findings are
build obligations, not design rejections; the constitutional shape (CC §4.2.6 /
§4.2.1.3) is upheld. Tracks CIRISVerify#98.*
