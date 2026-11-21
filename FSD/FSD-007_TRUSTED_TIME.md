# FSD-007 — Trusted Time

**Status:** Draft — not ratified. Specifies a time service built into CIRISVerify that every CIRIS
component reads instead of its own clock. Tracks CIRIS Constitution 1.0-rc20: CC 2.6.7 (time and
clocks), CC 4.2.1.1 (the halt fuse counts from receipt), CC 3.2 T4 / T4a (liveness is not validity;
attaching is gated on witness freshness), CC 5.3.1 (witness cosignature `signed_at`), CC 5.3.6
(`X-CEG-Server-Time`) and CC 5.3.6.1 (`CLOCK_SKEW_VIOLATION`). Nothing in it is implemented yet;
§10 gives the phases, and Phase 0 (the halt fuse) ships first, in 23.4.1.

**Builds on:** FSD-001 (protocol), FSD-004 (the accord's "always lean toward firing" posture),
FSD-005 (the halt latch), the host ABI `ciris:node@0.1.0` (`src/ciris-host-abi/wit/ciris-node.wit`,
`interface clock`), and the public-instant types of the chrono replacement (POSIX milliseconds as
`u64`; `Timestamp { secs, nanos }` for signed tree heads).

**Replaces:** the CIRISAgent `TimeService`
(`ciris_engine/logic/services/lifecycle/time/service.py`), whose clock and drift report the agent
delegates to verify (§8.3).

---

## 1. Purpose

Every signed instant in the federation is wall-clock UTC at the asserting peer (CC 2.6.7), and
every freshness rule reads a receiver's clock against one: the 5-minute future bound, a
`valid_until`, the 72-hour `W`, a witness cosignature's 5-minute bound, the attach window. Today
each component reads its own operating-system clock for these, with no measurement of whether that
clock is right. CC 2.6.7 requires more than that of a consumer:

> The freshness check is "the attestation has not yet reached its `valid_until`, AND the consumer's
> own clock is within ±5 minutes of the known-good time source it synchronises to". … A consumer
> whose clock drifts past the skew bound MUST fail-secure (reject) rather than accept.

A consumer cannot obey the second clause without measuring its own clock against a source. This
FSD specifies that measurement, once, in verify:

- a pure core that combines time samples into one interval and a state, and answers freshness
  questions against that interval (§4);
- the sources it samples, each with what it proves and how it can lie (§5);
- the signals that refute the local clock (§6);
- what it reports: flat measurements, never a tier (§7);
- the FFI, Python and WIT surfaces, and the components that consume them (§8);
- and one rule that needs no trusted time at all: the halt fuse runs on elapsed monotonic time
  (§3, Phase 0).

The service measures. It never sets the operating-system clock, and it never reports a number it
did not measure.

## 2. Principles

**P1. A reported value is a measurement or it is absent.** No field is filled by estimate,
simulation or default when its measurement failed. A failed query yields the source's error token
and no offset. This forbids, by name, the agent's current behaviour of fabricating a 50 ppm drift
when NTP is unreachable and reporting it as `time_drift_ms` (§8.3).

**P2. Uncertainty is carried, never rounded away.** Trusted time is an interval `[mid − radius,
mid + radius]`, not an instant. Between samples the radius grows by a stated drift bound, so the
interval stays honest without a new measurement. A freshness question whose answer differs across
the interval is `Undecidable`, and the caller's rule says which way that falls (§4.5).

**P3. Hardware refutes and never proves.** A TPM clock, a sealed high-water mark or a monotonic
counter can show that the wall clock is wrong. None of them can show that it is right. Their
absence is never a failure; their contradiction is a tamper signal (verify's rule: refuters, not
provers).

**P4. One identity, one voice.** Sources are counted by distinct identity (a pinned server key, a
seated federation identity), never by connection or by address. A thousand unseated peers count
zero.

**P5. The halt does not wait for time.** A `constitutional` halt acts at receipt whatever its
`asserted_at` (CC 2.6.7, CC 4.2.1.1). No state of this service delays, refuses or shortens a halt.
The fuse runs on elapsed monotonic time, which no wall-clock change can move (§3).

**P6. The pure tier reads no clock.** Every pure function takes its instants as parameters. Only
the host tier reads clocks, opens sockets or touches storage, as for every other pure-tier module.

## 3. Phase 0 — the halt fuse on monotonic elapsed time (23.4.1)

### 3.1 The defect

`ciris_verify_core::accord_halt_latch` stores `LatchedHalt.received_at: DateTime<Utc>` and lapses a
lone halt when `now >= received_at + halt_fuse_secs`, where `now` is a wall-clock instant the caller
passes (`HaltLatch::active_halt(now, fuse)`, `is_paused`, `apply_forward`; FFI
`ciris_verify_accord_latch_status` takes `"now": "<rfc3339>"`). Setting the wall clock forward by a
day therefore lapses a real halt at once. CC 4.2.1.1 calls a missed halt "the one unrecoverable
failure", and FSD-004 leans every ambiguity toward firing. A fuse that the operator's clock can
shorten is a halt the operator can cancel.

CC 4.2.1.1 counts the fuse "from receipt on the node's own clock". It does not say that clock is
the wall clock, and the reason it gives for counting from receipt ("a signed instant is the
signer's to choose") applies equally to an instant the operator can set. Elapsed monotonic time is
the node's own clock and is the one no operator command moves.

### 3.2 The rule

1. **The fuse is a duration, not a deadline.** Each latched halt carries `elapsed_ms: u64`, the
   monotonic time this node has counted since it received the halt. A lone halt lapses when
   `elapsed_ms >= halt_fuse_secs × 1000`. No wall-clock instant enters the comparison.
2. **Elapsed time is accumulated, not computed from an origin.** The host reads a monotonic clock
   `m` and the boot identity `b` at each checkpoint. Between two checkpoints of the same boot it adds
   `m − m_prev` (saturating). Across a boot change, or if `m < m_prev` within one boot, it adds
   **zero** and records a tamper signal (§6.1) for the second case. An unknown gap only ever extends
   a halt.
3. **The accumulator travels in the latch state the caller already keeps.** Verify is stateless
   at the latch today: the host persists the latch JSON and passes it to every
   `ciris_verify_accord_latch_*` call. Phase 0 keeps that: `elapsed_ms`, `m_prev` and `b_prev` ride
   in that JSON, and verify itself reads the monotonic clock and boot identity on each call, so the
   caller never supplies a time. The caller persists at every transition and at least every
   `FUSE_CHECKPOINT_SECS` (60 s) while a lone halt is latched; a crash loses at most one interval,
   which extends the halt. A caller able to edit that JSON could equally delete the halt, so Phase 0
   adds no integrity claim over the state; sealing it through `SecureBlobStorage` is Phase 1.
4. **Lost or old state extends; it never shortens.** A latch blob that is absent (`KeyNotFound`) or
   unreadable (`StorageFailed`) is read as no elapsed time. On start the host re-applies every
   accord row its store holds (`edition2::accord_halt` readings, then `apply_forward`), so a halt
   whose blob is lost re-latches with `elapsed_ms = 0`. A blob rolled back to an earlier snapshot
   carries a smaller `elapsed_ms` and extends the halt. The one rollback that loses a halt is a
   store that no longer holds the halt row, which is a store fault, not a clock fault (§11, TT-3).
5. **A confirmation is judged on the same count.** `lifecycle:confirmed` confirms a lone halt only
   while `elapsed_ms < halt_fuse_secs × 1000` at the checkpoint taken when it is applied. A
   resumption (`lifecycle:active`) ends any halt and reads no clock.
6. **The wall clock stays only where CC puts it.** `apply_forward` compares the receipt instant to
   a halt's signed `valid_until` (a halt past its `valid_until` that a held resumption names does
   not fire, CC 4.2.1.1). That is a comparison of two wall instants and stays one. Phase 0 keeps the
   caller's instant there; a wrong reading changes only whether an already-resumed halt re-fires,
   and a clock set back makes it re-fire, which leans toward firing. From Phase 1 the comparison
   uses trusted time and an `Undecidable` answer fires (§4.5).
7. **`received_at` stays as a report.** The wall instant of receipt is kept as
   `received_wall_ms: Option<u64>` for logs and the trust surface. Nothing reads it to decide.

### 3.3 Which monotonic clock

The clock must not go back, must not be settable, and should count time the device spends
suspended (a fuse that stops while the device sleeps extends the halt, which is safe but delays an
honest lapse).

| Platform | Clock | Counts suspend | Boot identity |
|---|---|---|---|
| Linux, Android (native) | `CLOCK_BOOTTIME` | yes | `/proc/sys/kernel/random/boot_id` |
| Android (JNI) | `SystemClock.elapsedRealtimeNanos()` | yes | `boot_id` as above, else `Settings.Global.BOOT_COUNT` |
| macOS, iOS | `mach_continuous_time()` | yes | `kern.boottime` (sysctl) |
| Windows | `QueryInterruptTimePrecise()` | yes | none stable: each process start is a new boot |
| WASM node | `clock.monotonic-us` | no promise (WIT) | none: every `init` is a new boot |

Where the platform gives no boot identity, every process start is treated as a new boot (rule 2
adds zero across it). `CLOCK_MONOTONIC` is not used on Linux: it stops during suspend.

### 3.4 Shape changes (23.4.1)

- `LatchedHalt { halt_id, halt_row, received_wall_ms: Option<u64>, elapsed_ms: u64, confirmed }`;
  `HaltLatch` gains `checkpoint: Option<FuseCheckpoint { monotonic_ms: u64, boot: [u8; 16] }>`.
- Pure tier: `HaltLatch::advance(&mut self, reading: MonotonicReading)` applies rule 2;
  `active_halt(fuse)` / `is_paused(fuse)` / `remaining_ms(fuse)` take no instant;
  `apply_forward(row, reading, received_wall_ms, fuse)`. `chrono` leaves the module.
- Host tier: `FuseMeter` reads the platform clock and boot identity of §3.3 and calls `advance`;
  the FFI calls it on the latch state it is handed. No new storage in Phase 0.
- FFI: `ciris_verify_accord_latch_status` no longer takes `now`; verify reads the monotonic clock
  and its own persisted latch. Output gains `elapsed_ms` and `remaining_ms` and drops `lapses_at`
  (a wall instant the fuse does not use). A request that still carries `now` is accepted and `now`
  is ignored.
- A persisted latch of the 23.4.0 shape (`received_at`, no `elapsed_ms`) is read once with
  `elapsed_ms = 0` and rewritten in the new shape. This departs from the 23.0.0 hard-cut rule on
  purpose: dropping an old shape here could drop a live halt.
- The latch module header cites `formal/accord_halt/AccordHaltFuse.tla`, which exists in neither
  repository (CC's `formal/accord_halt/` holds `AccordHaltRow.tla` and `AccordHaltReach.tla`). Phase 0
  corrects the citation and adds the fuse model with the accumulator as a variable and checks two
  properties: no wall-clock action changes `paused`, and no sequence of restarts makes a lone halt
  lapse before `halt_fuse_secs` of counted time.

Tests: a halt latched and the wall clock set forward 48 h stays paused; a halt restarted under a
new boot id after 20 h of counted time stays paused for 4 h more counted time, whatever the gap; a
deleted blob re-latches from the held row at zero; a rolled-back blob extends; `m` going back adds
zero and records `monotonic_regressed`.

## 4. The pure core

All of §4 is `no_std` + `alloc` in `ciris-verify-core` (proposed module `time`), checked on
`wasm32-unknown-unknown` and the UEFI targets with the rest of the pure tier. It reads no clock.

### 4.1 Instants

- `WallMs(u64)`: POSIX milliseconds, UTC. The public instant type of the chrono replacement. A
  negative value (WIT `wall-ms` is `s64`) is refused at the boundary as `pre_epoch`.
- `MonoUs(u64)`: a monotonic reading in microseconds, meaningful only against another reading of
  the same `Boot`.
- `Boot([u8; 16])`: the boot identity of §3.3, or a fresh random value per process where none
  exists.
- `Timestamp { secs, nanos }` (signed tree heads) converts to `WallMs` by truncation toward zero;
  the conversion is the only place nanoseconds are dropped.

### 4.2 Sample

```
Sample {
  source:      SourceKind,        // §5: roughtime | nts | signed_instant | peer | sntp | http_date | os
  identity:    SourceId,          // pinned key thumbprint, seated identity thumbprint, or host name
  mid_ms:      WallMs,            // the source's time at the midpoint of the exchange
  radius_ms:   u64,               // the source's stated radius + half the round trip, rounded up
  bound:       Bound,             // Interval | LowerOnly  (§5.3)
  boot:        Boot,
  mono_us:     MonoUs,            // the local monotonic reading at the exchange's midpoint
  os_wall_ms:  Option<WallMs>,    // the OS clock at the same midpoint, for offset reporting
  proof:       Option<Vec<u8>>,   // the signed response bytes, where the source signs
}
```

`radius_ms` is computed as `source_radius + ceil((t_recv − t_send) / 2)` over monotonic send and
receive readings, never wall readings. A source that states no radius is given none: its sample
carries the round-trip half only, and its class (§5.6) decides whether it may count.

### 4.3 Extrapolation

A sample taken at `mono_us = m0` speaks for a later reading `m` of the same boot as

```
mid(m)    = mid_ms + (m − m0) / 1000
radius(m) = radius_ms + ceil((m − m0) × DRIFT_PPM / 10^9) + 1
```

with `DRIFT_PPM = 200` (a bound twice the worst common quartz tolerance, stated as a bound and
never reported as a measured drift). A sample of another boot speaks for nothing. A sample older
than `MAX_SAMPLE_AGE` (6 h of monotonic time) is dropped.

### 4.4 Selection (Marzullo)

`select(samples, m, policy) -> Selection` extrapolates every live sample to `m`, takes the
`Interval` samples of the classes that may count (§5.6), and runs Marzullo's algorithm (as NTP's
intersection step and Roughtime clients do): sort the `2n` endpoints, sweep, and find the smallest
interval contained in the largest number of sample intervals. Ties on count go to the narrower
interval; ties on width to the earlier start. Counting is by distinct `SourceId`: where one
identity gave several samples, only its newest counts (P4). The result:

```
Selection {
  mid_ms, radius_ms,            // the chosen interval, extrapolated to m
  agreeing: Vec<SourceId>,      // identities whose intervals contain it
  consulted: Vec<SourceId>,     // identities with a live countable sample
  lower_bound_ms: Option<WallMs>,  // the greatest LowerOnly bound held (§5.3)
}
```

### 4.5 State

```
TimeState = Untrusted
          | Trusted { mid_ms, radius_ms }
          | Disagreeing { reason }
          | Tampered { signals }
```

The state is a function of the measurements; it is computed, never stored.

- **Tampered** if any tamper signal of §6 is open. An open signal closes only when a later
  selection is Trusted without counting any source that signal names, and the signal stays in the
  report's history (§7). Tampered is never sticky beyond that: a permanent flag would let one
  clock change disable a node.
- **Disagreeing** if two or more countable identities exist and the largest agreeing set is not a
  strict majority of `consulted`, or the chosen interval's upper end is below `lower_bound_ms −
  SKEW_MS` (a verified signed instant says it is later than every agreeing source does).
- **Trusted** if all of: at least `policy.min_agreeing` (default 2) distinct identities agree, at
  least one of them of the strong class (§5.6); the agreeing set is a strict majority of
  `consulted`; `radius_ms <= policy.max_radius_ms` (default and ceiling `SKEW_MS` = 300 000, the CC
  2.6.7 bound); and no signal is open.
- **Untrusted** otherwise.

`policy.max_radius_ms` MAY be tightened by a consumer (CC 2.6.7: "Tighter thresholds MAY be applied
by per-application consumer policy") and is never loosened past `SKEW_MS`.

### 4.6 Freshness helpers

Every helper takes a `TrustedNow`, never a bare integer:

```
TrustedNow { state: TimeState, lo_ms: WallMs, hi_ms: WallMs }   // lo/hi absent unless Trusted
Answer = Within | Outside | Undecidable
```

`Undecidable` is returned whenever the state is not Trusted, and whenever the two ends of the
interval give different answers. The caller's rule maps it; the defaults below are the fail-secure
direction of CC 2.6.7.

| Helper | CC | `Within` iff | `Undecidable` defaults to |
|---|---|---|---|
| `future_bound(asserted_at)` | 2.6.7 line 1 | `asserted_at <= lo + SKEW` (true at every point of the interval) | refuse, `CLOCK_SKEW_VIOLATION` |
| `before_valid_until(valid_until)` | 2.6.7 line 3 | `hi < valid_until` | refuse (not fresh) |
| `within_w(asserted_at)` | 2.6.7 line 5 | `hi − asserted_at <= W` | refuse, `asserted_at_stale` |
| `cosign_near(signed_at, sth_signed_at)` | 2.6.7 line 2 | `|signed_at − sth_signed_at| <= SKEW` | n/a: reads no clock |
| `witness_received(signed_at)` | CC 5.3.1 | `|signed_at − mid| <= SKEW − radius` | refuse |
| `attachable(newest_cosign)` | CC 3.2 T4a | `hi − newest_cosign <= attach_window_secs` | do not attach (`trust_root_head_stale`) |
| `halt_received_after(valid_until)` | CC 4.2.1.1 | `lo > valid_until` | **not after: the halt fires** |
| `key_record_live(valid_until)` | CC 2.4.1.1 | `hi < valid_until` | refuse |

Three rows read no clock and stay that way: `cosign_near` compares two signed instants; a
cosigned roster event has no window (CC 2.6.7 line 6); and a `constitutional` halt is not checked
against the future bound at all (CC 2.6.7 line 1, the one exception). The halt's own row is the
only one whose `Undecidable` falls toward acting.

T4 is not a helper: an attached root is valid until revoked, and no state of this service detaches
it or makes it invalid. Only attaching (T4a) reads the clock.

## 5. Sources

Each source produces `Sample`s. For each: what a sample proves, how the source can lie, and the
class that fixes its weight in §4.5.

### 5.1 Roughtime (strong)

`draft-ietf-ntp-roughtime`. The client sends a nonce; the server returns a signed response
containing the midpoint and radius, signed by an online key that the server's long-term key
delegates to for a stated validity window. Verify pins the long-term public keys.

- **Proves:** a holder of the pinned key asserted "the time is `mid ± radius`" after seeing this
  nonce. The nonce bounds the response to after the request; the round trip bounds it to before
  the receipt.
- **Chaining:** the nonce of request `i` is `H(response_{i−1} ‖ blind_i)`. A sequence of responses
  from different servers is therefore ordered by construction. If response `j` (later in the chain)
  states an interval wholly before response `i`'s, the pair is a transferable **malfeasance proof**
  against one of the two servers: anyone can verify both signatures and the chain. Verify keeps the
  chain of the last sampling round, raises `source_malfeasance` (§6.4) on such a pair, and reports
  the proof bytes.
- **Lies:** a server whose key is compromised, or whose operator lies, can state any time for any
  nonce. A single server's lie is undetectable alone; it is detected when a second server in the
  chain disagrees, and refuted by proof when the chain orders them.
- **Gap:** Roughtime signatures are Ed25519 only. A sample is a live freshness claim, not a
  long-lived authority, so a key broken later does not forge past samples; a key broken now forges
  live ones. CC's hybrid-at-every-federation-gate rule does not reach time samples as written (Q8).
- **Class:** strong. Two pinned servers under distinct operators can make the state Trusted.

### 5.2 NTS-secured NTPv4 (authenticated channel)

RFC 8915 over RFC 5905. A TLS 1.3 key-establishment exchange yields cookies and keys; each NTP
packet is then AEAD-authenticated.

- **Proves:** the NTP response came from the party that terminated the TLS session, as named by
  its WebPKI certificate. Offset and delay are NTP's (`((t2−t1)+(t3−t4))/2`, half the round trip
  added to the radius).
- **Does not prove:** anything transferable. The AEAD key is shared, so a response cannot be shown
  to a third party, and there is no malfeasance proof.
- **Lies:** the server lies freely; a mis-issued certificate lets a third party lie. Verify pins no
  certificate (removed in 23.0.0, #321); trust here is the WebPKI's, which is weaker than a
  signature against a baked key.
- **Class:** authenticated. Counts toward `consulted` and toward agreement, but cannot be the
  strong member §4.5 requires.

### 5.3 Signed instants verify already checks (lower bounds)

Verify verifies signed objects that carry instants: an edition-2 transparency receipt's CWT `iat`
(`edition2::receipt`, seconds), a signed tree head's `timestamp`, a witness cosignature's
`signed_at`, a verified genesis bundle's `asserted_at`, a verified row's `asserted_at`.

- **Proves:** the signer's clock read at least that instant when it signed, and the object existed
  before this node received it. With honest signers, true time at receipt is at least
  `instant − SKEW`. A signed instant gives a **lower bound only**: it carries no nonce from this
  node, so it cannot show that the present is not later (an old receipt replays forever).
- **Use:** these samples are `Bound::LowerOnly`. They never enter Marzullo and never make the state
  Trusted. They refute a clock set back (§4.5 Disagreeing; §6.2 high-water mark), which is the
  rollback attack T4a exists for.
- **Lies:** a signer with a fast clock raises the bound. Only verified objects under keys the node
  already recognises are taken, the bound is the signer's instant less `SKEW_MS`, and a bound more
  than `SKEW_MS` above every agreeing interval yields Disagreeing, not a correction.
- **Serve seats as time peers:** the genesis bundle seats serve nodes with composite key records.
  A seat could answer a nonce with a signed `mid ± radius` (a Roughtime-shaped response under its
  composite key), which would be a strong, hybrid-signed, seated source. No such object exists in CC
  today (Q1). Until it does, a seat contributes only the lower bounds above.

### 5.4 Peer time from mesh nodes (strong when signed and seated)

A peer answers a nonce with its trusted interval, signed.

- **Counting:** one voice per distinct seated identity (a key the node holds a live seat or
  membership for under the roster or community in force), never per occurrence, device or address
  (P4; CC 4.5.13's one vote per person counts fedIDs the same way). An unseated peer's sample is
  reported and counts zero. A peer that reports its own state as other than Trusted contributes no
  sample.
- **Proves:** a seated identity asserted the interval after seeing this nonce.
- **Lies:** a seated identity lies freely. Peer samples cannot outvote real sources unless the
  liars are a majority of the seated identities consulted. A peer relaying another source's time
  adds no independence: the peer's response names its own strong sources' identities, and an
  identity already counted directly is not counted again through a peer.
- **Gap:** CC has no object for a signed peer time response or for the nonce exchange (Q2).
- **Class:** strong when signed under a composite key and seated; otherwise not countable.

### 5.5 Weak signals (reported, never counted)

- **Plain SNTP / NTPv4 without NTS.** Unauthenticated UDP; any on-path party sets the answer.
  Reported with its offset; never counted.
- **`X-CEG-Server-Time` (CC 5.3.6).** An RFC 3339 header on every CEG response, protected only by
  TLS. Reported; never counted. The header gives no radius, so its sample carries the round-trip
  half only.
- **HTTP `Date`.** Seconds precision, unauthenticated beyond TLS. Reported; never counted.
- **The operating-system clock.** Whatever the operator or the OS's own NTP daemon set. It is the
  reference every offset is reported against (§7), and the one source this service exists to check.

### 5.6 Classes

| Class | Sources | Counts in Marzullo | Can be the strong member | Raises the high-water mark |
|---|---|---|---|---|
| strong | Roughtime (pinned key), signed seated peer, signed seat time (if Q1) | yes | yes | yes, while Trusted |
| authenticated | NTS-NTPv4 | yes | no | yes, while Trusted |
| lower bound | receipt `iat`, STH `timestamp`, cosignature `signed_at`, verified row and bundle instants | no | no | yes, at `instant − SKEW` |
| weak | SNTP, `X-CEG-Server-Time`, HTTP `Date`, OS clock | no | no | **no** |

The class is a property of how a sample was obtained, fixed in code and reported with the sample.
It is not an output tier; consumers read the measurements (§7).

## 6. Tamper detection

A tamper signal names a contradiction between the local clock and something that cannot have
moved the way the clock did. Each signal is a refutation; none is a proof of correct time.

### 6.1 Wall against monotonic

At each sampling round the host records `(os_wall_ms, mono_us, boot)`. Between two records of one
boot, `step = Δos_wall − Δmono/1000`.

- `|step| <= Δmono × DRIFT_PPM / 10^9 + 1000` ms is slew and is ignored.
- A larger step is recorded as `wall_step` with its size and sign. A step is not by itself
  tampering: the OS's own NTP daemon steps the clock. It becomes the open signal `wall_step_out`
  when the step moves the OS clock **out of** the current Trusted interval (a step into it is a
  correction).
- `mono_us` lower than the previous record of the same boot is `monotonic_regressed` (a host or
  hypervisor fault; the halt fuse adds zero for it, §3.2).

### 6.2 Sealed high-water mark

The host keeps `hwm_ms` in `SecureBlobStorage` (`ciris.time.high_water.v1`): the greatest of the
`lo` ends of Trusted intervals and of lower bounds (§5.3) it has held. It rises only from those
two; the OS clock and weak sources never raise it, or one forward clock change would make every
later honest reading look like a rollback.

- An OS clock below `hwm_ms − SKEW_MS` is `os_clock_below_high_water` (a clock set back).
- A Trusted interval whose `hi` is below `hwm_ms − SKEW_MS` is `trusted_below_high_water`: the
  sources agree on a time this node has already seen pass. The sources it names are excluded until
  the signal closes.
- **Limit:** sealing proves the blob came from this device, not that it is the newest blob. A
  replayed older blob lowers the mark. Where the TPM plugin offers an NV monotonic counter (§6.3)
  the blob carries the counter value and a blob behind the counter is refused; elsewhere the limit
  stands (TT-6).

### 6.3 TPM 2.0 clock

`TPMS_CLOCK_INFO { clock, resetCount, restartCount, safe }`, read by `TPM2_ReadClock` through the
TPM plugin. `clock` is milliseconds the TPM has been powered since its last clear, persisted to NV;
`resetCount` increments on each TPM Reset (cold boot); `restartCount` on each TPM Restart (resume
from hibernation); `safe` is NO when `clock` may have been reported higher before an unorderly
shutdown.

- Within one `(resetCount, restartCount)`, `Δclock` is an elapsed measure independent of the OS. A
  wall step not matched by `Δclock` (beyond slew) corroborates `wall_step`.
- `clock` lower than the last recorded value with `safe = YES` and the same `resetCount` is
  `tpm_clock_regressed`.
- A `resetCount` that goes down is `tpm_reset_count_regressed` (a different TPM, or a replayed
  record).
- `TPM2_ClockSet` lets the platform owner move `clock` forward, never back. The TPM clock therefore
  refutes a backward change and never measures the halt fuse: an owner could advance it and
  shorten a fuse counted on it.
- **ABI:** the plugin's ABI v3 offers seal, unseal, signer and quote. A quote's `TPMS_ATTEST`
  carries `clockInfo`, but under a non-endorsement key `resetCount` and `restartCount` are
  obfuscated. Phase 1 adds `ciris_tpm_read_clock` (ABI v4) and an NV counter pair
  (`ciris_tpm_nv_counter_read` / `_increment`) for §6.2. A plugin of ABI v3 yields no TPM signals,
  which is not a failure (P3).

### 6.4 Disagreement between sources

- `source_malfeasance`: a Roughtime chain pair of §5.1. The signal names one of the two servers
  without saying which; both are excluded until a later round orders them against a third.
- `source_outlier`: a countable identity outside the chosen interval in two consecutive rounds.
  Reported; not a tamper signal alone, since a lagging honest server looks the same.
- `lower_bound_above_trusted`: §4.5's Disagreeing condition, reported as a signal so the history
  shows it.

### 6.5 What a signal does

An open signal makes the state Tampered (§4.5), so every freshness helper answers `Undecidable`
and falls fail-secure, and the host refuses to stamp signed rows (§8.1). It does not touch the halt
latch (P5), does not detach an attached root (T4), and does not end a running node.

## 7. Outputs

The service reports measurements. The state of §4.5 is included because it is the rule every
helper reads, and the measurements it was computed from are always beside it, so a consumer can
apply its own rule instead.

```json
{
  "state": "trusted",
  "monotonic_us": 81234567890,
  "boot": "<32 hex>",
  "os_wall_ms": 1795262400123,
  "chosen": {
    "mid_ms": 1795262400101,
    "radius_ms": 41,
    "offset_ms": -22,
    "agreeing": ["roughtime:<thumbprint>", "roughtime:<thumbprint>", "nts:time.example"],
    "consulted": ["roughtime:<thumbprint>", "roughtime:<thumbprint>", "nts:time.example"],
    "anchored_monotonic_us": 81230000000,
    "drift_bound_ppm": 200
  },
  "lower_bound_ms": 1795262391000,
  "high_water_ms": 1795262400060,
  "sources": [
    {
      "kind": "roughtime", "class": "strong", "identity": "<thumbprint>",
      "offset_ms": -21, "radius_ms": 12, "rtt_us": 18400,
      "sampled_monotonic_us": 81230000000, "age_ms": 4567,
      "verified": true, "in_chosen": true, "error": null
    },
    {
      "kind": "sntp", "class": "weak", "identity": "pool.ntp.org",
      "offset_ms": null, "radius_ms": null, "rtt_us": null,
      "sampled_monotonic_us": 81229000000, "age_ms": 5567,
      "verified": false, "in_chosen": false, "error": "timeout"
    }
  ],
  "tamper_signals": [
    { "kind": "wall_step", "open": false, "step_ms": 3600000,
      "at_monotonic_us": 80000000000 }
  ],
  "tpm": { "clock_ms": 912345678, "reset_count": 41, "restart_count": 0, "safe": true }
}
```

- `offset_ms = mid_ms − os_wall_ms`: positive means the OS clock is behind. (The agent's
  `get_adjusted_time` subtracts an ntplib offset whose sign is the opposite of its docstring; one
  stated convention ends that.)
- Every field of a source whose query failed is `null` except `kind`, `class`, `identity`,
  `sampled_monotonic_us`, `age_ms`, `verified: false` and `error`. `chosen` is `null` unless
  Marzullo found an interval; `tpm` is absent without a TPM of ABI v4.
- `error` tokens: `timeout`, `unreachable`, `bad_signature`, `bad_delegation`, `delegation_expired`,
  `nonce_mismatch`, `malformed`, `unpinned_key`, `tls_failed`, `kod` (NTP kiss-of-death),
  `unseated`, `peer_not_trusted`, `rate_limited`.
- History: the last 64 tamper signals, open and closed, with their monotonic instants.

No field is named for a level or a tier, and none is filled by an estimate (P1).

## 8. Wiring

### 8.1 Host tier: the time service

`ciris_verify_core::time_host` (`host` feature) owns the sources, the samples and the persisted
high-water mark.

- **Sampling:** at start, then every 15 min of monotonic time while Trusted and every 60 s
  (backing off to 15 min) while not. A wall step (§6.1), a resume from suspend, or a boot change
  forces a round. Roughtime servers are queried in one chained round; NTS servers in parallel.
- **`now()`** returns `TrustedNow` (§4.6) extrapolated from the last selection to the current
  monotonic reading. It never returns the OS clock as trusted.
- **`stamp()`** returns the `mid_ms` to place in a signed `asserted_at`, in POSIX
  milliseconds, or `ClockUntrusted` unless the state is Trusted. This is the
  native form of the WIT rule that a node does not stamp signed rows before `clock-trusted`. A
  native producer may pass `StampPolicy::OsClockAccepted` to stamp from the OS clock while
  Untrusted; the result is marked so in the call's return and the process log. Whether CC allows it
  is Q6.
- **Configuration:** the Roughtime set (keys, addresses, operators), the NTS set, peer sampling on
  or off, `max_radius_ms`, `min_agreeing`. Defaults are baked; an operator may add sources and
  tighten policy, and may not remove the requirement for a strong member.

### 8.2 FFI and Python

FFI (JSON in / JSON out, as the other `ciris_verify_*` surfaces):

| Function | Returns |
|---|---|
| `ciris_verify_time_status()` | the §7 report |
| `ciris_verify_time_now()` | `{state, lo_ms, hi_ms, mid_ms, radius_ms}` (`lo`/`hi`/`mid`/`radius` null unless Trusted) |
| `ciris_verify_time_stamp(policy)` | `{asserted_at_ms, policy}` or `CLOCK_UNTRUSTED` |
| `ciris_verify_time_check({helper, instant_ms, …})` | `{answer: within/outside/undecidable, state}` for a §4.6 helper |
| `ciris_verify_time_sample()` | forces a round (rate-limited to one per 10 s); returns the report |
| `ciris_verify_accord_latch_status()` | §3.4 (Phase 0) |

Python (`ciris_verify.time`): `status()`, `now()`, `stamp(allow_os_clock=False)`,
`check(helper, instant_ms, **params)`, `sample()`, with `TimeReport`, `TrustedNow`, `TimeState`,
`SourceSample`, `TamperSignal` in `ciris_verify/types.py`. Rust `tracing` events for state
transitions and tamper signals reach logcat and the iOS console through the existing logging
wiring.

### 8.3 The agent

The agent's `TimeService` becomes a thin client of `ciris_verify.time`:

- `now()` / `now_iso()` / `timestamp()` keep their signatures for non-signing uses (logs,
  scheduling, UI) and return the OS clock, as today.
- A new `signing_now()` returns `ciris_verify.time.stamp()` and raises when the clock is untrusted.
  Every place the agent stamps a signed instant moves to it.
- `get_uptime()` reads the monotonic clock, not the difference of two wall readings.
- Metrics: `time_drift_ms` is removed. It is replaced by `time_offset_ms` (the §7 `offset_ms`, or no
  value when `chosen` is null), `time_radius_ms`, `time_state` and `time_tamper_signals_open`. The
  hourly `ntplib` query, the pool list and `_simulate_drift` are deleted: they are an
  unauthenticated weak source (§5.5) and a fabricated measurement (P1).
- `get_adjusted_time()` is removed. Correcting the OS clock by an offset is not this service's job,
  and the current implementation applies the offset with the wrong sign.
- The halt act gate reads `ciris_verify_accord_latch_status` and nothing of this service (P5).

### 8.4 CIRISPersist

Persist's admission checks (the CC 2.6.7 future bound, `asserted_at_stale` under `W`, the CC 5.3.1
cosignature receipt bound, CC 3.2 T4a attaching) call the §4.6 helpers with a `TrustedNow` from the
host's time service, and map `Undecidable` as the table says. A row refused only because the state
was not Trusted is refused with the same token (`CLOCK_SKEW_VIOLATION`, `asserted_at_stale`,
`trust_root_head_stale`) and a `details.clock_state` field, so the refusal can be retried; it is
never admitted-as-stale. Persist does not re-apply an arrival-clock check to a replicated row where
CC forbids it (CC 2.6.7 line 4; CC 3.1.3.1 session claims).

### 8.5 WIT host

The native host implementing `ciris:node@0.1.0` (`ciris-rt`'s `Host` seam; CIRISServer's native
host) implements `interface clock` from this service:

- `monotonic-us` from the §3.3 clock, rebased to the host's start. It exceeds the WIT promise (it
  advances across suspend where the platform allows).
- `wall-ms` is `none` until the first Trusted selection, then `mid_ms` of `now()`.
- `event.clock-trusted` fires on the first Trusted selection.
- The node's halt latch runs Phase 0's accumulator on `monotonic-us`. Every `init` is a new boot
  (§3.3), and persisted elapsed time is read from the node's sealed volume.

WIT 0.1.0 says `clock-trusted` "fires once" and does not say what `wall-ms` returns after the host
loses trust. This FSD needs `wall-ms` to return `none` again in the Disagreeing and Tampered
states, and an event when it does (proposed `clock-untrusted`, WIT 0.2.0). Until then the native
host keeps returning the last Trusted `mid_ms` extrapolated, with a radius that grows past
`SKEW_MS`, and logs the state; this is the one place the WIT contract and §6.5 disagree.

## 9. What stays out

- Setting the OS clock. The OS's NTP daemon does that; this service measures it.
- A time authority. No source, including a baked Roughtime set, is a federation authority; the
  accord's trust root is the genesis bundle (CC 5.3.4), and time decides attaching, never validity
  (T4).
- Leap seconds. POSIX milliseconds and Roughtime's midpoint both smear or ignore them; a leap
  second is within any radius this service accepts.
- Time zones and calendars. Every instant is UTC POSIX milliseconds.

## 10. Phases

| Phase | Release | Scope |
|---|---|---|
| 0 | 23.4.1 | §3: halt fuse on accumulated monotonic time, persisted in custody storage; latch shape and FFI change; TLA+ fuse model; agent act gate unchanged in shape |
| 1 | 23.5 | §4 pure core (samples, Marzullo, state, helpers); OS clock and monotonic sources; §6.1 wall/monotonic, §6.2 high-water mark; TPM plugin ABI v4 (`read_clock`, NV counter) and §6.3; §7 report; FFI and Python surface; `stamp()`; agent `TimeService` replacement (P1 enforced: drift fabrication removed) |
| 2 | 23.6 | Roughtime client with chaining and malfeasance proofs; baked Roughtime set (per Q3); §5.3 lower-bound samples from receipts, STHs, cosignatures and verified rows; persist switches its admission checks to the helpers; `halt_received_after` on trusted time |
| 3 | 24.x | NTS-NTPv4 client; peer time and seat time once CC has the object (Q1, Q2); WIT 0.2.0 `clock-untrusted` |

Phase 0 depends on nothing else here. Phases 1 to 3 do not change the fuse.

## 11. Threats

In the style of `docs/THREAT_MODEL.md` §3. Proposed for that document as AV-53 to AV-62 (AV-52 is
the kid/iss finding of #349).

#### TT-1: Clock set forward to lapse a halt

**Attack:** after a halt lands, the operator sets the wall clock forward by more than
`halt_fuse_secs`, so the latch reads the fuse as run and agents resume.
**Effect today:** the halt lapses at once (`accord_halt_latch`, §3.1).
**Mitigation:** Phase 0. The fuse is accumulated monotonic time; no wall-clock value enters it.
**Residual:** none from the wall clock. A host that controls the monotonic clock (a hypervisor)
can run it fast; TT-2.

#### TT-2: Monotonic clock run fast or a restart forged

**Attack:** a hypervisor advances `CLOCK_BOOTTIME`, or a debugger rewrites the persisted
`elapsed_ms` upward.
**Mitigation:** a boot change adds zero. In Phase 0 the latch state is the caller's JSON and an
edit to it is not detected (an actor who can edit it can delete the halt outright); from Phase 1 it
is sealed (`SecureBlobStorage`), so an edit requires the custody key.
**Residual:** a host that controls the virtual machine's clock and memory controls the agent; the
halt's reach then rests on the other nodes, each counting its own fuse (CC 4.2.1.1).

#### TT-3: Latch state deleted or rolled back

**Attack:** delete or restore an old latch blob to drop a halt.
**Mitigation:** absent or older state reads as less elapsed time (§3.2 rule 4); the host
re-applies held accord rows on start.
**Residual:** a store that no longer holds the halt row loses the halt. That is the store's
integrity, outside this FSD.

#### TT-4: Clock set forward to pass a freshness check

**Attack:** move the clock forward so a future-dated row admits, or so an attacker's row wins LWW
(CC 5.3.2.3's skew-bounded admission).
**Mitigation:** admission reads trusted time; a clock forward of the trusted interval makes no
difference, and a source-side lie needs a majority of countable identities including a strong one.
**Residual:** a compromised majority of the configured strong sources.

#### TT-5: Clock set back to keep an expired key or a stale head alive

**Attack:** move the clock back so a key past `valid_until` verifies, or a stale lineage head
attaches (the T4a rollback hole).
**Mitigation:** trusted time ignores the OS clock; §6.2 high-water mark and §5.3 lower bounds refute
a backward clock even with no network.
**Residual:** a node with no network, no TPM and a replayed high-water blob (TT-6) is Untrusted and
refuses; it does not accept.

#### TT-6: Replayed high-water blob

**Attack:** restore an older sealed high-water blob to lower the mark, then set the clock back.
**Mitigation:** the TPM NV counter binds the blob to a counter that only increases (§6.2).
**Residual:** without a TPM counter the mark can be lowered to any earlier sealed value. The node is
still Untrusted without network sources, so the effect is lost refutation, not false acceptance.

#### TT-7: One lying time server

**Attack:** a compromised or coerced Roughtime or NTS operator states a false time.
**Mitigation:** two agreeing identities including a strong one, a strict majority of those
consulted, and Roughtime chaining that turns a contradiction into a transferable proof.
**Residual:** a majority of the configured servers lying in concert. The baked set's operator
diversity is a governance question (Q3).

#### TT-8: Sybil peers

**Attack:** stand up many mesh nodes that report a false time.
**Mitigation:** peer samples count once per distinct seated identity; unseated peers count zero
(P4, §5.4).
**Residual:** a majority of seated identities colluding, which is also a capture of the roster.

#### TT-9: On-path attacker on plain NTP or HTTP time

**Attack:** rewrite SNTP replies or the `X-CEG-Server-Time` header.
**Mitigation:** both are weak signals and never counted (§5.5).
**Residual:** none to trusted time; the OS clock itself may follow a spoofed SNTP, which §6.1
reports as a step.

#### TT-10: Denial of trusted time

**Attack:** block every time source so the node stays Untrusted, and its admission checks refuse.
**Mitigation:** CC 2.6.7 requires the refusal (fail-secure). Running nodes keep their attached root
(T4), the halt latch needs no time (P5), and replication receive needs none (WIT).
**Residual:** an isolated node cannot admit rows that need a freshness check or stamp signed rows
until a source returns. That is the cost CC 2.6.7 chooses; Q4 and Q6 ask whether CC intends it.

#### TT-11: Fabricated measurement

**Attack (defect):** a component reports an estimate as a measurement, so an operator or a
consumer trusts a clock nobody checked. The agent's `_simulate_drift` does this today.
**Mitigation:** P1; the report's schema has no field for an estimate, and the agent's metric is
removed (§8.3).

## 12. Open questions for CC

1. Should serve nodes offer a Roughtime-shaped signed time response (nonce in, `mid ± radius`
   signed under the seat's composite key out), so that genesis-bundle seats are strong, hybrid,
   seated time sources?
2. Does peer time need a CC object: the nonce request, the signed response, and the rule that a
   peer's sample counts once per seated identity?
3. Which Roughtime servers or keys, if any, get baked into verify, and under what governance (who
   adds and removes a key, and whether operator diversity is a stated requirement)?
4. Is the ±5 min check made against trusted time or the raw clock? CC 2.6.7 line 3 reads as trusted
   time for long-lived attestations; line 1 (the future bound) and the admission bounds of CC 5.3.1
   and CC 5.3.2.3 say only "its own clock".
5. Does the halt fuse's monotonic rule need CC text? CC 4.2.1.1 says "the node's own clock" and
   CC 4.5.13 "receipt is the one clock no signer sets"; this FSD reads both as elapsed monotonic time,
   accumulated across restarts, with an unknown gap counted as zero.
6. May a producer stamp a signed instant from an untrusted clock? The WIT forbids it for a WASM
   node; CC 2.6.7 says only that producers SHOULD synchronise.
7. Should a Roughtime malfeasance proof (or any time-source contradiction) be a CEG row, so that
   one node's proof reaches the others?
8. Does the hybrid-at-every-federation-gate rule reach time samples? Roughtime is Ed25519 only; a
   seat time response (Q1) could be composite.
9. Should a suspended device's fuse count suspended time? §3.3 counts it where the platform allows
   and does not where it cannot (a WASM host), which extends the halt there.
