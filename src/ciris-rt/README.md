# ciris-rt

The single-threaded cooperative executor inside the CIRIS WASM node: work
item 2 of CIRISServer `FSD/WASM_NODE.md` (§5.1 model, §5.2 mapping, §5.4
bound, §11.4 replay). It runs under the host loop and reaches the host only
through [`ciris-host-abi`](../ciris-host-abi)'s wrappers.

```text
loop:
    poll host I/O; deliver events with on-event   -> Runtime::on_event
    deadline = tick(budget)                        -> Runtime::tick
    sleep until deadline or host event
```

## Writing a node

```rust
struct MyNode;
impl ciris_rt::RtNode for MyNode {
    fn init() -> Result<(), String> {
        ciris_rt::spawn(async {
            let mut iv = ciris_rt::time::interval(std::time::Duration::from_secs(30));
            loop {
                iv.tick().await;
                /* a replication round */
            }
        });
        Ok(())
    }
    fn api(req: Vec<u8>, _local: bool) -> Vec<u8> { req }
}
ciris_rt::node!(MyNode); // init / api from MyNode, tick / on-event from the runtime
```

`node!` expands to a `ciris_host_abi::Node` named `__CirisRtNode` and
calls `ciris_host_abi::export_node!` on it. On wasm32 that emits the
`node` world exports; natively a host (or the replayer) calls the
`Node` methods directly.

## API

| Item | Shape |
|---|---|
| `spawn` | `fn spawn<F: Future + 'static>(fut: F) -> JoinHandle<F::Output>`, no `Send` bound |
| `JoinHandle<T>` | `Future<Output = Result<T, JoinError>>`, `abort()`, `is_finished()`; drop detaches |
| `Runtime` | `new()`, `current()`, `spawn`, `tick(budget_us: u32) -> u64`, `on_event(Event)`, `tasks()`, `polls()`, `timers()` |
| `yield_now`, `blocking`, `spawn_blocking` | `blocking(f).await` and `spawn_blocking(f)` run `f` inline (FSD §5.2) |
| `time` | `Instant` (std-shaped, µs), `Duration`, `sleep`, `sleep_until`, `timeout`, `timeout_at` → `Result<T, Elapsed>`, `interval`, `interval_at`, `Interval::{tick, poll_tick, reset, period, set_missed_tick_behavior}`, `MissedTickBehavior` |
| `net` | `dial(..).await -> Connection`, `listen(c, &ListenOptions) -> Listener`, `Listener::accept().await`, `bind(..) -> Datagram`; `Connection::{conn_info, read, write, write_all, send_message, recv_message, close}`, `futures_io::AsyncRead` / `AsyncWrite`; `Datagram::{send_to, recv_from, local_addr, max_datagram, multicast_join, multicast_leave}`; `NetError` |
| `seal` | `generate(id, kind)`, `sign_composite`, `sign_classical`, `sign_pqc`, `xwing_decap` (transit or onion-hop, → `Zeroizing` 32-byte X-Wing secret), `wrap`, `unwrap` (→ `Zeroizing`); `describe`, `public_key` re-exported |
| `lifecycle` | `current()`, `next().await`, `clock_trusted()`, `wait_clock_trusted().await` |
| `RtNode`, `node!` | the export helper |
| `replay` (default feature) | `Session::{record, record_with, replaying, replaying_with, init, tick, on_event, api, log, finish}`, `replay::<N>(&Log) -> Log`, `replay_with::<N>(&Log, impl SecretSource) -> Log`, `Log::{to_jsonl, from_jsonl, entries, import_calls, secrets}`, `SecretSource`, `SecretOp`, `TestSecrets`, `SeededRandom`, `RecordOptions`, `raw_capture_allowed` |

## Tick and timers

* **Tasks** live in a slot vector with generation counters. Wakers are
  `Arc`s pushing onto a mutexed FIFO, so the `Waker` contract
  (`Send + Sync`) holds even if a channel moves a waker across threads.
* **`tick(budget_us)`** reads `clock.monotonic-us` once at the start and
  once after every poll, and stops as soon as `budget_us` has elapsed
  (§5.4). It always runs at least one poll, so a zero budget still makes
  progress. Tasks run in rounds: each round polls the tasks that were
  ready when it began, and tasks woken meanwhile run in the next round
  (round-robin; a self-yielding task cannot starve others). A tick makes
  at most `MAX_ROUNDS_PER_TICK` (64) rounds, so it returns even under a
  clock that never moves.
* **Return value:** the current time if tasks are still ready (tick me now),
  else the earliest timer deadline, else `u64::MAX`. The same value goes to
  `wake.next-deadline` on every tick.
* **Timers** are a `BTreeMap<(deadline_us, seq), Waker>`: ordered by
  deadline, ties in creation order, so firing is deterministic. Expired
  timers fire at the start of each tick and after every round. A `Sleep`
  reads the clock once on its first poll (and finishes at once if already
  due); after that it only checks whether its entry fired. Dropping it
  removes the entry. Sleep deadlines round **up** to the next microsecond,
  so a sleep never ends early. `Instant + Duration` truncates.
* **`Interval`'s missed-tick default is `Skip`**, not tokio's `Burst`: a
  hidden browser tab ticks once a minute and a suspended host not at all
  (FSD D2), so firing every missed tick on resume is the wrong default.
  `Burst` and `Delay` are available.
* **`event.timer`** needs no routing: timers fire on the tick that follows.

## Events and tokens

`Runtime::on_event` routes each `ciris:node` event by token:

| Event | Effect |
|---|---|
| `readable(t)`, `writable(t)` | wake the reader / writer parked on `t` |
| `connected(t)`, `failed({t, reason})` | record the dial outcome; wake the dialler |
| `listener-failed({t, reason})` | fail the listener's `accept` |
| `closed({t, reason})` | record it; wake everything on `t` |
| `sealed(t)` | wake the seal future, or take and zeroize an orphaned result |
| `lifecycle(p)` | queue `p` for `lifecycle::next` (oldest dropped past 64) |
| `clock-trusted` | wake `wait_clock_trusted` |
| `timer` | nothing; the tick fires due timers |

Tokens are `kind << 56 | n`, with `n` counting from 1 per runtime and never
reused. The kinds are 1 connection, 2 listener, 3 datagram socket and 4 seal
operation. They are deterministic, so a replay issues the same tokens.

Readiness is **edge-triggered** (ciris-host-abi README). Every adapter calls
the non-blocking operation first and parks only after `would-block`, so it
never waits for an edge that already passed. Each direction of a connection
has one waker slot, so one reader and one writer may wait at a time.

## Channels

Channels are not ciris-rt's job. Executor-agnostic channels work because
they use only the `Waker` contract. `tests/it/channels.rs` runs
`futures-channel` `oneshot` and a bounded `mpsc`, and `tokio::sync`
`oneshot`, a bounded `mpsc` and `Notify`, between ciris-rt tasks.

**tokio with only the `sync` feature** builds for wasm32-unknown-unknown and
pulls in no mio. On that target its whole dependency set is
`pin-project-lite` (`cargo tree -p ciris-rt --target wasm32-unknown-unknown
-e normal,dev`). Do not enable `rt`, `time` or `net` in a node build:
tokio's own timers panic without a tokio runtime, so use `ciris_rt::time`
instead.

## Record and replay (feature `replay`, default)

A `Session<N>` drives node `N`'s exports through a `Host` that does one of
two things:

- **records**: it forwards every import to a real host and logs the call,
  its arguments and its result;
- **replays**: it serves results from a log with no host, and panics at the
  first divergence. A divergence is a different call or argument, an
  unrecorded import, a recorded import never made, or a different export
  return.

`replay::<N>(&log)` re-runs a whole log and returns the log it produced,
byte-identical for a deterministic node.

**Format: JSON lines.** Line 1 is the header,
`{"format":"ciris-rt-replay","secrets":"redacted","version":2}`. Each
further line is an object with sorted keys `{"args","call","dir","ret","seq"}`:

* `dir` is one of:
  * `export`: the host called the node;
  * `import`: the node called the host;
  * `return`: the export returned `ret`.
* `call` is the WIT name, e.g. `tick`, `clock.monotonic-us` or
  `[method]stream.recv`.
* Bytes are lowercase hex and enums are their WIT names.
* `result<T, errno>` is `{"ok":T}` or `{"err":"would-block"}`. Options are
  `null` or the value.
* Host resources (a stream, volume or datagram socket) are numbered 1, 2, …
  in order of appearance: `{"ok":{"stream":1}}`.

The log covers every import in the `node` world, including storage, plus
every event delivered (as `on-event` exports).

### Secrets are redacted by default

Ephemeral keys are never persisted in plaintext, and a log is a file. So
these values are written as `{"len":<n>,"redacted":true,"sha256":"<hex>"}`
(SHA-256 of the bytes), never as the bytes:

* the result of `random.fill` (its bytes become ephemeral keys and nonces);
* the `seal.take` result of a `seal.unwrap` or `seal.xwing-decap` (the
  token is remembered when the operation starts);
* the `plaintext` argument of `seal.wrap`.

Signatures, public keys, wrapped blobs and everything else stay raw. A node
that logs a secret through `log.record`, or sends one in clear over a
stream, still puts it in the log; that is the node's bug, not the
recorder's.

**Replay of a redacted log** takes a `SecretSource`
(`replay::replay_with::<N>(&log, source)`, `Session::replaying_with`). The
source re-supplies each redacted value, and the replayer checks it against
the recorded `sha256` and `len`, panicking on any mismatch.
`replay::TestSecrets::new(SeededRandom::new(seed), vault)` is the test
source:

* `SeededRandom` is SHA-256 in counter mode over a seed, the same stream the
  scripted host's `random.fill` drew from. It is test only.
* `vault` is any `Host` implementing the seal operations, which re-runs
  each `unwrap` or `xwing-decap`.

Replaying a redacted log without a source panics, saying it needs one.

### Raw capture: never in release

`Session::record_with(host, RecordOptions { capture_raw_secrets: true })`
writes those values raw and marks the header `"secrets":"raw"`; a raw log
replays without a source. It needs **both** of these:

* the cargo feature `replay-capture-secrets` (off by default);
* the runtime flag.

It is **also refused (panics) in any build without `debug_assertions`**,
i.e. every `--release` build, even with the feature on. When it starts, it
logs an error-level `log.record` warning (`RAW SECRET CAPTURE IS ON …`)
through the live host. **Never enable `replay-capture-secrets` in a release
or production build.**

`tests/it/replay.rs` records a node that uses timers, `random.fill`, a
scripted stream with partial writes and `would-block`, a `timeout`, a
composite signature, `wrap` / `unwrap` and `xwing-decap`. It covers:

* a redacted record, then a replay with the test source, giving a
  byte-identical log, output and import sequence;
* the log contains none of the random draws, the wrap plaintext or the
  decapsulated secret;
* a wrongly seeded source and a tampered vault, both caught by the hash
  check;
* a missing source, a changed import and a truncated log, all failing
  loudly;
* raw capture refused without the feature (and in release with it), and
  working with it:
  `cargo test -p ciris-rt --features replay-capture-secrets`.

## No target cfg, and std

`ciris-cfg-lint src/ciris-rt` passes: the crate contains no `cfg(target_*)`.
It is `#![no_std]` + `alloc` and links `std` for three things only, all
available on wasm32-unknown-unknown and x86_64-unknown-uefi:

* `thread_local!`, for the per-thread current runtime;
* `std::sync::Mutex`, for the run queue behind the `Send + Sync` wakers;
* `std::io::Error`, for `futures-io`.

`ciris-host-abi` already requires `std` (wit-bindgen `std`).
`cargo +1.89 check -p ciris-rt --lib --target x86_64-unknown-uefi` passes.

## Smoke module

```
cargo build -p ciris-rt --example rt-smoke-node --target wasm32-unknown-unknown --release --no-default-features
cargo run -p ciris-host-abi --bin ciris-abi-gate -- target/wasm32-unknown-unknown/release/examples/rt_smoke_node.wasm
```

`init` spawns a task that draws `random.fill`, sleeps 20 ms on the runtime's
timers and logs when the sleep ends. The module's imports are six, all
`ciris:node/*`:

* `clock.monotonic-us`
* `log.metric`
* `log.record`
* `random.fill`
* `seal.take` (the orphaned-result cleanup in `on_event`)
* `wake.next-deadline`

`cargo test -p ciris-host-abi --test smoke_wasm -- --ignored` builds and
gates it. That test lives in ciris-host-abi because the gate is native-only.

## Checks

```
cargo fmt --all
cargo clippy -p ciris-rt --all-targets -- -D warnings
cargo clippy -p ciris-rt --all-targets --target wasm32-unknown-unknown -- -D warnings
cargo test -p ciris-rt
cargo +1.89 check -p ciris-rt --all-targets [--target wasm32-unknown-unknown]
cargo run -p ciris-host-abi --bin ciris-cfg-lint -- src/ciris-rt
```
