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
| `seal` | `generate(id, kind)`, `sign_composite`, `sign_classical`, `sign_pqc`, `kem_decap` (transit-kex, → `Zeroizing` 64-byte ikm), `xwing_decap` (onion-hop, → `Zeroizing` 32-byte X-Wing secret), `wrap`, `unwrap` (→ `Zeroizing`); `describe`, `public_key` re-exported |
| `lifecycle` | `current()`, `next().await`, `clock_trusted()`, `wait_clock_trusted().await` |
| `RtNode`, `node!` | the export helper |
| `replay` (default feature) | `Session::{record, replaying, init, tick, on_event, api, log, finish}`, `replay::<N>(&Log) -> Log`, `Log::{to_jsonl, from_jsonl, entries, import_calls}` |

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

**Format: JSON lines.** Line 1 is `{"format":"ciris-rt-replay","version":1}`.
Each further line is an object with sorted keys
`{"args","call","dir","ret","seq"}`:

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

**A log holds every secret that crossed the boundary** (random bytes,
`unwrap` plaintexts, `kem-decap` material). Treat it as secret.

`tests/it/replay.rs` records a node that uses timers, `random.fill`, a
scripted stream with partial writes and would-block, a `timeout` and a seal
call. It then round-trips the log through JSON lines and replays it with no
host. The replay gives an identical import sequence and a byte-identical log
and node output. A flipped random byte fails loudly, and so does a truncated
log.

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
