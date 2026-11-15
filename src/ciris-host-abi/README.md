# ciris-host-abi

The `ciris:node` host interface of the CIRIS WASM node: work item 1 of
CIRISServer `FSD/WASM_NODE.md` (§4, §5.1, §8, §10.1). It sits below every
repo that builds into the node module (verify, persist, edge, leviculum,
server).

| Piece | Where |
|---|---|
| The normative WIT, package `ciris:node@0.1.0`, worlds `node` and `vault` | [`wit/ciris-node.wit`](wit/ciris-node.wit) |
| wit-bindgen 0.51.0 guest bindings for a **core** module (§4.2) | `src/bindings.rs` |
| Safe wrappers node crates call (`clock`, `random`, `storage`, `net`, `seal`, `wake`, `log`), the `Node` trait, `export_node!` | `src/lib.rs` |
| The native host seam (`host::Host`, `host::install`) | `src/host.rs` |
| **The target boundary**: the only `cfg(target_*)` a node build depends on | `src/sys/` |
| getrandom custom backend over `random.fill` (feature `getrandom-backend`) | `src/sys/wasm.rs` |
| Import-allowlist gate | `src/gate.rs`, `ciris-abi-gate` |
| Target-`cfg` lint | `src/cfg_lint.rs`, `ciris-cfg-lint` |
| Smoke node module | `examples/smoke_node.rs` |

## The rule (§4.1)

1. The node module imports only `ciris:node/*` interfaces of its world. No
   `wasi:*`, no `env`, no wasm-bindgen. `ciris-abi-gate` enforces it.
2. Node crates contain no `cfg(target_*)`, `cfg(unix)` or `cfg(windows)`.
   Hosts differ by runtime answers (`net.carriers`, `net.can-listen`,
   `volume.durability`, `seal.describe`). `ciris-cfg-lint` enforces it.
   **This crate is the one place allowed to branch on target**, and all of
   that branching is inside `src/sys/` (plus the declarations of the two
   native-only tool modules, and `[target]` tables in this crate's
   `Cargo.toml`).
3. No ambient authority: no paths, environment, sockets or processes.

## Writing a node

```rust
use ciris_host_abi::{clock, log, random, Event, Node};

struct MyNode;
impl Node for MyNode {
    fn init() -> Result<(), String> { Ok(()) }
    fn tick(budget_us: u32) -> u64 { clock::monotonic_us() + 1_000 }
    fn on_event(e: Event) { /* readable / writable / connected / failed / closed / sealed / lifecycle / timer */ }
    fn api(req: Vec<u8>, local: bool) -> Vec<u8> { req }
}
ciris_host_abi::export_node!(MyNode);
```

On wasm32, `export_node!` emits the `node` world exports (`init`, `tick`,
`on-event`, `api`, with their `cabi_post_*`). On native it only checks that
the type implements `Node`; a native host calls the `Node` methods
directly.

## Native hosts and tests

Implement `ciris_host_abi::host::Host` (and `HostVolume` / `HostStream`
for storage and network) and call `ciris_host_abi::host::install(host)` on
the thread that runs the node. The node is single-threaded (§5.1), so the
host is per thread, and parallel tests install their own. `clock`,
`random.fill` and `log.record` are required; everything else defaults to
"this host does not offer it" (`unsupported`, no carriers, an
`unsupported` evictable volume). A wrapper called with no host installed
panics, as a module with an unsatisfied import would fail to instantiate.

## Implementing the imports (wasm hosts)

The browser, EFI and wasip2 hosts implement the `ciris:node/*` imports
under the canonical ABI as wit-bindgen lowers them: import module
`ciris:node/<interface>@0.1.0`, field the WIT function name
(`monotonic-us`, `[method]volume.read`, `[resource-drop]stream`, ...).
Lists and strings the host returns are allocated with the module's
exported `cabi_realloc` and written through the return-area pointer
argument. `ciris-abi-gate` prints the exact pairs a module uses.

Event delivery is the host loop of §5.1:

```
loop:
    poll host I/O; deliver events with on-event
    deadline = tick(budget)
    sleep until deadline or host event
```

Storage is synchronous. Network, seal and timers complete as events.

### Asynchronous operations: the token shape

Every asynchronous operation takes a `token: u64` **chosen by the node**,
returns at once, and later events carry that token back. The same shape
holds for `net` and `seal`:

* `net.dial(carrier, target, subprotocols, token)` → `connected(token)` or
  `failed(token)`; then `readable(token)`, `writable(token)`,
  `closed({token, reason})`.
* `net.listen(..., token)` → `readable(token)` means `accept` has a
  connection; `accept(listener, token2)` gives it `token2`.
* `seal.sign-composite(id, msg, token)` (and `provision`, `sign-classical`,
  `sign-pqc`) → `ok` means accepted, `err` means it never started; then
  `sealed(token)`; then `seal.take(token)` returns the signature once
  (`would-block` before the event, `not-found` after it was taken).

A node-chosen token keeps one namespace per node, needs no host-side id
allocation, and records and replays deterministically at the ABI boundary
(§5.1).

### `net` (as Leviculum needs it)

* Framing is reported **per connection** in `stream.info()`: `stream` or
  `message`, since a WebSocket dial can negotiate either.
* `conn-info` also carries `max-message` (message framing; sets Reticulum
  `hw_mtu`), `reliable`, the negotiated `subprotocol` (none = the default),
  `peer-subprotocols` (an accepted connection's client offer), the opaque
  `peer` address and an optional `bitrate-hint`.
* `dial` and `listen` take an ordered subprotocol list (e.g.
  `["rns.hdlc", "rns.raw"]`); other carriers require it empty.
* `send` is non-blocking: bytes accepted (stream framing, possibly short)
  or 1 (message framing; a message is never split), `would-block` with a
  later `writable(token)`, `invalid` for a message over `max-message`.
* `recv` returns `would-block` (not an empty list) when nothing is ready.
* `closed(close-info)` carries `peer-close`, `error` or `host-shutdown`.

## The seal deviation

§4.4 lists `sign-classical` and `sign-pqc` with no context. Every
forward-model signature is the CC 2.6.1.7 composite ML-DSA-65-Ed25519
(CIRISVerify#326, `ciris_crypto::composite`): ML-DSA-65 signs

```
M' = "CompositeAlgorithmSignatures2025" || "COMPSIG-MLDSA65-Ed25519-SHA512" || 0x00 || SHA-512(msg)
```

with the label as its FIPS 204 **context**, and Ed25519 signs `M'` as it
is. A context-free `sign-pqc` cannot produce that. So:

* `sign-pqc` takes `ctx: list<u8>`;
* `sign-composite(id, msg, token)` yields the 3373-byte composite
  (`mldsaSig || ed25519Sig`), the host or vault computing `M'` exactly as
  `ciris_crypto::composite` does;
* `sign-classical` stays (Ed25519 over `msg` as it is);
* `public-key(id)` returns the 1984-byte composite key (`mldsaPK || ed25519PK`).

Also: `describe` takes a key id, since custody differs per key on one
host; and §4.4's one-word `tier` enum is replaced by the per-half
`custody` record §8.1(1) requires (`classical-at-use`, `classical-at-rest`,
`pqc-at-use`, `pqc-at-rest`, `seal-root`, `platform`). Values follow
§8.2: at use `hardware | vault | software`; at rest
`hardware | sealed | wrapped | software-sealed | unprotected`; seal root
`tpm | tpm-measured | token-signature | webauthn-prf | platform-keystore | software`;
`platform` is the CC `hardware_custody:{platform}` token, or none.

## The vault world (§8.5)

`world vault` is the separate signing instance: its own fixed linear
memory, so seeds never enter the node's. It is **minimal on purpose**: it
imports only `log`. It imports no `random` because composite signing is
deterministic (FIPS 204 §3.4), and nothing else. It exports `signer`
(`install`, `public-key`, `sign-classical`, `sign-pqc`, `sign-composite`,
`forget`, `forget-all`), all synchronous: the host has already done any
gesture or unwrap. Bindings are in `ciris_host_abi::bindings::vault`, and
item 9 implements them with `export_vault!`. Gate a vault module with
`--world vault`.

## getrandom on wasm32

With feature `getrandom-backend`, on wasm32 this crate registers
getrandom's custom backend over `ciris:node/random.fill`, so every crate in
the module (`rand_core::OsRng`, Ed25519 / ML-DSA keygen, leviculum) draws
CSPRNG bytes with no code change and no wasm-bindgen or WASI import:

* getrandom **0.2**: `register_custom_getrandom!` (feature `custom`, which
  this crate enables);
* getrandom **0.3 and 0.4**: both call one symbol, `__getrandom_v03_custom`
  (0.4.2's `src/backends/custom.rs` keeps the 0.3 name), which this crate
  defines.

`random.fill` traps rather than return short or weak bytes (the wrapper
asserts the length; there is no fallback).

A module build needs **both** the feature and the cfg, for the wasm target
only:

```
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build --target wasm32-unknown-unknown --release --features ciris-host-abi/getrandom-backend
```

or in the module's `.cargo/config.toml`:

```toml
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="custom"']
```

Without the cfg, getrandom 0.3 / 0.4 refuse to compile for
wasm32-unknown-unknown; without the feature, the link has no backend. Do
not enable getrandom's `js` / `wasm_js` features anywhere in the graph:
they import wasm-bindgen.

The two symbols (`__getrandom_custom`, `__getrandom_v03_custom`) also
appear as module **exports**, since `#[no_mangle]` exports from a cdylib.
They are not imports, so the gate does not care, but a host should not
call them.

## The gate

```
cargo run -p ciris-host-abi --bin ciris-abi-gate -- [--wit <file|dir>] [--world node|vault] module.wasm...
```

It lists every import and exits 1 when any is outside the world's
allowlist, naming each offender and why (module not a `ciris:node`
interface of the world, field not declared by the WIT, or not a function).
The allowlist is derived from the WIT with `wit-parser` (the exact core
names wit-bindgen gives each function, method and resource drop): by
default the copy compiled into the binary, or `--wit`. Exit 2 is a usage
or read error, and a component (rather than a core module) is refused.

## The lint

```
cargo run -p ciris-host-abi --bin ciris-cfg-lint -- path/to/node-crate ...
```

Tokenizes every `.rs` file under each crate (skipping `target/` and
dot-directories) with `proc-macro2`, so comments and strings never match,
and exits 1 on any `cfg(…)`, `cfg!(…)` or `cfg_attr(…)` predicate naming
`target_*`, `unix` or `windows` (under `not` / `any` / `all` too, and in
`macro_rules!` bodies), and on `[target.'cfg(…)']` tables in the crate's
`Cargo.toml`. A crate named `ciris-host-abi` is skipped and reported as
exempt.

## Smoke test

```
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build -p ciris-host-abi --example smoke-node --target wasm32-unknown-unknown --release --features getrandom-backend
cargo run -p ciris-host-abi --bin ciris-abi-gate -- target/wasm32-unknown-unknown/release/examples/smoke_node.wasm
```

The smoke node calls `clock`, `random` and `log` and draws through
`rand_core::OsRng` and getrandom 0.2, 0.3 and 0.4. Its imports are exactly
five, all `ciris:node/*`: `clock.monotonic-us`, `clock.wall-ms`,
`log.record`, `log.metric`, `random.fill`. The same check runs as
`cargo test -p ciris-host-abi --test smoke_wasm -- --ignored`.

## MSRV

wit-bindgen 0.51.0 (rust-version 1.87), wit-parser / wasmparser /
wasm-encoder 0.244.0 (1.81). All were already in the workspace lock.
`cargo +1.89 check -p ciris-host-abi` passes.

## Open

* FSD D-items this crate does not settle: D1 (browser has no listener;
  `can-listen` reports it), D8 (browser owner key without PRF), D9 (EFI
  `PolicyAuthorize`; `tpm-measured` names the root, not the policy), D10
  (seed dwell; `signer.forget-all` is the hook), D12 (the crate lives in
  CIRISVerify for now, per Eric), D15 (the vault world exists; whether it
  is required is the decision).
* `seal.provision` passes the seed through node memory, which §8.5 forbids
  for seeds in use. It is kept from §4.4 for import/restore; a
  `generate`-in-vault operation is the likely replacement (item 9).
* `wit-bindgen` output under wasm2c (§4.2, "untested") is still untested;
  the smoke module runs under V8.
* `ciris-rt` (item 2) owns the executor, timers and record/replay over this
  ABI.
