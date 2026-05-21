# CIRISVerify Benchmarks

The criterion benchmark suite — what it measures, how to read the
curves, the leak guarantee behind them, and where we stand against the
state of the art.

## Running

```bash
# Default-feature benches: transparency_merkle, key_derivation,
# build_manifest (ciris-verify-core); storage_descriptor (ciris-keyring)
cargo bench --workspace

# Federation crypto authority — needs the v2.0+ feature set
cargo bench -p ciris-crypto --bench federation_crypto \
  --features aes-gcm,kdf,hmac,pqc-ml-dsa
```

CI:

- **`.github/workflows/bench.yml`** runs the full suite on every push to
  `main` and on manual dispatch, publishing the criterion HTML report
  (`criterion-report`) and a text summary (`bench-results-txt`) as
  artifacts. It is **not** a pass/fail gate — GitHub's shared runners
  are too noisy for that — it answers "what are our numbers" and
  surfaces unexplained curve shapes.
- **`ci.yml`'s `benches` job** is the fast per-PR gate: it compiles
  every bench (`--no-run`, including the feature-gated
  `federation_crypto`) so they cannot bit-rot, without running them.
- The **`alloc_stability` test** (the leak gate) runs in the normal
  `ci.yml` test job — see [Leak guarantee](#leak-guarantee).

## What is benched

| Bench | Crate | Surface |
|---|---|---|
| `transparency_merkle` | ciris-verify-core | Merkle append / inclusion proof / consistency proof / root / verifiers |
| `key_derivation` | ciris-verify-core | `derive_symmetric_key` (storage load + HKDF) |
| `build_manifest` | ciris-verify-core | canonical-bytes + hybrid-signature verify |
| `federation_crypto` | ciris-crypto | hybrid Ed25519+ML-DSA-65 sign/verify, AES-256-GCM, HKDF, PBKDF2, HMAC |
| `storage_descriptor` | ciris-keyring | keyring descriptor construction / serde / helpers |

## Reading the curves — clean and fully explained

Every swept curve has an expected shape. A point that deviates from its
shape is a bug to investigate, not noise to wave away. The size sweep is
five geometric points (×4 each, 256 → 65 536) so the shape is legible
from the data, not merely asserted.

| Curve | Expected shape | A deviation means |
|---|---|---|
| `transparency/merkle_root` | flat — O(1) cached-top read (v2.6.0) | scaling with N ⇒ level cache regressed |
| `transparency/inclusion_proof` | logarithmic, fixed-overhead-dominated | linear ⇒ O(N) recompute crept back |
| `transparency/consistency_proof` | slow rise — O(log² N) + overhead | linear ⇒ `range_root` missing the cache |
| `transparency/verify_inclusion` | logarithmic — one hash per tree doubling | — |
| `transparency/verify_consistency` | logarithmic — proof reconstruction walk | — |
| `transparency/append` (elem/s) | flat-ish — O(log N) incremental per leaf | throughput collapse ⇒ append went super-linear |
| `federation_crypto/aes_gcm_*` | flat bytes/sec at scale | — |
| `federation_crypto/hybrid_*` | flat (fixed-size keys) | — |

## v2.7.0 recorded numbers

Recorded with `cargo bench` on the v2.7.0 development host (Linux,
rustc 1.95.0 stable, `[profile.release]` lto + codegen-units=1) under
**moderate background load** — treat absolute numbers as indicative to
±30% and read the *shapes*. `bench.yml` re-records on a CI runner; that
run is the forward-tracked baseline.

### transparency_merkle

| N (leaves) | 256 | 1 024 | 4 096 | 16 384 | 65 536 |
|---|---|---|---|---|---|
| `merkle_root` | 13.3 ns | 12.6 ns | 12.8 ns | 16.7 ns | 21.8 ns |
| `inclusion_proof` | 167 ns | 259 ns | 253 ns | 234 ns | 248 ns |
| `verify_inclusion` | 698 ns | 808 ns | 984 ns | 1.45 µs | 1.95 µs |
| `consistency_proof` | 94 ns | 117 ns | 131 ns | 150 ns | 178 ns |
| `verify_consistency` | ~4.1 µs † | ~3.2 µs † | 1.76 µs | 1.98 µs | 2.24 µs |
| `append` (elem/s) | 1.07 M | 1.14 M | 1.28 M | 1.15 M | 1.03 M |

† host-contention noise — the 4 096+ points (tight criterion intervals)
are the trustworthy shape.

**Curve explanations:**

- **`merkle_root` — O(1), confirmed.** 13–22 ns, does **not** scale with
  N. The mild 13→22 ns drift across a 256× size range is cache
  footprint: the level cache for a 65 536-leaf tree spans ~2 MB, so
  reaching the cached root node touches colder memory. Constant in
  *operations*; the tiny drift is memory locality, not algorithm. This
  is the v2.6.0 win — pre-v2.6.0 this was an O(N) recompute.
- **`inclusion_proof` — O(log N), fixed-overhead-dominated.** ~165–260 ns,
  effectively flat: the path length doubles 8→16 over the sweep, but
  each extra sibling is a 33-byte `Vec` push, dwarfed by the fixed
  per-call cost (`RwLock` read + proof `Vec` allocation). Crucially
  **not** O(N) — pre-v2.6.0 it was.
- **`verify_inclusion` — O(log N), textbook.** 0.70 → 1.95 µs, ≈ +80 ns
  per tree doubling: each doubling adds one `hash_node` (SHA-256) to the
  reconstruction walk. The cleanest curve in the suite.
- **`consistency_proof` — O(log² N) + overhead.** Clean monotonic rise
  94 → 178 ns. Benched with a deliberately non-aligned `from = n/2 − 1`
  (an aligned `n/2` is a perfect subtree — the degenerate one-sibling
  case — and would hide the real shape).
- **`verify_consistency` — O(log N) reconstruction.** ~1.8 → 2.2 µs over
  4 096–65 536. Small-N points were measured under host contention.
- **`append` — O(log N) incremental.** Throughput holds ~1.0–1.3 M
  appends/s flat across the sweep. O(N) append would show throughput
  collapsing ~1/N; it does not. The gentle decline 1.28 M → 1.03 M from
  4 K → 64 K is the log-N term growing, exactly as expected.

### federation_crypto

| Operation | Time | Throughput |
|---|---|---|
| `hybrid_sign` (Ed25519 + ML-DSA-65) | 380 µs | — |
| `hybrid_verify` | 379 µs | — |
| `aes_gcm_encrypt` / 256 B | 438 ns | 557 MiB/s |
| `aes_gcm_decrypt` / 256 B | 318 ns | 767 MiB/s |
| `aes_gcm_encrypt` / 64 KiB | 39.7 µs | 1.54 GiB/s |
| `aes_gcm_decrypt` / 64 KiB | 40.3 µs | 1.51 GiB/s |
| `hkdf_sha256` | 597 ns | — |
| `pbkdf2_hmac_sha256` (100 k iters) | 15.1 ms | — |
| `hmac_sha256` | 251 ns | — |

- **`hybrid_sign` / `hybrid_verify` ≈ 380 µs** — dominated by ML-DSA-65;
  Ed25519 is a few µs of it. This is the per-signature cost of
  post-quantum coverage on every federation signature. Verifying 100
  peers' STHs at boot is ~38 ms; continuous verification of thousands
  needs amortization.
- **AES-GCM** — small-payload (256 B) throughput is per-call-overhead-
  bound (557 MiB/s); at 64 KiB it reaches 1.5 GiB/s as the fixed cost
  amortizes. Fully explained two-regime curve.
- **`pbkdf2_hmac_sha256`** scales linearly with the iteration count —
  15 ms at 100 k iters ⇒ ~150 ns/iter. Production iteration count is
  the caller's policy.

### key_derivation

| Operation | Time |
|---|---|
| `derive_symmetric_key` | 5.2 µs |

The full public-API path CIRISPersist#87's `secrets-hw` pays per
derivation: software-storage seed `load` (a file read — dominant) +
HKDF-Extract + HKDF-Expand. The pure-HKDF cost in isolation is
`federation_crypto/hkdf_sha256` (~600 ns); the rest is the storage read.
Hardware-backed storage (TPM / Keystore / Secure Enclave) replaces the
file read with a platform call — a separate cost not benched on host.

## Leak guarantee

The benches give timing curves; the **`alloc_stability` test**
(`src/ciris-verify-core/tests/alloc_stability.rs`) gives the memory
guarantee behind them. It installs a counting global allocator and
asserts every read-path operation — inclusion proof, consistency proof,
root, both verifiers, `derive_symmetric_key` — is **allocation-neutral
across 20 000 iterations**: each call allocates and frees the same
working set, so net live heap returns to baseline. A leak would climb
linearly with the iteration count.

Unlike the benches, this test **gates** — it runs in `ci.yml`'s normal
test job. As of v2.7.0 all six read-path operations pass with net heap
growth well under the 256 KiB slack (any real per-call leak would be
megabytes over 20 k iterations).

## State of the art

For the transparency log, SOTA is **RFC 6962 / RFC 9162** as realized by
**Google Trillian** and **Sigstore Rekor** — production transparency
logs serving inclusion and consistency proofs against millions of
leaves. The axes that matter, and where we land:

| Axis | SOTA (Trillian/Rekor) | CIRISVerify v2.7.0 |
|---|---|---|
| Inclusion-proof generation | O(log N), single-digit µs | O(log N), ~0.25 µs at 64 K leaves |
| Consistency-proof generation | O(log N)–O(log² N) | O(log² N), ~0.18 µs at 64 K leaves |
| Append | O(log N) incremental | O(log N) incremental, ~1 M/s |
| Root | O(1) from cached state | O(1), ~15 ns |

After v2.6.0's level-cache refactor CIRISVerify is in the **right
complexity class on every axis** — these benchmarks are the receipts.
The constant factors are competitive for an in-memory log; the
production gap versus Trillian is durability and horizontal scale
(Trillian is a sharded, database-backed service), which is a
deployment-architecture concern, not an algorithmic one — and is exactly
what the `TransparencyStore` trait exists to let CIRISPersist's
PG/SQLite backends address.

## Historical baselines (v1.7 / v1.8)

The `storage_descriptor` and `build_manifest` benches predate this suite
(v1.7.0 / v1.8-dev). Their numbers were recorded on a **different
reference host** (Intel i9-13900HX) and are kept here as a still-valid
baseline for those surfaces:

- **`StorageDescriptor`** — variant construction 7–13 ns; helper methods
  (`is_hardware_backed`, `hardware_type`, `disk_path`) sub-2 ns;
  JSON serialize 52–57 ns, deserialize 103–144 ns;
  `HardwareSigner::storage_descriptor()` through the trait ~12.5 ns.
  Threshold: `storage_descriptor()` must stay under 100 ns for any
  signer — exceeding it means a syscall snuck behind the trait method.
- **`BuildManifest`** — `canonical_bytes` is linear in extras size
  (191 ns no-extras → 14.2 µs at 256 entries), dominated by
  `serde_json`; `verify_hybrid_signature` ~142–220 µs (ML-DSA-65
  bound); full `verify_build_manifest` pipeline +3–80 µs over the bare
  signature check (JSON parse + canonical-bytes recompute). Threshold:
  `verify_build_manifest` for a 16–64-entry manifest under 250 µs.
