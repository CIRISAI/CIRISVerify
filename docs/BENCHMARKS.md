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

The forward-tracked baseline — recorded by `bench.yml` on a GitHub
Actions `ubuntu-latest` runner (commit `2abb4b2`), rustc 1.95.0 stable,
`[profile.release]` lto + codegen-units=1. Criterion intervals were
tight (a quiet runner); re-recorded on every push to `main`.

### transparency_merkle

| N (leaves) | 256 | 1 024 | 4 096 | 16 384 | 65 536 |
|---|---|---|---|---|---|
| `merkle_root` | 19.7 ns | 19.7 ns | 19.7 ns | 19.7 ns | 19.7 ns |
| `inclusion_proof` | 125 ns | 155 ns | 174 ns | 169 ns | 171 ns |
| `verify_inclusion` | 998 ns | 1.25 µs | 1.49 µs | 1.74 µs | 1.99 µs |
| `consistency_proof` | 180 ns | 217 ns | 216 ns | 240 ns | 296 ns |
| `verify_consistency` | 1.90 µs | 2.43 µs | 2.98 µs | 3.52 µs | 4.05 µs |
| `append` (elem/s) | 1.26 M | 1.08 M | 0.94 M | 0.84 M | 0.75 M |

**Curve explanations:**

- **`merkle_root` — O(1), confirmed.** 19.7 ns at *every* tree size —
  dead flat across a 256× range, the cleanest possible confirmation of
  the v2.6.0 O(1) cached-top read. (Pre-v2.6.0 this was an O(N)
  recompute.)
- **`inclusion_proof` — O(log N), fixed-overhead-dominated.** 125–174 ns:
  the path length doubles 8→16 over the sweep, but each extra sibling is
  a 33-byte `Vec` push, dwarfed by the fixed per-call cost (`RwLock`
  read + proof `Vec` allocation). The slight rise then plateau is that
  small log term against the fixed floor. Crucially **not** O(N) —
  pre-v2.6.0 it was.
- **`verify_inclusion` — O(log N), textbook.** 0.998 → 1.99 µs,
  ≈ +250 ns per 4× step (≈ +125 ns per tree doubling): each doubling
  adds one `hash_node` (SHA-256) to the reconstruction walk. A
  ruler-straight log curve.
- **`consistency_proof` — O(log² N) + overhead.** Monotonic rise
  180 → 296 ns. Benched with a deliberately non-aligned `from = n/2 − 1`
  (an aligned `n/2` is a perfect subtree — the degenerate one-sibling
  case — and would hide the real shape).
- **`verify_consistency` — O(log N) reconstruction.** Clean log curve
  1.90 → 4.05 µs, ≈ +0.54 µs per 4× step.
- **`append` — O(log N) incremental.** Throughput eases 1.26 M → 0.75 M
  appends/s as the tree grows 256× — per-append cost ~0.79 µs at 256
  leaves, ~1.33 µs at 65 536, i.e. it roughly *doubles* for a 256× size
  increase: `log(65536)/log(256) = 2`. That is O(log N) per leaf,
  exactly. An O(N) append would show throughput collapsing ~1/N (a 256×
  drop); it declines by under 2×.

### federation_crypto

v2.8.0 CI baseline (`ubuntu-latest`, commit `76598da`):

| Operation | Time | Throughput |
|---|---|---|
| `hybrid_sign` (Ed25519 + ML-DSA-65) | 466 µs | — |
| `hybrid_verify` | 276 µs | — |
| `aes_gcm_encrypt` / 256 B | 428 ns | 570 MiB/s |
| `aes_gcm_decrypt` / 256 B | 319 ns | 765 MiB/s |
| `aes_gcm_encrypt` / 64 KiB | 11.2 µs | 5.45 GiB/s |
| `aes_gcm_decrypt` / 64 KiB | 10.3 µs | 5.91 GiB/s |
| `hkdf_sha256` | 548 ns | — |
| `pbkdf2_hmac_sha256` (100 k iters) | 14.9 ms | — |
| `hmac_sha256` | 242 ns | — |

- **`hybrid_sign` 466 µs / `hybrid_verify` 276 µs** — both dominated by
  ML-DSA-65 (Ed25519 is a few µs of each); signing is heavier than
  verification, the expected asymmetry. This is the per-signature cost
  of post-quantum coverage on every federation signature: verifying 100
  peers' STHs at boot is ~28 ms; continuous verification of thousands
  needs amortization.
- **AES-GCM** — v2.8.0 switched the backend from RustCrypto `aes-gcm` to
  `ring` (CIRISVerify#26). Bulk (64 KiB) throughput went **1.0 →
  ~5.5–5.9 GiB/s on CI** (+~5×; the dev host, a faster CPU, hits
  ~9.5 GiB/s). Small-payload 256 B is up modestly (0.46 → ~0.6 GiB/s) —
  that regime is per-call-overhead-bound, not throughput-bound, so the
  win is small there by nature. `ring` was already a universal
  dependency here (rustls, via reqwest + hickory-resolver), so the
  switch cost zero new build surface. AES-256-GCM is a deterministic
  standard — the NIST known-answer test confirms `ring` is byte-identical
  to the old backend, so existing encrypted blobs stay readable.
- **`pbkdf2_hmac_sha256`** scales linearly with the iteration count —
  14.9 ms at 100 k iters ⇒ ~149 ns/iter. Production iteration count is
  the caller's policy.

### key_derivation

| Operation | Time |
|---|---|
| `derive_symmetric_key` | 8.8 µs |

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
| Inclusion-proof generation | O(log N), single-digit µs | O(log N), ~0.17 µs at 64 K leaves |
| Consistency-proof generation | O(log N)–O(log² N) | O(log² N), ~0.30 µs at 64 K leaves |
| Append | O(log N) incremental | O(log N) incremental, ~0.75–1.3 M/s |
| Root | O(1) from cached state | O(1), ~20 ns (flat across all N) |

After v2.6.0's level-cache refactor CIRISVerify is in the **right
complexity class on every axis** — these benchmarks are the receipts.
The constant factors are competitive for an in-memory log; the
production gap versus Trillian is durability and horizontal scale
(Trillian is a sharded, database-backed service), which is a
deployment-architecture concern, not an algorithmic one — and is exactly
what the `TransparencyStore` trait exists to let CIRISPersist's
PG/SQLite backends address.

### storage_descriptor (ciris-keyring)

The keyring descriptor surface (v1.7.0+), same CI baseline run:

- Variant construction 18–38 ns; helper methods (`is_hardware_backed`,
  `hardware_type`, `disk_path`) 1.4–2.8 ns; JSON serialize 80–119 ns,
  deserialize 210–300 ns. **Threshold:** `storage_descriptor()` must
  stay under 100 ns for any signer — exceeding it means a syscall snuck
  behind the trait method.

### build_manifest (ciris-verify-core)

The `BuildManifest` validator surface (v1.8.0+), same CI baseline run:

- `canonical_bytes` is linear in extras size (471 ns no-extras →
  24.1 µs at 256 entries), dominated by `serde_json`.
- `verify_hybrid_signature` 284–430 µs (Ed25519 + ML-DSA-65 bound);
  full `verify_build_manifest` pipeline 294–572 µs (adds JSON parse +
  canonical-bytes recompute + extras dispatch). **Threshold:**
  `verify_build_manifest` for a 16–64-entry manifest under ~350 µs.
