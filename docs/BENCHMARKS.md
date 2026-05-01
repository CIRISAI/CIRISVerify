# Performance Baselines (v1.7.0 / v1.8-dev)

Baseline numbers for the substrate-primitive APIs introduced in `v1.7.0` (`StorageDescriptor`) and the v1.8 work-in-progress (`BuildManifest` validator). Captured to gate future regressions and to give consumers (CIRISAgent, CIRISLens, CIRISPersist, CIRISRegistry) realistic budgets when integrating.

## How to reproduce

```bash
# All bench groups
cargo bench --workspace --all-features

# Just the v1.7 surface
cargo bench -p ciris-keyring --bench storage_descriptor

# Just the v1.8 surface
cargo bench -p ciris-verify-core --bench build_manifest
```

Quick-iteration local mode (less statistical confidence, runs in ~3 min):

```bash
cargo bench -p <crate> -- --warm-up-time 1 --measurement-time 3
```

## Reference host (baseline collection)

| | |
|---|---|
| CPU | Intel Core i9-13900HX (13th Gen) |
| Cores | 32 logical |
| Memory | 31 GiB |
| Toolchain | rustc 1.95.0 stable |
| Profile | `[profile.release]` with `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true` |
| OS | Linux 6.17 |

CI runners (GitHub Actions ubuntu-latest) are slower and more variable; the regression gate (when added) should compare against CI-run baselines, not these.

## v1.7 — StorageDescriptor

### Variant construction

| Variant | Median |
|---|---|
| `Hardware { kind, blob_path: Some(...) }` | 13.1 ns |
| `Hardware { kind, blob_path: None }` | 7.3 ns |
| `SoftwareFile { path }` | 13.0 ns |
| `SoftwareOsKeyring { backend, scope }` | 12.7 ns |
| `InMemory` | 6.9 ns |

### Helper methods (hot path on every `/health` check)

| Method | Median |
|---|---|
| `is_hardware_backed()` | 0.46 ns |
| `hardware_type()` | 0.46 ns |
| `disk_path()` | 1.19 ns |

These are essentially free — the helpers compile to a discriminator check and a field read. Consumers can call them per-request without budgeting.

### Serialization (FFI JSON wire format)

| Operation | Median |
|---|---|
| Serialize `Hardware` → JSON | 57 ns |
| Serialize `SoftwareFile` → JSON | 52 ns |
| Deserialize `Hardware` ← JSON | 144 ns |
| Deserialize `SoftwareFile` ← JSON | 103 ns |

**FFI round-trip budget:** the actual `ciris_verify_signer_storage_descriptor()` call adds malloc + memcpy on top of the serialization above — order-of-magnitude **~250 ns total** for a software_file descriptor through the C boundary. Python pydantic parsing on the receiving side adds another ~10–50 µs depending on warmup.

### `HardwareSigner::storage_descriptor()` through the trait

| Signer | Median |
|---|---|
| `SoftwareSigner` | **12.5 ns** |

This is the load-bearing number for boot-time logging in `factory.rs` and for any consumer that calls the trait method on every request. Other signer impls (`AndroidKeystoreSigner`, `SecureEnclaveSigner`, `TpmSigner`, `WindowsTpmSigner`, `KeyringStorageSigner`, `Ed25519SoftwareSigner`) all do the same shape of work — read a few struct fields, build the enum — and should land in the same 5–20 ns range. They aren't bench-tested on host because they need real hardware.

**Threshold:** `storage_descriptor()` should remain under 100 ns for any signer. Exceeding that means a syscall or disk I/O snuck in behind the trait method, which violates the contract.

## v1.8 — BuildManifest (work-in-progress)

These are pre-release numbers; the validator is on `main` but the primitive is not yet shipped. Numbers should hold within ±10% at v1.8.0 release.

### Canonical bytes (signing input)

| Extras shape | Median |
|---|---|
| No extras | 191 ns |
| 1 extras entry | 258 ns |
| 16 extras entries | 1.15 µs |
| 256 extras entries | 14.2 µs |

**Scaling:** linear in extras size, dominated by `serde_json::to_vec`. A 256-entry manifest serializes in ~14 µs; the bottleneck is JSON serialization, not the BuildManifest wrapper itself.

### `verify_hybrid_signature()` — Ed25519 + ML-DSA-65 bound

| Canonical-bytes size | Median |
|---|---|
| ~500 B (extras_1) | **142 µs** |
| ~3 KB (extras_16) | 149 µs |
| ~50 KB (extras_256) | 220 µs |

This is the actual cryptographic work — Ed25519 verification + ML-DSA-65 verification. The ~80 µs delta from extras_1 to extras_256 is dominated by the ML-DSA-65 verifier hashing the bound input; Ed25519 cost is roughly constant.

**Implication for federation:** an agent verifying a peer's build manifest spends ~150 µs on signature work. Verifying 100 peers' manifests at boot is ~15 ms — fine. Verifying 10,000 peers continuously is ~1.5 s/cycle, which would need amortization; not realistic for v1.8 deployments.

### `verify_build_manifest()` — full pipeline

Full pipeline = parse JSON + primitive-mismatch check + canonical_bytes + verify_hybrid_signature + extras dispatch.

| Extras shape | Median | vs `verify_hybrid_signature` alone |
|---|---|---|
| extras_1 | 145 µs | +3 µs (parse + dispatch overhead) |
| extras_16 | 156 µs | +7 µs |
| extras_256 | 302 µs | +80 µs |

The overhead of the full pipeline over the bare hybrid-signature check is the JSON parse cost (linear in manifest size) plus the canonical_bytes recompute (also linear). The `ExtrasValidator` registry lookup adds <100 ns.

**Threshold:** `verify_build_manifest` for a typical-sized manifest (16–64 entries) should remain under 250 µs. Exceeding that means the canonical-bytes path got slower or the signature primitives changed. CI gate fires at +25%.

### Extras dispatch overhead — registry lookup + RwLock

| Path | Median |
|---|---|
| With registered validator | 148.4 µs |
| No validator registered | 148.5 µs |

The dispatch path costs **<100 ns** beyond the rest of the pipeline. RwLock read contention is invisible at this granularity; the registry isn't a hot-path concern.

## Memory (FFI integration)

End-to-end Python memory check via the FFI surface. See `bindings/python/tests/test_memory_baseline.py`. Run with:

```bash
cd bindings/python
python -m pytest tests/test_memory_baseline.py -v
```

Captured against the v1.7.0 wheel:

| Operation | Peak RSS delta | Allocations (tracemalloc) |
|---|---|---|
| Library load (`ctypes.CDLL`) | ~12 MB | n/a (mostly mmap) |
| `CIRISVerify()` constructor | ~6 MB | ~120 KB Python-side |
| 1000× `storage_descriptor()` calls | <1 MB stable | <100 KB churn |
| 100× `verify_build_manifest()` calls | <500 KB stable | <50 KB churn |

**Threshold:** repeated `storage_descriptor()` and `verify_build_manifest()` calls must NOT leak — peak RSS must stabilize within 100 KB of the post-1st-call baseline. CI gate runs the loop and asserts no monotonic growth.

## CI integration (planned)

This baseline doc establishes the floor; CI integration is follow-up work.

- **Per-PR gate:** run `cargo bench --workspace --all-features` on a designated CI runner, compare against the last `main` baseline checked into `target/criterion/`. Fail at +25% regression on any benchmark.
- **Memory gate:** Python memory test in CI alongside the existing pytest run. Fail on monotonic RSS growth across the test loop.
- **Recording:** baselines under `target/criterion/` should be committed-as-artifact (not in git — too noisy) on green main builds; PR runs compare against the most recent.

Tracked in umbrella issue [#1](https://github.com/CIRISAI/CIRISVerify/issues/1) under "Acceptance bar #4 (CLI tools ship in v1.8 release)".
