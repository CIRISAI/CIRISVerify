# Runtime tree-walking verifier (`verify_tree`)

**Status:** Stable since v1.13.0 (CIRISVerify#9).

The runtime tree-walking verifier walks a source tree on disk and compares
it byte-for-byte against the registered `file_manifest_json` for a
`(project, binary_version)` pair. It exists so downstream consumers
(primarily CIRISAgent) can reach Level 4 file integrity at startup
without maintaining a duplicate hashing path
(`startup_python_hashes.json` + `regenerate_python_hashes.py`).

```python
from ciris_verify import verify_tree, TreeVerifyRequest

result = verify_tree(TreeVerifyRequest(
    root="/app",
    include_roots=["ciris_engine", "ciris_adapters", "ciris_ios", "ciris_sdk"],
    exempt_dirs=["__pycache__", ".venv", "venv", "node_modules", "logs",
                 ".pytest_cache", ".mypy_cache", "dist", "build",
                 ".ruff_cache", ".coverage", ".tox", ".nox", ".git"],
    exempt_extensions=["pyc", "pyo", "env", "log", "audit", "db",
                       "sqlite", "sqlite3"],
    project="ciris-agent",
    binary_version="2.8.3",
))

if result.valid:
    print(f"L4 OK: {result.files_checked} files, total {result.total_hash}")
else:
    print(f"drift: {len(result.failed_files)} files; "
          f"registry_error={result.registry_error}")
```

## API

### `TreeVerifyRequest`

| field             | type        | meaning                                                         |
| ----------------- | ----------- | --------------------------------------------------------------- |
| `root`            | `str`       | Filesystem root; `include_roots` are resolved against this.     |
| `include_roots`   | `list[str]` | Top-level subtrees to include. Empty = walk `root` itself.      |
| `exempt_dirs`     | `list[str]` | Directory basenames to skip anywhere in the tree.               |
| `exempt_extensions` | `list[str]` | File extensions to skip (no leading dot).                     |
| `project`         | `str`       | Registry namespace (e.g. `"ciris-agent"`).                      |
| `binary_version`  | `str`       | Registered version key (e.g. `"2.8.3"`).                        |

The `include_roots`, `exempt_dirs`, and `exempt_extensions` MUST mirror
the `--tree-include`, `--tree-exempt-dir`, and `--tree-exempt-ext` flags
passed to `ciris-build-sign sign --tree` at registration time. Different
rules will walk a different file set than what got registered, and the
verdict will diverge accordingly.

### `TreeVerifyResult`

| field                  | type                  | meaning                                                                 |
| ---------------------- | --------------------- | ----------------------------------------------------------------------- |
| `valid`                | `bool`                | Top-level verdict — `registry_match` AND no failed files AND registry reachable. |
| `files_checked`        | `int`                 | Files walked on disk.                                                   |
| `files_passed`         | `int`                 | Files whose disk hash matched the registered hash.                      |
| `failed_files`         | `list[FailedFile]`    | Per-file divergences (see below).                                       |
| `total_hash`           | `str`                 | Canonical computed total `sha256:<hex>`. Always populated.              |
| `expected_total_hash`  | `str | None`          | Registered `file_manifest_hash`. `None` when registry fetch failed.     |
| `registry_match`       | `bool`                | `total_hash == expected_total_hash` AND `failed_files == []`.           |
| `registry_error`       | `str | None`          | Set when registry fetch failed (network down, 404, parse error, …).    |
| `project`              | `str`                 | Echoed.                                                                 |
| `binary_version`       | `str`                 | Echoed.                                                                 |

### `FailedFile`

| field            | type           | meaning                                                       |
| ---------------- | -------------- | ------------------------------------------------------------- |
| `path`           | `str`          | Tree-relative path with forward-slash separators.             |
| `kind`           | `FailedFileKind` | `"missing"`, `"extra"`, or `"mismatch"`.                    |
| `computed_hash`  | `str | None`   | Disk hash (`sha256:<hex>`); `None` for `missing`.             |
| `expected_hash`  | `str | None`   | Registered hash (`sha256:<hex>`); `None` for `extra`.         |

## Canonical algorithm (Algorithm A)

`verify_tree` shares its primitives with `ciris-build-sign sign --tree`
([`ciris-verify-core::security::build_manifest`][bm]):

1. **Walk** with [`walk_file_tree(fs_root, &rules)`][walk]. Honors
   `ExemptRules`: empty `include_roots` walks `fs_root`; non-empty walks
   each `fs_root.join(root)` independently. Symlinks are skipped.
2. **Hash each surviving file** as `sha256:<hex>` (lowercase, no leading
   `0x`). Missing `include_root` entries are silently skipped.
3. **Canonical total** via [`FileTreeExtras::compute_tree_hash`][cth]:
   ```rust
   for (path, hash) in BTreeMap::iter() {
       hasher.update(path);
       hasher.update(b":");
       hasher.update(hash);   // hash is already "sha256:<hex>"
       hasher.update(b"\n");
   }
   format!("sha256:{}", hex::encode(hasher.finalize()))
   ```
   The `BTreeMap` iteration is sorted lexicographically on path, so the
   output is deterministic across platforms.

Path normalization: every relative path is joined with `/` regardless of
platform. The forward-slash convention is what `ciris-build-sign sign
--tree` writes into the registered manifest; Windows-built artifacts
running on Linux at verify time hash to the same bytes.

[bm]: ../src/ciris-verify-core/src/security/build_manifest.rs
[walk]: ../src/ciris-verify-core/src/security/build_manifest.rs#L483
[cth]: ../src/ciris-verify-core/src/security/build_manifest.rs#L346

## Parity contract

The contract that makes `verify_tree`'s `total_hash` directly comparable
to the registered `file_manifest_hash` is locked by two test sets:

- **In-crate**: `tree_verify::tests::algorithm_a_parity_with_build_sign`
  (in `ciris-verify-core`). Asserts the walk + hash matches the same
  primitives `ciris-build-sign register` consumes when writing the
  registered manifest.
- **Cross-crate**: `parity_with_verify_tree.rs` (in `ciris-build-tool`'s
  test suite). Builds a fake source tree, runs `build_file_tree_extras`
  (the signing-side `--tree` walker), runs `walk_file_tree` (the
  verify-side walker), asserts byte-equality of the `BTreeMap<path,
  sha256:hex>` AND the canonical hash. Also covers drift-detection
  (extra-file / modified-file).

If a future refactor introduces a second walker or hash algorithm, both
test sets must be updated for the new shape — and any divergence between
sign and verify will fail loudly at test time.

## Network behavior

- **Registry reachable, version exists** → `TreeVerifyResult.registry_error == None`,
  `expected_total_hash` populated. `valid` reflects the per-file diff.
- **Registry reachable, version missing (404)** → `registry_error`
  surfaces the HTTP status; `valid=False`, `expected_total_hash=None`.
- **Registry unreachable (DNS, timeout)** → `registry_error` surfaces
  the underlying error; `total_hash` is still populated so callers can
  persist it for later online verification.
- **Walk fails** (root missing, unreadable file) → the FFI returns a
  non-zero error code (`VerificationFailedError` in Python). This is the
  one case `verify_tree` raises — registry-side failures are *verdicts*,
  not exceptions.

The default registry URL is `https://api.registry.ciris-services-1.ai`;
override via `verify_tree(req, registry_url=...)` to point at a regional
fallback (`us.registry.ciris-services-1.ai`,
`eu.registry.ciris-services-1.ai`) or a staging registry.

## Relationship to legacy `python_hashes` (Algorithm B)

`UnifiedAttestationEngine::full_attest` still accepts the legacy
`python_hashes` JSON parameter — a pre-walked
`{total_hash, module_hashes, module_count, agent_version, computed_at}`
shape produced by
[`mobile_main.py:_save_hashes_to_file`][mobile_main] and
[`tools/dev/regenerate_python_hashes.py`][regen] in CIRISAgent. That path
is **retained** for backward compatibility (Android mobile builds ship a
pre-walked JSON in the AAB). It uses **Algorithm B**:

- `.py`-only, walked under hardcoded packages
  `["ciris_engine", "ciris_adapters"]`.
- Per-file hash stored as **raw hex** (no `sha256:` prefix).
- Total hash: sort `path:hex` strings, join with `\n` (no trailing),
  `sha256` → raw hex.

These two algorithms produce **different bytes** for the same input
tree:

| feature        | Algorithm A (`verify_tree`) | Algorithm B (legacy `python_hashes`) |
| -------------- | --------------------------- | ------------------------------------- |
| Per-file value | `sha256:<hex>`              | `<hex>`                               |
| Total hash     | `sha256:<hex>`              | `<hex>`                               |
| File set       | Configurable include/exempt | `.py` under `ciris_engine`/`ciris_adapters` only |
| Per-entry      | `path:sha256:hex\n`         | `path:hex` joined with `\n`           |

The registered `file_manifest_json` for ciris-agent uses **Algorithm A**
(written by `ciris-build-sign sign --tree`). Algorithm B's `total_hash`
therefore cannot match the registered manifest by construction —
that's the L3 ceiling CIRISAgent#9 calls out and what `verify_tree`
breaks through.

[mobile_main]: https://github.com/CIRISAI/CIRISAgent/blob/main/client/androidApp/src/main/python/mobile_main.py
[regen]: https://github.com/CIRISAI/CIRISAgent/blob/main/tools/dev/regenerate_python_hashes.py

## Migration: retiring `startup_python_hashes.json`

CIRISAgent integration steps once on `ciris-verify >= 1.13.0`:

1. Replace `attestation/hashes.py:load_python_hashes()` with a direct
   `verify_tree()` call:

    ```python
    from ciris_verify import verify_tree, TreeVerifyRequest, FailedFileKind

    result = verify_tree(TreeVerifyRequest(
        root=AGENT_ROOT,
        include_roots=AGENT_INCLUDE_ROOTS,    # same set used at sign time
        exempt_dirs=AGENT_EXEMPT_DIRS,
        exempt_extensions=AGENT_EXEMPT_EXTS,
        project="ciris-agent",
        binary_version=CIRIS_VERSION,         # the *runtime* version
    ))

    python_integrity = {
        "valid": result.valid,
        "modules_checked": result.files_checked,
        "modules_passed": result.files_passed,
        "failed_modules": [f.path for f in result.failed_files],
        "total_hash": result.total_hash,
        "expected_total_hash": result.expected_total_hash,
        "registry_match": result.registry_match,
    }
    ```

2. Drop:
   - `startup_python_hashes.json` from the runtime tree (no longer
     consulted).
   - `client/androidApp/src/main/python/mobile_main.py:_save_hashes_to_file`.
   - `tools/dev/regenerate_python_hashes.py`.
   - The "Regenerate startup_python_hashes.json" step in
     `.github/workflows/build.yml`.

3. Mobile (Android) note: the legacy `python_hashes` JSON parameter on
   `run_attestation` continues to work for callers that still pass it
   (Android Chaquopy builds where the runtime tree-walk is more
   expensive than precomputing at AAB-build time). Once Android also
   migrates to `verify_tree()`, the parameter can be marked deprecated
   in a future minor.

## Cross-links

- Issue: [CIRISVerify#9](https://github.com/CIRISAI/CIRISVerify/issues/9)
- Driving downstream issue: [CIRISAgent#9 in this repo's terms / CIRISAgent#738 wheel-vs-staged drift](https://github.com/CIRISAI/CIRISAgent/issues/738)
- Canonical algorithm: `src/ciris-verify-core/src/security/build_manifest.rs`
- Public Rust API: `src/ciris-verify-core/src/tree_verify.rs`
- FFI export: `ciris_verify_tree` in `src/ciris-verify-ffi/src/lib.rs`
- Python API: `bindings/python/ciris_verify/client.py:verify_tree`
