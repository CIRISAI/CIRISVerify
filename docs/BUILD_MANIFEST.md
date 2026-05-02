# BuildManifest Design Spec (v1.8)

**Status:** Design (P2.1 of v1.8)
**Driver issue:** #1 — Generalize substrate primitives for PoB federation peers
**Builds on:** Existing `FunctionManifest` at `src/ciris-verify-core/src/security/function_integrity.rs:73`

## Why this exists

CIRISVerify already validates function-level manifests for itself and the agent through `FunctionManifest` + `verify_manifest_signature` + `verify_self_against_manifest`. The math is right; the shape is hardcoded to one consumer (the agent's binary). PoB §2.3's score-as-pure-function only holds if every peer (lens, persist, registry, future primitives, and CIRISVerify itself) ships build-authentic, validated by the same machinery.

This spec generalizes the existing per-artifact manifest into a primitive-discriminated shape so the same verifier handles every PoB peer.

## What is NOT in scope

- The catalog-style `BinaryManifest` at `registry.rs:348` (target → binary hash). That's a different artifact, kept as-is for v1.8. Generalization of that catalog is follow-up work.
- New cryptographic primitives. Hybrid Ed25519 + ML-DSA-65 stays the only signing mode (PoB §1.4 precedent).
- Replacement of CIRISRegistry. The registry still publishes manifests; we publish the validator.
- PoB-domain naming inside CIRISVerify. We use `BuildPrimitive`, not `PoBPrimitive`.

## Types

### `BuildPrimitive`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "primitive", rename_all = "snake_case")]
pub enum BuildPrimitive {
    /// CIRISVerify itself. Self-check uses this discriminator.
    Verify,
    /// CIRISAgent.
    Agent,
    /// CIRISLens (until PoB §3.1 lens-into-agent collapse lands).
    Lens,
    /// CIRISPersist.
    Persist,
    /// CIRISRegistry.
    Registry,
    /// Forward-compat for primitives invented after this enum version.
    /// Use sparingly — production primitives should add named variants.
    Other(String),
}
```

**Naming rule.** Wire-format strings are snake_case (`"verify"`, `"agent"`, etc.). The Rust enum uses PascalCase variants. Consumers parsing JSON should not assume the discriminator equals the Rust variant name.

### `BuildManifest`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    /// Manifest schema version. Starts at "1.0".
    /// Bumped on backwards-incompatible field changes.
    pub manifest_schema_version: String,

    /// Which CIRIS primitive this manifest describes.
    pub primitive: BuildPrimitive,

    /// Build identifier (typically a git SHA or version tag).
    /// Distinct from `binary_version` because some primitives version
    /// their builds independently of the underlying binary's version.
    pub build_id: String,

    /// Target triple this manifest applies to (e.g., "x86_64-unknown-linux-gnu").
    /// Per-target manifests because primitive binaries are
    /// per-target-built.
    pub target: String,

    /// SHA-256 hash of the entire signed binary file (hex, with "sha256:" prefix).
    pub binary_hash: String,

    /// Binary version string from the primitive's source (e.g., Cargo.toml version).
    pub binary_version: String,

    /// ISO 8601 generation timestamp.
    pub generated_at: String,

    /// SHA-256 of the canonical extras representation.
    /// `null` if the primitive has no extras.
    /// For `BuildPrimitive::Verify`, this is the hash of the function
    /// table (preserving v1.7 self-check semantics).
    pub manifest_hash: String,

    /// Primitive-specific extras. Opaque to CIRISVerify; the registered
    /// `ExtrasValidator` for `primitive` parses + validates this.
    /// `None` if the primitive has no extras (some lightweight primitives
    /// may only need build_id + binary_hash).
    pub extras: Option<serde_json::Value>,

    /// Hybrid signature over the canonical bytes (everything above
    /// excluding signature itself). Both signatures must verify.
    pub signature: ManifestSignature,
}
```

**Field rationale:**

- `manifest_schema_version` — separate from `binary_version` and from `BuildPrimitive` evolution. Lets us add fields without forking the enum.
- `build_id` vs `binary_version` — agent has both a Cargo version and a git SHA; persist has a `migration_set_hash` it treats as "build identity"; registry has a release tag. `build_id` is the primitive's own identity for the build; `binary_version` is the underlying compilation.
- `manifest_hash` — preserves v1.7's `FunctionManifest::manifest_hash` semantics for the `Verify` case (it's the hash of the function table). For other primitives it's the hash of their extras canonical bytes.
- `extras: Option<Value>` — opaque on the verifier side. Dispatch to a registered `ExtrasValidator` happens after parse + signature verify. **Not** typed in CIRISVerify — primitives ship their own typed extras crate and register a validator.

### `ManifestSignature`

Reuse the existing `ManifestSignature` struct unchanged (`function_integrity.rs:149`). Hybrid Ed25519 + ML-DSA-65, `pqc` covers `data || classical_signature`.

### `ExtrasValidator`

```rust
pub trait ExtrasValidator: Send + Sync {
    /// Which primitive's extras this validator handles.
    fn primitive(&self) -> BuildPrimitive;

    /// Parse and validate the extras blob.
    /// Errors here are returned to the caller of `verify_build_manifest`
    /// as `VerifyError::InvalidExtras { reason }`.
    fn validate(&self, extras: &serde_json::Value) -> Result<(), VerifyError>;
}

/// Register an extras validator for a primitive.
///
/// If a validator is already registered for the primitive, the new one
/// replaces it. Returns the previous validator if any (for testing /
/// reset purposes).
///
/// Thread-safe via internal RwLock.
pub fn register_extras_validator(
    v: Box<dyn ExtrasValidator>,
) -> Option<Box<dyn ExtrasValidator>>;

/// Look up the registered validator for a primitive, if any.
pub fn extras_validator_for(
    primitive: &BuildPrimitive,
) -> Option<&'static dyn ExtrasValidator>;
```

The registry is a `RwLock<HashMap<BuildPrimitive, Box<dyn ExtrasValidator>>>` behind a `OnceLock`. Registration at startup; lookup at validation time.

**Opt-in dispatch.** If `extras` is present on the manifest AND a validator is registered for the primitive, the validator runs. If `extras` is present but no validator is registered, the manifest is still considered valid — CIRISVerify does not refuse to validate a manifest just because it doesn't recognize the primitive's extras schema. This is deliberate: it lets new primitives ship manifests through `verify_build_manifest` before their extras crate exists, treating extras as opaque for now.

## Public API

### `verify_build_manifest`

```rust
pub fn verify_build_manifest(
    bytes: &[u8],
    expected_primitive: BuildPrimitive,
    trusted_pubkey: &StewardPublicKey,
) -> Result<BuildManifest, VerifyError>;
```

Steps:

1. Parse `bytes` as JSON into `BuildManifest`. Reject if any required field missing.
2. Verify `manifest.primitive == expected_primitive`. Reject otherwise (defends against cross-primitive replay).
3. Compute canonical bytes (see "Canonical bytes" below).
4. Verify the hybrid signature over canonical bytes against `trusted_pubkey`. Reject if either signature fails.
5. If `manifest.extras.is_some()` AND `extras_validator_for(&expected_primitive).is_some()`, dispatch to the validator. Reject if it errors.
6. Return the parsed manifest.

Error cases use existing `VerifyError` variants where they exist; new variants:
- `VerifyError::ManifestPrimitiveMismatch { expected, found }`
- `VerifyError::InvalidExtras { primitive, reason }`

### Trust roots

CIRISVerify embeds its own steward key for `BuildPrimitive::Verify` (preserving v1.7 self-check). For all other primitives, the caller provides the trusted public key. CIRISVerify does **not** bundle trust anchors for primitives we don't author.

How callers get the right key:
- Agent looks up "lens steward key" in its registry-pinned trust list.
- Lens looks up "persist steward key" similarly.
- Registry-side bootstrap: each primitive's repo publishes its steward key; CIRISRegistry serves them through its existing public-key endpoint.

This keeps CIRISVerify's scope clean: we provide validation, not trust-root distribution.

## Canonical bytes

Match the v1.7 `FunctionManifest::canonical_bytes()` pattern: deterministic JSON, BTreeMap-ordered for the extras map (when extras is an object), signature field excluded.

```rust
#[derive(Serialize)]
struct CanonicalBuildManifest<'a> {
    manifest_schema_version: &'a str,
    primitive: &'a BuildPrimitive,
    build_id: &'a str,
    target: &'a str,
    binary_hash: &'a str,
    binary_version: &'a str,
    generated_at: &'a str,
    manifest_hash: &'a str,
    extras: &'a Option<serde_json::Value>,
}
```

`serde_json::to_vec` over this struct produces the bytes the signature covers. Field order is fixed by the struct definition; `extras` is whatever JSON shape the primitive defines, but the surrounding bytes are deterministic.

**Note on extras determinism.** If a primitive's extras includes nested objects, the primitive is responsible for choosing a deterministic representation. We recommend `serde_json::Value` arrays for ordered collections and `serde_json::Map` (which preserves insertion order in Rust) — but for cross-language stability primitives should serialize their extras through a `BTreeMap` first.

## Migration from `FunctionManifest`

`FunctionManifest` becomes a thin wrapper over `BuildManifest` + a registered `VerifyExtras` validator.

### Verify primitive's extras

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyExtras {
    /// Critical functions with their hashes (preserves v1.7 shape).
    pub functions: BTreeMap<String, FunctionEntry>,
    /// Metadata about offset computation (preserved from v1.7).
    pub metadata: ManifestMetadata,
}

pub struct VerifyExtrasValidator;

impl ExtrasValidator for VerifyExtrasValidator {
    fn primitive(&self) -> BuildPrimitive {
        BuildPrimitive::Verify
    }

    fn validate(&self, extras: &serde_json::Value) -> Result<(), VerifyError> {
        // Parse into typed struct. Errors propagate as InvalidExtras.
        let _: VerifyExtras = serde_json::from_value(extras.clone())
            .map_err(|e| VerifyError::InvalidExtras {
                primitive: "verify".into(),
                reason: format!("VerifyExtras parse failed: {}", e),
            })?;
        // No further semantic checks at this layer; the runtime
        // function-integrity check (function_integrity::verify_functions)
        // does the actual hash comparison.
        Ok(())
    }
}
```

### Compatibility shim

```rust
/// Compatibility alias for v1.7 callers.
///
/// New code should use `BuildManifest` + `verify_build_manifest`. The
/// `FunctionManifest` shape is preserved by treating its `functions` and
/// `metadata` fields as the `Verify` primitive's `extras`.
pub type FunctionManifest = BuildManifest;
```

If the wire format diverges (the registry still serves the old shape for some endpoints), we do a runtime translation in `RegistryClient`:

```rust
impl From<LegacyFunctionManifest> for BuildManifest {
    fn from(legacy: LegacyFunctionManifest) -> Self {
        BuildManifest {
            manifest_schema_version: "1.0".into(),
            primitive: BuildPrimitive::Verify,
            build_id: legacy.binary_version.clone(),
            target: legacy.target,
            binary_hash: legacy.binary_hash,
            binary_version: legacy.binary_version,
            generated_at: legacy.generated_at,
            manifest_hash: legacy.manifest_hash,
            extras: Some(serde_json::to_value(VerifyExtras {
                functions: legacy.functions,
                metadata: legacy.metadata,
            }).unwrap()),
            signature: legacy.signature,
        }
    }
}
```

The legacy struct stays in the codebase under `legacy::FunctionManifest` for one release cycle, then gets removed.

### Self-check refactor

```rust
pub fn verify_self_against_manifest(manifest: &BuildManifest) -> Result<bool, VerifyError> {
    // Now goes through the generic path:
    // 1. Confirm manifest.primitive == BuildPrimitive::Verify
    // 2. Compare manifest.binary_hash to compute_self_hash() for current_target()
    // 3. Hybrid signature was already verified by verify_build_manifest()
    // ...
}
```

The function stays in `registry.rs` for backwards compat, but its body becomes a wrapper around the generic API.

## Worked examples per primitive

### Verify (eats own dog food)

```json
{
  "manifest_schema_version": "1.0",
  "primitive": "verify",
  "build_id": "1.7.0",
  "target": "x86_64-unknown-linux-gnu",
  "binary_hash": "sha256:abc123...",
  "binary_version": "1.7.0",
  "generated_at": "2026-05-01T17:30:00Z",
  "manifest_hash": "sha256:def456...",
  "extras": {
    "functions": {
      "ciris_verify_init": {
        "name": "ciris_verify_init",
        "offset": 12345,
        "size": 678,
        "hash": "sha256:...",
        "first_bytes": "55488..."
      }
      // ...
    },
    "metadata": {
      "exec_segment_vaddr": 4096,
      "text_section_vaddr": 16384,
      "text_section_offset": 4096
    }
  },
  "signature": {
    "classical": "base64...",
    "classical_algorithm": "Ed25519",
    "pqc": "base64...",
    "pqc_algorithm": "ML-DSA-65",
    "key_id": "verify-steward-2026"
  }
}
```

### Agent

```json
{
  "manifest_schema_version": "1.0",
  "primitive": "agent",
  "build_id": "9b5d0e1",
  "target": "x86_64-unknown-linux-gnu",
  "binary_hash": "sha256:...",
  "binary_version": "1.5.7",
  "generated_at": "2026-05-01T...",
  "manifest_hash": "sha256:...",
  "extras": {
    "agent_template": "professional-medical-v2",
    "cognitive_state_hash": "sha256:...",
    "tripwire_files": { "...": "sha256:..." }
  },
  "signature": { "...": "..." }
}
```

The agent ships an `AgentExtrasValidator` that knows about `agent_template`, `cognitive_state_hash`, etc. CIRISVerify dispatches to it on validation.

### Persist

```json
{
  "manifest_schema_version": "1.0",
  "primitive": "persist",
  "build_id": "v0.1.8",
  "target": "x86_64-unknown-linux-gnu",
  "binary_hash": "sha256:...",
  "binary_version": "0.1.8",
  "generated_at": "2026-05-01T...",
  "manifest_hash": "sha256:...",
  "extras": {
    "migration_set_hash": "sha256:...",
    "dep_tree_hash": "sha256:...",
    "scrubber_bundle_hash": "sha256:..."
  },
  "signature": { "...": "..." }
}
```

Persist's `PersistExtrasValidator` (shipped from CIRISPersist) registers via `register_extras_validator(Box::new(PersistExtrasValidator))` at startup. CIRISVerify holds the validator, dispatches, but never knows what `migration_set_hash` means.

### Lens

```json
{
  "manifest_schema_version": "1.0",
  "primitive": "lens",
  "build_id": "...",
  "extras": {
    "scrubber_bundle_hash": "sha256:...",
    "scoring_config_hash": "sha256:..."
  }
}
```

Until the PoB §3.1 collapse, lens has its own primitive. After the collapse, lens functionality folds into agent and the lens primitive deprecates (kept in the enum for legacy manifest validation).

### Registry

```json
{
  "manifest_schema_version": "1.0",
  "primitive": "registry",
  "extras": {
    "schema_hash": "sha256:...",
    "trusted_keys_hash": "sha256:..."
  }
}
```

## Acceptance bar

1. `verify_build_manifest(BuildPrimitive::Verify, current_self_manifest, embedded_steward_key)` returns `Ok(...)` byte-identically to today's `verify_self_against_manifest`. Verified by parity tests (P2.7).
2. `verify_build_manifest(BuildPrimitive::Persist, persist_signed_manifest, persist_steward_key)` returns `Ok(...)` against a real persist-signed manifest. Verified by P2.8d.
3. `BuildPrimitive::Other("future-primitive")` works without code changes if a validator is registered.
4. The `FunctionManifest` type alias means existing v1.7 callers keep compiling.

## CLI tools (`ciris-build-tool` crate)

Two binaries ship in the v1.8 release for use in CI pipelines and
manual operator workflows:

### `ciris-build-sign`

```bash
# Generate a fresh test keypair (ed25519 + ML-DSA-65, 4 files in dir)
ciris-build-sign generate-keys --output-dir ./keys/

# Sign a Persist build manifest
ciris-build-sign sign \
    --primitive persist \
    --build-id "v0.1.8" \
    --target x86_64-unknown-linux-gnu \
    --binary target/release/persist-server \
    --binary-version 0.1.8 \
    --extras persist-extras.json \
    --ed25519-seed keys/ed25519.seed \
    --mldsa-secret keys/mldsa65.secret \
    --key-id "persist-steward-2026" \
    --output build-manifest.json

# Self-test (sanity-check the embedded crypto primitives)
ciris-build-sign self-test
```

`--binary` (path) and `--binary-hash` (`sha256:...`) are mutually
exclusive. Use `--binary` if the CLI should compute the hash; use
`--binary-hash` if the calling pipeline already computed it (saves
re-reading large artifacts).

Secret-key files are written with mode `0600` on Unix.

### `ciris-build-verify`

```bash
# Quiet (CI mode): exit 0 on success, non-zero on failure
ciris-build-verify \
    --manifest build-manifest.json \
    --primitive persist \
    --ed25519-pub keys/ed25519.pub \
    --mldsa-pub keys/mldsa65.pub

# Verbose (operator mode): print parsed manifest details
ciris-build-verify \
    --manifest build-manifest.json \
    --primitive persist \
    --ed25519-pub keys/ed25519.pub \
    --mldsa-pub keys/mldsa65.pub \
    --show
```

The verifier rejects manifests where the `primitive` field doesn't
match `--primitive`, where either signature fails, or where the
registered `ExtrasValidator` for the primitive errors. Three failure
modes empirically demonstrated in the lib tests (`tests::verify_*`).

## What's left to design (during implementation)

- **Versioning of extras schemas.** A primitive may evolve its extras shape. Two options: bump `manifest_schema_version` (coarse), or have each primitive's extras carry its own schema version (fine). Recommendation: fine-grained per-primitive extras versioning. Each primitive's `ExtrasValidator` decides what versions it accepts.
- **Trust-key rotation.** Out of scope for v1.8. Each primitive handles its own rotation through whatever mechanism it uses today.
- **Registry-side schema.** Coordinate with CIRISRegistry team (their issue #1) on the wire format for build records. The on-disk JSON shape above IS the registry response for `GET /v1/verify/build-manifest/{primitive}/{build_id}/{target}`.

## Wire-format stability contract

**Registry vendors a copy of `BuildManifest`**, not a `ciris-verify-core` dependency. The reason is a `rusqlite` ↔ `sqlx-sqlite` linker conflict on the registry side that prevents direct dependency. Their vendored copy in `rust-registry/src/build_manifest.rs` matches our v1.8.0 wire format byte-for-byte; their `ciris-crypto` dep gives them the verifier primitives directly.

**Implication**: when we change the `BuildManifest` wire format, the registry team needs to be told so they can update their vendored copy. Coordination protocol:

1. **Backwards-compatible additive changes** (new optional `extras` shapes, new `BuildPrimitive` variants via `Other(String)`, new fields with `serde(default)`) — registry is unaffected; their canonical-bytes computation stays valid for old manifests, and new manifests they don't understand fall through to opaque-extras handling.

2. **Breaking changes to canonical-bytes layout** (field order changes, new required fields, schema-version bump) — coordinate via:
   - File a CIRISRegistry issue with the proposed wire-format diff and a `manifest_schema_version` bump (currently `"1.0"`).
   - Their AV-26 closure machinery (`build_manifest::verify_uploaded_manifest`) needs to either accept both old and new schemas during a transition window OR coordinate a synchronized cutover.
   - Bump `BuildManifest::manifest_schema_version` past `"1.0"` so verifiers can dispatch on schema version.

3. **Hybrid signature changes** (e.g., adding a third PQC algorithm slot) — registry's `ciris-crypto` dep already provides Ed25519 + ML-DSA-65 verifiers; if we add a third algorithm, both sides need the new verifier. Coordinate the `ciris-crypto` version bump.

The vendored-not-dependency choice means registry is also forced to ship hybrid-sig verification matching ours — they can't lag behind by depending on an old `ciris-verify-core`. Operationally this enforces version-lockstep on signature math.

Tracked operationally via: every CIRISVerify minor-version bump triggers a check on the registry team's side ("is your `BuildManifest` still byte-compatible?"). If not, the CIRISRegistry issue is the coordination artifact.

## References

- Existing v1.7 implementation: `src/ciris-verify-core/src/security/function_integrity.rs:73-336`
- Self-check entry point: `src/ciris-verify-core/src/registry.rs:1482`
- Umbrella issue: https://github.com/CIRISAI/CIRISVerify/issues/1
- Registry coordination: https://github.com/CIRISAI/CIRISRegistry/issues/1
- Driver FSD: `CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §1.4 (hybrid sig precedent), §2.3 (score-as-pure-function), §7 (non-goals)
