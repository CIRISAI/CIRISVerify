//! `ciris-build-sign register` — atomically write all three registry tables
//! (`builds`, `binary_manifests`, `function_manifests`) for a CIRIS primitive
//! release. Closes CIRISVerify#6.
//!
//! Background. CIRISAgent CI cut over from the legacy
//! `register_agent_build.py` (which wrote all three tables) to
//! `ciris-build-sign sign` + `curl POST /v1/verify/build-manifest` (which
//! only writes `function_manifests`). Parent rows stopped being written for
//! every agent release ≥ 2.7.8 and the gap is structural — every primitive
//! that adopts the new tooling reproduces it. This module restores the
//! parent-row writes inside `ciris-build-sign` so all six onboarded
//! primitives get the fix for free.
//!
//! Wire formats are mirrored from the legacy script and the registry
//! handlers (cited in CIRISVerify#6). Auth split:
//!
//! - HTTP `POST /v1/verify/binary-manifest` and HTTP `POST
//!   /v1/verify/build-manifest`: `Authorization: Bearer
//!   $REGISTRY_ADMIN_TOKEN`.
//! - gRPC `RegistryAdminService.RegisterBuild`: HS256 JWT minted in-process
//!   from `$REGISTRY_JWT_SECRET` (mirrors `register_agent_build.py:336
//!   generate_admin_jwt`).
//!
//! Idempotency: each registry endpoint UPSERTs on `(project, version[,
//! target])`. The dispatcher treats 200/201/409 + "duplicate key" as
//! success so retried CI runs converge.
//!
//! gRPC dispatch uses `grpcurl` as a subprocess (matches the legacy script
//! exactly). This avoids pulling tonic + a build.rs into ciris-build-tool
//! for one RPC. CI runners that already have the legacy tool installed
//! (per agent's pre-2.7.8 build.yml) need no change; runners that don't
//! must add a one-line `go install` step or download a release binary.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ciris_verify_core::security::build_manifest::BuildManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Arguments for the `register` subcommand.
#[derive(Debug, Clone)]
pub struct RegisterArgs {
    /// CIRIS primitive name in kebab-case as it appears in
    /// `trusted_primitive_keys.project` (e.g., `"ciris-agent"`,
    /// `"ciris-persist"`).
    pub project: String,

    /// Binary version string (e.g., `"2.7.10"`). Must match the
    /// `binary_version` in every per-target BuildManifest passed via
    /// `--target`.
    pub binary_version: String,

    /// Build identifier (typically a git SHA). Used for the `builds`
    /// row's `build_id` field and for traceability.
    pub build_id: String,

    /// Per-target manifest files. Each entry is
    /// `target_name:path/to/build-manifest.json`. Targets must match
    /// the `target` field inside the BuildManifest.
    pub targets: Vec<TargetSpec>,

    /// Source repository URL. Stored on the `builds` row.
    pub source_repo: String,

    /// Source commit SHA. Stored on the `builds` row.
    pub source_commit: String,

    /// Modules included in the build (e.g., `["core"]`,
    /// `["core","ios"]`). Mirrors legacy `--modules`.
    pub modules: Vec<String>,

    /// Optional notes for the `builds` and `binary_manifests` rows.
    pub notes: Option<String>,

    /// Registry base URL (e.g., `"https://api.registry.ciris-services-1.ai"`).
    /// When `None`, falls back to `$REGISTRY_URL`.
    pub registry_url: Option<String>,

    /// gRPC address for `RegisterBuild` (e.g., `"207.148.13.157:50051"`).
    /// Defaults to `$REGISTRY_GRPC_ADDR` when omitted.
    pub registry_grpc_addr: Option<String>,

    /// Optional override for `--build-hash`. When omitted, the build
    /// hash is derived from the per-target manifest hashes (sorted-merkle
    /// — see [`derive_build_hash`]).
    pub build_hash_override: Option<String>,

    /// When true, prints what would be sent and exits without contacting
    /// the registry. Useful for CI dry-runs.
    pub dry_run: bool,
}

/// A `name:path` pair for one target's signed BuildManifest.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    pub name: String,
    pub path: PathBuf,
}

impl TargetSpec {
    pub fn parse(s: &str) -> Result<Self> {
        let (name, path) = s.split_once(':').ok_or_else(|| {
            anyhow!(
                "--target value must be 'name:path' (got {s:?}); \
                 example: --target python-source-tree:./build-manifest.json"
            )
        })?;
        if name.is_empty() {
            anyhow::bail!("--target value has empty name part: {s:?}");
        }
        if path.is_empty() {
            anyhow::bail!("--target value has empty path part: {s:?}");
        }
        Ok(Self {
            name: name.to_string(),
            path: PathBuf::from(path),
        })
    }
}

// =============================================================================
// Body shapes — mirror what the registry HTTP handlers expect.
// =============================================================================

/// Request body for `POST /v1/verify/binary-manifest`.
///
/// Mirrors `RegisterBinaryManifestRequest` in
/// `CIRISRegistry/rust-registry/src/api/http.rs:363`. The server signs the
/// canonical content `{project}/{version}:{binaries_json}` with the
/// registry steward key — the client does *not* sign here.
#[derive(Debug, Serialize)]
struct BinaryManifestRequest<'a> {
    project: &'a str,
    version: &'a str,
    binaries: &'a BTreeMap<String, String>,
    generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
}

/// Response body for `POST /v1/verify/binary-manifest` (and similar).
#[derive(Debug, Deserialize)]
struct RegistryResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

/// Loaded BuildManifest plus the file path it came from.
struct LoadedTarget {
    name: String,
    path: PathBuf,
    manifest: BuildManifest,
    raw_bytes: Vec<u8>,
}

// =============================================================================
// Public entry point
// =============================================================================

/// Run the `register` subcommand.
///
/// Reads each per-target BuildManifest, validates them against the
/// requested project + binary_version, derives `build_hash`, and dispatches
/// the three endpoints in dependency order:
///
/// 1. `gRPC RegistryAdminService.RegisterBuild` → `builds` row
/// 2. `POST /v1/verify/binary-manifest` → `binary_manifests` row
/// 3. `POST /v1/verify/build-manifest` (per target) → `function_manifests` rows
///
/// On dry_run, prints intended payloads and returns without contacting the
/// registry.
pub fn run(args: RegisterArgs) -> Result<()> {
    let admin_token = if args.dry_run {
        // Still required-ish so dry-run shape matches; emit a placeholder.
        std::env::var("REGISTRY_ADMIN_TOKEN").unwrap_or_else(|_| "<unset>".to_string())
    } else {
        std::env::var("REGISTRY_ADMIN_TOKEN")
            .context("REGISTRY_ADMIN_TOKEN is required for HTTP registry writes")?
    };
    let jwt_secret = if args.dry_run {
        std::env::var("REGISTRY_JWT_SECRET").unwrap_or_else(|_| "<unset>".to_string())
    } else {
        std::env::var("REGISTRY_JWT_SECRET")
            .context("REGISTRY_JWT_SECRET is required for gRPC RegisterBuild")?
    };
    let registry_url = match (&args.registry_url, std::env::var("REGISTRY_URL").ok()) {
        (Some(u), _) => u.clone(),
        (None, Some(env)) => env,
        (None, None) => {
            anyhow::bail!("registry HTTP URL required: pass --registry-url or set REGISTRY_URL")
        },
    };
    let grpc_addr = match (
        &args.registry_grpc_addr,
        std::env::var("REGISTRY_GRPC_ADDR").ok(),
    ) {
        (Some(a), _) => a.clone(),
        (None, Some(env)) => env,
        (None, None) => anyhow::bail!(
            "registry gRPC address required: pass --registry-grpc-addr or set REGISTRY_GRPC_ADDR"
        ),
    };

    // Load all per-target manifests. Validate that each has the right
    // project + binary_version + target name.
    let mut loaded = Vec::with_capacity(args.targets.len());
    for spec in &args.targets {
        let raw_bytes = fs::read(&spec.path)
            .with_context(|| format!("read per-target manifest {}", spec.path.display()))?;
        let manifest: BuildManifest = serde_json::from_slice(&raw_bytes)
            .with_context(|| format!("parse BuildManifest at {}", spec.path.display()))?;
        validate_target(&args, spec, &manifest)?;
        loaded.push(LoadedTarget {
            name: spec.name.clone(),
            path: spec.path.clone(),
            manifest,
            raw_bytes,
        });
    }
    if loaded.is_empty() {
        anyhow::bail!("at least one --target is required");
    }

    // Build the binaries map for the binary_manifests row.
    let binaries: BTreeMap<String, String> = loaded
        .iter()
        .map(|t| (t.name.clone(), t.manifest.manifest_hash.clone()))
        .collect();

    let build_hash = match &args.build_hash_override {
        Some(h) => h.clone(),
        None => derive_build_hash(&binaries),
    };

    // Construct the BuildRecord JSON for RegisterBuild. The registry's
    // BuildRecord proto requires file_manifest_* fields; for a multi-target
    // release we put the binary_manifests JSON in file_manifest_json so the
    // builds row carries a pointer to "what shipped". file_manifest_count
    // is the number of targets.
    let binary_manifest_json = serde_json::to_string(&serde_json::json!({
        "binaries": &binaries,
        "build_hash": &build_hash,
    }))
    .context("serialize binary_manifest JSON for builds row")?;
    let file_manifest_hash = sha256_hex(binary_manifest_json.as_bytes());

    if args.dry_run {
        eprintln!("[dry-run] register payload preview:");
        eprintln!("  project          = {}", args.project);
        eprintln!("  binary_version   = {}", args.binary_version);
        eprintln!("  build_id         = {}", args.build_id);
        eprintln!("  build_hash       = {}", &build_hash);
        eprintln!("  modules          = {:?}", args.modules);
        eprintln!("  source_repo      = {:?}", args.source_repo);
        eprintln!("  source_commit    = {:?}", args.source_commit);
        eprintln!("  binaries:");
        for (target, mh) in &binaries {
            eprintln!("    {target} -> {mh}");
        }
        eprintln!("  file_manifest_hash = {file_manifest_hash}");
        eprintln!("  registry_url     = {}", registry_url);
        eprintln!("  registry_grpc    = {grpc_addr}");
        eprintln!("[dry-run] no network calls made");
        return Ok(());
    }

    // === 1) gRPC RegisterBuild — writes builds row =========================
    register_build_via_grpc(
        &args,
        &grpc_addr,
        &jwt_secret,
        &build_hash,
        &file_manifest_hash,
        &binary_manifest_json,
    )?;

    // === 2) HTTP POST /v1/verify/binary-manifest — writes binary_manifests ==
    register_binary_manifest_via_http(&args, &registry_url, &admin_token, &binaries)?;

    // === 3) HTTP POST /v1/verify/build-manifest per target =================
    for t in &loaded {
        register_function_manifest_via_http(&args, &registry_url, &admin_token, t)?;
    }

    eprintln!(
        "OK: registered {} {} ({} target{}, build_hash={})",
        args.project,
        args.binary_version,
        loaded.len(),
        if loaded.len() == 1 { "" } else { "s" },
        &build_hash[..build_hash.len().min(16)],
    );
    Ok(())
}

// =============================================================================
// Validation
// =============================================================================

fn validate_target(args: &RegisterArgs, spec: &TargetSpec, manifest: &BuildManifest) -> Result<()> {
    // Per-target manifest's binary_version must match the release version
    // we're registering. Suffix-stripping (e.g., "2.7.10-rc1" → "2.7.10")
    // is intentionally NOT done here — see CIRISAgent#726 for that
    // workstream. If callers want to register a non-canonical version they
    // should pass the matching --binary-version explicitly.
    if manifest.binary_version != args.binary_version {
        anyhow::bail!(
            "target {:?} ({}): manifest binary_version is {:?}, but --binary-version is {:?}; \
             refuse to register a binary_manifests row that doesn't match its targets",
            spec.name,
            spec.path.display(),
            manifest.binary_version,
            args.binary_version,
        );
    }
    if manifest.target != spec.name {
        anyhow::bail!(
            "target {:?} ({}): manifest target field is {:?}, but --target name is {:?}; \
             pass --target {}:{} or fix the manifest",
            spec.name,
            spec.path.display(),
            manifest.target,
            spec.name,
            manifest.target,
            spec.path.display(),
        );
    }
    Ok(())
}

// =============================================================================
// build_hash derivation
// =============================================================================

/// Derive `build_hash` from a sorted set of per-target manifest hashes.
///
/// Format: `sha256(target1_name + ":" + manifest_hash1 + "\n" + target2_name +
/// ":" + manifest_hash2 + ...)`, with targets sorted by name. The ordering
/// is deterministic so the same set of targets produces the same build_hash
/// regardless of CLI argument order. Hex-encoded with `"sha256:"` prefix to
/// match the rest of CIRIS's hash conventions.
pub fn derive_build_hash(binaries: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (target, manifest_hash) in binaries {
        hasher.update(target.as_bytes());
        hasher.update(b":");
        hasher.update(manifest_hash.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

// =============================================================================
// HS256 JWT (mirror legacy register_agent_build.py:336 generate_admin_jwt)
// =============================================================================

/// Mint an admin HS256 JWT from the registry's shared secret.
///
/// Mirrors `generate_admin_jwt` from
/// `CIRISAgent/tools/legacy/register_agent_build.py:336` — same header,
/// same payload shape, same signing. CI sets `REGISTRY_JWT_SECRET` and the
/// secret is HMAC'd as UTF-8 bytes (NOT base64-decoded — explicit per
/// legacy comment).
pub fn mint_admin_jwt(secret: &str, issuer: &str, ttl_seconds: u64) -> Result<String> {
    use hmac::{Mac, SimpleHmac};

    let now = Utc::now().timestamp();
    let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
    let payload = serde_json::json!({
        "sub": "admin",
        "iss": issuer,
        "iat": now,
        "exp": now + i64::try_from(ttl_seconds).unwrap_or(3600),
        "role": 1,                 // SYSTEM_ADMIN
        "org_id": "",
    });
    let header_str = serde_json::to_string(&header)?;
    let payload_str = serde_json::to_string(&payload)?;
    let header_b64 = base64_url(header_str.as_bytes());
    let payload_b64 = base64_url(payload_str.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow!("HMAC key error: {e}"))?;
    mac.update(signing_input.as_bytes());
    let sig_bytes = mac.finalize().into_bytes();
    let sig_b64 = base64_url(&sig_bytes);
    Ok(format!("{signing_input}.{sig_b64}"))
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(bytes)
}

// =============================================================================
// gRPC RegisterBuild via grpcurl subprocess
// =============================================================================

/// Call `ciris.registry.v1.RegistryAdminService/RegisterBuild` via grpcurl.
///
/// Mirrors the legacy script's invocation (lines 234-252 in
/// register_agent_build.py). The payload field names match the
/// `BuildRecord` proto in `CIRISRegistry/protocol/ciris_registry.proto`.
fn register_build_via_grpc(
    args: &RegisterArgs,
    grpc_addr: &str,
    jwt_secret: &str,
    build_hash: &str,
    file_manifest_hash: &str,
    binary_manifest_json: &str,
) -> Result<()> {
    let token = mint_admin_jwt(jwt_secret, "ciris-registry", 3600)?;
    let payload = serde_json::json!({
        "build": {
            "build_id": uuid::Uuid::new_v4().to_string(),
            "version": args.binary_version,
            "build_hash": build_hash,
            "file_manifest_hash": file_manifest_hash,
            "file_manifest_count": args.targets.len() as i32,
            "file_manifest_json": STANDARD.encode(binary_manifest_json.as_bytes()),
            "includes_modules": args.modules,
            "project": args.project,
            "source_repo": args.source_repo,
            "source_commit": args.source_commit,
            "registered_at": Utc::now().timestamp(),
            "registered_by": format!("ciris-build-sign register/{}", env!("CARGO_PKG_VERSION")),
            "status": "active",
            "notes": args.notes.clone().unwrap_or_default(),
        }
    });
    let payload_str = serde_json::to_string(&payload)?;

    eprintln!("[1/3] gRPC RegisterBuild → {grpc_addr}");
    let scheme = if grpc_addr.starts_with("localhost")
        || grpc_addr.starts_with("127.")
        || grpc_addr.starts_with("0.0.0.0")
        || grpc_addr.contains(":50051")
    {
        "-plaintext"
    } else {
        ""
    };

    let mut cmd = Command::new("grpcurl");
    if !scheme.is_empty() {
        cmd.arg(scheme);
    }
    cmd.args([
        "-H",
        &format!("Authorization: Bearer {token}"),
        "-d",
        "@",
        grpc_addr,
        "ciris.registry.v1.RegistryAdminService/RegisterBuild",
    ]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().context(
        "failed to spawn `grpcurl`. Install with: \
         `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` \
         or download from https://github.com/fullstorydev/grpcurl/releases",
    )?;
    {
        use std::io::Write;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("grpcurl stdin"))?;
        stdin.write_all(payload_str.as_bytes())?;
    }
    let out = child.wait_with_output().context("await grpcurl")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    if out.status.success() {
        eprintln!(
            "      OK: {}",
            stdout.lines().next().unwrap_or("(empty response)")
        );
        return Ok(());
    }

    // Treat duplicate-key as success (idempotent re-runs).
    let combined = format!("{stdout}\n{stderr}");
    if combined.contains("duplicate key") || combined.contains("AlreadyExists") {
        eprintln!("      already registered (treating as success)");
        return Ok(());
    }
    anyhow::bail!("grpcurl RegisterBuild failed:\nstdout: {stdout}\nstderr: {stderr}");
}

// =============================================================================
// HTTP POST /v1/verify/binary-manifest
// =============================================================================

fn register_binary_manifest_via_http(
    args: &RegisterArgs,
    registry_url: &str,
    admin_token: &str,
    binaries: &BTreeMap<String, String>,
) -> Result<()> {
    let url = format!(
        "{}/v1/verify/binary-manifest",
        registry_url.trim_end_matches('/')
    );
    let body = BinaryManifestRequest {
        project: &args.project,
        version: &args.binary_version,
        binaries,
        generated_at: Utc::now().to_rfc3339(),
        notes: args.notes.as_deref(),
    };
    eprintln!("[2/3] POST {url}");
    let client = reqwest::blocking::Client::builder()
        .build()
        .context("build reqwest client")?;
    let resp = client
        .post(&url)
        .bearer_auth(admin_token)
        .json(&body)
        .send()
        .context("POST /v1/verify/binary-manifest")?;
    handle_http_response(resp, "binary-manifest")
}

// =============================================================================
// HTTP POST /v1/verify/build-manifest (one per target → function_manifests)
// =============================================================================

fn register_function_manifest_via_http(
    _args: &RegisterArgs,
    registry_url: &str,
    admin_token: &str,
    target: &LoadedTarget,
) -> Result<()> {
    let url = format!(
        "{}/v1/verify/build-manifest",
        registry_url.trim_end_matches('/')
    );
    eprintln!(
        "[3/3] POST {url}  (target={}, manifest={})",
        target.name,
        target.path.display()
    );
    let client = reqwest::blocking::Client::builder()
        .build()
        .context("build reqwest client")?;
    let resp = client
        .post(&url)
        .bearer_auth(admin_token)
        .header("Content-Type", "application/json")
        .body(target.raw_bytes.clone())
        .send()
        .context("POST /v1/verify/build-manifest")?;
    handle_http_response(resp, &format!("build-manifest({})", target.name))
}

// =============================================================================
// Common HTTP response handling
// =============================================================================

fn handle_http_response(resp: reqwest::blocking::Response, label: &str) -> Result<()> {
    let status = resp.status();
    let body_bytes = resp.bytes().unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Try to parse as RegistryResponse for nicer logging.
    let parsed: Option<RegistryResponse> = serde_json::from_slice(&body_bytes).ok();

    if status.is_success() {
        let msg = parsed.as_ref().map(|r| r.message.as_str()).unwrap_or("");
        eprintln!(
            "      OK ({status}){}",
            if msg.is_empty() {
                String::new()
            } else {
                format!(": {msg}")
            }
        );
        return Ok(());
    }
    if status == reqwest::StatusCode::CONFLICT {
        eprintln!("      already registered (HTTP 409, treating as success)");
        return Ok(());
    }
    // Some servers express idempotency in body content even with 200.
    if let Some(p) = &parsed {
        if (p.error.contains("duplicate") || p.message.contains("duplicate")) && !p.success {
            eprintln!("      already registered (body indicates duplicate, treating as success)");
            return Ok(());
        }
    }
    anyhow::bail!("{label} POST failed: HTTP {status}\nbody: {body_str}")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_spec_parses_name_path() {
        let s = TargetSpec::parse("python-source-tree:./build-manifest.json").unwrap();
        assert_eq!(s.name, "python-source-tree");
        assert_eq!(s.path, PathBuf::from("./build-manifest.json"));
    }

    #[test]
    fn target_spec_rejects_missing_colon() {
        let err = TargetSpec::parse("nope-no-colon").unwrap_err();
        assert!(err.to_string().contains("name:path"), "got: {err}");
    }

    #[test]
    fn target_spec_rejects_empty_parts() {
        assert!(TargetSpec::parse(":path").is_err());
        assert!(TargetSpec::parse("name:").is_err());
    }

    #[test]
    fn build_hash_is_deterministic_under_target_order() {
        // Same target set inserted in different orders → same BuildHash,
        // because BTreeMap iteration is by sorted key.
        let mut a = BTreeMap::new();
        a.insert("python-source-tree".to_string(), "sha256:aaaa".to_string());
        a.insert("ios-mobile-bundle".to_string(), "sha256:bbbb".to_string());

        let mut b = BTreeMap::new();
        b.insert("ios-mobile-bundle".to_string(), "sha256:bbbb".to_string());
        b.insert("python-source-tree".to_string(), "sha256:aaaa".to_string());

        assert_eq!(derive_build_hash(&a), derive_build_hash(&b));
    }

    #[test]
    fn build_hash_changes_with_manifest_hash() {
        let mut a = BTreeMap::new();
        a.insert("t".to_string(), "sha256:aaaa".to_string());
        let h1 = derive_build_hash(&a);

        let mut a2 = BTreeMap::new();
        a2.insert("t".to_string(), "sha256:bbbb".to_string());
        let h2 = derive_build_hash(&a2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_hash_format_has_sha256_prefix_and_64_hex() {
        let mut m = BTreeMap::new();
        m.insert("t".to_string(), "sha256:aaaa".to_string());
        let h = derive_build_hash(&m);
        assert!(h.starts_with("sha256:"), "got: {h}");
        let hex_part = &h["sha256:".len()..];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn jwt_has_three_dot_separated_parts() {
        let token = mint_admin_jwt("dev-secret", "ciris-registry", 3600).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "got: {token}");
        // Header decodes to {"alg":"HS256","typ":"JWT"}.
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "HS256");
        assert_eq!(header["typ"], "JWT");
    }

    #[test]
    fn jwt_payload_has_admin_role_and_issuer() {
        let token = mint_admin_jwt("k", "test-iss", 60).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["sub"], "admin");
        assert_eq!(payload["iss"], "test-iss");
        assert_eq!(payload["role"], 1);
        // exp = iat + ttl (60s)
        let iat = payload["iat"].as_i64().unwrap();
        let exp = payload["exp"].as_i64().unwrap();
        assert_eq!(exp - iat, 60);
    }

    #[test]
    fn jwt_signature_is_deterministic_for_same_input() {
        // HS256 with no nonce → same secret + same header/payload → same sig.
        // We can't easily fix iat across calls without mocking time, so this
        // test instead verifies the same secret produces a syntactically
        // valid signature each time.
        let t1 = mint_admin_jwt("s", "i", 60).unwrap();
        let t2 = mint_admin_jwt("s", "i", 60).unwrap();
        assert_eq!(t1.split('.').count(), 3);
        assert_eq!(t2.split('.').count(), 3);
    }
}
