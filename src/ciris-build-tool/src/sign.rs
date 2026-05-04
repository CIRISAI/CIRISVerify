//! `ciris-build-sign` — sign a `BuildManifest` for any CIRIS PoB primitive.
//!
//! Hybrid Ed25519 + ML-DSA-65, matching the verification side at
//! `ciris_verify_core::security::build_manifest::verify_build_manifest`.
//!
//! Usage in CI:
//!
//! ```text
//! ciris-build-sign \
//!     --primitive persist \
//!     --build-id "v0.1.0" \
//!     --target x86_64-unknown-linux-gnu \
//!     --binary target/release/persist-server \
//!     --binary-version 0.1.0 \
//!     --extras path/to/extras.json \
//!     --ed25519-seed steward.ed25519.seed \
//!     --mldsa-secret steward.mldsa65.secret \
//!     --key-id persist-steward-2026 \
//!     --output build-manifest.json
//! ```
//!
//! Or generate ephemeral keys for testing:
//!
//! ```text
//! ciris-build-sign generate-keys --output-dir ./test-keys/
//! ```

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use ciris_build_tool::{
    build_file_tree_extras, build_function_level_extras_from_file, file_tree_extras_to_value,
    function_level_extras_to_value, generate_ed25519_keypair, generate_mldsa65_keypair,
    parse_primitive, read_extra_hashes_file, read_key, self_test_crypto, sha256_file,
    sign_build_manifest,
};
use ciris_verify_core::security::build_manifest::ExemptRules;
use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "ciris-build-sign")]
#[command(version = VERSION)]
#[command(about = "Sign a CIRIS PoB BuildManifest with hybrid Ed25519 + ML-DSA-65 signatures")]
struct Cli {
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Sign a build manifest. Reads/computes binary hash, optional
    /// extras JSON, and emits a signed JSON manifest.
    Sign {
        /// Primitive name. Use snake_case ("verify", "agent", "lens",
        /// "persist", "registry"). Anything else becomes Other(name).
        #[arg(long)]
        primitive: String,

        /// Build identifier (typically a git SHA or release tag).
        #[arg(long)]
        build_id: String,

        /// Target triple (e.g., x86_64-unknown-linux-gnu).
        #[arg(long)]
        target: String,

        /// Path to the binary whose SHA-256 the manifest covers.
        /// Mutually exclusive with --binary-hash, --tree, --manifest-from.
        #[arg(long, conflicts_with_all = ["binary_hash", "tree", "manifest_from"])]
        binary: Option<PathBuf>,

        /// Pre-computed binary hash ("sha256:..."). Mutually exclusive
        /// with --binary, --tree, --manifest-from.
        #[arg(long, conflicts_with_all = ["tree", "manifest_from"])]
        binary_hash: Option<String>,

        /// Binary version string from the primitive's source.
        #[arg(long)]
        binary_version: String,

        /// Path to extras JSON file (optional). Conflicts with --tree
        /// and --manifest-from since those produce typed extras.
        #[arg(long, conflicts_with_all = ["tree", "manifest_from"])]
        extras: Option<PathBuf>,

        /// File-tree mode: walk this directory, build a FileTreeExtras
        /// from per-file SHA-256 hashes, and use the canonical tree
        /// hash as the manifest's binary_hash.
        #[arg(long, conflicts_with = "manifest_from")]
        tree: Option<PathBuf>,

        /// Top-level paths under --tree to include (allowlist). Empty
        /// means walk the whole --tree root.
        #[arg(long, num_args = 0.., requires = "tree")]
        tree_include: Vec<String>,

        /// Directory basenames to skip anywhere in --tree.
        #[arg(long, num_args = 0.., requires = "tree")]
        tree_exempt_dir: Vec<String>,

        /// File extensions (without dot) to skip in --tree.
        #[arg(long, num_args = 0.., requires = "tree")]
        tree_exempt_ext: Vec<String>,

        /// JSON file containing additional path→sha256 entries to merge
        /// into the file-tree map (e.g., build-secret hashes).
        #[arg(long, requires = "tree")]
        tree_extra_hashes_file: Option<PathBuf>,

        /// Function-level mode: ingest a ciris-manifest-tool output
        /// JSON file (function table + metadata) and pack it into
        /// FunctionLevelExtras.
        #[arg(long)]
        manifest_from: Option<PathBuf>,

        /// Path to raw 32-byte Ed25519 seed file.
        #[arg(long)]
        ed25519_seed: PathBuf,

        /// Path to raw ML-DSA-65 secret seed file (32 bytes).
        #[arg(long)]
        mldsa_secret: PathBuf,

        /// Steward key identifier (any string the verifier finds useful).
        #[arg(long)]
        key_id: String,

        /// Output path for the signed manifest. If omitted, writes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Generate a fresh Ed25519 + ML-DSA-65 keypair pair for testing
    /// or one-off CI bootstrap. Writes four files into --output-dir:
    ///   - ed25519.seed       (32 bytes, raw)
    ///   - ed25519.pub        (32 bytes, raw)
    ///   - mldsa65.secret     (32 bytes, raw)
    ///   - mldsa65.pub        (1952 bytes, raw)
    GenerateKeys {
        /// Directory to write keys into. Created if missing.
        #[arg(short, long)]
        output_dir: PathBuf,
    },

    /// Run a quick crypto self-test (sign + verify on a fresh keypair).
    /// Exits 0 if the underlying primitives are working.
    SelfTest,

    /// Register a release with CIRISRegistry. Writes the `builds` parent
    /// row plus, in binary mode, `binary_manifests` and `function_manifests`
    /// rows. File-vs-binary mode auto-detected from the per-target
    /// BuildManifest's extras.
    ///
    /// All endpoints use HTTP with bearer auth (REGISTRY_ADMIN_TOKEN). The
    /// gRPC `RegisterBuild` path was retired in v1.10.1 — use
    /// `ciris-build-sign register --help` if you're upgrading from v1.10.0
    /// and need the old flag mapping.
    ///
    /// Closes CIRISVerify#6.
    Register {
        /// CIRIS primitive's project name in kebab-case
        /// (e.g., "ciris-agent", "ciris-persist", "ciris-lens").
        /// Must match the `project` value the trusted_primitive_keys row
        /// is registered under.
        #[arg(long)]
        project: String,

        /// Binary version string (e.g., "2.7.10"). Must match the
        /// binary_version field in every per-target manifest.
        #[arg(long)]
        binary_version: String,

        /// Build identifier (typically a git SHA).
        #[arg(long)]
        build_id: String,

        /// Per-target manifest. Repeatable. Format: `name:path`, e.g.
        /// `--target python-source-tree:./build-manifest.json`. File mode
        /// requires exactly one target carrying FileTreeExtras; binary
        /// mode allows multiple targets.
        #[arg(long, value_name = "NAME:PATH", required = true)]
        target: Vec<String>,

        /// Source repository URL for the builds row.
        #[arg(long, default_value = "")]
        source_repo: String,

        /// Source commit SHA for the builds row.
        #[arg(long, default_value = "")]
        source_commit: String,

        /// Modules included in the build. Comma-separated or repeated.
        /// Defaults to `["core"]`.
        #[arg(long, value_delimiter = ',', default_values_t = vec!["core".to_string()])]
        modules: Vec<String>,

        /// Optional notes text persisted on the builds + binary_manifests
        /// rows.
        #[arg(long)]
        notes: Option<String>,

        /// Path to the Ed25519 seed file (32 bytes). Used to sign the
        /// `builds` row's CanonicalBuild. Same format as
        /// `ciris-build-sign sign --ed25519-seed`.
        #[arg(long)]
        ed25519_seed: PathBuf,

        /// Path to the ML-DSA-65 secret seed file (32 bytes). Used to
        /// sign the `builds` row's CanonicalBuild. Same format as
        /// `ciris-build-sign sign --mldsa-secret`.
        #[arg(long)]
        mldsa_secret: PathBuf,

        /// Steward `key_id` for the signature. Stored on the `builds` row.
        #[arg(long)]
        key_id: String,

        /// Registry HTTP base URL (e.g.,
        /// `<https://api.registry.ciris-services-1.ai>`). Falls back to
        /// `$REGISTRY_URL` env var if not provided.
        #[arg(long)]
        registry_url: Option<String>,

        /// Override the derived build_hash. By default, build_hash is
        /// computed as sha256(sorted target_name:manifest_hash pairs);
        /// pass this to inject a custom value (e.g., a git tree hash).
        #[arg(long)]
        build_hash: Option<String>,

        /// Print intended payloads and exit without contacting the registry.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    match cli.command {
        Cmd::Sign {
            primitive,
            build_id,
            target,
            binary,
            binary_hash,
            binary_version,
            extras,
            tree,
            tree_include,
            tree_exempt_dir,
            tree_exempt_ext,
            tree_extra_hashes_file,
            manifest_from,
            ed25519_seed,
            mldsa_secret,
            key_id,
            output,
        } => {
            let primitive = parse_primitive(&primitive);

            // Resolve binary_hash + extras based on which input mode the
            // caller picked. Clap's conflicts_with_all enforces that at
            // most one is set.
            let (binary_hash, extras_json) = if let Some(tree_root) = tree {
                let rules = ExemptRules {
                    include_roots: tree_include,
                    exempt_dirs: tree_exempt_dir,
                    exempt_extensions: tree_exempt_ext,
                };
                let extra_hashes = match tree_extra_hashes_file {
                    Some(p) => Some(read_extra_hashes_file(&p)?),
                    None => None,
                };
                let extras = build_file_tree_extras(&tree_root, rules, extra_hashes)?;
                eprintln!(
                    "File-tree mode: walked {}, hashed {} files, tree_hash = {}",
                    tree_root.display(),
                    extras.file_count,
                    extras.file_tree_hash
                );
                (
                    extras.file_tree_hash.clone(),
                    Some(file_tree_extras_to_value(&extras)?),
                )
            } else if let Some(manifest_path) = manifest_from {
                let (extras, source) = build_function_level_extras_from_file(&manifest_path)?;
                eprintln!(
                    "Function-level mode: ingested {} (functions={}, source binary_hash={})",
                    manifest_path.display(),
                    extras.functions.len(),
                    source.binary_hash
                );
                // Use the source manifest's binary_hash so federation
                // peers can match by binary even without parsing extras.
                (
                    source.binary_hash.clone(),
                    Some(function_level_extras_to_value(&extras)?),
                )
            } else {
                // Binary-blob mode (existing behavior).
                let bh = match (binary, binary_hash) {
                    (Some(p), None) => sha256_file(&p)?,
                    (None, Some(h)) => h,
                    (None, None) => {
                        anyhow::bail!(
                            "must specify exactly one of: --binary, --binary-hash, --tree, --manifest-from"
                        )
                    },
                    (Some(_), Some(_)) => unreachable!("clap conflicts_with_all"),
                };
                let ex = match extras {
                    Some(p) => {
                        let s = fs::read_to_string(&p)
                            .with_context(|| format!("read extras at {}", p.display()))?;
                        Some(serde_json::from_str(&s).context("parse extras JSON")?)
                    },
                    None => None,
                };
                (bh, ex)
            };

            let ed_seed = read_key(&ed25519_seed)?;
            let mldsa_seed = read_key(&mldsa_secret)?;

            let signed = sign_build_manifest(
                primitive,
                build_id,
                target,
                binary_hash,
                binary_version,
                extras_json,
                &ed_seed,
                &mldsa_seed,
                &key_id,
            )?;

            match output {
                Some(p) => {
                    fs::write(&p, &signed)
                        .with_context(|| format!("write manifest to {}", p.display()))?;
                    eprintln!("Signed manifest written to {}", p.display());
                },
                None => {
                    use std::io::Write;
                    std::io::stdout().write_all(&signed)?;
                },
            }
        },

        Cmd::GenerateKeys { output_dir } => {
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("create output dir {}", output_dir.display()))?;

            let (ed_seed, ed_pub) = generate_ed25519_keypair()?;
            let (mldsa_secret, mldsa_pub) = generate_mldsa65_keypair()?;

            let ed_seed_path = output_dir.join("ed25519.seed");
            let ed_pub_path = output_dir.join("ed25519.pub");
            let mldsa_secret_path = output_dir.join("mldsa65.secret");
            let mldsa_pub_path = output_dir.join("mldsa65.pub");

            fs::write(&ed_seed_path, ed_seed)?;
            fs::write(&ed_pub_path, ed_pub)?;
            fs::write(&mldsa_secret_path, &mldsa_secret)?;
            fs::write(&mldsa_pub_path, &mldsa_pub)?;

            // Restrict secret-key permissions on Unix.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::Permissions::from_mode(0o600);
                fs::set_permissions(&ed_seed_path, mode.clone())?;
                fs::set_permissions(&mldsa_secret_path, mode)?;
            }

            eprintln!("Generated keypair in {}", output_dir.display());
            eprintln!("  ed25519.seed   ({}B, mode 0600)", 32);
            eprintln!("  ed25519.pub    ({}B)", 32);
            eprintln!("  mldsa65.secret ({}B, mode 0600)", mldsa_secret.len());
            eprintln!("  mldsa65.pub    ({}B)", mldsa_pub.len());
        },

        Cmd::SelfTest => {
            self_test_crypto()?;
            println!("ciris-build-sign self-test: OK");
        },

        Cmd::Register {
            project,
            binary_version,
            build_id,
            target,
            source_repo,
            source_commit,
            modules,
            notes,
            ed25519_seed,
            mldsa_secret,
            key_id,
            registry_url,
            build_hash,
            dry_run,
        } => {
            use ciris_build_tool::register::{run as register_run, RegisterArgs, TargetSpec};

            let targets: Vec<TargetSpec> = target
                .iter()
                .map(|s| TargetSpec::parse(s))
                .collect::<Result<Vec<_>>>()
                .context("parse --target")?;

            let args = RegisterArgs {
                project,
                binary_version,
                build_id,
                targets,
                source_repo,
                source_commit,
                modules,
                notes,
                registry_url,
                build_hash_override: build_hash,
                ed25519_seed_path: ed25519_seed,
                mldsa_secret_path: mldsa_secret,
                key_id,
                dry_run,
            };

            register_run(args).context("register subcommand")?;
        },
    }

    Ok(())
}
