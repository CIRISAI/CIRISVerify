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
    generate_ed25519_keypair, generate_mldsa65_keypair, parse_primitive, read_key,
    self_test_crypto, sha256_file, sign_build_manifest,
};
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
        /// Mutually exclusive with --binary-hash.
        #[arg(long, conflicts_with = "binary_hash")]
        binary: Option<PathBuf>,

        /// Pre-computed binary hash ("sha256:..."). Mutually exclusive
        /// with --binary.
        #[arg(long)]
        binary_hash: Option<String>,

        /// Binary version string from the primitive's source.
        #[arg(long)]
        binary_version: String,

        /// Path to extras JSON file (optional).
        #[arg(long)]
        extras: Option<PathBuf>,

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
            ed25519_seed,
            mldsa_secret,
            key_id,
            output,
        } => {
            let primitive = parse_primitive(&primitive);

            let binary_hash = match (binary, binary_hash) {
                (Some(p), None) => sha256_file(&p)?,
                (None, Some(h)) => h,
                (None, None) => anyhow::bail!("must specify --binary or --binary-hash"),
                (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
            };

            let extras_json = match extras {
                Some(p) => {
                    let s = fs::read_to_string(&p)
                        .with_context(|| format!("read extras at {}", p.display()))?;
                    Some(serde_json::from_str(&s).context("parse extras JSON")?)
                },
                None => None,
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
    }

    Ok(())
}
