//! `ciris-build-verify` — verify a `BuildManifest` for any CIRIS PoB primitive.
//!
//! Reads a signed manifest JSON, the expected primitive, and the
//! trusted Ed25519 + ML-DSA-65 public keys. Exits 0 on full validation,
//! non-zero on any failure.
//!
//! Usage in CI:
//!
//! ```text
//! ciris-build-verify \
//!     --manifest build-manifest.json \
//!     --primitive persist \
//!     --ed25519-pub steward.ed25519.pub \
//!     --mldsa-pub steward.mldsa65.pub
//! ```

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use ciris_build_tool::{
    load_ed25519_pubkey, parse_primitive, read_key, verify_build_manifest_with_keys,
};
use clap::Parser;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "ciris-build-verify")]
#[command(version = VERSION)]
#[command(about = "Verify a CIRIS PoB BuildManifest with hybrid Ed25519 + ML-DSA-65 signatures")]
struct Cli {
    /// Path to signed manifest JSON.
    #[arg(short, long)]
    manifest: PathBuf,

    /// Expected primitive (snake_case).
    #[arg(long)]
    primitive: String,

    /// Path to raw 32-byte Ed25519 public key.
    #[arg(long)]
    ed25519_pub: PathBuf,

    /// Path to raw ML-DSA-65 public key.
    #[arg(long)]
    mldsa_pub: PathBuf,

    /// Print parsed manifest details on success (build_id, target, etc.).
    #[arg(long)]
    show: bool,

    /// Verbose tracing.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    let primitive = parse_primitive(&cli.primitive);

    let manifest_bytes = fs::read(&cli.manifest)
        .with_context(|| format!("read manifest at {}", cli.manifest.display()))?;

    let ed_pub_bytes = read_key(&cli.ed25519_pub)?;
    let ed_pub = load_ed25519_pubkey(ed_pub_bytes)?;

    let mldsa_pub_bytes = read_key(&cli.mldsa_pub)?;

    let manifest = verify_build_manifest_with_keys(
        &manifest_bytes,
        primitive.clone(),
        &ed_pub,
        &mldsa_pub_bytes,
    )
    .map_err(|e| anyhow!("verification failed: {e}"))?;

    if cli.show {
        println!("Verified BuildManifest:");
        println!("  primitive:               {:?}", manifest.primitive);
        println!("  build_id:                {}", manifest.build_id);
        println!("  target:                  {}", manifest.target);
        println!("  binary_hash:             {}", manifest.binary_hash);
        println!("  binary_version:          {}", manifest.binary_version);
        println!("  generated_at:            {}", manifest.generated_at);
        println!("  manifest_hash:           {}", manifest.manifest_hash);
        println!(
            "  manifest_schema_version: {}",
            manifest.manifest_schema_version
        );
        println!(
            "  signature.classical_alg: {}",
            manifest.signature.classical_algorithm
        );
        println!(
            "  signature.pqc_alg:       {}",
            manifest.signature.pqc_algorithm
        );
        println!("  signature.key_id:        {}", manifest.signature.key_id);
        println!(
            "  extras:                  {}",
            manifest
                .extras
                .as_ref()
                .map(|_| "present")
                .unwrap_or("none")
        );
    } else {
        // Quiet by default — exit 0 means success.
        eprintln!("OK: BuildManifest verified for {:?}", manifest.primitive);
    }

    Ok(())
}
