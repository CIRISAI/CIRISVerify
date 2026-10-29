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
//!
//! Or, offline, a safety-battery evidence row (CIRISVerify#322) and its blob:
//!
//! ```text
//! ciris-build-verify \
//!     --evidence contribution.json \
//!     --blob manifest.json \
//!     --key-id agent-steward-2026 \
//!     --ed25519-pub steward.ed25519.pub \
//!     --mldsa-pub steward.mldsa65.pub
//! ```
//!
//! That checks blob size and hash → row → signature → pinned key. The
//! pipeline's `infra:attest` standing is the reader's walk over its own key
//! directory, which an offline check cannot do; it is reported as unchecked.

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
    #[arg(
        short,
        long,
        required_unless_present = "evidence",
        conflicts_with = "evidence"
    )]
    manifest: Option<PathBuf>,

    /// Expected primitive (snake_case).
    #[arg(long, required_unless_present = "evidence")]
    primitive: Option<String>,

    /// A safety-evidence contribution JSON (`ciris-build-sign evidence`
    /// output) to verify instead of a manifest.
    #[arg(long, requires_all = ["blob", "key_id"])]
    evidence: Option<PathBuf>,

    /// The blob the evidence row names.
    #[arg(long, requires = "evidence")]
    blob: Option<PathBuf>,

    /// The pipeline key_id the pinned pubkeys belong to.
    #[arg(long, requires = "evidence")]
    key_id: Option<String>,

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

    if let Some(evidence) = &cli.evidence {
        return verify_evidence(&cli, evidence);
    }

    let primitive = parse_primitive(cli.primitive.as_deref().unwrap_or_default());
    let manifest_path = cli.manifest.as_ref().ok_or_else(|| anyhow!("--manifest"))?;
    let manifest_bytes = fs::read(manifest_path)
        .with_context(|| format!("read manifest at {}", manifest_path.display()))?;

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

/// Verify a safety-evidence row against its blob and pinned keys, offline.
fn verify_evidence(cli: &Cli, evidence: &std::path::Path) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ciris_verify_core::safety_evidence::verify_safety_evidence_signature;
    use ciris_verify_core::threshold::ThresholdMember;

    let contribution: serde_json::Value = serde_json::from_slice(
        &fs::read(evidence).with_context(|| format!("read {}", evidence.display()))?,
    )
    .context("evidence contribution is not JSON")?;
    let blob_path = cli.blob.as_ref().ok_or_else(|| anyhow!("--blob"))?;
    let blob = fs::read(blob_path).with_context(|| format!("read {}", blob_path.display()))?;
    let member = ThresholdMember {
        member_id: cli.key_id.clone().ok_or_else(|| anyhow!("--key-id"))?,
        ed25519_public_key_base64: STANDARD.encode(read_key(&cli.ed25519_pub)?),
        mldsa65_public_key_base64: Some(STANDARD.encode(read_key(&cli.mldsa_pub)?)),
        role: None,
    };

    let row = verify_safety_evidence_signature(&contribution, &member)
        .map_err(|e| anyhow!("verification failed: {e}"))?;
    row.check_blob(&blob)
        .map_err(|e| anyhow!("verification failed: {e}"))?;

    if cli.show {
        println!("Verified safety evidence:");
        println!("  dimension:      {}", row.dimension);
        println!("  score:          {}", row.score);
        println!("  attestation_id: {}", row.attestation_id);
        println!("  asserted_at:    {}", row.asserted_at);
        println!("  signed by:      {}", row.attested_by);
        println!(
            "  blob:           {} ({} bytes)",
            row.manifest_hash, row.manifest_size
        );
    }
    eprintln!(
        "OK: {} verified against its blob and the pinned key; infra:attest standing \
         not checked (the reader's walk)",
        row.dimension
    );
    Ok(())
}
