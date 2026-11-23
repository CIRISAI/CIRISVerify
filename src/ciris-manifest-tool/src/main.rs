//! ciris-manifest-tool - Function manifest generator for `CIRISVerify`.
//!
//! Generates signed manifests of function hashes for runtime integrity verification.
//!
//! ## Usage
//!
//! ```bash
//! # Generate manifest for a binary (unsigned)
//! ciris-manifest-tool generate \
//!     --binary target/release/libciris_verify_ffi.so \
//!     --target x86_64-unknown-linux-gnu \
//!     --output manifests/function_manifest.linux-x86_64.json
//!
//! # Generate with function filter (FFI exports only)
//! ciris-manifest-tool generate \
//!     --binary target/release/libciris_verify_ffi.so \
//!     --filter "ciris_verify_" \
//!     --output manifest.json
//!
//! # The ciris-binary-manifest/1 blob (FSD-008 §6) of a final shipped file
//! ciris-manifest-tool generate-blob \
//!     --binary ciris_server/_native.abi3.so \
//!     --project ciris-server --version 0.6.0 --target aarch64-apple-darwin \
//!     --inline-functions --output build_manifest.cbor
//!
//! # Detect target triple from binary
//! ciris-manifest-tool detect-target --binary libciris_verify_ffi.so
//! ```

mod blob;
mod manifest;
mod parser;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Function manifest generator for `CIRISVerify`.
///
/// Generates signed manifests of function hashes that can be verified at runtime
/// to detect function-level tampering.
#[derive(Parser)]
#[command(name = "ciris-manifest-tool")]
#[command(version = VERSION)]
#[command(about = "Function manifest generator for CIRISVerify")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a function manifest from a binary
    Generate {
        /// Path to the compiled binary (ELF, Mach-O, or PE)
        #[arg(short, long)]
        binary: PathBuf,

        /// Target triple (auto-detected if not specified)
        #[arg(short, long)]
        target: Option<String>,

        /// Binary version (from Cargo.toml or --version flag)
        #[arg(long, default_value = VERSION)]
        version: String,

        /// Function name prefix filter (e.g., "`ciris_verify`_")
        #[arg(short, long, default_value = "ciris_verify_")]
        filter: String,

        /// Output manifest path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Pretty-print JSON output
        #[arg(long)]
        pretty: bool,
    },

    /// Generate the `ciris-binary-manifest/1` blob (deterministic CBOR,
    /// FSD-008 §6) from the final shipped file
    GenerateBlob(GenerateBlobArgs),

    /// Detect the target triple from a binary
    DetectTarget {
        /// Path to the binary
        #[arg(short, long)]
        binary: PathBuf,
    },

    /// List functions in a binary
    ListFunctions {
        /// Path to the binary
        #[arg(short, long)]
        binary: PathBuf,

        /// Function name prefix filter
        #[arg(short, long)]
        filter: Option<String>,
    },
}

/// The `generate-blob` arguments.
#[derive(clap::Args)]
struct GenerateBlobArgs {
    /// Path to the final binary (ELF, Mach-O, or PE), after every post-link rewrite
    #[arg(short, long)]
    binary: PathBuf,

    /// Project, `[a-z0-9-]`, 1..=64 bytes (the build row's `build.project`)
    #[arg(long)]
    project: String,

    /// Version, 1..=64 bytes (the build row's `build.version`)
    #[arg(long)]
    version: String,

    /// Target triple (the build row's dimension `{target}`); required, never guessed
    #[arg(short, long)]
    target: String,

    /// Function name prefix filter
    #[arg(short, long, default_value = "ciris_verify_")]
    filter: String,

    /// Carry the function table inline (the root is always carried)
    #[arg(long)]
    inline_functions: bool,

    /// The `generated_at` member (RFC 3339). Default: `SOURCE_DATE_EPOCH`
    /// when set, else now. Fix it for byte-identical output.
    #[arg(long)]
    generated_at: Option<String>,

    /// Output path for the blob bytes (required: the blob is binary)
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .init();
    }

    match cli.command {
        Commands::Generate {
            binary,
            target,
            version,
            filter,
            output,
            pretty,
        } => {
            eprintln!("Generating function manifest...");
            eprintln!("  Binary: {}", binary.display());

            // Detect or use provided target
            let target = if let Some(t) = target {
                t
            } else {
                let detected = parser::detect_target(&binary)?;
                eprintln!("  Target (detected): {detected}");
                detected
            };

            eprintln!("  Version: {version}");
            eprintln!("  Filter: {filter}");

            // Generate manifest
            let manifest = manifest::generate_manifest(&binary, &target, &version, Some(&filter))?;

            eprintln!("  Functions: {}", manifest.functions.len());
            eprintln!("  Manifest hash: {}", manifest.manifest_hash);

            // Serialize
            let json = if pretty {
                serde_json::to_string_pretty(&manifest)?
            } else {
                serde_json::to_string(&manifest)?
            };

            // Output
            if let Some(output_path) = output {
                std::fs::write(&output_path, &json)?;
                eprintln!("  Output: {}", output_path.display());
            } else {
                println!("{json}");
            }

            eprintln!("\nManifest generated successfully.");
            eprintln!("\nNOTE: This manifest is UNSIGNED. For production use,");
            eprintln!("sign with the steward key via the CI pipeline.");
        },

        Commands::GenerateBlob(args) => generate_blob_cmd(args)?,

        Commands::DetectTarget { binary } => {
            let target = parser::detect_target(&binary)?;
            println!("{target}");
        },

        Commands::ListFunctions { binary, filter } => {
            let parsed = parser::parse_binary(&binary, filter.as_deref())?;

            println!("Functions in {}:", binary.display());
            println!("{:<60} {:>12} {:>12}", "Name", "Offset", "Size");
            println!("{}", "-".repeat(84));

            for func in &parsed.functions {
                println!("{:<60} 0x{:08x} {:>12}", func.name, func.offset, func.size);
            }

            println!("\nTotal: {} functions", parsed.functions.len());
        },
    }

    Ok(())
}

/// `generate-blob`: write the blob and print its summary.
fn generate_blob_cmd(args: GenerateBlobArgs) -> anyhow::Result<()> {
    let GenerateBlobArgs {
        binary,
        project,
        version,
        target,
        filter,
        inline_functions,
        generated_at,
        output,
    } = args;
    let generated_at = match generated_at {
        Some(g) => g,
        None => default_generated_at()?,
    };
    let tool = format!("ciris-manifest-tool/{VERSION}");
    let out = blob::generate_blob(
        &binary,
        &blob::BlobRequest {
            project: &project,
            version: &version,
            target: &target,
            filter: Some(&filter),
            inline_functions,
            generated_at: &generated_at,
            tool: &tool,
        },
    )?;
    std::fs::write(&output, &out.bytes)?;
    eprintln!(
        "Generated {}",
        ciris_verify_core::edition2::build_manifest::FORMAT
    );
    eprintln!("  Binary: {}", binary.display());
    eprintln!("  Project / version / target: {project} / {version} / {target}");
    eprintln!("  Binary hash: {}", hex::encode(out.manifest.binary_hash));
    eprintln!("  Functions: {}", out.function_count);
    eprintln!(
        "  Functions root: {}",
        hex::encode(out.manifest.functions_root)
    );
    eprintln!("  Inline table: {inline_functions}");
    eprintln!("  Blob: {} bytes", out.bytes.len());
    {
        use sha2::Digest as _;
        eprintln!(
            "  Manifest hash: {}",
            hex::encode(sha2::Sha256::digest(&out.bytes))
        );
    }
    eprintln!("  Output: {}", output.display());
    Ok(())
}

/// `SOURCE_DATE_EPOCH` (seconds) when set, so a reproducible build emits the
/// same blob; else now.
fn default_generated_at() -> anyhow::Result<String> {
    use ciris_verify_core::utc::{SecondsFormat, UtcDateTime};
    let t = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(s) => {
            let secs: i64 = s.trim().parse()?;
            secs.checked_mul(1000)
                .and_then(UtcDateTime::from_timestamp_millis)
                .ok_or_else(|| anyhow::anyhow!("SOURCE_DATE_EPOCH out of range"))?
        },
        Err(_) => UtcDateTime::now(),
    };
    Ok(t.to_rfc3339_opts(SecondsFormat::Secs, true))
}
