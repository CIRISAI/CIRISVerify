//! ciris-manifest-tool - Function manifest generator for CIRISVerify.
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
//! # Detect target triple from binary
//! ciris-manifest-tool detect-target --binary libciris_verify_ffi.so
//! ```

mod manifest;
mod parser;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Function manifest generator for CIRISVerify.
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

        /// Function name prefix filter (e.g., "ciris_verify_")
        #[arg(short, long, default_value = "ciris_verify_")]
        filter: String,

        /// Output manifest path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Pretty-print JSON output
        #[arg(long)]
        pretty: bool,
    },

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
            let target = match target {
                Some(t) => t,
                None => {
                    let detected = parser::detect_target(&binary)?;
                    eprintln!("  Target (detected): {}", detected);
                    detected
                }
            };

            eprintln!("  Version: {}", version);
            eprintln!("  Filter: {}", filter);

            // Generate manifest
            let manifest = manifest::generate_manifest(
                &binary,
                &target,
                &version,
                Some(&filter),
            )?;

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
                println!("{}", json);
            }

            eprintln!("\nManifest generated successfully.");
            eprintln!("\nNOTE: This manifest is UNSIGNED. For production use,");
            eprintln!("sign with the steward key via the CI pipeline.");
        }

        Commands::DetectTarget { binary } => {
            let target = parser::detect_target(&binary)?;
            println!("{}", target);
        }

        Commands::ListFunctions { binary, filter } => {
            let parsed = parser::parse_binary(&binary, filter.as_deref())?;

            println!("Functions in {}:", binary.display());
            println!("{:<60} {:>12} {:>12}", "Name", "Offset", "Size");
            println!("{}", "-".repeat(84));

            for func in &parsed.functions {
                println!(
                    "{:<60} 0x{:08x} {:>12}",
                    func.name, func.offset, func.size
                );
            }

            println!("\nTotal: {} functions", parsed.functions.len());
        }
    }

    Ok(())
}
