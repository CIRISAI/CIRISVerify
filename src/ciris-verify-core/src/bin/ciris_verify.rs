//! CIRISVerify CLI - Hardware-rooted license verification for CIRIS agents.
//!
//! This binary provides a command-line interface to run CIRISVerify checks
//! and display attestation results.

use std::time::Duration;

use clap::{Parser, Subcommand};
use ciris_verify_core::config::TrustModel;
use ciris_verify_core::validation::ConsensusValidator;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// CIRISVerify - Hardware-rooted license verification for CIRIS agents.
///
/// CIRISVerify is an open-source (AGPL-3.0) verification module that provides
/// cryptographic proof of license status. It ensures community agents cannot
/// masquerade as licensed professional agents (CIRISMedical, CIRISLegal, etc.).
///
/// Think of it like a DMV doing a background check:
/// - Source Validation: Verify the license exists in official databases
/// - Key Attestation: Verify the agent has proper credentials (hardware-backed)
/// - File Integrity: Verify the agent software hasn't been tampered with
/// - Audit Trail: Verify the agent's history is intact and authentic
#[derive(Parser)]
#[command(name = "ciris-verify")]
#[command(version = VERSION)]
#[command(about = "Hardware-rooted license verification for CIRIS agents")]
#[command(long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check DNS and HTTPS source validation
    Sources {
        /// DNS US host
        #[arg(long, default_value = "us.registry.ciris-services-1.ai")]
        dns_us: String,

        /// DNS EU host
        #[arg(long, default_value = "eu.registry.ciris-services-1.ai")]
        dns_eu: String,

        /// HTTPS endpoint
        #[arg(long, default_value = "https://registry.ciris.ai")]
        https: String,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Show system information and capabilities
    Info,

    /// Run full attestation check (requires agent context)
    Attest {
        /// Agent version to verify
        #[arg(long)]
        version: Option<String>,

        /// Agent root directory
        #[arg(long)]
        agent_root: Option<String>,
    },
}

fn print_banner() {
    println!(
        r#"
   ____ ___ ____  ___ ______     __         _  __
  / ___|_ _|  _ \|_ _/ ___\ \   / /__  _ __(_)/ _|_   _
 | |    | || |_) || |\___ \\ \ / / _ \| '__| | |_| | | |
 | |___ | ||  _ < | | ___) |\ V /  __/| |  | |  _| |_| |
  \____|___|_| \_\___|____/  \_/ \___||_|  |_|_|  \__, |
                                                  |___/
  Hardware-Rooted License Verification for CIRIS Agents
  Version: {}
"#,
        VERSION
    );
}

fn print_explanation() {
    println!(
        r#"
WHAT IS CIRISVERIFY?
====================

CIRISVerify is the cryptographic verification layer that ensures CIRIS agents
are legitimate. Like a DMV verifying a driver's license, CIRISVerify checks:

  1. SOURCE VALIDATION (DNS/HTTPS)
     Verifies license data from multiple independent sources using a
     consensus algorithm. HTTPS is authoritative; DNS provides cross-checks.

  2. KEY ATTESTATION
     Verifies the agent has valid cryptographic credentials, ideally
     backed by hardware security (TPM, Secure Enclave, StrongBox).

  3. FILE INTEGRITY
     Verifies agent binaries match the signed manifest from CIRISRegistry,
     detecting tampering or unauthorized modifications.

  4. AUDIT TRAIL
     Verifies the agent's cryptographic audit log has an unbroken hash
     chain from genesis, ensuring history hasn't been altered.

ATTESTATION LEVELS
==================

  Level 5: Full hardware attestation with all checks passing
  Level 4: Hardware keys with partial source validation
  Level 3: Software-only keys with file integrity verified
  Level 2: Basic validation, some checks unavailable
  Level 1: Minimal validation, degraded mode
  Level 0: Verification failed or unavailable

USAGE
=====

  ciris-verify sources    Check DNS and HTTPS source validation
  ciris-verify info       Show system capabilities
  ciris-verify attest     Run full attestation (requires agent context)

For more information: https://github.com/CIRISAI/CIRISVerify
"#
    );
}

async fn run_source_check(dns_us: &str, dns_eu: &str, https: &str, timeout_secs: u64, json: bool) {
    if !json {
        println!("\nSOURCE VALIDATION CHECK");
        println!("=======================\n");

        println!("Configuration:");
        println!("  DNS US:  {}", dns_us);
        println!("  DNS EU:  {}", dns_eu);
        println!("  HTTPS:   {}", https);
        println!("  Timeout: {}s", timeout_secs);
        println!();
        println!("Running validation...\n");
    }

    let validator = ConsensusValidator::with_trust_model(
        dns_us.to_string(),
        dns_eu.to_string(),
        https.to_string(),
        vec![], // No additional HTTPS endpoints
        TrustModel::HttpsAuthoritative,
        Duration::from_secs(timeout_secs),
        None, // No cert pinning for now
    );

    let result = validator.validate_steward_key().await;

    if json {
        // JSON output
        let output = serde_json::json!({
            "status": format!("{:?}", result.status),
            "allows_licensed": result.allows_licensed(),
            "is_security_alert": result.is_security_alert(),
            "is_degraded": result.is_degraded(),
            "authoritative_source": result.authoritative_source,
            "sources": {
                "dns_us": {
                    "reachable": result.source_details.dns_us_reachable,
                    "error": result.source_details.dns_us_error,
                },
                "dns_eu": {
                    "reachable": result.source_details.dns_eu_reachable,
                    "error": result.source_details.dns_eu_error,
                },
                "https": {
                    "reachable": result.source_details.https_reachable,
                    "error": result.source_details.https_error,
                },
            },
            "consensus": {
                "has_classical_key": result.consensus_key_classical.is_some(),
                "has_pqc_fingerprint": result.consensus_pqc_fingerprint.is_some(),
                "revocation_revision": result.consensus_revocation_revision,
            }
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        // Human-readable output
        println!("RESULTS");
        println!("-------\n");

        // Source status
        let dns_us_status = if result.source_details.dns_us_reachable {
            "\x1b[32mOK\x1b[0m"
        } else {
            "\x1b[31mFAIL\x1b[0m"
        };
        let dns_eu_status = if result.source_details.dns_eu_reachable {
            "\x1b[32mOK\x1b[0m"
        } else {
            "\x1b[31mFAIL\x1b[0m"
        };
        let https_status = if result.source_details.https_reachable {
            "\x1b[32mOK\x1b[0m"
        } else {
            "\x1b[31mFAIL\x1b[0m"
        };

        println!("Source Status:");
        println!("  DNS US:  {} {}", dns_us_status,
            result.source_details.dns_us_error.as_deref().unwrap_or(""));
        println!("  DNS EU:  {} {}",dns_eu_status,
            result.source_details.dns_eu_error.as_deref().unwrap_or(""));
        println!("  HTTPS:   {} {}",https_status,
            result.source_details.https_error.as_deref().unwrap_or(""));
        println!();

        // Overall status
        let status_str = format!("{:?}", result.status);
        let status_color = match result.status {
            ciris_verify_core::types::ValidationStatus::AllSourcesAgree => "\x1b[32m", // Green
            ciris_verify_core::types::ValidationStatus::PartialAgreement => "\x1b[33m", // Yellow
            ciris_verify_core::types::ValidationStatus::SourcesDisagree => "\x1b[31m", // Red
            ciris_verify_core::types::ValidationStatus::NoSourcesReachable => "\x1b[31m",
            ciris_verify_core::types::ValidationStatus::ValidationError => "\x1b[31m",
        };

        println!("Validation Status: {}{}\x1b[0m", status_color, status_str);

        if let Some(ref auth) = result.authoritative_source {
            println!("Authoritative Source: {}", auth);
        }

        println!();

        // Consensus data
        if result.consensus_key_classical.is_some() {
            println!("Consensus Data:");
            println!("  Classical Key: Present ({} bytes)",
                result.consensus_key_classical.as_ref().map(|k| k.len()).unwrap_or(0));
            println!("  PQC Fingerprint: {}",
                if result.consensus_pqc_fingerprint.is_some() { "Present" } else { "Not available" });
            if let Some(rev) = result.consensus_revocation_revision {
                println!("  Revocation Revision: {}", rev);
            }
            println!();
        }

        // Summary
        println!("Summary:");
        if result.allows_licensed() {
            println!("  \x1b[32m[PASS]\x1b[0m Source validation allows licensed operation");
        } else {
            println!("  \x1b[31m[FAIL]\x1b[0m Source validation does NOT allow licensed operation");
        }

        if result.is_security_alert() {
            println!("  \x1b[31m[ALERT]\x1b[0m Security alert: sources disagree!");
        }

        if result.is_degraded() {
            println!("  \x1b[33m[WARN]\x1b[0m Operating in degraded mode");
        }
    }
}

fn show_system_info() {
    println!("\nSYSTEM INFORMATION");
    println!("==================\n");

    println!("CIRISVerify Version: {}", VERSION);
    println!();

    // Platform info
    println!("Platform:");
    println!("  OS: {}", std::env::consts::OS);
    println!("  Arch: {}", std::env::consts::ARCH);
    println!();

    // Crypto capabilities
    println!("Cryptographic Capabilities:");
    println!("  Classical Signatures: Ed25519, ECDSA P-256");
    #[cfg(feature = "pqc")]
    println!("  Post-Quantum Signatures: ML-DSA-65 (FIPS 204)");
    #[cfg(not(feature = "pqc"))]
    println!("  Post-Quantum Signatures: Not enabled");
    println!();

    // Hardware capabilities
    println!("Hardware Security:");

    #[cfg(target_os = "macos")]
    println!("  Secure Enclave: Available (macOS)");

    #[cfg(target_os = "ios")]
    println!("  Secure Enclave: Available (iOS)");

    #[cfg(all(target_os = "linux", feature = "tpm"))]
    println!("  TPM 2.0: Enabled (Linux)");

    #[cfg(all(target_os = "linux", not(feature = "tpm")))]
    println!("  TPM 2.0: Not enabled (compile with --features tpm)");

    #[cfg(all(target_os = "windows", feature = "tpm-windows"))]
    println!("  TPM (PCP): Enabled (Windows - EXPERIMENTAL)");

    #[cfg(all(target_os = "windows", not(feature = "tpm-windows")))]
    println!("  TPM (PCP): Not enabled (compile with --features tpm-windows)");

    #[cfg(target_os = "android")]
    println!("  StrongBox/TEE: Available (Android)");

    println!();

    // Features
    println!("Enabled Features:");
    #[cfg(feature = "pqc")]
    println!("  - pqc (Post-Quantum Cryptography)");
    #[cfg(feature = "tpm")]
    println!("  - tpm (Linux TPM 2.0)");
    #[cfg(feature = "tpm-windows")]
    println!("  - tpm-windows (Windows PCP - EXPERIMENTAL)");
    #[cfg(feature = "android")]
    println!("  - android (Android Keystore)");
    #[cfg(feature = "ios")]
    println!("  - ios (iOS Keychain)");
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let json_output = cli.format == "json";

    // Initialize logging (suppress for JSON output)
    if json_output {
        // No logging for JSON mode
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_target(false)
            .init();
    } else if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_target(false)
            .init();
    }

    match cli.command {
        Some(Commands::Sources { dns_us, dns_eu, https, timeout }) => {
            if !json_output {
                print_banner();
            }
            run_source_check(&dns_us, &dns_eu, &https, timeout, json_output).await;
        }
        Some(Commands::Info) => {
            print_banner();
            show_system_info();
        }
        Some(Commands::Attest { version, agent_root }) => {
            print_banner();
            println!("\nFULL ATTESTATION");
            println!("================\n");

            if version.is_none() && agent_root.is_none() {
                println!("Full attestation requires agent context.");
                println!();
                println!("Usage:");
                println!("  ciris-verify attest --version 1.0.0 --agent-root /path/to/agent");
                println!();
                println!("This command verifies:");
                println!("  1. Source validation (DNS/HTTPS)");
                println!("  2. File integrity against registry manifest");
                println!("  3. Key attestation (if hardware available)");
                println!("  4. Audit trail integrity (if provided)");
                println!();
                println!("For standalone source validation, use:");
                println!("  ciris-verify sources");
            } else {
                println!("Agent Version: {}", version.as_deref().unwrap_or("not specified"));
                println!("Agent Root: {}", agent_root.as_deref().unwrap_or("not specified"));
                println!();
                println!("Full attestation with file integrity checking is not yet");
                println!("implemented in the CLI. Use the library API or Python bindings.");
                println!();
                println!("For now, you can run source validation:");
                println!("  ciris-verify sources");
            }
        }
        None => {
            // No command - show help
            print_banner();
            print_explanation();
        }
    }
}
