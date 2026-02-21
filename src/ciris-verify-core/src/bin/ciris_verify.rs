//! CIRISVerify CLI - Hardware-rooted license verification for CIRIS agents.
//!
//! This binary provides a command-line interface to run CIRISVerify checks
//! and display attestation results.

use std::time::Duration;

use ciris_verify_core::config::TrustModel;
use ciris_verify_core::registry::{compute_self_hash, current_target, RegistryClient};
use ciris_verify_core::validation::ConsensusValidator;
use clap::{Parser, Subcommand};

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
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
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

    /// Level 4: Verify this binary's integrity against registry
    SelfCheck {
        /// Registry API endpoint
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
        registry: String,
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

  1. BINARY SELF-VERIFICATION
     Verifies CIRISVerify itself hasn't been tampered with by checking its
     hash against a registry-hosted manifest. "Who watches the watchmen?"

  2. SOURCE VALIDATION (DNS/HTTPS)
     Verifies data from multiple independent sources using a consensus
     algorithm. HTTPS is authoritative; DNS provides cross-checks.

  3. FILE INTEGRITY
     Verifies agent binaries match the signed manifest from CIRISRegistry,
     detecting tampering or unauthorized modifications.

  4. KEY ATTESTATION + AUDIT TRAIL
     Verifies the agent has valid hardware-backed credentials and an
     unbroken cryptographic audit log from genesis.

ATTESTATION LEVELS (1-5)
========================

  The "DMV for AI Agents" - Progressive Trust Verification

  CRITICAL: If ANY level fails, ALL higher levels show YELLOW (unverified).
  A compromised verifier binary could report "all green" regardless of state.

  Level 1: LIBRARY LOADED (green if you see this output)
     CIRISVerify binary loaded and functional
     If this fails, you see nothing - the binary didn't run

  Level 2: BINARY SELF-VERIFICATION (recursive!)
     SHA-256 of THIS binary verified against registry manifest
     "Who watches the watchmen?" - proves the verifier itself is authentic
     RECURSIVE: Fetches manifest via Level 3, but if Level 2 fails,
                Level 3-5 results are MEANINGLESS (yellow/unverified)

  Level 3: REGISTRY CROSS-VALIDATION
     DNS (US/EU) + HTTPS registry queries (2/3 agreement)
     Multi-source consensus prevents single point of compromise
     HTTPS is authoritative, DNS is advisory

  Level 4: AGENT FILE INTEGRITY
     SHA-256 of agent files against registry-hosted manifest
     Tripwire-style tamper detection (spot-check or full)
     Detects code modifications or injected backdoors

  Level 5: PORTAL KEY + AUDIT TRAIL
     Ed25519 key from CIRISPortal + unbroken hash chain
     Full provenance - key legitimately issued, every action signed

TRUST BOUNDARIES
================

  Binary self-verification does NOT protect against a compromised registry.
  An attacker controlling the registry could update both binary and manifest.

  Mitigations:
  - Level 3 multi-source cross-validation (2/3 geographically distributed)
  - Initial provisioning via trusted app stores:
    * Android: Google Play Store
    * iOS: Apple App Store
    * Python: PyPI (pip install ciris-verify)
    * Linux: Official package repositories

  The initial provisioning moment is the weakest point in any trust chain.
  This is true of all trust systems (TLS CAs, PGP web of trust, etc.).

USAGE
=====

  ciris-verify sources    Check DNS and HTTPS source validation (Level 3)
  ciris-verify self-check Verify this binary's integrity (Level 2)
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
        println!(
            "  DNS US:  {} {}",
            dns_us_status,
            result.source_details.dns_us_error.as_deref().unwrap_or("")
        );
        println!(
            "  DNS EU:  {} {}",
            dns_eu_status,
            result.source_details.dns_eu_error.as_deref().unwrap_or("")
        );
        println!(
            "  HTTPS:   {} {}",
            https_status,
            result.source_details.https_error.as_deref().unwrap_or("")
        );
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
            println!(
                "  Classical Key: Present ({} bytes)",
                result
                    .consensus_key_classical
                    .as_ref()
                    .map(|k| k.len())
                    .unwrap_or(0)
            );
            println!(
                "  PQC Fingerprint: {}",
                if result.consensus_pqc_fingerprint.is_some() {
                    "Present"
                } else {
                    "Not available"
                }
            );
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

async fn run_self_check(registry_url: &str, json: bool) {
    if !json {
        println!("\nBINARY SELF-VERIFICATION (Level 2)");
        println!("===================================\n");
        println!("This verifies the CIRISVerify binary itself hasn't been tampered with.");
        println!("It computes a SHA-256 hash of the running executable and compares it");
        println!("against the registry-hosted manifest.\n");
    }

    // Compute self hash
    let self_hash = match compute_self_hash() {
        Ok(hash) => hash,
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!(
                    "\x1b[31m[ERROR]\x1b[0m Failed to compute binary hash: {}",
                    e
                );
            }
            return;
        },
    };

    let target = current_target();

    if !json {
        println!("Binary Information:");
        println!("  Target: {}", target);
        println!("  Version: {}", VERSION);
        println!("  SHA-256: {}", &self_hash[..16].to_uppercase());
        println!("           {}...", &self_hash[16..32].to_uppercase());
        println!();
    }

    // Try to fetch manifest from registry
    println!("Fetching manifest from registry...");
    let client = match RegistryClient::new(registry_url, Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => {
            if json {
                println!(
                    r#"{{"status":"error","message":"Registry client error: {}"}}"#,
                    e
                );
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Registry client error: {}", e);
                println!();
                println!("IMPORTANT: Binary self-verification requires the registry to");
                println!("implement: GET /v1/verify/binary-manifest/{{version}}");
                println!();
                println!("TRUST BOUNDARY NOTE:");
                println!("  Self-verification protects against tampered binaries but NOT");
                println!("  against a compromised registry. Initial provisioning via a");
                println!("  trusted distribution channel (Google Play, Apple App Store,");
                println!("  PyPI, package managers) is crucial for establishing the");
                println!("  initial trust chain.");
            }
            return;
        },
    };

    match client.get_binary_manifest(VERSION).await {
        Ok(manifest) => match manifest.binaries.get(target) {
            Some(expected_hash) => {
                let expected = expected_hash
                    .strip_prefix("sha256:")
                    .unwrap_or(expected_hash);

                let matches = self_hash.eq_ignore_ascii_case(expected);

                if json {
                    let output = serde_json::json!({
                        "status": if matches { "pass" } else { "fail" },
                        "target": target,
                        "version": VERSION,
                        "actual_hash": self_hash,
                        "expected_hash": expected,
                        "matches": matches
                    });
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else if matches {
                    println!("\x1b[32m[PASS]\x1b[0m Binary hash matches registry manifest");
                    println!();
                    println!("Level 2 verification PASSED. This binary is authentic.");
                } else {
                    println!("\x1b[31m[FAIL]\x1b[0m Binary hash does NOT match registry manifest!");
                    println!();
                    println!("  Expected: {}", expected);
                    println!("  Actual:   {}", self_hash);
                    println!();
                    println!("WARNING: This binary may have been tampered with.");
                    println!("All subsequent attestation levels are UNVERIFIED.");
                }
            },
            None => {
                if json {
                    println!(
                        r#"{{"status":"error","message":"No hash for target '{}' in manifest"}}"#,
                        target
                    );
                } else {
                    println!(
                        "\x1b[33m[WARN]\x1b[0m No binary hash for target '{}' in manifest",
                        target
                    );
                    println!();
                    println!("Available targets in manifest:");
                    for t in manifest.binaries.keys() {
                        println!("  - {}", t);
                    }
                }
            },
        },
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!(
                    "\x1b[33m[WARN]\x1b[0m Could not fetch binary manifest: {}",
                    e
                );
                println!();
                println!("The registry may not have implemented the binary manifest route yet.");
                println!("Route required: GET /v1/verify/binary-manifest/{}", VERSION);
                println!();
                println!("Your binary hash (for manual verification):");
                println!("  {}", self_hash);
                println!();
                println!("TRUST BOUNDARY NOTE:");
                println!("  Binary self-verification does NOT protect against a compromised");
                println!("  registry (an attacker could update both binary and manifest).");
                println!("  The Level 3 multi-source cross-validation (2/3 agreement across");
                println!("  geographically distributed sources) mitigates registry compromise.");
                println!();
                println!("  Initial provisioning via a trusted distribution channel is crucial:");
                println!("  - Android: Google Play Store");
                println!("  - iOS: Apple App Store");
                println!("  - Python: PyPI (pip install ciris-verify)");
                println!("  - Linux: Official package repositories");
            }
        },
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
        Some(Commands::Sources {
            dns_us,
            dns_eu,
            https,
            timeout,
        }) => {
            if !json_output {
                print_banner();
            }
            run_source_check(&dns_us, &dns_eu, &https, timeout, json_output).await;
        },
        Some(Commands::Info) => {
            print_banner();
            show_system_info();
        },
        Some(Commands::Attest {
            version,
            agent_root,
        }) => {
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
                println!(
                    "Agent Version: {}",
                    version.as_deref().unwrap_or("not specified")
                );
                println!(
                    "Agent Root: {}",
                    agent_root.as_deref().unwrap_or("not specified")
                );
                println!();
                println!("Full attestation with file integrity checking is not yet");
                println!("implemented in the CLI. Use the library API or Python bindings.");
                println!();
                println!("For now, you can run source validation:");
                println!("  ciris-verify sources");
            }
        },
        Some(Commands::SelfCheck { registry }) => {
            print_banner();
            run_self_check(&registry, json_output).await;
        },
        None => {
            // No command - show help
            print_banner();
            print_explanation();
        },
    }
}
