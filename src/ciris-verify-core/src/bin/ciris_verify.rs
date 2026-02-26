//! CIRISVerify CLI - Hardware-rooted license verification for CIRIS agents.
//!
//! This binary provides a command-line interface to run CIRISVerify checks
//! and display attestation results.

use std::path::Path;
use std::time::Duration;

use ciris_verify_core::audit::{read_audit_from_jsonl, read_audit_from_sqlite, AuditVerifier};
use ciris_verify_core::config::TrustModel;
use ciris_verify_core::registry::{compute_self_hash, current_target, RegistryClient};
use ciris_verify_core::security::file_integrity::{
    check_full, check_spot, FileManifest as AgentFileManifest,
};
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
    /// Check DNS and HTTPS source validation (Level 3)
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

    /// Verify this binary's integrity against registry (Level 2)
    SelfCheck {
        /// Registry API endpoint
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
        registry: String,
    },

    /// Verify FFI function integrity against registry manifest
    FunctionCheck {
        /// Registry API endpoint
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
        registry: String,

        /// Show individual function details (normally opaque for security)
        #[arg(long)]
        show_details: bool,
    },

    /// Verify agent files against registry manifest (Level 4)
    AgentFiles {
        /// Agent version to verify
        #[arg(long)]
        version: String,

        /// Agent root directory containing files to verify
        #[arg(long)]
        agent_root: String,

        /// Registry API endpoint
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
        registry: String,

        /// Perform spot-check (verify random sample) instead of full check
        #[arg(long)]
        spot_check: bool,

        /// Number of files to check in spot-check mode
        #[arg(long, default_value = "10")]
        sample_size: usize,
    },

    /// Verify audit trail integrity (Level 5)
    AuditTrail {
        /// Path to SQLite audit database (ciris_audit.db)
        #[arg(long)]
        db_path: Option<String>,

        /// Path to JSONL audit log (audit_logs.jsonl)
        #[arg(long)]
        jsonl_path: Option<String>,

        /// Expected Portal key ID for signature verification
        #[arg(long)]
        portal_key_id: Option<String>,

        /// Perform spot-check instead of full verification
        #[arg(long)]
        spot_check: bool,

        /// Number of entries to check in spot-check mode
        #[arg(long, default_value = "100")]
        sample_size: usize,
    },

    /// List available registry manifests for a version
    ListManifests {
        /// Version to query (e.g., "0.6.17")
        #[arg(long, default_value_t = String::from(VERSION))]
        version: String,

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

REGISTRY MANIFESTS
==================

  The registry hosts three types of manifests:

  1. BINARY MANIFEST (/v1/verify/binary-manifest/{{version}})
     SHA-256 hashes of CIRISVerify binaries for each platform target.
     Used for Level 2 self-verification.

  2. FILE MANIFEST (/v1/builds/{{version}})
     SHA-256 hashes of all CIRISAgent files (Python, configs, etc).
     Used for Level 4 agent file integrity verification.

  3. FUNCTION MANIFEST (/v1/verify/function-manifest/{{version}}/{{target}})
     SHA-256 hashes of FFI export functions at the bytecode level.
     Hybrid-signed (Ed25519 + ML-DSA-65) for post-quantum security.
     Used for runtime function integrity verification.

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

COMMANDS
========

  ciris-verify sources        Check DNS/HTTPS source validation (Level 3)
  ciris-verify self-check     Verify this binary's integrity (Level 2)
  ciris-verify function-check Verify FFI function integrity (runtime)
  ciris-verify agent-files    Verify agent files against manifest (Level 4)
  ciris-verify audit-trail    Verify audit log integrity (Level 5)
  ciris-verify list-manifests List available manifests for a version
  ciris-verify info           Show system capabilities
  ciris-verify attest         Run full attestation (all levels)

  Use --help with any command for detailed options.

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
    println!("  Target: {}", current_target());
    println!();

    // Crypto capabilities
    println!("Cryptographic Capabilities:");
    println!("  Classical Signatures: Ed25519, ECDSA P-256");
    println!("  Post-Quantum Signatures: ML-DSA-65 (FIPS 204)");
    println!("  Signature Binding: PQC covers (data || classical_sig)");
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

    // Registry info
    println!("Registry Endpoints:");
    println!("  API: https://api.registry.ciris-services-1.ai");
    println!("  DNS US: us.registry.ciris-services-1.ai");
    println!("  DNS EU: eu.registry.ciris-services-1.ai");
    println!();

    // Features
    println!("Verification Features:");
    println!("  - Binary self-verification (Level 2)");
    println!("  - Multi-source consensus (Level 3)");
    println!("  - Agent file integrity (Level 4)");
    println!("  - Audit trail verification (Level 5)");
    println!("  - FFI function integrity (runtime)");
}

async fn run_function_check(registry_url: &str, show_details: bool, json: bool) {
    if !json {
        println!("\nFUNCTION INTEGRITY CHECK");
        println!("========================\n");
        println!("Verifies FFI export functions against registry manifest.");
        println!("This is runtime verification - hashes computed from memory.\n");
    }

    let target = current_target();
    let version = VERSION;

    if !json {
        println!("Configuration:");
        println!("  Target: {}", target);
        println!("  Version: {}", version);
        println!("  Registry: {}", registry_url);
        println!();
    }

    // Fetch function manifest
    let client = match RegistryClient::new(registry_url, Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Registry client error: {}", e);
            }
            return;
        },
    };

    match client.get_function_manifest(version, target).await {
        Ok(manifest) => {
            if json {
                let output = serde_json::json!({
                    "status": "fetched",
                    "version": manifest.binary_version,
                    "target": manifest.target,
                    "function_count": manifest.functions.len(),
                    "binary_hash": manifest.binary_hash,
                    "generated_at": manifest.generated_at,
                    "signature": {
                        "classical_algorithm": manifest.signature.classical_algorithm,
                        "pqc_algorithm": manifest.signature.pqc_algorithm,
                        "key_id": manifest.signature.key_id,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                println!("\x1b[32m[OK]\x1b[0m Function manifest fetched successfully\n");
                println!("Manifest Details:");
                println!("  Version: {}", manifest.binary_version);
                println!("  Target: {}", manifest.target);
                println!("  Functions: {}", manifest.functions.len());
                println!("  Binary Hash: {}...", &manifest.binary_hash[..20]);
                println!("  Generated: {}", manifest.generated_at);
                println!();
                println!("Signature:");
                println!(
                    "  Classical: {} ({})",
                    manifest.signature.classical_algorithm,
                    if manifest.signature.classical.is_empty() {
                        "missing"
                    } else {
                        "present"
                    }
                );
                println!(
                    "  PQC: {} ({})",
                    manifest.signature.pqc_algorithm,
                    if manifest.signature.pqc.is_empty() {
                        "missing"
                    } else {
                        "present"
                    }
                );
                println!("  Key ID: {}", manifest.signature.key_id);

                if show_details {
                    println!();
                    println!("Functions (SECURITY NOTE: normally opaque):");
                    for (name, entry) in &manifest.functions {
                        println!("  {} @ 0x{:x} ({} bytes)", name, entry.offset, entry.size);
                    }
                }

                println!();
                println!("NOTE: Full runtime verification requires the FFI library context.");
                println!("Use the Python SDK or FFI for actual integrity verification.");
            }
        },
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!(
                    "\x1b[33m[WARN]\x1b[0m Could not fetch function manifest: {}",
                    e
                );
                println!();
                println!("The registry may not have a function manifest for this version/target.");
                println!(
                    "Route required: GET /v1/verify/function-manifest/{}/{}",
                    version, target
                );
            }
        },
    }
}

async fn run_agent_files_check(
    version: &str,
    agent_root: &str,
    registry_url: &str,
    spot_check: bool,
    sample_size: usize,
    json: bool,
) {
    if !json {
        println!("\nAGENT FILE INTEGRITY CHECK (Level 4)");
        println!("=====================================\n");
        println!("Verifies agent files against registry manifest.\n");
    }

    let root_path = Path::new(agent_root);
    if !root_path.exists() {
        if json {
            println!(
                r#"{{"status":"error","message":"Agent root not found: {}"}}"#,
                agent_root
            );
        } else {
            println!(
                "\x1b[31m[ERROR]\x1b[0m Agent root not found: {}",
                agent_root
            );
        }
        return;
    }

    if !json {
        println!("Configuration:");
        println!("  Agent Version: {}", version);
        println!("  Agent Root: {}", agent_root);
        println!("  Registry: {}", registry_url);
        println!(
            "  Mode: {}",
            if spot_check {
                format!("Spot check ({} files)", sample_size)
            } else {
                "Full check".to_string()
            }
        );
        println!();
    }

    // Fetch file manifest from registry
    let client = match RegistryClient::new(registry_url, Duration::from_secs(30)) {
        Ok(c) => c,
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Registry client error: {}", e);
            }
            return;
        },
    };

    match client.get_build_by_version(version).await {
        Ok(build) => {
            if !json {
                println!("\x1b[32m[OK]\x1b[0m Build manifest fetched");
                println!("  Build ID: {}", build.build_id);
                println!("  Files in manifest: {}", build.file_manifest_count);
                println!();
            }

            // Convert registry manifest to file integrity manifest
            let manifest = AgentFileManifest {
                version: build.version.clone(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                files: build
                    .file_manifest_json
                    .files()
                    .iter()
                    .map(|(k, v): (&String, &String)| (k.clone(), v.clone()))
                    .collect(),
                manifest_hash: build.file_manifest_hash.clone(),
            };

            let result = if spot_check {
                check_spot(&manifest, root_path, sample_size)
            } else {
                check_full(&manifest, root_path)
            };

            if json {
                let output = serde_json::json!({
                    "status": if result.integrity_valid { "pass" } else { "fail" },
                    "total_files": result.total_files,
                    "files_checked": result.files_checked,
                    "files_passed": result.files_passed,
                    "files_failed": result.files_failed,
                    "files_missing": result.files_missing,
                    "files_unexpected": result.files_unexpected,
                    "failure_reason": result.failure_reason,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                let status = if result.integrity_valid {
                    "\x1b[32m[PASS]\x1b[0m"
                } else {
                    "\x1b[31m[FAIL]\x1b[0m"
                };
                println!("{} File integrity check", status);
                println!();
                println!("Results:");
                println!("  Total files in manifest: {}", result.total_files);
                println!("  Files checked: {}", result.files_checked);
                println!("  Files passed: {}", result.files_passed);
                println!("  Files failed: {}", result.files_failed);
                println!("  Files missing: {}", result.files_missing);
                println!("  Unexpected files: {}", result.files_unexpected);

                if !result.failure_reason.is_empty() {
                    println!();
                    println!("Failure reason: {}", result.failure_reason);
                }
            }
        },
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!(
                    "\x1b[31m[ERROR]\x1b[0m Could not fetch build manifest: {}",
                    e
                );
                println!();
                println!("Route required: GET /v1/builds/{}", version);
            }
        },
    }
}

fn run_audit_trail_check(
    db_path: Option<&str>,
    jsonl_path: Option<&str>,
    portal_key_id: Option<String>,
    spot_check: bool,
    sample_size: usize,
    json: bool,
) {
    if db_path.is_none() && jsonl_path.is_none() {
        if json {
            println!(
                r#"{{"status":"error","message":"No audit source provided. Use --db-path or --jsonl-path"}}"#
            );
        } else {
            println!("\x1b[31m[ERROR]\x1b[0m No audit source provided.");
            println!();
            println!("Usage:");
            println!("  ciris-verify audit-trail --db-path /path/to/ciris_audit.db");
            println!("  ciris-verify audit-trail --jsonl-path /path/to/audit_logs.jsonl");
        }
        return;
    }

    if !json {
        println!("\nAUDIT TRAIL VERIFICATION (Level 5)");
        println!("===================================\n");
        println!("Verifies the cryptographic hash chain of the audit log.\n");
    }

    // Read entries from source
    let entries = if let Some(db) = db_path {
        if !json {
            println!("Reading from SQLite: {}", db);
        }
        match read_audit_from_sqlite(db) {
            Ok(e) => e,
            Err(e) => {
                if json {
                    println!(r#"{{"status":"error","message":"{}"}}"#, e);
                } else {
                    println!("\x1b[31m[ERROR]\x1b[0m {}", e);
                }
                return;
            },
        }
    } else if let Some(jsonl) = jsonl_path {
        if !json {
            println!("Reading from JSONL: {}", jsonl);
        }
        match read_audit_from_jsonl(jsonl) {
            Ok(e) => e,
            Err(e) => {
                if json {
                    println!(r#"{{"status":"error","message":"{}"}}"#, e);
                } else {
                    println!("\x1b[31m[ERROR]\x1b[0m {}", e);
                }
                return;
            },
        }
    } else {
        return;
    };

    if !json {
        println!("  Entries loaded: {}", entries.len());
        println!(
            "  Mode: {}",
            if spot_check {
                format!("Spot check ({} entries)", sample_size)
            } else {
                "Full verification".to_string()
            }
        );
        println!();
    }

    let verifier = AuditVerifier::new(portal_key_id);
    let result = if spot_check {
        verifier.verify_spot_check(&entries, sample_size, 42)
    } else {
        verifier.verify_entries(&entries, true)
    };

    if json {
        let output = serde_json::json!({
            "status": if result.valid { "pass" } else { "fail" },
            "total_entries": result.total_entries,
            "entries_verified": result.entries_verified,
            "hash_chain_valid": result.hash_chain_valid,
            "genesis_valid": result.genesis_valid,
            "portal_key_used": result.portal_key_used,
            "first_tampered_sequence": result.first_tampered_sequence,
            "verification_time_ms": result.verification_time_ms,
            "chain_summary": result.chain_summary,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        let status = if result.valid {
            "\x1b[32m[PASS]\x1b[0m"
        } else {
            "\x1b[31m[FAIL]\x1b[0m"
        };
        println!("{} Audit trail verification", status);
        println!();
        println!("Results:");
        println!("  Total entries: {}", result.total_entries);
        println!("  Entries verified: {}", result.entries_verified);
        println!(
            "  Hash chain valid: {}",
            if result.hash_chain_valid { "Yes" } else { "NO" }
        );
        println!(
            "  Genesis valid: {}",
            if result.genesis_valid { "Yes" } else { "NO" }
        );
        println!(
            "  Portal key used: {}",
            if result.portal_key_used { "Yes" } else { "No" }
        );
        println!("  Verification time: {}ms", result.verification_time_ms);

        if let Some(seq) = result.first_tampered_sequence {
            println!();
            println!(
                "\x1b[31m[ALERT]\x1b[0m First tampering detected at sequence: {}",
                seq
            );
        }

        if let Some(ref summary) = result.chain_summary {
            println!();
            println!("Chain Summary:");
            println!(
                "  Sequence range: {} - {}",
                summary.sequence_range.0, summary.sequence_range.1
            );
            println!(
                "  Current hash: {}...",
                &summary.current_hash[..20.min(summary.current_hash.len())]
            );
            if let Some(ref oldest) = summary.oldest_entry {
                println!("  Oldest entry: {}", oldest);
            }
            if let Some(ref newest) = summary.newest_entry {
                println!("  Newest entry: {}", newest);
            }
        }

        if !result.errors.is_empty() {
            println!();
            println!("Errors:");
            for err in &result.errors[..result.errors.len().min(5)] {
                println!("  - {}", err);
            }
            if result.errors.len() > 5 {
                println!("  ... and {} more", result.errors.len() - 5);
            }
        }
    }
}

async fn run_list_manifests(version: &str, registry_url: &str, json: bool) {
    if !json {
        println!("\nAVAILABLE MANIFESTS");
        println!("===================\n");
        println!(
            "Checking registry for manifests at version {}...\n",
            version
        );
    }

    let client = match RegistryClient::new(registry_url, Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Registry client error: {}", e);
            }
            return;
        },
    };

    let target = current_target();

    // Check binary manifest
    let binary_status = match client.get_binary_manifest(version).await {
        Ok(m) => format!("Available ({} targets)", m.binaries.len()),
        Err(_) => "Not found".to_string(),
    };

    // Check file manifest (build record)
    let file_status = match client.get_build_by_version(version).await {
        Ok(b) => format!("Available ({} files)", b.file_manifest_count),
        Err(_) => "Not found".to_string(),
    };

    // Check function manifest for current target
    let function_status = match client.get_function_manifest(version, target).await {
        Ok(m) => format!("Available ({} functions)", m.functions.len()),
        Err(_) => "Not found for this target".to_string(),
    };

    // List all available function manifest targets
    let available_targets = match client.list_function_manifest_targets(version).await {
        Ok(t) => t.targets,
        Err(_) => vec![],
    };

    if json {
        let output = serde_json::json!({
            "version": version,
            "current_target": target,
            "manifests": {
                "binary": binary_status,
                "file": file_status,
                "function": function_status,
            },
            "available_function_targets": available_targets,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("Version: {}", version);
        println!("Current Target: {}", target);
        println!();
        println!("Manifest Status:");
        println!("  Binary Manifest:   {}", binary_status);
        println!("  File Manifest:     {}", file_status);
        println!("  Function Manifest: {}", function_status);

        if !available_targets.is_empty() {
            println!();
            println!("Available Function Manifest Targets:");
            for t in &available_targets {
                let marker = if t == target { " (current)" } else { "" };
                println!("  - {}{}", t, marker);
            }
        }

        println!();
        println!("Registry Routes:");
        println!("  Binary:   GET /v1/verify/binary-manifest/{}", version);
        println!("  File:     GET /v1/builds/{}", version);
        println!(
            "  Function: GET /v1/verify/function-manifest/{}/{}",
            version, target
        );
        println!("  Targets:  GET /v1/verify/function-manifests/{}", version);
    }
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
            .with_max_level(tracing::Level::INFO)
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
        Some(Commands::FunctionCheck {
            registry,
            show_details,
        }) => {
            if !json_output {
                print_banner();
            }
            run_function_check(&registry, show_details, json_output).await;
        },
        Some(Commands::AgentFiles {
            version,
            agent_root,
            registry,
            spot_check,
            sample_size,
        }) => {
            if !json_output {
                print_banner();
            }
            run_agent_files_check(
                &version,
                &agent_root,
                &registry,
                spot_check,
                sample_size,
                json_output,
            )
            .await;
        },
        Some(Commands::AuditTrail {
            db_path,
            jsonl_path,
            portal_key_id,
            spot_check,
            sample_size,
        }) => {
            if !json_output {
                print_banner();
            }
            run_audit_trail_check(
                db_path.as_deref(),
                jsonl_path.as_deref(),
                portal_key_id,
                spot_check,
                sample_size,
                json_output,
            );
        },
        Some(Commands::ListManifests { version, registry }) => {
            if !json_output {
                print_banner();
            }
            run_list_manifests(&version, &registry, json_output).await;
        },
        None => {
            // No command - show help
            print_banner();
            print_explanation();
        },
    }
}
