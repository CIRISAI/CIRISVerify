//! CIRISVerify CLI - Hardware-rooted license verification for CIRIS agents.
//!
//! This binary provides a command-line interface to run CIRISVerify checks
//! and display attestation results.

use std::path::Path;
use std::time::Duration;

use ciris_verify_core::audit::{read_audit_from_jsonl, read_audit_from_sqlite, AuditVerifier};
use ciris_verify_core::config::{TrustModel, VerifyConfig};
use ciris_verify_core::registry::{compute_self_hash, current_target, RegistryClient};
use ciris_verify_core::security::file_integrity::{
    check_full, check_spot, FileManifest as AgentFileManifest,
};
use ciris_verify_core::unified::{FullAttestationRequest, UnifiedAttestationEngine};
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

        /// CIRIS primitive project under which the agent's build is registered.
        /// Independent of `--project` (which scopes the engine's own L1/L2
        /// self-attestation reads). v1.12.0+ supports both projects in one
        /// verify cycle from a single client (closes #10).
        #[arg(long, default_value = "ciris-agent")]
        agent_project: String,

        /// CIRIS primitive project for the engine's own L1/L2 self-verify.
        /// Typically `ciris-verify`. v1.12.0+ — see `--agent-project`.
        #[arg(long, default_value = "ciris-verify")]
        project: String,

        /// Registry API endpoint
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
        registry: String,
    },

    /// Verify this binary's integrity against registry (Level 2)
    SelfCheck {
        /// Registry API endpoint
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
        registry: String,

        /// CIRIS primitive project to query (kebab-case). Required since
        /// v1.11.0.
        #[arg(long, default_value = "ciris-verify")]
        project: String,
    },

    /// Verify FFI function integrity against registry manifest
    FunctionCheck {
        /// Registry API endpoint
        #[arg(long, default_value = "https://api.registry.ciris-services-1.ai")]
        registry: String,

        /// Show individual function details (normally opaque for security)
        #[arg(long)]
        show_details: bool,

        /// CIRIS primitive project to query (kebab-case). Required since
        /// v1.11.0.
        #[arg(long, default_value = "ciris-verify")]
        project: String,
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

        /// CIRIS primitive project to query (kebab-case). Required since
        /// v1.11.0. For agent file verification this is typically
        /// `ciris-agent`.
        #[arg(long, default_value = "ciris-agent")]
        project: String,
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

        /// CIRIS primitive project to query (kebab-case). Required since
        /// v1.11.0.
        #[arg(long, default_value = "ciris-verify")]
        project: String,
    },

    /// Inspect / sign with a PKCS#11 hardware token (YubiKey PIV, OpenSC).
    ///
    /// The federation owner-binding's classical half (Ed25519) can be
    /// custodied on a token (CIRISVerify#80). Requires a build with
    /// `--features pkcs11` and a physical token.
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    /// Federation identity — create your hardware-rooted federation ID and drop
    /// the signed CEG object in the outbox for CIRISServer to relay.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
}

/// `ciris-verify identity` actions.
#[derive(Subcommand)]
enum IdentityAction {
    /// Create a self-signed genesis federation key record — Ed25519 rooted in a
    /// PKCS#11 token (YubiKey PIV) + a software ML-DSA-65 half — and write it to
    /// `~/ciris/ceg/outbox/federation_key_record/<key_id>.json`. CIRISServer
    /// drains the outbox, verifies, and relays it over CEG.
    Create {
        /// Path to the PKCS#11 module (`libykcs11.so` / `opensc-pkcs11.so`).
        #[arg(long)]
        module: String,
        /// Token slot index. Default 0.
        #[arg(long, default_value = "0")]
        slot: usize,
        /// `CKA_LABEL` of the Ed25519 signing key (e.g. PIV slot 9c).
        #[arg(long)]
        key_label: Option<String>,
        /// `CKA_ID` of the key as hex (alternative to `--key-label`).
        #[arg(long)]
        key_id: Option<String>,
        /// CEG `identity_type` (`user` | `agent`). Default `user`.
        #[arg(long, default_value = "user")]
        identity_type: String,
        /// Override the derived federation `key_id` (default: `sha256(ed_pubkey)` hex).
        #[arg(long)]
        fed_key_id: Option<String>,
        /// Prompt for the token user PIN (a token requires login to sign).
        #[arg(long)]
        pin: bool,
        /// Auto-provision an Ed25519 key in the PIV slot via `ykman` if the slot
        /// is empty (YubiKey only). Generates the key + a self-signed cert with
        /// the touch/PIN policy below, then proceeds. A populated slot is never
        /// overwritten.
        #[arg(long)]
        provision: bool,
        /// PIV slot to provision (with `--provision`). Default `9c` (Digital
        /// Signature). ykcs11 maps `9c` to label "Private key for Digital Signature".
        #[arg(long, default_value = "9c")]
        piv_slot: String,
        /// Touch policy for the provisioned key (`always` | `cached` | `never`).
        #[arg(long, default_value = "always")]
        touch_policy: String,
        /// PIN policy for the provisioned key (`once` | `always` | `never`).
        #[arg(long, default_value = "once")]
        pin_policy: String,
        /// PIV management key for provisioning (hex). Defaults to the factory key.
        #[arg(
            long,
            default_value = "010203040506070801020304050607080102030405060708"
        )]
        management_key: String,
    },
}

/// `ciris-verify token` actions.
#[derive(Subcommand)]
enum TokenAction {
    /// List the token's slots and key objects — discover the `CKA_LABEL` /
    /// `CKA_ID` and confirm a key is Ed25519 (federation-usable).
    Probe {
        /// Path to the PKCS#11 module (`libykcs11.so` / `opensc-pkcs11.so`).
        #[arg(long)]
        module: String,
        /// Token slot index (into the tokens-present list). Default 0.
        #[arg(long, default_value = "0")]
        slot: usize,
        /// Prompt for the user PIN (needed to list private-key objects).
        #[arg(long)]
        pin: bool,
    },

    /// Sign a test preimage on the token and verify it — proves the token can
    /// custody the federation owner-binding key end-to-end.
    SignTest {
        /// Path to the PKCS#11 module.
        #[arg(long)]
        module: String,
        /// Token slot index. Default 0.
        #[arg(long, default_value = "0")]
        slot: usize,
        /// `CKA_LABEL` of the key to sign with (one of `--key-label`/`--key-id`).
        #[arg(long)]
        key_label: Option<String>,
        /// `CKA_ID` of the key as hex (alternative to `--key-label`).
        #[arg(long)]
        key_id: Option<String>,
        /// Prompt for the user PIN (a token requires login to sign).
        #[arg(long)]
        pin: bool,
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
THE DMV FOR AI AGENTS
=====================

DISCLAIMER: This is research software exploring approaches to AI agent
verification. It is NOT a complete security solution. No software provides
absolute protection. Use at your own risk. See LICENSE for details.

Every car needs a license, inspection, and insurance to drive legally.
Every CIRIS agent needs the same:

  DRIVER'S LICENSE    Hardware-bound signing key - unforgeable identity
  VEHICLE INSPECTION  Binary + file integrity - no tampering since manufacture
  INSURANCE           License certificate - who's responsible if something goes wrong

CIRISVerify is the DMV that checks all three.

THE 5-POINT INSPECTION
======================

  Before trusting an agent, we run a progressive verification:

  Level 1: THE CAR STARTS
     CIRISVerify binary loaded and functional.
     If this fails, you see nothing - the binary didn't run.

  Level 2: IS THIS A REAL INSPECTION STATION?
     Before checking anything else, verify the verifier itself.
     SHA-256 hash of THIS binary checked against registry manifest.
     "Who watches the watchmen?"

     * Linux/Android: Finds itself via /proc/self/maps
     * macOS/iOS: Iterates dyld loaded images
     * Windows: Standard executable path

  Level 3: CHECK THREE DMV DATABASES
     Query 3 independent sources (DNS US, DNS EU, HTTPS API).
     2-of-3 must agree. If they disagree, possible attack.
     HTTPS is authoritative; DNS provides cross-checks.

  Level 4: FULL VEHICLE INSPECTION
     SHA-256 of every agent file against the build manifest.
     Tripwire-style: any modification = forced shutdown.
     One tampered byte = inspection failed.

  Level 5: COMPLETE SERVICE HISTORY
     Verify the cryptographic audit log from genesis.
     Unbroken hash chain + Portal-issued signing key.
     Full provenance of every action.

  CRITICAL: If ANY level fails, ALL higher levels are YELLOW (unverified).
  A fake inspection station could stamp everything "passed" regardless.

LIMITATIONS (NOT EXHAUSTIVE)
============================

  This software CANNOT protect against:
  - Fully compromised registry (attacker updates both binary and manifest)
  - Compromised initial install (malicious app store listing)
  - Sophisticated runtime attacks (hypervisor, hardware implants)
  - Bugs in this code or its dependencies
  - Determined adversaries with sufficient resources

  Partial mitigations we attempt (not guarantees):
  - Multi-source consensus (attacker needs 2+ sources)
  - Encourage trusted distribution channels
  - Constant-time comparisons (implementation may have flaws)

  This is research software. We make no security guarantees.

COMMANDS
========

  ciris-verify self-check     Is this inspection station certified? (Level 2)
  ciris-verify sources        Cross-check 3 DMV databases (Level 3)
  ciris-verify agent-files    Full vehicle inspection (Level 4)
  ciris-verify audit-trail    Review complete service history (Level 5)
  ciris-verify function-check Check individual inspection equipment
  ciris-verify list-manifests What records exist for this version?
  ciris-verify info           System capabilities
  ciris-verify attest         Run all levels

  Use --help with any command for detailed options.

DOCUMENTATION
=============

  docs/HOW_IT_WORKS.md              Overview of CIRISVerify
  docs/BINARY_SELF_VERIFICATION.md  How Level 2 works per platform
  docs/THREAT_MODEL.md              Security analysis

RESEARCH CONTEXT
================

  This software is part of ongoing AI alignment and safety research.
  It explores one approach to agent verification—not a complete solution.
  Contributions, criticism, and security reports are welcome.

  https://github.com/CIRISAI/CIRISVerify

  Licensed under AGPL-3.0. Provided AS-IS with NO WARRANTY.
"#
    );
}

async fn run_source_check(dns_us: &str, dns_eu: &str, https: &str, timeout_secs: u64, json: bool) {
    if !json {
        println!("\nCROSS-CHECK THREE DMV DATABASES (Level 3)");
        println!("==========================================\n");
        println!("Querying 3 independent registries. 2-of-3 must agree.\n");

        println!("Sources:");
        println!("  DNS US:  {}", dns_us);
        println!("  DNS EU:  {}", dns_eu);
        println!("  HTTPS:   {} (authoritative)", https);
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

async fn run_self_check(registry_url: &str, project: &str, json: bool) {
    if !json {
        println!("\nIS THIS INSPECTION STATION CERTIFIED? (Level 2)");
        println!("================================================\n");
        println!("Before trusting any inspection results, verify the inspector.");
        println!("We hash THIS binary and check it against the official registry.\n");
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

    match client.get_binary_manifest(project, VERSION).await {
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
                    println!("\x1b[32m[PASS]\x1b[0m Binary hash matches registry");
                    println!();
                    println!("Hash matches the registry manifest for this version/platform.");
                    println!("This suggests (but does not guarantee) the binary is unmodified.");
                } else {
                    println!("\x1b[31m[FAIL]\x1b[0m Inspection station NOT certified!");
                    println!();
                    println!("  Expected: {}", expected);
                    println!("  Actual:   {}", self_hash);
                    println!();
                    println!("WARNING: This binary may have been tampered with.");
                    println!("All inspection results from this station are SUSPECT.");
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
    println!("  DNS EU: eu.registry.ciris-services-eu-1.com");
    println!();

    // Features
    println!("Verification Features:");
    println!("  - Binary self-verification (Level 2)");
    println!("  - Multi-source consensus (Level 3)");
    println!("  - Agent file integrity (Level 4)");
    println!("  - Audit trail verification (Level 5)");
    println!("  - FFI function integrity (runtime)");
}

async fn run_function_check(registry_url: &str, project: &str, show_details: bool, json: bool) {
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

    match client.get_function_manifest(project, version, target).await {
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
    project: &str,
    spot_check: bool,
    sample_size: usize,
    json: bool,
) {
    if !json {
        println!("\nFULL VEHICLE INSPECTION (Level 4)");
        println!("==================================\n");
        println!("Checking every component against the factory manifest.");
        println!("One modified byte = inspection failed.\n");
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

    match client.get_build_by_version(project, version).await {
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
        println!("\nCOMPLETE SERVICE HISTORY CHECK (Level 5)");
        println!("=========================================\n");
        println!("Verifying unbroken chain from genesis. No gaps allowed.\n");
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

/// Run a full unified attestation through `UnifiedAttestationEngine`.
///
/// This exercises the full end-to-end verify path including the cross-project
/// agent build fetch — same engine instance reads its OWN L1/L2 manifests
/// under `--project` AND the agent's L4 build under `--agent-project`.
///
/// Used in the post-release CI gate as the #10 regression lock against the
/// live registry.
async fn run_attest(
    version: Option<&str>,
    agent_root: Option<&str>,
    agent_project: &str,
    project: &str,
    registry_url: &str,
    json: bool,
) {
    if !json {
        println!("\nFULL ATTESTATION (Levels 1-5)");
        println!("=============================\n");
        println!("Engine project (self):  {}", project);
        println!("Agent project (target): {}", agent_project);
        println!("Registry:               {}", registry_url);
        if let Some(v) = version {
            println!("Agent version:          {}", v);
        }
        if let Some(r) = agent_root {
            println!("Agent root:             {}", r);
        }
        println!();
    }

    // Construct a config matching CLI flags. Reuse VerifyConfig::default()'s
    // DNS hosts + cert pin, but override project + endpoint from flags.
    let config = VerifyConfig {
        project: project.to_string(),
        https_endpoint: registry_url.to_string(),
        ..VerifyConfig::default()
    };

    let engine = match UnifiedAttestationEngine::new(config) {
        Ok(e) => e,
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Failed to initialize engine: {}", e);
            }
            return;
        },
    };

    // Generate a 32-byte challenge nonce — required by FullAttestationRequest.
    use rand::RngCore;
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    let request = FullAttestationRequest {
        challenge,
        agent_version: version.map(String::from),
        agent_root: agent_root.map(String::from),
        spot_check_count: 0,
        audit_entries: None,
        portal_key_id: None,
        skip_registry: false,
        skip_file_integrity: agent_root.is_none(),
        skip_audit: true,
        key_fingerprint: None,
        partial_file_check: false,
        python_hashes: None,
        expected_python_hash: None,
        agent_project: Some(agent_project.to_string()),
    };

    match engine.run_attestation(request).await {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            } else {
                let level = result.level;
                let valid = result.valid;
                println!(
                    "{} level = {} (valid={}) — checks {}/{}",
                    if valid {
                        "\x1b[32m[PASS]\x1b[0m"
                    } else {
                        "\x1b[31m[FAIL]\x1b[0m"
                    },
                    level,
                    valid,
                    result.checks_passed,
                    result.checks_total,
                );
                if !result.errors.is_empty() {
                    println!("\nErrors:");
                    for e in &result.errors {
                        println!("  - {}", e);
                    }
                }
                println!();
                println!("Diagnostics:\n{}", result.diagnostics);
            }
        },
        Err(e) => {
            if json {
                println!(r#"{{"status":"error","message":"{}"}}"#, e);
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Attestation failed: {}", e);
            }
        },
    }
}

async fn run_list_manifests(version: &str, registry_url: &str, project: &str, json: bool) {
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
    let binary_status = match client.get_binary_manifest(project, version).await {
        Ok(m) => format!("Available ({} targets)", m.binaries.len()),
        Err(_) => "Not found".to_string(),
    };

    // Check file manifest (build record)
    let file_status = match client.get_build_by_version(project, version).await {
        Ok(b) => format!("Available ({} files)", b.file_manifest_count),
        Err(_) => "Not found".to_string(),
    };

    // Check function manifest for current target
    let function_status = match client.get_function_manifest(project, version, target).await {
        Ok(m) => format!("Available ({} functions)", m.functions.len()),
        Err(_) => "Not found for this target".to_string(),
    };

    // List all available function manifest targets
    let available_targets = match client
        .list_function_manifest_targets(project, version)
        .await
    {
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

/// Enable ANSI escape sequence processing on Windows consoles so the CLI's
/// colored output renders instead of printing raw `ESC[31m` garbage. No-op on
/// other platforms and harmless when stdout/stderr aren't a tty.
#[cfg(target_os = "windows")]
fn enable_windows_ansi() {
    const STD_OUTPUT_HANDLE: i32 = -11;
    const STD_ERROR_HANDLE: i32 = -12;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = usize::MAX as *mut _;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(nStdHandle: i32) -> *mut std::ffi::c_void;
        fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
    }

    unsafe fn enable_for(handle_id: i32) {
        let h = GetStdHandle(handle_id);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return;
        }
        let mut mode: u32 = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            // Not a console (redirected to file/pipe); leave untouched.
            return;
        }
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    unsafe {
        enable_for(STD_OUTPUT_HANDLE);
        enable_for(STD_ERROR_HANDLE);
    }
}

#[cfg(not(target_os = "windows"))]
fn enable_windows_ansi() {}

// ===========================================================================
// `token` — PKCS#11 hardware-token (YubiKey PIV / OpenSC) support (#80)
// ===========================================================================

/// Resolve the token user PIN, or `None` when not requested. Prefers the
/// `CIRIS_PKCS11_PIN` env var (automation / no-TTY), falling back to a hidden
/// interactive prompt. The hidden prompt needs `rpassword`, which is only
/// compiled under `pkcs11`.
#[cfg(feature = "pkcs11")]
fn prompt_pin(enabled: bool) -> Option<String> {
    if !enabled {
        return None;
    }
    if let Ok(pin) = std::env::var("CIRIS_PKCS11_PIN") {
        return Some(pin);
    }
    match rpassword::prompt_password("Token user PIN: ") {
        Ok(pin) => Some(pin),
        Err(e) => {
            eprintln!("⚠️  could not read PIN: {e}");
            None
        },
    }
}

#[cfg(not(feature = "pkcs11"))]
fn prompt_pin(_enabled: bool) -> Option<String> {
    None
}

/// Decode a lowercase/uppercase hex string (the `--key-id` form) to bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err("hex string must have an even number of digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Fail fast with an actionable message when a token command runs on a build
/// that wasn't compiled with the `pkcs11` feature (otherwise the failure
/// surfaces deep in the keyring as an opaque `NotSupported`, and `--pin` is
/// silently dropped).
#[cfg(not(feature = "pkcs11"))]
fn require_pkcs11_feature() {
    eprintln!("❌ this command needs PKCS#11 (YubiKey) support, which is not in this build.");
    eprintln!("   Rebuild with the feature, then re-run:");
    eprintln!("     cargo build --release -p ciris-verify-core --features pkcs11");
    std::process::exit(3);
}

#[cfg(feature = "pkcs11")]
fn require_pkcs11_feature() {}

async fn run_token(action: TokenAction, json_output: bool) {
    require_pkcs11_feature();
    match action {
        TokenAction::Probe { module, slot, pin } => {
            run_token_probe(&module, slot, pin, json_output);
        },
        TokenAction::SignTest {
            module,
            slot,
            key_label,
            key_id,
            pin,
        } => {
            run_token_sign_test(&module, slot, key_label, key_id, pin, json_output).await;
        },
    }
}

fn run_token_probe(module: &str, slot: usize, pin: bool, json_output: bool) {
    use ciris_keyring::pkcs11::{probe_pkcs11, Pkcs11Config};

    let cfg = Pkcs11Config {
        module_path: module.into(),
        user_pin: prompt_pin(pin),
        key_label: None,
        key_id: None,
        slot_index: slot,
    };

    let probe = match probe_pkcs11(&cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ probe failed: {e}");
            std::process::exit(1);
        },
    };

    if json_output {
        let tokens: Vec<_> = probe
            .tokens
            .iter()
            .map(|t| {
                serde_json::json!({
                    "slot_index": t.slot_index,
                    "manufacturer": t.manufacturer,
                    "model": t.model,
                    "serial": t.serial,
                    "label": t.label,
                })
            })
            .collect();
        let keys: Vec<_> = probe
            .keys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "class": k.class,
                    "label": k.label,
                    "id_hex": k.id_hex,
                    "key_type": k.key_type,
                    "ciris_algorithm": k.ciris_algorithm.map(|a| format!("{a:?}")),
                    "federation_usable": k.ciris_algorithm.is_some(),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "tokens": tokens, "keys": keys }));
        return;
    }

    println!("🔑 PKCS#11 token probe ({module})\n");
    if probe.tokens.is_empty() {
        println!("  (no token present)");
        return;
    }
    for t in &probe.tokens {
        let sel = if t.slot_index == slot {
            " ◀ selected"
        } else {
            ""
        };
        println!("  slot[{}]{sel}", t.slot_index);
        println!("    manufacturer : {}", t.manufacturer);
        println!("    model        : {}", t.model);
        println!("    serial       : {}", t.serial);
        println!("    label        : {}", t.label);
    }
    println!("\n  Key objects in slot[{slot}]:");
    if probe.keys.is_empty() {
        println!("    (none visible — private keys need --pin to list)");
    }
    for k in &probe.keys {
        let fed = match k.ciris_algorithm {
            Some(ciris_keyring::ClassicalAlgorithm::Ed25519) => {
                "Ed25519 ✅ federation owner-binding"
            },
            Some(ciris_keyring::ClassicalAlgorithm::EcdsaP256) => {
                "P-256 ⚠️ (federation default is Ed25519)"
            },
            Some(_) => "(other)",
            None => "❌ not federation-usable",
        };
        println!(
            "    [{}] label={:?} id={} type={} → {fed}",
            k.class,
            k.label.as_deref().unwrap_or("<none>"),
            k.id_hex.as_deref().unwrap_or("<none>"),
            k.key_type,
        );
    }
}

async fn run_token_sign_test(
    module: &str,
    slot: usize,
    key_label: Option<String>,
    key_id: Option<String>,
    pin: bool,
    json_output: bool,
) {
    use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, P256Verifier};
    use ciris_keyring::pkcs11::{open_pkcs11_signer, Pkcs11Config};
    use ciris_keyring::ClassicalAlgorithm;

    let key_id_bytes = match key_id.as_deref().map(parse_hex).transpose() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ --key-id is not valid hex: {e}");
            std::process::exit(2);
        },
    };

    let cfg = Pkcs11Config {
        module_path: module.into(),
        user_pin: prompt_pin(pin),
        key_label,
        key_id: key_id_bytes,
        slot_index: slot,
    };

    let signer = match open_pkcs11_signer("token-sign-test", &cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ open token signer: {e}");
            std::process::exit(1);
        },
    };

    // Same preimage the keyring live test uses — the owner-binding test vector.
    let msg = b"ciris owner-binding test preimage";
    let pubkey = match signer.public_key().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ read public key: {e}");
            std::process::exit(1);
        },
    };
    let sig = match signer.sign(msg).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ C_Sign on token: {e}");
            std::process::exit(1);
        },
    };

    let alg = signer.algorithm();
    let verified = match alg {
        ClassicalAlgorithm::Ed25519 => Ed25519Verifier::new()
            .verify(&pubkey, msg, &sig)
            .unwrap_or(false),
        ClassicalAlgorithm::EcdsaP256 => P256Verifier::new()
            .verify(&pubkey, msg, &sig)
            .unwrap_or(false),
        ClassicalAlgorithm::EcdsaP384 => false,
    };
    let federation_usable = matches!(alg, ClassicalAlgorithm::Ed25519);

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "algorithm": format!("{alg:?}"),
                "hardware_type": format!("{:?}", signer.hardware_type()),
                "public_key_len": pubkey.len(),
                "signature_len": sig.len(),
                "verified": verified,
                "federation_usable": federation_usable,
            })
        );
    } else {
        println!("🔏 YubiKey / PKCS#11 sign-test\n");
        println!("  algorithm        : {alg:?}");
        println!("  hardware type    : {:?}", signer.hardware_type());
        println!("  public key       : {} bytes", pubkey.len());
        println!("  signature        : {} bytes", sig.len());
        println!(
            "  on-token verify  : {}",
            if verified {
                "✅ VERIFIED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  federation key   : {}",
            if federation_usable {
                "✅ Ed25519 — usable as the owner-binding classical half"
            } else {
                "⚠️  not Ed25519 — federation owner-binding requires Ed25519"
            }
        );
        println!(
            "\n  {}",
            if verified {
                "The private key never left the token; the signature it produced \
                 verifies against the token's public key."
            } else {
                "Signature did NOT verify — check the key/slot/PIN."
            }
        );
    }

    if !verified {
        std::process::exit(1);
    }
}

// ===========================================================================
// `identity create` — hardware-rooted federation ID → CEG outbox (6.0)
// ===========================================================================

/// Bundled `identity create` inputs (keeps the handler signature sane).
struct IdentityCreateArgs {
    module: String,
    slot: usize,
    key_label: Option<String>,
    key_id: Option<String>,
    identity_type: String,
    fed_key_id: Option<String>,
    pin: bool,
    provision: bool,
    piv_slot: String,
    touch_policy: String,
    pin_policy: String,
    management_key: String,
}

async fn run_identity(action: IdentityAction, json_output: bool) {
    require_pkcs11_feature();
    match action {
        IdentityAction::Create {
            module,
            slot,
            key_label,
            key_id,
            identity_type,
            fed_key_id,
            pin,
            provision,
            piv_slot,
            touch_policy,
            pin_policy,
            management_key,
        } => {
            run_identity_create(
                IdentityCreateArgs {
                    module,
                    slot,
                    key_label,
                    key_id,
                    identity_type,
                    fed_key_id,
                    pin,
                    provision,
                    piv_slot,
                    touch_policy,
                    pin_policy,
                    management_key,
                },
                json_output,
            )
            .await;
        },
    }
}

async fn run_identity_create(args: IdentityCreateArgs, json_output: bool) {
    use std::sync::Arc;

    use ciris_keyring::pkcs11::{open_pkcs11_signer, Pkcs11Config};
    use ciris_verify_core::ceg_outbox::SignedCegObject;
    use ciris_verify_core::federation_identity::create_federation_identity;

    let key_id_bytes = match args.key_id.as_deref().map(parse_hex).transpose() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ --key-id is not valid hex: {e}");
            std::process::exit(2);
        },
    };
    let cfg = Pkcs11Config {
        module_path: args.module.clone().into(),
        user_pin: prompt_pin(args.pin),
        key_label: args.key_label.clone(),
        key_id: key_id_bytes,
        slot_index: args.slot,
    };

    // 1. Open the token's Ed25519 key. A populated slot is used as-is (never
    //    overwritten); only an EMPTY slot triggers `--provision`.
    let hw_signer = match open_pkcs11_signer("federation-identity", &cfg) {
        Ok(s) => s,
        Err(e) if args.provision => {
            eprintln!("ℹ️  no usable key in the slot ({e}); provisioning via ykman…");
            if let Err(pe) = provision_piv_via_ykman(
                &args.piv_slot,
                &args.touch_policy,
                &args.pin_policy,
                &args.management_key,
            ) {
                eprintln!("❌ provisioning failed: {pe}");
                std::process::exit(1);
            }
            match open_pkcs11_signer("federation-identity", &cfg) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ open token signer after provisioning: {e}");
                    std::process::exit(1);
                },
            }
        },
        Err(e) => {
            eprintln!("❌ open token signer: {e}");
            eprintln!(
                "   (pass --provision to generate an Ed25519 key in PIV slot {} via ykman)",
                args.piv_slot
            );
            std::process::exit(1);
        },
    };
    let hw_type = hw_signer.hardware_type();

    // 2. Produce the self-signed genesis identity (the Ed25519 half signs on the
    //    token — a touch-required key blocks here until you tap it).
    if !json_output {
        println!(
            "🔏 signing the genesis key record on the token — tap the YubiKey if it blinks…\n"
        );
    }
    let now = chrono::Utc::now().to_rfc3339();
    let created = match create_federation_identity(
        Arc::from(hw_signer),
        &args.identity_type,
        args.fed_key_id.clone(),
        &now,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ create federation identity: {e}");
            if format!("{e}").contains("Ed25519") {
                eprintln!("   (the PIV key must be Ed25519 — re-run with --provision, or `ykman piv keys generate --algorithm ED25519 {} ...`)", args.piv_slot);
            }
            std::process::exit(1);
        },
    };

    let path = match created.object.write_to_outbox(&created.key_id) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ write to CEG outbox: {e}");
            std::process::exit(1);
        },
    };

    // ensure `SignedCegObject` is referenced for the import even in json mode
    let _: &SignedCegObject = &created.object;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "key_id": created.key_id,
                "identity_type": args.identity_type,
                "hardware_type": format!("{hw_type:?}"),
                "outbox_path": path.display().to_string(),
            })
        );
    } else {
        println!("✅ federation identity created (self-signed, hardware-rooted)\n");
        println!("  key_id        : {}", created.key_id);
        println!("  identity_type : {}", args.identity_type);
        println!("  hardware      : {hw_type:?} (Ed25519 on token)");
        println!("  PQC half      : ML-DSA-65, seed sealed at rest under ~/ciris/keys (#71)");
        println!("  CEG object    : {}", path.display());
        println!(
            "\n  Next: ensure CIRISServer is draining this ~/ciris root. It verifies the bound\n  \
             hybrid self-signature and relays via register_key → federation_keys, then moves\n  \
             the object to ~/ciris/ceg/sent/.\n  \
             The ML-DSA-65 seed in ~/ciris/keys is sealed by your platform secure storage\n  \
             (TPM when built --features tpm; software-sealed otherwise). A TPM-sealed seed is\n  \
             bound to THIS machine — enroll a second device key (OR-of-N) for redundancy."
        );
    }
}

/// Provision an Ed25519 key + self-signed cert in a YubiKey PIV slot via
/// `ykman` (the PIV-applet management tool — PIV slot policy + the slot cert are
/// not PKCS#11 operations). `ykman` inherits the terminal, so it prompts for the
/// PIN and the cert step requires a physical touch. The management key defaults
/// to the factory value; the PIN is NOT passed on argv (ykman prompts).
fn provision_piv_via_ykman(
    piv_slot: &str,
    touch_policy: &str,
    pin_policy: &str,
    management_key: &str,
) -> Result<(), String> {
    let pub_tmp = std::env::temp_dir().join(format!("ciris_piv_{piv_slot}_pub.pem"));
    let pub_path = pub_tmp.to_string_lossy().into_owned();

    eprintln!("🛠  provisioning Ed25519 in PIV slot {piv_slot} (touch-policy={touch_policy}, pin-policy={pin_policy})…");
    run_ykman(&[
        "piv",
        "keys",
        "generate",
        "--algorithm",
        "ED25519",
        "--pin-policy",
        pin_policy,
        "--touch-policy",
        touch_policy,
        "-m",
        management_key,
        piv_slot,
        &pub_path,
    ])?;

    eprintln!(
        "   generating the slot certificate — enter your PIN and TAP the YubiKey when it blinks…"
    );
    run_ykman(&[
        "piv",
        "certificates",
        "generate",
        "--subject",
        "CN=ciris-federation",
        "-m",
        management_key,
        piv_slot,
        &pub_path,
    ])?;

    let _ = std::fs::remove_file(&pub_tmp);
    Ok(())
}

fn run_ykman(args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("ykman")
        .args(args)
        .status()
        .map_err(|e| format!("could not run `ykman` (is yubikey-manager installed?): {e}"))?;
    if !status.success() {
        return Err(format!(
            "`ykman {}` failed (exit {:?})",
            args.join(" "),
            status.code()
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    enable_windows_ansi();

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
            agent_project,
            project,
            registry,
        }) => {
            if !json_output {
                print_banner();
            }
            run_attest(
                version.as_deref(),
                agent_root.as_deref(),
                &agent_project,
                &project,
                &registry,
                json_output,
            )
            .await;
        },
        Some(Commands::SelfCheck { registry, project }) => {
            print_banner();
            run_self_check(&registry, &project, json_output).await;
        },
        Some(Commands::FunctionCheck {
            registry,
            show_details,
            project,
        }) => {
            if !json_output {
                print_banner();
            }
            run_function_check(&registry, &project, show_details, json_output).await;
        },
        Some(Commands::AgentFiles {
            version,
            agent_root,
            registry,
            spot_check,
            sample_size,
            project,
        }) => {
            if !json_output {
                print_banner();
            }
            run_agent_files_check(
                &version,
                &agent_root,
                &registry,
                &project,
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
        Some(Commands::ListManifests {
            version,
            registry,
            project,
        }) => {
            if !json_output {
                print_banner();
            }
            run_list_manifests(&version, &registry, &project, json_output).await;
        },
        Some(Commands::Token { action }) => {
            if !json_output {
                print_banner();
            }
            run_token(action, json_output).await;
        },
        Some(Commands::Identity { action }) => {
            if !json_output {
                print_banner();
            }
            run_identity(action, json_output).await;
        },
        None => {
            // No command - show help
            print_banner();
            print_explanation();
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ML-DSA-65 seed custody tests live with the logic in
    // `ciris_verify_core::federation_identity` (it's the shared CLI+FFI core now).

    #[test]
    fn parse_hex_round_trips() {
        assert_eq!(parse_hex("0a1b").unwrap(), vec![0x0a, 0x1b]);
        assert_eq!(parse_hex("0x0A1B").unwrap(), vec![0x0a, 0x1b]);
        assert!(parse_hex("abc").is_err(), "odd length rejected");
    }
}
