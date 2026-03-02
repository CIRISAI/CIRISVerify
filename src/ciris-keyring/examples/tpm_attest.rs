//! Quick TPM attestation test - exercises dual-key architecture.

use ciris_keyring::{platform::TpmSigner, HardwareSigner, PlatformAttestation};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() {
    // Enable debug output via env var: RUST_LOG=debug
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("debug"));
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    println!("Testing TPM dual-key attestation...\n");

    // Create TPM signer
    let signer = match TpmSigner::new("test_key", None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create TPM signer: {}", e);
            return;
        }
    };

    println!("TPM Hardware Type: {:?}", signer.hardware_type());
    println!("Algorithm: {:?}", signer.algorithm());

    // Test attestation without nonce
    println!("\n--- Testing attestation (no external nonce) ---");
    match signer.attestation().await {
        Ok(attest) => {
            println!("Attestation succeeded!");
            if let PlatformAttestation::Tpm(tpm) = &attest {
                println!("  TPM Version: {}", tpm.tpm_version);
                println!("  Manufacturer: {}", tpm.manufacturer);
                println!("  Discrete: {}", tpm.discrete);
                println!("  Quote present: {}", tpm.quote.is_some());
                println!("  EK Cert present: {}", tpm.ek_cert.is_some());
                println!("  AK Public Key present: {}", tpm.ak_public_key.is_some());
                if let Some(ref q) = tpm.quote {
                    println!("  Quote details:");
                    println!("    - Quoted len: {} bytes", q.quoted.len());
                    println!("    - Signature len: {} bytes", q.signature.len());
                    println!("    - Qualifying data len: {} bytes", q.qualifying_data.len());
                    println!("    - Timestamp: {}", q.timestamp);
                }
                if let Some(ref ak) = tpm.ak_public_key {
                    println!("  AK Public Key: {} bytes", ak.len());
                }
            }
        }
        Err(e) => {
            eprintln!("Attestation failed: {}", e);
        }
    }

    // Test attestation with external nonce
    println!("\n--- Testing attestation WITH external nonce ---");
    let nonce = b"test_challenge_from_registry_12345";
    match signer.attestation_with_nonce(Some(nonce)).await {
        Ok(attest) => {
            println!("Attestation with nonce succeeded!");
            if let PlatformAttestation::Tpm(tpm) = &attest {
                if let Some(ref q) = tpm.quote {
                    let nonce_matches = q.qualifying_data == nonce.to_vec();
                    println!("  Qualifying data matches input nonce: {}", nonce_matches);
                    println!("  Qualifying data: {:?}", String::from_utf8_lossy(&q.qualifying_data));
                }
            }
        }
        Err(e) => {
            eprintln!("Attestation with nonce failed: {}", e);
        }
    }

    println!("\nDone!");
}
