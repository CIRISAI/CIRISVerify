//! Physical-key validation harness for the accord custody gate (CIRISVerify#91).
//!
//! Runs a **real** YubiKey 5 FIPS PIV slot-9c attestation straight through
//! `verify_yubikey_piv_attestation` — the exact function the CIRISServer
//! admission gate calls — and prints what it extracted. This closes the
//! "byte-encodings cross-confirmed against a real device" gate that the unit
//! tests (rcgen mocks) cannot: it proves the documented Yubico extension
//! encodings + the SHA256-RSA attestation chain verify against an actual key.
//!
//! **Read-only.** This binary only reads cert files off disk. The capture
//! commands below are also read-only — `ykman piv keys attest` reads an
//! attestation statement for the key already in the slot; it does not create,
//! overwrite, or modify any slot, and never touches FIDO2/U2F/OATH.
//!
//! ## Capture the three certs (read-only)
//!
//! ```sh
//! # 1. The slot-9c attestation (signed inside the YubiKey by its f9 key):
//! ykman piv keys attest 9c 9c.pem
//! # 2. The device's f9 attestation-signing cert (carries the FIPS .10 ext):
//! ykman piv certificates export f9 f9.pem
//! # 3. The pinned Yubico PIV attestation root CA (one-time download):
//! curl -O https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
//! ```
//!
//! ## Run
//!
//! ```sh
//! cargo run -p ciris-verify-core --example validate_yubikey_attestation -- \
//!     9c.pem f9.pem piv-attestation-ca.pem [expected_ed25519_pubkey_base64]
//! ```
//!
//! `expected_ed25519_pubkey_base64` is optional — the holder's 32-byte
//! federation Ed25519 key, base64. If omitted, the harness reads the attested
//! key out of the 9c cert and prints it (the binding check then trivially
//! passes), so you can eyeball it; pass it to also exercise the binding gate.

use std::process::ExitCode;

use base64::Engine;
use ciris_verify_core::accord_custody_attestation::verify_yubikey_piv_attestation;
use x509_parser::prelude::*;

/// Accept either a PEM file (`-----BEGIN CERTIFICATE-----`) or raw DER, and
/// return DER bytes. `ykman` emits PEM; this keeps the harness paste-friendly.
fn read_cert_der(path: &str) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if raw.starts_with(b"-----BEGIN") {
        let text = String::from_utf8_lossy(&raw);
        let b64: String = text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| format!("decode PEM body of {path}: {e}"))
    } else {
        Ok(raw)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <9c.pem|der> <f9.pem|der> <yubico-root.pem|der> \
             [expected_ed25519_pubkey_base64]",
            args[0]
        );
        return ExitCode::from(2);
    }

    let der_9c = match read_cert_der(&args[1]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        },
    };
    let der_f9 = match read_cert_der(&args[2]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        },
    };
    let der_root = match read_cert_der(&args[3]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        },
    };

    // Resolve the expected attested key: the holder's pubkey if supplied, else
    // read it out of the 9c cert so chain/FIPS/touch are still validated and the
    // attested key is surfaced for eyeballing.
    let expected_ed: Vec<u8> = if let Some(b64) = args.get(4) {
        match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("error: decode expected pubkey: {e}");
                return ExitCode::from(2);
            },
        }
    } else {
        match X509Certificate::from_der(&der_9c) {
            Ok((_, c)) => {
                let k = c.public_key().subject_public_key.data.to_vec();
                println!(
                    "(no expected pubkey given — using the attested key from the 9c cert: {})",
                    base64::engine::general_purpose::STANDARD.encode(&k)
                );
                k
            },
            Err(e) => {
                eprintln!("error: parse 9c cert to read attested key: {e}");
                return ExitCode::from(2);
            },
        }
    };

    println!("\nRunning verify_yubikey_piv_attestation (the production gate)…\n");
    match verify_yubikey_piv_attestation(&der_9c, &der_f9, &der_root, &expected_ed) {
        Ok(v) => {
            println!("✅ ADMITTED — the chain, attested-key, and FIPS+touch floor all hold.");
            println!("   hardware_class : {}", v.hardware_class);
            println!("   firmware       : {}", v.firmware);
            println!(
                "   serial         : {}",
                v.serial
                    .map_or_else(|| "(none)".to_string(), |s| s.to_string())
            );
            println!("   fips_certified : {}", v.fips_certified);
            println!("   touch_always   : {}", v.touch_always);
            println!(
                "\nCross-check these against the physical key (firmware via `ykman info`, \n\
                 serial on the device body, touch policy via `ykman piv info`). If they \n\
                 match, the #91 byte-encodings are confirmed and the safe-mesh floor gate \n\
                 can close."
            );
            ExitCode::SUCCESS
        },
        Err(e) => {
            println!("❌ REJECTED — {e}");
            println!(
                "\nThis is the signal to inspect: a real key SHOULD admit. A rejection here \n\
                 means a byte-encoding still diverges from the device — most likely the \n\
                 touch-policy offset (.8), the FIPS .10 placement/payload (on f9), or the \n\
                 SHA256-RSA chain not verifying through x509-parser. Dump the raw certs with \n\
                 `openssl x509 -in 9c.pem -text -noout` and compare to the module's parsing."
            );
            ExitCode::FAILURE
        },
    }
}
