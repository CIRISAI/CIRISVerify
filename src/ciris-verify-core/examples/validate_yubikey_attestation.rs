//! Physical-key validation harness for the accord custody gate (CIRISVerify#91).
//!
//! Runs a **real** YubiKey 5 FIPS PIV slot-9c attestation straight through
//! `verify_yubikey_piv_attestation` — the exact function the CIRISServer
//! admission gate calls — and prints what it extracted. This closes the
//! "byte-encodings + chain cross-confirmed against a real device" gate that the
//! rcgen unit tests cannot.
//!
//! It path-builds the attestation chain (`f9 → [intermediates] → root`) out of a
//! trust bundle by signature, so it works with both the pre-fw-5.7 PKI (`f9 →
//! Yubico PIV Root CA Serial 263751`) and the 2024-12 PKI (`f9 → Yubico PIV
//! Attestation B 1 → Yubico Attestation Root 1`).
//!
//! **Read-only.** This binary only reads cert files off disk. The capture
//! commands below are also read-only — `ykman piv keys attest` reads an
//! attestation statement for the key already in the slot; it does not create,
//! overwrite, or modify any slot, and never touches FIDO2/U2F/OATH.
//!
//! ## Capture the inputs (read-only)
//!
//! ```sh
//! # 1. The slot-9c attestation (signed inside the YubiKey by its f9 key):
//! ykman piv keys attest 9c 9c.pem
//! # 2. The device's f9 attestation-signing cert (carries the FIPS .10 ext):
//! ykman piv certificates export f9 f9.pem
//! # 3. A trust bundle of Yubico intermediates + roots (one-time download):
//! curl -fL -o yubico-intermediate.pem https://developers.yubico.com/PKI/yubico-intermediate.pem
//! curl -fL -o yubico-ca-1.pem         https://developers.yubico.com/PKI/yubico-ca-1.pem
//! cat yubico-intermediate.pem yubico-ca-1.pem > yubico-trust.pem
//! ```
//!
//! ## Run
//!
//! ```sh
//! cargo run -p ciris-verify-core --example validate_yubikey_attestation -- \
//!     9c.pem f9.pem yubico-trust.pem [expected_ed25519_pubkey_base64]
//! ```
//!
//! `expected_ed25519_pubkey_base64` is optional — the holder's 32-byte
//! federation Ed25519 key, base64. If omitted, the harness reads the attested
//! key out of the 9c cert and prints it (the binding check then trivially
//! passes); pass it to also exercise the binding gate.

use std::process::ExitCode;

use base64::Engine;
use ciris_verify_core::accord_custody_attestation::verify_yubikey_piv_attestation;
use x509_parser::prelude::*;

/// Parse a file into one-or-more cert DERs (raw DER, a single PEM, or a PEM
/// bundle), returning a DER per `-----BEGIN CERTIFICATE-----` block.
fn read_certs_der(path: &str) -> Result<Vec<Vec<u8>>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if !raw.starts_with(b"-----BEGIN") {
        return Ok(vec![raw]); // single raw DER
    }
    let text = String::from_utf8_lossy(&raw);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            inside = true;
            cur.clear();
        } else if line.starts_with("-----END") {
            inside = false;
            let der = base64::engine::general_purpose::STANDARD
                .decode(cur.trim())
                .map_err(|e| format!("decode a PEM block of {path}: {e}"))?;
            out.push(der);
        } else if inside {
            cur.push_str(line.trim());
        }
    }
    if out.is_empty() {
        return Err(format!("no PEM certificate blocks found in {path}"));
    }
    Ok(out)
}

/// First cert DER from a file (the 9c / f9 inputs are always single certs).
fn read_cert_der(path: &str) -> Result<Vec<u8>, String> {
    Ok(read_certs_der(path)?.remove(0))
}

fn subject(der: &[u8]) -> String {
    match X509Certificate::from_der(der) {
        Ok((_, c)) => c.subject().to_string(),
        Err(_) => "<unparseable>".into(),
    }
}

fn is_self_signed(der: &[u8]) -> bool {
    matches!(
        X509Certificate::from_der(der),
        Ok((_, c)) if c.verify_signature(Some(c.public_key())).is_ok()
    )
}

/// Does `issuer_der`'s key verify `cert_der`'s signature?
fn signs(cert_der: &[u8], issuer_der: &[u8]) -> bool {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return false;
    };
    let Ok((_, issuer)) = X509Certificate::from_der(issuer_der) else {
        return false;
    };
    cert.verify_signature(Some(issuer.public_key())).is_ok()
}

/// Build `(chain_above_f9, root)` from f9 up through `bundle` by signature:
/// `chain = [f9, …intermediates…]` (excl. root), `root` is the self-signed top.
fn build_chain(f9_der: &[u8], bundle: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    let mut chain = vec![f9_der.to_vec()];
    for _ in 0..16 {
        let cur = chain.last().unwrap().clone();
        let issuer = bundle
            .iter()
            .find(|cand| cand.as_slice() != cur.as_slice() && signs(&cur, cand));
        match issuer {
            Some(cand) if is_self_signed(cand) => return Ok((chain, cand.clone())),
            Some(cand) => chain.push(cand.clone()),
            None => {
                return Err(format!(
                    "no issuer in the trust bundle for `{}` — the bundle is missing a link \
                     of the chain (intermediate or root)",
                    subject(&cur)
                ))
            },
        }
    }
    Err("attestation chain deeper than 16 — possible loop in the bundle".into())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <9c.pem|der> <f9.pem|der> <trust-bundle.pem> \
             [expected_ed25519_pubkey_base64]",
            args[0]
        );
        return ExitCode::from(2);
    }

    let read = |label: &str, p: &str| -> Result<Vec<u8>, ()> {
        read_cert_der(p).map_err(|e| eprintln!("error reading {label}: {e}"))
    };
    let (Ok(der_9c), Ok(der_f9)) = (read("9c", &args[1]), read("f9", &args[2])) else {
        return ExitCode::from(2);
    };
    let bundle = match read_certs_der(&args[3]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error reading trust bundle: {e}");
            return ExitCode::from(2);
        },
    };
    println!("(trust bundle holds {} certs)", bundle.len());

    // Path-build f9 → … → root out of the bundle.
    let (chain, root) = match build_chain(&der_f9, &bundle) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ chain build failed: {e}");
            return ExitCode::from(1);
        },
    };
    print!("chain: 9c → ");
    for c in &chain {
        print!("[{}] → ", subject(c));
    }
    println!("(root) {}", subject(&root));

    // Resolve the expected attested key (holder pubkey if given, else from 9c).
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
                    "(no expected pubkey given — using the attested key from 9c: {})",
                    base64::engine::general_purpose::STANDARD.encode(&k)
                );
                k
            },
            Err(e) => {
                eprintln!("error: parse 9c to read attested key: {e}");
                return ExitCode::from(2);
            },
        }
    };

    let chain_refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    println!("\nRunning verify_yubikey_piv_attestation (the production gate)…\n");
    match verify_yubikey_piv_attestation(&der_9c, &chain_refs, &root, &expected_ed) {
        Ok(v) => {
            println!("✅ ADMITTED — chain, attested-key, and FIPS+touch floor all hold.");
            println!("   pinned root    : {}", subject(&root));
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
                "\nThis root is the one to PIN in production. Cross-check firmware/serial/touch \n\
                 against the physical key (`ykman piv info`). If they match, the #91 \n\
                 byte-encodings are confirmed and the safe-mesh floor gate can close."
            );
            ExitCode::SUCCESS
        },
        Err(e) => {
            println!("❌ REJECTED — {e}");
            println!(
                "\nThe chain built, so the divergence is a byte-encoding (touch .8 offset / \n\
                 FIPS .10 placement) or the attested-key type. Dump the certs with \n\
                 `openssl x509 -in 9c.pem -text -noout` and compare to the module's parsing."
            );
            ExitCode::FAILURE
        },
    }
}
