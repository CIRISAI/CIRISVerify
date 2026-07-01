//! Auditable proof-of-custody for the HUMANITY_ACCORD ceremony keys.
//!
//! The constitutional kill-switch's legitimacy rests on anyone being able to
//! **independently verify** that its keys are held on real, FIPS-certified,
//! touch-required hardware — not on trusting an assertion. This test re-runs the
//! exact CIRISServer admission-gate verifier
//! ([`verify_accord_custody_attestation`]) over the committed ceremony artifacts
//! in `accord_ceremony_artifacts/`, against the pinned **Yubico Attestation
//! Root 1**, and asserts for every one of the 6 keys (3 seated primaries +
//! 3 vaulted spares):
//!
//! - the bundle is holder-hybrid-signed (Ed25519 + ML-DSA-65),
//! - the YubiKey PIV slot-9c attestation chains `9c → f9 → … → pinned root`,
//! - the attested key equals the holder's federation Ed25519 key,
//! - the FIPS-certified extension is present and the touch policy is "always",
//! - the resolved hardware class is `YubiKey_5_FIPS`.
//!
//! CI failing this test means the audit trail no longer verifies — a loud,
//! non-silent signal. Anyone can reproduce it: `cargo test -p ciris-verify-core
//! --test accord_ceremony_custody`.

use base64::Engine;
use ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation;
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::threshold::ThresholdMember;
use serde_json::Value;

/// The 6 ceremony keys: 3 seated primaries (A1/B1/C1) + 3 vaulted spares
/// (A2/B2/C2). All must present a valid FIPS-hardware custody chain.
const KEYS: [&str; 6] = ["A1", "A2", "B1", "B2", "C1", "C2"];

fn artifacts_dir() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = src/ciris-verify-core → repo root is two up.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../accord_ceremony_artifacts")
}

fn read_json(path: &std::path::Path) -> Value {
    let raw =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Parse the single certificate in a PEM file to its DER bytes.
fn pem_to_der(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .expect("pinned Yubico root is valid base64 PEM")
}

#[test]
fn every_ceremony_key_has_a_valid_fips_hardware_custody_chain() {
    let dir = artifacts_dir();

    // The pinned trust anchor — Yubico Attestation Root 1
    // (developers.yubico.com/PKI/yubico-ca-1.pem), committed as a fixture so the
    // proof needs no network. This is the durable root, NOT the rotating
    // intermediate.
    let root_pem = std::fs::read_to_string(dir.join("yubico-attestation-root-1.pem"))
        .expect("pinned Yubico root fixture present");
    let root_der = pem_to_der(&root_pem);

    for key in KEYS {
        // Holder record → the holder's pinned hybrid federation pubkeys.
        let holder = read_json(&dir.join(format!("holders/{key}.json")));
        let record = &holder["holder_record"]["record"];
        let ed = record["pubkey_ed25519_base64"]
            .as_str()
            .unwrap_or_else(|| panic!("{key}: holder ed25519 pubkey"));
        let mldsa = record["pubkey_ml_dsa_65_base64"]
            .as_str()
            .unwrap_or_else(|| panic!("{key}: holder ml-dsa pubkey"));
        let member = ThresholdMember {
            member_id: key.to_string(),
            ed25519_public_key_base64: ed.to_string(),
            mldsa65_public_key_base64: Some(mldsa.to_string()),
            role: None,
        };

        // The standalone custody attestation object (the FIPS-YubiKey PIV proof).
        let att: SignedCegObject = serde_json::from_value(read_json(
            &dir.join(format!("custody_attestations/{key}.json")),
        ))
        .unwrap_or_else(|e| panic!("{key}: custody attestation deserialize: {e}"));

        // Re-run the exact admission-gate verifier against the pinned root.
        let verdict = verify_accord_custody_attestation(&att, &member, &root_der)
            .unwrap_or_else(|e| panic!("{key}: custody attestation FAILED to verify: {e:?}"));

        // The floor the CIRISServer#41 safe-mesh gate enforces.
        assert!(
            verdict.fips_certified,
            "{key}: NOT FIPS-certified (extension …3.10 absent)"
        );
        assert!(
            verdict.touch_always,
            "{key}: touch policy is not 'always' (extension …3.8)"
        );
        assert_eq!(
            verdict.hardware_class, "YubiKey_5_FIPS",
            "{key}: unexpected hardware_class"
        );
        assert_eq!(
            verdict.custody_tier, "portable_2fa",
            "{key}: unexpected custody tier"
        );

        println!(
            "  ✓ {key}: {} fw {} fips={} touch_always={} (serial {:?})",
            verdict.hardware_class,
            verdict.firmware,
            verdict.fips_certified,
            verdict.touch_always,
            verdict.serial
        );
    }
}
