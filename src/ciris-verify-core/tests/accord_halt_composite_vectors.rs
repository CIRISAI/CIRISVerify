//! Accord invocation holder-signature known answers (CC 4.2.1.1 / 4.2.1.3, rc20).
//!
//! `tests/vectors/accord_halt/accord_halt_composite_v1.json` was written by
//! `gen_accord_halt_composite.py` beside it (dilithium-py + pyca/cryptography,
//! its own preimage layout and CBOR), sharing no code with verify. Each case's
//! canonical bytes must be what [`Invocation::canonical_bytes`] lays out from
//! its fields; each signature must verify under
//! [`verify_invocation_composite`] and be byte-identical to verify's own
//! deterministic composite signature; each refusal must be refused.
#![cfg(feature = "pqc")]

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_verify_core::edition2::thumbprint;
use ciris_verify_core::humanity_accord::{
    verify_invocation_composite, Invocation, InvocationError, InvocationKind,
};
use serde_json::Value as J;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const FILE: &str = include_str!("vectors/accord_halt/accord_halt_composite_v1.json");

fn hx(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn seed(v: &J) -> [u8; 32] {
    hx(v).try_into().unwrap()
}

/// The roster's signing keys, rebuilt from the stated seeds and checked
/// against the file's public keys and thumbprints.
fn holders(f: &J) -> BTreeMap<String, CompositeSigningKey> {
    let mut out = BTreeMap::new();
    for h in f["roster"]
        .as_array()
        .unwrap()
        .iter()
        .chain([&f["outsider"]])
    {
        let label = h["label"].as_str().unwrap().to_owned();
        let sk = CompositeSigningKey::from_seeds(
            &seed(&h["mldsa65_seed_hex"]),
            &seed(&h["ed25519_seed_hex"]),
        );
        let pk = hx(&h["composite_public_key_hex"]);
        assert_eq!(sk.public_key().as_bytes().as_slice(), pk, "{label}");
        assert_eq!(
            Sha256::digest(&pk).to_vec(),
            hx(&h["composite_public_key_sha256"]),
            "{label}"
        );
        assert_eq!(
            thumbprint(sk.public_key()).to_vec(),
            hx(&h["thumbprint_hex"]),
            "{label}"
        );
        out.insert(label, sk);
    }
    out
}

fn pk<'a>(keys: &'a BTreeMap<String, CompositeSigningKey>, label: &J) -> &'a CompositePublicKey {
    keys[label.as_str().unwrap()].public_key()
}

#[test]
fn holder_signatures_verify_and_are_deterministic() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let keys = holders(&f);
    let cases = f["cases"].as_array().unwrap();
    let ids: Vec<&str> = cases.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        [
            "constitutional_halt",
            "lifecycle_confirmed",
            "lifecycle_active"
        ]
    );
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let inv: Invocation = serde_json::from_value(c["invocation"].clone()).unwrap();
        let canonical = inv.canonical_bytes();
        assert_eq!(canonical, hx(&c["canonical_bytes_hex"]), "{id}");
        assert_eq!(
            canonical,
            c["canonical_text"].as_str().unwrap().as_bytes(),
            "{id}"
        );
        assert_eq!(
            inv.canonical_digest().to_vec(),
            hx(&c["canonical_sha256_hex"]),
            "{id}"
        );
        assert_eq!(
            inv.payload_sha256,
            hex::encode(Sha256::digest(c["payload_text"].as_str().unwrap())),
            "{id}"
        );

        let sigs = c["signatures"].as_array().unwrap();
        // Each kind carries the signatures its threshold requires over the
        // seed roster of three: one for the halt, a strict majority otherwise.
        assert_eq!(
            Some(sigs.len()),
            inv.invocation_kind.required_signatures(3),
            "{id}"
        );
        for s in sigs {
            let label = s["holder"].as_str().unwrap();
            let sig = hx(&s["signature_hex"]);
            assert_eq!(
                Sha256::digest(&sig).to_vec(),
                hx(&s["signature_sha256"]),
                "{id}/{label}"
            );
            verify_invocation_composite(&inv, pk(&keys, &s["holder"]), &sig)
                .unwrap_or_else(|e| panic!("{id}/{label}: {e}"));
            assert_eq!(keys[label].sign(&canonical).unwrap(), sig, "{id}/{label}");
        }
    }
    let halt: Invocation = serde_json::from_value(cases[0]["invocation"].clone()).unwrap();
    assert_eq!(halt.invocation_kind, InvocationKind::Constitutional);
    for c in &cases[1..] {
        let inv: Invocation = serde_json::from_value(c["invocation"].clone()).unwrap();
        let named = inv.resumes_halt_id.or(inv.confirms_halt_id).unwrap();
        assert_eq!(named, halt.invocation_id);
    }
}

#[test]
fn refusals_are_refused() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let keys = holders(&f);
    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 6);
    let halt: Invocation = serde_json::from_value(f["cases"][0]["invocation"].clone()).unwrap();
    for r in refusals {
        let id = r["id"].as_str().unwrap();
        let inv: Invocation = serde_json::from_value(r["invocation"].clone()).unwrap();
        let sig = hx(&r["signature_hex"]);
        let signed = hx(&r["signed_message_hex"]);
        assert_eq!(
            Sha256::digest(&sig).to_vec(),
            hx(&r["signature_sha256"]),
            "{id}"
        );
        // Each refused signature is genuine over what it signed, by its signer.
        let signer = if id == "wrong_holder" {
            "outsider"
        } else {
            "A1"
        };
        keys[signer]
            .public_key()
            .verify(&signed, &sig)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(keys[signer].sign(&signed).unwrap(), sig, "{id}");
        // ... and refused as a holder signature on the invocation.
        for against in r["checked_against"].as_array().unwrap() {
            assert!(
                matches!(
                    verify_invocation_composite(&inv, pk(&keys, against), &sig),
                    Err(InvocationError::CompositeSignatureInvalid)
                ),
                "{id} against {against}"
            );
        }
        // What each refusal pins.
        let canonical = halt.canonical_bytes();
        match id {
            "domain_prefix_removed" => {
                assert_eq!(inv, halt);
                assert_eq!(signed, &canonical[b"ciris.accord_invoke.v2\n".len()..]);
            },
            "wrong_holder" => {
                assert_eq!(inv, halt);
                assert_eq!(signed, canonical);
                assert_eq!(
                    keys["outsider"].public_key().as_bytes().as_slice(),
                    hx(&r["signer_composite_public_key_hex"])
                );
            },
            "mutated_invocation_id" | "mutated_kind_drill" | "mutated_payload_sha256" => {
                assert_ne!(inv, halt);
                assert_eq!(signed, canonical);
                // The same signature over the unmutated halt verifies.
                verify_invocation_composite(&halt, keys["A1"].public_key(), &sig).unwrap();
            },
            "signed_sha256_not_text" => {
                assert_eq!(inv, halt);
                assert_eq!(signed, halt.canonical_digest());
            },
            other => panic!("unknown refusal {other}"),
        }
    }
}

/// The binding-line gate runs before the signature: a halt carrying a
/// `resumes_halt_id` is malformed, whatever it is signed with.
#[test]
fn binding_lines_gate_first() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let keys = holders(&f);
    let c = &f["cases"][0];
    let mut inv: Invocation = serde_json::from_value(c["invocation"].clone()).unwrap();
    inv.resumes_halt_id = Some("halt-0".into());
    let sig = hx(&c["signatures"][0]["signature_hex"]);
    assert!(matches!(
        verify_invocation_composite(&inv, keys["A1"].public_key(), &sig),
        Err(InvocationError::MalformedResumption { .. })
    ));
}
