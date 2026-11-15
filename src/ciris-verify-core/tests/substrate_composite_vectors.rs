//! Composite signatures over the CC Part 6 golden preimages (CC 2.6.1.7).
//!
//! `vectors/substrate_composite/composite_signatures_v1.json` was written by
//! `gen.py` beside it with dilithium-py and pyca/cryptography, without verify's
//! code. Every signature must verify under the stated key; every refusal must not.
#![cfg(feature = "pqc")]

use ciris_verify_core::substrate::{verify_composite, HolonomicError};
use serde_json::Value;

const FILE: &str = include_str!("vectors/substrate_composite/composite_signatures_v1.json");

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn every_preimage_signature_verifies_and_every_refusal_fails() {
    let f: Value = serde_json::from_str(FILE).unwrap();
    let pk = hx(&f["composite_public_key_hex"]);
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for c in cases {
        let id = c["vector_id"].as_str().unwrap();
        let pre = hx(&c["preimage_hex"]);
        verify_composite(&pre, &hx(&c["signature_hex"]), &pk)
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        for (name, sig) in c["refusals"].as_object().unwrap() {
            let want = if name == "truncated" {
                HolonomicError::MalformedKeyOrSignature
            } else {
                HolonomicError::SignatureInvalid
            };
            assert_eq!(
                verify_composite(&pre, &hx(sig), &pk),
                Err(want),
                "{id} {name}"
            );
        }
    }
}
