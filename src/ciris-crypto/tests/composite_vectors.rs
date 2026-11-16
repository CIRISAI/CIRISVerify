//! Composite ML-DSA-65 with Ed25519 known answers (CC 2.6.1.7, CIRISVerify#326).
//!
//! `vectors/composite/mldsa65_ed25519_draft_kats.json` is extracted from the
//! drafts' own text: draft-ietf-lamps-pq-composite-sigs-19 Appendix E (tcId
//! id-MLDSA65-Ed25519-SHA512) and draft-ietf-jose-pq-composite-sigs-06 Figure 12
//! (a COSE_Sign1 over the composite). Both were checked independently with
//! dilithium-py and pyca/cryptography before this code was written; see the
//! README beside the file.
#![cfg(feature = "composite")]

use ciris_crypto::composite::{
    message_representative, CompositePublicKey, CompositeSigningKey, MLDSA65_SIG_LEN,
};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/composite/mldsa65_ed25519_draft_kats.json");

fn v() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}
fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}

#[test]
fn lamps_19_keygen_and_signature() {
    let l = &v()["lamps_19"];
    let sk = CompositeSigningKey::from_bytes(&h(l, "sk_hex")).unwrap();
    assert_eq!(sk.public_key().as_bytes().as_slice(), h(l, "pk_hex"));
    let pk = CompositePublicKey::from_bytes(&h(l, "pk_hex")).unwrap();
    pk.verify(&h(l, "m_hex"), &h(l, "s_hex")).unwrap();
    // The application context is always empty in COSE: a signature made over
    // a non-empty one never verifies here.
    assert!(pk
        .verify(&h(l, "m_hex"), &h(l, "s_with_context_hex"))
        .is_err());
}

#[test]
fn jose_06_cose_example() {
    let j = &v()["jose_06"];
    let ml: [u8; 32] = h(j, "mldsa_seed_hex").try_into().unwrap();
    let ed: [u8; 32] = h(j, "ed25519_seed_hex").try_into().unwrap();
    let sk = CompositeSigningKey::from_seeds(&ml, &ed);
    assert_eq!(sk.public_key().as_bytes().as_slice(), h(j, "pub_hex"));

    // Sig_structure = ["Signature1", << {1: -59, 4: kid} >>, h'', payload],
    // encoded by hand so this test does not lean on verify's own CBOR.
    let kid = h(j, "kid_hex");
    let payload = h(j, "payload_hex");
    let mut prot = vec![0xa2, 0x01, 0x38, 0x3a, 0x04, 0x40 | kid.len() as u8];
    prot.extend_from_slice(&kid);
    let mut m = vec![0x84, 0x6a];
    m.extend_from_slice(b"Signature1");
    m.push(0x40 | prot.len() as u8);
    m.extend_from_slice(&prot);
    m.push(0x40);
    m.extend_from_slice(&[0x58, payload.len() as u8]);
    m.extend_from_slice(&payload);
    assert_eq!(message_representative(&m).as_slice(), h(j, "m_prime_hex"));

    let sig = h(j, "signature_hex");
    sk.public_key().verify(&m, &sig).unwrap();
    // Our deterministic signature verifies too (ML-DSA signing is hedged in
    // the draft, so the bytes differ; both are valid).
    let ours = sk.sign(&m).unwrap();
    sk.public_key().verify(&m, &ours).unwrap();

    // An ML-DSA half made over M' under the EMPTY FIPS 204 context, beside the
    // draft's valid Ed25519 half, is refused: the label is the context.
    let plain = ciris_crypto::MlDsa65Signer::from_seed(&ml).unwrap();
    let mut wrong_ctx = ciris_crypto::PqcSigner::sign(&plain, &message_representative(&m)).unwrap();
    assert_eq!(wrong_ctx.len(), MLDSA65_SIG_LEN);
    wrong_ctx.extend_from_slice(&sig[MLDSA65_SIG_LEN..]);
    assert!(sk.public_key().verify(&m, &wrong_ctx).is_err());
}

/// StreamKeyBinding v2, THE binding of the cut (Eric's ruling on
/// CIRISEdge#1007): `gen_stream_key_binding_v2.py`, independent of verify.
#[test]
fn stream_key_binding_v2_composite() {
    let v: Value = serde_json::from_str(include_str!(
        "vectors/composite/stream_key_binding_v2_composite_v1.json"
    ))
    .unwrap();
    let sk = CompositeSigningKey::from_seeds(&[0x54; 32], &[0x01; 32]);
    assert_eq!(
        sk.public_key().as_bytes().as_slice(),
        h(&v, "publisher_composite_public_key_hex")
    );
    for c in v["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let body = h(c, "body_hex");
        assert_eq!(body[0], 0x02, "{id}");
        let mut msg = b"ciris-edge:av-stream-key:v2".to_vec();
        msg.extend_from_slice(&body);
        assert_eq!(msg, h(c, "signing_bytes_hex"), "{id}");
        let sig = h(c, "signature_hex");
        sk.public_key().verify(&msg, &sig).unwrap();
        assert_eq!(sk.sign(&msg).unwrap(), sig, "{id}");
        let enc = h(c, "encoding_hex");
        assert_eq!(&enc[..body.len()], body.as_slice(), "{id}");
        assert_eq!(
            &enc[body.len()..body.len() + 2],
            &3373u16.to_be_bytes(),
            "{id}"
        );
        assert_eq!(&enc[body.len() + 2..], sig.as_slice(), "{id}");
    }
}
