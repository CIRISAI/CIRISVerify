//! CC 3.1.7: replay CIRISConstitution's `manifests/namespace_match_vectors.json`
//! against verify's port of the reference matcher (`namespace_match`).
//!
//! Every vector names the `(family, refusal)` the reference answers; the port
//! must agree on each, byte for byte.

use ciris_verify_core::namespace_match::{
    self, family_id, match_family, resolve, Refusal, Resolved,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("vectors/cc/namespace_match_vectors.json");

fn lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[test]
fn vendored_registry_is_the_pinned_one() {
    let digest = Sha256::digest(lf(namespace_match::NAMESPACE_REGISTRY_JSON).as_bytes());
    assert_eq!(
        hex::encode(digest),
        namespace_match::NAMESPACE_REGISTRY_SHA256
    );
}

#[test]
fn every_cc_vector_agrees() {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(
        vectors.len(),
        1354,
        "CC rc23 (0e80f21) ships 1,354 namespace vectors"
    );
    let mut failures = Vec::new();
    for (i, v) in vectors.iter().enumerate() {
        let dim = v["dimension"].as_str().expect("dimension");
        let want_family = v["family"].as_str();
        let want_refusal = v["refusal"].as_str();
        let got = match_family(dim);
        if got.family != want_family || got.refusal != want_refusal {
            failures.push(format!(
                "#{i} {dim:?}: expected ({want_family:?}, {want_refusal:?}) got ({:?}, {:?})",
                got.family, got.refusal
            ));
            continue;
        }
        // `resolve` is the same answer in its typed form.
        match (resolve(dim), want_refusal) {
            (Err(Refusal { family, token }), Some(r)) => {
                assert_eq!((family, token), (want_family, r), "#{i} {dim:?}");
            },
            (
                Ok(Resolved::Family {
                    prefix,
                    family_id: id,
                    ..
                }),
                None,
            ) => {
                assert_eq!(Some(prefix), want_family, "#{i} {dim:?}");
                assert_eq!(id, family_id(prefix), "#{i} {dim:?}");
            },
            (Ok(Resolved::OpenVocabulary), None) => {
                assert_eq!(want_family, None, "#{i} {dim:?}");
            },
            (other, _) => panic!("#{i} {dim:?}: resolve gave {other:?}"),
        }
    }
    let passed = vectors.len() - failures.len();
    assert!(
        failures.is_empty(),
        "{passed}/{} namespace vectors agree; disagreements:\n  {}",
        vectors.len(),
        failures.join("\n  ")
    );
}

#[test]
fn family_id_form() {
    assert_eq!(
        family_id("accord:lifecycle:{kind}"),
        "accord:lifecycle:.kind"
    );
    assert_eq!(family_id("accord:*"), "accord:.");
    assert_eq!(family_id("accord:human_dignity"), "accord:human_dignity");
    assert_eq!(family_id("trust:{job}:{version}"), "trust:.job:.version");
}

#[test]
fn binds_follow_the_reference() {
    // Values as `cc_namespace_match.py` returns them for the same inputs.
    let Ok(Resolved::Family { prefix, binds, .. }) = resolve("accord:invoke:constitutional:id1:v1")
    else {
        panic!("constitutional halt resolves");
    };
    assert_eq!(prefix, "accord:invoke:constitutional:{halt_id}");
    assert_eq!(binds.get("halt_id").map(String::as_str), Some("id1"));
    assert_eq!(binds.get("version").map(String::as_str), Some("v1"));

    let Ok(Resolved::Family { binds, .. }) = resolve("provenance:skill_import:registry:abc:v1")
    else {
        panic!("multi placeholder resolves");
    };
    assert_eq!(
        binds.get("source").map(String::as_str),
        Some("registry:abc")
    );
}
