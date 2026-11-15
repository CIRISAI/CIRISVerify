//! CC 5.1 per-stream call DEK known answers (CIRISVerify#308).
//!
//! Recomputes every vector in `tests/vectors/stream_dek/stream_dek_vectors.json`
//! with `ciris_crypto::stream_dek`. The file was generated independently of
//! this code (a from-scratch RFC 5869 HKDF in Python), so a failure means the
//! Rust derivation no longer matches CC 5.1 as written.
#![cfg(feature = "stream-dek")]

use ciris_crypto::stream_dek::{stream_dek, stream_dek_info, StreamDekError, STREAM_DEK_LABEL};

const VECTORS: &str = include_str!("vectors/stream_dek/stream_dek_vectors.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).expect("vector file is JSON")
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} is a string"))
}

#[test]
fn label_matches_the_file() {
    assert_eq!(s(&vectors(), "label"), STREAM_DEK_LABEL);
}

#[test]
fn every_valid_vector_recomputes() {
    let v = vectors();
    let cases = v["valid"].as_array().expect("valid is an array");
    assert!(cases.len() >= 4);
    for c in cases {
        let id = s(c, "id");
        let secret: [u8; 32] = hex::decode(s(c, "exporter_secret_hex"))
            .unwrap()
            .try_into()
            .unwrap();
        let sid = s(c, "stream_id");
        let epoch = c["epoch"].as_u64().unwrap();
        assert_eq!(
            hex::encode(stream_dek_info(sid, epoch)),
            s(c, "info_hex"),
            "{id}: info"
        );
        let dek = stream_dek(&secret, sid, epoch).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(hex::encode(*dek), s(c, "dek_hex"), "{id}: dek");
    }
}

#[test]
fn every_refusal_is_refused() {
    let v = vectors();
    for c in v["refusals"].as_array().expect("refusals is an array") {
        assert_eq!(
            stream_dek(&[0x42; 32], s(c, "stream_id"), 0).unwrap_err(),
            StreamDekError::MalformedStreamId,
            "{}",
            s(c, "id")
        );
    }
}
