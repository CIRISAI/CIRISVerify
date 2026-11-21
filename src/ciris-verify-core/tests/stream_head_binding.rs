//! `check_against_stream_binding` over the released StreamKeyBinding vectors
//! (`ciris-crypto/tests/vectors/composite/stream_key_binding_v2_composite_v3.json`).
#![cfg(feature = "pqc")]

use ciris_crypto::stream_binding::parse_stream_key_binding;
use ciris_verify_core::edition2::stream_head::{check_against_stream_binding, StreamHead};

const V3: &str = include_str!(
    "../../ciris-crypto/tests/vectors/composite/stream_key_binding_v2_composite_v3.json"
);

fn head_for(b: &ciris_crypto::stream_binding::StreamKeyBinding) -> StreamHead {
    StreamHead {
        stream_id: format!("av-{}", hex::encode(b.stream_id)),
        author: b.publisher.clone(),
        asserted_at: 1,
        epoch: b.epoch,
        tree_size: 1,
        root: [0; 32],
        sealed: false,
        room: (b.profile == 1).then(|| b.room.clone()),
        prev: None,
    }
}

#[test]
fn heads_under_each_binding() {
    let f: serde_json::Value = serde_json::from_str(V3).unwrap();
    let mut accountable = 0;
    for c in f["cases"].as_array().unwrap() {
        let b =
            parse_stream_key_binding(&hex::decode(c["encoding_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        accountable += usize::from(b.profile == 1);
        let ok = head_for(&b);
        assert_eq!(check_against_stream_binding(&ok, &b), Ok(()), "{}", c["id"]);

        let mut other_author = ok.clone();
        other_author.author.push('x');
        assert_eq!(
            check_against_stream_binding(&other_author, &b).map_err(|e| e.token()),
            Err("stream_head_author_not_publisher")
        );

        let mut other_stream = ok.clone();
        other_stream.stream_id = format!("av-{}", hex::encode([0u8; 32]));
        assert_eq!(
            check_against_stream_binding(&other_stream, &b).map_err(|e| e.token()),
            Err("stream_head_stream_mismatch")
        );
        let mut upper = ok.clone();
        upper.stream_id = upper.stream_id.to_uppercase().replacen("AV-", "av-", 1);
        assert!(check_against_stream_binding(&upper, &b).is_err());

        let mut room = ok.clone();
        room.room = if b.profile == 1 {
            Some("other".into())
        } else {
            Some(b.room.clone())
        };
        assert_eq!(
            check_against_stream_binding(&room, &b).map_err(|e| e.token()),
            Err("stream_head_room_mismatch")
        );
    }
    assert!(accountable > 0, "the vectors carry an accountable binding");
}
