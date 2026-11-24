//! Replays `tests/vectors/edition2/group_id_v1.json` (`gen_group_id_v1.py`,
//! independent of verify): the derived group id and the founding rule of a
//! `group:roster` version (CC rc22, ruled 2026-11-22). The file carries
//! CIRISConstitution's own known answer.
#![cfg(feature = "pqc")]

use std::collections::BTreeMap;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_verify_core::edition2::group::{derive_group_id, group_ref, is_group_ref};
use ciris_verify_core::edition2::{thumbprint, verify_row_statement, Digest32, Invalid, Verdict};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/group_id_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "c796353db656a32110fdb7e9c429c9f3e015f396d992751d13030723e49c1249";

fn held(c: &J) -> BTreeMap<Digest32, CompositePublicKey> {
    c["held_key_seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            let n = u8::try_from(n.as_u64().unwrap()).unwrap();
            let k = CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32]);
            (thumbprint(k.public_key()), k.public_key().clone())
        })
        .collect()
}

#[test]
fn file_is_pinned() {
    use sha2::Digest as _;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(FILE.as_bytes())),
        FILE_SHA256
    );
}

#[test]
fn derivations() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let ds = f["derivations"].as_array().unwrap();
    assert_eq!(ds.len(), 11);
    for d in ds {
        let id = d["id"].as_str().unwrap();
        let founders: Vec<&str> = d["founders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        let nonce: [u8; 32] = hex::decode(d["nonce_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let got = derive_group_id(
            d["group_kind"].as_str().unwrap(),
            &founders,
            d["founded_at"].as_u64().unwrap(),
            &nonce,
        );
        assert_eq!(got, d["group"].as_str().unwrap(), "{id}");
        assert!(is_group_ref(&got), "{id}");
        // The id is the group-ref of SHA-256 over the stated preimage.
        use sha2::Digest as _;
        let digest: [u8; 32] =
            sha2::Sha256::digest(hex::decode(d["input_hex"].as_str().unwrap()).unwrap()).into();
        assert_eq!(group_ref(&digest), got, "{id}");
    }
    // CIRISConstitution's known answer, by value.
    let cc = ds.iter().find(|d| d["id"] == "cc_known_answer").unwrap();
    assert_eq!(
        cc["group"],
        "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hI"
    );
}

#[test]
fn group_ref_form() {
    assert!(is_group_ref(
        "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hI"
    ));
    for bad in [
        "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hJ", // stray bits in the last character
        "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3h",  // 42 characters
        "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hI=", // padded
        "Group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hI",
        "urn:ietf:params:oauth:ckt:sha-256:8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hI",
        "humanity-accord",
        "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1+wsrnJ3hI", // not the URL alphabet
    ] {
        assert!(!is_group_ref(bad), "{bad}");
    }
}

#[test]
fn founding_cases() {
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let bytes = hex::decode(c["statement_hex"].as_str().unwrap()).unwrap();
        let got = match verify_row_statement(&bytes, &held(c)) {
            Verdict::Valid(_) => "valid".to_owned(),
            Verdict::Invalid(Invalid::Malformed { member }) => {
                format!("invalid:malformed:{member}")
            },
            Verdict::Invalid(i) => match i.token() {
                Some(t) => format!("invalid:{t}"),
                None => format!("invalid:{i:?}"),
            },
            Verdict::Waiting { .. } => "waiting".to_owned(),
        };
        assert_eq!(got, c["expect"].as_str().unwrap(), "{id}");
    }
}
