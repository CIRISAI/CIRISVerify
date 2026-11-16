//! The recovery commitment (CC 3.2 T3, CC 4.2.6, rc20).
//!
//! ```text
//! commitment = [-16, SHA-256( CDE( ["CEG-recovery/2", keys] ) )]
//! ```
//!
//! `keys` is a set of composite COSE keys (`ceg-key`, `{1: 7, 3: -70100, -1:
//! pub}`), each exactly as stored on its key record, sorted by the bytewise
//! order of their deterministic encodings with no duplicate (CC 2.6.1.2). The
//! T3 successor commitment is this over the root's successor keys; the CC 4.2.6
//! per-holder recovery commitment is this over one key. Known answers:
//! `tests/vectors/recovery_commitment/`.
//!
//! Pure: no clock, no randomness, no I/O.

use super::{cose_key, Digest32};
use crate::cde::{self, Value};
use crate::prelude::*;
use ciris_crypto::composite::CompositePublicKey;
use sha2::{Digest, Sha256};

/// The recovery commitment's digest over `keys`: SHA-256 of the deterministic
/// encoding of `["CEG-recovery/2", keys]`. It is carried as `[-16, digest]`.
///
/// `keys` is taken as a set: this sorts them by encoding and **drops
/// duplicates**, so a key given twice commits as given once, and any order
/// gives the same digest. The CDDL requires at least one key
/// (`[+ ceg-key]`); with none this returns the digest of the empty set, which
/// no key opens. A caller that must refuse an empty or duplicated input
/// checks that before calling.
#[must_use]
pub fn recovery_commitment(keys: &[CompositePublicKey]) -> Digest32 {
    let mut set: Vec<(Vec<u8>, Value)> = keys
        .iter()
        .map(|k| {
            let v = cose_key(k);
            (cde::encode(&v), v)
        })
        .collect();
    set.sort_by(|a, b| a.0.cmp(&b.0));
    set.dedup_by(|a, b| a.0 == b.0);
    let input = Value::Array(vec![
        Value::Text("CEG-recovery/2".into()),
        Value::Array(set.into_iter().map(|(_, v)| v).collect()),
    ]);
    Sha256::digest(cde::encode(&input)).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str =
        include_str!("../../tests/vectors/recovery_commitment/recovery_commitment_v1.json");

    fn hx(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// Replays `recovery_commitment_v1.json`, written by its independent
    /// generator: each case's digest, its CDE preimage and its `[-16, digest]`.
    #[test]
    fn replays_known_answers() {
        let f: serde_json::Value = serde_json::from_str(FILE).unwrap();
        let cases = f["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 6);
        for c in cases {
            let id = c["id"].as_str().unwrap();
            let keys: Vec<CompositePublicKey> = c["input_composite_public_keys_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| CompositePublicKey::from_bytes(&hx(k)).unwrap())
                .collect();
            let digest = recovery_commitment(&keys);
            assert_eq!(digest.to_vec(), hx(&c["digest_hex"]), "{id}");

            // The preimage is the deterministic encoding the file states.
            let pre = hx(&c["cde_hex"]);
            assert_eq!(Sha256::digest(&pre).to_vec(), digest.to_vec(), "{id}");
            assert_eq!(cde::encode(&cde::decode(&pre).unwrap()), pre, "{id}");

            let carried = Value::Array(vec![Value::int(-16), Value::Bytes(digest.to_vec())]);
            assert_eq!(cde::encode(&carried), hx(&c["commitment_cde_hex"]), "{id}");
        }
        let digest = |id: &str| {
            cases.iter().find(|c| c["id"] == id).unwrap()["digest_hex"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(
            digest("three_keys_unsorted"),
            digest("three_keys_other_order")
        );
        assert_eq!(digest("duplicate_key"), digest("one_key"));
        assert_ne!(digest("one_key"), digest("three_keys_unsorted"));
    }
}
