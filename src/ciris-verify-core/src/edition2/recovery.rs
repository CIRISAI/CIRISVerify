//! The recovery commitment of CC 3.2 T3 (CC 4.2.6, rc20).
//!
//! ```text
//! commitment = [-16, SHA-256( CDE( ["CEG-recovery/2", keys] ) )]
//! ```
//!
//! `keys` is a set of composite keys, each its AKP COSE_Key
//! `{1: 7, 3: -70100, -1: ML-DSA-65 pk ‖ Ed25519 pk}` exactly as a key record
//! stores it, sorted by the bytewise order of each key's encoding with no
//! duplicate (CC 2.6.1.2). A holder's recovery commitment is the commitment
//! over its one recovery key. CC refuses a commitment over no key
//! (`recovery-commitment-input` is `[+ ceg-key]`).
//!
//! Pure: no clock, no randomness, no I/O.

use super::{cde, cose_key, Digest32, Value};
use crate::prelude::*;
use ciris_crypto::composite::CompositePublicKey;
use sha2::{Digest, Sha256};

/// The domain label of the recovery commitment.
pub const RECOVERY_LABEL: &str = "CEG-recovery/2";

/// The deterministic encoding of `["CEG-recovery/2", keys]`, with `keys`
/// formed into a set (sorted by encoding, duplicates dropped).
#[must_use]
pub fn recovery_commitment_input(keys: &[CompositePublicKey]) -> Vec<u8> {
    let mut enc: Vec<Vec<u8>> = keys.iter().map(|k| cde::encode(&cose_key(k))).collect();
    enc.sort();
    enc.dedup();
    let set: Vec<Value> = enc
        .iter()
        .map(|e| cde::decode(e).expect("re-decodes its own encoding"))
        .collect();
    cde::encode(&Value::Array(vec![
        Value::Text(RECOVERY_LABEL.into()),
        Value::Array(set),
    ]))
}

/// The CC 3.2 T3 commitment digest over a set of composite keys (the 32
/// bytes of `[-16, digest]`). The set is formed from `keys` as
/// [`recovery_commitment_input`] does. CC refuses an empty set; use
/// [`checked_recovery_commitment`] where `keys` may be empty.
#[must_use]
pub fn recovery_commitment(keys: &[CompositePublicKey]) -> Digest32 {
    Sha256::digest(recovery_commitment_input(keys)).into()
}

/// [`recovery_commitment`], or `None` for an empty set (CC: `[+ ceg-key]`).
#[must_use]
pub fn checked_recovery_commitment(keys: &[CompositePublicKey]) -> Option<Digest32> {
    (!keys.is_empty()).then(|| recovery_commitment(keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::composite::CompositeSigningKey;

    fn pk(n: u8) -> CompositePublicKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
            .public_key()
            .clone()
    }

    #[test]
    fn a_set_is_order_free_and_duplicate_free() {
        let (a, b) = (pk(1), pk(2));
        assert_eq!(
            recovery_commitment(&[a.clone(), b.clone()]),
            recovery_commitment(&[b.clone(), a.clone(), b.clone()])
        );
        assert_ne!(
            recovery_commitment(core::slice::from_ref(&a)),
            recovery_commitment(&[b])
        );
        assert_eq!(checked_recovery_commitment(&[]), None);
        assert_eq!(
            checked_recovery_commitment(core::slice::from_ref(&a)),
            Some(recovery_commitment(&[a]))
        );
    }
}
