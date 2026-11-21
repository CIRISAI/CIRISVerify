//! The RNS `destination_hash` of a `transport_destination` (CEG §5.6.8.8.1 /
//! §5.6.8.8.1.1, AV-42; CIRISVerify#28).
//!
//! [`compute_destination_hash`] is the one producer/consumer derivation of the
//! §5.6.8.8.1.1 two-stage RNS hash; [`verify_destination_hash`] recomputes it
//! from a [`TransportDestination`]'s pubkeys / `app_name` / `aspects` and
//! byte-compares it to the bound hash. A mismatch MUST be treated as an
//! unauthenticated (advisory-only) announce. CIRISPersist, CIRISEdge and the
//! wheel (`rns_destination_hash`) use these.
//!
//! The pair-signed `identity_occurrence` transport binding
//! (`produce_signed_identity_occurrence`, `verify_transport_binding` and their
//! types) was removed in 23.3.3; the forward model signs with the CC 2.6.1.7
//! composite.

#[allow(unused_imports)]
use crate::prelude::*;

use serde::{Deserialize, Serialize};

/// Length of an X25519 / Ed25519 public key (raw bytes, pre-base64).
const PUBKEY_LEN: usize = 32;
/// Length of an RNS `destination_hash` (truncated SHA-256), per
/// §5.6.8.8 `destination_hash: [u8; 16]` and §5.6.8.8.1.1
/// `DEST_HASH_LEN` (RNS `Reticulum.TRUNCATED_HASHLENGTH` = 128 bits).
const DESTINATION_HASH_LEN: usize = 16;
/// Length of an RNS `name_hash` (truncated SHA-256), per §5.6.8.8.1.1
/// `NAME_HASH_LEN` (RNS `Identity.NAME_HASH_LENGTH` = 80 bits).
const NAME_HASH_LEN: usize = 10;

/// The `transport_destination` field of an `identity_occurrence`
/// (§5.6.8.8.1 / §8.1.12.7.1(c)).
///
/// Field byte payloads are base64-standard strings on the wire (the
/// §8.1.12.7.1 / §0.9.2.1 pin), decoded here only to length-check and
/// byte-compare. `aspects` retains RNS sequence order (NOT sorted) per
/// §8.1.12.7.1 — it is part of the hash preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDestination {
    /// Transport identity's X25519 (encryption) public key — base64
    /// standard, 32 raw bytes.
    pub reticulum_x25519_pubkey_base64: String,
    /// Transport identity's Ed25519 (signing) public key — base64
    /// standard, 32 raw bytes.
    pub reticulum_ed25519_pubkey_base64: String,
    /// RNS destination hash (truncated SHA-256), base64 standard, 16 raw
    /// bytes. MUST derive from the two pubkeys + `app_name` + `aspects`
    /// per the RNS rule (§5.6.8.8.1).
    pub destination_hash_base64: String,
    /// RNS destination app name (e.g. `"ciris.federation"`).
    pub app_name: String,
    /// RNS aspects (ordered; part of the hash preimage).
    pub aspects: Vec<String>,
}

/// Outcome of the `destination_hash == RNS_hash(...)` recompute
/// (§5.6.8.8.1 conformance point 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationHashCheck {
    /// The recomputed §5.6.8.8.1.1 two-stage hash matched the bound
    /// `destination_hash` — the producer derived it correctly from its
    /// pubkeys / `app_name` / `aspects`.
    Match,
    /// The recompute ran and did NOT match — the producer's hash is
    /// inconsistent with its pubkeys / `app_name` / `aspects` (or an
    /// aspect contained an illegal `.`). Per §5.6.8.8.1.1 the consumer
    /// MUST treat this as an unauthenticated (advisory-only) announce.
    Mismatch,
}

impl TransportDestination {
    /// Decode + length-check the transport Ed25519 pubkey.
    fn ed25519_pubkey(&self) -> Option<Vec<u8>> {
        decode_pubkey(&self.reticulum_ed25519_pubkey_base64)
    }
    /// Decode + length-check the transport X25519 pubkey.
    fn x25519_pubkey(&self) -> Option<Vec<u8>> {
        decode_pubkey(&self.reticulum_x25519_pubkey_base64)
    }
    /// Decode + length-check the `destination_hash` (16 bytes).
    fn destination_hash(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&self.destination_hash_base64)
            .ok()?;
        (raw.len() == DESTINATION_HASH_LEN).then_some(raw)
    }
}

/// Decode a base64-standard pubkey and require exactly 32 raw bytes.
fn decode_pubkey(b64: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    (raw.len() == PUBKEY_LEN).then_some(raw)
}

/// Derive the RNS `destination_hash` (16 bytes) from a destination's
/// `app_name`, ordered `aspects`, and transport pubkeys per the
/// **§5.6.8.8.1.1 pinned two-stage algorithm** — the single derivation a
/// **producer** uses to fill `destination_hash` and a **consumer**
/// ([`verify_destination_hash`]) recomputes to authenticate it. Returns
/// `None` iff an aspect carries an illegal `.` (the producer must reject
/// such input).
///
/// # The algorithm (§5.6.8.8.1.1, 1.0-RC6 — closed CEG reproduction of the
/// RNS construction; SHA-256 throughout)
///
/// This is a **two-stage** hash — NOT a single SHA-256 over a flat
/// `x25519 ‖ ed25519 ‖ app_name ‖ aspects` preimage (the naive flat form
/// yields a different, wrong value).
///
/// 1. **Expanded name** (UTF-8): `app_name`, then each `aspect` dot-joined
///    in field order; the identity hexhash is NOT included (RNS computes
///    `name_hash` with `identity=None`). An aspect containing a `.` is
///    illegal → `None`.
///    `expanded_name = app_name (+ "." + aspect for each aspect)`
/// 2. `name_hash = SHA256(utf8(expanded_name))[:NAME_HASH_LEN]` (10 bytes).
/// 3. `identity_hash = SHA256(x25519_pub ‖ ed25519_pub)[:DEST_HASH_LEN]`
///    (16 bytes). Key order is **x25519 THEN ed25519** — RNS
///    `get_public_key()` = `pub_bytes (X25519) ‖ sig_pub_bytes (Ed25519)`.
/// 4. `destination_hash = SHA256(name_hash ‖ identity_hash)[:DEST_HASH_LEN]`
///    (16 bytes; the 26-byte `name_hash ‖ identity_hash` material).
///
/// Pinned source: Reticulum `RNS/Destination.py::Destination.hash` +
/// `RNS/Identity.py` (`full_hash` = SHA-256; `truncated_hash`;
/// `get_public_key()` = `pub_bytes ‖ sig_pub_bytes`) + `RNS/Reticulum.py`
/// (`TRUNCATED_HASHLENGTH = 128`). CEG owns this reproduction; it does not
/// float with upstream Reticulum. Resolves CIRISVerify#28 / CIRISEdge#15
/// (AV-42).
#[must_use]
pub fn compute_destination_hash(
    app_name: &str,
    aspects: &[String],
    x25519_pubkey: &[u8],
    ed25519_pubkey: &[u8],
) -> Option<[u8; DESTINATION_HASH_LEN]> {
    use sha2::{Digest, Sha256};

    // 1. Expanded name (UTF-8), app_name then each aspect dot-joined in field
    //    order. A dot inside an aspect is illegal per §5.6.8.8.1.1.
    let mut expanded_name = app_name.to_string();
    for aspect in aspects {
        if aspect.contains('.') {
            return None;
        }
        expanded_name.push('.');
        expanded_name.push_str(aspect);
    }

    // 2. name_hash = SHA256(utf8(expanded_name))[:NAME_HASH_LEN]
    let name_hash = &Sha256::digest(expanded_name.as_bytes())[..NAME_HASH_LEN];

    // 3. identity_hash = SHA256(x25519 ‖ ed25519)[:DEST_HASH_LEN]
    let mut id_hasher = Sha256::new();
    id_hasher.update(x25519_pubkey);
    id_hasher.update(ed25519_pubkey);
    let identity_hash = id_hasher.finalize();
    let identity_hash = &identity_hash[..DESTINATION_HASH_LEN];

    // 4. destination_hash = SHA256(name_hash ‖ identity_hash)[:DEST_HASH_LEN]
    let mut final_hasher = Sha256::new();
    final_hasher.update(name_hash);
    final_hasher.update(identity_hash);
    let mut out = [0u8; DESTINATION_HASH_LEN];
    out.copy_from_slice(&final_hasher.finalize()[..DESTINATION_HASH_LEN]);
    Some(out)
}

/// Recompute the §5.6.8.8.1.1 `destination_hash` (via
/// [`compute_destination_hash`]) from a [`TransportDestination`]'s pubkeys /
/// `app_name` / `aspects` and compare it byte-for-byte to the bound
/// `destination_hash` (§5.6.8.8.1 conformance point 2 / §8.1.13.1.1(b)).
/// [`DestinationHashCheck::Match`] on byte-equality; otherwise
/// [`DestinationHashCheck::Mismatch`] — including any malformed field or an
/// aspect carrying an illegal `.`.
#[must_use]
pub fn verify_destination_hash(dest: &TransportDestination) -> DestinationHashCheck {
    // Decode + length-check the three byte fields; any malformation → Mismatch
    // (a malformed binding can never be hash-consistent).
    let (Some(x25519), Some(ed25519), Some(bound_hash)) = (
        dest.x25519_pubkey(),
        dest.ed25519_pubkey(),
        dest.destination_hash(),
    ) else {
        return DestinationHashCheck::Mismatch;
    };

    let Some(recomputed) =
        compute_destination_hash(&dest.app_name, &dest.aspects, &x25519, &ed25519)
    else {
        // An aspect carried an illegal `.` — never hash-consistent.
        return DestinationHashCheck::Mismatch;
    };

    // Constant-time-ish byte compare. (The hash is public material — both
    // sides are non-secret — but use a length+value compare for clarity.)
    if recomputed.as_slice() == bound_hash.as_slice() {
        DestinationHashCheck::Match
    } else {
        DestinationHashCheck::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    /// 32 deterministic bytes for a pubkey, derived from a seed byte so
    /// each test fixture pubkey is distinct + length-correct.
    fn pubkey_bytes(seed: u8) -> Vec<u8> {
        vec![seed; PUBKEY_LEN]
    }

    /// Recompute the correct §5.6.8.8.1.1 two-stage RNS `destination_hash`
    /// for the given fixture inputs, so a fixture binding's hash is
    /// derivation-consistent (and `verify_destination_hash` → Match). This
    /// is an INDEPENDENT re-derivation of the four pinned steps (not a call
    /// into the production fn) so the test is a genuine cross-check.
    fn rns_destination_hash(
        x25519: &[u8],
        ed25519: &[u8],
        app_name: &str,
        aspects: &[&str],
    ) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut expanded = app_name.to_string();
        for a in aspects {
            expanded.push('.');
            expanded.push_str(a);
        }
        let name_hash = &Sha256::digest(expanded.as_bytes())[..NAME_HASH_LEN];
        let mut idh = Sha256::new();
        idh.update(x25519);
        idh.update(ed25519);
        let identity_hash = idh.finalize();
        let mut fh = Sha256::new();
        fh.update(name_hash);
        fh.update(&identity_hash[..DESTINATION_HASH_LEN]);
        fh.finalize()[..DESTINATION_HASH_LEN].to_vec()
    }

    #[test]
    fn destination_hash_recompute_matches_correct_derivation() {
        // A derivation-consistent hash → Match. The fixture hash is built by
        // the test's independent re-derivation of the four §5.6.8.8.1.1
        // steps, so this is a genuine cross-check of the production fn.
        let x = pubkey_bytes(0x02);
        let ed = pubkey_bytes(0x01);
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(&x),
            reticulum_ed25519_pubkey_base64: b64().encode(&ed),
            destination_hash_base64: b64().encode(rns_destination_hash(
                &x,
                &ed,
                "ciris.federation",
                &["announce"],
            )),
            app_name: "ciris.federation".to_string(),
            aspects: vec!["announce".to_string()],
        };
        assert_eq!(verify_destination_hash(&td), DestinationHashCheck::Match);
    }

    #[test]
    fn destination_hash_recompute_detects_wrong_hash() {
        // A wrong bound hash (not derived from the pubkeys) → Mismatch.
        let x = pubkey_bytes(0x02);
        let ed = pubkey_bytes(0x01);
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(&x),
            reticulum_ed25519_pubkey_base64: b64().encode(&ed),
            destination_hash_base64: b64().encode(vec![0xABu8; DESTINATION_HASH_LEN]),
            app_name: "ciris.federation".to_string(),
            aspects: vec!["announce".to_string()],
        };
        assert_eq!(verify_destination_hash(&td), DestinationHashCheck::Mismatch);
    }

    #[test]
    fn destination_hash_key_order_is_x25519_then_ed25519() {
        // §5.6.8.8.1.1 step 3 pins x25519 THEN ed25519. Swapping the two
        // distinct keys must NOT match (proves order is load-bearing).
        let x = pubkey_bytes(0x02);
        let ed = pubkey_bytes(0x01);
        // Hash derived with the SWAPPED order (ed then x).
        let swapped = rns_destination_hash(&ed, &x, "ciris.federation", &["announce"]);
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(&x),
            reticulum_ed25519_pubkey_base64: b64().encode(&ed),
            destination_hash_base64: b64().encode(swapped),
            app_name: "ciris.federation".to_string(),
            aspects: vec!["announce".to_string()],
        };
        assert_eq!(
            verify_destination_hash(&td),
            DestinationHashCheck::Mismatch,
            "swapping the x25519/ed25519 key order must change the hash"
        );
    }

    #[test]
    fn destination_hash_aspect_with_dot_is_mismatch() {
        // §5.6.8.8.1.1 step 1: a dot inside an aspect is illegal → Mismatch
        // (regardless of any bound hash value).
        let x = pubkey_bytes(0x02);
        let ed = pubkey_bytes(0x01);
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(&x),
            reticulum_ed25519_pubkey_base64: b64().encode(&ed),
            // Even a hash that "matches" a naive join cannot rescue it.
            destination_hash_base64: b64().encode(vec![0u8; DESTINATION_HASH_LEN]),
            app_name: "ciris.federation".to_string(),
            aspects: vec!["bad.aspect".to_string()],
        };
        assert_eq!(verify_destination_hash(&td), DestinationHashCheck::Mismatch);
    }

    #[test]
    fn destination_hash_two_stage_not_flat_concat() {
        // §5.6.8.8.1.1 warns the naive flat SHA-256 over
        // x25519 ‖ ed25519 ‖ app_name ‖ aspects yields a DIFFERENT value.
        // Lock that the two-stage construction is not the flat one.
        use sha2::{Digest, Sha256};
        let x = pubkey_bytes(0x02);
        let ed = pubkey_bytes(0x01);
        let app_name = "ciris.federation";
        let aspects = ["announce"];

        let two_stage = rns_destination_hash(&x, &ed, app_name, &aspects);

        // Naive flat preimage: x ‖ ed ‖ app_name ‖ aspects, single SHA-256.
        let mut flat = Vec::new();
        flat.extend_from_slice(&x);
        flat.extend_from_slice(&ed);
        flat.extend_from_slice(app_name.as_bytes());
        for a in aspects {
            flat.extend_from_slice(a.as_bytes());
        }
        let flat_hash = Sha256::digest(&flat)[..DESTINATION_HASH_LEN].to_vec();

        assert_ne!(
            two_stage, flat_hash,
            "the §5.6.8.8.1.1 two-stage hash must differ from a flat-concat SHA-256"
        );
    }
}
