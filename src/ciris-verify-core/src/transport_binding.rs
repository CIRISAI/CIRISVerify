//! `transport_destination` binding verification (CEG 0.12 §5.6.8.8.1 /
//! §8.1.12.7.1(c), AV-42 / AV-17, Option C′ — resolves the Verify half of
//! CIRISVerify#28 and the transport-binding bullet of CIRISVerify#63).
//!
//! ## What this verifies
//!
//! In a CEG/RET stack there is **no DNS** (§5.6.8.8.1): a node resolves a
//! community member to a reachable Reticulum address with no trusted
//! nameserver. The authenticated substitute is a federation-key-signed
//! `identity_occurrence` carrying a `transport_destination` — "key K
//! asserts that transport identity T (a dual-key RNS destination) is
//! mine." A bare Reticulum announce only proves the announcer controls
//! *that transport identity*, never that it legitimately belongs to K
//! (AV-42); the signed binding is what closes the gap.
//!
//! This module is the **soundly-verifiable** half of that conformance
//! obligation. Per §5.6.8.8.1 a Consumer resolving an address MUST verify
//! three things; this module owns (1) and (2), and is explicit about the
//! limit of (3):
//!
//! 1. **Hybrid signature over `JCS(binding)`** — the binding is signed
//!    (Ed25519 + ML-DSA-65, the bound-sig discipline: PQC covers
//!    `bytes ‖ classical_sig`) by the occurrence's **signing key**,
//!    verified against the pubkeys **pinned by the caller** for the
//!    claimed `attesting_key_id` — never against pubkeys carried in the
//!    binding itself (the same identity-binding discipline as
//!    [`crate::operational_admit`]). Implemented + tested.
//!
//! 2. **Key separation (normative, load-bearing)** — three key *purposes*
//!    are three distinct keypairs (§5.6.8.8.2): signing, RET-transport,
//!    content-KEM. This module enforces the two byte-comparable cases:
//!    - the transport Ed25519 key MUST NOT equal the signing key (AV-17 —
//!      the federation signing seed never enters the transport layer);
//!    - per §5.6.8.8.2 admission check (1.0-RC1 #71 C4), if the occurrence
//!      also carries `encryption_pubkeys`, the content-KEM x25519 MUST NOT
//!      equal the transport x25519.
//!
//!    Both are exact-byte pubkey comparisons. Implemented + tested.
//!
//! 3. **`destination_hash` derivation** — §5.6.8.8.1 requires
//!    `destination_hash == RNS_hash(reticulum_x25519 ‖ reticulum_ed25519 ‖
//!    app_name ‖ aspects)`. This module verifies the hash is **present and
//!    a signed member** of the binding (so (1) covers it — a forged hash
//!    changes the JCS bytes and fails the signature). The *recompute* of
//!    `RNS_hash(...)` is **honestly stubbed**: §5.6.8.8.1 fixes only the
//!    preimage *ordering* and that it is a truncated SHA-256 to 16 bytes
//!    (§5.6.8.8 `destination_hash: [u8; 16]`), but defers the exact byte
//!    layout (name-hash framing, aspect joining/separator, name-expansion)
//!    to Reticulum/leviculum's RNS destination-hash rule, which is **not
//!    pinned in the CEG spec**. A wrong recompute is worse than an honest
//!    gap, so [`verify_destination_hash`] returns
//!    [`DestinationHashCheck::Unsupported`] until leviculum's exact rule is
//!    pinned. See that function's docs.
//!
//! ## Fail-closed
//!
//! Every check fails closed: any malformation (bad base64, wrong pubkey
//! length, missing field, canonicalization failure) → reject, with a
//! coarse reason (enough for audit, not so granular it aids forgery). The
//! caller MUST treat the absence of a positive [`TransportBindingVerdict`]
//! as rejection.
//!
//! ## Scope vs [`crate::federation_envelope`]
//!
//! [`crate::federation_envelope`] (CIRISVerify#27, Phase 1) carries the
//! envelope-level `Vec<transport_identity>` as opaque blobs for the
//! Option C′ envelope. This module is the distinct **structured
//! `transport_destination` `identity_occurrence` binding** (§5.6.8.8.1) —
//! the dual-key RNS destination with normative key-separation. They
//! compose (both serve AV-42) but verify different shapes; do not conflate
//! them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::VerifyError;
use crate::jcs;
use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// Length of an X25519 / Ed25519 public key (raw bytes, pre-base64).
const PUBKEY_LEN: usize = 32;
/// Length of an RNS `destination_hash` (truncated SHA-256), per
/// §5.6.8.8 `destination_hash: [u8; 16]`.
const DESTINATION_HASH_LEN: usize = 16;

/// The `transport_destination` field of an `identity_occurrence`
/// (§5.6.8.8.1 / §8.1.12.7.1(c)).
///
/// Field byte payloads are base64-standard strings on the wire (the
/// §8.1.12.7.1 / §0.9.2.1 pin), decoded here only to length-check and
/// byte-compare. `aspects` retains RNS sequence order (NOT sorted) per
/// §8.1.12.7.1 — it is part of the (deferred) hash preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDestination {
    /// Transport identity's X25519 (encryption) public key — base64
    /// standard, 32 raw bytes.
    pub reticulum_x25519_pubkey_base64: String,
    /// Transport identity's Ed25519 (signing) public key — base64
    /// standard, 32 raw bytes. MUST differ from the occurrence's
    /// federation signing key (AV-17).
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

/// The content-encryption KEM keys (§5.6.8.8.2), present iff the
/// occurrence is a v2 wrap target. Only the `x25519` half is byte-
/// comparable on the wire and so the only half this module inspects (for
/// the C4 key-separation check); the ML-KEM half is opaque payload here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionPubkeys {
    /// Content-KEM X25519 public key — base64 standard, 32 raw bytes. A
    /// FRESH key; MUST NOT equal the transport x25519 (§5.6.8.8.2 C4).
    pub x25519_base64: String,
    /// Content-KEM ML-KEM-768 public key — base64 standard, 1184 raw
    /// bytes. Opaque payload to this module (never verification material;
    /// the §5.6.8.8.2 / §8.1.12.7.1 type-enforced key-separation rule).
    pub ml_kem_768_base64: String,
}

/// The detached hybrid signature over `JCS(signed_envelope)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportBindingSignature {
    /// Ed25519 signature over the JCS bytes, base64 standard.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 signature over `JCS_bytes ‖ ed25519_sig` (the bound-sig
    /// discipline), base64 standard. `None` while hybrid-pending; the
    /// classical half alone is then verified (same rule as
    /// [`crate::threshold`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_signature_base64: Option<String>,
}

/// A `transport_destination` binding to verify.
///
/// `signed_envelope` is the **exact `identity_occurrence` member set the
/// producer signed**, parsed as a [`serde_json::Value`] preserving §0.9
/// member presence (omit-vs-materialize) — see [`crate::jcs`]. It MUST
/// already have any signature container stripped. The typed
/// [`Self::transport_destination`] / [`Self::encryption_pubkeys`] are the
/// caller's parse of the corresponding members of that same envelope, used
/// for the byte-level key-separation checks; the signature is computed over
/// `signed_envelope` (the whole occurrence), not over the typed projection,
/// so the §0.9 discipline is preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportBinding {
    /// The occurrence's federation signing key_id — the claimed signer.
    /// Its pinned pubkeys are looked up in the caller's `key_directory`.
    pub attesting_key_id: String,
    /// The exact signed `identity_occurrence` envelope (signature
    /// container stripped), as received.
    pub signed_envelope: Value,
    /// The `transport_destination` member, parsed.
    pub transport_destination: TransportDestination,
    /// The `encryption_pubkeys` member, if the occurrence carries one
    /// (§5.6.8.8.2). Drives the C4 content-KEM ≠ transport key check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_pubkeys: Option<EncryptionPubkeys>,
    /// The detached hybrid signature over `JCS(signed_envelope)`.
    pub signature: TransportBindingSignature,
}

/// Why a [`TransportBinding`] was accepted or rejected. Coarse by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportBindingReason {
    /// Signature valid + key separation holds + `destination_hash`
    /// present-and-signed. (The `RNS_hash` recompute is deferred — see
    /// [`DestinationHashCheck`].)
    Verified,
    /// The claimed `attesting_key_id` is not present in the caller's
    /// `key_directory`, or its pinned pubkeys are malformed.
    UnknownSigner,
    /// The hybrid signature did not verify against the pinned pubkeys
    /// (forged, wrong key, or tampered envelope → different JCS bytes).
    SignatureInvalid,
    /// Key-separation violation: the transport Ed25519 key equals the
    /// occurrence's signing key (AV-17), OR the content-KEM x25519 equals
    /// the transport x25519 (§5.6.8.8.2 C4).
    KeySeparationViolation,
    /// A pubkey / hash field was absent, the wrong length, or not valid
    /// base64 — the binding is structurally malformed. Fail-closed.
    Malformed,
}

/// The verdict from [`verify_transport_binding`]. `authentic` is the
/// single fail-closed gate: a Consumer MUST treat `authentic == false` as
/// "do not route to this destination as an authenticated binding."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportBindingVerdict {
    /// `true` iff every implemented check passed.
    pub authentic: bool,
    /// The coarse reason.
    pub reason: TransportBindingReason,
    /// Result of the (currently deferred) `destination_hash` recompute.
    /// Always [`DestinationHashCheck::Unsupported`] today; surfaced so the
    /// caller can see the binding's hash was *not* recomputed (only that
    /// it is present and signature-covered).
    pub destination_hash_check: DestinationHashCheck,
}

/// Outcome of the `destination_hash == RNS_hash(...)` recompute
/// (§5.6.8.8.1 conformance point 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationHashCheck {
    /// The recompute is not implemented — §5.6.8.8.1 defers the exact RNS
    /// destination-hash byte layout to Reticulum/leviculum (see
    /// [`verify_destination_hash`]). The hash is still
    /// **present-and-signature-covered** (the producer cannot have signed a
    /// different hash without breaking the hybrid signature), so a forged
    /// hash is already rejected by check (1); what is *not* yet checked is
    /// that the producer derived it correctly from the pubkeys.
    Unsupported,
    /// The recomputed `RNS_hash(...)` matched the bound `destination_hash`.
    /// (Reserved — not produced until the RNS rule is pinned.)
    Match,
    /// The recompute ran and did NOT match — the producer's hash is
    /// inconsistent with its pubkeys/app_name/aspects. (Reserved.)
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

/// Verify a `transport_destination` binding (§5.6.8.8.1 conformance points
/// 1 + 2; point 3 — the `RNS_hash` recompute — is deferred, see the module
/// docs and [`verify_destination_hash`]).
///
/// `key_directory` carries the caller-pinned pubkeys for federation
/// `key_id`s. The binding's signature is verified against the entry for
/// `binding.attesting_key_id` — never against pubkeys embedded in the
/// binding — so a forged binding under a steward's `key_id` fails. This is
/// the [`crate::operational_admit`] identity-binding discipline, reusing
/// [`verify_threshold_signatures`] at threshold 1 for the exact bound-sig
/// rule (Ed25519 over the bytes; ML-DSA-65 over `bytes ‖ ed25519_sig`).
///
/// Performs **no I/O**: a pure evaluator over caller-supplied state.
///
/// Returns a [`TransportBindingVerdict`]; `authentic == true` only when
/// every implemented check passes. This function never returns `Err` for a
/// plain "didn't verify" — only the verdict carries that. `Err` is reserved
/// for a genuine crypto-layer fault surfaced by canonicalization.
///
/// # Errors
///
/// [`VerifyError::IntegrityError`] if `signed_envelope` cannot be JCS-
/// canonicalized (e.g. a non-finite float — a structurally impossible CEG
/// envelope). A malformed *binding* (bad base64, wrong length, key reuse)
/// is a fail-closed verdict, not an `Err`.
pub fn verify_transport_binding(
    binding: &TransportBinding,
    key_directory: &[ThresholdMember],
) -> Result<TransportBindingVerdict, VerifyError> {
    // ---- (2a) structural decode of every byte field, fail-closed -------
    let Some(transport_ed) = binding.transport_destination.ed25519_pubkey() else {
        return Ok(reject(TransportBindingReason::Malformed));
    };
    let Some(transport_x) = binding.transport_destination.x25519_pubkey() else {
        return Ok(reject(TransportBindingReason::Malformed));
    };
    // destination_hash MUST be present and correctly-sized (16 bytes). It
    // is a signed member of the envelope, so its presence here + a valid
    // signature below means the hybrid sig covers it (point 3, partial).
    if binding.transport_destination.destination_hash().is_none() {
        return Ok(reject(TransportBindingReason::Malformed));
    }

    // ---- (2b) key separation — the load-bearing normative check --------
    // Look up the occurrence's pinned federation signing key first; we
    // need its raw Ed25519 bytes both to compare against the transport key
    // and to bind the signature. UnknownSigner is distinct from Malformed.
    let Some(signer) = key_directory
        .iter()
        .find(|m| m.member_id == binding.attesting_key_id)
    else {
        return Ok(reject(TransportBindingReason::UnknownSigner));
    };
    let Some(signing_ed) = decode_pubkey(&signer.ed25519_public_key_base64) else {
        // Caller's own directory entry is malformed — treat as an unknown
        // (unusable) signer rather than blaming the binding.
        return Ok(reject(TransportBindingReason::UnknownSigner));
    };

    // (i) AV-17: transport Ed25519 key MUST NOT equal the signing key.
    // The federation signing seed never enters the transport layer.
    if transport_ed == signing_ed {
        return Ok(reject(TransportBindingReason::KeySeparationViolation));
    }

    // (ii) §5.6.8.8.2 C4: if the occurrence carries encryption_pubkeys,
    // the content-KEM x25519 MUST NOT equal the transport x25519.
    if let Some(enc) = &binding.encryption_pubkeys {
        let Some(content_kem_x) = decode_pubkey(&enc.x25519_base64) else {
            return Ok(reject(TransportBindingReason::Malformed));
        };
        if content_kem_x == transport_x {
            return Ok(reject(TransportBindingReason::KeySeparationViolation));
        }
    }

    // ---- (1) hybrid signature over JCS(signed_envelope) ----------------
    // Verified against the PINNED signer pubkeys, not the binding's. The
    // threshold-1 path applies the bound-sig rule (PQC covers
    // bytes ‖ classical_sig) identically to operational_admit.
    let bytes = jcs::canonicalize(&binding.signed_envelope)?;
    let sig = ThresholdSignature {
        member_id: binding.attesting_key_id.clone(),
        ed25519_signature_base64: binding.signature.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: binding.signature.mldsa65_signature_base64.clone(),
    };
    if verify_threshold_signatures(&bytes, std::slice::from_ref(signer), &[sig], 1).is_err() {
        return Ok(reject(TransportBindingReason::SignatureInvalid));
    }

    // ---- (3) destination_hash recompute — deferred to leviculum --------
    let destination_hash_check = verify_destination_hash(&binding.transport_destination);

    Ok(TransportBindingVerdict {
        authentic: true,
        reason: TransportBindingReason::Verified,
        destination_hash_check,
    })
}

/// Recompute `RNS_hash(reticulum_x25519 ‖ reticulum_ed25519 ‖ app_name ‖
/// aspects)` and compare to the bound `destination_hash` (§5.6.8.8.1
/// conformance point 2).
///
/// **DELIBERATELY STUBBED — returns [`DestinationHashCheck::Unsupported`].**
///
/// §5.6.8.8.1 pins only:
/// - the preimage *ordering* (`x25519 ‖ ed25519 ‖ app_name ‖ aspects`,
///   §8.1.13.1.1(b) `RNS_hash(...)`);
/// - that the result is a truncated SHA-256 to 16 bytes (§5.6.8.8
///   `destination_hash: [u8; 16]`).
///
/// It does **not** pin the exact RNS destination-hash construction — the
/// name-hash framing, how `app_name` + `aspects[]` are joined/separated and
/// expanded into the Reticulum "full name", the truncation offset, or
/// whether intermediate name-hashing is applied before the final digest.
/// That layout lives in Reticulum/leviculum's RNS `Destination.hash` rule,
/// which is referenced ("per the RNS rule") but not reproduced in the CEG
/// spec. Implementing a *guess* here would manufacture a check that passes
/// for our encoding and silently rejects conformant producers (or vice
/// versa) — strictly worse than an honest gap, because a wrong hash impl
/// looks authoritative.
///
/// The binding is not unprotected in the meantime: `destination_hash` is a
/// signed member of the occurrence envelope, so
/// [`verify_transport_binding`] check (1) already rejects any *forged or
/// substituted* hash (it would change the JCS bytes and break the hybrid
/// signature). What is deferred is only the orthogonal check that the
/// producer *derived* the hash correctly from its own pubkeys — a
/// producer-side consistency proof.
///
/// TODO(leviculum): wire the exact RNS destination-hash algorithm (byte
/// layout + truncation) from leviculum's spec, then return
/// [`DestinationHashCheck::Match`] / [`DestinationHashCheck::Mismatch`].
/// Tracked against CIRISVerify#28 / CIRISEdge#15 (AV-42).
#[must_use]
pub fn verify_destination_hash(_dest: &TransportDestination) -> DestinationHashCheck {
    DestinationHashCheck::Unsupported
}

/// Build a fail-closed (non-authentic) verdict with the given reason.
fn reject(reason: TransportBindingReason) -> TransportBindingVerdict {
    TransportBindingVerdict {
        authentic: false,
        reason,
        destination_hash_check: DestinationHashCheck::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
    use serde_json::json;

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    /// A federation signing keypair (Ed25519 + ML-DSA-65) plus a directory
    /// entry pinning its pubkeys. Mirrors the threshold module's test
    /// `Party` so we use the same raw signers + bound-sig construction.
    struct Signer {
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Signer {
        fn random() -> Self {
            Self {
                ed: Ed25519Signer::random(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }

        fn ed_pubkey(&self) -> Vec<u8> {
            self.ed.public_key().unwrap()
        }

        fn directory_member(&self, key_id: &str) -> ThresholdMember {
            ThresholdMember {
                member_id: key_id.to_string(),
                ed25519_public_key_base64: b64().encode(self.ed.public_key().unwrap()),
                mldsa65_public_key_base64: Some(b64().encode(self.mldsa.public_key().unwrap())),
                role: None,
            }
        }

        /// Hybrid-sign `bytes` with the bound-sig discipline (ML-DSA over
        /// `bytes ‖ ed25519_sig`).
        fn sign(&self, bytes: &[u8]) -> TransportBindingSignature {
            let ed_sig = self.ed.sign(bytes).unwrap();
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = self.mldsa.sign(&bound).unwrap();
            TransportBindingSignature {
                ed25519_signature_base64: b64().encode(&ed_sig),
                mldsa65_signature_base64: Some(b64().encode(&pqc_sig)),
            }
        }
    }

    /// 32 deterministic bytes for a pubkey, derived from a seed byte so
    /// each test fixture pubkey is distinct + length-correct.
    fn pubkey_bytes(seed: u8) -> Vec<u8> {
        vec![seed; PUBKEY_LEN]
    }

    /// Build the signed occurrence envelope + the typed transport_dest,
    /// hybrid-sign it, and assemble a [`TransportBinding`]. `transport_ed`
    /// lets a test force the AV-17 collision (transport ed == signing ed).
    fn make_binding(
        signer: &Signer,
        key_id: &str,
        transport_ed: &[u8],
        transport_x: &[u8],
        encryption_x: Option<&[u8]>,
    ) -> TransportBinding {
        let dest_hash = vec![0xABu8; DESTINATION_HASH_LEN];
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(transport_x),
            reticulum_ed25519_pubkey_base64: b64().encode(transport_ed),
            destination_hash_base64: b64().encode(&dest_hash),
            app_name: "ciris.federation".to_string(),
            aspects: vec!["announce".to_string(), "v1".to_string()],
        };
        let enc = encryption_x.map(|x| EncryptionPubkeys {
            x25519_base64: b64().encode(x),
            // 1184-byte ML-KEM placeholder (opaque to this module).
            ml_kem_768_base64: b64().encode(vec![0x11u8; 1184]),
        });

        // The signed occurrence envelope mirrors §8.1.12.7.1(c). It
        // includes the transport_destination (and encryption_pubkeys, if
        // present) as members, so the hybrid sig covers them + the
        // destination_hash.
        let mut envelope = json!({
            "attestation_type": "scores",
            "subject_kind": "identity_occurrence",
            "attesting_key_id": key_id,
            "identity_key_id": key_id,
            "occurrence_key_id": "occ-key-1",
            "device_class": "agent",
            "transport_destination": {
                "reticulum_x25519_pubkey": td.reticulum_x25519_pubkey_base64,
                "reticulum_ed25519_pubkey": td.reticulum_ed25519_pubkey_base64,
                "destination_hash": td.destination_hash_base64,
                "app_name": td.app_name,
                "aspects": td.aspects,
            },
            "asserted_at": "2026-06-14T00:00:00.000Z",
            "signed_at": "2026-06-14T00:00:00.000Z",
        });
        if let Some(enc) = &enc {
            envelope["encryption_pubkeys"] = json!({
                "x25519_base64": enc.x25519_base64,
                "ml_kem_768_base64": enc.ml_kem_768_base64,
            });
        }

        let bytes = jcs::canonicalize(&envelope).unwrap();
        let signature = signer.sign(&bytes);

        TransportBinding {
            attesting_key_id: key_id.to_string(),
            signed_envelope: envelope,
            transport_destination: td,
            encryption_pubkeys: enc,
            signature,
        }
    }

    #[test]
    fn valid_binding_verifies() {
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),       // transport ed — distinct from signing ed
            &pubkey_bytes(0x02),       // transport x
            Some(&pubkey_bytes(0x03)), // content-KEM x — distinct from transport x
        );

        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(v.authentic, "a well-formed signed binding must verify");
        assert_eq!(v.reason, TransportBindingReason::Verified);
        // The hash recompute is honestly deferred.
        assert_eq!(v.destination_hash_check, DestinationHashCheck::Unsupported);
    }

    #[test]
    fn valid_binding_without_encryption_pubkeys_verifies() {
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        // No encryption_pubkeys → the C4 check is simply not applicable.
        let binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(v.authentic);
        assert_eq!(v.reason, TransportBindingReason::Verified);
    }

    #[test]
    fn forged_signature_rejected() {
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let mut binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );

        // Tamper a signed member AFTER signing → JCS bytes change → the
        // hybrid sig no longer covers them.
        binding.signed_envelope["device_class"] = json!("laptop");

        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::SignatureInvalid);
    }

    #[test]
    fn signature_from_wrong_key_rejected() {
        // Binding signed by `attacker`, but the directory pins `steward-us`
        // to a DIFFERENT keypair. The bound-sig check against the pinned
        // pubkey fails — a forged binding under a steward's key_id.
        let attacker = Signer::random();
        let real_steward = Signer::random();
        let dir = vec![real_steward.directory_member("steward-us")];

        let binding = make_binding(
            &attacker,
            "steward-us", // claims to be the steward
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(
            !v.authentic,
            "a binding signed by the wrong key must reject"
        );
        assert_eq!(v.reason, TransportBindingReason::SignatureInvalid);
    }

    #[test]
    fn signing_key_equals_transport_key_rejected() {
        // AV-17: transport Ed25519 key == the occurrence's signing key.
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let transport_ed = signer.ed_pubkey(); // <-- the violation

        let binding = make_binding(
            &signer,
            "steward-us",
            &transport_ed,
            &pubkey_bytes(0x02),
            None,
        );
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::KeySeparationViolation);
    }

    #[test]
    fn content_kem_equals_transport_x25519_rejected() {
        // §5.6.8.8.2 C4: content-KEM x25519 == transport x25519.
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let transport_x = pubkey_bytes(0x02);

        let binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &transport_x,
            Some(&transport_x), // <-- the violation: reused as content-KEM
        );
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::KeySeparationViolation);
    }

    #[test]
    fn unknown_signer_rejected() {
        let signer = Signer::random();
        // Directory pins a DIFFERENT key_id → attesting_key_id absent.
        let dir = vec![signer.directory_member("some-other-key")];
        let binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::UnknownSigner);
    }

    #[test]
    fn malformed_transport_pubkey_rejected() {
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let mut binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );

        // Truncated transport ed pubkey (16 bytes, not 32) → Malformed,
        // caught before any signature work.
        binding
            .transport_destination
            .reticulum_ed25519_pubkey_base64 = b64().encode(vec![0u8; 16]);

        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::Malformed);
    }

    #[test]
    fn malformed_destination_hash_rejected() {
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let mut binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );

        // destination_hash wrong length (32, not 16) → Malformed.
        binding.transport_destination.destination_hash_base64 = b64().encode(vec![0u8; 32]);

        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::Malformed);
    }

    #[test]
    fn non_base64_pubkey_rejected() {
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let mut binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );

        binding.transport_destination.reticulum_x25519_pubkey_base64 =
            "!!! not base64 !!!".to_string();

        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(!v.authentic);
        assert_eq!(v.reason, TransportBindingReason::Malformed);
    }

    #[test]
    fn destination_hash_recompute_is_stubbed_unsupported() {
        // Explicitly lock the honest gap: the recompute is deferred.
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(pubkey_bytes(0x02)),
            reticulum_ed25519_pubkey_base64: b64().encode(pubkey_bytes(0x01)),
            destination_hash_base64: b64().encode(vec![0xABu8; DESTINATION_HASH_LEN]),
            app_name: "ciris.federation".to_string(),
            aspects: vec!["announce".to_string()],
        };
        assert_eq!(
            verify_destination_hash(&td),
            DestinationHashCheck::Unsupported,
            "the RNS destination-hash recompute is deliberately deferred to leviculum"
        );
    }

    #[test]
    fn hybrid_pending_classical_only_signature_verifies() {
        // A binding with no ML-DSA half (hybrid-pending) still verifies on
        // the classical half alone — the threshold rule.
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let mut binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );
        binding.signature.mldsa65_signature_base64 = None;

        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(v.authentic, "classical-only signature must still verify");
        assert_eq!(v.reason, TransportBindingReason::Verified);
    }
}
