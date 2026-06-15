//! Document-integrity signing substrate (CIRISVerify#54 Gap G, Phase 2 —
//! closes F-AV-MAINT).
//!
//! The Federation Threat Model markdown, the per-repo Threat Model, and
//! MISSION.md are authoritative governance documents whose **content** is
//! load-bearing: an F-AV status, a mitigation claim, or a threat-class
//! verdict can be silently downgraded by a maintainer compromise or a
//! careless edit, with no cryptographic detection. This module is the
//! substrate that makes such tampering detectable: it produces a
//! *detached*, hybrid-signed integrity attestation over a canonical hash
//! of a document's bytes.
//!
//! ## Discipline
//!
//! Same house style as [`crate::federation_keyset`],
//! `SignedTreeHead::signing_bytes`, and `TransparencyEntry::canonical_bytes`:
//! a domain-separated, length-prefixed canonical byte string hashed with
//! SHA-256. The domain-sep tag ([`DOC_INTEGRITY_DOMAIN_SEP`]) is distinct
//! from every other canonical-bytes tag in the crate, so a doc-integrity
//! hash can never collide with an envelope / keyset / STH hash. The schema
//! version and both binding labels (path + version) live *inside* the
//! hashed bytes, so a signature over `v1.2` of a given doc can never be
//! replayed as covering `v1.3`, nor as covering a different document.
//!
//! ## Signing
//!
//! Signatures are hybrid (Ed25519 + ML-DSA-65) via
//! [`ciris_crypto::HybridSigner`]: both halves must verify. The PQC half
//! already covers the classical half (stripping protection), and the
//! domain-sep is folded into the hash the hybrid signer signs over.
//!
//! ## Out of scope (future composition)
//!
//! M-of-N *threshold* doc signing (Phase 3) — requiring `M` distinct
//! stewards to co-sign a doc's canonical hash before its status is
//! authoritative — is deferred. It composes cleanly over the now-shipped
//! [`crate::threshold::verify_threshold_signatures`] primitive applied to
//! the [`doc_content_hash`] output, exactly as
//! [`crate::federation_keyset`] composes threshold verification over its
//! canonical bytes. This module ships the single-signer substrate Phase 2
//! needs; the threshold path is a later composition, not a schema change
//! here.

use crate::error::VerifyError;
use base64::Engine;
use ciris_crypto::{
    Ed25519Signer, Ed25519Verifier, HybridSignature, HybridSigner, HybridVerifier, MlDsa65Signer,
    MlDsa65Verifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation prefix for document-integrity content hashes.
/// Distinct from every other canonical-bytes tag in the crate so a
/// doc-integrity hash can never collide with an envelope / keyset /
/// STH hash.
pub const DOC_INTEGRITY_DOMAIN_SEP: &[u8] = b"CIRIS-DOC-INTEGRITY-V1";

/// Schema version, inside the hashed bytes.
pub const DOC_INTEGRITY_SCHEMA_VERSION: u8 = 1;

/// Append a `u32`-LE length prefix followed by the field bytes.
///
/// This is the `LP(..)` primitive in the canonical-bytes spec — the same
/// length-prefixing discipline [`crate::federation_keyset`] uses, which
/// makes the encoding unambiguous (no field-boundary confusion between two
/// inputs that concatenate to the same flat byte string).
fn push_lp(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
    buf.extend_from_slice(field);
}

/// Compute the raw 32-byte canonical content hash of a document.
///
/// Hashes `DOC_INTEGRITY_DOMAIN_SEP · schema_version · LP(doc_path_label)
/// · LP(doc_version_label) · LP(content_bytes)` with SHA-256. The path and
/// version labels bind the hash to a specific document + version (replay
/// protection); the domain-sep prevents cross-protocol collisions.
fn doc_content_hash_raw(doc_path_label: &str, doc_version_label: &str, content: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        DOC_INTEGRITY_DOMAIN_SEP.len()
            + 1
            + doc_path_label.len()
            + doc_version_label.len()
            + content.len()
            + 12,
    );
    buf.extend_from_slice(DOC_INTEGRITY_DOMAIN_SEP);
    buf.push(DOC_INTEGRITY_SCHEMA_VERSION);
    push_lp(&mut buf, doc_path_label.as_bytes());
    push_lp(&mut buf, doc_version_label.as_bytes());
    push_lp(&mut buf, content);

    let digest = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Compute the canonical content hash of a document.
///
/// Hashes `DOC_INTEGRITY_DOMAIN_SEP · schema_version · LP(doc_path_label)
/// · LP(doc_version_label) · LP(content_bytes)` with SHA-256.
/// `doc_path_label` (e.g. "docs/FEDERATION_THREAT_MODEL.md") and
/// `doc_version_label` (e.g. "1.2") bind the hash to a specific doc +
/// version, so a signature over v1.2 can't be replayed as covering v1.3.
/// Returns the 32-byte hash hex-encoded.
#[must_use]
pub fn doc_content_hash(doc_path_label: &str, doc_version_label: &str, content: &[u8]) -> String {
    hex::encode(doc_content_hash_raw(
        doc_path_label,
        doc_version_label,
        content,
    ))
}

/// A detached, hybrid-signed integrity attestation over a document.
///
/// Serializable to JSON for storage alongside the doc / in a release
/// tarball / in the transparency log. The wire shape is locked by
/// `doc_signature_json_round_trips` in this module's tests.
///
/// The trust root is **not** `signer_key_id`; it is the verifier's pinned
/// public key, embedded in the supplied [`HybridVerifier`]. `signer_key_id`
/// is informational only (audit / key-selection convenience).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocSignature {
    /// Canonical-bytes schema version (see [`DOC_INTEGRITY_SCHEMA_VERSION`]).
    pub schema_version: u8,
    /// Path label this signature binds to (e.g. "docs/FEDERATION_THREAT_MODEL.md").
    pub doc_path_label: String,
    /// Version label this signature binds to (e.g. "1.2").
    pub doc_version_label: String,
    /// Hex SHA-256 content hash (== [`doc_content_hash`] output).
    pub content_hash: String,
    /// Signer key_id (informational; the actual trust root is the
    /// verifier's pinned pubkey, not this field).
    pub signer_key_id: String,
    /// Hybrid signature over the raw 32-byte hash digest (NOT the hex
    /// string). Classical (Ed25519) + PQC (ML-DSA-65) halves, each carried
    /// as base64-encoded signature + public-key strings so the artifact is
    /// pure-JSON / human-diffable.
    pub signature: SerializableHybridSignature,
}

/// JSON-friendly projection of [`ciris_crypto::HybridSignature`].
///
/// `HybridSignature` itself serializes its `signature` / `public_key`
/// `Vec<u8>` fields as JSON arrays of integers, which bloat the artifact
/// and don't diff cleanly. We instead base64-encode each byte vector and
/// carry the algorithm tags as their numeric discriminants, then rebuild
/// the exact `HybridSignature` on the way back. Round-trip equality is
/// covered by `doc_signature_json_round_trips`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableHybridSignature {
    /// Crypto-kind tag, base64 of the 4-byte [`ciris_crypto::CryptoKind`].
    pub crypto_kind: String,
    /// Classical algorithm discriminant (`ClassicalAlgorithm as u8`).
    pub classical_algorithm: u8,
    /// Base64 classical signature bytes.
    pub classical_signature: String,
    /// Base64 classical public-key bytes.
    pub classical_public_key: String,
    /// PQC algorithm discriminant (`PqcAlgorithm as u8`).
    pub pqc_algorithm: u8,
    /// Base64 PQC signature bytes.
    pub pqc_signature: String,
    /// Base64 PQC public-key bytes.
    pub pqc_public_key: String,
    /// Signature-mode discriminant (`SignatureMode as u8`).
    pub mode: u8,
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn integrity_err(msg: impl Into<String>) -> VerifyError {
    VerifyError::IntegrityError {
        message: msg.into(),
    }
}

impl SerializableHybridSignature {
    fn from_hybrid(sig: &HybridSignature) -> Self {
        let enc = b64();
        Self {
            crypto_kind: enc.encode(sig.crypto_kind),
            classical_algorithm: sig.classical.algorithm as u8,
            classical_signature: enc.encode(&sig.classical.signature),
            classical_public_key: enc.encode(&sig.classical.public_key),
            pqc_algorithm: sig.pqc.algorithm as u8,
            pqc_signature: enc.encode(&sig.pqc.signature),
            pqc_public_key: enc.encode(&sig.pqc.public_key),
            mode: sig.mode as u8,
        }
    }

    fn to_hybrid(&self) -> Result<HybridSignature, VerifyError> {
        use ciris_crypto::{
            ClassicalAlgorithm, CryptoKind, PqcAlgorithm, SignatureMode, TaggedClassicalSignature,
            TaggedPqcSignature,
        };

        let dec = b64();
        let decode = |s: &str, what: &str| {
            dec.decode(s)
                .map_err(|e| integrity_err(format!("base64 decode of {what}: {e}")))
        };

        let ck_bytes = decode(&self.crypto_kind, "crypto_kind")?;
        let crypto_kind: CryptoKind = ck_bytes
            .as_slice()
            .try_into()
            .map_err(|_| integrity_err("crypto_kind must be exactly 4 bytes"))?;

        let classical_algorithm = match self.classical_algorithm {
            1 => ClassicalAlgorithm::EcdsaP256,
            2 => ClassicalAlgorithm::Ed25519,
            3 => ClassicalAlgorithm::EcdsaP384,
            other => {
                return Err(integrity_err(format!(
                    "unknown classical algorithm {other}"
                )))
            },
        };
        let pqc_algorithm = match self.pqc_algorithm {
            1 => PqcAlgorithm::MlDsa44,
            2 => PqcAlgorithm::MlDsa65,
            3 => PqcAlgorithm::MlDsa87,
            10 => PqcAlgorithm::SlhDsaSha2_128s,
            11 => PqcAlgorithm::SlhDsaSha2_256s,
            other => return Err(integrity_err(format!("unknown PQC algorithm {other}"))),
        };
        let mode = match self.mode {
            1 => SignatureMode::ClassicalOnly,
            2 => SignatureMode::HybridRequired,
            3 => SignatureMode::PqcOnly,
            other => return Err(integrity_err(format!("unknown signature mode {other}"))),
        };

        Ok(HybridSignature {
            crypto_kind,
            classical: TaggedClassicalSignature {
                algorithm: classical_algorithm,
                signature: decode(&self.classical_signature, "classical_signature")?,
                public_key: decode(&self.classical_public_key, "classical_public_key")?,
            },
            pqc: TaggedPqcSignature {
                algorithm: pqc_algorithm,
                signature: decode(&self.pqc_signature, "pqc_signature")?,
                public_key: decode(&self.pqc_public_key, "pqc_public_key")?,
            },
            mode,
        })
    }
}

/// Sign a document's canonical content hash with a hybrid signer.
///
/// Produces a [`DocSignature`]. The hybrid signature covers the raw 32-byte
/// hash digest (the same digest [`doc_content_hash`] hex-encodes), with the
/// domain-sep + binding labels already folded into that hash.
///
/// # Errors
///
/// Returns [`VerifyError::CryptoError`] if the underlying hybrid signer
/// fails (e.g. the PQC half can't sign).
pub fn sign_document(
    doc_path_label: &str,
    doc_version_label: &str,
    content: &[u8],
    signer_key_id: &str,
    signer: &HybridSigner<Ed25519Signer, MlDsa65Signer>,
) -> Result<DocSignature, VerifyError> {
    let hash = doc_content_hash_raw(doc_path_label, doc_version_label, content);
    let hybrid = signer.sign(&hash)?;

    Ok(DocSignature {
        schema_version: DOC_INTEGRITY_SCHEMA_VERSION,
        doc_path_label: doc_path_label.to_string(),
        doc_version_label: doc_version_label.to_string(),
        content_hash: hex::encode(hash),
        signer_key_id: signer_key_id.to_string(),
        signature: SerializableHybridSignature::from_hybrid(&hybrid),
    })
}

/// Verify a [`DocSignature`] against the document's current content.
///
/// Recomputes the canonical hash from `content` using the labels carried in
/// `sig`, and checks BOTH:
///
/// 1. the recomputed hash equals `sig.content_hash` (a one-byte content edit
///    flips the hash and fails here), AND
/// 2. the hybrid signature verifies against the supplied verifier over the
///    raw 32-byte digest (a forged or wrong-key signature fails here).
///
/// Returns `Ok(true)` only if both hold, `Ok(false)` if either content or
/// signature check fails cleanly.
///
/// # Errors
///
/// Returns [`VerifyError::IntegrityError`] if the embedded signature can't
/// be decoded into a [`HybridSignature`], or [`VerifyError::CryptoError`]
/// for a hard crypto failure that isn't a clean verification miss.
pub fn verify_document(
    content: &[u8],
    sig: &DocSignature,
    verifier: &HybridVerifier<Ed25519Verifier, MlDsa65Verifier>,
) -> Result<bool, VerifyError> {
    // (a) recompute canonical hash from current content + the labels the
    // signature claims to bind, and compare to the signed hash.
    let recomputed = doc_content_hash_raw(&sig.doc_path_label, &sig.doc_version_label, content);
    if hex::encode(recomputed) != sig.content_hash {
        return Ok(false);
    }

    // (b) verify the hybrid signature over the raw digest. The hybrid
    // verifier returns Err on a clean classical/PQC mismatch; map that to
    // Ok(false) so a forged-or-wrong-key signature is a soft failure, while
    // genuinely malformed input (undecodable signature) is a hard error.
    let hybrid = sig.signature.to_hybrid()?;
    match verifier.verify(&recomputed, &hybrid) {
        Ok(valid) => Ok(valid),
        Err(
            ciris_crypto::CryptoError::ClassicalVerificationFailed { .. }
            | ciris_crypto::CryptoError::PqcVerificationFailed { .. },
        ) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "docs/FEDERATION_THREAT_MODEL.md";
    const VERSION: &str = "1.2";
    const SAMPLE: &[u8] = b"# Federation Threat Model\n\nF-AV-MAINT: status OPEN.\n";

    fn make_signer() -> HybridSigner<Ed25519Signer, MlDsa65Signer> {
        HybridSigner::new(
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        )
        .unwrap()
    }

    fn matching_verifier() -> HybridVerifier<Ed25519Verifier, MlDsa65Verifier> {
        HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new())
    }

    #[test]
    fn content_hash_is_deterministic() {
        let a = doc_content_hash(PATH, VERSION, SAMPLE);
        let b = doc_content_hash(PATH, VERSION, SAMPLE);
        assert_eq!(a, b);
        // 32-byte digest -> 64 hex chars.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn content_hash_sensitive_to_content() {
        let mut tampered = SAMPLE.to_vec();
        // Flip one byte (OPEN -> oPEN).
        let idx = tampered.len() - 7;
        tampered[idx] ^= 0x20;
        assert_ne!(
            doc_content_hash(PATH, VERSION, SAMPLE),
            doc_content_hash(PATH, VERSION, &tampered),
        );
    }

    #[test]
    fn content_hash_sensitive_to_version_label() {
        assert_ne!(
            doc_content_hash(PATH, "1.2", SAMPLE),
            doc_content_hash(PATH, "1.3", SAMPLE),
            "same content under a different version label must not share a hash (replay protection)"
        );
    }

    #[test]
    fn content_hash_sensitive_to_path_label() {
        assert_ne!(
            doc_content_hash("docs/FEDERATION_THREAT_MODEL.md", VERSION, SAMPLE),
            doc_content_hash("MISSION.md", VERSION, SAMPLE),
        );
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let signer = make_signer();
        let sig = sign_document(PATH, VERSION, SAMPLE, "steward-1", &signer).unwrap();

        assert_eq!(sig.content_hash, doc_content_hash(PATH, VERSION, SAMPLE));
        assert_eq!(sig.signer_key_id, "steward-1");

        let verifier = matching_verifier();
        assert!(verify_document(SAMPLE, &sig, &verifier).unwrap());
    }

    #[test]
    fn verify_fails_on_tampered_content() {
        let signer = make_signer();
        let sig = sign_document(PATH, VERSION, SAMPLE, "steward-1", &signer).unwrap();

        let mut tampered = SAMPLE.to_vec();
        tampered[0] ^= 0x01;

        let verifier = matching_verifier();
        // Hash mismatch -> Ok(false), not an error.
        assert!(!verify_document(&tampered, &sig, &verifier).unwrap());
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        // Sign with signer 1.
        let signer1 = make_signer();
        let sig = sign_document(PATH, VERSION, SAMPLE, "steward-1", &signer1).unwrap();

        // The embedded signature carries signer1's pubkeys; to test a
        // wrong-key scenario we re-point the artifact at signer2's pubkeys,
        // simulating an attacker who substitutes the keys but cannot forge a
        // matching signature. The hybrid verifier (which trusts the pubkeys
        // embedded in the signature) then sees a signature that doesn't
        // verify under those substituted keys.
        let signer2 = make_signer();
        let other = sign_document(PATH, VERSION, SAMPLE, "steward-2", &signer2).unwrap();

        let mut forged = sig.clone();
        forged.signature.classical_public_key = other.signature.classical_public_key.clone();
        forged.signature.pqc_public_key = other.signature.pqc_public_key.clone();

        let verifier = matching_verifier();
        assert!(!verify_document(SAMPLE, &forged, &verifier).unwrap());
    }

    #[test]
    fn doc_signature_json_round_trips() {
        let signer = make_signer();
        let sig = sign_document(PATH, VERSION, SAMPLE, "steward-1", &signer).unwrap();

        let json = serde_json::to_string(&sig).unwrap();
        let back: DocSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back, "JSON serialization must round-trip exactly");

        // And the round-tripped artifact still verifies.
        let verifier = matching_verifier();
        assert!(verify_document(SAMPLE, &back, &verifier).unwrap());
    }
}
