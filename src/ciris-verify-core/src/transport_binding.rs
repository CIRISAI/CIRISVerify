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
//!    `destination_hash` to recompute from `reticulum_x25519_pubkey`,
//!    `reticulum_ed25519_pubkey`, `app_name`, and `aspects` per the
//!    **§5.6.8.8.1.1 pinned two-stage RNS algorithm** (1.0-RC6 reproduced
//!    the RNS construction in-spec, resolving CIRISVerify#28). On top of
//!    (1) — which covers a forged-and-resigned hash because it changes the
//!    JCS bytes — [`verify_destination_hash`] now recomputes the hash and
//!    returns [`DestinationHashCheck::Match`] / [`DestinationHashCheck::Mismatch`],
//!    catching the orthogonal case of a producer whose own hash is
//!    inconsistent with its pubkeys / `app_name` / `aspects`. A mismatch
//!    MUST be treated as an unauthenticated (advisory-only) announce.
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

/// Produce the detached hybrid signature over an `identity_occurrence`
/// envelope — the **byte-exact producer** for what [`verify_transport_binding`]
/// verifies. There was no producer before this: every occurrence envelope was
/// hand-rolled, so producer/verifier coherence rested on each call site.
///
/// `occurrence_envelope` is the EXACT member set to sign (§0.9 presence,
/// omit-vs-materialize), with **no signature container** — the same value the
/// verifier will JCS-canonicalize. The signature is Ed25519 over
/// `JCS(occurrence_envelope)`, then ML-DSA-65 over `JCS_bytes ‖ ed25519_sig`
/// (the bound-sig discipline `verify_transport_binding` re-checks), produced
/// via the identity's [`SelfSigner::sign_bound`](crate::self_at_login::SelfSigner::sign_bound) so any custody tier
/// (hardware-sealed or software) drives it identically.
///
/// Returns the (unchanged) envelope alongside its [`TransportBindingSignature`],
/// so a caller assembles a [`TransportBinding`] / occurrence record without
/// re-canonicalizing. This is the producer CIRISPersist's signed-occurrence
/// admission (arc 2/4) verifies and CIRISServer's boot self-publish (arc 4/4)
/// calls (CIRISVerify#183).
///
/// # Errors
/// [`VerifyError`] on a JCS canonicalization or signer fault.
pub async fn produce_signed_identity_occurrence(
    signer: &dyn crate::self_at_login::SelfSigner,
    occurrence_envelope: Value,
) -> Result<(Value, TransportBindingSignature), VerifyError> {
    let bytes = jcs::canonicalize(&occurrence_envelope)?;
    let (ed25519_signature_base64, mldsa65_signature_base64) = signer.sign_bound(&bytes).await?;
    Ok((
        occurrence_envelope,
        TransportBindingSignature {
            ed25519_signature_base64,
            mldsa65_signature_base64: Some(mldsa65_signature_base64),
        },
    ))
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
    /// recomputes per §5.6.8.8.1.1 (carries
    /// [`DestinationHashCheck::Match`]).
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
    /// The signature + key-separation checks passed, but the bound
    /// `destination_hash` does NOT recompute from the pubkeys / `app_name`
    /// / `aspects` per the §5.6.8.8.1.1 two-stage RNS algorithm (or an
    /// aspect contained an illegal `.`). Per §8.1.13.1.1(b) the consumer
    /// MUST treat this as an unauthenticated (advisory-only) announce.
    DestinationHashMismatch,
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
    /// Result of the §5.6.8.8.1.1 `destination_hash` recompute.
    /// [`DestinationHashCheck::Match`] on an authentic verdict;
    /// [`DestinationHashCheck::Mismatch`] when the producer's hash is
    /// inconsistent with its pubkeys / `app_name` / `aspects`;
    /// [`DestinationHashCheck::Unsupported`] when the binding was rejected
    /// before the recompute was reached.
    pub destination_hash_check: DestinationHashCheck,
}

/// Outcome of the `destination_hash == RNS_hash(...)` recompute
/// (§5.6.8.8.1 conformance point 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationHashCheck {
    /// The recompute did not run for this verdict — the binding was
    /// rejected on a structurally-earlier check (malformed field, unknown
    /// signer, key-separation, bad signature), so the §5.6.8.8.1.1
    /// recompute was never reached. Carried only on a non-authentic
    /// verdict; an authentic verdict always carries `Match`.
    Unsupported,
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

    // ---- (3) destination_hash recompute — §5.6.8.8.1.1 two-stage RNS ----
    // §8.1.13.1.1(b) REQUIREs destination_hash == rns_destination_hash(...);
    // a mismatch is fail-closed (advisory-only announce, never authentic).
    let destination_hash_check = verify_destination_hash(&binding.transport_destination);
    if destination_hash_check != DestinationHashCheck::Match {
        return Ok(TransportBindingVerdict {
            authentic: false,
            reason: TransportBindingReason::DestinationHashMismatch,
            destination_hash_check: DestinationHashCheck::Mismatch,
        });
    }

    Ok(TransportBindingVerdict {
        authentic: true,
        reason: TransportBindingReason::Verified,
        destination_hash_check,
    })
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
                ed: Ed25519Signer::random().unwrap(),
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
        let app_name = "ciris.federation";
        let aspects = ["announce", "v1"];
        // Derivation-consistent hash per §5.6.8.8.1.1 — so a well-formed
        // fixture verifies (Match). A test that wants a Mismatch tampers
        // this field after the fact.
        let dest_hash = rns_destination_hash(transport_x, transport_ed, app_name, &aspects);
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(transport_x),
            reticulum_ed25519_pubkey_base64: b64().encode(transport_ed),
            destination_hash_base64: b64().encode(&dest_hash),
            app_name: app_name.to_string(),
            aspects: aspects.iter().map(|s| (*s).to_string()).collect(),
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
        // The §5.6.8.8.1.1 hash recompute matches the derivation-consistent
        // fixture hash.
        assert_eq!(v.destination_hash_check, DestinationHashCheck::Match);
    }

    #[tokio::test]
    async fn producer_output_verifies_through_the_real_verifier() {
        use crate::self_at_login::HybridSigningIdentity;

        // The producer signs with a SelfSigner (any custody tier). Build a
        // software identity and pin ITS pubkeys in the directory.
        let identity = HybridSigningIdentity::new(
            "steward-us",
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().unwrap(),
        );
        let dir = vec![identity.directory_member().unwrap()];

        // A well-formed occurrence envelope (same shape make_binding signs),
        // with a derivation-consistent §5.6.8.8.1.1 hash and distinct
        // transport-x vs content-KEM-x (C4).
        let (transport_ed, transport_x, content_x) =
            (pubkey_bytes(0x01), pubkey_bytes(0x02), pubkey_bytes(0x03));
        let app_name = "ciris.federation";
        let aspects = ["announce", "v1"];
        let dest_hash = rns_destination_hash(&transport_x, &transport_ed, app_name, &aspects);
        let td = TransportDestination {
            reticulum_x25519_pubkey_base64: b64().encode(&transport_x),
            reticulum_ed25519_pubkey_base64: b64().encode(&transport_ed),
            destination_hash_base64: b64().encode(&dest_hash),
            app_name: app_name.to_string(),
            aspects: aspects.iter().map(|s| (*s).to_string()).collect(),
        };
        let enc = EncryptionPubkeys {
            x25519_base64: b64().encode(&content_x),
            ml_kem_768_base64: b64().encode(vec![0x11u8; 1184]),
        };
        let envelope = json!({
            "attestation_type": "scores",
            "subject_kind": "identity_occurrence",
            "attesting_key_id": "steward-us",
            "identity_key_id": "steward-us",
            "occurrence_key_id": "occ-key-1",
            "device_class": "agent",
            "transport_destination": {
                "reticulum_x25519_pubkey": td.reticulum_x25519_pubkey_base64,
                "reticulum_ed25519_pubkey": td.reticulum_ed25519_pubkey_base64,
                "destination_hash": td.destination_hash_base64,
                "app_name": td.app_name,
                "aspects": td.aspects,
            },
            "encryption_pubkeys": {
                "x25519_base64": enc.x25519_base64,
                "ml_kem_768_base64": enc.ml_kem_768_base64,
            },
            "asserted_at": "2026-06-14T00:00:00.000Z",
            "signed_at": "2026-06-14T00:00:00.000Z",
        });

        // Produce, then verify through the REAL verifier — no hand-rolled sig.
        let (signed_envelope, signature) = produce_signed_identity_occurrence(&identity, envelope)
            .await
            .unwrap();
        let binding = TransportBinding {
            attesting_key_id: "steward-us".to_string(),
            signed_envelope,
            transport_destination: td,
            encryption_pubkeys: Some(enc),
            signature,
        };
        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(v.authentic, "producer output must verify: {:?}", v.reason);
        assert_eq!(v.reason, TransportBindingReason::Verified);
        assert_eq!(v.destination_hash_check, DestinationHashCheck::Match);
        // The producer emits BOTH halves (hybrid, not classical-pending).
        assert!(binding.signature.mldsa65_signature_base64.is_some());
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

    #[test]
    fn binding_with_wrong_destination_hash_is_not_authentic() {
        // End-to-end: a signed, key-separated binding whose destination_hash
        // is NOT derivation-consistent must fail-closed (§8.1.13.1.1(b)).
        let signer = Signer::random();
        let dir = vec![signer.directory_member("steward-us")];
        let mut binding = make_binding(
            &signer,
            "steward-us",
            &pubkey_bytes(0x01),
            &pubkey_bytes(0x02),
            None,
        );

        // Replace the (correct) hash with a wrong one, then RE-SIGN so the
        // signature still verifies — isolating the hash-derivation check
        // from the signature check.
        binding.transport_destination.destination_hash_base64 =
            b64().encode(vec![0xCDu8; DESTINATION_HASH_LEN]);
        binding.signed_envelope["transport_destination"]["destination_hash"] =
            json!(binding.transport_destination.destination_hash_base64);
        let bytes = jcs::canonicalize(&binding.signed_envelope).unwrap();
        binding.signature = signer.sign(&bytes);

        let v = verify_transport_binding(&binding, &dir).unwrap();
        assert!(
            !v.authentic,
            "a signed binding with a non-derivation-consistent hash must reject"
        );
        assert_eq!(v.reason, TransportBindingReason::DestinationHashMismatch);
        assert_eq!(v.destination_hash_check, DestinationHashCheck::Mismatch);
    }

    #[test]
    fn hybrid_pending_classical_only_signature_rejected() {
        // RC7 §10.1.5.1.1 / F-AV-14: a transport_destination binding is a
        // federation-tier identity binding (AV-17 / AV-42). A binding with no
        // ML-DSA half (classical-only / hybrid-pending, or a stripped PQC
        // half) MUST NOT verify — accepting it would let a future Ed25519
        // break forge an authenticated announce.
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
        assert!(!v.authentic, "classical-only binding must be rejected");
        assert_eq!(v.reason, TransportBindingReason::SignatureInvalid);
    }
}
