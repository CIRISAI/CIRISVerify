//! Federation message envelope — the authenticated transport-identity
//! binding substrate (CIRISVerify#27, v2.9.0+).
//!
//! ## What this is
//!
//! Reticulum (and any mesh transport) addresses peers by a *transport
//! identity* — `hash(x25519‖ed25519)` — which is **not** the federation
//! Ed25519 `key_id` (AV-17: the federation seed must never enter the
//! transport process). A sender calling `send(key_id, …)` needs an
//! authenticated binding "transport-identity T belongs to federation-key
//! K". An unauthenticated mesh announce is spoofable (**AV-42**): any
//! peer can announce `key_id=K` at its own destination and intercept.
//!
//! **Option C′** carries the binding as a signature-covered field of
//! this envelope. Every federation message is a [`FederationEnvelope`],
//! hybrid-signed (Ed25519 + ML-DSA-65) by the sender's federation key.
//! Verifying the envelope — which a recipient does anyway — yields, as a
//! byproduct, an authenticated statement: *"key K asserts its transport
//! identity is T."* No separate attestation artifact, no directory
//! schema migration.
//!
//! ## What this is NOT
//!
//! The binding is **routing-only**. Per `MISSION.md` §1.4 — every
//! federation primitive authenticates *origin*; none confers *trust* —
//! learning where K is reachable says nothing about whether K should be
//! trusted. A verified envelope from a never-seen `key_id` lands that
//! entity at trust-degree = default-untrusted. Routing is not a
//! privilege; `purpose` (below) is a plain discriminant and does **not**
//! gate whether the binding may be consumed as routing.
//!
//! ## Canonical bytes
//!
//! The hybrid signature covers [`FederationEnvelope::signing_bytes`]:
//! `domain_sep · schema_version · sender_key_id · recipient_key_id ·
//! purpose · transport_epoch · sender_transport_identities · payload`.
//! The `domain_sep` constant ([`ENVELOPE_DOMAIN_SEP`]) prevents a
//! transport-identity-shaped field in any *other* signed primitive (an
//! STH, a build manifest) from ever parsing as an envelope binding — it
//! is what closes the AV-8 cross-primitive confused-deputy concern.
//!
//! ## Replay defense
//!
//! `transport_epoch` is a per-`key_id` monotonic counter. A replayed
//! *older* envelope carries a *lower* epoch; [`TransportEpochGuard`]
//! rejects it, so a stale (possibly adversary-controlled) transport
//! identity cannot be replayed back over a newer binding. This mirrors
//! the `revocation_revision` anti-rollback rule.
//!
//! ## Rollout (v2.9.0)
//!
//! `sender_transport_identities` is **advisory** in v2.9.0 — an empty
//! list is valid (no binding asserted), recipients tolerate it. A later
//! release makes a non-empty binding required after a fleet floor
//! version + flag day (CIRISVerify#28 Phase 4).

use std::collections::HashMap;
use std::sync::RwLock;

use ciris_crypto::{
    ClassicalSigner, ClassicalVerifier, HybridSignature, HybridSigner, HybridVerifier, PqcSigner,
    PqcVerifier,
};
use serde::{Deserialize, Serialize};

use crate::error::VerifyError;

/// RFC-6962-style domain-separation prefix for envelope signing bytes.
///
/// Every byte string this module hands to the hybrid signer begins with
/// this constant. Because no other CIRIS signed primitive
/// (`SignedTreeHead`, `TransparencyEntry`, `CanonicalBuild`) begins its
/// canonical bytes with it, an envelope signature can never be confused
/// with — or harvested from — a different primitive. Changing this
/// constant is a coordinated wire-format break.
pub const ENVELOPE_DOMAIN_SEP: &[u8] = b"CIRIS-FED-ENVELOPE-V1";

/// Current envelope canonical-bytes schema version. Bumped only on an
/// incompatible layout change; the value is inside the signed bytes so a
/// verifier can never be fooled into reading new bytes as old.
pub const ENVELOPE_SCHEMA_VERSION: u8 = 1;

/// An opaque transport identity — for Reticulum, the destination
/// `hash(x25519‖ed25519)`.
///
/// CIRISVerify carries and signs these bytes; it does **not** interpret
/// them. The exact encoding (destination hash vs. dual public keys) is
/// the transport layer's concern (CIRISEdge). Keeping it opaque is the
/// correct layering — CIRISVerify owns the canonical-bytes *framing*,
/// edge owns the transport *semantics*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportIdentity(pub Vec<u8>);

/// Envelope purpose — a stable-tagged discriminant.
///
/// CIRISVerify treats `purpose` opaquely. It exists for envelope typing
/// and for downstream routing rules (e.g. CIRISEdge gating one-way
/// broadcast classes), but it does **not** gate whether the
/// transport-identity binding may be consumed as routing — see the
/// module docs and `MISSION.md` §1.4. The value-set is a downstream
/// federation enumeration, not pinned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopePurpose(pub u16);

impl EnvelopePurpose {
    /// Sentinel for an envelope whose purpose the producer left unset.
    pub const UNSPECIFIED: EnvelopePurpose = EnvelopePurpose(0);
}

/// Verification policy for [`FederationEnvelope::verify_with_policy`] —
/// the advisory→required rollout control (CIRISVerify#28 Phase 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeVerifyPolicy {
    /// Accept an envelope that asserts no transport identity. The
    /// v2.9.0+ rollout state — `sender_transport_identities` is
    /// advisory while the fleet is mixed-version.
    Advisory,
    /// Reject an envelope with an empty `sender_transport_identities`.
    /// The enforced state, switched on fleet-wide once the floor
    /// version is met (the #28 Phase 4 cutover).
    RequireTransportBinding,
}

/// A federation message envelope: a payload plus the sender's
/// authenticated transport-identity binding, hybrid-signed by the
/// sender's federation key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationEnvelope {
    /// Canonical-bytes schema version. See [`ENVELOPE_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Federation `key_id` of the signer.
    pub sender_key_id: String,
    /// Federation `key_id` this envelope is addressed to. A recipient
    /// drops envelopes not addressed to it — see [`Self::is_addressed_to`].
    pub recipient_key_id: String,
    /// Envelope purpose discriminant.
    pub purpose: EnvelopePurpose,
    /// Per-`sender_key_id` monotonic counter. See [`TransportEpochGuard`].
    pub transport_epoch: u64,
    /// The sender's transport identities (a flat set — one identity per
    /// interface a multi-homed member is reachable on). **Advisory in
    /// v2.9.0**: an empty list means "no binding asserted".
    #[serde(default)]
    pub sender_transport_identities: Vec<TransportIdentity>,
    /// Opaque application payload.
    pub payload: Vec<u8>,
    /// Hybrid Ed25519 + ML-DSA-65 signature over [`Self::signing_bytes`].
    pub signature: HybridSignature,
}

/// Append a `u32`-length-prefixed byte string. Length-prefixing every
/// variable field makes the concatenation unambiguous — no field's
/// content can be read as another field's framing.
fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(u32::try_from(bytes.len()).unwrap_or(u32::MAX)).to_le_bytes());
    buf.extend_from_slice(bytes);
}

impl FederationEnvelope {
    /// Canonical bytes the hybrid signature covers.
    ///
    /// Layout: `domain_sep · schema_version · LP(sender_key_id) ·
    /// LP(recipient_key_id) · purpose(u16 LE) · transport_epoch(u64 LE) ·
    /// count(u32 LE) · LP(identity)* · LP(payload)`, where `LP` is a
    /// `u32`-length-prefixed byte string. Deterministic — two honest
    /// implementations produce identical bytes for identical inputs.
    #[must_use]
    pub fn signing_bytes(
        schema_version: u8,
        sender_key_id: &str,
        recipient_key_id: &str,
        purpose: EnvelopePurpose,
        transport_epoch: u64,
        transport_identities: &[TransportIdentity],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ENVELOPE_DOMAIN_SEP.len() + 64 + payload.len());
        buf.extend_from_slice(ENVELOPE_DOMAIN_SEP);
        buf.push(schema_version);
        push_lp(&mut buf, sender_key_id.as_bytes());
        push_lp(&mut buf, recipient_key_id.as_bytes());
        buf.extend_from_slice(&purpose.0.to_le_bytes());
        buf.extend_from_slice(&transport_epoch.to_le_bytes());
        buf.extend_from_slice(
            &(u32::try_from(transport_identities.len()).unwrap_or(u32::MAX)).to_le_bytes(),
        );
        for ti in transport_identities {
            push_lp(&mut buf, &ti.0);
        }
        push_lp(&mut buf, payload);
        buf
    }

    /// The signing bytes for this envelope's own fields.
    #[must_use]
    pub fn signing_bytes_of(&self) -> Vec<u8> {
        Self::signing_bytes(
            self.schema_version,
            &self.sender_key_id,
            &self.recipient_key_id,
            self.purpose,
            self.transport_epoch,
            &self.sender_transport_identities,
            &self.payload,
        )
    }

    /// Construct + hybrid-sign a federation envelope.
    ///
    /// # Errors
    ///
    /// [`VerifyError::CryptoError`] if the hybrid signer fails.
    #[allow(clippy::too_many_arguments)]
    pub fn seal<C, P>(
        signer: &HybridSigner<C, P>,
        sender_key_id: impl Into<String>,
        recipient_key_id: impl Into<String>,
        purpose: EnvelopePurpose,
        transport_epoch: u64,
        sender_transport_identities: Vec<TransportIdentity>,
        payload: Vec<u8>,
    ) -> Result<Self, VerifyError>
    where
        C: ClassicalSigner,
        P: PqcSigner,
    {
        let sender_key_id = sender_key_id.into();
        let recipient_key_id = recipient_key_id.into();
        let bytes = Self::signing_bytes(
            ENVELOPE_SCHEMA_VERSION,
            &sender_key_id,
            &recipient_key_id,
            purpose,
            transport_epoch,
            &sender_transport_identities,
            &payload,
        );
        let signature = signer.sign(&bytes)?;
        Ok(Self {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            sender_key_id,
            recipient_key_id,
            purpose,
            transport_epoch,
            sender_transport_identities,
            payload,
            signature,
        })
    }

    /// Verify the envelope's hybrid signature over its canonical bytes.
    ///
    /// `Ok(())` means the envelope is authentically from `sender_key_id`
    /// — **authentication only**; it says nothing about whether the
    /// sender is *trusted* (`MISSION.md` §1.4). Any `Err` — a signature
    /// mismatch, a malformed signature, a crypto fault — means the
    /// envelope's origin is unestablished; fail-secure, the caller must
    /// not act on it and must not learn its transport binding.
    ///
    /// # Errors
    ///
    /// [`VerifyError::CryptoError`] if either signature half does not
    /// verify or the verifier faults. (`HybridVerifier::verify` reports
    /// a mismatch as `Err`, never as `Ok(false)` — so success here is
    /// unambiguous and carries no `bool`.)
    pub fn verify<C, P>(&self, verifier: &HybridVerifier<C, P>) -> Result<(), VerifyError>
    where
        C: ClassicalVerifier,
        P: PqcVerifier,
    {
        self.verify_with_policy(verifier, EnvelopeVerifyPolicy::Advisory)
    }

    /// Verify the envelope under an explicit [`EnvelopeVerifyPolicy`] —
    /// the enforcement-capable verify path (CIRISVerify#28 Phase 4).
    ///
    /// [`EnvelopeVerifyPolicy::Advisory`] (what [`Self::verify`] uses)
    /// accepts an envelope with no `sender_transport_identities` — the
    /// v2.9.0 rollout state. [`EnvelopeVerifyPolicy::RequireTransportBinding`]
    /// additionally rejects an envelope that asserts no binding: it is
    /// the verify-side half of the advisory→required cutover, to be
    /// switched on fleet-wide once the floor version is met (#28
    /// Phase 4). The signature check is identical under both policies;
    /// the policy only gates the *presence* of the binding.
    ///
    /// # Errors
    ///
    /// [`VerifyError::CryptoError`] on a signature failure (as
    /// [`Self::verify`]); [`VerifyError::IntegrityError`] if the policy
    /// is `RequireTransportBinding` and `sender_transport_identities` is
    /// empty.
    pub fn verify_with_policy<C, P>(
        &self,
        verifier: &HybridVerifier<C, P>,
        policy: EnvelopeVerifyPolicy,
    ) -> Result<(), VerifyError>
    where
        C: ClassicalVerifier,
        P: PqcVerifier,
    {
        verifier.verify(&self.signing_bytes_of(), &self.signature)?;
        if policy == EnvelopeVerifyPolicy::RequireTransportBinding
            && self.sender_transport_identities.is_empty()
        {
            return Err(VerifyError::IntegrityError {
                message: "FederationEnvelope asserts no transport identity \
                          (policy: RequireTransportBinding)"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Whether this envelope is addressed to `my_key_id`. A recipient
    /// drops envelopes that are not (finding B — prevents a relayed
    /// envelope being ingested by a third party it was not sent to).
    #[must_use]
    pub fn is_addressed_to(&self, my_key_id: &str) -> bool {
        self.recipient_key_id == my_key_id
    }
}

/// Per-`key_id` monotonic `transport_epoch` watermark — the replay
/// defense for the transport-identity binding (AV-42).
///
/// A recipient feeds every authenticated envelope through [`Self::admit`].
/// An envelope whose `transport_epoch` is **below** the highest already
/// seen for its `sender_key_id` is rejected: it is a replayed older
/// envelope, and admitting it would let a stale transport identity
/// overwrite a newer binding. An equal epoch is allowed (idempotent
/// re-delivery is normal on a mesh); a higher epoch advances the
/// watermark.
///
/// Mirrors the `revocation_revision` anti-rollback rule.
#[derive(Debug, Default)]
pub struct TransportEpochGuard {
    seen: RwLock<HashMap<String, u64>>,
}

impl TransportEpochGuard {
    /// A fresh guard with no watermarks.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit an envelope's `(key_id, transport_epoch)`.
    ///
    /// # Errors
    ///
    /// [`VerifyError::TransportEpochRollback`] if `epoch` is below the
    /// highest previously admitted for `key_id`.
    /// [`VerifyError::IntegrityError`] if the internal lock is poisoned.
    pub fn admit(&self, key_id: &str, epoch: u64) -> Result<(), VerifyError> {
        let mut seen = self.seen.write().map_err(|_| VerifyError::IntegrityError {
            message: "TransportEpochGuard lock poisoned".to_string(),
        })?;
        match seen.get(key_id).copied() {
            Some(high) if epoch < high => Err(VerifyError::TransportEpochRollback {
                key_id: key_id.to_string(),
                attempted: epoch,
                highest_seen: high,
            }),
            Some(high) => {
                // epoch >= high — advance (or hold on equal).
                if epoch > high {
                    seen.insert(key_id.to_string(), epoch);
                }
                Ok(())
            },
            None => {
                seen.insert(key_id.to_string(), epoch);
                Ok(())
            },
        }
    }

    /// The highest epoch admitted for `key_id`, if any.
    #[must_use]
    pub fn highest(&self, key_id: &str) -> Option<u64> {
        self.seen.read().ok().and_then(|s| s.get(key_id).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{
        ClassicalAlgorithm, Ed25519Signer, Ed25519Verifier, MlDsa65Signer, MlDsa65Verifier,
        PqcAlgorithm,
    };

    fn ti(bytes: &[u8]) -> TransportIdentity {
        TransportIdentity(bytes.to_vec())
    }

    // ---- canonical bytes -------------------------------------------------

    #[test]
    fn signing_bytes_begin_with_domain_sep() {
        let b = FederationEnvelope::signing_bytes(1, "k", "r", EnvelopePurpose(0), 0, &[], b"");
        assert!(b.starts_with(ENVELOPE_DOMAIN_SEP));
    }

    #[test]
    fn signing_bytes_deterministic() {
        let mk = || {
            FederationEnvelope::signing_bytes(
                1,
                "sender-a",
                "recipient-b",
                EnvelopePurpose(7),
                42,
                &[ti(b"dest-1"), ti(b"dest-2")],
                b"payload",
            )
        };
        assert_eq!(mk(), mk());
    }

    #[test]
    fn signing_bytes_sensitive_to_every_field() {
        let base = FederationEnvelope::signing_bytes(
            1,
            "s",
            "r",
            EnvelopePurpose(1),
            5,
            &[ti(b"d")],
            b"p",
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(
                2,
                "s",
                "r",
                EnvelopePurpose(1),
                5,
                &[ti(b"d")],
                b"p"
            )
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(
                1,
                "S",
                "r",
                EnvelopePurpose(1),
                5,
                &[ti(b"d")],
                b"p"
            )
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(
                1,
                "s",
                "R",
                EnvelopePurpose(1),
                5,
                &[ti(b"d")],
                b"p"
            )
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(
                1,
                "s",
                "r",
                EnvelopePurpose(2),
                5,
                &[ti(b"d")],
                b"p"
            )
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(
                1,
                "s",
                "r",
                EnvelopePurpose(1),
                6,
                &[ti(b"d")],
                b"p"
            )
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(
                1,
                "s",
                "r",
                EnvelopePurpose(1),
                5,
                &[ti(b"e")],
                b"p"
            )
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(1, "s", "r", EnvelopePurpose(1), 5, &[], b"p")
        );
        assert_ne!(
            base,
            FederationEnvelope::signing_bytes(
                1,
                "s",
                "r",
                EnvelopePurpose(1),
                5,
                &[ti(b"d")],
                b"q"
            )
        );
    }

    /// Length-prefixing must make field boundaries unambiguous — moving
    /// a byte across the sender/recipient boundary changes the bytes.
    #[test]
    fn signing_bytes_no_field_boundary_ambiguity() {
        let a = FederationEnvelope::signing_bytes(1, "ab", "c", EnvelopePurpose(0), 0, &[], b"");
        let b = FederationEnvelope::signing_bytes(1, "a", "bc", EnvelopePurpose(0), 0, &[], b"");
        assert_ne!(a, b, "field boundary must be unambiguous");
    }

    // ---- sign / verify ---------------------------------------------------

    fn signer() -> HybridSigner<Ed25519Signer, MlDsa65Signer> {
        HybridSigner::new(
            Ed25519Signer::random().unwrap(),
            MlDsa65Signer::new().expect("ml-dsa signer"),
        )
        .expect("hybrid signer")
    }

    #[test]
    fn seal_then_verify_round_trip() {
        let s = signer();
        let env = FederationEnvelope::seal(
            &s,
            "agent-x",
            "agent-y",
            EnvelopePurpose(3),
            10,
            vec![ti(b"reticulum-dest-hash")],
            b"hello federation".to_vec(),
        )
        .unwrap();
        assert_eq!(env.schema_version, ENVELOPE_SCHEMA_VERSION);
        let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());
        assert!(env.verify(&verifier).is_ok(), "sealed envelope must verify");
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let s = signer();
        let mut env = FederationEnvelope::seal(
            &s,
            "a",
            "b",
            EnvelopePurpose(0),
            1,
            vec![],
            b"original".to_vec(),
        )
        .unwrap();
        env.payload = b"tampered".to_vec();
        let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());
        assert!(
            env.verify(&verifier).is_err(),
            "tampered payload must not verify"
        );
    }

    #[test]
    fn tampered_transport_identity_fails_verify() {
        let s = signer();
        let mut env = FederationEnvelope::seal(
            &s,
            "a",
            "b",
            EnvelopePurpose(0),
            1,
            vec![ti(b"real-dest")],
            b"p".to_vec(),
        )
        .unwrap();
        // An adversary swaps in its own destination.
        env.sender_transport_identities = vec![ti(b"adversary-dest")];
        let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());
        assert!(
            env.verify(&verifier).is_err(),
            "the binding is signature-covered — swapping it must break verification"
        );
    }

    #[test]
    fn empty_transport_identities_is_valid_advisory() {
        let s = signer();
        let env =
            FederationEnvelope::seal(&s, "a", "b", EnvelopePurpose(0), 0, vec![], b"p".to_vec())
                .unwrap();
        assert!(env.sender_transport_identities.is_empty());
        let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());
        assert!(
            env.verify(&verifier).is_ok(),
            "advisory empty binding is valid"
        );
    }

    #[test]
    fn require_transport_binding_rejects_empty() {
        let s = signer();
        let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());

        // Empty binding: ok under Advisory, rejected under enforcement.
        let bare =
            FederationEnvelope::seal(&s, "a", "b", EnvelopePurpose(0), 0, vec![], b"p".to_vec())
                .unwrap();
        assert!(bare
            .verify_with_policy(&verifier, EnvelopeVerifyPolicy::Advisory)
            .is_ok());
        assert!(
            bare.verify_with_policy(&verifier, EnvelopeVerifyPolicy::RequireTransportBinding)
                .is_err(),
            "an envelope asserting no binding must fail enforced verification"
        );

        // A non-empty binding passes under both policies.
        let bound = FederationEnvelope::seal(
            &s,
            "a",
            "b",
            EnvelopePurpose(0),
            0,
            vec![ti(b"dest")],
            b"p".to_vec(),
        )
        .unwrap();
        assert!(bound
            .verify_with_policy(&verifier, EnvelopeVerifyPolicy::RequireTransportBinding)
            .is_ok());
    }

    #[test]
    fn enforcement_policy_still_checks_the_signature() {
        // RequireTransportBinding must not weaken the signature check:
        // a tampered envelope fails regardless of the binding.
        let s = signer();
        let mut env = FederationEnvelope::seal(
            &s,
            "a",
            "b",
            EnvelopePurpose(0),
            1,
            vec![ti(b"dest")],
            b"orig".to_vec(),
        )
        .unwrap();
        env.payload = b"tampered".to_vec();
        let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());
        assert!(env
            .verify_with_policy(&verifier, EnvelopeVerifyPolicy::RequireTransportBinding)
            .is_err());
    }

    #[test]
    fn is_addressed_to() {
        let s = signer();
        let env = FederationEnvelope::seal(
            &s,
            "a",
            "agent-y",
            EnvelopePurpose(0),
            0,
            vec![],
            b"p".to_vec(),
        )
        .unwrap();
        assert!(env.is_addressed_to("agent-y"));
        assert!(!env.is_addressed_to("agent-z"));
    }

    // ---- transport-epoch guard ------------------------------------------

    #[test]
    fn epoch_guard_admits_monotonic() {
        let g = TransportEpochGuard::new();
        assert!(g.admit("k", 1).is_ok());
        assert!(g.admit("k", 2).is_ok());
        assert!(g.admit("k", 100).is_ok());
        assert_eq!(g.highest("k"), Some(100));
    }

    #[test]
    fn epoch_guard_allows_equal_epoch() {
        // Idempotent re-delivery (normal on a mesh) carries the same epoch.
        let g = TransportEpochGuard::new();
        assert!(g.admit("k", 5).is_ok());
        assert!(
            g.admit("k", 5).is_ok(),
            "equal epoch is idempotent re-delivery"
        );
    }

    #[test]
    fn epoch_guard_rejects_rollback() {
        let g = TransportEpochGuard::new();
        g.admit("k", 10).unwrap();
        let err = g.admit("k", 9).unwrap_err();
        match err {
            VerifyError::TransportEpochRollback {
                key_id,
                attempted,
                highest_seen,
            } => {
                assert_eq!(key_id, "k");
                assert_eq!(attempted, 9);
                assert_eq!(highest_seen, 10);
            },
            other => panic!("expected TransportEpochRollback, got {other:?}"),
        }
        // The watermark is unmoved by a rejected envelope.
        assert_eq!(g.highest("k"), Some(10));
    }

    #[test]
    fn epoch_guard_is_per_key_id() {
        let g = TransportEpochGuard::new();
        g.admit("key-a", 50).unwrap();
        // A different key_id has its own independent watermark.
        assert!(g.admit("key-b", 1).is_ok());
    }

    /// `signer` uses Ed25519 + ML-DSA-65 — confirm the hybrid algorithms
    /// are what the federation mandates (PQC day one).
    #[test]
    fn envelope_uses_hybrid_pq_signature() {
        let s = signer();
        let env =
            FederationEnvelope::seal(&s, "a", "b", EnvelopePurpose(0), 0, vec![], b"p".to_vec())
                .unwrap();
        assert_eq!(
            env.signature.classical.algorithm,
            ClassicalAlgorithm::Ed25519
        );
        assert_eq!(env.signature.pqc.algorithm, PqcAlgorithm::MlDsa65);
    }
}
