//! Peer-presentable, peer-verifiable **build-attestation bundle** — the
//! presenter binding (CIRISVerify#181).
//!
//! ## The gap this closes
//!
//! Before this module verify had two halves that never met:
//!
//! - [`crate::manifest_contribution`] binds **pipeline → build M** (a CI key,
//!   accord-co-scrubbed, signs "this build is approved"). It says nothing about
//!   who is *presenting* it.
//! - [`crate::transport_binding`] binds **key K → transport identity T**. It says
//!   nothing about what code K runs.
//! - [`crate::registry::verify_self_against_manifest`] compares the running
//!   binary to a manifest — but it is a **local `bool`**, not a transmissible
//!   artifact. A peer cannot consume it.
//!
//! So a peer could verify *"this build is approved"* and *"this key owns that
//! address"*, but never **"the entity presenting this is the one running it."**
//! This module is that missing artifact: a **K-signed** object binding the
//! presenter's federation `key_id` to the pipeline-signed manifest it claims to
//! run, plus (optionally) an RFC 6962 inclusion proof that the manifest is in
//! the public transparency log.
//!
//! ## What it proves — and what it does NOT
//!
//! Stated honestly, because the boundary is the whole point:
//!
//! - **Proved:** the holder of K's federation private key signed *this*
//!   assertion, over *this* fresh envelope, referencing a manifest that
//!   **independently roots** to the accord anchors via the pipeline's co-scrub
//!   (CIRISVerify#185) — and, when an inclusion proof rides along, that the
//!   manifest is a logged leaf under the committed root.
//! - **NOT proved:** that the presenter is *actually executing* that binary.
//!   Remote code execution is not remotely provable. The presenter's claim is an
//!   **assertion**; its value is that it is *attributable* (signed by K) and
//!   *falsifiable* (it can be caught contradicting other evidence), not that it
//!   is self-certifying.
//!
//! Per CIRISVerify#181 this path is deliberately **SW-friendly**: no hardware,
//! no trust in the peer's self-report. The build facts are never read from the
//! presenter's claims — they come from the *pipeline-signed* manifest, which the
//! verifier re-roots itself. Hardware-rooted device attestation (StrongBox /
//! App Attest / TPM vendor chains) is the separate, complementary
//! CIRISVerify#199 leg and is intentionally absent here.
//!
//! ## Denial-of-service posture (load-bearing design constraint)
//!
//! This is a **cacheable artifact, not a live handshake**. That is the whole DoS
//! answer, and the shape is deliberate:
//!
//! - The producer runs on its **own** schedule (per epoch / per release), never
//!   on demand from a peer. Nothing here touches a hardware key, a TPM, or a
//!   rate-limited vendor attestation service, so a flood cannot exhaust a
//!   serialized resource or burn a daily quota.
//! - Verification is **cheap and offline**: signature checks plus a Merkle
//!   recompute. No network I/O, no unbounded work, no attacker-chosen program.
//! - The bundle is **self-contained and gossipable** — a third party can relay
//!   it, so the common case needs no round trip with the presenter at all.
//!
//! A verifier under load should serve or accept a cached bundle rather than
//! demanding a fresh one. Any future *live* challenge belongs behind
//! authentication and the [`crate::reconsider_dos`] budget primitives — never on
//! this path.
//!
//! ## Evidence is hash-bound, not inlined in the signed preimage
//!
//! The signed envelope commits to `sha256(JCS(manifest_contribution))`; the
//! manifest object itself rides in the **unsigned** outer `body` and is
//! recomputed + checked by the verifier. Same discipline as
//! [`crate::accord_custody_attestation`] (CIRISVerify#113/#116): the presenter's
//! signing preimage stays small and **independent of the manifest's size**, so a
//! hardware Ed25519 token with a single-shot input ceiling can produce this
//! bundle. Tampering with the carried evidence breaks the commitment.

use serde_json::{json, Value};

use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::federation_provenance::{dim, AttestationEntry};
use crate::federation_self_record::KeyRecord;
use crate::manifest_contribution::{
    verify_build_manifest_via_coscrub, ManifestRejection, VerifiedManifest,
};
use crate::self_at_login::SelfSigner;
use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};
use crate::transparency::{hash_leaf, verify_inclusion, MerkleProof};

/// CEG `kind` for a build-attestation bundle in the outbox / on the wire.
pub const BUILD_ATTESTATION_BUNDLE_KIND: &str = "build_attestation_bundle";

/// The evidence a presenter packages into a bundle.
pub struct BundleInputs<'a> {
    /// The pipeline-signed `build_manifest_contribution` for the build the
    /// presenter claims to run (CIRISVerify#185). Carried whole as hash-bound
    /// evidence; the verifier re-roots it independently.
    pub manifest_contribution: &'a SignedCegObject,
    /// Optional RFC 6962 inclusion proof placing the manifest in the
    /// transparency log. When present, the verifier checks the proof
    /// reconstructs, that its root matches the committed root, **and** that its
    /// leaf is this manifest — so a proof for an unrelated leaf cannot be
    /// bolted on.
    pub inclusion: Option<&'a MerkleProof>,
}

/// Canonical bytes of a carried manifest contribution — the one preimage both
/// the commitment and the transparency leaf derive from, so they cannot drift.
fn canonical_bytes(obj: &SignedCegObject) -> Result<Vec<u8>, VerifyError> {
    let value = serde_json::to_value(obj).map_err(|e| VerifyError::IntegrityError {
        message: format!("serialize manifest contribution: {e}"),
    })?;
    crate::jcs::canonicalize(&value)
}

/// `sha256(JCS(obj))`, hex — the commitment the presenter signs over carried
/// evidence. A public digest, so a plain comparison is correct (nothing secret
/// is being compared).
fn commitment_hex(obj: &SignedCegObject) -> Result<String, VerifyError> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(canonical_bytes(obj)?)))
}

/// Produce a build-attestation bundle signed by the **presenting** node.
///
/// `presenter` is the node's own federation hybrid identity — the binding this
/// object exists to create. The build facts are read out of
/// `inputs.manifest_contribution` (never invented here), so a produced bundle
/// cannot disagree with the manifest it carries.
///
/// Run this on your **own** schedule and cache the result; see the DoS note in
/// the module docs.
///
/// # Errors
///
/// [`VerifyError`] on a malformed manifest contribution, a canonicalization
/// fault, or a signer fault.
pub async fn produce_build_attestation_bundle(
    presenter: &dyn SelfSigner,
    inputs: &BundleInputs<'_>,
    signed_at: &str,
) -> Result<SignedCegObject, VerifyError> {
    let manifest_env = inputs
        .manifest_contribution
        .body
        .get("signed_envelope")
        .and_then(|e| e.get("build"))
        .ok_or_else(|| VerifyError::IntegrityError {
            message: "manifest contribution has no signed_envelope.build".into(),
        })?;
    let field = |name: &str| -> Result<String, VerifyError> {
        manifest_env
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| VerifyError::IntegrityError {
                message: format!("manifest contribution build.{name} missing"),
            })
    };
    let target = field("target")?;
    let build_id = field("build_id")?;

    let mut envelope = json!({
        "attestation_type": "scores",
        "attesting_key_id": presenter.key_id(),
        "dimension": dim::provenance_build_manifest(&target),
        "score": 1,
        "subject_key_ids": [build_id],
        "manifest_contribution_sha256": commitment_hex(inputs.manifest_contribution)?,
        "signed_at": signed_at,
    });

    // §0.9 materialize-when-present: the transparency root appears only when an
    // inclusion proof is actually carried, so a proof-less bundle reproduces a
    // stable, smaller envelope.
    if let Some(proof) = inputs.inclusion {
        envelope["transparency_root_sha256"] = json!(hex::encode(proof.root));
    }

    let signed = presenter.sign_envelope_async(envelope).await?;
    let mut body: Value =
        serde_json::to_value(&signed).map_err(|e| VerifyError::IntegrityError {
            message: format!("serialize bundle envelope: {e}"),
        })?;

    // Hash-bound evidence rides OUTSIDE the signed preimage.
    body["manifest_contribution"] =
        serde_json::to_value(inputs.manifest_contribution).map_err(|e| {
            VerifyError::IntegrityError {
                message: format!("serialize manifest contribution: {e}"),
            }
        })?;
    if let Some(proof) = inputs.inclusion {
        body["inclusion_proof"] =
            serde_json::to_value(proof).map_err(|e| VerifyError::IntegrityError {
                message: format!("serialize inclusion proof: {e}"),
            })?;
    }

    Ok(SignedCegObject::new(
        BUILD_ATTESTATION_BUNDLE_KIND,
        presenter.key_id(),
        signed_at,
        body,
    ))
}

// ===========================================================================
// Consumer side.
// ===========================================================================

/// Outcome of the RFC 6962 inclusion check. A measurement, not a verdict — the
/// consumer decides what (if anything) absence implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparencyCheck {
    /// No inclusion proof was carried. Not an error: the log leg is optional on
    /// the SW-friendly path (CIRISVerify#181).
    Absent,
    /// The proof reconstructs to its stated root, that root is the one the
    /// presenter signed over, and its leaf is the carried manifest.
    Verified,
    /// The proof does not reconstruct, its root disagrees with the signed
    /// commitment, or its leaf is **not** this manifest (a proof for an
    /// unrelated log entry).
    Invalid,
}

/// The trust-bearing facts of a verified bundle.
///
/// Deliberately **measurements, not levels** (`MISSION.md` §1.4): each field
/// states what was checked. No tier, score, or "attestation level" is composed
/// here — that is consumer policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVerdict {
    /// The federation `key_id` that signed the bundle — the **presenter**.
    pub presenter_key_id: String,
    /// The build facts, taken from the *pipeline-signed* manifest after it was
    /// independently re-rooted — never from the presenter's claims.
    pub build: VerifiedManifest,
    /// Result of the transparency-log inclusion check.
    pub transparency: TransparencyCheck,
}

/// Why a bundle was **not** accepted. Every variant is a hard reject; there is
/// no partial-trust path (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRejection {
    /// The object is not a `build_attestation_bundle`.
    WrongKind {
        /// The kind actually found.
        kind: String,
    },
    /// A required field is missing or the wrong type.
    Malformed {
        /// Which field.
        field: &'static str,
    },
    /// The presenter's bound-hybrid signature did not verify at threshold 1
    /// against its pinned pubkeys (RequireHybrid — federation tier).
    PresenterSignatureInvalid,
    /// The envelope's `attesting_key_id` is not the pinned presenter member —
    /// the caller pinned a different key than the bundle claims.
    PresenterKeyMismatch {
        /// The `attesting_key_id` in the envelope.
        envelope: String,
        /// The `member_id` of the pinned member.
        member: String,
    },
    /// The carried manifest does not hash to the commitment the presenter
    /// signed — the evidence was swapped after signing.
    EvidenceCommitmentMismatch,
    /// The carried manifest did not verify / did not root to the accord anchors.
    ManifestRejected(ManifestRejection),
    /// The presenter's envelope disagrees with the verified manifest (e.g. the
    /// `dimension` names a different target than the manifest attests) — a
    /// mismatched or forged subject.
    PresentedBuildDiverges {
        /// Which envelope field diverged.
        field: &'static str,
        /// What the verified manifest says.
        expected: String,
        /// What the envelope claims.
        found: String,
    },
}

impl std::fmt::Display for BundleRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKind { kind } => write!(f, "not a build_attestation_bundle (got {kind})"),
            Self::Malformed { field } => write!(f, "malformed bundle: field {field}"),
            Self::PresenterSignatureInvalid => write!(f, "presenter signature invalid"),
            Self::PresenterKeyMismatch { envelope, member } => write!(
                f,
                "presenter key mismatch: envelope {envelope}, pinned {member}"
            ),
            Self::EvidenceCommitmentMismatch => {
                write!(f, "carried manifest does not match the signed commitment")
            },
            Self::ManifestRejected(r) => write!(f, "carried manifest rejected: {r}"),
            Self::PresentedBuildDiverges {
                field,
                expected,
                found,
            } => write!(
                f,
                "presented build diverges on {field}: manifest {expected}, envelope {found}"
            ),
        }
    }
}

impl std::error::Error for BundleRejection {}

/// Pull a `&str` field from a JSON object, or [`BundleRejection::Malformed`].
fn str_field<'a>(v: &'a Value, field: &'static str) -> Result<&'a str, BundleRejection> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or(BundleRejection::Malformed { field })
}

/// Verify a peer's build-attestation bundle end-to-end.
///
/// The full chain (all fail-closed):
///
/// 1. `bundle` is a `build_attestation_bundle` with a well-formed envelope.
/// 2. The **presenter's** bound-hybrid signature verifies at threshold 1
///    against `presenter_member`, and the envelope's `attesting_key_id` **is**
///    that member — the presenter binding (the #65 / §8.1.12.7.1
///    identity-binding discipline: pubkeys come from the caller's directory,
///    never from the object).
/// 3. The carried manifest hashes to the signed `manifest_contribution_sha256`
///    commitment.
/// 4. The carried manifest independently verifies and roots to the accord
///    anchors via the pipeline co-scrub ([`verify_build_manifest_via_coscrub`]).
/// 5. The presenter's `dimension` matches the verified manifest's target —
///    the presenter cannot claim one build while carrying another's proof.
/// 6. If an inclusion proof is carried, it reconstructs, its root matches the
///    signed commitment, and its leaf is **this** manifest.
///
/// `presenter_member` / `pipeline_member` / `accord_anchor_members` are all
/// pinned by the **caller**. Nothing is trusted from the object itself.
///
/// Cheap and offline by construction — see the DoS note in the module docs.
///
/// # Errors
///
/// A [`BundleRejection`] naming the first failing step.
pub fn verify_build_attestation_bundle(
    bundle: &SignedCegObject,
    presenter_member: &ThresholdMember,
    pipeline_member: &ThresholdMember,
    pipeline_record: &KeyRecord,
    accord_anchor_members: &[ThresholdMember],
) -> Result<BundleVerdict, BundleRejection> {
    if bundle.kind != BUILD_ATTESTATION_BUNDLE_KIND {
        return Err(BundleRejection::WrongKind {
            kind: bundle.kind.clone(),
        });
    }

    // --- 1. Extract the signed envelope + its signatures. ---
    let env = bundle
        .body
        .get("signed_envelope")
        .ok_or(BundleRejection::Malformed {
            field: "signed_envelope",
        })?;
    let ed_sig = str_field(&bundle.body, "ed25519_signature_base64")?;
    let mldsa_sig = bundle
        .body
        .get("mldsa65_signature_base64")
        .and_then(Value::as_str);

    // --- 2. Presenter signature verifies AND binds to the pinned member. ---
    let attesting_key_id = str_field(env, "attesting_key_id")?;
    if attesting_key_id != presenter_member.member_id {
        return Err(BundleRejection::PresenterKeyMismatch {
            envelope: attesting_key_id.to_string(),
            member: presenter_member.member_id.clone(),
        });
    }
    let Ok(bytes) = crate::jcs::canonicalize(env) else {
        return Err(BundleRejection::PresenterSignatureInvalid);
    };
    let sig = ThresholdSignature {
        member_id: presenter_member.member_id.clone(),
        ed25519_signature_base64: ed_sig.to_string(),
        mldsa65_signature_base64: mldsa_sig.map(str::to_string),
    };
    if verify_threshold_signatures(&bytes, std::slice::from_ref(presenter_member), &[sig], 1)
        != Ok(1)
    {
        return Err(BundleRejection::PresenterSignatureInvalid);
    }

    // --- 3. Carried evidence matches the signed commitment. ---
    let manifest_value =
        bundle
            .body
            .get("manifest_contribution")
            .ok_or(BundleRejection::Malformed {
                field: "manifest_contribution",
            })?;
    let manifest: SignedCegObject =
        serde_json::from_value(manifest_value.clone()).map_err(|_| BundleRejection::Malformed {
            field: "manifest_contribution",
        })?;
    let committed = str_field(env, "manifest_contribution_sha256")?;
    let recomputed =
        commitment_hex(&manifest).map_err(|_| BundleRejection::EvidenceCommitmentMismatch)?;
    if committed != recomputed {
        return Err(BundleRejection::EvidenceCommitmentMismatch);
    }

    // --- 4. The manifest roots to the accord anchors on its own merits. ---
    let build = verify_build_manifest_via_coscrub(
        &manifest,
        pipeline_member,
        pipeline_record,
        accord_anchor_members,
    )
    .map_err(BundleRejection::ManifestRejected)?;

    // --- 5. The presenter's claim matches what the manifest actually attests. ---
    let claimed_dimension = str_field(env, "dimension")?;
    let expected_dimension = dim::provenance_build_manifest(&build.target);
    if claimed_dimension != expected_dimension {
        return Err(BundleRejection::PresentedBuildDiverges {
            field: "dimension",
            expected: expected_dimension,
            found: claimed_dimension.to_string(),
        });
    }

    // --- 6. Optional transparency-log inclusion. ---
    let transparency = match bundle.body.get("inclusion_proof") {
        None => TransparencyCheck::Absent,
        Some(raw) => {
            let parsed: Result<MerkleProof, _> = serde_json::from_value(raw.clone());
            match parsed {
                Err(_) => TransparencyCheck::Invalid,
                Ok(proof) => {
                    let root_committed = env
                        .get("transparency_root_sha256")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c == hex::encode(proof.root));
                    let leaf_is_this_manifest =
                        canonical_bytes(&manifest).is_ok_and(|b| hash_leaf(&b) == proof.leaf_hash);
                    if root_committed && leaf_is_this_manifest && verify_inclusion(&proof) {
                        TransparencyCheck::Verified
                    } else {
                        TransparencyCheck::Invalid
                    }
                },
            }
        },
    };

    Ok(BundleVerdict {
        presenter_key_id: attesting_key_id.to_string(),
        build,
        transparency,
    })
}

// ===========================================================================
// Scoring signal — what the consumer hands upstream.
// ===========================================================================

impl BundleVerdict {
    /// Project a verified bundle into [`AttestationEntry`] measurements — the
    /// signal a scoring consumer (CIRISServer's lens scoring path) ingests.
    ///
    /// **Measurements, not levels.** Each entry states one checked fact under an
    /// existing `provenance:*` dimension; no tier is composed and no new wire
    /// vocabulary is minted here. The `source_ref` carries the manifest hash so
    /// a scorer can correlate independent presenters of the same build — the
    /// input a source-independence gate
    /// ([`crate::holonomic::aggregation::effective_source_count`]) needs to tell
    /// N genuinely distinct attesters from one build echoed N times.
    #[must_use]
    pub fn to_attestation_entries(&self, attester: &str) -> Vec<AttestationEntry> {
        let mut entries = vec![AttestationEntry::pass(
            dim::provenance_build_manifest(&self.build.target),
            attester,
        )
        .with_source_ref(self.build.manifest_hash.clone())];

        // The transparency leg is reported only when it was actually exercised;
        // absence is not a failure on the SW-friendly path.
        match self.transparency {
            TransparencyCheck::Verified => entries.push(
                AttestationEntry::pass(dim::cert_validity("transparency_log"), attester)
                    .with_source_ref(self.build.manifest_hash.clone()),
            ),
            TransparencyCheck::Invalid => entries.push(
                AttestationEntry::fail(dim::cert_validity("transparency_log"), attester)
                    .with_source_ref(self.build.manifest_hash.clone()),
            ),
            TransparencyCheck::Absent => {},
        }

        entries
    }
}

impl BundleRejection {
    /// Project a rejection into a failing [`AttestationEntry`] — the
    /// **refutation** signal.
    ///
    /// This is the direction that carries hard information: a bundle that fails
    /// verification is decisive evidence about the presenter, whereas a bundle
    /// that passes only shows the presenter holds correct, correctly-rooted
    /// evidence (which an honest peer and a well-resourced impostor both can).
    /// Scorers should weight a failure far more heavily than a success.
    ///
    /// `target` is the build target when known; use `"unknown"` when the
    /// rejection happened before the target could be established.
    #[must_use]
    pub fn to_attestation_entry(&self, attester: &str, target: &str) -> AttestationEntry {
        AttestationEntry::fail(dim::provenance_build_manifest(target), attester)
            .with_source_ref(self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest_contribution::{sign_build_manifest_contribution, BuildAttestation};
    use crate::self_at_login::HybridSigningIdentity;

    const TS: &str = "2026-07-31T00:00:00Z";

    /// A pipeline identity + an accord-co-scrubbed KeyRecord blessing it for
    /// `infra:attest`, mirroring the #185 fixture shape.
    async fn fixture() -> (
        HybridSigningIdentity, // presenter
        HybridSigningIdentity, // pipeline
        SignedCegObject,       // manifest contribution
        KeyRecord,
        Vec<ThresholdMember>,
    ) {
        let presenter = HybridSigningIdentity::generate("presenter-node").unwrap();
        let pipeline = HybridSigningIdentity::generate("ci-pipeline").unwrap();
        let a1 = HybridSigningIdentity::generate("A1").unwrap();
        let b1 = HybridSigningIdentity::generate("B1").unwrap();

        let bh = "aa".repeat(32);
        let mh = "bb".repeat(32);
        let manifest = sign_build_manifest_contribution(
            &pipeline,
            &BuildAttestation {
                target: "x86_64-unknown-linux-gnu",
                binary_hash: &bh,
                build_id: "build-1",
                binary_version: "10.6.3",
                manifest_hash: &mh,
            },
            "human-1",
            "grant-1",
            TS,
        )
        .await
        .unwrap();

        let pm = pipeline.directory_member().unwrap();
        let record = crate::federation_self_record::produce_multiscrub_key_record(
            &[&a1, &b1],
            crate::federation_self_record::ScrubTarget {
                key_id: pipeline.key_id().to_string(),
                pubkey_ed25519_base64: pm.ed25519_public_key_base64.clone(),
                pubkey_ml_dsa_65_base64: pm.mldsa65_public_key_base64.clone().unwrap(),
                identity_type: "node".to_string(),
                roles: vec!["infra:attest".to_string()],
            },
            TS,
            &[],
        )
        .await
        .unwrap()
        .record;

        let anchors = vec![
            a1.directory_member().unwrap(),
            b1.directory_member().unwrap(),
        ];
        (presenter, pipeline, manifest, record, anchors)
    }

    #[tokio::test]
    async fn produced_bundle_verifies_and_binds_the_presenter() {
        let (presenter, pipeline, manifest, record, anchors) = fixture().await;
        let bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                manifest_contribution: &manifest,
                inclusion: None,
            },
            TS,
        )
        .await
        .unwrap();

        let verdict = verify_build_attestation_bundle(
            &bundle,
            &presenter.directory_member().unwrap(),
            &pipeline.directory_member().unwrap(),
            &record,
            &anchors,
        )
        .unwrap();

        assert_eq!(verdict.presenter_key_id, "presenter-node");
        assert_eq!(verdict.build.target, "x86_64-unknown-linux-gnu");
        assert_eq!(verdict.build.build_id, "build-1");
        assert_eq!(verdict.transparency, TransparencyCheck::Absent);
    }

    /// The binding is load-bearing: the SAME bundle checked against a DIFFERENT
    /// pinned presenter must fail. Without this, any peer could relay someone
    /// else's bundle as its own.
    #[tokio::test]
    async fn another_node_cannot_present_this_bundle_as_its_own() {
        let (presenter, pipeline, manifest, record, anchors) = fixture().await;
        let impostor = HybridSigningIdentity::generate("impostor").unwrap();
        let bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                manifest_contribution: &manifest,
                inclusion: None,
            },
            TS,
        )
        .await
        .unwrap();

        let err = verify_build_attestation_bundle(
            &bundle,
            &impostor.directory_member().unwrap(),
            &pipeline.directory_member().unwrap(),
            &record,
            &anchors,
        )
        .unwrap_err();
        assert!(matches!(err, BundleRejection::PresenterKeyMismatch { .. }));
    }

    /// Swapping the carried evidence after signing breaks the commitment.
    #[tokio::test]
    async fn tampered_evidence_breaks_the_commitment() {
        let (presenter, pipeline, manifest, record, anchors) = fixture().await;
        let mut bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                manifest_contribution: &manifest,
                inclusion: None,
            },
            TS,
        )
        .await
        .unwrap();

        bundle.body["manifest_contribution"]["body"]["signed_envelope"]["build"]["binary_hash"] =
            json!("00".repeat(32));

        let err = verify_build_attestation_bundle(
            &bundle,
            &presenter.directory_member().unwrap(),
            &pipeline.directory_member().unwrap(),
            &record,
            &anchors,
        )
        .unwrap_err();
        assert_eq!(err, BundleRejection::EvidenceCommitmentMismatch);
    }

    /// A bundle whose manifest does not root to the caller's anchors is
    /// rejected — the presenter's signature does not launder an unrooted build.
    #[tokio::test]
    async fn manifest_that_does_not_root_is_rejected() {
        let (presenter, pipeline, manifest, record, _) = fixture().await;
        let stranger = HybridSigningIdentity::generate("stranger").unwrap();
        let bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                manifest_contribution: &manifest,
                inclusion: None,
            },
            TS,
        )
        .await
        .unwrap();

        let err = verify_build_attestation_bundle(
            &bundle,
            &presenter.directory_member().unwrap(),
            &pipeline.directory_member().unwrap(),
            &record,
            &[stranger.directory_member().unwrap()],
        )
        .unwrap_err();
        assert!(matches!(err, BundleRejection::ManifestRejected(_)));
    }

    /// An inclusion proof for an unrelated leaf must not count, even when the
    /// proof itself reconstructs correctly.
    #[tokio::test]
    async fn inclusion_proof_for_another_leaf_does_not_count() {
        let (presenter, pipeline, manifest, record, anchors) = fixture().await;
        let foreign_leaf = hash_leaf(b"some other log entry");
        let proof = MerkleProof {
            entry_index: 0,
            leaf_hash: foreign_leaf,
            siblings: vec![],
            root: foreign_leaf,
        };
        let bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                manifest_contribution: &manifest,
                inclusion: Some(&proof),
            },
            TS,
        )
        .await
        .unwrap();

        let verdict = verify_build_attestation_bundle(
            &bundle,
            &presenter.directory_member().unwrap(),
            &pipeline.directory_member().unwrap(),
            &record,
            &anchors,
        )
        .unwrap();
        assert_eq!(verdict.transparency, TransparencyCheck::Invalid);
    }

    #[tokio::test]
    async fn verdict_projects_to_measurement_entries() {
        let (presenter, pipeline, manifest, record, anchors) = fixture().await;
        let bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                manifest_contribution: &manifest,
                inclusion: None,
            },
            TS,
        )
        .await
        .unwrap();
        let verdict = verify_build_attestation_bundle(
            &bundle,
            &presenter.directory_member().unwrap(),
            &pipeline.directory_member().unwrap(),
            &record,
            &anchors,
        )
        .unwrap();

        let entries = verdict.to_attestation_entries("ciris-verify");
        assert_eq!(entries.len(), 1, "no transparency proof carried");
        assert!(entries[0].is_pass());
        assert_eq!(
            entries[0].dimension,
            "provenance:build_manifest:x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            entries[0].source_ref.as_deref(),
            Some("bb".repeat(32).as_str())
        );
    }

    #[test]
    fn rejection_projects_to_a_failing_entry() {
        let entry = BundleRejection::PresenterSignatureInvalid
            .to_attestation_entry("ciris-verify", "x86_64-unknown-linux-gnu");
        assert!(entry.is_fail());
        assert_eq!(
            entry.dimension,
            "provenance:build_manifest:x86_64-unknown-linux-gnu"
        );
    }
}
