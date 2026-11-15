//! Level 1 reads a **signed** build claim (CC 3.1.2.1, CC 3.3.6).
//!
//! A build manifest is published as one claim: a `scores` Contribution on
//! `provenance:build_manifest:{target}:v1`, signed by the pipeline that built
//! it, citing the manifest's bytes from `evidence_refs[]`. A read route returns
//! the signed claim with the bytes so the reader can re-verify it (CC 3.1.2.1,
//! CC 5.3.4); nothing a serving install says on its own account is a root.
//!
//! This module is that reader. It takes a [`SignedBuild`] — the Contribution
//! exactly as the pipeline signed it, the pipeline's key record, and the
//! manifest bytes — and returns the
//! [`VerifiedManifest`](crate::manifest_contribution::VerifiedManifest) only when all of these
//! hold, in this order:
//!
//! 1. **Standing on the ceremony plane** (CC 4.2.1 "Blessing a build pipeline
//!    is in scope"): the pipeline's key record is co-scrubbed by a strict
//!    majority of the standing accord roster, hybrid on every counted scrub,
//!    over a registration envelope bearing `roles: ["infra:attest"]` and
//!    nothing wider. The roster is the one baked into this binary
//!    ([`crate::accord_genesis::baked_accord_roster`]), the same one the
//!    GenesisBundle is verified against. A pipeline key that sits on the
//!    roster is refused (bound (2): a pipeline carries no seat).
//! 2. **The Contribution** verifies against the pubkeys in that record
//!    ([`verify_build_manifest_contribution`](crate::manifest_contribution::verify_build_manifest_contribution)).
//! 3. **The target** is the one the reader asked for.
//! 4. **The blob**: its length equals the signed `manifest_size`, checked
//!    before hashing (CC 5.3.2.5), and its SHA-256 equals the signed
//!    `manifest_hash`, compared in constant time.
//!
//! ## What is not evaluated here
//!
//! The **delegation plane** (a `trust:confers:v1` grant carrying
//! `infra:attest`) needs the grant row and the granter's key, which the
//! registry's build route does not serve. A pipeline blessed only that way does
//! not verify here; that is an unverifiable claim, so Level 1 fails closed. The
//! conferring roster's **revocation** of a pipeline record (bound (3)) is a row
//! this reader does not see either: a revoked record keeps verifying until the
//! reader can read revocations.
//!
//! ## Failure is opaque to the attestation result
//!
//! [`BuildClaimRejection`] names the failing step for logs and tests. The
//! attestation result carries only pass or fail (the "never expose individual
//! integrity check results" invariant).

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::accord_genesis::strict_majority;
use crate::ceg_outbox::SignedCegObject;
use crate::federation_self_record::KeyRecord;
use crate::manifest_contribution::{
    verify_build_manifest_contribution, ManifestRejection, PipelineBlessing, VerifiedManifest,
    BUILD_MANIFEST_CONTRIBUTION_KIND, MANIFEST_PUBLISH_SCOPE,
};
use crate::self_at_login::SignedEnvelope;
use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// The `identity_type` a build pipeline's key record carries.
pub const PIPELINE_IDENTITY_TYPE: &str = "node";

/// A build claim as a reader holds it: the pipeline-signed Contribution, the
/// pipeline's key record (the standing evidence), and the manifest bytes the
/// Contribution cites. Self-authenticating: [`verify_signed_build`] re-derives
/// every fact from these three, so it is safe to cache and to relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBuild {
    /// The Contribution exactly as the pipeline signed it.
    pub contribution: SignedEnvelope,
    /// The pipeline's key record, co-scrubbed by the accord.
    pub pipeline_record: KeyRecord,
    /// The manifest bytes, base64 standard.
    pub manifest_base64: String,
}

impl SignedBuild {
    /// Assemble from a registry build response and the manifest bytes.
    #[must_use]
    pub fn from_parts(response: BuildClaimResponse, manifest: &[u8]) -> Self {
        Self {
            contribution: response.contribution,
            pipeline_record: response.pipeline_record,
            manifest_base64: base64::engine::general_purpose::STANDARD.encode(manifest),
        }
    }

    /// The manifest hash the Contribution claims (unverified; use it only to
    /// address the blob fetch).
    #[must_use]
    pub fn claimed_manifest_hash(&self) -> Option<&str> {
        self.contribution
            .signed_envelope
            .get("build")
            .and_then(|b| b.get("manifest_hash"))
            .and_then(Value::as_str)
    }
}

/// The members of the registry's `GET /v1/builds/{version}?target=` response
/// that carry authority: the signed Contribution and the pipeline's key
/// record. Every other member of that response (`standing`, `build_hash`,
/// `federation_provenance`, …) is the serving node's unsigned account and is
/// ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildClaimResponse {
    /// The Contribution as the pipeline signed it.
    pub contribution: SignedEnvelope,
    /// The pipeline's key record.
    pub pipeline_record: KeyRecord,
}

impl BuildClaimResponse {
    /// The manifest hash the Contribution claims, used only to address the
    /// blob fetch; [`verify_signed_build`] checks the bytes against it.
    #[must_use]
    pub fn claimed_manifest_hash(&self) -> Option<&str> {
        self.contribution
            .signed_envelope
            .get("build")
            .and_then(|b| b.get("manifest_hash"))
            .and_then(Value::as_str)
    }
}

/// Why a build claim did not verify. Every variant is a hard reject.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildClaimRejection {
    /// No accord roster is baked into this binary.
    NoRoster,
    /// The pipeline's key record does not carry ceremony-plane standing.
    NoStanding {
        /// Which check failed.
        reason: &'static str,
    },
    /// The Contribution itself was refused.
    Contribution(ManifestRejection),
    /// The Contribution is for another target.
    WrongTarget {
        /// The target the reader asked for.
        expected: String,
        /// The target the Contribution attests.
        found: String,
    },
    /// The manifest bytes are not valid base64.
    BlobEncoding,
    /// The manifest is not `manifest_size` bytes long.
    BlobSizeMismatch,
    /// The manifest does not hash to `manifest_hash`.
    BlobHashMismatch,
}

impl std::fmt::Display for BuildClaimRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRoster => f.write_str("no accord roster is baked into this binary"),
            Self::NoStanding { reason } => write!(f, "pipeline has no standing: {reason}"),
            Self::Contribution(r) => write!(f, "build Contribution refused: {r}"),
            Self::WrongTarget { expected, found } => {
                write!(
                    f,
                    "Contribution is for target {found:?}, expected {expected:?}"
                )
            },
            Self::BlobEncoding => f.write_str("manifest bytes are not base64"),
            Self::BlobSizeMismatch => f.write_str("manifest length differs from manifest_size"),
            Self::BlobHashMismatch => f.write_str("manifest bytes do not hash to manifest_hash"),
        }
    }
}

impl std::error::Error for BuildClaimRejection {}

fn no_standing(reason: &'static str) -> BuildClaimRejection {
    BuildClaimRejection::NoStanding { reason }
}

/// Evaluate a pipeline's standing on the ceremony plane (CC 4.2.1) against
/// `roster`, and return the blessing plus the pipeline's pinned member.
///
/// # Errors
/// [`BuildClaimRejection::NoRoster`] for an empty roster, otherwise
/// [`BuildClaimRejection::NoStanding`] naming the failing check.
pub fn ceremony_standing(
    record: &KeyRecord,
    roster: &[ThresholdMember],
    now: DateTime<Utc>,
) -> Result<(PipelineBlessing, ThresholdMember), BuildClaimRejection> {
    if roster.is_empty() {
        return Err(BuildClaimRejection::NoRoster);
    }
    // The identity outside the envelope must be the identity inside it, or a
    // genuinely co-scrubbed envelope for another key could bless this one.
    record
        .check_subject_binding()
        .map_err(|_| no_standing("key record identity does not match its signed envelope"))?;
    if record.identity_type != PIPELINE_IDENTITY_TYPE {
        return Err(no_standing("key record is not a node key"));
    }
    if roster.iter().any(|m| m.member_id == record.key_id) {
        return Err(no_standing("a pipeline key carries no accord seat"));
    }
    if record.roles_in_envelope() != [MANIFEST_PUBLISH_SCOPE] {
        return Err(no_standing(
            "the co-scrubbed envelope does not bear exactly roles [\"infra:attest\"]",
        ));
    }
    if let Some(until) = record.valid_until_in_envelope() {
        let until = DateTime::parse_from_rfc3339(&until)
            .map_err(|_| no_standing("valid_until is not RFC 3339"))?;
        if now >= until {
            return Err(no_standing("key record has expired"));
        }
    }
    let canonical = crate::jcs::canonicalize(&record.registration_envelope)
        .map_err(|_| no_standing("registration envelope does not canonicalize"))?;
    if hex::encode(Sha256::digest(&canonical)) != record.original_content_hash {
        return Err(no_standing(
            "original_content_hash does not match the envelope",
        ));
    }
    let scrubs: Vec<ThresholdSignature> = record
        .scrubs()
        .into_iter()
        .map(|s| ThresholdSignature {
            member_id: s.scrub_key_id,
            ed25519_signature_base64: s.scrub_signature_classical,
            mldsa65_signature_base64: s.scrub_signature_pqc,
        })
        .collect();
    let quorum = strict_majority(roster.len());
    let counted = verify_threshold_signatures(&canonical, roster, &scrubs, quorum).unwrap_or(0);
    if counted < quorum {
        return Err(no_standing(
            "the accord co-scrub does not reach a strict majority of the standing roster",
        ));
    }
    let mldsa = record
        .pubkey_ml_dsa_65_base64
        .clone()
        .ok_or_else(|| no_standing("key record carries no ML-DSA-65 key"))?;
    let member = ThresholdMember {
        member_id: record.key_id.clone(),
        ed25519_public_key_base64: record.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: Some(mldsa),
        role: None,
    };
    Ok((PipelineBlessing::accord_role(record.key_id.clone()), member))
}

/// Verify a build claim for `expected_target` against `roster`.
///
/// See the module docs for the order of checks.
///
/// # Errors
/// A [`BuildClaimRejection`] naming the first failing step.
pub fn verify_signed_build(
    build: &SignedBuild,
    expected_target: &str,
    roster: &[ThresholdMember],
    now: DateTime<Utc>,
) -> Result<VerifiedManifest, BuildClaimRejection> {
    let (blessing, member) = ceremony_standing(&build.pipeline_record, roster, now)?;
    let body =
        serde_json::to_value(&build.contribution).map_err(|_| BuildClaimRejection::BlobEncoding)?;
    let obj = SignedCegObject::new(
        BUILD_MANIFEST_CONTRIBUTION_KIND,
        member.member_id.clone(),
        String::new(),
        body,
    );
    let verified = verify_build_manifest_contribution(&obj, &member, &blessing)
        .map_err(BuildClaimRejection::Contribution)?;
    if verified.target != expected_target {
        return Err(BuildClaimRejection::WrongTarget {
            expected: expected_target.to_string(),
            found: verified.target,
        });
    }
    check_blob(&build.manifest_base64, &verified)?;
    Ok(verified)
}

/// Size first, then SHA-256 in constant time (CC 5.3.2.5).
fn check_blob(
    manifest_base64: &str,
    verified: &VerifiedManifest,
) -> Result<(), BuildClaimRejection> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(manifest_base64)
        .map_err(|_| BuildClaimRejection::BlobEncoding)?;
    if bytes.len() as u64 != verified.manifest_size {
        return Err(BuildClaimRejection::BlobSizeMismatch);
    }
    let expected =
        hex::decode(&verified.manifest_hash).map_err(|_| BuildClaimRejection::BlobHashMismatch)?;
    let actual = Sha256::digest(&bytes);
    if bool::from(actual.as_slice().ct_eq(&expected)) {
        Ok(())
    } else {
        Err(BuildClaimRejection::BlobHashMismatch)
    }
}

/// Verify against the accord roster baked into this binary, now.
///
/// # Errors
/// As [`verify_signed_build`].
pub fn verify_signed_build_baked(
    build: &SignedBuild,
    expected_target: &str,
) -> Result<VerifiedManifest, BuildClaimRejection> {
    verify_signed_build(
        build,
        expected_target,
        &crate::accord_genesis::baked_accord_roster(),
        Utc::now(),
    )
}

/// Name the build a Level 5 check ran against (CIRISVerify#315 ask 1).
///
/// Level 5's file map still comes from the registry's build record, because
/// the claim that should govern it, `agent_files:build:{target}` from the
/// canonical attester (CC 3.1.9.1, Policy F), is not served yet. This does not
/// change Level 5's verdict. It returns the pipeline-signed Contribution the
/// checked file map belongs to, and only when every link holds:
///
/// - the record carries a Contribution and pipeline record that verify
///   ([`verify_signed_build`], ceremony standing against `roster`);
/// - `blob` passes the size and hash checks against that Contribution;
/// - the record's `file_manifest_hash` is that manifest hash; and
/// - the files `blob` lists are exactly the files the record lists, so the
///   map Level 5 checked is the signed bytes.
///
/// Anything else names no build (`None`).
#[must_use]
pub fn name_agent_build(
    record: &crate::registry::BuildRecord,
    blob: &[u8],
    roster: &[ThresholdMember],
    now: DateTime<Utc>,
) -> Option<VerifiedManifest> {
    let contribution = record.contribution.clone()?;
    let pipeline_record = record.pipeline_record.clone()?;
    let target = contribution
        .signed_envelope
        .get("build")
        .and_then(|b| b.get("target"))
        .and_then(Value::as_str)?
        .to_string();
    let build = SignedBuild {
        contribution,
        pipeline_record,
        manifest_base64: base64::engine::general_purpose::STANDARD.encode(blob),
    };
    let verified = verify_signed_build(&build, &target, roster, now).ok()?;
    let record_hash = record
        .file_manifest_hash
        .strip_prefix("sha256:")
        .unwrap_or(&record.file_manifest_hash);
    if record_hash != verified.manifest_hash {
        return None;
    }
    let signed_files: crate::registry::FileManifest = serde_json::from_slice(blob).ok()?;
    (signed_files.files() == record.file_manifest_json.files()).then_some(verified)
}

/// Does the running binary's hash (`actual_hex`, lowercase hex) equal the
/// verified build's `binary_hash`? Constant time; a malformed hex on either
/// side is a mismatch.
#[must_use]
pub fn binary_hash_matches(verified: &VerifiedManifest, actual_hex: &str) -> bool {
    let (Ok(expected), Ok(actual)) = (hex::decode(&verified.binary_hash), hex::decode(actual_hex))
    else {
        return false;
    };
    expected.len() == 32 && bool::from(actual.ct_eq(&expected))
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    use super::*;
    use crate::federation_self_record::{produce_multiscrub_key_record, ScrubTarget};
    use crate::manifest_contribution::{sign_build_manifest_contribution, BuildAttestation};
    use crate::self_at_login::{HybridSigningIdentity, SelfSigner};

    pub(crate) const PIPELINE: &str = "ci-pipeline-node-k7";
    pub(crate) const TARGET: &str = "x86_64-unknown-linux-gnu";
    pub(crate) const MANIFEST: &[u8] = br#"{"files":{"a.py":"00"},"version":"1.0.0"}"#;

    pub(crate) struct Fixture {
        pub holders: Vec<HybridSigningIdentity>,
        pub roster: Vec<ThresholdMember>,
        pub pipeline: HybridSigningIdentity,
        pub build: SignedBuild,
        pub binary_hash: String,
    }

    pub(crate) fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A pipeline record co-scrubbed by `scrubbers` (indices into the holders)
    /// with `roles`, and a Contribution for `target` over `manifest`.
    pub(crate) async fn fixture_with(
        scrubbers: &[usize],
        roles: &[&str],
        target: &str,
        manifest: &[u8],
    ) -> Fixture {
        let holders: Vec<HybridSigningIdentity> = ["A1", "B1", "C1"]
            .iter()
            .map(|k| HybridSigningIdentity::generate(*k).unwrap())
            .collect();
        let roster: Vec<ThresholdMember> = holders
            .iter()
            .map(|h| h.directory_member().unwrap())
            .collect();
        let pipeline = HybridSigningIdentity::generate(PIPELINE).unwrap();
        let pm = pipeline.directory_member().unwrap();
        let signers: Vec<&dyn SelfSigner> = scrubbers
            .iter()
            .map(|i| &holders[*i] as &dyn SelfSigner)
            .collect();
        let record = produce_multiscrub_key_record(
            &signers,
            ScrubTarget {
                key_id: PIPELINE.into(),
                pubkey_ed25519_base64: pm.ed25519_public_key_base64.clone(),
                pubkey_ml_dsa_65_base64: pm.mldsa65_public_key_base64.clone().unwrap(),
                identity_type: PIPELINE_IDENTITY_TYPE.into(),
                roles: roles.iter().map(|r| (*r).to_string()).collect(),
            },
            "2026-10-01T00:00:00Z",
            None,
            &[],
        )
        .await
        .unwrap()
        .record;
        let binary_hash = "ab".repeat(32);
        let manifest_hash = hex::encode(Sha256::digest(manifest));
        let obj = sign_build_manifest_contribution(
            &pipeline,
            &BuildAttestation {
                target,
                binary_hash: &binary_hash,
                build_id: "v23.0.0",
                binary_version: "23.0.0",
                manifest_hash: &manifest_hash,
                manifest_size: manifest.len() as u64,
            },
            now(),
        )
        .await
        .unwrap();
        let contribution: SignedEnvelope = serde_json::from_value(obj.body).unwrap();
        let build = SignedBuild {
            contribution,
            pipeline_record: record,
            manifest_base64: base64::engine::general_purpose::STANDARD.encode(manifest),
        };
        Fixture {
            holders,
            roster,
            pipeline,
            build,
            binary_hash,
        }
    }

    pub(crate) async fn fixture() -> Fixture {
        fixture_with(&[0, 1], &[MANIFEST_PUBLISH_SCOPE], TARGET, MANIFEST).await
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;

    fn verify(f: &Fixture) -> Result<VerifiedManifest, BuildClaimRejection> {
        verify_signed_build(&f.build, TARGET, &f.roster, now())
    }

    #[tokio::test]
    async fn a_good_claim_verifies_and_names_its_row() {
        let f = fixture().await;
        let v = verify(&f).unwrap();
        assert_eq!(v.target, TARGET);
        assert_eq!(v.attested_by, PIPELINE);
        assert_eq!(v.manifest_hash, hex::encode(Sha256::digest(MANIFEST)));
        assert_eq!(
            v.attestation_id,
            f.build.contribution.signed_envelope["row"]["attestation_id"]
        );
        assert!(binary_hash_matches(&v, &f.binary_hash));
        assert!(!binary_hash_matches(&v, &"ac".repeat(32)));
        assert!(!binary_hash_matches(&v, "not-hex"));
    }

    #[tokio::test]
    async fn a_tampered_blob_fails_on_the_hash() {
        let mut f = fixture().await;
        let mut bytes = MANIFEST.to_vec();
        bytes[3] ^= 0x01; // same length, different bytes
        f.build.manifest_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert_eq!(verify(&f), Err(BuildClaimRejection::BlobHashMismatch));
    }

    #[tokio::test]
    async fn a_blob_of_another_length_fails_before_hashing() {
        let mut f = fixture().await;
        let mut bytes = MANIFEST.to_vec();
        bytes.push(b' ');
        f.build.manifest_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert_eq!(verify(&f), Err(BuildClaimRejection::BlobSizeMismatch));
    }

    #[tokio::test]
    async fn a_claim_naming_another_hash_fails() {
        // The pipeline genuinely signed a Contribution, but for other bytes.
        let f = fixture().await;
        let other = fixture_with(&[0, 1], &[MANIFEST_PUBLISH_SCOPE], TARGET, b"other bytes!").await;
        let mut build = other.build.clone();
        build.manifest_base64 = f.build.manifest_base64.clone();
        assert!(matches!(
            verify_signed_build(&build, TARGET, &other.roster, now()),
            Err(BuildClaimRejection::BlobSizeMismatch | BuildClaimRejection::BlobHashMismatch)
        ));
    }

    #[tokio::test]
    async fn a_claim_for_another_target_fails() {
        let f = fixture_with(
            &[0, 1],
            &[MANIFEST_PUBLISH_SCOPE],
            "aarch64-apple-darwin",
            MANIFEST,
        )
        .await;
        assert!(matches!(
            verify(&f),
            Err(BuildClaimRejection::WrongTarget { .. })
        ));
    }

    #[tokio::test]
    async fn an_unsigned_or_resigned_claim_fails() {
        let mut f = fixture().await;
        // Tamper with the signed facts: the signature no longer covers them.
        f.build.contribution.signed_envelope["build"]["binary_hash"] =
            serde_json::json!("cd".repeat(32));
        assert_eq!(
            verify(&f),
            Err(BuildClaimRejection::Contribution(
                ManifestRejection::PipelineSignatureInvalid
            ))
        );
        // No signature at all.
        let mut g = fixture().await;
        g.build.contribution.ed25519_signature_base64 = String::new();
        g.build.contribution.mldsa65_signature_base64 = String::new();
        assert!(matches!(
            verify(&g),
            Err(BuildClaimRejection::Contribution(_))
        ));
    }

    #[tokio::test]
    async fn a_claim_by_a_key_other_than_the_record_fails() {
        let mut f = fixture().await;
        // Re-sign the same envelope with a different key under the pipeline's name.
        let impostor = crate::self_at_login::HybridSigningIdentity::generate(PIPELINE).unwrap();
        let env = f.build.contribution.signed_envelope.clone();
        f.build.contribution =
            crate::self_at_login::SelfSigner::sign_envelope_async(&impostor, env)
                .await
                .unwrap();
        assert_eq!(
            verify(&f),
            Err(BuildClaimRejection::Contribution(
                ManifestRejection::PipelineSignatureInvalid
            ))
        );
    }

    #[tokio::test]
    async fn one_scrub_is_not_a_strict_majority() {
        let f = fixture_with(&[0], &[MANIFEST_PUBLISH_SCOPE], TARGET, MANIFEST).await;
        assert!(matches!(
            verify(&f),
            Err(BuildClaimRejection::NoStanding { .. })
        ));
    }

    #[tokio::test]
    async fn scrubs_by_keys_off_the_roster_do_not_count() {
        let f = fixture().await;
        let strangers: Vec<ThresholdMember> = ["A1", "B1", "C1"]
            .iter()
            .map(|k| {
                crate::self_at_login::HybridSigningIdentity::generate(*k)
                    .unwrap()
                    .directory_member()
                    .unwrap()
            })
            .collect();
        assert!(matches!(
            verify_signed_build(&f.build, TARGET, &strangers, now()),
            Err(BuildClaimRejection::NoStanding { .. })
        ));
        assert_eq!(
            verify_signed_build(&f.build, TARGET, &[], now()),
            Err(BuildClaimRejection::NoRoster)
        );
    }

    #[tokio::test]
    async fn roles_must_be_exactly_infra_attest() {
        for roles in [
            &[][..],
            &["infra:serve"][..],
            &["infra:attest", "infra:serve"][..],
        ] {
            let f = fixture_with(&[0, 1], roles, TARGET, MANIFEST).await;
            assert!(
                matches!(verify(&f), Err(BuildClaimRejection::NoStanding { .. })),
                "{roles:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_tampered_record_envelope_loses_standing() {
        let mut f = fixture().await;
        f.build.pipeline_record.registration_envelope["roles"] =
            serde_json::json!(["infra:attest"]);
        f.build.pipeline_record.registration_envelope["valid_from"] =
            serde_json::json!("2020-01-01T00:00:00Z");
        assert!(matches!(
            verify(&f),
            Err(BuildClaimRejection::NoStanding { .. })
        ));
    }

    #[tokio::test]
    async fn a_seated_holder_is_not_a_pipeline() {
        let f = fixture().await;
        let mut roster = f.roster.clone();
        roster[2].member_id = PIPELINE.into();
        assert!(matches!(
            verify_signed_build(&f.build, TARGET, &roster, now()),
            Err(BuildClaimRejection::NoStanding { .. })
        ));
        let _ = &f.holders;
        let _ = &f.pipeline;
    }

    #[tokio::test]
    async fn signed_build_round_trips_through_json() {
        let f = fixture().await;
        let json = serde_json::to_string(&f.build).unwrap();
        let back: SignedBuild = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f.build);
        assert!(verify_signed_build(&back, TARGET, &f.roster, now()).is_ok());
    }

    fn record_for(f: &Fixture, files: &str) -> crate::registry::BuildRecord {
        serde_json::from_value(serde_json::json!({
            "build_id": "b",
            "version": "1.0.0",
            "build_hash": "00",
            "file_manifest_hash": hex::encode(Sha256::digest(MANIFEST)),
            "file_manifest_json": serde_json::from_str::<Value>(files).unwrap(),
            "contribution": f.build.contribution,
            "pipeline_record": f.build.pipeline_record,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn an_agent_build_is_named_only_when_the_checked_map_is_the_signed_bytes() {
        let f = fixture().await;
        let good = record_for(&f, std::str::from_utf8(MANIFEST).unwrap());
        let named = name_agent_build(&good, MANIFEST, &f.roster, now()).unwrap();
        assert_eq!(named.manifest_hash, hex::encode(Sha256::digest(MANIFEST)));

        // The record's file map differs from the signed bytes: no name.
        let other = record_for(&f, r#"{"files":{"a.py":"11"},"version":"1.0.0"}"#);
        assert!(name_agent_build(&other, MANIFEST, &f.roster, now()).is_none());
        // Tampered bytes, or a roster that never blessed the pipeline: no name.
        assert!(name_agent_build(&good, b"{\"files\":{}}", &f.roster, now()).is_none());
        let strangers = fixture().await.roster;
        assert!(name_agent_build(&good, MANIFEST, &strangers, now()).is_none());
        // A record with no Contribution names no build.
        let mut bare = good.clone();
        bare.contribution = None;
        assert!(name_agent_build(&bare, MANIFEST, &f.roster, now()).is_none());
    }
}
