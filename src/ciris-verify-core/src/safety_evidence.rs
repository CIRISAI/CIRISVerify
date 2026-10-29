//! Safety-battery evidence as a CEG `scores` Contribution (CC 3.1.5.5,
//! CIRISVerify#322).
//!
//! ## The object
//!
//! One row per safety-battery blob, on
//! `evidence:safety_battery:{kind}:{cell}:{prefix}:v1`, signed bound-hybrid by
//! the agent's build pipeline key and naming the blob by hash in
//! `evidence_refs`. The envelope is the one
//! [`crate::manifest_contribution::sign_build_manifest_contribution`] produces
//! for builds, with the evidence dimension and an `evidence` descriptor in
//! place of `build`:
//!
//! ```json
//! {
//!   "asserted_at": "2026-10-29T14:50:29.308Z",
//!   "delegation_scope": "infra:attest",
//!   "dimension": "evidence:safety_battery:interpret:ru_mental_health:8af424544249c1c6:v1",
//!   "evidence": { "suite": "safety_battery", "kind": "interpret",
//!                 "cell": "ru_mental_health", "prefix": "8af424544249c1c6",
//!                 "agent_version": "…", "rubric": { "id": "…", "version": "…",
//!                 "sha256": "…" }, "judge": { "model": "…", "prompt_sha256": "…" },
//!                 "capture_prefix": "8af424544249c1c6", "ci_provenance": { … },
//!                 "captured_at": "…", "manifest_hash": "…", "manifest_size": 5120 },
//!   "evidence_refs": ["<manifest_hash>"],
//!   "row": { "attestation_id": "…", "attestation_type": "scores",
//!            "attested_key_id": "<pipeline>", "attesting_key_id": "<pipeline>",
//!            "cohort_scope": "federation", "subject_key_ids": [] },
//!   "score": 0.5
//! }
//! ```
//!
//! The field set is CIRISAgent `FSD/SAFETY_EVIDENCE_BLOBS.md` §4.1, the shape
//! CIRISRegistry's `POST /v1/evidence/safety_battery` door (CIRISRegistry#151)
//! reads.
//!
//! ## Score
//!
//! The family is signed-polarity from CC rc14. A capture scores `1`. An
//! interpretation scores `2·pass_ratio − 1`, so `−1` is every criterion failed
//! and `+1` every criterion passed; the ratio reads back as `(score + 1) / 2`.
//! From counts the score is computed as `(2·passed − total) / total`, a single
//! rounding, so a reader that recomputes it from the manifest's
//! `verdicts_summary` gets the same `f64`.
//!
//! ## What is refused at signing
//!
//! The dimension's segments are checked before anything is signed, so a
//! malformed row is refused here rather than at admission:
//!
//! - `{kind}` is `capture` or `interpret`;
//! - `{cell}` matches `^[a-z]{2,3}_[a-z_]+$` (`{lang}_{domain}`);
//! - `{prefix}` is 16 lowercase hex characters, and for a **capture** it is
//!   the first 16 characters of the row's own `manifest_hash` (an interpret
//!   row carries the prefix of the capture it judges, which this row cannot
//!   see).
//!
//! Domain separation between this row and a build row is the `dimension`
//! inside the signed envelope: the two verifiers each require their own
//! family, so neither row verifies as the other.
//!
//! ## Standing
//!
//! As for build manifests, whether the pipeline holds `infra:attest` is the
//! reader's walk. [`verify_safety_evidence_signature`] checks the signature and
//! the shape; [`SignedSafetyEvidence::bless`] then takes the caller's
//! [`PipelineBlessing`] and checks it names the pipeline that signed. An
//! offline check (`ciris-build-verify --evidence`) stops at the signature.

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::federation_provenance::dim::DIMENSION_VERSION;
use crate::manifest_contribution::{
    envelope_verifies, is_bare_sha256_hex, mint_attestation_id, render_signed_instant, row_mirror,
    ManifestRejection, PipelineBlessing, PipelineStanding, ATTESTATION_TYPE_SCORES,
    COHORT_SCOPE_FEDERATION, MANIFEST_PUBLISH_SCOPE,
};
use crate::self_at_login::SelfSigner;
use crate::threshold::ThresholdMember;

/// CEG `kind` for a safety-evidence Contribution in the outbox.
pub const SAFETY_EVIDENCE_CONTRIBUTION_KIND: &str = "safety_evidence_contribution";

/// The `{suite}` this module signs for. CC generalizes the family to
/// `evidence:{suite}:…`; `safety_battery` is its first member.
pub const SAFETY_BATTERY_SUITE: &str = "safety_battery";

/// Length of the `{prefix}` segment: the first 16 lowercase hex characters of
/// the capture blob's SHA-256.
pub const EVIDENCE_PREFIX_LEN: usize = 16;

/// `{kind}`: what the blob is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// What was asked and answered.
    Capture,
    /// What a judge made of a capture.
    Interpret,
}

impl EvidenceKind {
    /// The dimension segment.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Interpret => "interpret",
        }
    }

    /// Parse the dimension segment; anything else is `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "capture" => Some(Self::Capture),
            "interpret" => Some(Self::Interpret),
            _ => None,
        }
    }
}

/// The rubric a run was held to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rubric<'a> {
    /// Rubric identifier.
    pub id: &'a str,
    /// Rubric version.
    pub version: &'a str,
    /// SHA-256 of the rubric text, bare lowercase hex.
    pub sha256: &'a str,
}

/// How an interpretation's pass ratio is stated.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PassRatio {
    /// `passed` of `total` criteria passed (`total > 0`, `passed <= total`).
    Counts {
        /// Criteria passed.
        passed: u64,
        /// Criteria judged.
        total: u64,
    },
    /// A ratio in `[0, 1]`.
    Ratio(f64),
}

impl PassRatio {
    /// The signed score `2·pass_ratio − 1`, or `None` if the ratio is out of
    /// range.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn score(self) -> Option<f64> {
        match self {
            Self::Counts { passed, total } => {
                if total == 0 || passed > total {
                    return None;
                }
                // One rounding: (2p − t) / t, computed in i128 so 2p cannot overflow.
                let num = 2 * i128::from(passed) - i128::from(total);
                Some(num as f64 / total as f64)
            },
            Self::Ratio(r) if r.is_finite() && (0.0..=1.0).contains(&r) => Some(2.0 * r - 1.0),
            Self::Ratio(_) => None,
        }
    }
}

/// What kind of row, with the facts only that kind carries.
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceVerdict<'a> {
    /// A capture row; scores `1`.
    Capture,
    /// An interpretation row.
    Interpret {
        /// The interpretation's pass ratio.
        pass_ratio: PassRatio,
        /// The judge model.
        judge_model: &'a str,
        /// SHA-256 of the judge prompt, bare lowercase hex.
        judge_prompt_sha256: &'a str,
    },
}

impl EvidenceVerdict<'_> {
    const fn kind(&self) -> EvidenceKind {
        match self {
            Self::Capture => EvidenceKind::Capture,
            Self::Interpret { .. } => EvidenceKind::Interpret,
        }
    }
}

/// The facts a safety-evidence row attests.
#[derive(Debug, Clone, PartialEq)]
pub struct SafetyEvidence<'a> {
    /// Capture or interpretation, with its score inputs.
    pub verdict: EvidenceVerdict<'a>,
    /// `{lang}_{domain}`, e.g. `ru_mental_health`.
    pub cell: &'a str,
    /// The capture blob's 16-hex prefix (for an interpretation, the capture it
    /// judges).
    pub prefix: &'a str,
    /// The agent version under test.
    pub agent_version: &'a str,
    /// The rubric.
    pub rubric: Rubric<'a>,
    /// The CI run that produced the bundle. Opaque.
    pub ci_provenance: &'a Value,
    /// When the bundle was captured, RFC 3339. Carried verbatim.
    pub captured_at: &'a str,
    /// SHA-256 of the blob, bare lowercase hex; emitted as `evidence_refs[0]`.
    pub manifest_hash: &'a str,
    /// The blob's length in bytes (CC 5.3.2.5).
    pub manifest_size: u64,
}

/// `evidence:safety_battery:{kind}:{cell}:{prefix}:v1`.
#[must_use]
pub fn safety_battery_dimension(kind: EvidenceKind, cell: &str, prefix: &str) -> String {
    format!(
        "evidence:{SAFETY_BATTERY_SUITE}:{}:{cell}:{prefix}:{DIMENSION_VERSION}",
        kind.as_str()
    )
}

/// `^[a-z]{2,3}_[a-z_]+$`.
fn is_valid_cell(cell: &str) -> bool {
    let Some((lang, domain)) = cell.split_once('_') else {
        return false;
    };
    (2..=3).contains(&lang.len())
        && lang.bytes().all(|b| b.is_ascii_lowercase())
        && !domain.is_empty()
        && domain.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

fn is_valid_prefix(prefix: &str) -> bool {
    prefix.len() == EVIDENCE_PREFIX_LEN
        && prefix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn refuse(message: String) -> VerifyError {
    VerifyError::IntegrityError { message }
}

/// Sign a safety-evidence row with the pipeline's own key.
///
/// The output's `body` is the signed envelope (`signed_envelope`,
/// `ed25519_signature_base64`, `mldsa65_signature_base64`) that the registry
/// door takes as `contribution`.
///
/// # Errors
///
/// [`VerifyError`] if a dimension segment, hash, ratio or `captured_at` is
/// malformed (see the module docs), if the RNG health latch has tripped, or on
/// a canonicalization or signer fault.
pub async fn sign_safety_evidence_contribution(
    pipeline: &dyn SelfSigner,
    evidence: &SafetyEvidence<'_>,
    asserted_at: DateTime<Utc>,
) -> Result<SignedCegObject, VerifyError> {
    let kind = evidence.verdict.kind();
    if !is_valid_cell(evidence.cell) {
        return Err(refuse(format!(
            "cell must match ^[a-z]{{2,3}}_[a-z_]+$ ({{lang}}_{{domain}}); got {:?}",
            evidence.cell
        )));
    }
    if !is_valid_prefix(evidence.prefix) {
        return Err(refuse(format!(
            "prefix must be {EVIDENCE_PREFIX_LEN} lowercase hex characters; got {:?}",
            evidence.prefix
        )));
    }
    for (name, h) in [
        ("manifest_hash", evidence.manifest_hash),
        ("rubric.sha256", evidence.rubric.sha256),
    ] {
        if !is_bare_sha256_hex(h) {
            return Err(refuse(format!(
                "{name} must be 64 lowercase hex chars with no `sha256:` prefix; got {h:?}"
            )));
        }
    }
    if kind == EvidenceKind::Capture && !evidence.manifest_hash.starts_with(evidence.prefix) {
        return Err(refuse(format!(
            "a capture's prefix is the first {EVIDENCE_PREFIX_LEN} characters of its own \
             manifest_hash: {:?} is not a prefix of {:?}",
            evidence.prefix, evidence.manifest_hash
        )));
    }
    if DateTime::parse_from_rfc3339(evidence.captured_at).is_err() {
        return Err(refuse(format!(
            "captured_at must be RFC 3339; got {:?}",
            evidence.captured_at
        )));
    }

    let mut ev = Map::new();
    ev.insert("suite".into(), json!(SAFETY_BATTERY_SUITE));
    ev.insert("kind".into(), json!(kind.as_str()));
    ev.insert("cell".into(), json!(evidence.cell));
    ev.insert("prefix".into(), json!(evidence.prefix));
    ev.insert("agent_version".into(), json!(evidence.agent_version));
    ev.insert(
        "rubric".into(),
        json!({
            "id": evidence.rubric.id,
            "version": evidence.rubric.version,
            "sha256": evidence.rubric.sha256,
        }),
    );
    ev.insert("ci_provenance".into(), evidence.ci_provenance.clone());
    ev.insert("captured_at".into(), json!(evidence.captured_at));
    ev.insert("manifest_hash".into(), json!(evidence.manifest_hash));
    ev.insert("manifest_size".into(), json!(evidence.manifest_size));

    let score = match &evidence.verdict {
        EvidenceVerdict::Capture => json!(1),
        EvidenceVerdict::Interpret {
            pass_ratio,
            judge_model,
            judge_prompt_sha256,
        } => {
            if !is_bare_sha256_hex(judge_prompt_sha256) {
                return Err(refuse(format!(
                    "judge.prompt_sha256 must be 64 lowercase hex chars; got \
                     {judge_prompt_sha256:?}"
                )));
            }
            let Some(score) = pass_ratio.score() else {
                return Err(refuse(format!(
                    "pass ratio out of range (counts need 0 <= passed <= total, total > 0; \
                     a ratio is in [0, 1]); got {pass_ratio:?}"
                )));
            };
            ev.insert(
                "judge".into(),
                json!({ "model": judge_model, "prompt_sha256": judge_prompt_sha256 }),
            );
            ev.insert("capture_prefix".into(), json!(evidence.prefix));
            json!(score)
        },
    };

    let asserted_at = render_signed_instant(asserted_at);
    let pipeline_key_id = pipeline.key_id();
    let envelope = json!({
        "asserted_at": asserted_at,
        "delegation_scope": MANIFEST_PUBLISH_SCOPE,
        "dimension": safety_battery_dimension(kind, evidence.cell, evidence.prefix),
        "evidence": Value::Object(ev),
        "evidence_refs": [evidence.manifest_hash],
        "row": {
            "attestation_id": mint_attestation_id()?,
            "attestation_type": ATTESTATION_TYPE_SCORES,
            "attested_key_id": pipeline_key_id,
            "attesting_key_id": pipeline_key_id,
            "cohort_scope": COHORT_SCOPE_FEDERATION,
            "subject_key_ids": [],
        },
        "score": score,
    });

    let signed = pipeline.sign_envelope_async(envelope).await?;
    let body: Value = serde_json::to_value(&signed)
        .map_err(|e| refuse(format!("serialize safety evidence contribution: {e}")))?;
    Ok(SignedCegObject::new(
        SAFETY_EVIDENCE_CONTRIBUTION_KIND,
        pipeline_key_id,
        asserted_at,
        body,
    ))
}

// ===========================================================================
// Consumer side.
// ===========================================================================

/// Why a safety-evidence Contribution was **not** accepted. Every variant is a
/// hard reject.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceRejection {
    /// A required member is missing, the wrong type, or not the value this
    /// shape requires.
    Malformed {
        /// Which member, and what was wrong with it.
        field: &'static str,
    },
    /// The signed `row.attesting_key_id` is not the supplied pipeline member.
    PipelineKeyMismatch {
        /// The `row.attesting_key_id` in the envelope.
        envelope: String,
        /// The `member_id` of the pinned member.
        member: String,
    },
    /// The pipeline's bound-hybrid signature did not verify.
    PipelineSignatureInvalid,
    /// `delegation_scope` is not `infra:attest`.
    WrongScope {
        /// The scope found.
        scope: String,
    },
    /// The `dimension` is not the one the `evidence` descriptor names, or is
    /// not in this family.
    DimensionMismatch {
        /// The dimension built from `evidence`.
        expected: String,
        /// The dimension in the envelope.
        found: String,
    },
    /// The score is not `1` for a capture, or not in `[-1, 1]` for an
    /// interpretation.
    ScoreInvalid,
    /// The blob's length is not `evidence.manifest_size`.
    BlobSizeMismatch {
        /// The declared size.
        declared: u64,
        /// The blob's length.
        actual: u64,
    },
    /// The blob's SHA-256 is not `evidence.manifest_hash`.
    BlobHashMismatch,
    /// The [`PipelineBlessing`] names a different pipeline.
    BlessingNamesAnotherPipeline {
        /// The pipeline the blessing names.
        blessing: String,
        /// The pipeline that signed.
        pipeline: String,
    },
}

impl std::fmt::Display for EvidenceRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { field } => write!(f, "malformed safety evidence: {field}"),
            Self::PipelineKeyMismatch { envelope, member } => write!(
                f,
                "row.attesting_key_id {envelope:?} is not the pinned pipeline {member:?}"
            ),
            Self::PipelineSignatureInvalid => write!(
                f,
                "pipeline signature does not verify against the pinned key"
            ),
            Self::WrongScope { scope } => write!(
                f,
                "delegation_scope is {scope:?}, expected {MANIFEST_PUBLISH_SCOPE:?}"
            ),
            Self::DimensionMismatch { expected, found } => write!(
                f,
                "dimension is {found:?}, expected {expected:?} from the evidence descriptor"
            ),
            Self::ScoreInvalid => write!(
                f,
                "score is not 1 for a capture or not in [-1, 1] for an interpretation"
            ),
            Self::BlobSizeMismatch { declared, actual } => write!(
                f,
                "blob is {actual} bytes, evidence.manifest_size declares {declared}"
            ),
            Self::BlobHashMismatch => {
                write!(f, "blob SHA-256 is not evidence.manifest_hash")
            },
            Self::BlessingNamesAnotherPipeline { blessing, pipeline } => write!(
                f,
                "blessing is for pipeline {blessing:?}, but {pipeline:?} signed this row"
            ),
        }
    }
}

impl std::error::Error for EvidenceRejection {}

impl From<ManifestRejection> for EvidenceRejection {
    fn from(r: ManifestRejection) -> Self {
        match r {
            ManifestRejection::Malformed { field } => Self::Malformed { field },
            ManifestRejection::PipelineSignatureInvalid => Self::PipelineSignatureInvalid,
            _ => Self::Malformed {
                field: "row (rejected by the shared row checks)",
            },
        }
    }
}

/// A row whose signature and shape verified, standing not yet checked.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedSafetyEvidence {
    /// The pipeline key that signed.
    pub attested_by: String,
    /// The row id minted into the signed envelope.
    pub attestation_id: String,
    /// The signed instant.
    pub asserted_at: String,
    /// The dimension.
    pub dimension: String,
    /// `capture` or `interpret`.
    pub kind: EvidenceKind,
    /// The cell.
    pub cell: String,
    /// The 16-hex prefix.
    pub prefix: String,
    /// The signed score.
    pub score: f64,
    /// SHA-256 of the blob, bare hex.
    pub manifest_hash: String,
    /// The blob's declared length.
    pub manifest_size: u64,
    /// The signed `evidence` descriptor, as signed.
    pub evidence: Value,
}

/// A row whose signature, shape and blessing all verified.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedSafetyEvidence {
    /// The signed row.
    pub row: SignedSafetyEvidence,
    /// How the pipeline holds `infra:attest`.
    pub standing: PipelineStanding,
}

impl SignedSafetyEvidence {
    /// Check that `blessing` names the pipeline that signed.
    ///
    /// # Errors
    ///
    /// [`EvidenceRejection::BlessingNamesAnotherPipeline`].
    pub fn bless(
        self,
        blessing: &PipelineBlessing,
    ) -> Result<VerifiedSafetyEvidence, EvidenceRejection> {
        if blessing.pipeline_key_id != self.attested_by {
            return Err(EvidenceRejection::BlessingNamesAnotherPipeline {
                blessing: blessing.pipeline_key_id.clone(),
                pipeline: self.attested_by,
            });
        }
        Ok(VerifiedSafetyEvidence {
            row: self,
            standing: blessing.standing.clone(),
        })
    }

    /// Check a fetched blob against the row: length first (CC 5.3.2.5), then
    /// SHA-256 in constant time.
    ///
    /// # Errors
    ///
    /// [`EvidenceRejection::BlobSizeMismatch`] or
    /// [`EvidenceRejection::BlobHashMismatch`].
    pub fn check_blob(&self, blob: &[u8]) -> Result<(), EvidenceRejection> {
        let actual = blob.len() as u64;
        if actual != self.manifest_size {
            return Err(EvidenceRejection::BlobSizeMismatch {
                declared: self.manifest_size,
                actual,
            });
        }
        let digest = hex::encode(Sha256::digest(blob));
        if bool::from(digest.as_bytes().ct_eq(self.manifest_hash.as_bytes())) {
            Ok(())
        } else {
            Err(EvidenceRejection::BlobHashMismatch)
        }
    }
}

fn field<'a>(v: &'a Value, field: &'static str) -> Result<&'a str, EvidenceRejection> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or(EvidenceRejection::Malformed { field })
}

/// Verify a safety-evidence Contribution's signature and shape.
///
/// `contribution` is the signed envelope object (`signed_envelope`,
/// `ed25519_signature_base64`, `mldsa65_signature_base64`) — the registry
/// door's `contribution`, or a [`SignedCegObject`]'s `body`. All fail-closed,
/// in this order:
///
/// 1. The signed `row` mirror is persist's shape and `row.attesting_key_id` is
///    `pipeline_member`, which the caller pinned from its own key directory.
/// 2. The bound-hybrid signature verifies.
/// 3. `delegation_scope` is `infra:attest`; `evidence.suite` is
///    `safety_battery`; `kind`, `cell` and `prefix` are well formed and the
///    `dimension` is the one they name; `evidence_refs` names
///    `evidence.manifest_hash`, and for a capture the prefix is that hash's.
/// 4. The score is `1` for a capture and in `[-1, 1]` for an interpretation.
///
/// # Errors
///
/// An [`EvidenceRejection`] naming the first failing step.
pub fn verify_safety_evidence_signature(
    contribution: &Value,
    pipeline_member: &ThresholdMember,
) -> Result<SignedSafetyEvidence, EvidenceRejection> {
    let env = contribution
        .get("signed_envelope")
        .ok_or(EvidenceRejection::Malformed {
            field: "signed_envelope",
        })?;

    // --- 1. The row mirror, and who signed. ---
    let (attesting_key_id, attestation_id) = row_mirror(env)?;
    if attesting_key_id != pipeline_member.member_id {
        return Err(EvidenceRejection::PipelineKeyMismatch {
            envelope: attesting_key_id.to_string(),
            member: pipeline_member.member_id.clone(),
        });
    }

    // --- 2. The signature. ---
    let ed_sig = field(contribution, "ed25519_signature_base64")?;
    let mldsa_sig = contribution
        .get("mldsa65_signature_base64")
        .and_then(Value::as_str);
    if !envelope_verifies(env, ed_sig, mldsa_sig, pipeline_member) {
        return Err(EvidenceRejection::PipelineSignatureInvalid);
    }

    // --- 3. What the row says about itself. ---
    let scope = field(env, "delegation_scope")?;
    if scope != MANIFEST_PUBLISH_SCOPE {
        return Err(EvidenceRejection::WrongScope {
            scope: scope.to_string(),
        });
    }
    let ev = env
        .get("evidence")
        .ok_or(EvidenceRejection::Malformed { field: "evidence" })?;
    if field(ev, "suite")? != SAFETY_BATTERY_SUITE {
        return Err(EvidenceRejection::Malformed {
            field: "evidence.suite (not `safety_battery`)",
        });
    }
    let kind = EvidenceKind::parse(field(ev, "kind")?).ok_or(EvidenceRejection::Malformed {
        field: "evidence.kind (not `capture` or `interpret`)",
    })?;
    let cell = field(ev, "cell")?;
    if !is_valid_cell(cell) {
        return Err(EvidenceRejection::Malformed {
            field: "evidence.cell (not {lang}_{domain})",
        });
    }
    let prefix = field(ev, "prefix")?;
    if !is_valid_prefix(prefix) {
        return Err(EvidenceRejection::Malformed {
            field: "evidence.prefix (not 16 lowercase hex)",
        });
    }
    let dimension = field(env, "dimension")?;
    let expected = safety_battery_dimension(kind, cell, prefix);
    if dimension != expected {
        return Err(EvidenceRejection::DimensionMismatch {
            expected,
            found: dimension.to_string(),
        });
    }
    let manifest_hash = field(ev, "manifest_hash")?;
    if !is_bare_sha256_hex(manifest_hash) {
        return Err(EvidenceRejection::Malformed {
            field: "evidence.manifest_hash (not bare lowercase sha256 hex)",
        });
    }
    let refs =
        env.get("evidence_refs")
            .and_then(Value::as_array)
            .ok_or(EvidenceRejection::Malformed {
                field: "evidence_refs (absent or not an array)",
            })?;
    if !refs.iter().any(|r| r.as_str() == Some(manifest_hash)) {
        return Err(EvidenceRejection::Malformed {
            field: "evidence_refs (does not contain evidence.manifest_hash)",
        });
    }
    if kind == EvidenceKind::Capture && !manifest_hash.starts_with(prefix) {
        return Err(EvidenceRejection::Malformed {
            field: "evidence.prefix (a capture's prefix is its own manifest_hash's)",
        });
    }
    let manifest_size =
        ev.get("manifest_size")
            .and_then(Value::as_u64)
            .ok_or(EvidenceRejection::Malformed {
                field: "evidence.manifest_size (absent or not a u64 — CC 5.3.2.5)",
            })?;

    // --- 4. The score. ---
    let score = env
        .get("score")
        .and_then(Value::as_f64)
        .ok_or(EvidenceRejection::Malformed { field: "score" })?;
    let score_ok = match kind {
        #[allow(clippy::float_cmp)]
        EvidenceKind::Capture => score == 1.0,
        EvidenceKind::Interpret => score.is_finite() && (-1.0..=1.0).contains(&score),
    };
    if !score_ok {
        return Err(EvidenceRejection::ScoreInvalid);
    }

    Ok(SignedSafetyEvidence {
        attested_by: attesting_key_id.to_string(),
        attestation_id: attestation_id.to_string(),
        asserted_at: field(env, "asserted_at")?.to_string(),
        dimension: dimension.to_string(),
        kind,
        cell: cell.to_string(),
        prefix: prefix.to_string(),
        score,
        manifest_hash: manifest_hash.to_string(),
        manifest_size,
        evidence: ev.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest_contribution::{sign_build_manifest_contribution, BuildAttestation};
    use crate::manifest_contribution::{PipelineBlessing, WalkPlane};
    use crate::self_at_login::HybridSigningIdentity;

    const PIPELINE: &str = "agent-steward-2026";
    const BLOB: &[u8] = b"{\"manifest\":\"capture bundle\"}";

    fn blob_hash() -> String {
        hex::encode(Sha256::digest(BLOB))
    }

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-29T14:50:29.308917Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn provenance() -> Value {
        json!({ "run_id": 123, "repo": "CIRISAI/CIRISAgent" })
    }

    fn evidence<'a>(
        verdict: EvidenceVerdict<'a>,
        prefix: &'a str,
        hash: &'a str,
        prov: &'a Value,
    ) -> SafetyEvidence<'a> {
        SafetyEvidence {
            verdict,
            cell: "ru_mental_health",
            prefix,
            agent_version: "2.9.7",
            rubric: Rubric {
                id: "mh-rubric",
                version: "3",
                sha256: "abababababababababababababababababababababababababababababababab",
            },
            ci_provenance: prov,
            captured_at: "2026-10-28T09:00:00Z",
            manifest_hash: hash,
            manifest_size: BLOB.len() as u64,
        }
    }

    fn interpret(passed: u64, total: u64) -> EvidenceVerdict<'static> {
        EvidenceVerdict::Interpret {
            pass_ratio: PassRatio::Counts { passed, total },
            judge_model: "judge-model-1",
            judge_prompt_sha256: "cd".repeat(32).leak(),
        }
    }

    async fn sign(
        ev: &SafetyEvidence<'_>,
    ) -> (HybridSigningIdentity, Result<SignedCegObject, VerifyError>) {
        let id = HybridSigningIdentity::generate(PIPELINE).unwrap();
        let r = sign_safety_evidence_contribution(&id, ev, at()).await;
        (id, r)
    }

    #[tokio::test]
    async fn capture_round_trips_and_checks_its_blob() {
        let h = blob_hash();
        let prov = provenance();
        let (id, obj) = sign(&evidence(EvidenceVerdict::Capture, &h[..16], &h, &prov)).await;
        let obj = obj.unwrap();
        assert_eq!(obj.kind, SAFETY_EVIDENCE_CONTRIBUTION_KIND);
        let row =
            verify_safety_evidence_signature(&obj.body, &id.directory_member().unwrap()).unwrap();
        assert_eq!(row.kind, EvidenceKind::Capture);
        assert_eq!(
            row.dimension,
            format!(
                "evidence:safety_battery:capture:ru_mental_health:{}:v1",
                &h[..16]
            )
        );
        assert!((row.score - 1.0).abs() < f64::EPSILON);
        row.check_blob(BLOB).unwrap();
        assert_eq!(
            row.check_blob(b"other bytes of a different length!"),
            Err(EvidenceRejection::BlobSizeMismatch {
                declared: BLOB.len() as u64,
                actual: 34
            })
        );
        let mut same_len = BLOB.to_vec();
        same_len[0] ^= 1;
        assert_eq!(
            row.check_blob(&same_len),
            Err(EvidenceRejection::BlobHashMismatch)
        );
        let v = row.bless(&PipelineBlessing::accord_role(PIPELINE)).unwrap();
        assert_eq!(v.standing, PipelineStanding::AccordRole);
    }

    /// The exact member set the registry door reads (CIRISAgent FSD §4.1).
    #[tokio::test]
    async fn envelope_member_sets_are_the_door_shape() {
        let h = blob_hash();
        let prov = provenance();
        let (_, obj) = sign(&evidence(interpret(3, 4), "8af424544249c1c6", &h, &prov)).await;
        let env = &obj.unwrap().body["signed_envelope"];
        let keys = |v: &Value| {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(
            keys(env),
            [
                "asserted_at",
                "delegation_scope",
                "dimension",
                "evidence",
                "evidence_refs",
                "row",
                "score"
            ]
        );
        assert_eq!(
            keys(&env["evidence"]),
            [
                "agent_version",
                "capture_prefix",
                "captured_at",
                "cell",
                "ci_provenance",
                "judge",
                "kind",
                "manifest_hash",
                "manifest_size",
                "prefix",
                "rubric",
                "suite"
            ]
        );
        assert_eq!(env["asserted_at"], "2026-10-29T14:50:29.308Z");
        assert_eq!(env["evidence"]["capture_prefix"], "8af424544249c1c6");
        assert_eq!(env["score"], json!(0.5));
        assert_eq!(env["evidence_refs"], json!([h]));
    }

    #[test]
    fn interpret_score_is_signed() {
        let s = |p, t| {
            PassRatio::Counts {
                passed: p,
                total: t,
            }
            .score()
        };
        assert_eq!(s(0, 5), Some(-1.0));
        assert_eq!(s(5, 5), Some(1.0));
        assert_eq!(s(1, 2), Some(0.0));
        assert_eq!(s(2, 3), Some(1.0 / 3.0));
        assert_eq!(s(4, 3), None);
        assert_eq!(s(0, 0), None);
        assert_eq!(PassRatio::Ratio(0.25).score(), Some(-0.5));
        assert_eq!(PassRatio::Ratio(1.5).score(), None);
        assert_eq!(PassRatio::Ratio(f64::NAN).score(), None);
    }

    #[tokio::test]
    async fn all_failed_interpretation_signs_minus_one() {
        let h = blob_hash();
        let prov = provenance();
        let (id, obj) = sign(&evidence(interpret(0, 7), "8af424544249c1c6", &h, &prov)).await;
        let row =
            verify_safety_evidence_signature(&obj.unwrap().body, &id.directory_member().unwrap())
                .unwrap();
        assert!((row.score + 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn producer_refuses_malformed_segments() {
        let h = blob_hash();
        let prov = provenance();
        for (cell, prefix, hash) in [
            ("russian_mental_health", &h[..16], h.as_str()), // lang too long
            ("ru", &h[..16], h.as_str()),                    // no domain
            ("ru_Mental", &h[..16], h.as_str()),             // upper case
            ("ru_mental_health", &h[..15], h.as_str()),      // short prefix
            ("ru_mental_health", "0123456789abcdef", h.as_str()), // not this capture's
        ] {
            let mut ev = evidence(EvidenceVerdict::Capture, prefix, hash, &prov);
            ev.cell = cell;
            assert!(
                sign(&ev).await.1.is_err(),
                "{cell} {prefix} should be refused"
            );
        }
        let upper = h.to_uppercase();
        let ev = evidence(EvidenceVerdict::Capture, &h[..16], &upper, &prov);
        assert!(sign(&ev).await.1.is_err());
        let mut ev = evidence(interpret(3, 2), "8af424544249c1c6", &h, &prov);
        assert!(sign(&ev).await.1.is_err());
        ev.verdict = interpret(1, 2);
        ev.captured_at = "yesterday";
        assert!(sign(&ev).await.1.is_err());
    }

    #[tokio::test]
    async fn verifier_refuses_tampering_and_another_pipeline() {
        let h = blob_hash();
        let prov = provenance();
        let (id, obj) = sign(&evidence(interpret(3, 4), "8af424544249c1c6", &h, &prov)).await;
        let obj = obj.unwrap();
        let member = id.directory_member().unwrap();

        let mut tampered = obj.body.clone();
        tampered["signed_envelope"]["score"] = json!(1);
        assert_eq!(
            verify_safety_evidence_signature(&tampered, &member),
            Err(EvidenceRejection::PipelineSignatureInvalid)
        );

        let other = HybridSigningIdentity::generate("someone-else").unwrap();
        assert!(matches!(
            verify_safety_evidence_signature(&obj.body, &other.directory_member().unwrap()),
            Err(EvidenceRejection::PipelineKeyMismatch { .. })
        ));

        let row = verify_safety_evidence_signature(&obj.body, &member).unwrap();
        assert!(matches!(
            row.bless(&PipelineBlessing::conferred(
                "someone-else",
                "root",
                "grant",
                WalkPlane::Delegation
            )),
            Err(EvidenceRejection::BlessingNamesAnotherPipeline { .. })
        ));
    }

    /// Re-signed envelopes that lie about themselves are refused even with a
    /// valid signature.
    #[tokio::test]
    async fn verifier_refuses_inconsistent_signed_envelopes() {
        let h = blob_hash();
        let prov = provenance();
        let (id, obj) = sign(&evidence(EvidenceVerdict::Capture, &h[..16], &h, &prov)).await;
        let env = obj.unwrap().body["signed_envelope"].clone();
        let member = id.directory_member().unwrap();
        // (JSON pointer, replacement) — each re-signed so only the shape check
        // can refuse it.
        let cases = [
            (
                "/dimension",
                json!("evidence:safety_battery:capture:ru_other:0000000000000000:v1"),
            ),
            ("/score", json!(0.5)),
            ("/delegation_scope", json!("infra:relay")),
            ("/evidence_refs", json!(["ee".repeat(32)])),
            ("/evidence/kind", json!("summary")),
            ("/evidence/suite", json!("other")),
        ];
        for (ptr, value) in cases {
            let mut e = env.clone();
            *e.pointer_mut(ptr).unwrap() = value;
            let body = serde_json::to_value(id.sign_envelope_async(e).await.unwrap()).unwrap();
            assert!(
                verify_safety_evidence_signature(&body, &member).is_err(),
                "{ptr} tamper should be refused"
            );
        }
    }

    /// Domain separation: a build row never verifies as evidence.
    #[tokio::test]
    async fn a_build_row_is_not_evidence() {
        let id = HybridSigningIdentity::generate(PIPELINE).unwrap();
        let mh = "cd".repeat(32);
        let obj = sign_build_manifest_contribution(
            &id,
            &BuildAttestation {
                target: "python-source-tree",
                binary_hash: &"ab".repeat(32),
                build_id: "b",
                binary_version: "2.9.7",
                manifest_hash: &mh,
                manifest_size: 10,
            },
            at(),
        )
        .await
        .unwrap();
        assert!(matches!(
            verify_safety_evidence_signature(&obj.body, &id.directory_member().unwrap()),
            Err(EvidenceRejection::Malformed { field: "evidence" })
        ));
    }
}
