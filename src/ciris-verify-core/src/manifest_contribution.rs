//! Build manifest as a CEG `scores` Contribution, in the one shape a node can
//! store (CIRISVerify#299).
//!
//! ## The object
//!
//! A `scores` attestation on `provenance:build_manifest:{target}:v1`, signed
//! bound-hybrid by the CI pipeline's own `node` key, naming the manifest blob
//! by hash in `evidence_refs`. Its envelope is persist's attestation envelope:
//!
//! ```json
//! {
//!   "asserted_at": "2026-10-01T14:50:29.308Z",
//!   "build": { "target": "…", "build_id": "…", "binary_hash": "…",
//!              "binary_version": "…", "manifest_hash": "…",
//!              "manifest_size": 41237 },
//!   "delegation_scope": "infra:attest",
//!   "dimension": "provenance:build_manifest:python-source-tree:v1",
//!   "evidence_refs": ["<manifest_hash>"],
//!   "row": { "attestation_id": "…", "attestation_type": "scores",
//!            "attested_key_id": "<pipeline>", "attesting_key_id": "<pipeline>",
//!            "cohort_scope": "federation", "subject_key_ids": [] },
//!   "score": 1
//! }
//! ```
//!
//! Three properties are load-bearing, and v18 got the first two wrong:
//!
//! - **The dimension carries the `:v1` tail.** CC 3.1.7 R3 requires exactly
//!   one trailing version segment; persist refuses its absence as
//!   `missing_version_segment`.
//! - **The row's columns live in the signed `row` mirror** (CIRISPersist#643).
//!   A node derives `attestation_id`, `attesting_key_id`, `attestation_type`,
//!   `attested_key_id`, `subject_key_ids` and `cohort_scope` from these bytes,
//!   so whoever stores the row cannot choose them. They are stated **once**:
//!   the envelope has no top-level copies that could disagree with the mirror.
//!   `subject_key_ids` is empty because CC 2.3.2.1 admits only canonical
//!   key_ids there, and a build id is not one — the build is named by `build`
//!   and by the blob in `evidence_refs`.
//! - **`asserted_at` is the one signed instant**, rendered persist's way
//!   (RFC 3339, UTC, millisecond, `Z` — CC 2.6.2).
//!
//! Persist's canonical bytes are JCS, so the pipeline's bound-hybrid signature
//! over this envelope is what persist re-verifies, unchanged. CIRISRegistry's
//! `fold_builds::contribution_envelope` spells the same members; the
//! round-trip test there is the cross-repo witness.
//!
//! ## Who may attest a build — and who decides
//!
//! A Contribution is worth something only if the pipeline key holds
//! [`MANIFEST_PUBLISH_SCOPE`]. That answer lives in the node's directory —
//! grants, role withdrawals, expiry, and which roots *this* node accepts — and
//! Verify does not re-derive it: a pure function holding a copy of one grant or
//! one key record cannot see its withdrawal, and a second, staler authority
//! beside the substrate's is exactly the drift this ecosystem keeps paying for.
//!
//! Persist holds **two** authorities that can bless a pipeline, and production
//! uses the second:
//!
//! - the capability walk above (Delegation or FamilyQuorum arm) — a grant; and
//! - `admission::is_infra_attest_effective(directory, pipeline)` — the
//!   `infra:attest` role inside the pipeline's accord-co-scrubbed key record,
//!   which is what CIRISServer's `/v1/accord/ci-key` ceremony writes.
//!
//! So the verifier takes a [`PipelineBlessing`] stating which authority the
//! caller asked and what it answered, and checks that it names **this**
//! pipeline. A call site cannot reach a [`VerifiedManifest`] without having
//! asked one of them.
//!
//! (Until 19.0.0 verify carried two authority models of its own: a one-hop
//! grant check, and an accord co-scrub check on the pipeline's key record. The
//! co-scrub check was the right *question* — it is what persist's
//! `is_infra_attest_effective` answers — but verify's copy could not see a
//! quorum role-withdrawal, so a withdrawn pipeline still verified. Both are
//! gone; the substrate, which sees withdrawals, answers.)

use chrono::{DateTime, Timelike, Utc};
use serde_json::{json, Value};

use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::self_at_login::SelfSigner;
use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// The `infra:*` scope a pipeline must hold to publish build manifests (the
/// #77 "attest on my behalf" scope). Persist's capability walk asks for
/// exactly this token.
pub const MANIFEST_PUBLISH_SCOPE: &str = "infra:attest";

/// CEG `kind` for a build-manifest Contribution in the outbox.
pub const BUILD_MANIFEST_CONTRIBUTION_KIND: &str = "build_manifest_contribution";

/// The `attestation_type` of a build-manifest Contribution.
const ATTESTATION_TYPE_SCORES: &str = "scores";

/// The `cohort_scope` a build-manifest Contribution is published at.
const COHORT_SCOPE_FEDERATION: &str = "federation";

/// The members persist's `RowMirror` admits (`deny_unknown_fields`). A row
/// carrying anything else is refused there, so it is refused here too.
const ROW_MIRROR_MEMBERS: &[&str] = &[
    "attestation_id",
    "attesting_key_id",
    "attestation_type",
    "attested_key_id",
    "subject_key_ids",
    "cohort_scope",
    "weight",
];

/// The build facts a manifest Contribution attests. (The full file manifest
/// stays available by `manifest_hash`; the Contribution carries the trust-
/// bearing facts so a consumer can decide without fetching the file list.)
pub struct BuildAttestation<'a> {
    /// Build target (a Rust triple, `python-source-tree`, …).
    pub target: &'a str,
    /// SHA-256 of the built binary, hex.
    pub binary_hash: &'a str,
    /// The build identifier.
    pub build_id: &'a str,
    /// The binary's version string.
    pub binary_version: &'a str,
    /// SHA-256 of the canonical file manifest — **64 lowercase hex chars,
    /// no `sha256:` prefix** (CIRISVerify#281).
    ///
    /// This value is emitted as the Contribution's `evidence_refs[0]`, and
    /// every blob consumer (CIRISEdge `BlobMeaning::project`, CIRISPersist
    /// `envelope_binds_content`) resolves a blob to its referencing rows by
    /// comparing that entry to the blob's bare sha256 hex. A prefixed or
    /// upper-case value would produce a ref that exists and **never
    /// matches** — so the producer refuses it rather than emit it.
    pub manifest_hash: &'a str,
    /// The manifest blob's length in bytes. CC 5.3.2.5: a descriptor citing a
    /// blob from `evidence_refs` carries its size, and a fetcher checks size
    /// **before** the full SHA, so an oversized or truncated body is refused
    /// without hashing it. `build` is that descriptor (CC 3.1.2.1).
    pub manifest_size: u64,
}

/// Is `s` exactly 64 lowercase hex chars — the one form a blob consumer will
/// match as an evidence ref?
fn is_bare_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The `provenance:build_manifest:{target}:v1` dimension a Contribution for
/// `target` attests. One spelling, shared with
/// [`crate::federation_provenance::dim::provenance_build_manifest`].
#[must_use]
pub fn build_manifest_dimension(target: &str) -> String {
    crate::federation_provenance::dim::provenance_build_manifest(target)
}

/// Render a signed instant the way persist mints and binds it (CC 2.6.2):
/// truncated to the millisecond, RFC 3339, UTC, `Z` suffix.
///
/// Truncated **before** rendering, so the signed string and any column a node
/// derives from it are the same instant by construction.
#[must_use]
pub fn render_signed_instant(t: DateTime<Utc>) -> String {
    let millis = t.nanosecond() / 1_000_000 * 1_000_000;
    t.with_nanosecond(millis)
        .unwrap_or(t)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Mint a row's `attestation_id`: a random UUIDv4, drawn through the
/// SP 800-90B-latched RNG (#74) like every other value this crate mints.
///
/// Minted into the signed bytes, so one envelope can only ever name one row —
/// the reason persist moved the id inside the signature (CIRISPersist#643).
pub(crate) fn mint_attestation_id() -> Result<String, VerifyError> {
    let mut b = [0u8; 16];
    ciris_crypto::random::fill(&mut b).map_err(|e| VerifyError::IntegrityError {
        message: format!("attestation_id draw failed closed: {e}"),
    })?;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let h = hex::encode(b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// Sign a build-manifest Contribution with the pipeline's own key.
///
/// The output's `body` is a signed envelope (`signed_envelope`,
/// `ed25519_signature_base64`, `mldsa65_signature_base64`) that a node stores
/// as-is: every column comes out of the signed `row` mirror. Whether the
/// pipeline is *blessed* to attest builds is not something the producer can
/// state — see the module docs.
///
/// # Errors
///
/// [`VerifyError`] if `manifest_hash` is not bare lowercase sha256 hex, if the
/// RNG health latch has tripped, or on a canonicalization or signer fault.
pub async fn sign_build_manifest_contribution(
    pipeline: &dyn SelfSigner,
    build: &BuildAttestation<'_>,
    asserted_at: DateTime<Utc>,
) -> Result<SignedCegObject, VerifyError> {
    // CIRISVerify#281: the Contribution must REFERENCE its own blob, and the
    // reference must be in the one form consumers match. Refuse here rather
    // than emit an `evidence_refs` entry that can never fire.
    if !is_bare_sha256_hex(build.manifest_hash) {
        return Err(VerifyError::IntegrityError {
            message: format!(
                "manifest_hash must be 64 lowercase hex chars with no `sha256:` prefix \
                 (it is emitted as evidence_refs[0] and matched verbatim by blob \
                 consumers); got {:?}",
                build.manifest_hash
            ),
        });
    }
    let asserted_at = render_signed_instant(asserted_at);
    let pipeline_key_id = pipeline.key_id();
    let envelope = json!({
        "asserted_at": asserted_at,
        "build": {
            "target": build.target,
            "build_id": build.build_id,
            "binary_hash": build.binary_hash,
            "binary_version": build.binary_version,
            "manifest_hash": build.manifest_hash,
            "manifest_size": build.manifest_size,
        },
        "delegation_scope": MANIFEST_PUBLISH_SCOPE,
        "dimension": build_manifest_dimension(build.target),
        // CIRISVerify#281: the blob this Contribution vouches for. Exactly the
        // manifest — NOT `binary_hash`: the binary is not a blob on this plane,
        // and naming it would claim bytes nobody serves.
        "evidence_refs": [build.manifest_hash],
        "row": {
            "attestation_id": mint_attestation_id()?,
            "attestation_type": ATTESTATION_TYPE_SCORES,
            "attested_key_id": pipeline_key_id,
            "attesting_key_id": pipeline_key_id,
            "cohort_scope": COHORT_SCOPE_FEDERATION,
            "subject_key_ids": [],
        },
        "score": 1,
    });

    let signed = pipeline.sign_envelope_async(envelope).await?;
    let body: Value = serde_json::to_value(&signed).map_err(|e| VerifyError::IntegrityError {
        message: format!("serialize manifest contribution: {e}"),
    })?;
    Ok(SignedCegObject::new(
        BUILD_MANIFEST_CONTRIBUTION_KIND,
        pipeline_key_id,
        asserted_at,
        body,
    ))
}

// ===========================================================================
// Consumer side.
// ===========================================================================

/// Which arm of persist's **capability walk** conferred the scope. Mirrors the
/// two arms of persist's `trust_root::ConferralPlane` that can bless a pipeline.
///
/// The walk's third arm, `AccordCoScrub`, is deliberately absent: it makes the
/// subject itself the candidate root and then requires `trust_root_valid` on it
/// (a self-charter, a recovery commitment, a fresh heartbeat), which a build
/// pipeline never has. So it cannot produce a pipeline blessing, and a value that
/// claims it could would be a wrong state. The accord co-scrub reaches a
/// pipeline through [`PipelineStanding::AccordRole`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkPlane {
    /// A live `delegates_to(root → pipeline)` grant (`trust:confers:v1`).
    Delegation,
    /// A grant whose scrub set reached a constitutional family's quorum. The
    /// root is the **family id**, not a key.
    FamilyQuorum,
}

/// How the pipeline came to hold [`MANIFEST_PUBLISH_SCOPE`] — the answer of
/// whichever persist authority the caller asked. Verify cannot ask either one
/// (both read the caller's directory), so the caller states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineStanding {
    /// persist's `trust_root::capability_roots_to_trusted_root(directory,
    /// reader, pipeline, "infra:attest")` returned a `TrustedGrant`.
    /// **Reader-relative**: it holds for the node that ran it, against the
    /// roots that node accepts.
    Conferred {
        /// The trust root (a family id under [`WalkPlane::FamilyQuorum`]).
        root_key_id: String,
        /// The grant that conferred the scope.
        grant_attestation_id: String,
        /// Which arm of the walk.
        plane: WalkPlane,
    },
    /// persist's `admission::is_infra_attest_effective(directory, pipeline)`
    /// returned `true`: the pipeline's key record carries `infra:attest` inside
    /// its accord-co-scrubbed registration envelope, at the accord's quorum,
    /// and no quorum role-withdrawal has ended it (CIRISPersist#422/#424).
    ///
    /// This is how CIRISServer's `/v1/accord/ci-key/{propose,cosign}` ceremony
    /// blesses production pipelines (CIRISVerify#185), and it gives a
    /// `federation`-scope manifest Global reach. Not reader-relative.
    AccordRole,
}

impl PipelineStanding {
    /// Wire name of the standing's source: `delegation` | `family_quorum` |
    /// `accord_role`.
    #[must_use]
    pub const fn plane_str(&self) -> &'static str {
        match self {
            Self::Conferred {
                plane: WalkPlane::Delegation,
                ..
            } => "delegation",
            Self::Conferred {
                plane: WalkPlane::FamilyQuorum,
                ..
            } => "family_quorum",
            Self::AccordRole => "accord_role",
        }
    }
}

/// The caller's statement that `pipeline_key_id` holds
/// [`MANIFEST_PUBLISH_SCOPE`], and from which persist authority.
///
/// Verify cannot check either authority (both need the directory). What it
/// checks is that the blessing names the pipeline that actually signed, so a
/// blessing obtained for one pipeline cannot be spent on another's
/// Contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineBlessing {
    /// The pipeline key the authority was asked about.
    pub pipeline_key_id: String,
    /// What the authority answered.
    pub standing: PipelineStanding,
}

impl PipelineBlessing {
    /// The walk's answer — from persist's `TrustedGrant`.
    #[must_use]
    pub fn conferred(
        pipeline_key_id: impl Into<String>,
        root_key_id: impl Into<String>,
        grant_attestation_id: impl Into<String>,
        plane: WalkPlane,
    ) -> Self {
        Self {
            pipeline_key_id: pipeline_key_id.into(),
            standing: PipelineStanding::Conferred {
                root_key_id: root_key_id.into(),
                grant_attestation_id: grant_attestation_id.into(),
                plane,
            },
        }
    }

    /// `is_infra_attest_effective(directory, pipeline_key_id) == true`.
    #[must_use]
    pub fn accord_role(pipeline_key_id: impl Into<String>) -> Self {
        Self {
            pipeline_key_id: pipeline_key_id.into(),
            standing: PipelineStanding::AccordRole,
        }
    }
}

/// The facts of a build whose Contribution passed every check. A server stores
/// or relays these — never the unverified body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    /// The pipeline `node` key_id that signed the Contribution.
    pub attested_by: String,
    /// How the pipeline holds `infra:attest` (from the [`PipelineBlessing`]).
    pub standing: PipelineStanding,
    /// The row id minted into the signed envelope.
    pub attestation_id: String,
    /// The signed instant.
    pub asserted_at: String,
    /// Build target.
    pub target: String,
    /// The build identifier.
    pub build_id: String,
    /// SHA-256 of the built binary, hex.
    pub binary_hash: String,
    /// The binary's version string.
    pub binary_version: String,
    /// SHA-256 of the canonical file manifest, hex.
    pub manifest_hash: String,
    /// The manifest blob's declared length in bytes (CC 5.3.2.5). A fetcher
    /// MUST refuse a body of any other length before hashing it.
    pub manifest_size: u64,
    /// The blob(s) this Contribution references (CIRISVerify#281); always
    /// contains `manifest_hash`.
    pub evidence_refs: Vec<String>,
}

/// Why a build-manifest Contribution was **not** accepted. Every variant is a
/// hard reject — there is no partial-trust path (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestRejection {
    /// The outbox object is not a `build_manifest_contribution`.
    WrongKind {
        /// The kind actually found.
        kind: String,
    },
    /// A required member is missing, the wrong type, or not the value this
    /// shape requires.
    Malformed {
        /// Which member, and what was wrong with it.
        field: &'static str,
    },
    /// The pipeline's bound-hybrid signature did not verify at threshold 1
    /// against its pinned pubkeys (RequireHybrid — federation tier).
    PipelineSignatureInvalid,
    /// The signed `row.attesting_key_id` is not the supplied pipeline member —
    /// the caller pinned the wrong key.
    PipelineKeyMismatch {
        /// The `row.attesting_key_id` in the envelope.
        envelope: String,
        /// The `member_id` of the pinned member.
        member: String,
    },
    /// The Contribution's `delegation_scope` is not [`MANIFEST_PUBLISH_SCOPE`].
    WrongScope {
        /// The scope found.
        scope: String,
    },
    /// The `dimension` is not `provenance:build_manifest:{target}:v1` for the
    /// attested `build.target`.
    DimensionMismatch {
        /// The dimension expected from `build.target`.
        expected: String,
        /// The dimension found in the envelope.
        found: String,
    },
    /// The [`PipelineBlessing`] was obtained for a different pipeline than the
    /// one that signed this Contribution.
    BlessingNamesAnotherPipeline {
        /// The pipeline the blessing names.
        blessing: String,
        /// The pipeline that signed.
        pipeline: String,
    },
}

impl std::fmt::Display for ManifestRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKind { kind } => {
                write!(f, "not a build-manifest contribution: kind {kind:?}")
            },
            Self::Malformed { field } => {
                write!(f, "malformed manifest contribution: {field}")
            },
            Self::PipelineSignatureInvalid => {
                write!(
                    f,
                    "pipeline signature does not verify against the pinned key"
                )
            },
            Self::PipelineKeyMismatch { envelope, member } => {
                write!(
                    f,
                    "row.attesting_key_id {envelope:?} is not the pinned pipeline {member:?}"
                )
            },
            Self::WrongScope { scope } => {
                write!(
                    f,
                    "delegation_scope is {scope:?}, expected {MANIFEST_PUBLISH_SCOPE:?}"
                )
            },
            Self::DimensionMismatch { expected, found } => {
                write!(
                    f,
                    "dimension is {found:?}, expected {expected:?} for this build's target"
                )
            },
            Self::BlessingNamesAnotherPipeline { blessing, pipeline } => {
                write!(
                    f,
                    "blessing is for pipeline {blessing:?}, but {pipeline:?} signed this \
                     contribution"
                )
            },
        }
    }
}

impl std::error::Error for ManifestRejection {}

fn str_field<'a>(v: &'a Value, field: &'static str) -> Result<&'a str, ManifestRejection> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or(ManifestRejection::Malformed { field })
}

/// Read `evidence_refs` and enforce that it names `manifest_hash` in the one
/// form a blob consumer matches (CIRISVerify#281). Required: a Contribution
/// that references no blob can never trigger a pull, so it is not this shape.
fn evidence_refs_bound_to(
    env: &Value,
    manifest_hash: &str,
) -> Result<Vec<String>, ManifestRejection> {
    let arr =
        env.get("evidence_refs")
            .and_then(Value::as_array)
            .ok_or(ManifestRejection::Malformed {
                field: "evidence_refs (absent or not an array)",
            })?;
    let mut refs = Vec::with_capacity(arr.len());
    for r in arr {
        let Some(sha) = r.as_str() else {
            return Err(ManifestRejection::Malformed {
                field: "evidence_refs (non-string entry)",
            });
        };
        if !is_bare_sha256_hex(sha) {
            return Err(ManifestRejection::Malformed {
                field: "evidence_refs (entry is not bare sha256 hex)",
            });
        }
        refs.push(sha.to_string());
    }
    if !refs.iter().any(|r| r == manifest_hash) {
        return Err(ManifestRejection::Malformed {
            field: "evidence_refs (does not contain build.manifest_hash — the Contribution \
                    does not reference the blob it attests)",
        });
    }
    Ok(refs)
}

/// The signed `row` mirror, checked against what a build-manifest
/// Contribution must say about itself. Returns `(attesting_key_id,
/// attestation_id)`.
fn row_mirror(env: &Value) -> Result<(&str, &str), ManifestRejection> {
    let row = env
        .get("row")
        .and_then(Value::as_object)
        .ok_or(ManifestRejection::Malformed {
            field: "row (no signed row mirror — CIRISPersist#643)",
        })?;
    if row
        .keys()
        .any(|k| !ROW_MIRROR_MEMBERS.contains(&k.as_str()))
    {
        return Err(ManifestRejection::Malformed {
            field: "row (member outside persist's RowMirror)",
        });
    }
    let row = env.get("row").expect("checked above");
    if str_field(row, "attestation_type")? != ATTESTATION_TYPE_SCORES {
        return Err(ManifestRejection::Malformed {
            field: "row.attestation_type (not `scores`)",
        });
    }
    if str_field(row, "cohort_scope")? != COHORT_SCOPE_FEDERATION {
        return Err(ManifestRejection::Malformed {
            field: "row.cohort_scope (not `federation`)",
        });
    }
    let attesting = str_field(row, "attesting_key_id")?;
    if str_field(row, "attested_key_id")? != attesting {
        return Err(ManifestRejection::Malformed {
            field: "row.attested_key_id (a build Contribution is the pipeline's own claim)",
        });
    }
    let attestation_id = str_field(row, "attestation_id")?;
    if attestation_id.is_empty() {
        return Err(ManifestRejection::Malformed {
            field: "row.attestation_id (empty)",
        });
    }
    Ok((attesting, attestation_id))
}

/// Verify a bound-hybrid signature over `envelope` at threshold 1 against a
/// single pinned `member` (RequireHybrid — the federation-tier default).
fn envelope_verifies(
    envelope: &Value,
    ed_sig: &str,
    mldsa_sig: Option<&str>,
    member: &ThresholdMember,
) -> bool {
    let Ok(bytes) = crate::jcs::canonicalize(envelope) else {
        return false;
    };
    let sig = ThresholdSignature {
        member_id: member.member_id.clone(),
        ed25519_signature_base64: ed_sig.to_string(),
        mldsa65_signature_base64: mldsa_sig.map(str::to_string),
    };
    verify_threshold_signatures(&bytes, std::slice::from_ref(member), &[sig], 1) == Ok(1)
}

/// Verify a build-manifest Contribution and return its facts.
///
/// All fail-closed, in this order:
///
/// 1. `obj` is a `build_manifest_contribution` carrying a `signed_envelope`.
/// 2. The signed `row` mirror is persist's shape — `scores`, `federation`,
///    the pipeline attesting about itself — and `row.attesting_key_id` is
///    `pipeline_member`, which the **caller** pinned from its own key
///    directory (never from the object).
/// 3. The pipeline's bound-hybrid signature verifies at threshold 1.
/// 4. `delegation_scope` is [`MANIFEST_PUBLISH_SCOPE`], the `dimension` is
///    `provenance:build_manifest:{build.target}:v1`, `asserted_at` is present,
///    and `evidence_refs` names `build.manifest_hash`.
/// 5. `blessing` names this pipeline. Whether the blessing is *true* is the
///    caller's walk — see [`PipelineBlessing`].
///
/// # Errors
///
/// A [`ManifestRejection`] naming the first failing step.
pub fn verify_build_manifest_contribution(
    obj: &SignedCegObject,
    pipeline_member: &ThresholdMember,
    blessing: &PipelineBlessing,
) -> Result<VerifiedManifest, ManifestRejection> {
    if obj.kind != BUILD_MANIFEST_CONTRIBUTION_KIND {
        return Err(ManifestRejection::WrongKind {
            kind: obj.kind.clone(),
        });
    }
    let env = obj
        .body
        .get("signed_envelope")
        .ok_or(ManifestRejection::Malformed {
            field: "signed_envelope",
        })?;

    // --- 2. The row mirror, and who signed. ---
    let (attesting_key_id, attestation_id) = row_mirror(env)?;
    if attesting_key_id != pipeline_member.member_id {
        return Err(ManifestRejection::PipelineKeyMismatch {
            envelope: attesting_key_id.to_string(),
            member: pipeline_member.member_id.clone(),
        });
    }

    // --- 3. The signature. ---
    let ed_sig = str_field(&obj.body, "ed25519_signature_base64")?;
    let mldsa_sig = obj
        .body
        .get("mldsa65_signature_base64")
        .and_then(Value::as_str);
    if !envelope_verifies(env, ed_sig, mldsa_sig, pipeline_member) {
        return Err(ManifestRejection::PipelineSignatureInvalid);
    }

    // --- 4. What the Contribution says about itself. ---
    let scope = str_field(env, "delegation_scope")?;
    if scope != MANIFEST_PUBLISH_SCOPE {
        return Err(ManifestRejection::WrongScope {
            scope: scope.to_string(),
        });
    }
    let build = env
        .get("build")
        .ok_or(ManifestRejection::Malformed { field: "build" })?;
    let target = str_field(build, "target")?;
    let dimension = str_field(env, "dimension")?;
    let expected_dim = build_manifest_dimension(target);
    if dimension != expected_dim {
        return Err(ManifestRejection::DimensionMismatch {
            expected: expected_dim,
            found: dimension.to_string(),
        });
    }
    let asserted_at = str_field(env, "asserted_at")?;
    let manifest_hash = str_field(build, "manifest_hash")?;
    let evidence_refs = evidence_refs_bound_to(env, manifest_hash)?;

    // --- 5. The blessing is about this pipeline. ---
    if blessing.pipeline_key_id != attesting_key_id {
        return Err(ManifestRejection::BlessingNamesAnotherPipeline {
            blessing: blessing.pipeline_key_id.clone(),
            pipeline: attesting_key_id.to_string(),
        });
    }

    Ok(VerifiedManifest {
        attested_by: attesting_key_id.to_string(),
        standing: blessing.standing.clone(),
        attestation_id: attestation_id.to_string(),
        asserted_at: asserted_at.to_string(),
        target: target.to_string(),
        build_id: str_field(build, "build_id")?.to_string(),
        binary_hash: str_field(build, "binary_hash")?.to_string(),
        binary_version: str_field(build, "binary_version")?.to_string(),
        manifest_hash: manifest_hash.to_string(),
        manifest_size: build.get("manifest_size").and_then(Value::as_u64).ok_or(
            ManifestRejection::Malformed {
                field: "build.manifest_size (absent or not a u64 — CC 5.3.2.5)",
            },
        )?,
        evidence_refs,
    })
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    //! Shared by this module's tests and `build_attestation_bundle`'s.
    use super::*;
    use crate::self_at_login::HybridSigningIdentity;

    pub(crate) const PIPELINE: &str = "ci-pipeline-node-k7";
    pub(crate) const ROOT: &str = "humanity-accord";
    pub(crate) const GRANT: &str = "grant-infra-attest-1";

    pub(crate) fn asserted_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-01T14:50:29.308917Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    pub(crate) fn blessing() -> PipelineBlessing {
        PipelineBlessing::conferred(PIPELINE, ROOT, GRANT, WalkPlane::Delegation)
    }

    /// A pipeline identity and a Contribution it signed for `target`.
    pub(crate) async fn signed(target: &str) -> (HybridSigningIdentity, SignedCegObject, String) {
        let pipeline = HybridSigningIdentity::generate(PIPELINE).unwrap();
        let manifest_hash = "cd".repeat(32);
        let obj = sign_build_manifest_contribution(
            &pipeline,
            &BuildAttestation {
                target,
                binary_hash: &"ab".repeat(32),
                build_id: "ciris-verify@19.0.0",
                binary_version: "19.0.0",
                manifest_hash: &manifest_hash,
                manifest_size: 41_237,
            },
            asserted_at(),
        )
        .await
        .unwrap();
        (pipeline, obj, manifest_hash)
    }

    /// Re-sign `env` with `pipeline` into a Contribution object, so a test can
    /// alter the envelope and still present a valid signature over it.
    pub(crate) async fn resigned(pipeline: &HybridSigningIdentity, env: Value) -> SignedCegObject {
        let signed = pipeline.sign_envelope_async(env).await.unwrap();
        SignedCegObject::new(
            BUILD_MANIFEST_CONTRIBUTION_KIND,
            PIPELINE,
            "2026-10-01T14:50:29.308Z",
            serde_json::to_value(&signed).unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;

    const TARGET: &str = "python-source-tree";

    fn verify(
        pipeline: &crate::self_at_login::HybridSigningIdentity,
        obj: &SignedCegObject,
    ) -> Result<VerifiedManifest, ManifestRejection> {
        verify_build_manifest_contribution(obj, &pipeline.directory_member().unwrap(), &blessing())
    }

    /// The exact member set persist and CIRISRegistry's `fold_builds` read.
    /// A member added or dropped here is a wire change and must be deliberate.
    #[tokio::test]
    async fn producer_emits_the_persist_storable_shape() {
        let (_, obj, mh) = signed(TARGET).await;
        let env = &obj.body["signed_envelope"];
        let mut top: Vec<&str> = env
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        top.sort_unstable();
        assert_eq!(
            top,
            [
                "asserted_at",
                "build",
                "delegation_scope",
                "dimension",
                "evidence_refs",
                "row",
                "score"
            ],
            "no top-level identity members: the row mirror states them once"
        );
        assert_eq!(
            env["dimension"],
            "provenance:build_manifest:python-source-tree:v1"
        );
        assert_eq!(
            env["asserted_at"], "2026-10-01T14:50:29.308Z",
            "ms-truncated, Z"
        );
        assert_eq!(env["evidence_refs"], json!([mh]));
        let row = &env["row"];
        assert_eq!(row["attestation_type"], "scores");
        assert_eq!(row["cohort_scope"], "federation");
        assert_eq!(row["attesting_key_id"], PIPELINE);
        assert_eq!(row["attested_key_id"], PIPELINE);
        assert_eq!(row["subject_key_ids"], json!([]));
        let mut members: Vec<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        members.sort_unstable();
        assert!(members.iter().all(|m| ROW_MIRROR_MEMBERS.contains(m)));
    }

    /// The CC 3.1.7 R3 tail is on the dimension the producer emits — the
    /// defect #299 measured against a live persist Engine.
    #[tokio::test]
    async fn dimension_carries_the_version_tail() {
        let (_, obj, _) = signed("x86_64-unknown-linux-gnu").await;
        let d = obj.body["signed_envelope"]["dimension"].as_str().unwrap();
        assert!(d.ends_with(":v1"), "{d}");
        assert_eq!(d, build_manifest_dimension("x86_64-unknown-linux-gnu"));
    }

    #[tokio::test]
    async fn attestation_ids_are_fresh_uuid_v4() {
        let (_, a, _) = signed(TARGET).await;
        let (_, b, _) = signed(TARGET).await;
        let id = |o: &SignedCegObject| {
            o.body["signed_envelope"]["row"]["attestation_id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (ia, ib) = (id(&a), id(&b));
        assert_ne!(ia, ib, "one envelope names one row");
        assert_eq!(ia.len(), 36);
        assert_eq!(&ia[14..15], "4", "version nibble");
        assert!(matches!(&ia[19..20], "8" | "9" | "a" | "b"), "variant bits");
    }

    #[tokio::test]
    async fn round_trip_verifies_and_carries_the_blessing() {
        let (pipeline, obj, mh) = signed(TARGET).await;
        let v = verify(&pipeline, &obj).unwrap();
        assert_eq!(v.attested_by, PIPELINE);
        assert_eq!(
            v.standing,
            PipelineStanding::Conferred {
                root_key_id: ROOT.into(),
                grant_attestation_id: GRANT.into(),
                plane: WalkPlane::Delegation,
            }
        );
        assert_eq!(v.target, TARGET);
        assert_eq!(v.manifest_hash, mh);
        assert_eq!(v.evidence_refs, vec![mh]);
        assert_eq!(v.manifest_size, 41_237);
        assert_eq!(v.asserted_at, "2026-10-01T14:50:29.308Z");
    }

    /// The pre-19 unversioned dimension is refused, signature notwithstanding —
    /// no compatibility path, because no node could store that shape.
    #[tokio::test]
    async fn an_unversioned_dimension_is_refused() {
        let (pipeline, obj, _) = signed(TARGET).await;
        let mut env = obj.body["signed_envelope"].clone();
        env["dimension"] = json!("provenance:build_manifest:python-source-tree");
        let obj = resigned(&pipeline, env).await;
        assert!(matches!(
            verify(&pipeline, &obj),
            Err(ManifestRejection::DimensionMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn a_dimension_for_another_target_is_refused() {
        let (pipeline, obj, _) = signed(TARGET).await;
        let mut env = obj.body["signed_envelope"].clone();
        env["dimension"] = json!(build_manifest_dimension("ios-mobile-bundle"));
        let obj = resigned(&pipeline, env).await;
        assert!(matches!(
            verify(&pipeline, &obj),
            Err(ManifestRejection::DimensionMismatch { .. })
        ));
    }

    /// The v18 shape: top-level identity members, no row mirror.
    #[tokio::test]
    async fn an_envelope_without_a_row_mirror_is_refused() {
        let (pipeline, obj, _) = signed(TARGET).await;
        let mut env = obj.body["signed_envelope"].clone();
        let o = env.as_object_mut().unwrap();
        o.remove("row");
        o.insert("attesting_key_id".into(), json!(PIPELINE));
        let obj = resigned(&pipeline, env).await;
        assert!(matches!(
            verify(&pipeline, &obj),
            Err(ManifestRejection::Malformed { .. })
        ));
    }

    #[tokio::test]
    async fn row_mirror_shape_violations_are_refused() {
        let (pipeline, obj, _) = signed(TARGET).await;
        for (member, value) in [
            ("attestation_type", json!("delegates_to")),
            ("cohort_scope", json!("self")),
            ("attested_key_id", json!("someone-else")),
            ("attestation_id", json!("")),
            ("on_behalf_of", json!("a-human")),
        ] {
            let mut env = obj.body["signed_envelope"].clone();
            env["row"][member] = value;
            let o = resigned(&pipeline, env).await;
            assert!(
                matches!(
                    verify(&pipeline, &o),
                    Err(ManifestRejection::Malformed { .. })
                ),
                "row.{member} must be refused"
            );
        }
    }

    /// CC 5.3.2.5: the descriptor carries the blob's size; without it a
    /// fetcher can only fall back to the global cap.
    #[tokio::test]
    async fn a_build_without_a_declared_size_is_refused() {
        let (pipeline, obj, _) = signed(TARGET).await;
        for bad in [json!(null), json!("41237"), json!(-1)] {
            let mut env = obj.body["signed_envelope"].clone();
            if bad.is_null() {
                env["build"]
                    .as_object_mut()
                    .unwrap()
                    .remove("manifest_size");
            } else {
                env["build"]["manifest_size"] = bad;
            }
            let o = resigned(&pipeline, env).await;
            assert!(matches!(
                verify(&pipeline, &o),
                Err(ManifestRejection::Malformed { .. })
            ));
        }
    }

    #[tokio::test]
    async fn tampering_after_signing_breaks_the_signature() {
        let (pipeline, mut obj, _) = signed(TARGET).await;
        obj.body["signed_envelope"]["build"]["binary_hash"] = json!("00".repeat(32));
        assert_eq!(
            verify(&pipeline, &obj),
            Err(ManifestRejection::PipelineSignatureInvalid)
        );
    }

    #[tokio::test]
    async fn a_contribution_by_another_key_is_refused_before_the_signature() {
        let (_, obj, _) = signed(TARGET).await;
        let other =
            crate::self_at_login::HybridSigningIdentity::generate("other-pipeline").unwrap();
        assert!(matches!(
            verify_build_manifest_contribution(
                &obj,
                &other.directory_member().unwrap(),
                &blessing()
            ),
            Err(ManifestRejection::PipelineKeyMismatch { .. })
        ));
    }

    /// A blessing the caller obtained for pipeline P cannot be spent on a
    /// Contribution signed by Q.
    #[tokio::test]
    async fn a_blessing_for_another_pipeline_is_refused() {
        let (pipeline, obj, _) = signed(TARGET).await;
        let other = PipelineBlessing::accord_role("other-pipeline");
        assert!(matches!(
            verify_build_manifest_contribution(&obj, &pipeline.directory_member().unwrap(), &other),
            Err(ManifestRejection::BlessingNamesAnotherPipeline { .. })
        ));
    }

    #[tokio::test]
    async fn producer_references_exactly_the_manifest_blob() {
        let (_, obj, mh) = signed(TARGET).await;
        let env = &obj.body["signed_envelope"];
        assert_eq!(env["evidence_refs"], json!([mh]));
        assert_ne!(env["evidence_refs"][0], env["build"]["binary_hash"]);
    }

    #[tokio::test]
    async fn evidence_refs_must_name_the_manifest() {
        let (pipeline, obj, _) = signed(TARGET).await;
        for refs in [
            json!(null),
            json!(["ee".repeat(32)]),
            json!([format!("sha256:{}", "cd".repeat(32))]),
        ] {
            let mut env = obj.body["signed_envelope"].clone();
            if refs.is_null() {
                env.as_object_mut().unwrap().remove("evidence_refs");
            } else {
                env["evidence_refs"] = refs;
            }
            let o = resigned(&pipeline, env).await;
            assert!(matches!(
                verify(&pipeline, &o),
                Err(ManifestRejection::Malformed { .. })
            ));
        }
    }

    #[tokio::test]
    async fn producer_refuses_a_manifest_hash_no_consumer_would_match() {
        let pipeline = crate::self_at_login::HybridSigningIdentity::generate(PIPELINE).unwrap();
        for bad in [format!("sha256:{}", "cd".repeat(32)), "CD".repeat(32)] {
            let r = sign_build_manifest_contribution(
                &pipeline,
                &BuildAttestation {
                    target: TARGET,
                    binary_hash: &"ab".repeat(32),
                    build_id: "b",
                    binary_version: "v",
                    manifest_hash: &bad,
                    manifest_size: 1,
                },
                asserted_at(),
            )
            .await;
            assert!(r.is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn wrong_kind_object_is_rejected() {
        let (pipeline, mut obj, _) = signed(TARGET).await;
        obj.kind = "something_else".into();
        assert!(matches!(
            verify(&pipeline, &obj),
            Err(ManifestRejection::WrongKind { .. })
        ));
    }

    /// The production path (CIRISServer's accord ci-key ceremony): no grant
    /// exists, the accord role on the key record is the standing.
    #[tokio::test]
    async fn an_accord_role_blessing_verifies_and_is_reported_as_such() {
        let (pipeline, obj, _) = signed(TARGET).await;
        let v = verify_build_manifest_contribution(
            &obj,
            &pipeline.directory_member().unwrap(),
            &PipelineBlessing::accord_role(PIPELINE),
        )
        .unwrap();
        assert_eq!(v.standing, PipelineStanding::AccordRole);
        assert_eq!(v.standing.plane_str(), "accord_role");
    }

    #[test]
    fn standing_wire_names_are_distinct() {
        let names = [
            PipelineBlessing::conferred("p", "r", "g", WalkPlane::Delegation)
                .standing
                .plane_str(),
            PipelineBlessing::conferred("p", "r", "g", WalkPlane::FamilyQuorum)
                .standing
                .plane_str(),
            PipelineBlessing::accord_role("p").standing.plane_str(),
        ];
        assert_eq!(names, ["delegation", "family_quorum", "accord_role"]);
    }

    #[test]
    fn signed_instants_render_at_millisecond_resolution() {
        assert_eq!(
            render_signed_instant(asserted_at()),
            "2026-10-01T14:50:29.308Z"
        );
        let whole = DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(render_signed_instant(whole), "2026-10-01T00:00:00.000Z");
    }
}
