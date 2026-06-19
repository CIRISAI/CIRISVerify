//! Build manifest as a CEG `scores` Contribution — the **pipeline-as-delegated-
//! attester** model (drops the free-floating "steward key").
//!
//! ## The trust model
//!
//! Authority roots in an accountable human (CC §1.13.2), never a bare build
//! key. So:
//!
//! 1. The CI **pipeline** holds a `node` (infrastructure) hybrid identity — its
//!    own keyset, made into a nodecode ([`crate::fedcode`], `kind: node`).
//! 2. The human **grants** the pipeline `delegates_to(human → pipeline,
//!    infra:attest)` (CC §2.4.1; the existing [`MANIFEST_PUBLISH_SCOPE`] infra
//!    scope from the #77 split — a `node` may hold `infra:*`, never `agency:*`).
//!    That grant is "publish manifests on my behalf."
//! 3. The pipeline signs each build manifest **as the human's delegate** — this
//!    producer. The Contribution carries `on_behalf_of` (the human) +
//!    `delegation_ref` (the grant), so a consumer can walk the authority chain
//!    up from the pipeline's `attesting_key_id` to the human (CC RC24 walk-up).
//! 4. The canonical infra trio (`ciris-canonical`, [`crate::infrastructure_community`],
//!    #31) trusts a build iff its chain roots in a human the trio recognizes as
//!    a build authority — "trust the builds I trust," configured once.
//!
//! ## The object
//!
//! A JCS-canonicalized `scores` Contribution on
//! `provenance:build_manifest:{target}` ([`crate::federation_provenance`]),
//! bound-hybrid-signed by the pipeline identity (any [`SelfSigner`]), emitted as
//! a [`SignedCegObject`] for the CEG outbox → CIRISServer relay → CEG-native
//! replication by registry/server. The signature is the same threshold-1
//! bound-hybrid the rest of the federation verifies; no bespoke `/v1/builds`
//! path.
//!
//! **Cross-impl flag:** the envelope member set (`on_behalf_of`,
//! `delegation_ref`, the `build` sub-object) is pinned here but flagged for
//! CIRISServer/Registry cross-confirmation, like the #76 partnership set.

use serde_json::{json, Value};

use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::operational_admit::verify_delegation_scope_split;
use crate::self_at_login::{SelfSigner, SignedEnvelope};
use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// The `infra:*` scope a pipeline must hold (via `delegates_to`) to publish
/// manifests on a human's behalf — the existing #77 "attest on my behalf" scope.
pub const MANIFEST_PUBLISH_SCOPE: &str = "infra:attest";

/// CEG `kind` for a build-manifest Contribution in the outbox.
pub const BUILD_MANIFEST_CONTRIBUTION_KIND: &str = "build_manifest_contribution";

/// The build facts a manifest Contribution attests. (The full file manifest
/// stays available by `manifest_hash`; the Contribution carries the trust-
/// bearing facts so the trio can decide without fetching the file list.)
pub struct BuildAttestation<'a> {
    /// Rust target triple (e.g. `x86_64-unknown-linux-gnu`).
    pub target: &'a str,
    /// SHA-256 of the built binary, hex.
    pub binary_hash: &'a str,
    /// The build identifier (the Contribution's subject).
    pub build_id: &'a str,
    /// The binary's version string.
    pub binary_version: &'a str,
    /// SHA-256 of the canonical file manifest, hex.
    pub manifest_hash: &'a str,
}

/// The `provenance:build_manifest:{target}` dimension this attests.
#[must_use]
pub fn build_manifest_dimension(target: &str) -> String {
    format!("provenance:build_manifest:{target}")
}

/// Sign a build-manifest Contribution **as the human's delegate**.
///
/// `pipeline` is the pipeline's hybrid `node` identity (owner-bound to
/// `on_behalf_of` via the `delegation_ref` grant). The output verifies as a
/// threshold-1 bound-hybrid signature against the pipeline's pinned pubkeys;
/// the consumer additionally walks the authority chain to `on_behalf_of` and
/// checks the trio trusts that human.
///
/// # Errors
///
/// [`VerifyError`] only on a canonicalization or signer fault.
pub async fn sign_build_manifest_contribution(
    pipeline: &dyn SelfSigner,
    build: &BuildAttestation<'_>,
    on_behalf_of: &str,
    delegation_ref: &str,
    signed_at: &str,
) -> Result<SignedCegObject, VerifyError> {
    let envelope = json!({
        "attestation_type": "scores",
        "attesting_key_id": pipeline.key_id(),
        "dimension": build_manifest_dimension(build.target),
        "score": 1,
        "subject_key_ids": [build.build_id],
        "on_behalf_of": on_behalf_of,
        "delegation_scope": MANIFEST_PUBLISH_SCOPE,
        "delegation_ref": delegation_ref,
        "build": {
            "target": build.target,
            "binary_hash": build.binary_hash,
            "build_id": build.build_id,
            "binary_version": build.binary_version,
            "manifest_hash": build.manifest_hash,
        },
        "signed_at": signed_at,
    });

    let signed = pipeline.sign_envelope_async(envelope).await?;
    let body: Value = serde_json::to_value(&signed).map_err(|e| VerifyError::IntegrityError {
        message: format!("serialize manifest contribution: {e}"),
    })?;
    Ok(SignedCegObject::new(
        BUILD_MANIFEST_CONTRIBUTION_KIND,
        pipeline.key_id(),
        signed_at,
        body,
    ))
}

// ===========================================================================
// Consumer side: verify a build-manifest Contribution end-to-end.
//
// This is the verify-side primitive CIRISServer (#25) calls when it drains the
// CEG outbox. Per the #65 two-quorums split, *signature + authority
// verification is Verify's* — the substrate's merge logic never counts
// signatures. The server resolves the pinned pubkeys from its key directory and
// the trusted-author set from the trio's config, then asks this one function
// "should I trust this build?".
// ===========================================================================

/// The trust-bearing facts of a build, returned once a Contribution has passed
/// the full chain. The server stores/relays these — never the unverified body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    /// The pipeline `node` key_id that signed the Contribution.
    pub attested_by: String,
    /// The accountable human the chain roots in (CC §1.13.2).
    pub on_behalf_of: String,
    /// Rust target triple.
    pub target: String,
    /// The build identifier (Contribution subject).
    pub build_id: String,
    /// SHA-256 of the built binary, hex.
    pub binary_hash: String,
    /// The binary's version string.
    pub binary_version: String,
    /// SHA-256 of the canonical file manifest, hex.
    pub manifest_hash: String,
}

/// Why a build-manifest Contribution was **not** trusted. Every variant is a
/// hard reject — there is no partial-trust path (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestRejection {
    /// The outbox object is not a `build_manifest_contribution`.
    WrongKind {
        /// The kind actually found.
        kind: String,
    },
    /// A required field is missing or the wrong type.
    Malformed {
        /// Which field.
        field: &'static str,
    },
    /// The pipeline's bound-hybrid signature did not verify at threshold 1
    /// against its pinned pubkeys (RequireHybrid — federation tier).
    PipelineSignatureInvalid,
    /// The envelope's `attesting_key_id` does not match the supplied pipeline
    /// member's `member_id` — the caller pinned the wrong key.
    PipelineKeyMismatch {
        /// The `attesting_key_id` in the envelope.
        envelope: String,
        /// The `member_id` of the pinned member.
        member: String,
    },
    /// The Contribution's `delegation_scope` is not [`MANIFEST_PUBLISH_SCOPE`].
    WrongScope {
        /// The scope found.
        scope: String,
    },
    /// The `dimension` is not `provenance:build_manifest:{target}` for the
    /// attested `build.target` — a mismatched/forged subject.
    DimensionMismatch {
        /// The dimension expected from `build.target`.
        expected: String,
        /// The dimension found in the envelope.
        found: String,
    },
    /// The granter's (human's) signature over the delegation grant did not
    /// verify at threshold 1 against the pinned granter pubkeys.
    GrantSignatureInvalid,
    /// The grant envelope is not a `dimension: "delegates_to"` capability grant.
    GrantNotDelegation {
        /// The dimension found on the grant.
        dimension: String,
    },
    /// The grant's `attesting_key_id` (the granter) does not equal the
    /// Contribution's `on_behalf_of`, or the pinned granter member — the grant
    /// does not authorize *this* human.
    GranterMismatch {
        /// The grant's `attesting_key_id`.
        grant: String,
        /// The Contribution's `on_behalf_of`.
        on_behalf_of: String,
    },
    /// The grant's `subject_key_ids` does not include the pipeline — the human
    /// delegated to someone else, not this pipeline.
    GrantSubjectMismatch {
        /// The pipeline key_id that should have been the subject.
        pipeline: String,
    },
    /// The grant does not actually carry [`MANIFEST_PUBLISH_SCOPE`].
    GrantMissingScope {
        /// The scope the Contribution claimed but the grant omits.
        scope: String,
    },
    /// The grant's scope set violates the §1.3 infra/agency split for a `node`
    /// delegate (e.g. it smuggles an `agency:*` scope).
    ScopeSplitViolation {
        /// Human-readable detail from [`verify_delegation_scope_split`].
        detail: String,
    },
    /// The chain is cryptographically sound but the human it roots in is **not**
    /// in the trio's trusted-build-authority set — "I don't trust this builder."
    AuthorityNotTrusted {
        /// The human key_id that was not trusted.
        on_behalf_of: String,
    },
}

impl std::fmt::Display for ManifestRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKind { kind } => {
                write!(f, "not a build-manifest contribution: kind {kind:?}")
            },
            Self::Malformed { field } => {
                write!(f, "malformed manifest contribution: field {field:?}")
            },
            Self::PipelineSignatureInvalid => {
                write!(f, "pipeline bound-hybrid signature did not verify")
            },
            Self::PipelineKeyMismatch { envelope, member } => {
                write!(
                    f,
                    "pipeline key mismatch: envelope {envelope:?} != pinned member {member:?}"
                )
            },
            Self::WrongScope { scope } => write!(
                f,
                "contribution delegation_scope {scope:?} is not infra:attest"
            ),
            Self::DimensionMismatch { expected, found } => {
                write!(
                    f,
                    "dimension mismatch: expected {expected:?}, found {found:?}"
                )
            },
            Self::GrantSignatureInvalid => write!(f, "delegation grant signature did not verify"),
            Self::GrantNotDelegation { dimension } => {
                write!(f, "grant is not delegates_to: dimension {dimension:?}")
            },
            Self::GranterMismatch {
                grant,
                on_behalf_of,
            } => {
                write!(
                    f,
                    "granter mismatch: grant signer {grant:?} != on_behalf_of {on_behalf_of:?}"
                )
            },
            Self::GrantSubjectMismatch { pipeline } => {
                write!(f, "grant does not delegate to pipeline {pipeline:?}")
            },
            Self::GrantMissingScope { scope } => write!(f, "grant does not carry scope {scope:?}"),
            Self::ScopeSplitViolation { detail } => write!(f, "scope split violation: {detail}"),
            Self::AuthorityNotTrusted { on_behalf_of } => {
                write!(
                    f,
                    "authority not trusted: {on_behalf_of:?} is not a trusted build authority"
                )
            },
        }
    }
}

impl std::error::Error for ManifestRejection {}

/// Pull a `&str` field from a JSON object, or [`ManifestRejection::Malformed`].
fn str_field<'a>(v: &'a Value, field: &'static str) -> Result<&'a str, ManifestRejection> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or(ManifestRejection::Malformed { field })
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

/// Verify a build-manifest Contribution end-to-end and return the trusted build
/// facts — the **consumer** of [`sign_build_manifest_contribution`].
///
/// The full chain (all fail-closed):
///
/// 1. `obj` is a `build_manifest_contribution`; its envelope is well-formed.
/// 2. The **pipeline** bound-hybrid signature verifies at threshold 1 against
///    `pipeline_member` (the pinned `node` pubkeys), and the envelope's
///    `attesting_key_id` is that member.
/// 3. The Contribution carries `delegation_scope == infra:attest` and a
///    `dimension` matching its own `build.target`.
/// 4. The **granter** (human) signature over `grant` verifies at threshold 1
///    against `granter_member`, and `grant` is a `delegates_to` whose signer is
///    the Contribution's `on_behalf_of`, whose `subject_key_ids` includes the
///    pipeline, and whose `delegated_scope` carries `infra:attest`.
/// 5. That scope set passes the §1.3 infra/agency split for a `node` delegate.
/// 6. `on_behalf_of` is in `trusted_build_authorities` — the trio's "builders I
///    trust" set. (Pass an empty slice to verify the chain *without* the trust
///    decision — e.g. to surface "who does this root in?" before deciding.)
///
/// `pipeline_member` / `granter_member` are pinned by the **caller** from its
/// key directory (by `attesting_key_id`) — never taken from the object — so a
/// forged grant under a human's key_id fails the binding (the #65 / §8.1.12.7.1
/// identity-binding discipline).
///
/// # Errors
///
/// A [`ManifestRejection`] naming the first failing step.
pub fn verify_build_manifest_contribution(
    obj: &SignedCegObject,
    pipeline_member: &ThresholdMember,
    grant: &SignedEnvelope,
    granter_member: &ThresholdMember,
    trusted_build_authorities: &[String],
) -> Result<VerifiedManifest, ManifestRejection> {
    if obj.kind != BUILD_MANIFEST_CONTRIBUTION_KIND {
        return Err(ManifestRejection::WrongKind {
            kind: obj.kind.clone(),
        });
    }

    // --- 1. Extract the signed Contribution envelope + its signatures. ---
    let env = obj
        .body
        .get("signed_envelope")
        .ok_or(ManifestRejection::Malformed {
            field: "signed_envelope",
        })?;
    let ed_sig = str_field(&obj.body, "ed25519_signature_base64")?;
    let mldsa_sig = obj
        .body
        .get("mldsa65_signature_base64")
        .and_then(Value::as_str);

    // --- 2. Pipeline signature verifies, and binds to the pinned member. ---
    let attesting_key_id = str_field(env, "attesting_key_id")?;
    if attesting_key_id != pipeline_member.member_id {
        return Err(ManifestRejection::PipelineKeyMismatch {
            envelope: attesting_key_id.to_string(),
            member: pipeline_member.member_id.clone(),
        });
    }
    if !envelope_verifies(env, ed_sig, mldsa_sig, pipeline_member) {
        return Err(ManifestRejection::PipelineSignatureInvalid);
    }

    // --- 3. Scope + dimension self-consistency. ---
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
    let on_behalf_of = str_field(env, "on_behalf_of")?;

    // --- 4. The delegation grant: human → pipeline, signature-valid. ---
    let grant_env = &grant.signed_envelope;
    let grant_dimension = str_field(grant_env, "dimension")?;
    if grant_dimension != "delegates_to" {
        return Err(ManifestRejection::GrantNotDelegation {
            dimension: grant_dimension.to_string(),
        });
    }
    let grant_signer = str_field(grant_env, "attesting_key_id")?;
    // The grant must be signed by the human the Contribution claims, *and* that
    // human must be the pinned granter member (binding to the directory, not to
    // the self-asserted field).
    if grant_signer != on_behalf_of || grant_signer != granter_member.member_id {
        return Err(ManifestRejection::GranterMismatch {
            grant: grant_signer.to_string(),
            on_behalf_of: on_behalf_of.to_string(),
        });
    }
    let mldsa_grant = if grant.mldsa65_signature_base64.is_empty() {
        None
    } else {
        Some(grant.mldsa65_signature_base64.as_str())
    };
    if !envelope_verifies(
        grant_env,
        &grant.ed25519_signature_base64,
        mldsa_grant,
        granter_member,
    ) {
        return Err(ManifestRejection::GrantSignatureInvalid);
    }

    // The grant must delegate to *this* pipeline.
    let subjects = grant_env
        .get("subject_key_ids")
        .and_then(Value::as_array)
        .ok_or(ManifestRejection::Malformed {
            field: "subject_key_ids",
        })?;
    if !subjects
        .iter()
        .any(|s| s.as_str() == Some(attesting_key_id))
    {
        return Err(ManifestRejection::GrantSubjectMismatch {
            pipeline: attesting_key_id.to_string(),
        });
    }

    // The grant must actually carry the manifest-publish scope.
    let grant_scopes: Vec<String> = grant_env
        .get("delegated_scope")
        .and_then(Value::as_array)
        .ok_or(ManifestRejection::Malformed {
            field: "delegated_scope",
        })?
        .iter()
        .filter_map(|s| s.as_str().map(str::to_string))
        .collect();
    if !grant_scopes.iter().any(|s| s == MANIFEST_PUBLISH_SCOPE) {
        return Err(ManifestRejection::GrantMissingScope {
            scope: MANIFEST_PUBLISH_SCOPE.to_string(),
        });
    }

    // --- 5. §1.3 infra/agency split: a `node` pipeline may hold only infra:*. ---
    if let Err(e) = verify_delegation_scope_split("node", &grant_scopes) {
        return Err(ManifestRejection::ScopeSplitViolation {
            detail: e.to_string(),
        });
    }

    // --- 6. The trust decision: is the root human a trusted build authority? ---
    if !trusted_build_authorities.is_empty()
        && !trusted_build_authorities.iter().any(|a| a == on_behalf_of)
    {
        return Err(ManifestRejection::AuthorityNotTrusted {
            on_behalf_of: on_behalf_of.to_string(),
        });
    }

    Ok(VerifiedManifest {
        attested_by: attesting_key_id.to_string(),
        on_behalf_of: on_behalf_of.to_string(),
        target: target.to_string(),
        build_id: str_field(build, "build_id")?.to_string(),
        binary_hash: str_field(build, "binary_hash")?.to_string(),
        binary_version: str_field(build, "binary_version")?.to_string(),
        manifest_hash: str_field(build, "manifest_hash")?.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jcs;
    use crate::self_at_login::{sign_delegation_grant, HybridSigningIdentity};
    use crate::threshold::{verify_threshold_signatures, ThresholdSignature};

    fn build_owned() -> (String, String) {
        ("ab".repeat(32), "cd".repeat(32))
    }

    #[tokio::test]
    async fn pipeline_signed_manifest_verifies_at_threshold_one() {
        let pipeline = HybridSigningIdentity::generate("ci-pipeline-node-k7").unwrap();
        let (bh, mh) = build_owned();
        let b = BuildAttestation {
            target: "x86_64-unknown-linux-gnu",
            binary_hash: &bh,
            build_id: "ciris-verify@6.0.0",
            binary_version: "6.0.0",
            manifest_hash: &mh,
        };

        let obj = sign_build_manifest_contribution(
            &pipeline,
            &b,
            "eric-moore-6qg6wdx2dq", // the human the pipeline attests FOR
            "delegation:infra-attest:abc123",
            "2026-06-18T00:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(obj.kind, BUILD_MANIFEST_CONTRIBUTION_KIND);
        let env = &obj.body["signed_envelope"];
        assert_eq!(env["attestation_type"], "scores");
        assert_eq!(
            env["dimension"],
            "provenance:build_manifest:x86_64-unknown-linux-gnu"
        );
        assert_eq!(env["on_behalf_of"], "eric-moore-6qg6wdx2dq");
        assert_eq!(env["delegation_scope"], "infra:attest");

        // The pipeline's signature verifies at threshold 1 (the consumer then
        // walks on_behalf_of/delegation_ref to root the authority in the human).
        let bytes = jcs::canonicalize(env).unwrap();
        let sig = ThresholdSignature {
            member_id: "ci-pipeline-node-k7".to_string(),
            ed25519_signature_base64: obj.body["ed25519_signature_base64"]
                .as_str()
                .unwrap()
                .to_string(),
            mldsa65_signature_base64: obj.body["mldsa65_signature_base64"]
                .as_str()
                .map(str::to_string),
        };
        assert_eq!(
            verify_threshold_signatures(&bytes, &[pipeline.directory_member().unwrap()], &[sig], 1),
            Ok(1),
        );
    }

    #[tokio::test]
    async fn tampering_the_binary_hash_breaks_the_signature() {
        let pipeline = HybridSigningIdentity::generate("ci-pipeline-node-k7").unwrap();
        let (bh, mh) = build_owned();
        let b = BuildAttestation {
            target: "x",
            binary_hash: &bh,
            build_id: "b",
            binary_version: "v",
            manifest_hash: &mh,
        };
        let mut obj =
            sign_build_manifest_contribution(&pipeline, &b, "human", "ref", "2026-06-18T00:00:00Z")
                .await
                .unwrap();
        // Swap the attested binary_hash after signing.
        obj.body["signed_envelope"]["build"]["binary_hash"] = json!("00".repeat(32));
        let bytes = jcs::canonicalize(&obj.body["signed_envelope"]).unwrap();
        let sig = ThresholdSignature {
            member_id: "ci-pipeline-node-k7".to_string(),
            ed25519_signature_base64: obj.body["ed25519_signature_base64"]
                .as_str()
                .unwrap()
                .into(),
            mldsa65_signature_base64: obj.body["mldsa65_signature_base64"]
                .as_str()
                .map(Into::into),
        };
        assert!(
            verify_threshold_signatures(&bytes, &[pipeline.directory_member().unwrap()], &[sig], 1)
                .is_err(),
            "a tampered build_hash must break the manifest signature"
        );
    }

    // -- Consumer side: verify_build_manifest_contribution --------------------

    const HUMAN: &str = "eric-moore-6qg6wdx2dq";
    const PIPELINE: &str = "ciris-verify-build-pipeline";
    const TS: &str = "2026-06-18T00:00:00Z";

    /// Build a full valid chain: a human grants `infra:attest` to a pipeline
    /// `node`, the pipeline signs a manifest Contribution on the human's behalf.
    /// Returns everything `verify_build_manifest_contribution` needs.
    async fn valid_chain() -> (
        SignedCegObject,
        ThresholdMember,
        SignedEnvelope,
        ThresholdMember,
    ) {
        let human = HybridSigningIdentity::generate(HUMAN).unwrap();
        let pipeline = HybridSigningIdentity::generate(PIPELINE).unwrap();
        let grant =
            sign_delegation_grant(&human, PIPELINE, &["infra:attest".to_string()], TS).unwrap();
        let (bh, mh) = build_owned();
        let b = BuildAttestation {
            target: "x86_64-unknown-linux-gnu",
            binary_hash: &bh,
            build_id: "ciris-verify@6.2.0",
            binary_version: "6.2.0",
            manifest_hash: &mh,
        };
        let obj = sign_build_manifest_contribution(
            &pipeline,
            &b,
            HUMAN,
            "delegation:infra-attest:abc123",
            TS,
        )
        .await
        .unwrap();
        (
            obj,
            pipeline.directory_member().unwrap(),
            grant,
            human.directory_member().unwrap(),
        )
    }

    #[tokio::test]
    async fn valid_chain_verifies_and_roots_in_the_trusted_human() {
        let (obj, pm, grant, gm) = valid_chain().await;
        let v = verify_build_manifest_contribution(&obj, &pm, &grant, &gm, &[HUMAN.to_string()])
            .expect("a fully valid chain rooting in a trusted human must verify");
        assert_eq!(v.attested_by, PIPELINE);
        assert_eq!(v.on_behalf_of, HUMAN);
        assert_eq!(v.target, "x86_64-unknown-linux-gnu");
        assert_eq!(v.binary_version, "6.2.0");
    }

    #[tokio::test]
    async fn empty_trust_set_verifies_chain_without_trust_decision() {
        // Chain-valid but no trust list supplied → "who does this root in?" path.
        let (obj, pm, grant, gm) = valid_chain().await;
        let v = verify_build_manifest_contribution(&obj, &pm, &grant, &gm, &[]).unwrap();
        assert_eq!(v.on_behalf_of, HUMAN);
    }

    #[tokio::test]
    async fn untrusted_human_is_rejected_even_with_a_valid_chain() {
        let (obj, pm, grant, gm) = valid_chain().await;
        let err = verify_build_manifest_contribution(
            &obj,
            &pm,
            &grant,
            &gm,
            &["someone-else-zzz".to_string()],
        )
        .unwrap_err();
        assert_eq!(
            err,
            ManifestRejection::AuthorityNotTrusted {
                on_behalf_of: HUMAN.to_string()
            }
        );
    }

    #[tokio::test]
    async fn tampered_contribution_fails_the_pipeline_signature() {
        let (mut obj, pm, grant, gm) = valid_chain().await;
        obj.body["signed_envelope"]["build"]["binary_hash"] = json!("00".repeat(32));
        let err = verify_build_manifest_contribution(&obj, &pm, &grant, &gm, &[HUMAN.to_string()])
            .unwrap_err();
        assert_eq!(err, ManifestRejection::PipelineSignatureInvalid);
    }

    #[tokio::test]
    async fn wrong_pinned_pipeline_key_is_rejected_before_sig_check() {
        let (obj, _pm, grant, gm) = valid_chain().await;
        let wrong = HybridSigningIdentity::generate("not-the-pipeline")
            .unwrap()
            .directory_member()
            .unwrap();
        let err =
            verify_build_manifest_contribution(&obj, &wrong, &grant, &gm, &[HUMAN.to_string()])
                .unwrap_err();
        assert!(matches!(err, ManifestRejection::PipelineKeyMismatch { .. }));
    }

    #[tokio::test]
    async fn forged_grant_under_the_humans_key_id_fails_the_binding() {
        // An attacker mints a grant claiming the human's key_id but signs it with
        // their own key. The pinned granter member is the REAL human → sig fails.
        let (obj, pm, _grant, gm) = valid_chain().await;
        let attacker = HybridSigningIdentity::generate(HUMAN).unwrap(); // same id, different keys
        let forged =
            sign_delegation_grant(&attacker, PIPELINE, &["infra:attest".to_string()], TS).unwrap();
        let err = verify_build_manifest_contribution(&obj, &pm, &forged, &gm, &[HUMAN.to_string()])
            .unwrap_err();
        assert_eq!(err, ManifestRejection::GrantSignatureInvalid);
    }

    #[tokio::test]
    async fn grant_to_a_different_pipeline_is_rejected() {
        let (obj, pm, _grant, _gm) = valid_chain().await;
        // The human really did sign a grant — but to some other node. Rebuild a
        // fresh granter member so its keys match this new grant.
        let human = HybridSigningIdentity::generate(HUMAN).unwrap();
        let gm2 = human.directory_member().unwrap();
        let grant =
            sign_delegation_grant(&human, "some-other-node", &["infra:attest".to_string()], TS)
                .unwrap();
        let err = verify_build_manifest_contribution(&obj, &pm, &grant, &gm2, &[HUMAN.to_string()])
            .unwrap_err();
        assert_eq!(
            err,
            ManifestRejection::GrantSubjectMismatch {
                pipeline: PIPELINE.to_string()
            }
        );
    }

    #[tokio::test]
    async fn grant_missing_infra_attest_scope_is_rejected() {
        let (obj, pm, _grant, _gm) = valid_chain().await;
        let human = HybridSigningIdentity::generate(HUMAN).unwrap();
        let gm2 = human.directory_member().unwrap();
        // A grant that delegates SOME infra scope, but not infra:attest.
        let grant =
            sign_delegation_grant(&human, PIPELINE, &["infra:relay".to_string()], TS).unwrap();
        let err = verify_build_manifest_contribution(&obj, &pm, &grant, &gm2, &[HUMAN.to_string()])
            .unwrap_err();
        assert_eq!(
            err,
            ManifestRejection::GrantMissingScope {
                scope: "infra:attest".to_string()
            }
        );
    }

    #[tokio::test]
    async fn node_grant_smuggling_agency_scope_fails_the_split() {
        let (obj, pm, _grant, _gm) = valid_chain().await;
        let human = HybridSigningIdentity::generate(HUMAN).unwrap();
        let gm2 = human.directory_member().unwrap();
        // Carries infra:attest (so the scope check passes) but also an agency
        // scope a node must never hold → §1.3 split rejects it.
        let grant = sign_delegation_grant(
            &human,
            PIPELINE,
            &["infra:attest".to_string(), "agency:act".to_string()],
            TS,
        )
        .unwrap();
        let err = verify_build_manifest_contribution(&obj, &pm, &grant, &gm2, &[HUMAN.to_string()])
            .unwrap_err();
        assert!(matches!(err, ManifestRejection::ScopeSplitViolation { .. }));
    }

    #[tokio::test]
    async fn wrong_kind_object_is_rejected() {
        let (mut obj, pm, grant, gm) = valid_chain().await;
        obj.kind = "something_else".to_string();
        let err = verify_build_manifest_contribution(&obj, &pm, &grant, &gm, &[HUMAN.to_string()])
            .unwrap_err();
        assert_eq!(
            err,
            ManifestRejection::WrongKind {
                kind: "something_else".to_string()
            }
        );
    }
}
