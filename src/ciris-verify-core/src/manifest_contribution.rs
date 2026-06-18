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
use crate::self_at_login::SelfSigner;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jcs;
    use crate::self_at_login::HybridSigningIdentity;
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
}
