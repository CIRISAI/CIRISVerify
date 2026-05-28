//! Federation provenance — scalar attestation surface (CIRISVerify#33).
//!
//! The response-shape change that makes verify's `MISSION.md` §1.4
//! invariant — *every federation primitive authenticates origin; none
//! confers trust* — **structural** rather than just documented.
//!
//! Today verify returns a binary trust verdict. In the decentralized
//! federation (Agent 3.0 — registry / node / lens fold into the agent;
//! no central authority), no single verdict can be authoritative
//! because no single party decides policy. Verify must therefore
//! expose the **composed attestations themselves** — dimension /
//! score / attester triples — so each consumer applies its own policy
//! per the eight epistemic axes (FSD-002 §1).
//!
//! ## The dimension namespace (FSD-002 §3.2)
//!
//! CIRISVerify owns twelve canonical dimensions, named for what is
//! measured (no L1/L2/L3/L4/L5 ladder numbering in the wire shape —
//! the ladder is consumer policy, not verify-side framing; v3.7.0+).
//! Addressable via the [`dim`] module:
//!
//! | Dimension                                  | Polarity         |
//! |--------------------------------------------|------------------|
//! | `attestation:self_verify`                  | boolean-via-score |
//! | `attestation:hardware`                     | boolean-via-score |
//! | `attestation:registry_consensus`           | boolean-via-score + Indeterminate (future) |
//! | `attestation:license_validity`             | boolean-via-score |
//! | `attestation:agent_integrity`              | boolean-via-score |
//! | `provenance:slsa:{level}`                  | boolean-via-score |
//! | `provenance:build_manifest:{target}`       | boolean-via-score |
//! | `transparency_log:inclusion`               | boolean-via-score |
//! | `transparency_log:consistency`             | boolean-via-score |
//! | `rollback_detected:{revision_field}`       | **-1 only** (no positive direction) |
//! | `cert_validity:{authority}`                | boolean-via-score |
//! | `hardware_custody:{platform}`              | boolean-via-score |
//!
//! "boolean-via-score" means a 0.0 or 1.0 score; `rollback_detected`
//! is the one dimension that may legitimately emit a *negative* score
//! (and only -1.0 — there is no positive direction).
//! `attestation:registry_consensus` may also emit Indeterminate
//! (mapped to `Score::Indeterminate` in v3.2+; not yet wired by
//! [`crate::unified::FullAttestationResult`]).
//!
//! ## What this module does NOT do
//!
//! It does **not** compose a verdict. Verify *carries* the attestation
//! list; consumers (CIRISAgent's runtime policy, CIRISPersist's
//! `secrets-hw` gate, CIRISLensCore's scoring) compose a verdict per
//! their own named policy. A policy *name* may travel in
//! [`FederationProvenance::policy`] for auditability, but the
//! verdict itself is not verify's to declare.

use serde::{Deserialize, Serialize};

/// Verify-owned canonical dimension strings (FSD-002 §3.2). Stable
/// wire constants — a change is a cross-repo coordination event.
///
/// Parameterized dimensions use the helper functions; unparameterized
/// ones are `&'static str` constants.
pub mod dim {
    /// Self-verification — the running CIRISVerify binary attests
    /// itself against its function manifest ("who watches the
    /// watchmen"). The recursive golden rule.
    pub const SELF_VERIFY: &str = "attestation:self_verify";

    /// Hardware attestation — hardware-rooted attestation
    /// (TPM 2.0 / Android Keystore / iOS Secure Enclave).
    pub const HARDWARE: &str = "attestation:hardware";

    /// Registry consensus — 2-of-3 multi-source registry consensus.
    /// May legitimately emit Indeterminate when sources disagree.
    pub const REGISTRY_CONSENSUS: &str = "attestation:registry_consensus";

    /// License validity — registry-signed, verify-verified license.
    pub const LICENSE_VALIDITY: &str = "attestation:license_validity";

    /// Agent integrity — agent source-tree byte-equal against
    /// registered manifest (`verify_tree` Algorithm A).
    pub const AGENT_INTEGRITY: &str = "attestation:agent_integrity";

    /// RFC 6962 inclusion proof for an audit leaf.
    pub const TRANSPARENCY_LOG_INCLUSION: &str = "transparency_log:inclusion";

    /// RFC 6962 consistency proof between two STHs.
    pub const TRANSPARENCY_LOG_CONSISTENCY: &str = "transparency_log:consistency";

    /// SLSA build provenance at `level` (1-3). FSD-002 §3.2.
    #[must_use]
    pub fn provenance_slsa(level: u8) -> String {
        format!("provenance:slsa:{level}")
    }

    /// Per-target canonical-staged-runtime manifest hash equality.
    #[must_use]
    pub fn provenance_build_manifest(target: &str) -> String {
        format!("provenance:build_manifest:{target}")
    }

    /// Anti-rollback signal — a decrease in a revocation revision.
    /// **Polarity: -1 only.** Emit with `score = -1.0`.
    #[must_use]
    pub fn rollback_detected(revision_field: &str) -> String {
        format!("rollback_detected:{revision_field}")
    }

    /// Validity of a certification authority's signature over the key.
    #[must_use]
    pub fn cert_validity(authority: &str) -> String {
        format!("cert_validity:{authority}")
    }

    /// Hardware-custody statement — where the seed lives. `platform`
    /// is one of `tpm` / `ios_secure_enclave` / `android_keystore` /
    /// `software_fallback` (the last caps at `UNLICENSED_COMMUNITY`).
    #[must_use]
    pub fn hardware_custody(platform: &str) -> String {
        format!("hardware_custody:{platform}")
    }
}

/// One attestation entry — `dimension`, `score`, who attested.
///
/// Per FSD-002 §3.2 the polarity of `score` is dimension-defined:
/// most dimensions are boolean-via-score (0.0 = fail, 1.0 = pass);
/// `rollback_detected:*` is **-1 only** (anti-rollback signal).
/// `attestation:registry_consensus` may emit Indeterminate (see
/// [`Score::INDETERMINATE`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationEntry {
    /// Canonical dimension string (see [`dim`]).
    pub dimension: String,
    /// Score under the dimension's polarity.
    pub score: f64,
    /// Who produced the attestation — a `key_id`, a registry steward
    /// id, the verify binary itself ("ciris-verify"), etc.
    pub attester: String,
    /// Optional source reference — a persist row hash, a registry
    /// URL, a transparency-log STH, an audit-leaf hash. Lets a
    /// consumer trace the attestation back to its origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}

/// Score sentinels — semantic constants for the three legitimate
/// boolean-via-score values plus Indeterminate.
pub struct Score;
impl Score {
    /// Boolean-via-score: the attestation passed.
    pub const PASS: f64 = 1.0;
    /// Boolean-via-score: the attestation failed.
    pub const FAIL: f64 = 0.0;
    /// `rollback_detected:*` only — a negative-direction signal.
    pub const ROLLBACK: f64 = -1.0;
    /// `registry_consensus` only — verdict undecidable from
    /// available evidence (encoded as NaN). Tests use
    /// [`AttestationEntry::is_indeterminate`].
    pub const INDETERMINATE: f64 = f64::NAN;
}

impl AttestationEntry {
    /// Construct an entry with an explicit score (any polarity).
    #[must_use]
    pub fn new(dimension: impl Into<String>, score: f64, attester: impl Into<String>) -> Self {
        Self {
            dimension: dimension.into(),
            score,
            attester: attester.into(),
            source_ref: None,
        }
    }

    /// A passing boolean-via-score entry (1.0).
    #[must_use]
    pub fn pass(dimension: impl Into<String>, attester: impl Into<String>) -> Self {
        Self::new(dimension, Score::PASS, attester)
    }

    /// A failing boolean-via-score entry (0.0).
    #[must_use]
    pub fn fail(dimension: impl Into<String>, attester: impl Into<String>) -> Self {
        Self::new(dimension, Score::FAIL, attester)
    }

    /// A rollback-detected entry on the named revision field. Always
    /// `-1.0` — this dimension has no positive direction.
    #[must_use]
    pub fn rollback(revision_field: impl AsRef<str>, attester: impl Into<String>) -> Self {
        Self::new(
            dim::rollback_detected(revision_field.as_ref()),
            Score::ROLLBACK,
            attester,
        )
    }

    /// An indeterminate entry — verdict undecidable. Only legitimate
    /// on `attestation:registry_consensus` per FSD-002 §3.2.
    #[must_use]
    pub fn indeterminate(dimension: impl Into<String>, attester: impl Into<String>) -> Self {
        Self::new(dimension, Score::INDETERMINATE, attester)
    }

    /// Attach a source reference (persist row hash, registry URL, …).
    #[must_use]
    pub fn with_source_ref(mut self, source_ref: impl Into<String>) -> Self {
        self.source_ref = Some(source_ref.into());
        self
    }

    /// Did the attestation pass under boolean-via-score polarity?
    #[must_use]
    pub fn is_pass(&self) -> bool {
        (self.score - Score::PASS).abs() < f64::EPSILON
    }

    /// Did the attestation fail under boolean-via-score polarity?
    #[must_use]
    pub fn is_fail(&self) -> bool {
        (self.score - Score::FAIL).abs() < f64::EPSILON
    }

    /// Is this a rollback-detected entry?
    #[must_use]
    pub fn is_rollback(&self) -> bool {
        self.score < 0.0
    }

    /// Is the verdict undecidable (Indeterminate)?
    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        self.score.is_nan()
    }
}

/// The `federation_provenance` block that travels in verify's response
/// surface — the composed attestation list + optional metadata.
///
/// Per `MISSION.md` §1.4 this is **data, not a verdict.** Consumers
/// compose a verdict under their own policy from the
/// `attestations_consumed` list; verify does not declare one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FederationProvenance {
    /// Optional caller-supplied policy name for audit purposes (e.g.
    /// `"registry-v1.4-direct-trust"`, `"humanity-accord-only"`).
    /// Verify *carries* this string; it does not interpret it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,

    /// The composed attestation list — what verify actually checked
    /// and the verdict per dimension. Empty list is legitimate (e.g.
    /// no checks ran yet); absent dimensions are *not* implicitly
    /// passing — they are not-checked.
    pub attestations_consumed: Vec<AttestationEntry>,

    /// Age of the cached data backing this attestation set, in
    /// seconds. `None` when the data was freshly fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_age_seconds: Option<u64>,

    /// SHA-256 (hex) of the persist row this attestation set derived
    /// from, when applicable. Lets the consumer trace the response
    /// back to the underlying storage row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist_row_hash: Option<String>,
}

impl FederationProvenance {
    /// Fresh builder.
    #[must_use]
    pub fn builder() -> FederationProvenanceBuilder {
        FederationProvenanceBuilder::default()
    }

    /// Number of `attestations_consumed` entries that passed
    /// (`score == 1.0`).
    #[must_use]
    pub fn count_passing(&self) -> usize {
        self.attestations_consumed
            .iter()
            .filter(|e| e.is_pass())
            .count()
    }

    /// Number of `attestations_consumed` entries that failed
    /// (`score == 0.0`).
    #[must_use]
    pub fn count_failing(&self) -> usize {
        self.attestations_consumed
            .iter()
            .filter(|e| e.is_fail())
            .count()
    }

    /// Number of indeterminate entries (only legitimate on
    /// `attestation:registry_consensus`).
    #[must_use]
    pub fn count_indeterminate(&self) -> usize {
        self.attestations_consumed
            .iter()
            .filter(|e| e.is_indeterminate())
            .count()
    }

    /// Whether the set carries any rollback-detected signal — the one
    /// negative-direction polarity in the namespace. A non-zero count
    /// here is a hard signal; consumer policy typically treats it as
    /// an immediate reject.
    #[must_use]
    pub fn has_rollback(&self) -> bool {
        self.attestations_consumed.iter().any(|e| e.is_rollback())
    }

    /// Find the first entry on `dimension`, if present.
    #[must_use]
    pub fn entry_for(&self, dimension: &str) -> Option<&AttestationEntry> {
        self.attestations_consumed
            .iter()
            .find(|e| e.dimension == dimension)
    }
}

/// Builder for [`FederationProvenance`].
#[derive(Debug, Default)]
pub struct FederationProvenanceBuilder {
    inner: FederationProvenance,
}

impl FederationProvenanceBuilder {
    /// Set the caller-policy label.
    #[must_use]
    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.inner.policy = Some(policy.into());
        self
    }

    /// Append one [`AttestationEntry`].
    #[must_use]
    pub fn attestation(mut self, entry: AttestationEntry) -> Self {
        self.inner.attestations_consumed.push(entry);
        self
    }

    /// Append many entries at once.
    #[must_use]
    pub fn attestations<I: IntoIterator<Item = AttestationEntry>>(mut self, entries: I) -> Self {
        self.inner.attestations_consumed.extend(entries);
        self
    }

    /// Set the cache-age metadata.
    #[must_use]
    pub fn cache_age_seconds(mut self, secs: u64) -> Self {
        self.inner.cache_age_seconds = Some(secs);
        self
    }

    /// Set the persist row hash.
    #[must_use]
    pub fn persist_row_hash(mut self, hash: impl Into<String>) -> Self {
        self.inner.persist_row_hash = Some(hash.into());
        self
    }

    /// Finalize.
    #[must_use]
    pub fn build(self) -> FederationProvenance {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_and_fail_helpers() {
        let p = AttestationEntry::pass(dim::LICENSE_VALIDITY, "registry-steward-us");
        assert!(p.is_pass() && !p.is_fail() && !p.is_rollback() && !p.is_indeterminate());
        assert_eq!(p.score, 1.0);
        assert_eq!(p.dimension, "attestation:license_validity");

        let f = AttestationEntry::fail(dim::SELF_VERIFY, "ciris-verify");
        assert!(f.is_fail() && !f.is_pass());
        assert_eq!(f.score, 0.0);
    }

    #[test]
    fn rollback_is_negative_polarity() {
        let r = AttestationEntry::rollback("license_revocation_revision", "ciris-verify");
        assert!(r.is_rollback());
        assert!(!r.is_pass() && !r.is_fail());
        assert_eq!(r.score, -1.0);
        assert_eq!(r.dimension, "rollback_detected:license_revocation_revision");
    }

    #[test]
    fn indeterminate_is_nan() {
        let i = AttestationEntry::indeterminate(dim::REGISTRY_CONSENSUS, "ciris-verify");
        assert!(i.is_indeterminate());
        assert!(!i.is_pass() && !i.is_fail() && !i.is_rollback());
        assert!(i.score.is_nan());
    }

    #[test]
    fn parameterized_dimensions_format_correctly() {
        assert_eq!(dim::provenance_slsa(3), "provenance:slsa:3");
        assert_eq!(
            dim::provenance_build_manifest("aarch64-apple-ios"),
            "provenance:build_manifest:aarch64-apple-ios"
        );
        assert_eq!(
            dim::rollback_detected("license_revocation_revision"),
            "rollback_detected:license_revocation_revision"
        );
        assert_eq!(
            dim::cert_validity("registry-steward-us"),
            "cert_validity:registry-steward-us"
        );
        assert_eq!(dim::hardware_custody("tpm"), "hardware_custody:tpm");
    }

    #[test]
    fn source_ref_attaches() {
        let e = AttestationEntry::pass(dim::LICENSE_VALIDITY, "registry-steward-us")
            .with_source_ref("persist:sha256:deadbeef");
        assert_eq!(e.source_ref.as_deref(), Some("persist:sha256:deadbeef"));
    }

    #[test]
    fn builder_composes_a_full_provenance_block() {
        let fp = FederationProvenance::builder()
            .policy("registry-v1.4-direct-trust")
            .attestation(AttestationEntry::pass(dim::SELF_VERIFY, "ciris-verify"))
            .attestation(AttestationEntry::pass(
                dim::LICENSE_VALIDITY,
                "registry-steward-us",
            ))
            .attestation(AttestationEntry::fail(dim::AGENT_INTEGRITY, "ciris-verify"))
            .cache_age_seconds(47)
            .persist_row_hash("sha256:cafef00d")
            .build();
        assert_eq!(fp.policy.as_deref(), Some("registry-v1.4-direct-trust"));
        assert_eq!(fp.attestations_consumed.len(), 3);
        assert_eq!(fp.count_passing(), 2);
        assert_eq!(fp.count_failing(), 1);
        assert_eq!(fp.cache_age_seconds, Some(47));
        assert_eq!(fp.persist_row_hash.as_deref(), Some("sha256:cafef00d"));
        assert!(!fp.has_rollback());
    }

    #[test]
    fn entry_for_dimension_lookup() {
        let fp = FederationProvenance::builder()
            .attestation(AttestationEntry::pass(dim::SELF_VERIFY, "ciris-verify"))
            .attestation(AttestationEntry::fail(dim::AGENT_INTEGRITY, "ciris-verify"))
            .build();
        assert!(fp.entry_for(dim::SELF_VERIFY).is_some_and(|e| e.is_pass()));
        assert!(fp
            .entry_for(dim::AGENT_INTEGRITY)
            .is_some_and(|e| e.is_fail()));
        assert!(fp.entry_for(dim::REGISTRY_CONSENSUS).is_none());
    }

    #[test]
    fn has_rollback_detects_negative_polarity() {
        let fp = FederationProvenance::builder()
            .attestation(AttestationEntry::pass(dim::SELF_VERIFY, "v"))
            .attestation(AttestationEntry::rollback(
                "license_revocation_revision",
                "ciris-verify",
            ))
            .build();
        assert!(fp.has_rollback());
        // Rollback entries don't count as pass/fail.
        assert_eq!(fp.count_passing(), 1);
        assert_eq!(fp.count_failing(), 0);
    }

    #[test]
    fn indeterminate_count() {
        let fp = FederationProvenance::builder()
            .attestation(AttestationEntry::indeterminate(
                dim::REGISTRY_CONSENSUS,
                "ciris-verify",
            ))
            .attestation(AttestationEntry::pass(dim::LICENSE_VALIDITY, "registry"))
            .build();
        assert_eq!(fp.count_indeterminate(), 1);
        assert_eq!(fp.count_passing(), 1);
    }

    /// FSD-002 §3.2 contract: dimension strings are stable wire
    /// constants. If a value here changes, every downstream consumer
    /// that string-matched on it breaks. Lock them.
    #[test]
    fn dimension_constants_are_stable_wire_strings() {
        assert_eq!(dim::SELF_VERIFY, "attestation:self_verify");
        assert_eq!(dim::HARDWARE, "attestation:hardware");
        assert_eq!(dim::REGISTRY_CONSENSUS, "attestation:registry_consensus");
        assert_eq!(dim::LICENSE_VALIDITY, "attestation:license_validity");
        assert_eq!(dim::AGENT_INTEGRITY, "attestation:agent_integrity");
        assert_eq!(
            dim::TRANSPARENCY_LOG_INCLUSION,
            "transparency_log:inclusion"
        );
        assert_eq!(
            dim::TRANSPARENCY_LOG_CONSISTENCY,
            "transparency_log:consistency"
        );
    }

    /// JSON serialization matches the FSD-002 §11.2 example shape.
    #[test]
    fn serializes_to_expected_json_shape() {
        let fp = FederationProvenance::builder()
            .policy("registry-v1.4-direct-trust")
            .attestation(AttestationEntry::pass(
                dim::provenance_slsa(3),
                "registry-steward-us",
            ))
            .attestation(AttestationEntry::pass(
                dim::LICENSE_VALIDITY,
                "registry-steward-eu",
            ))
            .cache_age_seconds(47)
            .persist_row_hash("sha256:deadbeef")
            .build();
        let j: serde_json::Value = serde_json::to_value(&fp).unwrap();
        assert_eq!(j["policy"], "registry-v1.4-direct-trust");
        assert_eq!(
            j["attestations_consumed"][0]["dimension"],
            "provenance:slsa:3"
        );
        assert_eq!(j["attestations_consumed"][0]["score"], 1.0);
        assert_eq!(
            j["attestations_consumed"][0]["attester"],
            "registry-steward-us"
        );
        assert_eq!(j["cache_age_seconds"], 47);
        assert_eq!(j["persist_row_hash"], "sha256:deadbeef");
    }

    /// Round-trip via JSON — full equality.
    #[test]
    fn json_round_trip() {
        let fp = FederationProvenance::builder()
            .policy("p1")
            .attestation(AttestationEntry::pass(dim::SELF_VERIFY, "v").with_source_ref("ref"))
            .attestation(AttestationEntry::fail(dim::AGENT_INTEGRITY, "v"))
            .build();
        let json = serde_json::to_string(&fp).unwrap();
        let back: FederationProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, back);
    }
}
