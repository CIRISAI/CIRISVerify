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
//! ## The dimension namespace — **CC part_3 is authoritative**
//!
//! Dimensions are named for what is **measured** — no L1/L2/L3/L4/L5 ladder
//! numbering in the wire shape, because the ladder is consumer policy, not
//! verify-side framing (v3.7.0+). CC part_3 ratified that choice explicitly:
//! *"L-numbers name a verdict-shape (ladder position), not a mechanism — the
//! L1-L5 ladder lives as consumer-side composition."*
//!
//! ### How many dimensions? (the count, stated precisely)
//!
//! Prose here previously said "twelve", which matched nothing. The number
//! depends on what is counted, so all three are given:
//!
//! | Count | What it counts |
//! |---|---|
//! | **15** | rows in CC part_3's table (it lists the `:locale:` sub-form as its own row) |
//! | **14** | distinct prefix **families** — [`dim::ALL`], the registry below |
//! | **13** | families verify actually **emits** (`transparency_log:cosigned:` is witness-emitted) |
//!
//! **Authority note (v11.0.0).** Where CC part_3 and CIRISRegistry FSD-002
//! §3.2 disagree, **CC wins**. FSD-002 §3.2 still specifies the retired
//! ladder-named prefixes (`attestation:l1:self_verify`, …); CC and this crate
//! agree on the mechanism-named set. Tracked as CIRISRegistry#132.
//!
//! CC part_3 lists **15** dimensions in the verify namespace. The 15th,
//! `transparency_log:cosigned:{tree_size}`, is **witness-emitted, not
//! verify-emitted** (CC binds its emitter to a `federation_keys` row with
//! `identity_type="witness"`), so it is exposed here as a *recognition*
//! constant with no emitter — see [`dim::TRANSPARENCY_LOG_COSIGNED_PREFIX`].
//!
//! Addressable via the [`dim`] module:
//!
//! | Dimension                                  | Polarity         |
//! |--------------------------------------------|------------------|
//! | `attestation:self_verify`                  | boolean-via-score |
//! | `attestation:hardware_rooted`                     | boolean-via-score |
//! | `attestation:registry_consensus`           | boolean-via-score + Indeterminate (future) |
//! | `attestation:license_validity`             | boolean-via-score |
//! | `attestation:agent_integrity`              | boolean-via-score |
//! | `provenance:slsa:{level}`                  | boolean-via-score |
//! | `provenance:build_manifest:{target}`       | boolean-via-score |
//! | `provenance:build_manifest:{target}:locale:{lang_code}` | boolean-via-score (v3.8.0+, #37) |
//! | `provenance:skill_import:{source}`         | **signed** (per CC part_3; v3.8.0+, #37) |
//! | `transparency_log:inclusion`               | boolean-via-score |
//! | `transparency_log:consistency`             | boolean-via-score |
//! | `transparency_log:cosigned:{tree_size}`    | **signed** — *recognized, never emitted by verify* (witness-emitted per CC part_3) |
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

    /// Hardware-rooted attestation (TPM 2.0 / Android Keystore /
    /// iOS Secure Enclave). v4.0.0 wire-string realigned to CEG 0.2
    /// §5.2 mechanism-only naming (`hardware_rooted`, not the
    /// CEG-0.1 `attestation:hardware`).
    pub const HARDWARE: &str = "attestation:hardware_rooted";

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

    /// Prefix of CC part_3's 15th verify-namespace dimension,
    /// `transparency_log:cosigned:{tree_size}`.
    ///
    /// **Recognition only — verify never emits this.** CC binds the emitter to
    /// an `attesting_key_id` whose `federation_keys` row has
    /// `identity_type="witness"`, so a witness produces it and verify (which
    /// holds the machinery in [`crate::transparency`]: `WitnessSignature`,
    /// `count_valid_witnesses`, `witness_quorum_met`) consumes it. Exposed so a
    /// consumer can match the family without hand-writing the string.
    pub const TRANSPARENCY_LOG_COSIGNED_PREFIX: &str = "transparency_log:cosigned:";

    /// Build the `transparency_log:cosigned:{tree_size}` dimension.
    ///
    /// Provided for **consumers matching or reconstructing** the dimension —
    /// verify itself is not an emitter (see
    /// [`TRANSPARENCY_LOG_COSIGNED_PREFIX`]).
    #[must_use]
    pub fn transparency_log_cosigned(tree_size: u64) -> String {
        format!("{TRANSPARENCY_LOG_COSIGNED_PREFIX}{tree_size}")
    }

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

    /// Per-locale leaf under a `provenance:build_manifest:{target}`
    /// root — for the 29-locale localized-artifact tree
    /// (CIRISRegistry#29 / CIRISVerify#37). `lang_code` is an ISO
    /// language code (e.g. `en`, `my`, `id`). The parent
    /// [`provenance_build_manifest`] entry stays the Merkle root over
    /// all per-locale leaves; this dimension carries the per-leaf
    /// verdict.
    #[must_use]
    pub fn provenance_build_manifest_locale(target: &str, lang_code: &str) -> String {
        format!("provenance:build_manifest:{target}:locale:{lang_code}")
    }

    /// Community-skill import provenance (CIRISRegistry#28 /
    /// CIRISVerify#37). `source` is one of
    /// `registry:{registry_id}` / `direct:{url}` / `local:{path}` —
    /// the source-type prefix determines which trusted-emitter set
    /// the signer identity is checked against.
    #[must_use]
    pub fn provenance_skill_import(source: &str) -> String {
        format!("provenance:skill_import:{source}")
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

    /// CC 3.4.5's **ratified** per-family consent disposition.
    ///
    /// # This tracks CC; it is not verify's opinion
    ///
    /// An earlier version of this type (v11.0.0–v11.1.0) shipped a verify-side
    /// *proposal* that placed four families on the consensual-reputation side.
    /// **CIRISConstitution rc3 ratified CC 3.4.5, which disposes of all
    /// fourteen families individually and places every one OUTSIDE the consent
    /// gate.** The proposal contradicted the ruling, so the proposal is gone —
    /// this enum now records CC's disposition and nothing else.
    ///
    /// CIRISPersist#569 derived its admission gate from this registry rather
    /// than transcribing a list (the right instinct — it avoids two lists that
    /// disagree), which made the classification load-bearing in another repo.
    /// CIRISVerify#238 caught the contradiction before it shipped there.
    ///
    /// # Why the old classification failed in a security-relevant direction
    ///
    /// - **`rollback_detected:*` is −1-only.** Gating it on subject consent
    ///   would let an **adversary opt out of rollback detection** by declining
    ///   `analyze`.
    /// - **Artifact-integrity families verify a subject's artifacts.** Gating
    ///   them would let a subject block verification of their own build,
    ///   license or certificate — CC's stated reason for the carve-out is
    ///   exactly that *"a forger never consents to verification."*
    ///
    /// Consent-before-scoring binds the family that judges **agents**
    /// (`capacity:*`, which verify does not own) — never the families that
    /// verify **artifacts**.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ConsentDisposition {
        /// CC 3.4.5 **self-reports** — a pro-self statement about the emitter
        /// itself, so there is no third-party data subject to consent.
        SelfReport,
        /// CC 3.4.5 **artifact-integrity verification** — scores builds,
        /// manifests, licenses and certificates, not a subject's conduct or
        /// capacity. *"A forger never consents to verification."*
        ArtifactVerification,
        /// CC 3.4.5 **log infrastructure** — proves properties of a public log.
        /// The cosigned form is separately role-gated to witnesses (CC 3.4.9).
        LogInfrastructure,
        /// CC 3.4.5 **abuse response** — an adversarial detector, on the
        /// abuse-response side of the line by construction.
        AbuseResponse,
    }

    impl ConsentDisposition {
        /// Is a family with this disposition gated on the subject's `analyze`
        /// consent? **Always `false`** — CC 3.4.5 places every verify-owned
        /// family outside the consent gate.
        ///
        /// Returned as a method rather than left implicit so a consumer cannot
        /// re-derive a gate from the variant names and reach a different answer
        /// than the Constitution.
        #[must_use]
        pub const fn is_consent_gated(self) -> bool {
            false
        }
    }

    /// One entry in the authoritative registry of verify-namespace dimensions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DimensionSpec {
        /// The exact dimension string, or its `{param}`-terminated prefix.
        pub prefix: &'static str,
        /// `true` when `prefix` is a prefix requiring a parameter suffix.
        pub parameterized: bool,
        /// Does verify itself emit this dimension?
        pub verify_emits: bool,
        /// CC 3.4.5 ratified consent disposition.
        pub consent_disposition: ConsentDisposition,
    }

    /// **The authoritative, exhaustive registry** of the verify-owned dimension
    /// namespace — CC part_3's 15 families.
    ///
    /// CIRISPersist#569 ask 3 asked for the set to be *"exhaustive-match or
    /// manifest-pinned, so a 15th dimension added upstream is a compile failure
    /// or a gate failure rather than a silent ungated family."* This is that
    /// pin: a consumer iterates `ALL` instead of hand-listing strings, so a
    /// family added here shows up downstream rather than slipping past a gate.
    ///
    /// 14 are verify-emitted; `transparency_log:cosigned:` is
    /// recognition-only (witness-emitted per CC part_3).
    pub const ALL: &[DimensionSpec] = &[
        DimensionSpec {
            prefix: SELF_VERIFY,
            parameterized: false,
            verify_emits: true,
            consent_disposition: ConsentDisposition::SelfReport,
        },
        DimensionSpec {
            prefix: HARDWARE,
            parameterized: false,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: REGISTRY_CONSENSUS,
            parameterized: false,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: LICENSE_VALIDITY,
            parameterized: false,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: AGENT_INTEGRITY,
            parameterized: false,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: TRANSPARENCY_LOG_INCLUSION,
            parameterized: false,
            verify_emits: true,
            consent_disposition: ConsentDisposition::LogInfrastructure,
        },
        DimensionSpec {
            prefix: TRANSPARENCY_LOG_CONSISTENCY,
            parameterized: false,
            verify_emits: true,
            consent_disposition: ConsentDisposition::LogInfrastructure,
        },
        DimensionSpec {
            prefix: TRANSPARENCY_LOG_COSIGNED_PREFIX,
            parameterized: true,
            verify_emits: false,
            consent_disposition: ConsentDisposition::LogInfrastructure,
        },
        DimensionSpec {
            prefix: "provenance:slsa:",
            parameterized: true,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: "provenance:build_manifest:",
            parameterized: true,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: "provenance:skill_import:",
            parameterized: true,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: "rollback_detected:",
            parameterized: true,
            verify_emits: true,
            consent_disposition: ConsentDisposition::AbuseResponse,
        },
        DimensionSpec {
            prefix: "cert_validity:",
            parameterized: true,
            verify_emits: true,
            consent_disposition: ConsentDisposition::ArtifactVerification,
        },
        DimensionSpec {
            prefix: "hardware_custody:",
            parameterized: true,
            verify_emits: true,
            consent_disposition: ConsentDisposition::SelfReport,
        },
    ];

    /// Resolve a dimension string to its registry entry, or `None` if it is not
    /// in the verify namespace.
    ///
    /// Longest-prefix match, so `provenance:build_manifest:{t}:locale:{l}`
    /// resolves to the `provenance:build_manifest:` family (its locale variant
    /// is a sub-form, not a separate family).
    #[must_use]
    pub fn lookup(dimension: &str) -> Option<&'static DimensionSpec> {
        ALL.iter()
            .filter(|d| {
                if d.parameterized {
                    dimension.starts_with(d.prefix) && dimension.len() > d.prefix.len()
                } else {
                    dimension == d.prefix
                }
            })
            .max_by_key(|d| d.prefix.len())
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

    /// CIRISVerify#37 (v3.8.0): per-locale build_manifest leaf +
    /// skill_import helpers. Wire-string format must match the
    /// Registry#28 / #29 specs.
    #[test]
    fn skill_import_and_per_locale_dimensions_format_correctly() {
        assert_eq!(
            dim::provenance_skill_import("registry:ciris-registry-us"),
            "provenance:skill_import:registry:ciris-registry-us"
        );
        assert_eq!(
            dim::provenance_skill_import("direct:https://example.org/skill.tar.gz"),
            "provenance:skill_import:direct:https://example.org/skill.tar.gz"
        );
        assert_eq!(
            dim::provenance_skill_import("local:/opt/ciris/skills/triage.tar.gz"),
            "provenance:skill_import:local:/opt/ciris/skills/triage.tar.gz"
        );
        assert_eq!(
            dim::provenance_build_manifest_locale("ios-mobile-bundle", "my"),
            "provenance:build_manifest:ios-mobile-bundle:locale:my"
        );
        assert_eq!(
            dim::provenance_build_manifest_locale("python-source-tree", "en"),
            "provenance:build_manifest:python-source-tree:locale:en"
        );
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
        assert_eq!(dim::HARDWARE, "attestation:hardware_rooted");
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

#[cfg(test)]
mod registry_tests {
    use super::dim::{self, ConsentDisposition};

    /// **The count question, answered precisely** (CIRISServer#340 asked which
    /// of "twelve" vs 14 is authoritative; the honest answer is that it depends
    /// on what you count):
    ///
    /// - **15** — rows in CC part_3's table. It lists
    ///   `provenance:build_manifest:{target}:locale:{lang_code}` as its own row
    ///   even though it is a *sub-form* of the build-manifest family.
    /// - **14** — distinct prefix families (this registry). The locale sub-form
    ///   resolves into `provenance:build_manifest:` by longest-prefix match.
    /// - **13** — families verify actually **emits**;
    ///   `transparency_log:cosigned:` is witness-emitted, recognized only.
    ///
    /// The old module prose said "twelve", which matched none of these.
    #[test]
    fn registry_cardinality_is_stated_precisely() {
        assert_eq!(dim::ALL.len(), 14, "distinct prefix families");
        assert_eq!(
            dim::ALL.iter().filter(|d| d.verify_emits).count(),
            13,
            "verify-emitted families; cosigned is witness-emitted"
        );
        assert_eq!(
            dim::ALL.iter().filter(|d| !d.verify_emits).count(),
            1,
            "exactly one recognition-only family"
        );
    }

    /// Every emitted dimension the code can actually produce must resolve.
    #[test]
    fn every_emitted_dimension_resolves() {
        for d in [
            dim::SELF_VERIFY.to_string(),
            dim::HARDWARE.to_string(),
            dim::REGISTRY_CONSENSUS.to_string(),
            dim::LICENSE_VALIDITY.to_string(),
            dim::AGENT_INTEGRITY.to_string(),
            dim::TRANSPARENCY_LOG_INCLUSION.to_string(),
            dim::TRANSPARENCY_LOG_CONSISTENCY.to_string(),
            dim::provenance_slsa(3),
            dim::provenance_build_manifest("x86_64-unknown-linux-gnu"),
            dim::provenance_build_manifest_locale("ios-mobile-bundle", "my"),
            dim::provenance_skill_import("registry:reg1"),
            dim::rollback_detected("revocation_revision"),
            dim::cert_validity("registry-us"),
            dim::hardware_custody("android"),
            dim::transparency_log_cosigned(32),
        ] {
            assert!(dim::lookup(&d).is_some(), "unregistered dimension: {d}");
        }
    }

    /// The locale sub-form belongs to the build_manifest family (longest-prefix
    /// match), not to a family of its own.
    #[test]
    fn locale_subform_resolves_to_the_build_manifest_family() {
        let d = dim::provenance_build_manifest_locale("ios-mobile-bundle", "my");
        assert_eq!(
            dim::lookup(&d).unwrap().prefix,
            "provenance:build_manifest:"
        );
    }

    /// A dimension outside the verify namespace must NOT resolve — the gate a
    /// consumer builds on this must not silently claim foreign families.
    #[test]
    fn foreign_dimensions_do_not_resolve() {
        for d in [
            "capacity:relay",
            "detection:cross_agent_divergence",
            "system:disk_pressure",
            "provenance:slsa:", // bare prefix, no parameter
        ] {
            assert!(dim::lookup(d).is_none(), "should not resolve: {d}");
        }
    }

    /// **CC 3.4.5 (ratified) — no verify-owned family is consent-gated.**
    ///
    /// The Constitution disposes of all fourteen families individually and puts
    /// every one outside the gate. This asserts the ruling directly, so a future
    /// edit that reintroduces a consent-gated family fails here rather than in a
    /// downstream admission path (CIRISVerify#238 / CIRISPersist#569).
    #[test]
    fn cc_3_4_5_no_verify_family_is_consent_gated() {
        assert_eq!(dim::ALL.len(), 14, "CC 3.4.5 disposes of fourteen families");
        for d in dim::ALL {
            assert!(
                !d.consent_disposition.is_consent_gated(),
                "{} must not be consent-gated (CC 3.4.5)",
                d.prefix
            );
        }
    }

    /// The security case CIRISVerify#238 named: `rollback_detected` is a −1-only
    /// adversarial detector. Gating it on subject consent would let an
    /// **adversary opt out of rollback detection** by declining `analyze`.
    #[test]
    fn rollback_detection_can_never_be_opted_out_of() {
        let d = dim::lookup(&dim::rollback_detected("revocation_revision")).unwrap();
        assert_eq!(d.consent_disposition, ConsentDisposition::AbuseResponse);
        assert!(!d.consent_disposition.is_consent_gated());
    }

    /// Artifact-integrity families verify a subject's *artifacts*, so gating
    /// them would let a subject block verification of their own build, license
    /// or certificate — CC: *"a forger never consents to verification."*
    #[test]
    fn artifact_verification_families_track_cc_3_4_5() {
        for d in [
            dim::HARDWARE,
            dim::REGISTRY_CONSENSUS,
            dim::LICENSE_VALIDITY,
            dim::AGENT_INTEGRITY,
        ] {
            assert_eq!(
                dim::lookup(d).unwrap().consent_disposition,
                ConsentDisposition::ArtifactVerification,
                "{d} is artifact-integrity verification per CC 3.4.5"
            );
        }
        for d in [
            dim::provenance_slsa(3),
            dim::provenance_build_manifest("x86_64-unknown-linux-gnu"),
            dim::provenance_skill_import("registry:r"),
            dim::cert_validity("registry-us"),
        ] {
            assert_eq!(
                dim::lookup(&d).unwrap().consent_disposition,
                ConsentDisposition::ArtifactVerification
            );
        }
    }

    /// CC 3.4.5 separates *self-reports* from artifact verification: a pro-self
    /// statement has no third-party subject. Note `hardware_custody:*` is a
    /// self-report while `attestation:hardware_rooted` is artifact-integrity —
    /// an easy pair to conflate, so it is pinned.
    #[test]
    fn self_reports_and_log_infrastructure_track_cc_3_4_5() {
        assert_eq!(
            dim::lookup(dim::SELF_VERIFY).unwrap().consent_disposition,
            ConsentDisposition::SelfReport
        );
        assert_eq!(
            dim::lookup(&dim::hardware_custody("android"))
                .unwrap()
                .consent_disposition,
            ConsentDisposition::SelfReport
        );
        assert_ne!(
            dim::lookup(dim::HARDWARE).unwrap().consent_disposition,
            ConsentDisposition::SelfReport,
            "attestation:hardware_rooted is artifact-integrity, NOT a self-report"
        );
        for d in [
            dim::TRANSPARENCY_LOG_INCLUSION,
            dim::TRANSPARENCY_LOG_CONSISTENCY,
        ] {
            assert_eq!(
                dim::lookup(d).unwrap().consent_disposition,
                ConsentDisposition::LogInfrastructure
            );
        }
    }
}
