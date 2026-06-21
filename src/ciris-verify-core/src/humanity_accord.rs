//! CEG §9.2.1 HUMANITY_ACCORD invocation anti-replay surface
//! (CIRISVerify#41, v4.2.0+).
//!
//! Per CIRISRegistry CEG §9.2.1: every `accord:invoke:*`
//! Contribution signs canonical bytes binding the discriminator,
//! per-invocation nonce, timestamps, and payload hash. Both the
//! discriminator AND the nonce are in the signed payload — that's
//! what prevents `CONSTITUTIONAL` ↔ `notify` ↔ `drill` cross-replay.
//!
//! ## What this module ships
//!
//! - [`InvocationKind`] — the three discriminator values
//!   (CONSTITUTIONAL / notify / drill).
//! - [`Invocation`] — the signed-canonical-bytes shape.
//! - [`Invocation::canonical_bytes`] — exact §9.2.1 layout.
//! - [`InvocationDedup`] — in-memory dedup tracker rejecting
//!   duplicate `invocation_id` within its `valid_until` window
//!   (per-kind unique per the §9.2.1 normative rule).
//! - [`verify_invocation`] — 2-of-3 holder hybrid signature
//!   verification (reuses existing `verify_threshold_signatures`).
//!
//! ## Strongest safety-critical path in the grammar
//!
//! §9.2 mandates that HUMANITY_ACCORD signatures are scope-isolated
//! AND wire-isolated. The §9.2.1 invocation discipline is what
//! makes the constitutional-emergency path itself tamper-evident:
//! a `CONSTITUTIONAL` signature on `{halt_id: X}` MUST NOT verify
//! against `notify {notify_id: Y}` even with the same nonce.
//!
//! ## Canonical bytes (§9.2.1)
//!
//! ```text
//! canonical = sha256(
//!     "ciris.accord_invoke.v1\n" ||
//!     "invocation_kind=" || ("CONSTITUTIONAL" | "notify" | "drill") || "\n" ||
//!     "invocation_id=" || halt_id_or_notify_id_or_drill_id || "\n" ||
//!     "nonce=" || base64url(rand_32_bytes) || "\n" ||
//!     "asserted_at=" || rfc3339_canonical || "\n" ||   // per §0.5
//!     "valid_until=" || rfc3339_canonical || "\n" ||
//!     "payload_sha256=" || sha256_hex_lowercase_of_payload   // per §0.6
//! )
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// Domain prefix for invocation canonical bytes (§9.2.1).
/// Trailing newline is part of the prefix.
pub const INVOCATION_DOMAIN_PREFIX: &str = "ciris.accord_invoke.v1\n";

/// Domain prefix for the **separate** `accord:lifecycle:active` scope
/// (CC 4.2.1 / CEG §9.2 resumption) — wire-isolated from `accord:invoke:*` so no
/// signature crosses scopes. Trailing newline is part of the prefix.
///
/// **First-impl note:** CC §4.2.1.1 normatively pins only the `accord:invoke`
/// preimage; this `accord:lifecycle` layout is verify-authored and flagged for
/// CEG cross-confirmation (CIRISRegistry).
pub const LIFECYCLE_DOMAIN_PREFIX: &str = "ciris.accord_lifecycle.v1\n";

/// CEG §9.2.1 invocation discriminator. Stable wire constants;
/// JSON serialization uses spec-exact casing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InvocationKind {
    /// EmergencyShutdown CONSTITUTIONAL —
    /// `IncidentSeverity::INCIDENT_CONSTITUTIONAL = 5`.
    #[serde(rename = "CONSTITUTIONAL")]
    Constitutional,
    /// `accord:invoke:notify:{notify_id}`.
    #[serde(rename = "notify")]
    Notify,
    /// `accord:invoke:drill:{drill_id}`.
    #[serde(rename = "drill")]
    Drill,
    /// `accord:lifecycle:active` (CC 4.2.1 / CEG §9.2) — the ONLY
    /// constitutionally-valid **resumption** after a halt (CIRISVerify#95
    /// "Gap 1"; the server's `reactivate`). This is a **separate scope** from
    /// `accord:invoke:*`: the CC §4.2.1.1 invocation preimage is closed to
    /// exactly {CONSTITUTIONAL, notify, drill}, and accord scopes are
    /// "wire-isolated AND scope-isolated", so a `LifecycleActive` signs a
    /// **distinct** canonical-bytes domain ([`LIFECYCLE_DOMAIN_PREFIX`]) — never
    /// the invoke preimage. It is still quorum-cleared 2/3 and rides the same
    /// concurrence flow. **NB:** CC §4.2.1.1 pins only the `accord:invoke`
    /// preimage; the `accord:lifecycle` canonical-bytes layout here is
    /// verify-authored (first impl) and flagged for CEG cross-confirmation.
    #[serde(rename = "lifecycle:active")]
    LifecycleActive,
}

impl InvocationKind {
    /// Stable wire-string per §9.2.1 — exactly the form that goes
    /// into canonical bytes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Constitutional => "CONSTITUTIONAL",
            Self::Notify => "notify",
            Self::Drill => "drill",
            Self::LifecycleActive => "lifecycle:active",
        }
    }

    /// The canonical-bytes **domain prefix** for this kind. `accord:invoke:*`
    /// (the three) share [`INVOCATION_DOMAIN_PREFIX`]; the separate
    /// `accord:lifecycle:active` scope uses [`LIFECYCLE_DOMAIN_PREFIX`] —
    /// wire-isolation so no signature crosses between the invoke and lifecycle
    /// scopes.
    #[must_use]
    fn domain_prefix(self) -> &'static str {
        match self {
            Self::LifecycleActive => LIFECYCLE_DOMAIN_PREFIX,
            _ => INVOCATION_DOMAIN_PREFIX,
        }
    }
}

/// One HUMANITY_ACCORD invocation per §9.2.1.
///
/// All `String` fields carry the exact UTF-8 form they were signed
/// under — `nonce` is the base64url-encoded 32 random bytes,
/// timestamps are §0.5 canonical RFC 3339 form, `payload_sha256`
/// is §0.6 canonical lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invocation {
    /// CONSTITUTIONAL / notify / drill discriminator.
    pub invocation_kind: InvocationKind,
    /// Per-kind unique id (`halt_id` / `notify_id` / `drill_id`).
    pub invocation_id: String,
    /// `base64url(rand_32_bytes)`. Verify only checks form; CSPRNG
    /// is the producer's responsibility.
    pub nonce: String,
    /// §0.5 canonical RFC 3339 `YYYY-MM-DDTHH:MM:SS.sssZ`.
    pub asserted_at: String,
    /// §0.5 canonical RFC 3339 `YYYY-MM-DDTHH:MM:SS.sssZ`.
    pub valid_until: String,
    /// §0.6 canonical lowercase 64-char hex of the application payload.
    pub payload_sha256: String,
}

impl Invocation {
    /// Compute §9.2.1 canonical bytes — the bytes the inner SHA-256
    /// produces. The hybrid signatures (Ed25519 over canonical_bytes;
    /// ML-DSA-65 over canonical_bytes || ed25519_sig) cover this
    /// exact byte sequence per §5.2.1 bound-payload convention.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let body = format!(
            "{prefix}invocation_kind={kind}\ninvocation_id={id}\nnonce={nonce}\nasserted_at={ts}\nvalid_until={vu}\npayload_sha256={hash}",
            prefix = self.invocation_kind.domain_prefix(),
            kind = self.invocation_kind.as_str(),
            id = self.invocation_id,
            nonce = self.nonce,
            ts = self.asserted_at,
            vu = self.valid_until,
            hash = self.payload_sha256,
        );
        // §9.2.1 wraps the layout in sha256(). Producers sign that
        // 32-byte digest's preimage; verify reconstructs the same
        // preimage bytes for signature verification.
        body.into_bytes()
    }

    /// SHA-256 digest of the canonical bytes — what producers
    /// actually pin to in their signed payload per §9.2.1.
    #[must_use]
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }
}

/// Verification errors for [`verify_invocation`].
#[derive(Debug, Clone)]
pub enum InvocationError {
    /// Fewer than 2 of the 3 holder signatures verified — the §9.2.1
    /// 2-of-3 threshold was not met.
    QuorumNotMet {
        /// How many valid signatures were observed.
        valid: usize,
        /// The threshold (2).
        required: usize,
    },
    /// Duplicate `(invocation_kind, invocation_id)` within the
    /// active dedup window — §9.2.1 anti-replay rejected.
    DuplicateInvocationId {
        /// The duplicated id.
        invocation_id: String,
        /// Which kind it duplicates against (per-kind unique).
        invocation_kind: InvocationKind,
    },
    /// Underlying threshold-signature error.
    Threshold(String),
}

impl std::fmt::Display for InvocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuorumNotMet { valid, required } => {
                write!(
                    f,
                    "§9.2.1: holder quorum not met ({valid} valid of {required} required)"
                )
            },
            Self::DuplicateInvocationId {
                invocation_id,
                invocation_kind,
            } => {
                write!(
                    f,
                    "§9.2.1: duplicate invocation_id {:?} within valid_until window (kind {:?})",
                    invocation_id,
                    invocation_kind.as_str(),
                )
            },
            Self::Threshold(msg) => write!(f, "§9.2.1 threshold verify: {msg}"),
        }
    }
}

impl std::error::Error for InvocationError {}

/// Verify an invocation: 2-of-3 holder hybrid signatures over the
/// §9.2.1 canonical bytes.
///
/// `holders` is the 3-member accord-holder set; `signatures` are
/// the (≤ 3) holder cosignatures. Returns `Ok(valid_count)` on
/// success (≥ 2 of 3 verified); the caller's dedup tracker is
/// queried separately via [`InvocationDedup::record_or_reject`].
///
/// This function deliberately keeps verification + dedup separate
/// so a caller can dedup-first-then-verify or vice versa per its
/// audit / observability preference.
pub fn verify_invocation(
    invocation: &Invocation,
    holders: &[ThresholdMember],
    signatures: &[ThresholdSignature],
) -> Result<usize, InvocationError> {
    let canonical = invocation.canonical_bytes();
    let valid = verify_threshold_signatures(&canonical, holders, signatures, 2).map_err(|e| {
        // Map the threshold error: short quorum is "quorum not met";
        // any other variant is an underlying threshold-layer issue.
        match e {
            crate::threshold::ThresholdError::Insufficient {
                valid, threshold, ..
            } => InvocationError::QuorumNotMet {
                valid,
                required: threshold,
            },
            other => InvocationError::Threshold(format!("{other:?}")),
        }
    })?;
    Ok(valid)
}

/// CEG §9.2.1 dedup tracker — rejects duplicate `invocation_id`
/// within the `valid_until` window, per-kind unique.
///
/// **Per-kind unique**: the same `invocation_id` string is
/// legitimate for two different kinds (e.g. a `notify` with id
/// `inv-001` and a `drill` with id `inv-001` are distinct because
/// the canonical bytes differ in `invocation_kind`).
///
/// **Caller drives expiry**. `record_or_reject` accepts a
/// `now: &str` parameter (canonical RFC 3339 per §0.5); entries
/// whose `valid_until <= now` are evicted before the duplicate
/// check. Storage is in-memory; consumers needing persistence
/// wrap this in their own backing store.
#[derive(Debug, Clone, Default)]
pub struct InvocationDedup {
    // BTreeMap so iteration order is deterministic for tests.
    seen: BTreeMap<(InvocationKind, String), String>, // (kind, id) → valid_until
}

impl InvocationDedup {
    /// Fresh dedup tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an invocation or reject as a §9.2.1 anti-replay
    /// violation. `now` is the canonical RFC 3339 timestamp the
    /// caller treats as the present moment for expiry purposes
    /// (allows deterministic testing).
    ///
    /// Returns `Ok(())` if the invocation is new (recorded);
    /// `Err(DuplicateInvocationId)` if `(kind, invocation_id)` is
    /// already present and its `valid_until > now`. Expired
    /// entries are evicted opportunistically before the check.
    pub fn record_or_reject(
        &mut self,
        invocation: &Invocation,
        now: &str,
    ) -> Result<(), InvocationError> {
        // Evict expired entries first — string comparison is fine
        // because §0.5 canonical RFC 3339 form is sort-stable when
        // all timestamps are UTC `Z`-suffixed with fixed-width fields.
        self.seen.retain(|_, vu| vu.as_str() > now);

        let key = (invocation.invocation_kind, invocation.invocation_id.clone());
        if self.seen.contains_key(&key) {
            return Err(InvocationError::DuplicateInvocationId {
                invocation_id: invocation.invocation_id.clone(),
                invocation_kind: invocation.invocation_kind,
            });
        }
        self.seen.insert(key, invocation.valid_until.clone());
        Ok(())
    }

    /// Number of currently-tracked invocations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Is the tracker empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_invocation(kind: InvocationKind, id: &str) -> Invocation {
        Invocation {
            invocation_kind: kind,
            invocation_id: id.to_string(),
            nonce: "AAAA-base64url-32-bytes-XXXXXXXXXXXX".to_string(),
            asserted_at: "2026-05-29T17:00:00.000Z".to_string(),
            valid_until: "2026-05-29T17:15:00.000Z".to_string(),
            payload_sha256: "a".repeat(64),
        }
    }

    /// §9.2.1 wire-string stability — the three discriminator values
    /// MUST match the spec verbatim (CONSTITUTIONAL uppercase, notify
    /// + drill lowercase).
    #[test]
    fn discriminator_wire_strings_are_stable() {
        assert_eq!(InvocationKind::Constitutional.as_str(), "CONSTITUTIONAL");
        assert_eq!(InvocationKind::Notify.as_str(), "notify");
        assert_eq!(InvocationKind::Drill.as_str(), "drill");
        assert_eq!(InvocationKind::LifecycleActive.as_str(), "lifecycle:active");
    }

    /// #95 Gap 1: `accord:lifecycle:active` is a SEPARATE scope — its canonical
    /// bytes use the `ciris.accord_lifecycle.v1` domain, NOT the invoke domain, so
    /// no signature can cross between the invoke and lifecycle scopes (CC 4.2.1
    /// "wire-isolated AND scope-isolated") even with identical id/nonce/payload.
    #[test]
    fn lifecycle_scope_is_wire_isolated_from_invoke() {
        let halt = sample_invocation(InvocationKind::Constitutional, "shared-id");
        let mut reactivate = halt.clone();
        reactivate.invocation_kind = InvocationKind::LifecycleActive;
        let bytes = String::from_utf8(reactivate.canonical_bytes()).unwrap();
        assert!(bytes.starts_with("ciris.accord_lifecycle.v1\n"));
        assert!(bytes.contains("invocation_kind=lifecycle:active\n"));
        // Distinct domain ⇒ distinct bytes + digest from the CONSTITUTIONAL kill.
        assert_ne!(halt.canonical_bytes(), reactivate.canonical_bytes());
        assert_ne!(halt.canonical_digest(), reactivate.canonical_digest());
    }

    /// The lifecycle kind serde-round-trips on the spec wire string.
    #[test]
    fn lifecycle_kind_serde_round_trips() {
        let json = serde_json::to_string(&InvocationKind::LifecycleActive).unwrap();
        assert_eq!(json, "\"lifecycle:active\"");
        let back: InvocationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, InvocationKind::LifecycleActive);
    }

    /// §9.2.1 canonical-bytes layout — exact spec form.
    #[test]
    fn canonical_bytes_matches_spec_layout() {
        let inv = Invocation {
            invocation_kind: InvocationKind::Constitutional,
            invocation_id: "halt-001".to_string(),
            nonce: "NONCE".to_string(),
            asserted_at: "2026-05-29T17:00:00.000Z".to_string(),
            valid_until: "2026-05-29T17:15:00.000Z".to_string(),
            payload_sha256: "0".repeat(64),
        };
        let expected = format!(
            "ciris.accord_invoke.v1\ninvocation_kind=CONSTITUTIONAL\ninvocation_id=halt-001\nnonce=NONCE\nasserted_at=2026-05-29T17:00:00.000Z\nvalid_until=2026-05-29T17:15:00.000Z\npayload_sha256={zero}",
            zero = "0".repeat(64),
        );
        assert_eq!(String::from_utf8(inv.canonical_bytes()).unwrap(), expected);
    }

    /// §9.2.1 cross-replay defense: CONSTITUTIONAL canonical bytes
    /// differ from notify canonical bytes EVEN WITH THE SAME NONCE
    /// and payload. The discriminator binding is what closes the
    /// cross-replay hole.
    #[test]
    fn cross_replay_constitutional_vs_notify_produces_different_canonical_bytes() {
        let c = Invocation {
            invocation_kind: InvocationKind::Constitutional,
            invocation_id: "id-001".to_string(),
            nonce: "same-nonce".to_string(),
            asserted_at: "2026-05-29T17:00:00.000Z".to_string(),
            valid_until: "2026-05-29T17:15:00.000Z".to_string(),
            payload_sha256: "a".repeat(64),
        };
        let mut n = c.clone();
        n.invocation_kind = InvocationKind::Notify;
        assert_ne!(
            c.canonical_bytes(),
            n.canonical_bytes(),
            "§9.2.1: CONSTITUTIONAL and notify with same nonce/payload MUST produce \
             distinct canonical bytes — discriminator bound in the signed payload"
        );
        // And distinct digests follow.
        assert_ne!(c.canonical_digest(), n.canonical_digest());
    }

    /// §9.2.1: changing the payload_sha256 changes canonical bytes.
    #[test]
    fn payload_binding_in_canonical_bytes() {
        let a = sample_invocation(InvocationKind::Notify, "id");
        let mut b = a.clone();
        b.payload_sha256 = "b".repeat(64);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    /// §9.2.1: same invocation_id legitimate across different kinds
    /// — the dedup tracker is per-kind unique.
    #[test]
    fn dedup_per_kind_unique() {
        let mut d = InvocationDedup::new();
        let constitutional = sample_invocation(InvocationKind::Constitutional, "shared-id");
        let drill = sample_invocation(InvocationKind::Drill, "shared-id");
        let now = "2026-05-29T17:05:00.000Z";
        assert!(d.record_or_reject(&constitutional, now).is_ok());
        // Same id, different kind — accepted.
        assert!(d.record_or_reject(&drill, now).is_ok());
        assert_eq!(d.len(), 2);
    }

    /// §9.2.1 normative: duplicate `invocation_id` within
    /// `valid_until` window MUST be rejected.
    #[test]
    fn dedup_rejects_duplicate_within_valid_until() {
        let mut d = InvocationDedup::new();
        let inv = sample_invocation(InvocationKind::Notify, "inv-1");
        let now = "2026-05-29T17:05:00.000Z";
        assert!(d.record_or_reject(&inv, now).is_ok());
        let err = d.record_or_reject(&inv, now).unwrap_err();
        match err {
            InvocationError::DuplicateInvocationId {
                invocation_id,
                invocation_kind,
            } => {
                assert_eq!(invocation_id, "inv-1");
                assert_eq!(invocation_kind, InvocationKind::Notify);
            },
            other => panic!("expected DuplicateInvocationId, got {other:?}"),
        }
    }

    /// §9.2.1: reuse after `valid_until` expiry → accepted. The
    /// dedup tracker evicts expired entries opportunistically.
    #[test]
    fn dedup_accepts_reuse_after_valid_until_expiry() {
        let mut d = InvocationDedup::new();
        let inv = sample_invocation(InvocationKind::Notify, "inv-1");
        assert!(d.record_or_reject(&inv, "2026-05-29T17:05:00.000Z").is_ok());
        // valid_until in the sample is 17:15; advance now past it.
        let future = "2026-05-29T18:00:00.000Z";
        assert!(
            d.record_or_reject(&inv, future).is_ok(),
            "§9.2.1: reuse after expiry MUST be accepted"
        );
        assert_eq!(d.len(), 1, "expired entry should have been evicted");
    }

    #[test]
    fn json_round_trip_invocation() {
        let inv = sample_invocation(InvocationKind::Constitutional, "halt-1");
        let json = serde_json::to_string(&inv).unwrap();
        assert!(json.contains("\"invocation_kind\":\"CONSTITUTIONAL\""));
        assert!(json.contains("\"invocation_id\":\"halt-1\""));
        let back: Invocation = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    /// §9.2.1 domain prefix stability — the prefix string is a
    /// federation-wide wire constant.
    #[test]
    fn domain_prefix_is_stable() {
        assert_eq!(INVOCATION_DOMAIN_PREFIX, "ciris.accord_invoke.v1\n");
    }

    /// Conformance harness acceptance from #41:
    /// 1. CONSTITUTIONAL canonical signature does NOT verify against
    ///    a notify invocation (cross-replay rejected).
    /// 2. Duplicate `invocation_id` within `valid_until` → rejected;
    ///    reuse after expiry → accepted.
    /// 3. < 2 valid holder signatures → rejected.
    ///
    /// (1) is structurally proven by the canonical-bytes test above;
    /// (2) by the dedup tests; (3) needs a real signer to drive the
    /// threshold-verify path. We exercise the dedup + canonical-bytes
    /// invariants here; the threshold-quorum path is tested in
    /// `threshold::tests` against real ed25519+ml-dsa-65 signers.
    #[test]
    fn conformance_harness_acceptance_criteria() {
        // (1) cross-replay defense.
        let c = sample_invocation(InvocationKind::Constitutional, "id");
        let mut n = c.clone();
        n.invocation_kind = InvocationKind::Notify;
        assert_ne!(c.canonical_bytes(), n.canonical_bytes());

        // (2) dedup within window + reuse after.
        let mut d = InvocationDedup::new();
        let inv = sample_invocation(InvocationKind::Notify, "inv-1");
        assert!(d.record_or_reject(&inv, "2026-05-29T17:05:00.000Z").is_ok());
        assert!(d
            .record_or_reject(&inv, "2026-05-29T17:06:00.000Z")
            .is_err());
        assert!(d.record_or_reject(&inv, "2026-05-29T18:00:00.000Z").is_ok());
    }
}
