//! **"Who is this ABOUT?"** — the question a signature check does not answer
//! (CIRISVerify#252, CIRISPersist#660).
//!
//! ## The class
//!
//! Every authority gate answers *"who signed?"*. A quorum verifies m-of-n over
//! `JCS(envelope)` and **nothing else** — so if the value naming the subject is
//! not compared against those bytes, the same valid signature applies to any
//! subject.
//!
//! Concretely, the shape that shipped here: a `ProvenanceLink` declares a
//! `key_id` and pubkeys *outside* the signed envelope, and the verifier
//! canonicalized the envelope, hashed it, and verified signatures over it —
//! without ever reading the `key_id` **inside**. An attacker wraps a victim's
//! genuine, validly-signed envelope in a link declaring their own identity.
//! Content hash matches (it really is the victim's envelope), signatures verify
//! (really signed by the real parent), linkage passes — and the chain roots the
//! *attacker's* key.
//!
//! The binding was already in the signed bytes. Nobody opened the letter.
//!
//! ## The four rules, each paid for
//!
//! 1. **Bind the identity, not just the name.** Binding `key_id` alone loses to
//!    a race: on a node that has not replicated the victim's row, an attacker
//!    registers the victim's `key_id` with their **own** pubkeys. Bind every
//!    key leg, with absence asserted as JSON `null`, so substituting a PQC key
//!    the signature never covered is refused exactly as a differing string is.
//! 2. **The checker ITERATES the projection.** Adding a member extends the
//!    check with no second edit — exhaustive by construction rather than by
//!    anyone remembering. This is what makes the fix safe to reuse unchanged.
//! 3. **Fail CLOSED on absence.** An envelope not carrying a projected member
//!    is REFUSED, never tolerated: *an optional check is skippable by omission,
//!    which is the whole attack.*
//! 4. **Check the binding FIRST**, before roster, anchor or custody
//!    resolution, so the refusal is deterministic regardless of that state.
//!
//! One trap worth inheriting from persist: *"this record confers nothing
//! today"* is **not** a reason to skip binding it. Records become conferral
//! subjects through elevation paths added later.

use serde_json::{Map, Value};

/// A subject binding did not hold. Every variant is a refusal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SubjectBindingError {
    /// The signed object is not a JSON object, so it carries no binding at all.
    NotAnObject {
        /// What was being checked, for the diagnostic.
        context: String,
    },
    /// A projected member is **absent** from the signed bytes — refused, never
    /// tolerated (rule 3).
    Missing {
        /// What was being checked.
        context: String,
        /// The member the projection requires.
        member: String,
    },
    /// A projected member is present but names a **different subject** — the
    /// attack this module exists to refuse.
    Mismatch {
        /// What was being checked.
        context: String,
        /// The member that disagreed.
        member: String,
        /// What the signed bytes actually say.
        signed: String,
        /// What the carrier claimed.
        claimed: String,
    },
}

impl SubjectBindingError {
    /// The projected member that failed, as data.
    ///
    /// A consumer asserting its own projection against verify's needs the
    /// member **name**, not a rendered message (CIRISVerify#254). `None` only
    /// for [`NotAnObject`](Self::NotAnObject), where no single member is at
    /// fault.
    #[must_use]
    pub fn member(&self) -> Option<&str> {
        match self {
            Self::NotAnObject { .. } => None,
            Self::Missing { member, .. } | Self::Mismatch { member, .. } => Some(member),
        }
    }

    /// What the carrier claimed for the failing member, as data.
    #[must_use]
    pub fn claimed(&self) -> Option<&str> {
        match self {
            Self::Mismatch { claimed, .. } => Some(claimed),
            _ => None,
        }
    }
}

impl std::fmt::Display for SubjectBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject { context } => {
                write!(f, "{context}: signed payload is not a JSON object, so it carries no subject binding")
            },
            Self::Missing { context, member } => write!(
                f,
                "{context}: signed bytes do not carry `{member}` — refusing, \
                 an absent binding is skippable by omission"
            ),
            Self::Mismatch {
                context,
                member,
                signed,
                claimed,
            } => write!(
                f,
                "{context}: subject mismatch on `{member}` — signed bytes say {signed}, \
                 carrier claims {claimed}. The signature is valid but it is about a \
                 DIFFERENT subject."
            ),
        }
    }
}

impl std::error::Error for SubjectBindingError {}

/// Builder for the set of members that name **who a signed object is about**.
///
/// Callers construct one per verified object and hand it to
/// [`check`](SubjectBinding::check), which iterates it (rule 2).
#[derive(Debug, Clone, Default)]
pub struct SubjectBinding {
    members: Map<String, Value>,
}

impl SubjectBinding {
    /// Start an empty projection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require `member` in the signed bytes to equal `value`.
    #[must_use]
    pub fn require(mut self, member: &str, value: impl Into<Value>) -> Self {
        self.members.insert(member.to_string(), value.into());
        self
    }

    /// Require an **optional** key leg, asserting absence as JSON `null`
    /// (rule 1) — so a PQC key the signature never covered cannot be
    /// substituted in, and is refused exactly as a differing string is.
    #[must_use]
    pub fn require_optional(mut self, member: &str, value: Option<&str>) -> Self {
        self.members.insert(
            member.to_string(),
            value.map_or(Value::Null, |v| Value::String(v.to_string())),
        );
        self
    }

    /// The projected members, for tests and diagnostics.
    #[must_use]
    pub fn members(&self) -> &Map<String, Value> {
        &self.members
    }

    /// **Check the projection against the signed bytes**, iterating every
    /// projected member.
    ///
    /// `signed` MUST be the object whose canonicalization the signature
    /// actually covers — passing anything else re-opens the hole this closes.
    ///
    /// # Errors
    /// [`SubjectBindingError`] on a non-object payload, an absent member, or a
    /// member naming a different subject.
    pub fn check(&self, context: &'static str, signed: &Value) -> Result<(), SubjectBindingError> {
        let obj = signed
            .as_object()
            .ok_or_else(|| SubjectBindingError::NotAnObject {
                context: context.to_string(),
            })?;

        for (member, expected) in &self.members {
            // Absent is REFUSED, not tolerated — except that an expected
            // `null` is satisfied by an absent member, since JCS producers
            // legitimately omit rather than materialize a null (CEG §0.9
            // omit-vs-materialize). A *present* value still must match.
            let actual = match obj.get(member) {
                Some(v) => v,
                None if expected.is_null() => continue,
                None => {
                    return Err(SubjectBindingError::Missing {
                        context: context.to_string(),
                        member: member.clone(),
                    })
                },
            };
            if actual != expected {
                return Err(SubjectBindingError::Mismatch {
                    context: context.to_string(),
                    member: member.clone(),
                    signed: actual.to_string(),
                    claimed: expected.to_string(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matching_subject_passes() {
        let signed = json!({"key_id": "k1", "pubkey_ed25519_base64": "AAA", "extra": 1});
        SubjectBinding::new()
            .require("key_id", "k1")
            .require("pubkey_ed25519_base64", "AAA")
            .check("t", &signed)
            .expect("a coherent object must pass");
    }

    /// The attack: valid signature, different subject.
    #[test]
    fn differing_subject_is_a_mismatch() {
        let signed = json!({"key_id": "victim"});
        let err = SubjectBinding::new()
            .require("key_id", "mallory")
            .check("t", &signed)
            .unwrap_err();
        assert!(matches!(err, SubjectBindingError::Mismatch { .. }));
        assert!(err.to_string().contains("DIFFERENT subject"));
    }

    /// Rule 3: absence is REFUSED, not tolerated — an optional check is
    /// skippable by omission, which is the whole attack.
    #[test]
    fn absent_member_is_refused_not_tolerated() {
        let signed = json!({"something_else": 1});
        assert!(matches!(
            SubjectBinding::new()
                .require("key_id", "k1")
                .check("t", &signed),
            Err(SubjectBindingError::Missing { .. })
        ));
    }

    /// Rule 1: an optional leg the carrier claims must be present in the
    /// signed bytes — substituting a key the signature never covered is
    /// refused exactly as a differing string is.
    #[test]
    fn substituted_optional_leg_is_refused() {
        let signed = json!({"pqc": "REAL"});
        assert!(matches!(
            SubjectBinding::new()
                .require_optional("pqc", Some("SUBSTITUTED"))
                .check("t", &signed),
            Err(SubjectBindingError::Mismatch { .. })
        ));
    }

    /// A carrier claiming *no* optional leg while the signed bytes declare one
    /// is also refused — the asymmetric direction, which is how a downgrade
    /// would sneak in.
    #[test]
    fn dropping_a_declared_optional_leg_is_refused() {
        let signed = json!({"pqc": "REAL"});
        assert!(matches!(
            SubjectBinding::new()
                .require_optional("pqc", None)
                .check("t", &signed),
            Err(SubjectBindingError::Mismatch { .. })
        ));
    }

    /// An expected-null leg is satisfied by omission, since JCS producers
    /// legitimately omit rather than materialize a null (CEG §0.9). This is
    /// the ONE tolerated absence, and only when the carrier claims nothing.
    #[test]
    fn expected_null_is_satisfied_by_omission() {
        let signed = json!({"key_id": "k1"});
        SubjectBinding::new()
            .require("key_id", "k1")
            .require_optional("pqc", None)
            .check("t", &signed)
            .expect("omit-vs-materialize: absent == null when nothing is claimed");
    }

    /// Rule 2: the checker ITERATES, so a projection member added later is
    /// enforced with no second edit.
    #[test]
    fn every_projected_member_is_checked() {
        let signed = json!({"a": "1", "b": "2", "c": "WRONG"});
        let sb = SubjectBinding::new()
            .require("a", "1")
            .require("b", "2")
            .require("c", "3");
        assert_eq!(sb.members().len(), 3);
        assert!(matches!(
            sb.check("t", &signed),
            Err(SubjectBindingError::Mismatch { member, .. }) if member == "c"
        ));
    }

    #[test]
    fn non_object_payload_carries_no_binding() {
        assert!(matches!(
            SubjectBinding::new()
                .require("k", "v")
                .check("t", &json!("a string")),
            Err(SubjectBindingError::NotAnObject { .. })
        ));
    }
}

/// **Cross-plane agreement** — verify's own planes must not drift apart
/// (CIRISVerify#254).
///
/// The projections live in separate `.require(…)` chains on three types.
/// Nothing forced them to agree, and a consumer produces ONE envelope that has
/// to satisfy whichever plane it reaches. CIRISPersist's conformance probe was
/// asserting this on verify's behalf; verify should hold its own invariant.
#[cfg(test)]
mod cross_plane {
    use crate::federation_self_record::KeyRecord;
    use crate::provenance::ProvenanceLink;
    use serde_json::json;

    fn envelope(key_id: &str) -> serde_json::Value {
        json!({
            "key_id": key_id,
            "identity_type": "steward",
            "pubkey_ed25519_base64": "ED",
            "pubkey_ml_dsa_65_base64": "PQ",
        })
    }

    fn link() -> ProvenanceLink {
        ProvenanceLink {
            key_id: "k1".into(),
            pubkey_ed25519_base64: "ED".into(),
            pubkey_ml_dsa_65_base64: Some("PQ".into()),
            identity_type: "steward".into(),
            identity_ref: "ref".into(),
            registration_envelope: envelope("k1"),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "k1".into(),
            scrub_timestamp: String::new(),
            is_self_signed: true,
        }
    }

    /// The registration-envelope planes bind the SAME member set. A member
    /// added to one and not the other means one envelope satisfies the
    /// provenance walk and fails `KeyRecord`, or the reverse.
    #[test]
    fn provenance_and_key_record_bind_the_same_members() {
        let rec: KeyRecord = serde_json::from_value(json!({
            "key_id": "k1",
            "algorithm": "hybrid",
            "identity_type": "steward",
            "identity_ref": "ref",
            "pubkey_ed25519_base64": "ED",
            "pubkey_ml_dsa_65_base64": "PQ",
            "valid_from": "2026-01-01T00:00:00Z",
            "registration_envelope": envelope("k1"),
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": "k1",
            "scrub_timestamp": "",
            "persist_row_hash": "",
        }))
        .expect("KeyRecord fixture must deserialize");

        let (lb, rb) = (link().subject_binding(), rec.subject_binding());
        let a: Vec<&String> = lb.members().keys().collect();
        let b: Vec<&String> = rb.members().keys().collect();
        assert_eq!(
            a, b,
            "provenance and key-record planes must bind the same members; \
             a member added to one only means the same envelope passes one \
             plane and fails the other"
        );
    }

    /// …and on the same VALUES for the same underlying row, not merely the
    /// same names. Equal key sets with divergent values is the subtler drift.
    #[test]
    fn the_two_planes_agree_on_values_too() {
        let l = link();
        let rec: KeyRecord = serde_json::from_value(json!({
            "key_id": "k1",
            "algorithm": "hybrid",
            "identity_type": "steward",
            "identity_ref": "ref",
            "pubkey_ed25519_base64": "ED",
            "pubkey_ml_dsa_65_base64": "PQ",
            "valid_from": "2026-01-01T00:00:00Z",
            "registration_envelope": envelope("k1"),
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": "k1",
            "scrub_timestamp": "",
            "persist_row_hash": "",
        }))
        .unwrap();
        let (lb, rb) = (l.subject_binding(), rec.subject_binding());
        assert_eq!(lb.members(), rb.members());
    }

    /// The projection a plane exposes is the one it CHECKS — otherwise the
    /// exported list is a documentation comment with extra steps.
    #[test]
    fn the_exposed_projection_is_the_one_enforced() {
        let l = link();
        // Satisfied by the coherent envelope …
        assert!(l
            .subject_binding()
            .check("t", &l.registration_envelope)
            .is_ok());
        // … and every exposed member is actually enforced: flip each in turn.
        let proj = l.subject_binding();
        for member in proj.members().keys() {
            let mut tampered = l.registration_envelope.clone();
            tampered[member] = json!("TAMPERED");
            assert!(
                l.subject_binding().check("t", &tampered).is_err(),
                "exposed member `{member}` is not enforced — the projection would be advisory"
            );
        }
    }
}
