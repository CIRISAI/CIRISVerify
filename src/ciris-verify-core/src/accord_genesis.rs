//! HUMANITY_ACCORD genesis producer (CEG §9.1, `docs/ACCORD_KEY_GENESIS_RUNBOOK.md`
//! §5 / §7) — CIRISVerify#? scope-genesis path.
//!
//! Verify already **verifies** the accord 2-of-3
//! ([`crate::threshold::verify_founder_quorum`],
//! [`crate::humanity_accord::verify_invocation`]); this module is the
//! **producer** side the runbook §11 named as "a future ceremony tool could
//! wrap §4–§7". Every object it emits round-trips back through those verifiers
//! before it reaches the CEG outbox — the producer↔verifier round-trip *is* the
//! contract.
//!
//! Two surfaces:
//!
//! 1. `produce_accord_holder_record` — runbook §5: a holder's self-signed
//!    `accord_holder` genesis `SignedKeyRecord` (hybrid Ed25519 + ML-DSA-65,
//!    hardware-rooted when the `SelfSigner` is a YubiKey-backed
//!    `HardwareRootedIdentity`). Thin pin over `produce_self_key_record`.
//! 2. `build_accord_family_envelope` → `co_sign_accord_family` (×founders) →
//!    `assemble_accord_family_genesis` — runbook §7: the entrenched-`family`
//!    Contribution. Each founder co-signs the JCS bytes **on their own token**
//!    (no human signs another's key); the assembler verifies the accord's
//!    **2/3** founder quorum of **distinct keys** before wrapping the genesis
//!    object (genesis is *not* unanimous — see `assemble_accord_family_genesis`).
//!
//! **family vs community:** this is the entrenched **family** (§9.1,
//! `quorum:2/3`, `consensus_protocol_entrenched`); `ciris-canonical` is the
//! infrastructure **community** ([`crate::infrastructure_community`], #31). Easy
//! to conflate — they are not the same object.
//!
//! **Cross-impl flag:** the family-envelope member set (runbook §7) and the
//! `accord_holder` row schema are pinned here but flagged for CIRISPersist /
//! CIRISRegistry / CEG §9.1 cross-confirmation (runbook §5), like the #76
//! partnership set and the manifest-contribution shape.

use base64::Engine;
use serde_json::{json, Value};

use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::federation_self_record::{produce_self_key_record, SignedKeyRecord};
use crate::jcs;
use crate::self_at_login::SelfSigner;
use crate::threshold::{
    verify_founder_quorum, Role, ThresholdError, ThresholdMember, ThresholdSignature,
};

/// CEG §9.3 `identity_type` for a HUMANITY_ACCORD holder key.
pub const IDENTITY_TYPE_ACCORD_HOLDER: &str = "accord_holder";

/// The canonical `family_key_id` of the accord (runbook §7).
pub const HUMANITY_ACCORD_FAMILY_KEY_ID: &str = "humanity-accord";

/// The entrenched-family consensus protocol string (runbook §7).
pub const ACCORD_CONSENSUS_PROTOCOL: &str = "quorum:2/3";

/// The founder quorum threshold (`M` of `quorum:M/N`) — used for **genesis and
/// every later `supersedes` alike**. Genesis is *not* unanimous; 2-of-3 of the
/// declared founders authorizes it, the same bar the accord uses throughout.
pub const ACCORD_QUORUM_THRESHOLD: usize = 2;

/// CEG `kind` for the entrenched-family genesis object in the outbox.
pub const ACCORD_FAMILY_GENESIS_KIND: &str = "accord_family_genesis";

/// Runbook §5 — produce a holder's self-signed `accord_holder` genesis
/// [`SignedKeyRecord`], hardware-rooted when `holder` is a YubiKey-backed
/// [`crate::self_at_login::HardwareRootedIdentity`].
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization or signer fault.
pub async fn produce_accord_holder_record(
    holder: &dyn SelfSigner,
    valid_from: &str,
) -> Result<SignedKeyRecord, VerifyError> {
    produce_self_key_record(holder, IDENTITY_TYPE_ACCORD_HOLDER, valid_from).await
}

/// Runbook §7 — the canonical entrenched-`family` envelope.
///
/// `member_key_ids` are the **live-roster** founders (the 3 *primaries*; the
/// cold-spares are NOT in the roster). Input order is preserved — JCS arrays are
/// order-significant (§0.9.2.1), so producer and verifier must agree on it.
#[must_use]
pub fn build_accord_family_envelope(
    family_key_id: &str,
    family_name: &str,
    member_key_ids: &[String],
) -> Value {
    let members: Vec<Value> = member_key_ids
        .iter()
        .map(|k| json!({ "key_id": k, "role": "founder" }))
        .collect();
    json!({
        "family_key_id": family_key_id,
        "family_name": family_name,
        "members": members,
        "consensus_protocol": ACCORD_CONSENSUS_PROTOCOL,
        "consensus_protocol_entrenched": true,
    })
}

/// The JCS signing bytes of a family envelope (CEG §0.9) — the one blessed
/// encoder every founder and the verifier recompute.
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization fault.
pub fn accord_family_signing_bytes(envelope: &Value) -> Result<Vec<u8>, VerifyError> {
    jcs::canonicalize(envelope)
}

/// Runbook §7 — one founder co-signs the family envelope on **their own** token
/// (bound hybrid: Ed25519 touch + ML-DSA-65). Each holder calls this
/// independently; collect the results for [`assemble_accord_family_genesis`].
///
/// # Errors
///
/// [`VerifyError`] on a canonicalization or signer fault.
pub async fn co_sign_accord_family(
    founder: &dyn SelfSigner,
    envelope: &Value,
) -> Result<ThresholdSignature, VerifyError> {
    let bytes = accord_family_signing_bytes(envelope)?;
    let (ed_sig_b64, pqc_sig_b64) = founder.sign_bound(&bytes).await?;
    Ok(ThresholdSignature {
        member_id: founder.key_id().to_string(),
        ed25519_signature_base64: ed_sig_b64,
        mldsa65_signature_base64: Some(pqc_sig_b64),
    })
}

/// Build a **founder-role** [`ThresholdMember`] from a signer's hybrid pubkeys —
/// the pinned identity the assembler verifies signatures against.
///
/// # Errors
///
/// [`VerifyError`] on a signer fault.
pub async fn founder_member(signer: &dyn SelfSigner) -> Result<ThresholdMember, VerifyError> {
    let ed = signer.ed25519_public_key().await?;
    let mldsa = signer.mldsa65_public_key().await?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(ThresholdMember {
        member_id: signer.key_id().to_string(),
        ed25519_public_key_base64: b64.encode(&ed),
        mldsa65_public_key_base64: Some(b64.encode(&mldsa)),
        role: Some(Role::Founder),
    })
}

/// Why an accord-family genesis assembly was rejected. Every variant is a hard
/// fail-closed reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccordGenesisError {
    /// The envelope is malformed (missing/!array `members`, or a member with no
    /// `key_id`).
    MalformedEnvelope {
        /// What was wrong.
        detail: String,
    },
    /// The supplied founder members do not match the envelope's member set
    /// (key_id sets differ) — the pinned pubkeys are for a different roster.
    EnvelopeMemberMismatch {
        /// The envelope's member key_ids.
        envelope: Vec<String>,
        /// The supplied founder member_ids.
        supplied: Vec<String>,
    },
    /// The roster lists the same `key_id` more than once — a degenerate roster
    /// that would let one seat be double-counted. Founders must be distinct.
    DuplicateMemberKeyId {
        /// The repeated `key_id`.
        key_id: String,
    },
    /// Two supplied founders carry the **same public key** under different
    /// `member_id`s — one key occupying multiple founder seats. This is the
    /// attack that defeats the quorum: `verify_founder_quorum` counts
    /// distinctness by `member_id` string, so without this gate one key could
    /// sign twice under two `member_id`s and meet 2/3 *by itself*. Founders MUST
    /// be distinct keys.
    DuplicateFounderKey {
        /// The `member_id` whose key duplicates an earlier founder's.
        member_id: String,
    },
    /// A supplied member is not `role: founder` — the family roster is
    /// founders-only and [`verify_founder_quorum`] would silently drop it.
    NotAllFounders {
        /// The offending member_id.
        member_id: String,
    },
    /// Fewer distinct valid founder signatures than the accord's 2/3 quorum
    /// ([`ACCORD_QUORUM_THRESHOLD`]). Genesis is **not** unanimous — a 2-of-3
    /// quorum of distinct founder keys authorizes it.
    QuorumNotMet {
        /// Distinct valid founder signatures counted.
        valid: usize,
        /// The quorum threshold required (2).
        required: usize,
    },
    /// The threshold layer rejected the signature set for a reason other than
    /// count (deadlock policy, roster mismatch, a malformed signature, …).
    Threshold {
        /// The underlying [`crate::threshold::ThresholdError`] rendered.
        detail: String,
    },
    /// A canonicalization fault computing the signing bytes.
    Canonicalize {
        /// The underlying error.
        detail: String,
    },
}

impl std::fmt::Display for AccordGenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedEnvelope { detail } => {
                write!(f, "malformed accord family envelope: {detail}")
            },
            Self::EnvelopeMemberMismatch { envelope, supplied } => write!(
                f,
                "envelope members {envelope:?} do not match supplied founders {supplied:?}"
            ),
            Self::DuplicateMemberKeyId { key_id } => {
                write!(f, "roster lists key_id {key_id:?} more than once")
            },
            Self::DuplicateFounderKey { member_id } => write!(
                f,
                "founder {member_id:?} reuses another founder's public key (one key, multiple seats)"
            ),
            Self::NotAllFounders { member_id } => {
                write!(f, "member {member_id:?} is not role:founder")
            },
            Self::QuorumNotMet { valid, required } => write!(
                f,
                "founder quorum not met: {valid} valid distinct signatures, need {required}"
            ),
            Self::Threshold { detail } => write!(f, "founder quorum rejected: {detail}"),
            Self::Canonicalize { detail } => write!(f, "canonicalize: {detail}"),
        }
    }
}

impl std::error::Error for AccordGenesisError {}

/// Extract the envelope's member `key_id`s in order.
fn envelope_member_key_ids(envelope: &Value) -> Result<Vec<String>, AccordGenesisError> {
    let members = envelope.get("members").and_then(Value::as_array).ok_or(
        AccordGenesisError::MalformedEnvelope {
            detail: "missing or non-array `members`".to_string(),
        },
    )?;
    members
        .iter()
        .map(|m| {
            m.get("key_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(AccordGenesisError::MalformedEnvelope {
                    detail: "a member has no string `key_id`".to_string(),
                })
        })
        .collect()
}

/// Runbook §7 — assemble + **round-trip-verify** the entrenched-family genesis.
///
/// Fail-closed checks, in order:
/// 1. The envelope is well-formed, lists **distinct** member `key_id`s, and its
///    `key_id` set equals the supplied `founders`' `member_id` set.
/// 2. The supplied founders are **distinct keys** — no two share an Ed25519 (or
///    ML-DSA-65) public key. This is load-bearing: [`verify_founder_quorum`]
///    counts distinctness by `member_id` *string*, so without this gate one key
///    relabeled under a second `member_id` would meet the quorum by itself (a
///    single-key capture).
/// 3. Every supplied founder is `role: founder`.
/// 4. [`verify_founder_quorum`] over the JCS bytes meets the accord's **2/3**
///    quorum ([`ACCORD_QUORUM_THRESHOLD`]) of distinct founder keys. Genesis is
///    **not** unanimous — founding must not require every holder present (that
///    would defeat the fault-tolerance 2/3 exists for), and any 2-of-3 is a
///    trusted quorum under the accord's own model.
///
/// **Scope of the guarantee:** this proves *a 2/3 quorum of distinct keys each
/// validly signed the exact family envelope*. It does **not** prove each pubkey
/// belongs to the named human — that key↔human binding is established
/// out-of-band by the §6 steward cross-attestation, not asserted here (genesis
/// has no pinned directory yet). The caller supplies all founder pubkeys (the
/// full roster, from the §5 self-signed holder records); a downstream consumer
/// re-pins them and re-runs the quorum. (Having all three present at the
/// ceremony is recommended best practice, but **not** enforced.)
///
/// On success returns a [`SignedCegObject`] (`kind: accord_family_genesis`)
/// whose body carries the envelope + the founder signature set, ready for the
/// outbox → CIRISServer relay.
///
/// # Errors
///
/// [`AccordGenesisError`] naming the first failing step.
pub fn assemble_accord_family_genesis(
    envelope: &Value,
    founders: &[ThresholdMember],
    signatures: &[ThresholdSignature],
    created_at: &str,
) -> Result<SignedCegObject, AccordGenesisError> {
    // 1. Envelope well-formed + distinct key_ids + envelope↔founders set match.
    let mut env_ids = envelope_member_key_ids(envelope)?;
    {
        let mut seen = std::collections::HashSet::new();
        for k in &env_ids {
            if !seen.insert(k.as_str()) {
                return Err(AccordGenesisError::DuplicateMemberKeyId { key_id: k.clone() });
            }
        }
    }
    let mut sup_ids: Vec<String> = founders.iter().map(|m| m.member_id.clone()).collect();
    let (mut a, mut b) = (env_ids.clone(), sup_ids.clone());
    a.sort();
    b.sort();
    if a != b {
        env_ids.sort();
        sup_ids.sort();
        return Err(AccordGenesisError::EnvelopeMemberMismatch {
            envelope: env_ids,
            supplied: sup_ids,
        });
    }

    // 2. Founders must be DISTINCT KEYS — no key may occupy two seats. (The
    //    quorum verifier dedups by member_id string only, so this gate is what
    //    stops one key meeting the 2/3 bar by itself.)
    let mut seen_ed = std::collections::HashSet::new();
    let mut seen_pqc = std::collections::HashSet::new();
    for m in founders {
        if !seen_ed.insert(m.ed25519_public_key_base64.as_str()) {
            return Err(AccordGenesisError::DuplicateFounderKey {
                member_id: m.member_id.clone(),
            });
        }
        if let Some(pqc) = m.mldsa65_public_key_base64.as_deref() {
            if !seen_pqc.insert(pqc) {
                return Err(AccordGenesisError::DuplicateFounderKey {
                    member_id: m.member_id.clone(),
                });
            }
        }
    }

    // 3. Founders-only.
    if let Some(m) = founders.iter().find(|m| m.role != Some(Role::Founder)) {
        return Err(AccordGenesisError::NotAllFounders {
            member_id: m.member_id.clone(),
        });
    }

    // 4. Founder quorum over the JCS bytes — the accord's 2/3, NOT unanimous.
    //    The roster is the full founder set; a 2-of-3 quorum of distinct keys
    //    authorizes genesis, consistent with how the accord operates (and with
    //    its fault-tolerance: founding must not require every holder present).
    //    Roster integrity is the distinct-key gate (step 2) + the §6 steward
    //    cross-attestation, not unanimity.
    let bytes =
        accord_family_signing_bytes(envelope).map_err(|e| AccordGenesisError::Canonicalize {
            detail: e.to_string(),
        })?;
    let _valid = match verify_founder_quorum(&bytes, founders, signatures, ACCORD_QUORUM_THRESHOLD)
    {
        Ok(n) => n,
        Err(ThresholdError::Insufficient { valid, threshold }) => {
            return Err(AccordGenesisError::QuorumNotMet {
                valid,
                required: threshold,
            })
        },
        Err(e) => {
            return Err(AccordGenesisError::Threshold {
                detail: format!("{e:?}"),
            })
        },
    };

    let family_key_id = envelope
        .get("family_key_id")
        .and_then(Value::as_str)
        .unwrap_or(HUMANITY_ACCORD_FAMILY_KEY_ID);
    let body = json!({
        "family": envelope,
        "founder_signatures": signatures,
    });
    Ok(SignedCegObject::new(
        ACCORD_FAMILY_GENESIS_KIND,
        family_key_id,
        created_at,
        body,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_at_login::HybridSigningIdentity;

    const TS: &str = "2026-06-19T00:00:00Z";

    fn holders() -> [HybridSigningIdentity; 3] {
        [
            HybridSigningIdentity::generate("accord-eric-moore-primary").unwrap(),
            HybridSigningIdentity::generate("accord-eric-kudzin-primary").unwrap(),
            HybridSigningIdentity::generate("accord-haley-bradley-primary").unwrap(),
        ]
    }

    fn member_ids(hs: &[HybridSigningIdentity]) -> Vec<String> {
        hs.iter().map(|h| h.key_id().to_string()).collect()
    }

    async fn members_of(hs: &[HybridSigningIdentity]) -> Vec<ThresholdMember> {
        let mut v = Vec::new();
        for h in hs {
            v.push(founder_member(h).await.unwrap());
        }
        v
    }

    #[tokio::test]
    async fn holder_record_is_accord_holder() {
        let h = HybridSigningIdentity::generate("accord-eric-moore-primary").unwrap();
        let rec = produce_accord_holder_record(&h, TS).await.unwrap();
        assert_eq!(rec.record.identity_type, "accord_holder");
        assert_eq!(rec.record.key_id, "accord-eric-moore-primary");
        assert!(rec.record.pubkey_ml_dsa_65_base64.is_some());
    }

    #[tokio::test]
    async fn all_three_founders_assembles_and_round_trips() {
        let hs = holders();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &member_ids(&hs),
        );
        let mut sigs = Vec::new();
        for h in &hs {
            sigs.push(co_sign_accord_family(h, &envelope).await.unwrap());
        }
        let founders = members_of(&hs).await;
        let obj = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS).unwrap();

        assert_eq!(obj.kind, ACCORD_FAMILY_GENESIS_KIND);
        assert_eq!(obj.key_id, "humanity-accord");
        assert_eq!(obj.body["family"]["consensus_protocol"], "quorum:2/3");
        assert_eq!(obj.body["family"]["consensus_protocol_entrenched"], true);

        // Independent round-trip: a consumer recomputes the JCS bytes and
        // re-verifies the founder quorum against the same pinned pubkeys.
        let bytes = accord_family_signing_bytes(&obj.body["family"]).unwrap();
        assert_eq!(
            verify_founder_quorum(&bytes, &founders, &sigs, ACCORD_QUORUM_THRESHOLD),
            Ok(3)
        );
    }

    #[tokio::test]
    async fn genesis_admits_two_of_three_quorum() {
        // Genesis is the accord's 2/3, NOT unanimous: two of the three founders
        // sign the full 3-member roster → genesis is authorized. (Founding must
        // not require every holder present.)
        let hs = holders();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &member_ids(&hs),
        );
        let sigs = vec![
            co_sign_accord_family(&hs[0], &envelope).await.unwrap(),
            co_sign_accord_family(&hs[1], &envelope).await.unwrap(),
        ];
        let founders = members_of(&hs).await; // full 3-member roster pinned
        let obj = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS)
            .expect("a 2-of-3 quorum of distinct founders must authorize genesis");
        // The body re-verifies at the 2/3 quorum against the full roster.
        let bytes = accord_family_signing_bytes(&obj.body["family"]).unwrap();
        assert_eq!(verify_founder_quorum(&bytes, &founders, &sigs, 2), Ok(2));
    }

    #[tokio::test]
    async fn genesis_one_signature_rejected() {
        // One signature is below the 2/3 quorum → rejected.
        let hs = holders();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &member_ids(&hs),
        );
        let sigs = vec![co_sign_accord_family(&hs[0], &envelope).await.unwrap()];
        let founders = members_of(&hs).await;
        let err = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS).unwrap_err();
        assert_eq!(
            err,
            AccordGenesisError::QuorumNotMet {
                valid: 1,
                required: 2
            }
        );
    }

    #[tokio::test]
    async fn tampered_envelope_after_signing_breaks_quorum() {
        let hs = holders();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &member_ids(&hs),
        );
        let mut sigs = Vec::new();
        for h in &hs {
            sigs.push(co_sign_accord_family(h, &envelope).await.unwrap());
        }
        // Flip the entrenchment flag after the founders signed.
        let mut tampered = envelope.clone();
        tampered["consensus_protocol_entrenched"] = json!(false);
        let founders = members_of(&hs).await;
        let err = assemble_accord_family_genesis(&tampered, &founders, &sigs, TS).unwrap_err();
        // Signatures are over the original bytes → quorum collapses to 0.
        assert!(matches!(
            err,
            AccordGenesisError::QuorumNotMet { valid: 0, .. }
                | AccordGenesisError::Threshold { .. }
        ));
    }

    #[tokio::test]
    async fn envelope_member_mismatch_rejected() {
        let hs = holders();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &member_ids(&hs),
        );
        let mut sigs = Vec::new();
        for h in &hs {
            sigs.push(co_sign_accord_family(h, &envelope).await.unwrap());
        }
        // Swap one pinned founder for a stranger.
        let mut founders = members_of(&hs).await;
        founders[2] = founder_member(&HybridSigningIdentity::generate("stranger").unwrap())
            .await
            .unwrap();
        let err = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS).unwrap_err();
        assert!(matches!(
            err,
            AccordGenesisError::EnvelopeMemberMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn non_founder_member_rejected() {
        let hs = holders();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &member_ids(&hs),
        );
        let mut sigs = Vec::new();
        for h in &hs {
            sigs.push(co_sign_accord_family(h, &envelope).await.unwrap());
        }
        let mut founders = members_of(&hs).await;
        founders[1].role = None; // demote a founder
        let err = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS).unwrap_err();
        assert_eq!(
            err,
            AccordGenesisError::NotAllFounders {
                member_id: "accord-eric-kudzin-primary".to_string()
            }
        );
    }

    #[tokio::test]
    async fn co_sign_alone_verifies_at_threshold_one() {
        // A single founder's co-signature verifies against their own pinned
        // pubkeys — proves co_sign emits the bound-hybrid form the verifier wants.
        let h = HybridSigningIdentity::generate("accord-solo").unwrap();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &["accord-solo".to_string()],
        );
        let sig = co_sign_accord_family(&h, &envelope).await.unwrap();
        let m = founder_member(&h).await.unwrap();
        let bytes = accord_family_signing_bytes(&envelope).unwrap();
        assert_eq!(verify_founder_quorum(&bytes, &[m], &[sig], 1), Ok(1));
    }

    /// CRITICAL regression (adversarial review): one keyholder MUST NOT meet the
    /// quorum alone by relabeling a single key's signatures across multiple
    /// founder seats. `verify_founder_quorum` dedups by `member_id` *string*, so
    /// the distinct-key gate in the assembler is what closes this single-key
    /// capture (decisive under 2/3, where one key in two seats would otherwise
    /// suffice).
    #[tokio::test]
    async fn one_key_filling_two_seats_is_rejected() {
        let ha = HybridSigningIdentity::generate("accord-a").unwrap();
        let hb = HybridSigningIdentity::generate("accord-b").unwrap();
        let c_id = "accord-c";
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &[
                "accord-a".to_string(),
                "accord-b".to_string(),
                c_id.to_string(),
            ],
        );
        // a and b sign; a signs AGAIN, relabeled as the third founder "c".
        let sig_a = co_sign_accord_family(&ha, &envelope).await.unwrap();
        let sig_b = co_sign_accord_family(&hb, &envelope).await.unwrap();
        let mut sig_c = co_sign_accord_family(&ha, &envelope).await.unwrap();
        sig_c.member_id = c_id.to_string();
        // The "c" founder member carries a's pubkeys under c's key_id.
        let mut m_c = founder_member(&ha).await.unwrap();
        m_c.member_id = c_id.to_string();
        let founders = vec![
            founder_member(&ha).await.unwrap(),
            founder_member(&hb).await.unwrap(),
            m_c,
        ];
        let err = assemble_accord_family_genesis(&envelope, &founders, &[sig_a, sig_b, sig_c], TS)
            .unwrap_err();
        assert_eq!(
            err,
            AccordGenesisError::DuplicateFounderKey {
                member_id: c_id.to_string()
            }
        );
    }

    /// A roster that lists the same `key_id` twice is rejected before any quorum
    /// math (degenerate double-counted seat).
    #[tokio::test]
    async fn duplicate_roster_key_id_rejected() {
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &[
                "accord-a".to_string(),
                "accord-a".to_string(),
                "accord-b".to_string(),
            ],
        );
        let h = HybridSigningIdentity::generate("accord-a").unwrap();
        let founders = vec![founder_member(&h).await.unwrap()];
        let err = assemble_accord_family_genesis(&envelope, &founders, &[], TS).unwrap_err();
        assert_eq!(
            err,
            AccordGenesisError::DuplicateMemberKeyId {
                key_id: "accord-a".to_string()
            }
        );
    }
}
