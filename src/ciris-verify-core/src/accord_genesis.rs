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

#[allow(unused_imports)]
use crate::prelude::*;

use base64::Engine;
use serde_json::{json, Value};

use crate::accord_live_quorum::{
    apply_seat_change, seat_change_digest, AccordAction, AccordDecision, DecidedSeatChange,
    FamilyRecord, FamilyRecordMember, SeatChange, ROSTER_CHANGE_KIND,
};
use crate::ceg_outbox::SignedCegObject;
use crate::error::VerifyError;
use crate::federation_self_record::{produce_self_key_record, SignedKeyRecord};
use crate::humanity_accord::Invocation;
use crate::jcs;
use crate::self_at_login::SelfSigner;
use crate::threshold::{
    verify_founder_quorum, verify_threshold_signatures, Role, ThresholdError, ThresholdMember,
    ThresholdSignature,
};
use chrono::{DateTime, Utc};

/// CEG §9.3 `identity_type` for a HUMANITY_ACCORD holder key.
pub const IDENTITY_TYPE_ACCORD_HOLDER: &str = "accord_holder";

/// The canonical `family_key_id` of the accord (runbook §7).
pub const HUMANITY_ACCORD_FAMILY_KEY_ID: &str = "humanity-accord";

/// The entrenched-family consensus protocol string for the genesis **3-member**
/// accord (`quorum:2/3`). The family is **growable** (M-of-N, CEG §9.1): use
/// [`accord_consensus_protocol`] for an arbitrary member count, and
/// [`accord_quorum_from_family`] to read the live threshold back off a family
/// object. This constant is the N=3 case of that rule.
pub const ACCORD_CONSENSUS_PROTOCOL: &str = "quorum:2/3";

/// The founder quorum threshold for the genesis **3-member** accord (2-of-3).
/// The general rule is [`strict_majority`] of the live member count; this is its
/// N=3 value. Genesis is *not* unanimous; a strict-majority quorum of distinct
/// founder keys authorizes it, the same bar the accord uses throughout.
pub const ACCORD_QUORUM_THRESHOLD: usize = 2;

/// The accord quorum threshold for an `n`-member family: a **strict majority**,
/// `⌊n/2⌋ + 1` (3→2, 5→3, 7→4). `2·M > N` always holds, so no two disjoint
/// quorums can both act — the invariant the growable family preserves across
/// every `supersedes` (it may strengthen but never weaken it).
#[must_use]
pub fn strict_majority(n: usize) -> usize {
    n / 2 + 1
}

/// The `quorum:M/N` consensus-protocol string for an `n`-member family at the
/// strict-majority threshold — `quorum:2/3` for 3, `quorum:3/5` for 5, etc.
#[must_use]
pub fn accord_consensus_protocol(n: usize) -> String {
    format!("quorum:{}/{n}", strict_majority(n))
}

/// Parse a `quorum:M/N` protocol string into `(M, N)`.
fn parse_quorum_protocol(s: &str) -> Option<(usize, usize)> {
    let (m, n) = s.strip_prefix("quorum:")?.split_once('/')?;
    Some((m.parse().ok()?, n.parse().ok()?))
}

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
    // An accord holder is a custody principal, not a dialed-into network node —
    // no transport hint (#172).
    //
    // `valid_until: None` deliberately (#267): an accord holder key is the
    // constitutional kill-switch custody root, and a self-asserted expiry on
    // it would create a date after which the accord silently has fewer
    // holders than its quorum needs. Rotation is the m-of-n membership-change
    // ceremony (`build_accord_membership_change`), never a timeout.
    produce_self_key_record(holder, IDENTITY_TYPE_ACCORD_HOLDER, valid_from, None, &[]).await
}

/// Runbook §7 — the canonical entrenched-`family` envelope.
///
/// `member_key_ids` are the **live-roster** members (each person's *primary*; a
/// person's cold-spare(s) are NOT in the roster — they enter only via a
/// roster change, [`build_membership_change`]). The family is **growable**:
/// `consensus_protocol` is set to the strict-majority `quorum:M/N` for the member
/// count ([`accord_consensus_protocol`]) — `quorum:2/3` at genesis, `quorum:3/5`
/// once grown to five, etc. Input order is preserved — JCS arrays are
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
        "consensus_protocol": accord_consensus_protocol(member_key_ids.len()),
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
#[non_exhaustive]
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
    /// The CEG object is not the expected `kind` (e.g. parsing an invocation but
    /// the object is a family genesis).
    WrongKind {
        /// The `kind` actually found.
        kind: String,
    },
    /// The concurring signer is not a member of the invocation's roster.
    NotARosterMember {
        /// The signer's key_id.
        key_id: String,
    },
    /// The signer's key_id is in the roster but their **pubkeys do not match**
    /// the pinned roster entry — concurring as a different identity is refused.
    RosterIdentityMismatch {
        /// The mismatched member_id.
        member_id: String,
    },
    /// The signer has already signed this invocation — no double-counting.
    AlreadySigned {
        /// The member_id that already signed.
        member_id: String,
    },
    /// A signature already on the object does not verify against its roster
    /// member — the object is tampered; refuse to concur on it.
    InvalidExistingSignature {
        /// The member_id whose existing signature failed.
        member_id: String,
    },
    /// A family member's `key_id` was not found in the supplied directory when
    /// deriving the kill-switch roster — the roster cannot be assembled without
    /// every live member's pinned pubkeys.
    MemberNotInDirectory {
        /// The missing family member `key_id`.
        key_id: String,
    },
    /// The family's `consensus_protocol` is not a **strict majority** (`2·M > N`)
    /// — a growable accord must never weaken below strict majority, or two
    /// disjoint quorums could both act.
    WeakQuorum {
        /// The declared M.
        m: usize,
        /// The declared (and member-count) N.
        n: usize,
    },
    /// A roster change does not name the family, the standing head it succeeds
    /// (`prior_persist_row_hash`, the offered `prev_head_digest`) or the offered
    /// version (`next_persist_row_hash`) (CIRISPersist
    /// `accord_roster_change_unbound`).
    RosterChangeUnbound {
        /// What is wrong.
        detail: String,
    },
    /// A roster change changes more than the seats, the charter it names and
    /// the head link (CIRISPersist `accord_roster_change_not_seats`).
    RosterChangeNotSeats,
    /// A roster change's seats are not covered by authorized, closed decisions
    /// binding exactly those changes (CIRISPersist
    /// `accord_roster_change_uncovered`).
    RosterChangeUncovered {
        /// What is wrong.
        detail: String,
    },
}

impl core::fmt::Display for AccordGenesisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
            Self::WrongKind { kind } => write!(f, "unexpected object kind {kind:?}"),
            Self::NotARosterMember { key_id } => {
                write!(f, "{key_id:?} is not a member of this invocation's roster")
            },
            Self::RosterIdentityMismatch { member_id } => write!(
                f,
                "{member_id:?} is in the roster but the signer's pubkeys do not match the pinned entry"
            ),
            Self::AlreadySigned { member_id } => {
                write!(f, "{member_id:?} has already signed this invocation")
            },
            Self::InvalidExistingSignature { member_id } => write!(
                f,
                "an existing signature from {member_id:?} does not verify — object is tampered"
            ),
            Self::MemberNotInDirectory { key_id } => write!(
                f,
                "family member {key_id:?} has no pinned entry in the supplied directory"
            ),
            Self::WeakQuorum { m, n } => write!(
                f,
                "consensus_protocol quorum:{m}/{n} is not a strict majority (need 2·M > N)"
            ),
            Self::RosterChangeUnbound { detail } => write!(f, "roster change unbound: {detail}"),
            Self::RosterChangeNotSeats => write!(
                f,
                "a roster change changes the seats (and the charter it names), nothing else"
            ),
            Self::RosterChangeUncovered { detail } => {
                write!(f, "roster change uncovered: {detail}")
            },
        }
    }
}

impl core::error::Error for AccordGenesisError {}

/// Extract the envelope's member `key_id`s in order.
pub(crate) fn envelope_member_key_ids(envelope: &Value) -> Result<Vec<String>, AccordGenesisError> {
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

/// Derive + validate the strict-majority quorum threshold `M` from an envelope's
/// `consensus_protocol` (`quorum:M/N`): `N` must equal the member count and
/// `2·M > N` (strict majority — the growable family's entrenched invariant).
fn quorum_threshold_from_envelope(envelope: &Value) -> Result<usize, AccordGenesisError> {
    let n_members = envelope_member_key_ids(envelope)?.len();
    let cp = envelope
        .get("consensus_protocol")
        .and_then(Value::as_str)
        .ok_or(AccordGenesisError::MalformedEnvelope {
            detail: "missing `consensus_protocol`".to_string(),
        })?;
    let (m, n) = parse_quorum_protocol(cp).ok_or(AccordGenesisError::MalformedEnvelope {
        detail: format!("consensus_protocol {cp:?} is not quorum:M/N"),
    })?;
    if n != n_members {
        return Err(AccordGenesisError::MalformedEnvelope {
            detail: format!("consensus_protocol N={n} != member count {n_members}"),
        });
    }
    // Strict majority: `2·M > N` (no minimum-N floor — the family is M-of-N and
    // may legitimately degrade to 1/1, 2/2, 2/3, 3/5, …; only split-brain ratios
    // like 1/2 are refused). `checked_mul` guards a parsed-giant `M` from an
    // overflow panic (fail-closed: an un-doublable M is rejected).
    if m == 0 || m.checked_mul(2).is_none_or(|two_m| two_m <= n) {
        return Err(AccordGenesisError::WeakQuorum { m, n });
    }
    Ok(m)
}

/// Reject a roster where any two members share an Ed25519 or ML-DSA-65 public
/// key — one key occupying two seats. `verify_founder_quorum` dedups by
/// `member_id` *string*, so without this a single key relabeled under two
/// member_ids (or one human's primary+spare both seated) meets the quorum by
/// itself. The load-bearing one-key/one-human-one-seat gate, shared by genesis,
/// the roster derivation, and the membership-change verifier.
fn reject_duplicate_member_keys(members: &[ThresholdMember]) -> Result<(), AccordGenesisError> {
    let mut seen_ed = alloc::collections::BTreeSet::new();
    let mut seen_pqc = alloc::collections::BTreeSet::new();
    for m in members {
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
    Ok(())
}

/// Resolve a list of member `key_id`s to their pinned [`ThresholdMember`]s from
/// a caller-supplied `directory`, preserving order. Fail-closed: a `key_id` with
/// no directory entry is [`AccordGenesisError::MemberNotInDirectory`].
fn resolve_members(
    member_ids: &[String],
    directory: &[ThresholdMember],
) -> Result<Vec<ThresholdMember>, AccordGenesisError> {
    member_ids
        .iter()
        .map(|key_id| {
            directory
                .iter()
                .find(|m| &m.member_id == key_id)
                .cloned()
                .ok_or(AccordGenesisError::MemberNotInDirectory {
                    key_id: key_id.clone(),
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
        let mut seen = alloc::collections::BTreeSet::new();
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
    //    stops one key meeting the quorum bar by itself.)
    reject_duplicate_member_keys(founders)?;

    // 3. Founders-only.
    if let Some(m) = founders.iter().find(|m| m.role != Some(Role::Founder)) {
        return Err(AccordGenesisError::NotAllFounders {
            member_id: m.member_id.clone(),
        });
    }

    // 4. Founder quorum over the JCS bytes — the accord's **strict majority**
    //    (M-of-N derived from the envelope's consensus_protocol; 2/3 at genesis,
    //    3/5 once grown), NOT unanimous. The roster is the full founder set; a
    //    strict-majority quorum of distinct keys authorizes genesis, consistent
    //    with how the accord operates (and its fault-tolerance: founding must not
    //    require every holder present). Roster integrity is the distinct-key gate
    //    (step 2) + the §6 steward cross-attestation, not unanimity.
    let threshold = quorum_threshold_from_envelope(envelope)?;
    let bytes =
        accord_family_signing_bytes(envelope).map_err(|e| AccordGenesisError::Canonicalize {
            detail: e.to_string(),
        })?;
    let _valid = match verify_founder_quorum(&bytes, founders, signatures, threshold) {
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

/// Derive the accord **kill-switch roster** from the entrenched-family genesis —
/// the one blessed way to build it (CIRISVerify#96).
///
/// The roster is the family's **member set** (the live founders / primaries named
/// in the `accord_family_genesis` object), resolved against `directory` — the
/// caller's pinned `key_id → ThresholdMember` map (e.g. from `federation_keys`).
/// It is keyed off `family.members`, **NOT** "every `accord_holder` row": any
/// cold-spare or other accord_holder identity present in `directory` is **ignored**
/// (selected out), so one human's spare can never become a second live quorum
/// seat. This is the property the distinct-key gate cannot provide — that gate is
/// per-*key* (it stops one key filling two seats), whereas one-seat-per-*human*
/// comes precisely from `roster = family.members`. A spare enters the roster only
/// via a family `supersedes` that simultaneously removes the primary it replaces
/// (runbook §10), never by being an additional directory row.
///
/// Members are returned in the family-declared order (JCS array order is
/// significant). Fail-closed: a declared member missing from `directory`, a
/// duplicate member `key_id`, two members resolving to the **same pubkey**, or
/// an empty roster are all rejects.
///
/// **Trust boundary (load-bearing — read this):** this helper *reads* the
/// roster off `family_genesis.body.family.members`; it does **not** re-verify
/// the object's `founder_signatures`. The caller MUST pass a genesis object
/// whose quorum it has already verified (via [`assemble_accord_family_genesis`]
/// or an equivalent re-check against pinned keys), and `directory` MUST be the
/// authoritative `federation_keys` pin set (key↔human binding established by the
/// §6 steward cross-attestation) — never anything sourced from the bundle being
/// admitted. The function trusts both; a forged genesis or poisoned directory
/// yields a poisoned roster, exactly as the invocation path documents for its
/// embedded roster.
///
/// # Errors
///
/// [`AccordGenesisError`] if `family_genesis` is the wrong kind / malformed, a
/// declared member has no pinned `directory` entry, or the resolved roster has a
/// duplicate key_id / duplicate pubkey / is empty.
pub fn accord_roster_from_family(
    family_genesis: &SignedCegObject,
    directory: &[ThresholdMember],
) -> Result<Vec<ThresholdMember>, AccordGenesisError> {
    roster_from_envelope(family_envelope(family_genesis)?, directory)
}

/// Resolve + integrity-check a roster from any group envelope's `members` against
/// a pinned directory (CIRISVerify#104 — the role-agnostic core shared by the
/// accord and a plain `quorum:M/N` community). Rejects a duplicate member
/// `key_id`, two members resolving to the **same pubkey** (one-seat gate), a
/// member missing from `directory`, or an empty roster — fail-closed.
///
/// **Trust boundary:** the caller MUST pass a pre-verified envelope and an
/// authoritative `directory` (key↔human binding established upstream); this reads
/// the members, it does not re-verify the group's signatures.
///
/// # Errors
///
/// [`AccordGenesisError`] on a malformed/empty/duplicate roster or a member not
/// in `directory`.
pub fn roster_from_envelope(
    envelope: &Value,
    directory: &[ThresholdMember],
) -> Result<Vec<ThresholdMember>, AccordGenesisError> {
    let member_ids = envelope_member_key_ids(envelope)?;
    if member_ids.is_empty() {
        return Err(AccordGenesisError::MalformedEnvelope {
            detail: "group has no members".to_string(),
        });
    }
    // Defense-in-depth: even though a verified genesis cannot carry duplicate
    // members (the assembler rejects them), a caller may pass an unverified
    // object — reject duplicate key_ids and duplicate pubkeys at derivation too,
    // so a malformed `members` can never silently double-seat a human.
    let mut seen = alloc::collections::BTreeSet::new();
    for k in &member_ids {
        if !seen.insert(k.as_str()) {
            return Err(AccordGenesisError::DuplicateMemberKeyId { key_id: k.clone() });
        }
    }
    let roster = resolve_members(&member_ids, directory)?;
    reject_duplicate_member_keys(&roster)?;
    Ok(roster)
}

/// The live kill-switch **quorum threshold** `M` for a family genesis object —
/// read off its `consensus_protocol` (`quorum:M/N`), validated strict-majority
/// against the live member count (CIRISVerify#96). Pair with
/// [`accord_roster_from_family`]: the family object is the single source of truth
/// for **both** the roster (members) and the threshold, so a growable accord
/// (3/3 → 3/5 → …) needs no recompiled constant.
///
/// # Errors
///
/// [`AccordGenesisError`] if `family_genesis` is the wrong kind / malformed, or
/// its `consensus_protocol` is not a strict majority of the member count.
pub fn accord_quorum_from_family(
    family_genesis: &SignedCegObject,
) -> Result<usize, AccordGenesisError> {
    if family_genesis.kind != ACCORD_FAMILY_GENESIS_KIND {
        return Err(AccordGenesisError::WrongKind {
            kind: family_genesis.kind.clone(),
        });
    }
    let envelope =
        family_genesis
            .body
            .get("family")
            .ok_or(AccordGenesisError::MalformedEnvelope {
                detail: "missing `family`".to_string(),
            })?;
    quorum_threshold_from_envelope(envelope)
}

/// The **baked** canonical HUMANITY_ACCORD family-genesis object as JSON
/// (CIRISVerify#107). **BAKED 2026-06-23** from the real 6-key ceremony (#118):
/// `key_id: "humanity-accord"`, `quorum:2/3` entrenched, founders A1/B1/C1, all
/// three hardware-rooted on FIPS YubiKeys and **3-of-3 cosigned** (≥ the 2/3
/// floor). The genesis object lives as a checked-in artifact (`genesis/…json`)
/// so it is auditable as a file; `humanity_accord_genesis_is_baked_and_quorum_valid`
/// re-verifies its founder quorum against the ceremony's published holder pubkeys.
const HUMANITY_ACCORD_GENESIS_JSON: &str = include_str!("genesis/humanity_accord_genesis.json");

/// The ceremony's published founder pubkeys (A1/B1/C1 hybrid keys), checked in
/// alongside the genesis so the 2-of-3 quorum — and the #160 bootstrap anchor —
/// are independently auditable from a pinned file. Deserializes to
/// [`ThresholdMember`]s.
const FOUNDER_PUBKEYS_JSON: &str = include_str!("genesis/founder_pubkeys.json");

/// The pinned, **no-TOFU** HUMANITY_ACCORD family-genesis recognition root
/// (CIRISVerify#107). A node that was **not** at the ceremony resolves the accord
/// kill-switch roster + quorum from **this** baked object (via
/// [`accord_roster_from_family`] / [`accord_quorum_from_family`]), **never** from
/// a peer — fetching the genesis would be trust-on-first-use.
///
/// This is a constitutional trust root in the same class as the steward /
/// `ciris-canonical` / Yubico custody roots verify already pins, and explicitly
/// does **NOT** ride CIRISServer's `CANONICAL_BOOTSTRAP_PEERS` (infra/node trust,
/// not constitutional kill-switch trust).
///
/// Returns `Some(genesis)` once baked (parsed once, cached); `None` until then —
/// **absence means "not yet pinned"; a cold-start consumer MUST NOT fall back to
/// fetching it from a peer.** Parses to a [`ACCORD_FAMILY_GENESIS_KIND`] object or
/// stays `None` (a malformed bake is treated as not-baked, fail-closed).
#[must_use]
pub fn humanity_accord_genesis() -> Option<&'static SignedCegObject> {
    static PARSED: once_cell::race::OnceBox<Option<SignedCegObject>> =
        once_cell::race::OnceBox::new();
    PARSED
        .get_or_init(|| {
            let trimmed = HUMANITY_ACCORD_GENESIS_JSON.trim();
            if trimmed.is_empty() {
                return Box::new(None);
            }
            Box::new(
                serde_json::from_str::<SignedCegObject>(trimmed)
                    .ok()
                    .filter(|o| o.kind == ACCORD_FAMILY_GENESIS_KIND),
            )
        })
        .as_ref()
}

/// The seated accord holders baked into this binary — the baked
/// `humanity_accord_genesis()` roster resolved against the pinned
/// `founder_pubkeys.json`, both halves of each key. Empty if either is not
/// baked or does not resolve: callers treat that as "no roster", never as an
/// empty quorum.
///
/// This is the roster a trust-root bundle is verified against
/// ([`crate::genesis_bundle::verify_genesis_bundle`]) and the source of
/// [`accord_holder_bootstrap_anchor`], so the two cannot drift.
#[must_use]
pub fn baked_accord_roster() -> Vec<ThresholdMember> {
    let Some(genesis) = humanity_accord_genesis() else {
        return Vec::new();
    };
    let Ok(founders) = serde_json::from_str::<Vec<ThresholdMember>>(FOUNDER_PUBKEYS_JSON) else {
        return Vec::new();
    };
    accord_roster_from_family(genesis, &founders).unwrap_or_default()
}

/// The trusted-bootstrap **rooting anchor** for genesis mesh seeding
/// (CIRISVerify#160, the "centipede head"): the Ed25519 public keys of the
/// **seated** HUMANITY_ACCORD holders (A1/B1/C1).
///
/// A provenance chain that terminates at **any one** of these seated holder keys
/// roots during cold-start bootstrap — the anchor check in
/// [`crate::provenance::verify_provenance_chain`] is set-**membership** (1-of-N),
/// NOT a 2/3 threshold. So a mesh whose canonical node is scrubbed by A1 alone
/// roots. (Invocation thresholds are their own matter — see
/// [`crate::humanity_accord::InvocationKind::required_signatures`]: since
/// CIRISConstitution#146 a `constitutional` halt fires on ONE holder's signature
/// and resumption needs a strict majority of the standing roster.)
///
/// **One source of truth, cross-validated:** the anchor is the *seated roster*
/// resolved from the baked [`humanity_accord_genesis()`] against the pinned
/// `founder_pubkeys.json` directory (via [`accord_roster_from_family`], which
/// applies the one-seat / no-duplicate-pubkey integrity gates). So the anchor and
/// the kill-switch roster can never drift, and spares (A2/B2/C2) are excluded —
/// only *seated* holders are a rooting terminus.
///
/// Returns **empty** (fail-closed) if the genesis is not baked, the pinned
/// founder directory is malformed, the roster fails to resolve, or any holder key
/// is not a valid 32-byte Ed25519 key — no anchor → nothing roots, never a
/// partial/ambiguous anchor.
///
/// ## Test-mode override (CIRISVerify#202)
///
/// In a build carrying the `test-anchor` Cargo feature, with the runtime AND-gate
/// active, a **software single-key** trust root from `CIRIS_TEST_TRUST_ROOT`
/// *replaces* the baked roster (1-of-N rooting makes one key a valid anchor). The
/// feature is absent from every production artifact, so for a prod node this call
/// is byte-for-byte the baked path below. See [`crate::test_anchor`].
#[must_use]
pub fn accord_holder_bootstrap_anchor() -> Vec<[u8; 32]> {
    // TEST-ONLY (compile-time-fenced + runtime-gated): a software test anchor for
    // the local mesh harness. `None` in prod (feature absent) → baked path.
    #[cfg(feature = "std")]
    if let Some(test_root) = crate::test_anchor::test_trust_root_override() {
        return test_root;
    }

    let roster = baked_accord_roster();
    if roster.is_empty() {
        return Vec::new();
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut anchor = Vec::with_capacity(roster.len());
    for member in &roster {
        match b64
            .decode(&member.ed25519_public_key_base64)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        {
            Some(key) => anchor.push(key),
            // A bad/short key in the pinned directory is a hard fault: fail the
            // WHOLE anchor closed rather than root against a partial set.
            None => return Vec::new(),
        }
    }
    anchor
}

/// Extract the `family` envelope from a family-genesis object.
fn family_envelope(family_genesis: &SignedCegObject) -> Result<&Value, AccordGenesisError> {
    if family_genesis.kind != ACCORD_FAMILY_GENESIS_KIND {
        return Err(AccordGenesisError::WrongKind {
            kind: family_genesis.kind.clone(),
        });
    }
    family_genesis
        .body
        .get("family")
        .ok_or(AccordGenesisError::MalformedEnvelope {
            detail: "missing `family`".to_string(),
        })
}

/// A drafted roster change (CC 4.2.6, CC 3.2 T6): the offered version, the
/// change envelope the standing roster's yes-cosigners sign, and the bytes
/// they sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterChangeDraft {
    /// The offered version of the family record (`persist_row_hash` empty).
    pub next: FamilyRecord,
    /// The change envelope ([`ROSTER_CHANGE_KIND`]).
    pub change_envelope: Value,
    /// JCS of the change envelope ([`accord_family_signing_bytes`]): the
    /// yes-cosigners sign these ([`co_sign_accord_family`]).
    pub signing_bytes: Vec<u8>,
    /// JCS of the offered record's signing envelope: the record's author and
    /// every added holder sign these (signing the record is consent).
    pub record_bytes: Vec<u8>,
}

fn roster_change_uncovered(detail: impl Into<String>) -> AccordGenesisError {
    AccordGenesisError::RosterChangeUncovered {
        detail: detail.into(),
    }
}

fn roster_change_unbound(detail: impl Into<String>) -> AccordGenesisError {
    AccordGenesisError::RosterChangeUnbound {
        detail: detail.into(),
    }
}

fn standing_hash(standing: &FamilyRecord) -> Result<String, AccordGenesisError> {
    let computed = standing
        .row_hash()
        .map_err(|e| roster_change_unbound(e.to_string()))?;
    if !standing.persist_row_hash.is_empty() && standing.persist_row_hash != computed {
        return Err(roster_change_unbound(format!(
            "the standing record's stored persist_row_hash {} does not recompute ({computed})",
            standing.persist_row_hash
        )));
    }
    Ok(computed)
}

/// Build a **roster change** (add / remove / swap) of `standing`, the stored
/// head, in CIRISPersist's shape (CC 4.2.6, CC 3.2 T6):
///
/// - the offered version is `standing` with each change applied in order (its
///   removed seats dropped, its added seats appended with `joined_at` and their
///   role), `prev_head_digest` = the standing version's `persist_row_hash`,
///   `charter_digest` = `charter_digest`, and nothing else changed;
/// - the change envelope is `{kind: ROSTER_CHANGE_KIND, family_key_id,
///   prior_persist_row_hash, next_persist_row_hash, changes: [{remove, add,
///   decision}]}`, each change naming the [`AccordProposal::digest`](crate::accord_live_quorum::AccordProposal::digest) of the
///   decision that authorized it.
///
/// A change that adds a holder names a re-scrubbed charter committing the new
/// holder's recovery key (CC 4.2.6), hence the explicit `charter_digest`.
///
/// The standing roster's yes-cosigners sign [`RosterChangeDraft::signing_bytes`]
/// ([`co_sign_accord_family`]); [`verify_membership_change`] verifies the
/// result.
///
/// # Errors
/// [`AccordGenesisError::RosterChangeUncovered`] for no change, a removal of an
/// unseated key or an addition of a seated one;
/// [`AccordGenesisError::RosterChangeUnbound`] when `standing`'s stored
/// `persist_row_hash` does not recompute; [`AccordGenesisError::Canonicalize`]
/// on a canonicalization fault.
pub fn build_membership_change(
    standing: &FamilyRecord,
    changes: &[DecidedSeatChange],
    charter_digest: &str,
    joined_at: DateTime<Utc>,
) -> Result<RosterChangeDraft, AccordGenesisError> {
    if changes.is_empty() {
        return Err(roster_change_uncovered("no decision is named"));
    }
    let prior = standing_hash(standing)?;
    let mut next = standing.clone();
    let mut seats: alloc::collections::BTreeMap<String, Option<String>> = standing
        .members
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    let mut envelope_changes = Vec::with_capacity(changes.len());
    for c in changes {
        apply_seat_change(&mut seats, &c.change).map_err(roster_change_uncovered)?;
        next.members
            .retain(|m| !c.change.remove.contains(&m.key_id));
        next.members
            .extend(c.change.add.iter().map(|a| FamilyRecordMember {
                key_id: a.key_id.clone(),
                joined_at,
                role: a.role.clone(),
            }));
        let mut v =
            serde_json::to_value(&c.change).map_err(|e| AccordGenesisError::Canonicalize {
                detail: e.to_string(),
            })?;
        v["decision"] = Value::from(c.decision.as_str());
        envelope_changes.push(v);
    }
    next.prev_head_digest = prior.clone();
    next.charter_digest = charter_digest.to_string();
    next.persist_row_hash = String::new();
    let canon = |e: crate::accord_live_quorum::LiveQuorumError| AccordGenesisError::Canonicalize {
        detail: e.to_string(),
    };
    let change_envelope = json!({
        "kind": ROSTER_CHANGE_KIND,
        "family_key_id": standing.family_key_id,
        "prior_persist_row_hash": prior,
        "next_persist_row_hash": next.row_hash().map_err(canon)?,
        "changes": envelope_changes,
    });
    let signing_bytes = accord_family_signing_bytes(&change_envelope).map_err(|e| {
        AccordGenesisError::Canonicalize {
            detail: e.to_string(),
        }
    })?;
    Ok(RosterChangeDraft {
        record_bytes: next.record_signing_bytes().map_err(canon)?,
        next,
        change_envelope,
        signing_bytes,
    })
}

/// Verify a **roster change** of the accord (CC 4.2.6, CC 3.2 T6) as
/// CIRISPersist's door (`accord_roster::verify_accord_roster_change`) does:
/// `offered`, carried by `change_envelope` and its `quorum_signatures`,
/// succeeds `standing`, the stored head.
///
/// Fail-closed checks, in order:
/// 1. **Bound**: the envelope is a [`ROSTER_CHANGE_KIND`] envelope naming the
///    family, `prior_persist_row_hash` and the offered `prev_head_digest` are
///    the standing version's `persist_row_hash`, and `next_persist_row_hash`
///    is the offered version's.
/// 2. **Seats only**: the offered record keeps the standing name, founding,
///    consensus protocol, entrenchment and dissolution (it changes the seats,
///    the charter it names and the head link, nothing else).
/// 3. **Covered**: the envelope names at least one change, each bound to a
///    distinct decision in `decisions` that is authorized, a `roster_change` of
///    this family anchored on the standing head, closed at `now`, and whose
///    `payload_sha256` is the [`seat_change_digest`] of exactly that change;
///    the changes, applied to the standing roster in order, give the offered
///    roster, which lists no seat twice.
/// 4. **Quorum**: yes-cosigns over the envelope's JCS bytes from a strict
///    majority of the **standing** roster (CC 4.2.6: `2·yes > N_standing`),
///    resolved in `directory`.
/// 5. **One key, one seat**: the offered roster resolves in `directory` to
///    distinct public keys.
///
/// Returns the key ids the change seats.
///
/// # Conformance
/// This is a pure verifier: it reads no store. CC 4.2.6 requires three more
/// checks of whoever admits a change that adds a holder, and this function
/// makes **none** of them; a caller that skips them does not conform. For each
/// key id returned (each added holder), the caller must check:
/// - **The added holder's own signature on the record**: a hybrid signature by
///   that key, resolved in the caller's key directory, over
///   `offered.record_signing_bytes()` (JCS of the offered record without
///   `persist_row_hash`, [`RosterChangeDraft::record_bytes`]). The standing
///   roster's cosigns over the envelope are not this signature; signing the
///   record is the holder's consent to the seat.
/// - **Its key type**: the key id names a registered key record of type
///   `accord_holder` (`directory` here supplies only public keys and proves
///   nothing about the record's type).
/// - **Charter coverage**: the charter row the offered version names
///   (`offered.charter_digest`, that row's `persist_row_hash`) is stored, and
///   covers the offered roster: in particular its `recovery_commitments`
///   lists each added holder's commitment (CC 4.2.6).
///
/// CIRISPersist's door (`accord_roster::verify_accord_roster_change`) makes
/// these checks against its store.
///
/// # Errors
/// [`AccordGenesisError`] naming the first failing check.
pub fn verify_membership_change(
    standing: &FamilyRecord,
    offered: &FamilyRecord,
    change_envelope: &Value,
    quorum_signatures: &[ThresholdSignature],
    decisions: &[AccordDecision],
    directory: &[ThresholdMember],
    now: DateTime<Utc>,
) -> Result<Vec<String>, AccordGenesisError> {
    let env = change_envelope;
    let field = |k: &str| env.get(k).and_then(Value::as_str).unwrap_or_default();

    // 1. Bound.
    if field("kind") != ROSTER_CHANGE_KIND {
        return Err(roster_change_unbound("not a roster change envelope"));
    }
    let prior = standing_hash(standing)?;
    let next = offered
        .row_hash()
        .map_err(|e| roster_change_unbound(e.to_string()))?;
    let eq = |a: &str, b: &str| ciris_crypto::constant_time_eq(a.as_bytes(), b.as_bytes());
    if field("family_key_id") != standing.family_key_id
        || offered.family_key_id != standing.family_key_id
        || !eq(field("prior_persist_row_hash"), &prior)
        || !eq(&offered.prev_head_digest, &prior)
        || !eq(field("next_persist_row_hash"), &next)
    {
        return Err(roster_change_unbound(
            "the envelope must name the family, the standing head it succeeds and this version",
        ));
    }

    // 2. Seats only.
    if offered.family_name != standing.family_name
        || offered.founded_at != standing.founded_at
        || offered.consensus_protocol != standing.consensus_protocol
        || offered.consensus_protocol_entrenched != standing.consensus_protocol_entrenched
        || offered.dissolved_at != standing.dissolved_at
    {
        return Err(AccordGenesisError::RosterChangeNotSeats);
    }

    // 3. Covered by authorized, closed decisions binding exactly these changes.
    let changes = env
        .get("changes")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| roster_change_uncovered("no decision is named"))?;
    let mut seats: alloc::collections::BTreeMap<String, Option<String>> = standing
        .members
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    let mut seen = alloc::collections::BTreeSet::new();
    for c in changes {
        let digest = c
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !seen.insert(digest) {
            return Err(roster_change_uncovered("a decision is named twice"));
        }
        let change: SeatChange = serde_json::from_value(c.clone())
            .map_err(|e| roster_change_uncovered(format!("seat change: {e}")))?;
        let decision = decisions
            .iter()
            .find(|d| d.proposal.digest() == digest)
            .ok_or_else(|| roster_change_uncovered(format!("no decision {digest}")))?;
        let p = &decision.proposal;
        let closed = DateTime::parse_from_rfc3339(&p.window_until)
            .is_ok_and(|t| t.with_timezone(&Utc) <= now);
        let payload = seat_change_digest(&standing.family_key_id, &change)
            .map_err(|e| roster_change_uncovered(e.to_string()))?;
        if !decision.authorized
            || p.action != AccordAction::RosterChange
            || p.family_key_id != standing.family_key_id
            || !eq(&p.prior_family_digest, &prior)
            || !closed
            || p.payload_sha256 != payload
        {
            return Err(roster_change_uncovered(format!(
                "decision {digest} is not an authorized roster change of the standing head, \
                 closed, binding exactly this seat change"
            )));
        }
        apply_seat_change(&mut seats, &change).map_err(roster_change_uncovered)?;
    }
    let mut listed = alloc::collections::BTreeSet::new();
    if let Some(m) = offered.members.iter().find(|m| !listed.insert(&m.key_id)) {
        return Err(roster_change_uncovered(format!(
            "{} is listed twice in the offered roster",
            m.key_id
        )));
    }
    let offered_seats: alloc::collections::BTreeMap<String, Option<String>> = offered
        .members
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    if offered_seats != seats {
        return Err(roster_change_uncovered(
            "the offered roster is not the standing roster with the decided changes applied",
        ));
    }

    // 4. A strict majority of the STANDING roster cosigned the envelope.
    let standing_ids = standing.member_key_ids();
    let standing_roster: Vec<ThresholdMember> = directory
        .iter()
        .filter(|m| standing_ids.contains(&m.member_id))
        .cloned()
        .collect();
    let bytes = accord_family_signing_bytes(env).map_err(|e| AccordGenesisError::Canonicalize {
        detail: e.to_string(),
    })?;
    match verify_threshold_signatures(
        &bytes,
        &standing_roster,
        quorum_signatures,
        strict_majority(standing_ids.len()),
    ) {
        Ok(_) => {},
        Err(ThresholdError::Insufficient { valid, threshold }) => {
            return Err(AccordGenesisError::QuorumNotMet {
                valid,
                required: threshold,
            });
        },
        Err(e) => {
            return Err(AccordGenesisError::Threshold {
                detail: format!("{e:?}"),
            });
        },
    }

    // 5. One key, one seat over the offered roster.
    let offered_roster = resolve_members(&offered.member_key_ids(), directory)?;
    reject_duplicate_member_keys(&offered_roster)?;

    Ok(offered
        .member_key_ids()
        .into_iter()
        .filter(|k| !standing_ids.contains(k))
        .collect())
}

// ===========================================================================
// Invocations — the operational kill-switch concurrence flow (CEG §9.2.1).
//
// One holder invokes (signs `accord:invoke:*`), ships the object; another holder
// picks it up, confirms it's for a family they're a member of, and CONCURS (adds
// their signature) until the kind's threshold is reached. Since
// CIRISConstitution#146 that threshold is ONE for a `constitutional` halt — the
// invoking holder's own signature fires it, and concurrence adds nothing a
// consumer needs — and a strict majority of the standing roster for
// `lifecycle:active` resumption, the act that leans hard. `humanity_accord` owns the
// `Invocation` type + `verify_invocation`; this is the producer + the
// self-contained CEG object that carries the roster, invocation, and the
// accumulating signatures so a concurring holder has everything in one file.
//
// Two crown-jewel properties (adversarially verified): (a) one key cannot reach
// a multi-holder threshold (resumption) alone — each signature is checked against its OWN roster
// member's pubkey, and the distinct-key gate (`require_distinct_keys`) applies in
// both `accord_invocation_status` and `concur_accord_invocation`; (b) a `drill` /
// `notify` signature cannot be replayed onto a `CONSTITUTIONAL` kill — the
// invocation_kind + nonce are inside `Invocation::canonical_bytes`, so mutating
// the kind drops every signature.
//
// **Boundary (not a hole, but know it):** the roster is EMBEDDED in the object,
// so `accord_invocation_status`'s `quorum_met` is computed against caller-
// supplied pubkeys — a holder controlling N distinct keys CAN make a local object
// read "quorum met". This is **advisory only**; the authoritative 2/3 check is
// CIRISServer recomputing against real `federation_keys` accord-holder pubkeys.
// The CLI labels local quorum as advisory; no automated consumer may treat this
// layer's `quorum_met` as authoritative.
//
// **Cross-impl flag (future §9.2.1 v2):** `Invocation::canonical_bytes` does NOT
// bind `family_key_id` (the CC 4.2.1.1 preimage is intentionally closed +
// stable). Harmless today — HUMANITY_ACCORD is the only accord family — but if a
// second accord family with overlapping holders ever ships, `family_key_id`
// should join the signed preimage (a coordinated CEG §9.2.1 v2 bump) to prevent
// cross-family signature binding.
// ===========================================================================

/// CEG `kind` for an accord invocation object in the outbox.
pub const ACCORD_INVOCATION_KIND: &str = "accord_invocation";

/// Runbook §9 / CEG §9.2.1 — one holder signs an invocation's canonical bytes on
/// their own token (bound hybrid). The first signer *invokes*; later signers
/// *concur* via [`concur_accord_invocation`].
///
/// # Errors
///
/// [`VerifyError`] on a signer fault.
pub async fn co_sign_invocation(
    signer: &dyn SelfSigner,
    invocation: &Invocation,
) -> Result<ThresholdSignature, VerifyError> {
    let (ed_sig_b64, pqc_sig_b64) = signer.sign_bound(&invocation.canonical_bytes()).await?;
    Ok(ThresholdSignature {
        member_id: signer.key_id().to_string(),
        ed25519_signature_base64: ed_sig_b64,
        mldsa65_signature_base64: Some(pqc_sig_b64),
    })
}

/// Package a (partially- or fully-signed) invocation as a self-contained CEG
/// object — the roster (with pubkeys), the invocation, and the signatures so far.
#[must_use]
pub fn build_accord_invocation_object(
    family_key_id: &str,
    roster: &[ThresholdMember],
    invocation: &Invocation,
    signatures: &[ThresholdSignature],
    created_at: &str,
) -> SignedCegObject {
    let body = json!({
        "family_key_id": family_key_id,
        "roster": roster,
        "invocation": invocation,
        "signatures": signatures,
    });
    SignedCegObject::new(ACCORD_INVOCATION_KIND, family_key_id, created_at, body)
}

/// The parsed contents of an [`ACCORD_INVOCATION_KIND`] object.
pub struct ParsedInvocation {
    /// The family the invocation is scoped to.
    pub family_key_id: String,
    /// The embedded roster (with pubkeys).
    pub roster: Vec<ThresholdMember>,
    /// The invocation itself.
    pub invocation: Invocation,
    /// The signatures collected so far.
    pub signatures: Vec<ThresholdSignature>,
}

/// Parse an [`ACCORD_INVOCATION_KIND`] object body.
///
/// # Errors
///
/// [`AccordGenesisError::MalformedEnvelope`] if a field is missing/ill-typed, or
/// [`AccordGenesisError::WrongKind`] if `obj.kind` is not an accord invocation.
pub fn parse_accord_invocation(
    obj: &SignedCegObject,
) -> Result<ParsedInvocation, AccordGenesisError> {
    if obj.kind != ACCORD_INVOCATION_KIND {
        return Err(AccordGenesisError::WrongKind {
            kind: obj.kind.clone(),
        });
    }
    let field = |name: &'static str| {
        obj.body
            .get(name)
            .ok_or(AccordGenesisError::MalformedEnvelope {
                detail: format!("missing `{name}`"),
            })
    };
    let family_key_id = field("family_key_id")?
        .as_str()
        .ok_or(AccordGenesisError::MalformedEnvelope {
            detail: "`family_key_id` not a string".to_string(),
        })?
        .to_string();
    let roster: Vec<ThresholdMember> =
        serde_json::from_value(field("roster")?.clone()).map_err(|e| {
            AccordGenesisError::MalformedEnvelope {
                detail: format!("`roster`: {e}"),
            }
        })?;
    let invocation: Invocation =
        serde_json::from_value(field("invocation")?.clone()).map_err(|e| {
            AccordGenesisError::MalformedEnvelope {
                detail: format!("`invocation`: {e}"),
            }
        })?;
    let signatures: Vec<ThresholdSignature> = serde_json::from_value(field("signatures")?.clone())
        .map_err(|e| AccordGenesisError::MalformedEnvelope {
            detail: format!("`signatures`: {e}"),
        })?;
    Ok(ParsedInvocation {
        family_key_id,
        roster,
        invocation,
        signatures,
    })
}

/// Is `key_id` a member of `roster`?
#[must_use]
pub fn is_roster_member(roster: &[ThresholdMember], key_id: &str) -> bool {
    roster.iter().any(|m| m.member_id == key_id)
}

/// Reject a roster whose members are not distinct keys (the same gate genesis
/// uses — a forged roster could otherwise let one key meet 2/3 alone).
fn require_distinct_keys(roster: &[ThresholdMember]) -> Result<(), AccordGenesisError> {
    let mut seen_ed = alloc::collections::BTreeSet::new();
    let mut seen_pqc = alloc::collections::BTreeSet::new();
    for m in roster {
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
    Ok(())
}

/// Inspection summary of an invocation object — for `accord list` and for a
/// holder deciding whether to concur.
pub struct InvocationStatus {
    /// The family the invocation is scoped to.
    pub family_key_id: String,
    /// Invocation kind wire string (`CONSTITUTIONAL` / `notify` / `drill`).
    pub invocation_kind: String,
    /// The invocation id.
    pub invocation_id: String,
    /// Roster member ids.
    pub roster_member_ids: Vec<String>,
    /// Member ids whose signature over the invocation verifies (distinct).
    pub valid_signers: Vec<String>,
    /// How many distinct valid signers this kind needs for this roster
    /// ([`crate::humanity_accord::InvocationKind::required_signatures`]): 1 for
    /// a `constitutional` halt, a strict majority for `lifecycle:active`.
    pub quorum_threshold: usize,
    /// Whether that many distinct valid signers are present. **Advisory** — see
    /// the boundary note above: the roster here is the object's own.
    pub quorum_met: bool,
}

/// Verify the signatures collected on an invocation object against its embedded
/// roster and report status. Applies the distinct-key gate to the roster.
///
/// # Errors
///
/// [`AccordGenesisError::DuplicateFounderKey`] if the embedded roster is not
/// distinct keys (a forged roster).
pub fn accord_invocation_status(
    parsed: &ParsedInvocation,
) -> Result<InvocationStatus, AccordGenesisError> {
    require_distinct_keys(&parsed.roster)?;
    let bytes = parsed.invocation.canonical_bytes();
    // A signer counts iff its signature verifies against its OWN roster member.
    let mut valid = Vec::new();
    for m in &parsed.roster {
        if let Some(sig) = parsed
            .signatures
            .iter()
            .find(|s| s.member_id == m.member_id)
        {
            if verify_threshold_signatures(
                &bytes,
                core::slice::from_ref(m),
                core::slice::from_ref(sig),
                1,
            ) == Ok(1)
            {
                valid.push(m.member_id.clone());
            }
        }
    }
    let threshold = parsed
        .invocation
        .invocation_kind
        .required_signatures(parsed.roster.len())
        .ok_or_else(|| AccordGenesisError::MalformedEnvelope {
            detail: "invocation roster is empty".to_string(),
        })?;
    let quorum_met = valid.len() >= threshold;
    Ok(InvocationStatus {
        family_key_id: parsed.family_key_id.clone(),
        invocation_kind: parsed.invocation.invocation_kind.as_str().to_string(),
        invocation_id: parsed.invocation.invocation_id.clone(),
        roster_member_ids: parsed.roster.iter().map(|m| m.member_id.clone()).collect(),
        valid_signers: valid,
        quorum_threshold: threshold,
        quorum_met,
    })
}

/// Holder B picks up A's invocation object and **concurs** — adds their own
/// signature, reaching toward the kind's threshold (a strict majority of the
/// standing roster for `lifecycle:active`; a `constitutional` halt needs no
/// concurrence — one signature fires it).
///
/// Fail-closed: the signer must be a roster member **by matching pubkeys** (not
/// just key_id), must not have already signed, the roster must be distinct keys,
/// and every signature already present must verify (no concurring on a tampered
/// object). Returns the updated object for the outbox.
///
/// # Errors
///
/// [`AccordGenesisError`] naming the failing check.
pub async fn concur_accord_invocation(
    obj: &SignedCegObject,
    signer: &dyn SelfSigner,
    created_at: &str,
) -> Result<SignedCegObject, AccordGenesisError> {
    let parsed = parse_accord_invocation(obj)?;
    require_distinct_keys(&parsed.roster)?;

    // The signer must be in the roster, bound by KEY not just key_id.
    let me = founder_member(signer)
        .await
        .map_err(|e| AccordGenesisError::Canonicalize {
            detail: e.to_string(),
        })?;
    match parsed.roster.iter().find(|m| m.member_id == me.member_id) {
        None => {
            return Err(AccordGenesisError::NotARosterMember {
                key_id: me.member_id,
            })
        },
        Some(m) if m.ed25519_public_key_base64 != me.ed25519_public_key_base64 => {
            return Err(AccordGenesisError::RosterIdentityMismatch {
                member_id: me.member_id,
            })
        },
        Some(_) => {},
    }

    // Don't sign twice.
    if parsed
        .signatures
        .iter()
        .any(|s| s.member_id == me.member_id)
    {
        return Err(AccordGenesisError::AlreadySigned {
            member_id: me.member_id,
        });
    }

    // Don't concur on a tampered object: every existing signature must verify.
    let bytes = parsed.invocation.canonical_bytes();
    for s in &parsed.signatures {
        let member = parsed
            .roster
            .iter()
            .find(|m| m.member_id == s.member_id)
            .ok_or(AccordGenesisError::MalformedEnvelope {
                detail: format!("signature from non-roster member {:?}", s.member_id),
            })?;
        if verify_threshold_signatures(
            &bytes,
            core::slice::from_ref(member),
            core::slice::from_ref(s),
            1,
        ) != Ok(1)
        {
            return Err(AccordGenesisError::InvalidExistingSignature {
                member_id: s.member_id.clone(),
            });
        }
    }

    let sig = co_sign_invocation(signer, &parsed.invocation)
        .await
        .map_err(|e| AccordGenesisError::Canonicalize {
            detail: e.to_string(),
        })?;
    let mut signatures = parsed.signatures.clone();
    signatures.push(sig);
    Ok(build_accord_invocation_object(
        &parsed.family_key_id,
        &parsed.roster,
        &parsed.invocation,
        &signatures,
        created_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_at_login::HybridSigningIdentity;

    const TS: &str = "2026-06-19T00:00:00Z";

    fn holders() -> [HybridSigningIdentity; 3] {
        [
            HybridSigningIdentity::generate("A1").unwrap(),
            HybridSigningIdentity::generate("B1").unwrap(),
            HybridSigningIdentity::generate("C1").unwrap(),
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
        let h = HybridSigningIdentity::generate("A1").unwrap();
        let rec = produce_accord_holder_record(&h, TS).await.unwrap();
        assert_eq!(rec.record.identity_type, "accord_holder");
        assert_eq!(rec.record.key_id, "A1");
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
    async fn roster_from_family_selects_members_and_ignores_spares() {
        // #96: the kill-switch roster is the family member set, resolved from a
        // directory that ALSO holds a spare — the spare must NOT become a seat.
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
        let genesis = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS).unwrap();

        // Directory = the 3 family members PLUS a cold-spare row (extra identity).
        let spare = HybridSigningIdentity::generate("A2").unwrap();
        let mut directory = founders.clone();
        directory.push(founder_member(&spare).await.unwrap());

        let roster = accord_roster_from_family(&genesis, &directory).unwrap();
        // Exactly the 3 family members, in family order — the spare is excluded.
        assert_eq!(roster.len(), 3);
        assert_eq!(
            member_ids(&hs),
            roster
                .iter()
                .map(|m| m.member_id.clone())
                .collect::<Vec<_>>()
        );
        assert!(!roster.iter().any(|m| m.member_id == "A2"));
    }

    #[test]
    fn humanity_accord_genesis_is_baked_and_quorum_valid() {
        use crate::threshold::{verify_founder_quorum, ThresholdMember, ThresholdSignature};
        // #107 BAKED from the #118 six-key ceremony (was empty/no-TOFU until the
        // real genesis was in hand). Prove (a) the pinned recognition root parses
        // + is the right kind/key_id/protocol, and (b) its founder quorum
        // CRYPTOGRAPHICALLY verifies — full hybrid Ed25519 + ML-DSA-65, against the
        // ceremony's PUBLISHED holder pubkeys. The bake is validated, not pasted.
        let genesis = humanity_accord_genesis().expect("the genesis must be baked");
        assert_eq!(genesis.kind, ACCORD_FAMILY_GENESIS_KIND);
        assert_eq!(genesis.key_id, "humanity-accord");

        let family = genesis.body.get("family").expect("family");
        assert_eq!(
            family.get("consensus_protocol").and_then(Value::as_str),
            Some("quorum:2/3")
        );
        assert_eq!(
            family
                .get("consensus_protocol_entrenched")
                .and_then(Value::as_bool),
            Some(true)
        );

        // The ceremony's published founder pubkeys (the holders/ records, #118),
        // checked in alongside the genesis so the quorum is independently auditable.
        let founders: Vec<ThresholdMember> =
            serde_json::from_str(include_str!("genesis/founder_pubkeys.json")).unwrap();
        assert!(
            founders
                .iter()
                .all(|m| m.mldsa65_public_key_base64.is_some()),
            "every founder must carry its ML-DSA-65 half (hybrid-required)"
        );
        let sigs: Vec<ThresholdSignature> =
            serde_json::from_value(genesis.body.get("founder_signatures").unwrap().clone())
                .unwrap();

        let bytes = accord_family_signing_bytes(family).unwrap();
        let threshold = quorum_threshold_from_envelope(family).unwrap();
        assert_eq!(threshold, 2, "quorum:2/3 → strict-majority threshold 2");
        let count = verify_founder_quorum(&bytes, &founders, &sigs, threshold)
            .expect("the 2-of-3 hybrid founder quorum MUST verify");
        assert_eq!(
            count, 3,
            "all three founders cosigned (3-of-3, ≥ the 2/3 floor)"
        );
    }

    /// #160: the bootstrap rooting anchor is exactly the 3 seated holders'
    /// Ed25519 keys, cross-checked against the pinned founder directory, and
    /// stays in lockstep with the kill-switch roster (one source of truth).
    #[test]
    fn accord_holder_bootstrap_anchor_is_the_seated_holder_ed25519_keys() {
        // Share the crate env lock: under `--features test-anchor` a sibling test
        // may set CIRIS_TESTING_MODE, which would otherwise swap the baked roster
        // out from under this assertion (#202).
        let _g = crate::test_anchor::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let anchor = accord_holder_bootstrap_anchor();
        assert_eq!(
            anchor.len(),
            3,
            "3 seated holders (A1/B1/C1); spares are not a rooting terminus"
        );

        // Every anchor key is exactly a pinned founder ed25519 key, and vice
        // versa (order-independent set equality).
        let b64 = base64::engine::general_purpose::STANDARD;
        let founders: Vec<ThresholdMember> =
            serde_json::from_str(include_str!("genesis/founder_pubkeys.json")).unwrap();
        let expected: Vec<[u8; 32]> = founders
            .iter()
            .map(|m| {
                <[u8; 32]>::try_from(b64.decode(&m.ed25519_public_key_base64).unwrap()).unwrap()
            })
            .collect();
        assert_eq!(anchor.len(), expected.len());
        for e in &expected {
            assert!(anchor.contains(e), "founder key missing from the anchor");
        }
        // The anchor is the SAME set the accord roster resolves to (lockstep).
        let roster =
            accord_roster_from_family(humanity_accord_genesis().expect("baked"), &founders)
                .expect("roster resolves");
        assert_eq!(
            roster.len(),
            anchor.len(),
            "anchor tracks the seated roster"
        );
    }

    /// #202 acceptance: under `--features test-anchor` with the runtime AND-gate,
    /// `accord_holder_bootstrap_anchor()` returns EXACTLY the software test root
    /// from `CIRIS_TEST_TRUST_ROOT` (replacing the baked roster); with the env
    /// unset it returns the baked 3-holder roster unchanged.
    #[test]
    #[cfg(feature = "test-anchor")]
    fn test_anchor_env_swaps_the_bootstrap_anchor_else_baked() {
        use base64::Engine as _;
        let _g = crate::test_anchor::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let b64 = base64::engine::general_purpose::STANDARD;

        // Snapshot + clear, restore on drop (no leak into siblings).
        let saved: Vec<(&str, Option<String>)> = [
            "CIRIS_TESTING_MODE",
            "CIRIS_TEST_TRUST_ROOT",
            "ENVIRONMENT",
            "CIRIS_ENV",
        ]
        .iter()
        .map(|v| (*v, std::env::var(v).ok()))
        .collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }

        // Env unset ⇒ baked roster (3 seated holders), unchanged.
        assert_eq!(accord_holder_bootstrap_anchor().len(), 3);

        // Env set ⇒ exactly the SW test key(s).
        let sw = [0xABu8; 32];
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var("CIRIS_TEST_TRUST_ROOT", b64.encode(sw));
        assert_eq!(accord_holder_bootstrap_anchor(), vec![sw]);

        // Anti-prod tripwire: a prod signal alongside the flags ⇒ baked, not SW.
        std::env::set_var("ENVIRONMENT", "production");
        assert_eq!(
            accord_holder_bootstrap_anchor().len(),
            3,
            "ENVIRONMENT=production must refuse the SW test root and fall back to baked"
        );

        for (k, v) in &saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        // The rooting half — a chain terminating at a 1-of-N anchor key roots — is
        // proven independently by `provenance::tests::
        // accord_holder_terminus_roots_under_one_of_n_anchor`. This test proves the
        // anchor *becomes* the SW test key; composed, a SW-scrubbed canonical roots.
    }

    #[tokio::test]
    async fn roster_from_family_missing_member_fails_closed() {
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
        let genesis = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS).unwrap();

        // Directory missing one declared family member → fail-closed.
        let partial = founders[..2].to_vec();
        assert!(matches!(
            accord_roster_from_family(&genesis, &partial).unwrap_err(),
            AccordGenesisError::MemberNotInDirectory { .. }
        ));
    }

    #[tokio::test]
    async fn growable_family_of_five_is_three_of_five() {
        // #95/#96: a grown 5-member accord is strict-majority 3/5 — admits at 3,
        // rejects at 2.
        let ids: Vec<HybridSigningIdentity> = (0..5)
            .map(|i| HybridSigningIdentity::generate(format!("M{i}")).unwrap())
            .collect();
        let envelope = build_accord_family_envelope(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            "Humanity Accord",
            &member_ids(&ids),
        );
        assert_eq!(envelope["consensus_protocol"], "quorum:3/5");
        let founders = members_of(&ids).await;

        // 3 of 5 → admits.
        let mut sigs = Vec::new();
        for h in &ids[..3] {
            sigs.push(co_sign_accord_family(h, &envelope).await.unwrap());
        }
        let obj = assemble_accord_family_genesis(&envelope, &founders, &sigs, TS).unwrap();
        assert_eq!(accord_quorum_from_family(&obj).unwrap(), 3);

        // 2 of 5 → rejected (below strict majority).
        let two = sigs[..2].to_vec();
        assert!(matches!(
            assemble_accord_family_genesis(&envelope, &founders, &two, TS).unwrap_err(),
            AccordGenesisError::QuorumNotMet { required: 3, .. }
        ));
    }

    // -- Roster change in CIRISPersist's shape (CC 4.2.6, CC 3.2 T6) -----------

    use crate::accord_live_quorum::{AccordProposal, SeatAdd};

    const T0: &str = "2026-01-01T00:00:00Z";
    const JOINED: &str = "2026-03-14T15:09:26.535897932Z";

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    /// The stored genesis record over `ids`.
    fn standing_record(ids: &[String]) -> FamilyRecord {
        let mut f = FamilyRecord {
            family_key_id: HUMANITY_ACCORD_FAMILY_KEY_ID.to_string(),
            family_name: "Humanity Accord".to_string(),
            members: ids
                .iter()
                .map(|k| FamilyRecordMember {
                    key_id: k.clone(),
                    joined_at: at(T0),
                    role: Some("founder".to_string()),
                })
                .collect(),
            founded_at: at(T0),
            consensus_protocol: ACCORD_CONSENSUS_PROTOCOL.to_string(),
            consensus_protocol_entrenched: true,
            dissolved_at: None,
            prev_head_digest: String::new(),
            charter_digest: "1".repeat(64),
            persist_row_hash: String::new(),
        };
        f.persist_row_hash = f.row_hash().unwrap();
        f
    }

    fn seat_change(remove: &[&str], add: &[&str]) -> SeatChange {
        SeatChange {
            remove: remove.iter().map(|k| (*k).to_string()).collect(),
            add: add
                .iter()
                .map(|k| SeatAdd {
                    key_id: (*k).to_string(),
                    role: Some("founder".to_string()),
                })
                .collect(),
        }
    }

    /// An authorized, closed decision on `standing` binding `change`.
    fn decided(standing: &FamilyRecord, change: &SeatChange) -> AccordDecision {
        AccordDecision {
            proposal: AccordProposal {
                family_key_id: standing.family_key_id.clone(),
                action: AccordAction::RosterChange,
                nonce: "roster-nonce".to_string(),
                window_until: "2026-02-01T00:00:00+00:00".to_string(),
                prior_family_digest: standing.row_hash().unwrap(),
                payload_sha256: seat_change_digest(&standing.family_key_id, change).unwrap(),
            },
            live_set: vec![],
            yes: 2,
            no: 0,
            abstain: 0,
            authorized: true,
        }
    }

    fn draft_for(
        standing: &FamilyRecord,
        change: &SeatChange,
        d: &AccordDecision,
    ) -> RosterChangeDraft {
        build_membership_change(
            standing,
            &[DecidedSeatChange {
                change: change.clone(),
                decision: d.proposal.digest(),
            }],
            "2".repeat(64).as_str(),
            at(JOINED),
        )
        .unwrap()
    }

    async fn cosign(hs: &[&HybridSigningIdentity], env: &Value) -> Vec<ThresholdSignature> {
        let mut v = Vec::new();
        for h in hs {
            v.push(co_sign_accord_family(*h, env).await.unwrap());
        }
        v
    }

    fn verify(
        standing: &FamilyRecord,
        draft: &RosterChangeDraft,
        sigs: &[ThresholdSignature],
        decisions: &[AccordDecision],
        dir: &[ThresholdMember],
    ) -> Result<Vec<String>, AccordGenesisError> {
        verify_membership_change(
            standing,
            &draft.next,
            &draft.change_envelope,
            sigs,
            decisions,
            dir,
            Utc::now(),
        )
    }

    /// Re-point the envelope at the (tampered) offered record.
    fn rebind(draft: &mut RosterChangeDraft) {
        draft.change_envelope["next_persist_row_hash"] = json!(draft.next.row_hash().unwrap());
    }

    #[tokio::test]
    async fn roster_change_is_persists_shape() {
        let hs = holders();
        let standing = standing_record(&member_ids(&hs));
        let change = seat_change(&["A1"], &["A2", "D1"]);
        let d = decided(&standing, &change);
        let draft = draft_for(&standing, &change, &d);
        let ids: Vec<&str> = draft
            .next
            .members
            .iter()
            .map(|m| m.key_id.as_str())
            .collect();
        assert_eq!(
            ids,
            ["B1", "C1", "A2", "D1"],
            "kept in order, adds appended"
        );
        assert_eq!(draft.next.prev_head_digest, standing.row_hash().unwrap());
        assert_eq!(draft.next.charter_digest, "2".repeat(64));
        assert_eq!(draft.next.consensus_protocol, ACCORD_CONSENSUS_PROTOCOL);
        assert_eq!(draft.next.members[2].joined_at, at(JOINED));
        assert_eq!(
            draft.change_envelope,
            json!({
                "kind": ROSTER_CHANGE_KIND,
                "family_key_id": HUMANITY_ACCORD_FAMILY_KEY_ID,
                "prior_persist_row_hash": standing.row_hash().unwrap(),
                "next_persist_row_hash": draft.next.row_hash().unwrap(),
                "changes": [{
                    "remove": ["A1"],
                    "add": [
                        {"key_id": "A2", "role": "founder"},
                        {"key_id": "D1", "role": "founder"},
                    ],
                    "decision": d.proposal.digest(),
                }],
            })
        );
        assert_eq!(
            draft.signing_bytes,
            accord_family_signing_bytes(&draft.change_envelope).unwrap()
        );
        assert_eq!(
            draft.record_bytes,
            draft.next.record_signing_bytes().unwrap()
        );
    }

    #[tokio::test]
    async fn roster_change_carries_on_a_standing_majority() {
        let hs = holders();
        let d1 = HybridSigningIdentity::generate("D1").unwrap();
        let mut dir = members_of(&hs).await;
        dir.push(founder_member(&d1).await.unwrap());
        let standing = standing_record(&member_ids(&hs));
        let change = seat_change(&[], &["D1"]);
        let d = decided(&standing, &change);
        let draft = draft_for(&standing, &change, &d);

        let sigs = cosign(&[&hs[1], &hs[2]], &draft.change_envelope).await;
        assert_eq!(
            verify(&standing, &draft, &sigs, core::slice::from_ref(&d), &dir).unwrap(),
            vec!["D1".to_string()]
        );
        // One standing cosign is short; the incoming holder's does not count.
        let sigs = cosign(&[&hs[0], &d1], &draft.change_envelope).await;
        assert!(matches!(
            verify(&standing, &draft, &sigs, &[d], &dir).unwrap_err(),
            AccordGenesisError::QuorumNotMet {
                valid: 1,
                required: 2
            }
        ));
    }

    #[tokio::test]
    async fn roster_change_swap_and_one_human_two_seats() {
        let hs = holders();
        let a2 = HybridSigningIdentity::generate("A2").unwrap();
        let mut dir = members_of(&hs).await;
        dir.push(founder_member(&a2).await.unwrap());
        let standing = standing_record(&member_ids(&hs));
        let change = seat_change(&["A1"], &["A2"]);
        let d = decided(&standing, &change);
        let draft = draft_for(&standing, &change, &d);
        let sigs = cosign(&[&hs[1], &hs[2]], &draft.change_envelope).await;
        assert_eq!(
            verify(&standing, &draft, &sigs, &[d], &dir).unwrap(),
            vec!["A2".to_string()]
        );

        // "A1-dup" carries A1's exact pubkeys: seating it beside A1 is one key
        // in two seats.
        let mut dup = dir[0].clone();
        dup.member_id = "A1-dup".to_string();
        dir.push(dup);
        let change = seat_change(&[], &["A1-dup"]);
        let d = decided(&standing, &change);
        let draft = draft_for(&standing, &change, &d);
        let sigs = cosign(&[&hs[1], &hs[2]], &draft.change_envelope).await;
        assert!(matches!(
            verify(&standing, &draft, &sigs, &[d], &dir).unwrap_err(),
            AccordGenesisError::DuplicateFounderKey { .. }
        ));
    }

    #[tokio::test]
    async fn roster_change_changes_only_the_seats() {
        let hs = holders();
        let dir = members_of(&hs).await;
        let standing = standing_record(&member_ids(&hs));
        let change = seat_change(&["C1"], &[]);
        let d = decided(&standing, &change);
        let base = draft_for(&standing, &change, &d);
        let tweaks: [fn(&mut FamilyRecord); 3] = [
            |n| n.consensus_protocol_entrenched = false,
            |n| n.consensus_protocol = "quorum:1/2".to_string(),
            |n| n.family_name = "renamed".to_string(),
        ];
        for tweak in tweaks {
            let mut draft = base.clone();
            tweak(&mut draft.next);
            rebind(&mut draft);
            let sigs = cosign(&[&hs[0], &hs[1]], &draft.change_envelope).await;
            assert!(matches!(
                verify(&standing, &draft, &sigs, core::slice::from_ref(&d), &dir).unwrap_err(),
                AccordGenesisError::RosterChangeNotSeats
            ));
        }
        // A seat beyond the decided change.
        let mut draft = base.clone();
        draft.next.members.retain(|m| m.key_id != "B1");
        rebind(&mut draft);
        let sigs = cosign(&[&hs[0], &hs[1]], &draft.change_envelope).await;
        assert!(matches!(
            verify(&standing, &draft, &sigs, core::slice::from_ref(&d), &dir).unwrap_err(),
            AccordGenesisError::RosterChangeUncovered { .. }
        ));
        // Not bound to the standing head, or to the offered version.
        let mut draft = base.clone();
        draft.change_envelope["prior_persist_row_hash"] = json!("0".repeat(64));
        assert!(matches!(
            verify(&standing, &draft, &[], core::slice::from_ref(&d), &dir).unwrap_err(),
            AccordGenesisError::RosterChangeUnbound { .. }
        ));
        let mut draft = base;
        draft.change_envelope["next_persist_row_hash"] = json!("0".repeat(64));
        assert!(matches!(
            verify(&standing, &draft, &[], &[d], &dir).unwrap_err(),
            AccordGenesisError::RosterChangeUnbound { .. }
        ));
    }

    #[tokio::test]
    async fn roster_change_needs_an_authorized_closed_decision_binding_it() {
        let hs = holders();
        let dir = members_of(&hs).await;
        let standing = standing_record(&member_ids(&hs));
        let change = seat_change(&["C1"], &[]);
        let good = decided(&standing, &change);
        let tweaks: [fn(&mut AccordDecision); 4] = [
            |d| d.authorized = false,
            |d| d.proposal.window_until = "2999-01-01T00:00:00Z".to_string(),
            |d| d.proposal.prior_family_digest = "0".repeat(64),
            |d| d.proposal.payload_sha256 = "0".repeat(64),
        ];
        for tweak in tweaks {
            let mut d = good.clone();
            tweak(&mut d);
            let draft = draft_for(&standing, &change, &d);
            let sigs = cosign(&[&hs[0], &hs[1]], &draft.change_envelope).await;
            assert!(matches!(
                verify(&standing, &draft, &sigs, &[d], &dir).unwrap_err(),
                AccordGenesisError::RosterChangeUncovered { .. }
            ));
        }
        // The same decision named twice.
        let mut draft = build_membership_change(
            &standing,
            &[DecidedSeatChange {
                change: change.clone(),
                decision: good.proposal.digest(),
            }],
            "2".repeat(64).as_str(),
            at(JOINED),
        )
        .unwrap();
        let first = draft.change_envelope["changes"][0].clone();
        draft.change_envelope["changes"] = json!([first.clone(), first]);
        assert!(matches!(
            verify(&standing, &draft, &[], &[good], &dir).unwrap_err(),
            AccordGenesisError::RosterChangeUncovered { .. }
        ));
    }

    #[test]
    fn build_refuses_a_change_that_does_not_apply() {
        let ids = vec!["A1".to_string(), "B1".to_string(), "C1".to_string()];
        let standing = standing_record(&ids);
        let decided_change = |c: SeatChange| DecidedSeatChange {
            change: c,
            decision: "d".repeat(64),
        };
        for c in [seat_change(&["Z9"], &[]), seat_change(&[], &["B1"])] {
            assert!(matches!(
                build_membership_change(&standing, &[decided_change(c)], "", at(JOINED)),
                Err(AccordGenesisError::RosterChangeUncovered { .. })
            ));
        }
        assert!(matches!(
            build_membership_change(&standing, &[], "", at(JOINED)),
            Err(AccordGenesisError::RosterChangeUncovered { .. })
        ));
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
                member_id: "B1".to_string()
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

    // -- Invocations: the operational kill-switch concurrence flow -------------

    use crate::humanity_accord::{Invocation, InvocationKind};

    fn drill(id: &str) -> Invocation {
        Invocation {
            invocation_kind: InvocationKind::Drill,
            invocation_id: id.to_string(),
            resumes_halt_id: None,
            confirms_halt_id: None,
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            asserted_at: "2026-06-19T00:00:00.000Z".to_string(),
            valid_until: "2026-06-20T00:00:00.000Z".to_string(),
            payload_sha256: "00".repeat(32),
        }
    }

    // -- CIRISConstitution#146 (entrenched CC 4.2, rc7): one holder fires --------

    fn halt(id: &str) -> Invocation {
        Invocation {
            invocation_kind: InvocationKind::Constitutional,
            invocation_id: id.to_string(),
            resumes_halt_id: None,
            confirms_halt_id: None,
            nonce: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
            // Signed long ago and sealed: a pre-signed halt is valid when
            // published, so nothing here may depend on the present.
            asserted_at: "2020-01-01T00:00:00.000Z".to_string(),
            valid_until: "2099-01-01T00:00:00.000Z".to_string(),
            payload_sha256: "22".repeat(32),
        }
    }

    fn resumption(id: &str, of: &str) -> Invocation {
        Invocation {
            invocation_kind: InvocationKind::LifecycleActive,
            invocation_id: id.to_string(),
            resumes_halt_id: Some(of.to_string()),
            confirms_halt_id: None,
            nonce: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_string(),
            asserted_at: "2026-10-05T00:00:00.000Z".to_string(),
            valid_until: "2026-10-06T00:00:00.000Z".to_string(),
            payload_sha256: "33".repeat(32),
        }
    }

    /// The ruling itself: ONE seated holder's hybrid signature fires a
    /// constitutional halt, through both the verifier and the concurrence
    /// status — and a pre-signed row signed years ago is valid when published.
    #[tokio::test]
    async fn one_holder_fires_a_constitutional_halt() {
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = halt("halt-sealed-2020");
        let sig = co_sign_invocation(&hs[1], &inv).await.unwrap();
        assert_eq!(
            crate::humanity_accord::verify_invocation(&inv, &roster, core::slice::from_ref(&sig))
                .unwrap(),
            1
        );
        let obj = build_accord_invocation_object(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &roster,
            &inv,
            core::slice::from_ref(&sig),
            TS,
        );
        let st = accord_invocation_status(&parse_accord_invocation(&obj).unwrap()).unwrap();
        assert_eq!(st.quorum_threshold, 1);
        assert!(st.quorum_met, "one holder's halt is complete on arrival");
    }

    /// One is the floor, not a bypass: the signature must be a SEATED holder's,
    /// over THIS row, verifying against that holder's pinned key.
    #[tokio::test]
    async fn a_one_signature_halt_still_needs_a_genuine_seated_holder() {
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = halt("halt-1");

        // No signature at all.
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&inv, &roster, &[]),
            Err(crate::humanity_accord::InvocationError::QuorumNotMet {
                valid: 0,
                required: 1
            })
        ));

        // An outsider's key, claiming a seated member's id.
        let outsider = HybridSigningIdentity::generate("A1").unwrap();
        let forged = co_sign_invocation(&outsider, &inv).await.unwrap();
        assert!(crate::humanity_accord::verify_invocation(
            &inv,
            &roster,
            core::slice::from_ref(&forged)
        )
        .is_err());

        // A genuine holder signature over a DIFFERENT row (a drill) does not
        // fire this halt: kind and nonce are inside the signed bytes.
        let drill_sig = co_sign_invocation(&hs[0], &drill("d-1")).await.unwrap();
        assert!(crate::humanity_accord::verify_invocation(
            &inv,
            &roster,
            core::slice::from_ref(&drill_sig)
        )
        .is_err());

        // Tampering with the halt after signing drops the signature.
        let sig = co_sign_invocation(&hs[0], &inv).await.unwrap();
        let mut tampered = inv.clone();
        tampered.payload_sha256 = "44".repeat(32);
        assert!(crate::humanity_accord::verify_invocation(
            &tampered,
            &roster,
            core::slice::from_ref(&sig)
        )
        .is_err());
    }

    /// Un-firing leans hard: one holder can never resume a halt; a strict
    /// majority of the STANDING roster can, and the majority grows with it.
    #[tokio::test]
    async fn resumption_needs_a_strict_majority_of_the_standing_roster() {
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = resumption("resume-1", "halt-1");
        let a = co_sign_invocation(&hs[0], &inv).await.unwrap();
        let b = co_sign_invocation(&hs[1], &inv).await.unwrap();
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&inv, &roster, core::slice::from_ref(&a)),
            Err(crate::humanity_accord::InvocationError::QuorumNotMet {
                valid: 1,
                required: 2
            })
        ));
        assert_eq!(
            crate::humanity_accord::verify_invocation(&inv, &roster, &[a.clone(), b.clone()])
                .unwrap(),
            2
        );

        // A grown five-seat roster: two is no longer a majority.
        let five: Vec<HybridSigningIdentity> = ["A1", "B1", "C1", "D1", "E1"]
            .iter()
            .map(|k| HybridSigningIdentity::generate(*k).unwrap())
            .collect();
        let roster5 = members_of(&five).await;
        let mut sigs = Vec::new();
        for h in &five[..2] {
            sigs.push(co_sign_invocation(h, &inv).await.unwrap());
        }
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&inv, &roster5, &sigs),
            Err(crate::humanity_accord::InvocationError::QuorumNotMet {
                valid: 2,
                required: 3
            })
        ));
        sigs.push(co_sign_invocation(&five[2], &inv).await.unwrap());
        assert_eq!(
            crate::humanity_accord::verify_invocation(&inv, &roster5, &sigs).unwrap(),
            3
        );
    }

    /// CC 4.2.1.1 threshold table: notify and drill take ONE holder, like the
    /// fire they share a path with.
    #[tokio::test]
    async fn notify_and_drill_take_one_holder() {
        let hs = holders();
        let roster = members_of(&hs).await;
        for kind in [InvocationKind::Notify, InvocationKind::Drill] {
            let mut inv = drill("x-1");
            inv.invocation_kind = kind;
            let a = co_sign_invocation(&hs[0], &inv).await.unwrap();
            assert_eq!(
                crate::humanity_accord::verify_invocation(&inv, &roster, core::slice::from_ref(&a))
                    .unwrap(),
                1,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn thresholds_follow_the_bias_gradient() {
        use crate::humanity_accord::InvocationKind as K;
        for n in 1..=9 {
            assert_eq!(
                K::Drill.required_signatures(n),
                Some(1),
                "a drill takes what a fire takes"
            );
            assert_eq!(K::Notify.required_signatures(n), Some(1));
            let fire = K::Constitutional.required_signatures(n).unwrap();
            let resume = K::LifecycleActive.required_signatures(n).unwrap();
            assert_eq!(fire, 1, "n={n}");
            assert_eq!(resume, n / 2 + 1, "n={n}");
            assert_eq!(
                K::LifecycleConfirmed.required_signatures(n),
                Some(n / 2 + 1),
                "n={n}"
            );
            assert!(
                fire <= resume,
                "fire must never be harder than un-firing (n={n})"
            );
        }
        for k in [
            K::Constitutional,
            K::LifecycleActive,
            K::LifecycleConfirmed,
            K::Notify,
            K::Drill,
        ] {
            assert_eq!(
                k.required_signatures(0),
                None,
                "{k:?}: nothing verifies against nobody"
            );
        }
    }

    fn confirmation(id: &str, of: &str) -> Invocation {
        Invocation {
            invocation_kind: InvocationKind::LifecycleConfirmed,
            invocation_id: id.to_string(),
            resumes_halt_id: None,
            confirms_halt_id: Some(of.to_string()),
            nonce: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string(),
            asserted_at: "2026-10-05T01:00:00.000Z".to_string(),
            valid_until: "2026-10-06T00:00:00.000Z".to_string(),
            payload_sha256: "66".repeat(32),
        }
    }

    /// CC 4.2.1.3 (rc7 7923cde): `lifecycle:confirmed` signs the lifecycle
    /// domain with `confirms_halt_id=` where `resumes_halt_id=` would be —
    /// written out literally so a layout change is a red here, not a silent
    /// re-derivation.
    #[test]
    fn confirmation_canonical_bytes_are_the_cc_4_2_1_3_layout() {
        let c = confirmation("confirm-1", "halt-1");
        assert_eq!(
            String::from_utf8(c.canonical_bytes()).unwrap(),
            "ciris.accord_lifecycle.v1\n\
             invocation_kind=lifecycle:confirmed\n\
             invocation_id=confirm-1\n\
             confirms_halt_id=halt-1\n\
             nonce=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n\
             asserted_at=2026-10-05T01:00:00.000Z\n\
             valid_until=2026-10-06T00:00:00.000Z\n\
             payload_sha256=6666666666666666666666666666666666666666666666666666666666666666"
        );
    }

    /// Each lifecycle kind carries exactly its own binding line.
    #[test]
    fn a_confirmation_must_name_its_halt_and_only_that_way() {
        let roster: Vec<ThresholdMember> = Vec::new();
        let mut c = confirmation("c", "halt-1");
        c.confirms_halt_id = None;
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&c, &roster, &[]),
            Err(crate::humanity_accord::InvocationError::MalformedResumption { .. })
        ));
        let mut c = confirmation("c", "halt-1");
        c.resumes_halt_id = Some("halt-1".into());
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&c, &roster, &[]),
            Err(crate::humanity_accord::InvocationError::MalformedResumption { .. })
        ));
        let mut r = resumption("r", "halt-1");
        r.confirms_halt_id = Some("halt-1".into());
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&r, &roster, &[]),
            Err(crate::humanity_accord::InvocationError::MalformedResumption { .. })
        ));
        let mut h = halt("h");
        h.confirms_halt_id = Some("halt-0".into());
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&h, &roster, &[]),
            Err(crate::humanity_accord::InvocationError::MalformedResumption { .. })
        ));
    }

    /// Confirmation is a strict majority; a lone holder (the firer included)
    /// cannot confirm alone, and a resumption signature is not a confirmation.
    #[tokio::test]
    async fn confirmation_needs_a_majority_and_is_not_a_resumption() {
        let hs = holders();
        let roster = members_of(&hs).await;
        let c = confirmation("confirm-1", "halt-1");
        let a = co_sign_invocation(&hs[0], &c).await.unwrap();
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&c, &roster, core::slice::from_ref(&a)),
            Err(crate::humanity_accord::InvocationError::QuorumNotMet {
                valid: 1,
                required: 2
            })
        ));
        let b = co_sign_invocation(&hs[1], &c).await.unwrap();
        assert_eq!(
            crate::humanity_accord::verify_invocation(&c, &roster, &[a, b]).unwrap(),
            2
        );

        // Two genuine signatures over a RESUMPTION of the same halt, presented
        // as a confirmation, verify nothing: the kind line is signed.
        let r = resumption("confirm-1", "halt-1");
        let ra = co_sign_invocation(&hs[0], &r).await.unwrap();
        let rb = co_sign_invocation(&hs[1], &r).await.unwrap();
        assert!(crate::humanity_accord::verify_invocation(&c, &roster, &[ra, rb]).is_err());
    }

    #[tokio::test]
    async fn an_empty_roster_verifies_nothing() {
        let hs = holders();
        let inv = halt("halt-1");
        let sig = co_sign_invocation(&hs[0], &inv).await.unwrap();
        assert!(matches!(
            crate::humanity_accord::verify_invocation(&inv, &[], core::slice::from_ref(&sig)),
            Err(crate::humanity_accord::InvocationError::EmptyRoster)
        ));
    }

    #[tokio::test]
    async fn reactivate_lifecycle_reaches_two_of_three() {
        // #95 Gap 1: the `accord:lifecycle:active` resumption (the server's
        // `reactivate`) rides the SAME 2/3 concurrence flow as any invocation —
        // one holder invokes, another concurs, quorum met.
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = Invocation {
            invocation_kind: InvocationKind::LifecycleActive,
            invocation_id: "resume-2026-06".to_string(),
            resumes_halt_id: Some("halt-2026-05".to_string()),
            confirms_halt_id: None,
            nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            asserted_at: "2026-06-21T00:00:00.000Z".to_string(),
            valid_until: "2026-06-22T00:00:00.000Z".to_string(),
            payload_sha256: "11".repeat(32),
        };
        let sig_a = co_sign_invocation(&hs[0], &inv).await.unwrap();
        let obj = build_accord_invocation_object(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &roster,
            &inv,
            core::slice::from_ref(&sig_a),
            TS,
        );
        let obj2 = concur_accord_invocation(&obj, &hs[1], TS).await.unwrap();
        let parsed = parse_accord_invocation(&obj2).unwrap();
        let st = accord_invocation_status(&parsed).unwrap();
        assert_eq!(st.invocation_kind, "lifecycle:active");
        assert!(st.quorum_met);
        assert_eq!(
            crate::humanity_accord::verify_invocation(
                &parsed.invocation,
                &roster,
                &parsed.signatures
            )
            .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn invocation_concurrence_reaches_two_of_three() {
        // Since CIRISConstitution#146 only resumption is multi-holder — every
        // invoke kind completes on one — so concurrence is exercised on it.
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = resumption("resume-2026-06", "halt-2026-05");
        // Holder A invokes (signs) → object with 1 signature.
        let sig_a = co_sign_invocation(&hs[0], &inv).await.unwrap();
        let obj = build_accord_invocation_object(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &roster,
            &inv,
            core::slice::from_ref(&sig_a),
            TS,
        );
        let st = accord_invocation_status(&parse_accord_invocation(&obj).unwrap()).unwrap();
        assert_eq!(st.valid_signers, vec!["A1"]);
        assert!(!st.quorum_met);

        // Holder B picks it up and concurs → 2 signatures, quorum met.
        let obj2 = concur_accord_invocation(&obj, &hs[1], TS).await.unwrap();
        let parsed = parse_accord_invocation(&obj2).unwrap();
        let st2 = accord_invocation_status(&parsed).unwrap();
        assert_eq!(st2.valid_signers.len(), 2);
        assert!(st2.quorum_met);
        // Cross-check against the canonical humanity_accord verifier.
        assert_eq!(
            crate::humanity_accord::verify_invocation(
                &parsed.invocation,
                &roster,
                &parsed.signatures
            )
            .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn concur_by_non_member_rejected() {
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = drill("d1");
        let sig_a = co_sign_invocation(&hs[0], &inv).await.unwrap();
        let obj = build_accord_invocation_object(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &roster,
            &inv,
            &[sig_a],
            TS,
        );
        let stranger = HybridSigningIdentity::generate("not-a-holder").unwrap();
        let err = concur_accord_invocation(&obj, &stranger, TS)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            AccordGenesisError::NotARosterMember {
                key_id: "not-a-holder".to_string()
            }
        );
    }

    #[tokio::test]
    async fn concur_twice_by_same_holder_rejected() {
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = drill("d1");
        let sig_a = co_sign_invocation(&hs[0], &inv).await.unwrap();
        let obj = build_accord_invocation_object(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &roster,
            &inv,
            &[sig_a],
            TS,
        );
        let err = concur_accord_invocation(&obj, &hs[0], TS)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            AccordGenesisError::AlreadySigned {
                member_id: "A1".to_string()
            }
        );
    }

    #[tokio::test]
    async fn concur_refuses_a_tampered_existing_signature() {
        let hs = holders();
        let roster = members_of(&hs).await;
        let inv = drill("d1");
        let mut sig_a = co_sign_invocation(&hs[0], &inv).await.unwrap();
        // Corrupt A's signature.
        sig_a.ed25519_signature_base64 =
            base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let obj = build_accord_invocation_object(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &roster,
            &inv,
            &[sig_a],
            TS,
        );
        let err = concur_accord_invocation(&obj, &hs[1], TS)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            AccordGenesisError::InvalidExistingSignature {
                member_id: "A1".to_string()
            }
        );
    }

    #[tokio::test]
    async fn concur_refuses_identity_mismatch() {
        // The roster entry for "A1" carries B's pubkeys;
        // A (the real owner of that key_id) tries to concur → mismatch.
        let ha = HybridSigningIdentity::generate("A1").unwrap();
        let hb = HybridSigningIdentity::generate("B1").unwrap();
        let hc = HybridSigningIdentity::generate("C1").unwrap();
        let mut bad_a = founder_member(&hb).await.unwrap();
        bad_a.member_id = "A1".to_string(); // A's id, B's keys
        let roster = vec![
            bad_a,
            founder_member(&hb).await.unwrap(),
            founder_member(&hc).await.unwrap(),
        ];
        let inv = drill("d1");
        // Need a valid existing signature so we reach the identity check; hc signs.
        let sig_c = co_sign_invocation(&hc, &inv).await.unwrap();
        let obj = build_accord_invocation_object(
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &roster,
            &inv,
            &[sig_c],
            TS,
        );
        let err = concur_accord_invocation(&obj, &ha, TS).await.unwrap_err();
        // bad_a shares hb's keys → roster has duplicate keys → caught first.
        assert!(matches!(
            err,
            AccordGenesisError::DuplicateFounderKey { .. }
                | AccordGenesisError::RosterIdentityMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn is_roster_member_checks_key_id() {
        let hs = holders();
        let roster = members_of(&hs).await;
        assert!(is_roster_member(&roster, "A1"));
        assert!(!is_roster_member(&roster, "some-stranger"));
    }
}
