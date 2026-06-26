//! HUMANITY_ACCORD live-quorum objects — Phase 1, step 1 (FSD-004 / CC §4.2.6).
//!
//! The wire objects the live-quorum decimation-recovery rides on:
//! `AccordProposal` (the action + server-issued nonce + window) and
//! `AccordParticipation` (a holder's **proof-of-life bundled with a vote** in
//! ONE signed object — entering the live set `L` and voting are the same act).
//! The tally / membership-change / fire surfaces are step 2.
//!
//! This module exists to satisfy the **CRITICAL** obligations the adversarial
//! review (`FSD/FSD-004_ADVERSARIAL_REVIEW.md`) found in the design's soft
//! underbelly — the participation preimage — *before* any tally code is written:
//!
//! - **C1 (vote-flip / cross-proposal replay):** `AccordParticipation` has an
//!   exact, domain-separated `canonical_bytes`
//!   that binds — INSIDE the signed preimage — the **vote**, the **full proposal
//!   digest** (not a bare nonce), the **member seat**, the **family**, and the
//!   **window**. A relay/server cannot flip a recorded vote or replay a
//!   participation into a different proposal without breaking the signature.
//! - **C3 (anti-replay anchor):** the proposal binds `prior_family_digest` — the
//!   digest of the **standing** family envelope — so a participation is bound to a
//!   decision over a specific standing roster, never the manipulable live set.
//!   (The tally in step 2 keeps the anti-replay anchor on the standing roster.)
//! - **M3 (directory-only resolution):** a participation's signature is verified
//!   against the holder's **pinned** `ThresholdMember` key, and its `member_id`
//!   self-attests its seat in the preimage.
//! - **M5 (`family_key_id` binding):** bound in the preimage, so a participation
//!   is non-transferable across families by construction.
//!
//! Both preimages use the same line-format `domain_prefix ‖ k=v\n…` discipline as
//! `crate::humanity_accord::Invocation`, with **distinct domain prefixes** so a
//! participation signature can never verify as an invoke / lifecycle / proposal
//! signature (the CC §9.2 "wire-isolated AND scope-isolated" property).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// Domain prefix for `AccordProposal` canonical bytes (trailing `\n` included).
pub const PROPOSAL_DOMAIN_PREFIX: &str = "ciris.accord_proposal.v1\n";
/// Domain prefix for `AccordParticipation` canonical bytes (trailing `\n`).
pub const PARTICIPATION_DOMAIN_PREFIX: &str = "ciris.accord_participation.v1\n";

/// The action an `AccordProposal` opens for a live-quorum decision.
///
/// `DECIMATION` is a quorum-computation rule over the existing `CONSTITUTIONAL`
/// kind, not a new invocation verb (FSD-004 §11) — so the *action* is just which
/// of the two decision shapes this proposal seeks. The closed set keeps an
/// unknown action fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccordAction {
    /// A live-quorum `CONSTITUTIONAL` fire (tallied at the floor of 1 in step 2).
    Fire,
    /// A roster grow / shrink / swap (tallied at strict-majority-of-`L` + the
    /// `L_floor` steward backstop in step 2), carried as a family `supersedes`.
    RosterChange,
}

impl AccordAction {
    /// Canonical wire token.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fire => "fire",
            Self::RosterChange => "roster_change",
        }
    }
}

/// A holder's vote, carried INSIDE the signed `AccordParticipation` preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vote {
    /// In favour of the proposed action.
    Yes,
    /// Against the proposed action.
    No,
    /// Present (counts toward `L`) but expresses no preference.
    Abstain,
}

impl Vote {
    /// Canonical wire token — part of the signed bytes (C1).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Abstain => "abstain",
        }
    }
}

/// An accord live-quorum proposal: the action, the **server-issued** freshness
/// nonce, the window upper bound, and the standing-roster anti-replay anchor.
///
/// The proposal's `digest` is what every
/// `AccordParticipation` binds to — so a participation is non-transferable
/// between proposals even if a nonce ever collided (C1/C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccordProposal {
    /// The accord family this decision is for (e.g. `humanity-accord`).
    pub family_key_id: String,
    /// What is being decided.
    pub action: AccordAction,
    /// Server-issued freshness nonce, `base64url(rand_32)`. Verify checks form;
    /// the authoritative server owns issuance + the issued-nonce set (M4).
    pub nonce: String,
    /// §0.5 canonical RFC 3339 — the window upper bound `W`. The authoritative
    /// `L` membership is server-observed arrival within `W`, NOT a holder's
    /// self-asserted `signed_at` (C2); this field pins `W` into the signed bytes.
    pub window_until: String,
    /// Lowercase-hex SHA-256 of the **standing** family envelope this decision
    /// supersedes — the anti-replay anchor (C3). Bound here so two decisions over
    /// the same prior digest are detectable as a fork (the step-2 equivocation
    /// gate, H3).
    pub prior_family_digest: String,
    /// Lowercase-hex SHA-256 of the action payload (the proposed `supersedes` for
    /// a roster change, or the halt payload for a fire). Binds *what* is proposed.
    pub payload_sha256: String,
}

impl AccordProposal {
    /// §4.2.6 canonical bytes — the line-format preimage, domain-separated.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{PROPOSAL_DOMAIN_PREFIX}family_key_id={fk}\naction={action}\nnonce={nonce}\nwindow_until={wu}\nprior_family_digest={pfd}\npayload_sha256={ph}",
            fk = self.family_key_id,
            action = self.action.as_str(),
            nonce = self.nonce,
            wu = self.window_until,
            pfd = self.prior_family_digest,
            ph = self.payload_sha256,
        )
        .into_bytes()
    }

    /// Lowercase-hex SHA-256 of the canonical bytes — the `proposal_digest` every
    /// participation binds to (C1/C3).
    #[must_use]
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.canonical_bytes());
        hex::encode(h.finalize())
    }
}

/// A holder's proof-of-life **bundled with** a vote — entering `L` and voting are
/// one signed act (FSD-004 §4.2 / §6). The signature is a hybrid (Ed25519 +
/// ML-DSA-65) `ThresholdSignature` over `canonical_bytes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccordParticipation {
    /// MUST equal the proposal's `family_key_id` (M5; checked in `verify`).
    pub family_key_id: String,
    /// Lowercase-hex digest of the ONE proposal this participates in (C1/C3).
    pub proposal_digest: String,
    /// The holder's roster seat — self-attested in the preimage (M3).
    pub member_id: String,
    /// The vote, INSIDE the signed bytes (C1) — un-flippable post-signature.
    pub vote: Vote,
    /// The proposal's `window_until`, bound into the signed bytes (C2). The
    /// authoritative `L`-gate is server arrival time; this is the signed copy.
    pub window_until: String,
    /// §0.5 RFC 3339. **Advisory display only** — MUST NOT gate `L` (C2). Bound
    /// in the preimage for completeness/audit, never trusted as the window clock.
    pub signed_at: String,
    /// The holder's hybrid signature over the canonical bytes.
    pub signature: ThresholdSignature,
}

impl AccordParticipation {
    /// CC §4.2.6 canonical bytes — domain-separated, with the **vote**, **proposal
    /// digest**, **member seat**, **family**, and **window** all inside the signed
    /// preimage (C1/C2/M3/M5). `proof_of_life=true` is implicit in a valid
    /// participation existing; it is written explicitly so the preimage reads as
    /// the proof-of-life-plus-vote bundle it is.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{PARTICIPATION_DOMAIN_PREFIX}family_key_id={fk}\nproposal_digest={pd}\nmember_id={mid}\nproof_of_life=true\nvote={vote}\nwindow_until={wu}\nsigned_at={sa}",
            fk = self.family_key_id,
            pd = self.proposal_digest,
            mid = self.member_id,
            vote = self.vote.as_str(),
            wu = self.window_until,
            sa = self.signed_at,
        )
        .into_bytes()
    }

    /// Verify this participation against the proposal it claims and the holder's
    /// **pinned** directory key — fail-closed on every mismatch.
    ///
    /// Checks, in order: the participation binds THIS proposal's digest (C1/C3),
    /// the family matches (M5), the `member_id` is consistent across the object +
    /// the signature + the pinned member (M3), and the holder's **hybrid**
    /// signature verifies over the recomputed canonical bytes (RequireHybrid at
    /// the federation tier). A participation that passes is a valid, vote-bound
    /// member of `L` for `proposal`.
    ///
    /// # Errors
    /// `LiveQuorumError` describing the first failed check.
    pub fn verify(
        &self,
        member: &ThresholdMember,
        proposal: &AccordProposal,
    ) -> Result<(), LiveQuorumError> {
        // C1/C3: bound to exactly this proposal — a participation for a different
        // proposal (or a bare-nonce replay) does not carry this digest.
        let expected = proposal.digest();
        if self.proposal_digest != expected {
            return Err(LiveQuorumError::ProposalMismatch {
                expected,
                got: self.proposal_digest.clone(),
            });
        }
        // M5: same family.
        if self.family_key_id != proposal.family_key_id {
            return Err(LiveQuorumError::FamilyMismatch {
                proposal: proposal.family_key_id.clone(),
                participation: self.family_key_id.clone(),
            });
        }
        // M3: the seat self-attested in the object, in the signature, and in the
        // pinned directory member must all agree.
        if self.member_id != self.signature.member_id || self.member_id != member.member_id {
            return Err(LiveQuorumError::MemberMismatch {
                participation: self.member_id.clone(),
                signature: self.signature.member_id.clone(),
                pinned: member.member_id.clone(),
            });
        }
        // The hybrid signature must verify over the recomputed canonical bytes,
        // against the pinned key, at the federation tier (RequireHybrid default).
        let canonical = self.canonical_bytes();
        verify_threshold_signatures(
            &canonical,
            std::slice::from_ref(member),
            std::slice::from_ref(&self.signature),
            1,
        )
        .map_err(|e| LiveQuorumError::Signature(format!("{e:?}")))?;
        Ok(())
    }
}

/// Why a live-quorum object failed verification — fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveQuorumError {
    /// The participation's `proposal_digest` does not match the proposal it was
    /// verified against (C1/C3 — cross-proposal replay / vote for a different
    /// proposal).
    ProposalMismatch {
        /// The digest of the proposal being verified against.
        expected: String,
        /// The digest the participation carried.
        got: String,
    },
    /// `family_key_id` mismatch between participation and proposal (M5).
    FamilyMismatch {
        /// The proposal's family.
        proposal: String,
        /// The participation's family.
        participation: String,
    },
    /// The seat is inconsistent across the object / signature / pinned member (M3).
    MemberMismatch {
        /// `member_id` on the participation object.
        participation: String,
        /// `member_id` on the signature.
        signature: String,
        /// `member_id` of the pinned directory member.
        pinned: String,
    },
    /// A participation names a member that is NOT in the pinned standing roster
    /// (C3 — `L ⊆ standing roster`; only real, key-holding members count).
    NotInStandingRoster {
        /// The unrecognized `member_id`.
        member_id: String,
    },
    /// The same member appears twice in one tally — a member counts once (M3).
    DuplicateParticipant {
        /// The duplicated `member_id`.
        member_id: String,
    },
    /// The proposal's action is not the one this verifier handles (fire vs.
    /// roster-change).
    WrongAction {
        /// The action this verifier expects.
        expected: &'static str,
        /// The action the proposal actually carries.
        got: &'static str,
    },
    /// The proposed roster-change envelope failed a structural invariant
    /// (distinct/strict-majority/entrenchment/anti-replay anchor) — wraps the
    /// `accord_genesis` validator's reason (C3).
    Structure(String),
    /// `proposal.payload_sha256` does not equal the digest of the proposed new
    /// family envelope (the proposal doesn't bind *what* is being installed).
    PayloadMismatch {
        /// Digest of the proposed new envelope.
        expected: String,
        /// `payload_sha256` the proposal carried.
        got: String,
    },
    /// `proposal.prior_family_digest` does not equal the digest of the standing
    /// family envelope (the C3 anti-replay anchor is not bound to this prior state).
    AnchorMismatch {
        /// Digest of the standing (prior) envelope.
        expected: String,
        /// `prior_family_digest` the proposal carried.
        got: String,
    },
    /// The proposed roster has fewer than 2 members — a `1/1` rebuild is a single
    /// point of compromise and is rejected (H5, `N_min > 1`).
    RosterTooSmall {
        /// The proposed roster size.
        size: usize,
    },
    /// A standing member was removed by the change but did NOT prove life (∉ `L`)
    /// — removal-under-cover-of-absence is forbidden (H5): a censored member can't
    /// be dropped by the live quorum.
    RemovedAbsentMember {
        /// The `member_id` that would be removed without consenting/participating.
        member_id: String,
    },
    /// The hybrid signature did not verify over the recomputed canonical bytes.
    Signature(String),
}

impl std::fmt::Display for LiveQuorumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProposalMismatch { expected, got } => write!(
                f,
                "participation binds proposal {got} but was verified against {expected} (C1/C3)"
            ),
            Self::FamilyMismatch {
                proposal,
                participation,
            } => write!(
                f,
                "family mismatch: proposal {proposal} vs participation {participation} (M5)"
            ),
            Self::MemberMismatch {
                participation,
                signature,
                pinned,
            } => write!(
                f,
                "member_id mismatch: object {participation} / sig {signature} / pinned {pinned} (M3)"
            ),
            Self::NotInStandingRoster { member_id } => write!(
                f,
                "participant {member_id} is not in the pinned standing roster (C3)"
            ),
            Self::DuplicateParticipant { member_id } => {
                write!(f, "member {member_id} participated twice in one tally (M3)")
            },
            Self::WrongAction { expected, got } => {
                write!(f, "wrong proposal action: expected {expected}, got {got}")
            },
            Self::Structure(e) => write!(f, "roster-change structure invalid: {e}"),
            Self::PayloadMismatch { expected, got } => write!(
                f,
                "proposal payload_sha256 {got} != proposed new-envelope digest {expected}"
            ),
            Self::AnchorMismatch { expected, got } => write!(
                f,
                "proposal prior_family_digest {got} != standing envelope digest {expected} (C3)"
            ),
            Self::RosterTooSmall { size } => {
                write!(f, "proposed roster has {size} members; N_min is 2 (H5)")
            },
            Self::RemovedAbsentMember { member_id } => write!(
                f,
                "standing member {member_id} removed without proving life ∉ L (H5)"
            ),
            Self::Signature(e) => write!(f, "participation signature invalid: {e}"),
        }
    }
}

impl std::error::Error for LiveQuorumError {}

/// The result of tallying participations over the live set — the frozen `L` (M2)
/// plus the vote breakdown. `live_set` is the distinct set of members who proved
/// life, each verified against the **standing** roster (C3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveQuorumTally {
    /// `member_id`s who proved life within the window — distinct, each a verified
    /// standing-roster member. This is the live set `L`.
    pub live_set: Vec<String>,
    /// `yes` votes within `L`.
    pub yes: usize,
    /// `no` votes within `L`.
    pub no: usize,
    /// `abstain` votes within `L` (present, no preference).
    pub abstain: usize,
}

impl LiveQuorumTally {
    /// `|L|` — the size of the live set.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live_set.len()
    }
}

/// Tally `participations` against `proposal` over the **standing** roster.
///
/// Each participation is cryptographically verified ([`AccordParticipation::verify`]
/// — sig + proposal-digest binding + family), and its signer is resolved **only**
/// against `standing_roster` (C3/M3: `L ⊆ standing roster`, never a bundle-embedded
/// roster). `L` is deduped by member (a member counts once). **Fail-closed:** any
/// participation that fails verification, names a non-standing member, or duplicates
/// a member rejects the whole tally.
///
/// **Window boundary (C2):** the authoritative-server window gate — `L` membership
/// by **server-observed arrival within `W`** — is the *caller's* responsibility.
/// This function is the cryptographic + roster-membership core; CIRISServer filters
/// participations by arrival time before calling it. `signed_at` is never trusted
/// as the clock.
///
/// # Errors
/// [`LiveQuorumError`] on the first failed participation.
pub fn tally_live_quorum(
    proposal: &AccordProposal,
    participations: &[AccordParticipation],
    standing_roster: &[ThresholdMember],
) -> Result<LiveQuorumTally, LiveQuorumError> {
    let mut live_set: Vec<String> = Vec::with_capacity(participations.len());
    let (mut yes, mut no, mut abstain) = (0usize, 0usize, 0usize);
    for p in participations {
        // C3/M3: resolve the signer ONLY in the pinned standing roster.
        let member = standing_roster
            .iter()
            .find(|m| m.member_id == p.member_id)
            .ok_or_else(|| LiveQuorumError::NotInStandingRoster {
                member_id: p.member_id.clone(),
            })?;
        p.verify(member, proposal)?;
        // M3: a member counts once.
        if live_set.iter().any(|id| id == &p.member_id) {
            return Err(LiveQuorumError::DuplicateParticipant {
                member_id: p.member_id.clone(),
            });
        }
        live_set.push(p.member_id.clone());
        match p.vote {
            Vote::Yes => yes += 1,
            Vote::No => no += 1,
            Vote::Abstain => abstain += 1,
        }
    }
    Ok(LiveQuorumTally {
        live_set,
        yes,
        no,
        abstain,
    })
}

/// The verdict of a live-quorum FIRE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FireVerdict {
    /// Whether the kill-switch fired.
    pub fired: bool,
    /// The frozen tally the verdict was computed over.
    pub tally: LiveQuorumTally,
}

/// Whether a live-quorum `CONSTITUTIONAL` FIRE is authorized.
///
/// **M1 — the fire floor is pinned to 1:** a SINGLE `yes` participation in `L`
/// fires. Firing leans easiest because a missed fire is terminal; the floor is
/// **never** `strict_majority(|L|)` (which would let an adversary inflate `|L|`
/// with captured keys to raise the fire bar — a suppression lever). The
/// `fire ≤ roster-change ≤ standing` bias gradient (CC §4.2.1.3) starts here.
///
/// # Errors
/// [`LiveQuorumError::WrongAction`] if `proposal.action` isn't [`AccordAction::Fire`];
/// any [`tally_live_quorum`] error.
pub fn verify_fire_by_live_quorum(
    proposal: &AccordProposal,
    participations: &[AccordParticipation],
    standing_roster: &[ThresholdMember],
) -> Result<FireVerdict, LiveQuorumError> {
    if proposal.action != AccordAction::Fire {
        return Err(LiveQuorumError::WrongAction {
            expected: "fire",
            got: proposal.action.as_str(),
        });
    }
    let tally = tally_live_quorum(proposal, participations, standing_roster)?;
    // Floor of 1: any single `yes` fires.
    Ok(FireVerdict {
        fired: tally.yes >= 1,
        tally,
    })
}

/// The `L_floor` below which a roster change additionally requires the steward
/// backstop (CC §4.2.6 / FSD-004 Q4). At `|L| < 3` a lone or pair of (possibly
/// coerced) survivors must not be able to rebuild the roster unaided.
pub const L_FLOOR: usize = 3;

/// The verdict of a live-quorum roster change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterChangeVerdict {
    /// Whether the change is authorized (strict-majority-of-`L` yes votes, plus
    /// the steward backstop when it was required).
    pub authorized: bool,
    /// The frozen tally over `L`.
    pub tally: LiveQuorumTally,
    /// Whether `|L| < L_FLOOR` forced the steward 2-of-3 backstop (H6).
    pub used_steward_backstop: bool,
}

/// Verify a live-quorum **roster change** (grow / shrink / swap) — the
/// decimation-recovery rebuild (FSD-004 / CC §4.2.6).
///
/// Authorization is the live set `L`'s strict majority, but **every other
/// invariant is anchored to the standing roster, never `L`** (C3). Checks:
/// 1. the proposal is a [`AccordAction::RosterChange`];
/// 2. **structure** ([`crate::accord_genesis::validate_membership_change_structure`]):
///    distinct + strict-majority new roster, distinct pubkeys, entrenchment +
///    `family_key_id` preserved, and `supersedes.prior_member_key_ids ==` the
///    **standing** roster (the C3 anti-replay anchor);
/// 3. the proposal binds the change — `payload_sha256 ==` the new envelope digest
///    and `prior_family_digest ==` the standing envelope digest (C3);
/// 4. the tally over `L` (signers resolved only in the standing roster, M3);
/// 5. **`N_min`** — the new roster has ≥ 2 members (no `1/1` rebuild, H5);
/// 6. **removal-continuity** — any standing member *removed* by the change MUST
///    have proved life (`∈ L`); a censored/absent member can't be dropped (H5);
/// 7. **authorization** — `yes ≥ strict_majority(|L|)`, AND when `|L| < L_FLOOR`
///    the **steward 2-of-3 backstop** over the proposal (a key-independent trust
///    domain, H6) computed on the **server-recomputed** `|L|`.
///
/// Steps 1-6 fail-closed with an error (the change is malformed/illegal); step 7
/// is reported as [`RosterChangeVerdict::authorized`] (a valid tally that did or
/// didn't reach the bar).
///
/// # Errors
/// [`LiveQuorumError`] for a wrong action, a structural/binding violation, an
/// undersized roster, or removal of an absent member.
#[allow(clippy::too_many_arguments)]
pub fn verify_membership_change_by_live_quorum(
    proposal: &AccordProposal,
    participations: &[AccordParticipation],
    prior_envelope: &serde_json::Value,
    new_envelope: &serde_json::Value,
    standing_roster: &[ThresholdMember],
    steward_members: &[ThresholdMember],
    steward_signatures: &[ThresholdSignature],
) -> Result<RosterChangeVerdict, LiveQuorumError> {
    // 1. Action.
    if proposal.action != AccordAction::RosterChange {
        return Err(LiveQuorumError::WrongAction {
            expected: "roster_change",
            got: proposal.action.as_str(),
        });
    }

    // 2. Structure (C3 anchor on the standing roster, entrenchment, distinct, etc.)
    crate::accord_genesis::validate_membership_change_structure(
        prior_envelope,
        new_envelope,
        standing_roster,
    )
    .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;

    // 3. The proposal binds the proposed change + the standing prior state (C3).
    let envelope_digest = |env: &serde_json::Value| -> Result<String, LiveQuorumError> {
        let bytes = crate::accord_genesis::accord_family_signing_bytes(env)
            .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
        let mut h = Sha256::new();
        h.update(&bytes);
        Ok(hex::encode(h.finalize()))
    };
    let new_digest = envelope_digest(new_envelope)?;
    if proposal.payload_sha256 != new_digest {
        return Err(LiveQuorumError::PayloadMismatch {
            expected: new_digest,
            got: proposal.payload_sha256.clone(),
        });
    }
    let prior_digest = envelope_digest(prior_envelope)?;
    if proposal.prior_family_digest != prior_digest {
        return Err(LiveQuorumError::AnchorMismatch {
            expected: prior_digest,
            got: proposal.prior_family_digest.clone(),
        });
    }

    // 4. Tally over L (anchored to the standing roster, M3/C3).
    let tally = tally_live_quorum(proposal, participations, standing_roster)?;

    // 5. N_min (H5): no 1/1 rebuild.
    let new_ids = crate::accord_genesis::envelope_member_key_ids(new_envelope)
        .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
    if new_ids.len() < 2 {
        return Err(LiveQuorumError::RosterTooSmall {
            size: new_ids.len(),
        });
    }

    // 6. Removal-continuity (H5): a removed standing member must have proved life.
    let prior_ids = crate::accord_genesis::envelope_member_key_ids(prior_envelope)
        .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
    for removed in prior_ids.iter().filter(|id| !new_ids.contains(id)) {
        if !tally.live_set.iter().any(|id| id == removed) {
            return Err(LiveQuorumError::RemovedAbsentMember {
                member_id: removed.clone(),
            });
        }
    }

    // 7. Authorization: strict-majority-of-L + the L_floor steward backstop (H6).
    let majority_met = tally.yes >= crate::accord_genesis::strict_majority(tally.live_count());
    let used_steward_backstop = tally.live_count() < L_FLOOR;
    let steward_ok = if used_steward_backstop {
        // 2-of-3 (strict majority) of an INDEPENDENT steward set, over the proposal
        // bytes (which transitively bind the new roster via payload_sha256). The
        // |L| trigger is the SERVER-recomputed tally, never a claimed value.
        let steward_threshold =
            crate::accord_genesis::strict_majority(steward_members.len().max(1));
        verify_threshold_signatures(
            &proposal.canonical_bytes(),
            steward_members,
            steward_signatures,
            steward_threshold,
        )
        .is_ok()
    } else {
        true
    };

    Ok(RosterChangeVerdict {
        authorized: majority_met && steward_ok,
        tally,
        used_steward_backstop,
    })
}

/// The frozen, server-attested outcome of a live-quorum decision (M2).
///
/// Once a window closes, `L` is **final**: it carries the immutable live-set
/// snapshot + tally for `proposal`. A later proof-of-life is only ever admissible
/// against a *new* proposal nonce — it never re-opens a closed window
/// (Enoch-Arden: re-enrollment is *going-forward* only, never a retroactive
/// recompute of a decided denominator). The authoritative server emits and
/// append-only-logs this; consumers treat the snapshot as immutable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccordDecision {
    /// The proposal this decides (binds the action, nonce, window, the standing
    /// `prior_family_digest`, and `payload_sha256`).
    pub proposal: AccordProposal,
    /// The frozen live set `L` — the `member_id`s who proved life within `W`.
    pub live_set: Vec<String>,
    /// `yes` / `no` / `abstain` over `L`.
    pub yes: usize,
    /// See [`Self::yes`].
    pub no: usize,
    /// See [`Self::yes`].
    pub abstain: usize,
    /// The verdict (fired, or roster-change authorized).
    pub authorized: bool,
}

impl AccordDecision {
    /// Assemble a decision from a proposal + its frozen tally + the verdict.
    #[must_use]
    pub fn new(proposal: AccordProposal, tally: &LiveQuorumTally, authorized: bool) -> Self {
        Self {
            proposal,
            live_set: tally.live_set.clone(),
            yes: tally.yes,
            no: tally.no,
            abstain: tally.abstain,
            authorized,
        }
    }
}

/// Whether two decisions **equivocate** — the H3 split-brain fork.
///
/// Two roster-change decisions equivocate iff they supersede the **same standing
/// roster** (same `family_key_id` + `prior_family_digest`) into **different new
/// rosters** (`payload_sha256` differs). Under partition each may be locally
/// "authorized" by a different live set, but installing two different rosters off
/// one prior state is a fork: the authoritative server MUST treat a detected
/// equivocation as a **hard fail-closed conflict**, admitting neither pending the
/// steward reconciliation, rather than last-writer-wins.
///
/// (A re-proposal of the *same* outcome — identical `payload_sha256` — is not an
/// equivocation; that's the H4 coalescing case, handled server-side.)
#[must_use]
pub fn decisions_equivocate(a: &AccordDecision, b: &AccordDecision) -> bool {
    a.proposal.action == AccordAction::RosterChange
        && b.proposal.action == AccordAction::RosterChange
        && a.proposal.family_key_id == b.proposal.family_key_id
        && a.proposal.prior_family_digest == b.proposal.prior_family_digest
        && a.proposal.payload_sha256 != b.proposal.payload_sha256
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    /// A holder with hybrid keys (mirrors the `threshold` test `Party`).
    struct Holder {
        member_id: String,
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Holder {
        fn new(id: &str) -> Self {
            Self {
                member_id: id.to_string(),
                ed: Ed25519Signer::random().unwrap(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }
        fn member(&self) -> ThresholdMember {
            ThresholdMember {
                member_id: self.member_id.clone(),
                ed25519_public_key_base64: B64.encode(self.ed.public_key().unwrap()),
                mldsa65_public_key_base64: Some(B64.encode(self.mldsa.public_key().unwrap())),
                role: None,
            }
        }
        fn sign(&self, bytes: &[u8]) -> ThresholdSignature {
            let ed_sig = self.ed.sign(bytes).unwrap();
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&ed_sig);
            ThresholdSignature {
                member_id: self.member_id.clone(),
                ed25519_signature_base64: B64.encode(&ed_sig),
                mldsa65_signature_base64: Some(B64.encode(self.mldsa.sign(&bound).unwrap())),
            }
        }
    }

    fn sample_proposal() -> AccordProposal {
        AccordProposal {
            family_key_id: "humanity-accord".to_string(),
            action: AccordAction::RosterChange,
            nonce: "AAAAbase64url-nonce-XXXXXXXXXXXXXXXXXXXX".to_string(),
            window_until: "2026-06-29T00:00:00.000Z".to_string(),
            prior_family_digest: "a".repeat(64),
            payload_sha256: "b".repeat(64),
        }
    }

    /// Build a holder's valid, signed participation in `proposal`.
    fn participate(h: &Holder, proposal: &AccordProposal, vote: Vote) -> AccordParticipation {
        let mut p = AccordParticipation {
            family_key_id: proposal.family_key_id.clone(),
            proposal_digest: proposal.digest(),
            member_id: h.member_id.clone(),
            vote,
            window_until: proposal.window_until.clone(),
            signed_at: "2026-06-26T12:00:00.000Z".to_string(),
            // placeholder; replaced below once we can sign the canonical bytes.
            signature: ThresholdSignature {
                member_id: h.member_id.clone(),
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        p.signature = h.sign(&p.canonical_bytes());
        p
    }

    #[test]
    fn proposal_digest_is_stable_and_field_sensitive() {
        let p = sample_proposal();
        assert_eq!(p.digest(), p.clone().digest(), "deterministic");
        let mut p2 = p.clone();
        p2.nonce = "different-nonce".to_string();
        assert_ne!(p.digest(), p2.digest(), "nonce change → different digest");
        let mut p3 = p.clone();
        p3.action = AccordAction::Fire;
        assert_ne!(p.digest(), p3.digest(), "action change → different digest");
        let mut p4 = p.clone();
        p4.prior_family_digest = "c".repeat(64);
        assert_ne!(p.digest(), p4.digest(), "anchor change → different digest");
    }

    #[test]
    fn participation_preimage_binds_the_vote() {
        // C1: changing the vote MUST change the signed bytes.
        let prop = sample_proposal();
        let base = AccordParticipation {
            family_key_id: prop.family_key_id.clone(),
            proposal_digest: prop.digest(),
            member_id: "A1".to_string(),
            vote: Vote::Yes,
            window_until: prop.window_until.clone(),
            signed_at: "2026-06-26T12:00:00.000Z".to_string(),
            signature: ThresholdSignature {
                member_id: "A1".to_string(),
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        let mut no = base.clone();
        no.vote = Vote::No;
        assert_ne!(base.canonical_bytes(), no.canonical_bytes());
        // and the vote is actually present in the bytes
        let s = String::from_utf8(base.canonical_bytes()).unwrap();
        assert!(s.contains("\nvote=yes\n"));
        assert!(s.starts_with("ciris.accord_participation.v1\n"));
    }

    #[test]
    fn participation_scope_is_isolated_from_proposal_and_invoke() {
        // Distinct domain prefixes ⇒ a participation signature can't verify as a
        // proposal/invoke/lifecycle signature even with identical content.
        let prop = sample_proposal();
        let part = AccordParticipation {
            family_key_id: prop.family_key_id.clone(),
            proposal_digest: prop.digest(),
            member_id: "A1".to_string(),
            vote: Vote::Yes,
            window_until: prop.window_until.clone(),
            signed_at: "2026-06-26T12:00:00.000Z".to_string(),
            signature: ThresholdSignature {
                member_id: "A1".to_string(),
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        assert!(part
            .canonical_bytes()
            .starts_with(b"ciris.accord_participation.v1\n"));
        assert!(prop
            .canonical_bytes()
            .starts_with(b"ciris.accord_proposal.v1\n"));
        assert_ne!(part.canonical_bytes(), prop.canonical_bytes());
    }

    #[test]
    fn valid_participation_verifies() {
        let h = Holder::new("A1");
        let prop = sample_proposal();
        let part = participate(&h, &prop, Vote::Yes);
        assert_eq!(part.verify(&h.member(), &prop), Ok(()));
    }

    #[test]
    fn cross_proposal_replay_is_rejected() {
        // C1/C3: a participation signed for proposal A must not verify against B.
        let h = Holder::new("A1");
        let prop_a = sample_proposal();
        let mut prop_b = sample_proposal();
        prop_b.nonce = "a-totally-different-nonce".to_string();
        assert_ne!(prop_a.digest(), prop_b.digest());

        let part_for_a = participate(&h, &prop_a, Vote::Yes);
        assert!(matches!(
            part_for_a.verify(&h.member(), &prop_b),
            Err(LiveQuorumError::ProposalMismatch { .. })
        ));
    }

    #[test]
    fn flipped_vote_breaks_the_signature() {
        // C1: take a valid yes-participation, flip the recorded vote to no without
        // re-signing — the recomputed bytes no longer match the signature.
        let h = Holder::new("A1");
        let prop = sample_proposal();
        let mut part = participate(&h, &prop, Vote::Yes);
        part.vote = Vote::No; // tamper, keep the old signature
        assert!(matches!(
            part.verify(&h.member(), &prop),
            Err(LiveQuorumError::Signature(_))
        ));
    }

    #[test]
    fn signature_from_a_different_holder_is_rejected() {
        // M3: a participation claiming A1 but signed by B's key fails.
        let a = Holder::new("A1");
        let b = Holder::new("A1"); // same claimed id, different keys
        let prop = sample_proposal();
        let part = participate(&b, &prop, Vote::Yes);
        // verify against A1's pinned (real) directory key → signature mismatch
        assert!(matches!(
            part.verify(&a.member(), &prop),
            Err(LiveQuorumError::Signature(_))
        ));
    }

    #[test]
    fn classical_only_participation_is_rejected_at_federation_tier() {
        // The accord is a federation-tier gate (RequireHybrid): a participation
        // with no ML-DSA half does not count.
        let h = Holder::new("A1");
        let prop = sample_proposal();
        let mut part = participate(&h, &prop, Vote::Yes);
        part.signature.mldsa65_signature_base64 = None; // strip the PQC half
        assert!(matches!(
            part.verify(&h.member(), &prop),
            Err(LiveQuorumError::Signature(_))
        ));
    }

    fn fire_proposal() -> AccordProposal {
        let mut p = sample_proposal();
        p.action = AccordAction::Fire;
        p
    }

    #[test]
    fn tally_builds_live_set_and_counts_votes() {
        let prop = sample_proposal();
        let hs: Vec<Holder> = ["A1", "B1", "C1"]
            .iter()
            .map(|id| Holder::new(id))
            .collect();
        let roster: Vec<ThresholdMember> = hs.iter().map(Holder::member).collect();
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::Yes),
            participate(&hs[2], &prop, Vote::No),
        ];
        let t = tally_live_quorum(&prop, &parts, &roster).unwrap();
        assert_eq!(t.live_count(), 3);
        assert_eq!((t.yes, t.no, t.abstain), (2, 1, 0));
    }

    #[test]
    fn tally_rejects_a_non_standing_participant() {
        // C3: only members of the pinned standing roster count.
        let prop = sample_proposal();
        let a = Holder::new("A1");
        let intruder = Holder::new("X9"); // not in the roster
        let roster = vec![a.member()];
        let parts = vec![
            participate(&a, &prop, Vote::Yes),
            participate(&intruder, &prop, Vote::Yes),
        ];
        assert!(matches!(
            tally_live_quorum(&prop, &parts, &roster),
            Err(LiveQuorumError::NotInStandingRoster { .. })
        ));
    }

    #[test]
    fn tally_rejects_a_duplicate_participant() {
        // M3: a member counts once.
        let prop = sample_proposal();
        let a = Holder::new("A1");
        let roster = vec![a.member()];
        let parts = vec![
            participate(&a, &prop, Vote::Yes),
            participate(&a, &prop, Vote::No), // same member twice
        ];
        assert!(matches!(
            tally_live_quorum(&prop, &parts, &roster),
            Err(LiveQuorumError::DuplicateParticipant { .. })
        ));
    }

    #[test]
    fn fire_floor_is_one_even_with_a_large_live_set() {
        // M1: a SINGLE yes fires, regardless of |L| — the floor is never
        // strict-majority-of-L. A big live set that mostly votes no but with one
        // yes still fires (a missed fire is terminal; firing leans easiest).
        let prop = fire_proposal();
        let hs: Vec<Holder> = (0..7).map(|i| Holder::new(&format!("H{i}"))).collect();
        let roster: Vec<ThresholdMember> = hs.iter().map(Holder::member).collect();
        let mut parts: Vec<AccordParticipation> =
            hs.iter().map(|h| participate(h, &prop, Vote::No)).collect();
        // flip exactly one to yes
        parts[3] = participate(&hs[3], &prop, Vote::Yes);
        let v = verify_fire_by_live_quorum(&prop, &parts, &roster).unwrap();
        assert!(v.fired, "one yes fires even with 6 no in L");
        assert_eq!(v.tally.yes, 1);
    }

    #[test]
    fn fire_does_not_fire_without_a_yes() {
        let prop = fire_proposal();
        let a = Holder::new("A1");
        let roster = vec![a.member()];
        let parts = vec![participate(&a, &prop, Vote::Abstain)];
        let v = verify_fire_by_live_quorum(&prop, &parts, &roster).unwrap();
        assert!(!v.fired, "presence without a yes does not fire");
    }

    #[test]
    fn fire_verifier_rejects_a_roster_change_proposal() {
        let prop = sample_proposal(); // RosterChange
        let a = Holder::new("A1");
        let roster = vec![a.member()];
        let parts = vec![participate(&a, &prop, Vote::Yes)];
        assert!(matches!(
            verify_fire_by_live_quorum(&prop, &parts, &roster),
            Err(LiveQuorumError::WrongAction {
                expected: "fire",
                ..
            })
        ));
    }

    // --- roster-change (step 3) ---------------------------------------------

    use crate::accord_genesis::{accord_family_signing_bytes, build_membership_change};
    use crate::threshold::Role;
    use serde_json::{json, Value};

    /// A standing (prior) accord family envelope over `ids`, entrenched.
    fn family_envelope(ids: &[&str]) -> Value {
        let members: Vec<Value> = ids
            .iter()
            .map(|k| json!({ "key_id": k, "role": "founder" }))
            .collect();
        json!({
            "family_key_id": "humanity-accord",
            "family_name": "HUMANITY_ACCORD",
            "members": members,
            "consensus_protocol": format!("quorum:{}/{}", crate::accord_genesis::strict_majority(ids.len()), ids.len()),
            "consensus_protocol_entrenched": true,
        })
    }

    fn env_digest(env: &Value) -> String {
        let bytes = accord_family_signing_bytes(env).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    }

    fn roster_proposal(prior: &Value, new: &Value) -> AccordProposal {
        AccordProposal {
            family_key_id: "humanity-accord".to_string(),
            action: AccordAction::RosterChange,
            nonce: "roster-nonce-XXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            window_until: "2026-06-29T00:00:00.000Z".to_string(),
            prior_family_digest: env_digest(prior),
            payload_sha256: env_digest(new),
        }
    }

    /// Holders A1,B1,C1 (standing) + D1 (candidate) + the directory over all four.
    fn roster_fixture() -> (Vec<Holder>, Vec<ThresholdMember>) {
        let hs: Vec<Holder> = ["A1", "B1", "C1", "D1"]
            .iter()
            .map(|id| Holder::new(id))
            .collect();
        let dir: Vec<ThresholdMember> = hs.iter().map(Holder::member).collect();
        (hs, dir)
    }

    #[test]
    fn roster_grow_authorized_by_live_majority() {
        let (hs, dir) = roster_fixture();
        let prior = family_envelope(&["A1", "B1", "C1"]);
        // grow A1,B1,C1 → A1,B1,C1,D1 (quorum 3/4), entrenched preserved.
        let new = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let prop = roster_proposal(&prior, &new);
        // A1,B1,C1 prove life + vote yes → |L|=3, strict-majority(3)=2, met.
        let parts: Vec<_> = hs[..3]
            .iter()
            .map(|h| participate(h, &prop, Vote::Yes))
            .collect();
        let v =
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir, &[], &[])
                .unwrap();
        assert!(v.authorized);
        assert!(!v.used_steward_backstop, "|L|=3 ≥ L_FLOOR");
        assert_eq!(v.tally.live_count(), 3);
    }

    #[test]
    fn roster_change_below_majority_is_not_authorized() {
        let (hs, dir) = roster_fixture();
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let prop = roster_proposal(&prior, &new);
        // 3 live, only 1 yes (2 no) → strict-majority(3)=2 not met.
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::No),
            participate(&hs[2], &prop, Vote::No),
        ];
        let v =
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir, &[], &[])
                .unwrap();
        assert!(!v.authorized, "1 of 3 yes does not reach strict majority");
    }

    #[test]
    fn shrink_to_one_member_is_rejected_n_min() {
        // H5: a 1/1 rebuild is a single point of compromise.
        let (hs, dir) = roster_fixture();
        let prior = family_envelope(&["A1", "B1", "C1"]);
        // attempt A1,B1,C1 → A1 only (would be quorum:1/1). Removed B1,C1 ARE in L
        // (so it's not the removal-continuity error — it's the size floor).
        let new = build_membership_change(&prior, &["A1".to_string()], Role::Founder, true, None);
        let prop = roster_proposal(&prior, &new);
        let parts: Vec<_> = hs[..3]
            .iter()
            .map(|h| participate(h, &prop, Vote::Yes))
            .collect();
        assert!(matches!(
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir, &[], &[]),
            Err(LiveQuorumError::RosterTooSmall { size: 1 })
        ));
    }

    #[test]
    fn removing_a_censored_member_is_rejected() {
        // H5 removal-continuity: C1 is censored (∉ L) and the change drops C1.
        let (hs, dir) = roster_fixture();
        let prior = family_envelope(&["A1", "B1", "C1"]);
        // shrink A1,B1,C1 → A1,B1 (quorum 2/2 — valid 2·2>2). C1 removed.
        let new = build_membership_change(
            &prior,
            &["A1", "B1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let prop = roster_proposal(&prior, &new);
        // only A1,B1 prove life — C1 is absent/censored.
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::Yes),
        ];
        // |L|=2 < L_FLOOR triggers the steward backstop; supply valid stewards so
        // the test isolates the removal-continuity check (which fires first).
        let stewards: Vec<Holder> = ["S1", "S2", "S3"]
            .iter()
            .map(|id| Holder::new(id))
            .collect();
        let sm: Vec<ThresholdMember> = stewards.iter().map(Holder::member).collect();
        let ss: Vec<ThresholdSignature> = stewards[..2]
            .iter()
            .map(|s| s.sign(&prop.canonical_bytes()))
            .collect();
        assert!(matches!(
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir, &sm, &ss),
            Err(LiveQuorumError::RemovedAbsentMember { .. })
        ));
    }

    #[test]
    fn steward_backstop_required_below_l_floor() {
        // H6: |L| < 3 requires the 2-of-3 steward co-sign; without it, not authorized.
        let (hs, dir) = roster_fixture();
        let prior = family_envelope(&["A1", "B1", "C1"]);
        // grow A1,B1,C1 → A1,B1,C1,D1; only A1,B1 prove life → |L|=2 < L_FLOOR.
        let new = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let prop = roster_proposal(&prior, &new);
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::Yes),
        ];
        let stewards: Vec<Holder> = ["S1", "S2", "S3"]
            .iter()
            .map(|id| Holder::new(id))
            .collect();
        let sm: Vec<ThresholdMember> = stewards.iter().map(Holder::member).collect();

        // Without steward sigs → backstop unmet → not authorized.
        let v_no =
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir, &sm, &[])
                .unwrap();
        assert!(v_no.used_steward_backstop);
        assert!(
            !v_no.authorized,
            "|L|<3 with no steward co-sign is not authorized"
        );

        // With 2-of-3 valid steward sigs → authorized.
        let ss: Vec<ThresholdSignature> = stewards[..2]
            .iter()
            .map(|s| s.sign(&prop.canonical_bytes()))
            .collect();
        let v_yes =
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir, &sm, &ss)
                .unwrap();
        assert!(v_yes.used_steward_backstop);
        assert!(v_yes.authorized, "|L|<3 + 2-of-3 stewards authorizes");
    }

    #[test]
    fn roster_anchor_and_payload_must_bind() {
        let (hs, dir) = roster_fixture();
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        // Wrong prior_family_digest (C3 anchor) → AnchorMismatch.
        let mut bad_anchor = roster_proposal(&prior, &new);
        bad_anchor.prior_family_digest = "f".repeat(64);
        // participations must bind THIS (bad) proposal to reach the anchor check
        let parts_bad: Vec<_> = hs[..3]
            .iter()
            .map(|h| participate(h, &bad_anchor, Vote::Yes))
            .collect();
        assert!(matches!(
            verify_membership_change_by_live_quorum(
                &bad_anchor,
                &parts_bad,
                &prior,
                &new,
                &dir,
                &[],
                &[]
            ),
            Err(LiveQuorumError::AnchorMismatch { .. })
        ));
    }

    // --- decision + equivocation (step 4) -----------------------------------

    fn decision_for(
        prop: AccordProposal,
        yes: usize,
        no: usize,
        authorized: bool,
    ) -> AccordDecision {
        let tally = LiveQuorumTally {
            live_set: (0..(yes + no)).map(|i| format!("M{i}")).collect(),
            yes,
            no,
            abstain: 0,
        };
        AccordDecision::new(prop, &tally, authorized)
    }

    #[test]
    fn decision_freezes_the_tally() {
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let prop = roster_proposal(&prior, &new);
        let tally = LiveQuorumTally {
            live_set: vec!["A1".into(), "B1".into(), "C1".into()],
            yes: 3,
            no: 0,
            abstain: 0,
        };
        let d = AccordDecision::new(prop.clone(), &tally, true);
        assert_eq!(d.live_set, tally.live_set);
        assert_eq!((d.yes, d.no, d.abstain), (3, 0, 0));
        assert!(d.authorized);
        assert_eq!(d.proposal, prop);
    }

    #[test]
    fn two_rosters_off_the_same_prior_equivocate() {
        // H3: two roster-changes superseding the SAME standing roster into
        // DIFFERENT new rosters are a fork — both must be rejected.
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new_x = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let new_y = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "E1"].map(String::from), // different new member
            Role::Founder,
            true,
            None,
        );
        let dx = decision_for(roster_proposal(&prior, &new_x), 3, 0, true);
        let dy = decision_for(roster_proposal(&prior, &new_y), 3, 0, true);
        assert!(
            decisions_equivocate(&dx, &dy),
            "different new rosters off one prior = equivocation"
        );
    }

    #[test]
    fn same_outcome_re_proposal_does_not_equivocate() {
        // The H4 coalescing case (same outcome, different nonce) is NOT a fork.
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = build_membership_change(
            &prior,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let mut p1 = roster_proposal(&prior, &new);
        let mut p2 = roster_proposal(&prior, &new);
        p1.nonce = "nonce-one-aaaaaaaaaaaaaaaaaaaaaaaa".into();
        p2.nonce = "nonce-two-bbbbbbbbbbbbbbbbbbbbbbbb".into();
        let d1 = decision_for(p1, 2, 1, true);
        let d2 = decision_for(p2, 3, 0, true);
        assert!(
            !decisions_equivocate(&d1, &d2),
            "same prior + same new roster (different nonce) is coalescing, not a fork"
        );
    }

    #[test]
    fn decisions_off_different_priors_do_not_equivocate() {
        let prior_a = family_envelope(&["A1", "B1", "C1"]);
        let prior_b = family_envelope(&["A1", "B1", "D1"]); // different standing roster
        let new_a = build_membership_change(
            &prior_a,
            &["A1", "B1", "C1", "D1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let new_b = build_membership_change(
            &prior_b,
            &["A1", "B1", "D1", "E1"].map(String::from),
            Role::Founder,
            true,
            None,
        );
        let da = decision_for(roster_proposal(&prior_a, &new_a), 3, 0, true);
        let db = decision_for(roster_proposal(&prior_b, &new_b), 3, 0, true);
        assert!(
            !decisions_equivocate(&da, &db),
            "different prior digests are sequential states, not a fork"
        );
    }
}
