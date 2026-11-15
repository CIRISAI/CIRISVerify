//! HUMANITY_ACCORD roster changes and holder recovery (FSD-004 / CC 4.2.6, rc19).
//!
//! **Scope: the roster, never the halt.** A `constitutional` halt is one
//! holder's self-contained, pre-signable row that fires on receipt — no
//! proposal, no participation window, no vote, no decision object
//! ([`crate::humanity_accord::verify_invocation`],
//! [`crate::accord_halt_latch`]). Confirmation and resumption are cosigned
//! `accord:lifecycle:*` rows by a strict majority of the standing roster. None
//! of them passes through this module.
//!
//! What lives here (CC 4.2.6):
//!
//! - **Roster change** (add / remove / swap): an `AccordProposal` (the
//!   membership-change envelope's digest, a **proposer-minted** nonce, the
//!   window `W`), `AccordParticipation`s (proof-of-life **bundled with** a vote
//!   in one signed object), tallied by [`tally_live_quorum`](crate::accord_live_quorum::tally_live_quorum) and decided by
//!   [`verify_membership_change_by_live_quorum`](crate::accord_live_quorum::verify_membership_change_by_live_quorum). The change carries iff
//!   `2·yes > N_standing`, where `N_standing` is **every** member at the roster
//!   head the change supersedes. Absence neither blocks nor helps: it is simply
//!   not a yes. The live set `L` is the record of who voted, never a
//!   denominator.
//! - **Holder recovery** ([`verify_holder_recovery`](crate::accord_live_quorum::verify_holder_recovery)): a new version of the
//!   roster record signed under one holder's pre-committed recovery key alone,
//!   changing only that holder's own seat (its signing key and its next
//!   recovery commitment). It needs no quorum.
//!
//! There is no steward backstop, no restore and no contest (CC 4.2.6 rc19: "No
//! second roster", "There is no restore and no contest"). The domain labels
//! `ciris.accord_contest.v1` and `ciris.accord_restore.v1` are retired and MUST
//! NOT be reused.
//!
//! A holder named for removal keeps fire authority through the lame-duck
//! window: until the removal's `W` has closed and the decision is recorded, the
//! standing roster a halt verifies against still lists them. This module never
//! shortens that; the caller pins the new roster only once a decision is
//! recorded.
//!
//! The participation preimage obligations from the adversarial review
//! (`FSD/FSD-004_ADVERSARIAL_REVIEW.md`):
//!
//! - **C1 (vote-flip / cross-proposal replay):** `AccordParticipation` has an
//!   exact, domain-separated `canonical_bytes` that binds the **vote**, the
//!   **full proposal digest**, the **member seat**, the **family** and the
//!   **window** inside the signed preimage.
//! - **C3 (anti-replay anchor):** the proposal binds `prior_family_digest` — the
//!   digest of the **standing** family envelope — so a participation is bound
//!   to a decision over one specific standing roster.
//! - **M3 (directory-only resolution):** a participation's signature is verified
//!   against the holder's **pinned** `ThresholdMember` key.
//! - **M5 (`family_key_id` binding):** bound in the preimage.
//!
//! Both preimages use the line-format `domain_prefix ‖ k=v\n…` discipline of
//! `crate::humanity_accord::Invocation`, with **distinct domain prefixes** so a
//! participation signature can never verify as an invoke / lifecycle /
//! proposal signature.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// Domain prefix for `AccordProposal` canonical bytes (trailing `\n` included).
pub const PROPOSAL_DOMAIN_PREFIX: &str = "ciris.accord_proposal.v1\n";
/// Domain prefix for `AccordParticipation` canonical bytes (trailing `\n`).
pub const PARTICIPATION_DOMAIN_PREFIX: &str = "ciris.accord_participation.v1\n";

/// The seat member a recovery version installs: the holder's **next** recovery
/// commitment (CC 4.2.6 pre-rotation), lowercase hex SHA-256.
pub const SEAT_RECOVERY_COMMITMENT_FIELD: &str = "recovery_commitment";
/// The charter member holding every holder's recovery commitment (CC 2.1,
/// CC 4.2.6): `{holder_key_id: commitment}`.
pub const CHARTER_RECOVERY_COMMITMENTS_FIELD: &str = "recovery_commitments";
/// The `supersedes` member naming the seat a recovery version rotates.
pub const SUPERSEDES_RECOVERY_OF_FIELD: &str = "recovery_of";

/// The action an `AccordProposal` opens.
///
/// The `accord_proposal` action is the membership-change envelope only
/// (CC 4.2.6; a fire is never a proposal, CC 4.2.1.1). The closed set keeps an
/// unknown action fail-closed at parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccordAction {
    /// A roster add / remove / swap, carried as a family `supersedes`.
    RosterChange,
}

impl AccordAction {
    /// Canonical wire token.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RosterChange => "roster_change",
        }
    }
}

/// A holder's vote, carried INSIDE the signed `AccordParticipation` preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vote {
    /// In favour of the proposed change.
    Yes,
    /// Against the proposed change.
    No,
    /// Present (enters `L`) but expresses no preference.
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

/// An accord roster-change proposal: the action, the **proposer-minted**
/// freshness nonce, the window upper bound, and the standing-roster anti-replay
/// anchor.
///
/// The proposal's `digest` is what every `AccordParticipation` binds to, so a
/// participation is non-transferable between proposals (C1/C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccordProposal {
    /// The accord family this decision is for (e.g. `humanity-accord`).
    pub family_key_id: String,
    /// What is being decided.
    pub action: AccordAction,
    /// Freshness nonce, `base64url(rand_32)`, **minted by the proposer — never
    /// issued by a server** (CC 4.2.6). Verify checks form; single use is the
    /// substrate's dedup.
    pub nonce: String,
    /// §0.5 canonical RFC 3339 — the window upper bound `W`. Membership of `L`
    /// is arrival within `W`, NOT a holder's self-asserted `signed_at` (C2);
    /// this field pins `W` into the signed bytes.
    pub window_until: String,
    /// Lowercase-hex SHA-256 of the **standing** family envelope this decision
    /// supersedes — the anti-replay anchor (C3), and the roster head whose
    /// members are `N_standing` (CC 2.7.4).
    pub prior_family_digest: String,
    /// Lowercase-hex SHA-256 of the proposed membership-change envelope.
    pub payload_sha256: String,
}

impl AccordProposal {
    /// CC 4.2.6 canonical bytes — the line-format preimage, domain-separated.
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
/// one signed act (CC 4.2.6). The signature is a hybrid (Ed25519 + ML-DSA-65)
/// `ThresholdSignature` over `canonical_bytes`.
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
    /// The proposal's `window_until`, bound into the signed bytes (C2).
    pub window_until: String,
    /// §0.5 RFC 3339. **Advisory display only** — MUST NOT gate `L` (C2).
    pub signed_at: String,
    /// The holder's hybrid signature over the canonical bytes.
    pub signature: ThresholdSignature,
}

impl AccordParticipation {
    /// CC 4.2.6 canonical bytes — domain-separated, with the **vote**, **proposal
    /// digest**, **member seat**, **family**, and **window** all inside the signed
    /// preimage (C1/C2/M3/M5).
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
    /// the family matches (M5), the `member_id` is consistent across the object,
    /// the signature and the pinned member (M3), and the holder's **hybrid**
    /// signature verifies over the recomputed canonical bytes.
    ///
    /// # Errors
    /// `LiveQuorumError` describing the first failed check.
    pub fn verify(
        &self,
        member: &ThresholdMember,
        proposal: &AccordProposal,
    ) -> Result<(), LiveQuorumError> {
        let expected = proposal.digest();
        if self.proposal_digest != expected {
            return Err(LiveQuorumError::ProposalMismatch {
                expected,
                got: self.proposal_digest.clone(),
            });
        }
        if self.family_key_id != proposal.family_key_id {
            return Err(LiveQuorumError::FamilyMismatch {
                proposal: proposal.family_key_id.clone(),
                participation: self.family_key_id.clone(),
            });
        }
        if self.member_id != self.signature.member_id || self.member_id != member.member_id {
            return Err(LiveQuorumError::MemberMismatch {
                participation: self.member_id.clone(),
                signature: self.signature.member_id.clone(),
                pinned: member.member_id.clone(),
            });
        }
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

/// Why a roster-change or recovery object failed verification — fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveQuorumError {
    /// The participation's `proposal_digest` does not match the proposal it was
    /// verified against (C1/C3).
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
    /// A participation names a member that is NOT in the standing roster
    /// (`L ⊆ standing roster`; only real, key-holding members count).
    NotInStandingRoster {
        /// The unrecognized `member_id`.
        member_id: String,
    },
    /// The same member appears twice in one tally — a member counts once (M3).
    DuplicateParticipant {
        /// The duplicated `member_id`.
        member_id: String,
    },
    /// The proposed envelope failed a structural invariant (distinct members,
    /// strict-majority `quorum:M/N`, entrenchment, anti-replay anchor) — wraps
    /// the `accord_genesis` validator's reason (C3).
    Structure(String),
    /// `proposal.payload_sha256` does not equal the digest of the proposed new
    /// family envelope.
    PayloadMismatch {
        /// Digest of the proposed new envelope.
        expected: String,
        /// `payload_sha256` the proposal carried.
        got: String,
    },
    /// `proposal.prior_family_digest` does not equal the digest of the standing
    /// family envelope (C3).
    AnchorMismatch {
        /// Digest of the standing (prior) envelope.
        expected: String,
        /// `prior_family_digest` the proposal carried.
        got: String,
    },
    /// The proposed roster has fewer than 2 members (H5, `N_min > 1`).
    RosterTooSmall {
        /// The proposed roster size.
        size: usize,
    },
    /// A recovery names a holder who has no seat at the standing roster head.
    HolderNotSeated {
        /// The holder key id the recovery names.
        holder_key_id: String,
    },
    /// A recovery version changes something other than the rotating holder's
    /// own seat — another seat, the threshold, the charter — and so concludes
    /// nothing (CC 4.2.6).
    RecoveryOutsideOwnSeat {
        /// What changed.
        detail: String,
    },
    /// A recovery commitment is not 64 lowercase hex.
    MalformedCommitment {
        /// The offending value.
        value: String,
    },
    /// The presented recovery key's record does not hash to the commitment in
    /// force for the holder (CC 4.2.6: the recovery concludes nothing).
    RecoveryCommitmentMismatch,
    /// A recovery version is not signed under the recovery key alone.
    RecoveryNotSoleSigner {
        /// The `member_id`s on the presented signatures.
        signers: Vec<String>,
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
                "participant {member_id} is not in the standing roster (CC 4.2.6)"
            ),
            Self::DuplicateParticipant { member_id } => {
                write!(f, "member {member_id} participated twice in one tally (M3)")
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
            Self::HolderNotSeated { holder_key_id } => write!(
                f,
                "recovery names {holder_key_id}, who holds no seat at the standing head"
            ),
            Self::RecoveryOutsideOwnSeat { detail } => write!(
                f,
                "recovery changes more than the holder's own seat: {detail} (CC 4.2.6)"
            ),
            Self::MalformedCommitment { value } => {
                write!(f, "recovery commitment {value:?} is not 64 lowercase hex")
            },
            Self::RecoveryCommitmentMismatch => write!(
                f,
                "recovery key does not hash to the commitment in force (CC 4.2.6)"
            ),
            Self::RecoveryNotSoleSigner { signers } => write!(
                f,
                "recovery must be signed under the recovery key alone; signers {signers:?}"
            ),
            Self::Signature(e) => write!(f, "signature invalid: {e}"),
        }
    }
}

impl std::error::Error for LiveQuorumError {}

/// The result of tallying participations — the frozen `L` (M2) plus the vote
/// breakdown. `live_set` is the distinct set of members who proved life, each
/// verified against the standing roster. It records the votes; it is never a
/// denominator (CC 4.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveQuorumTally {
    /// `member_id`s who proved life within the window — distinct, each a verified
    /// standing-roster member. This is the live set `L`.
    pub live_set: Vec<String>,
    /// `yes` votes.
    pub yes: usize,
    /// `no` votes.
    pub no: usize,
    /// `abstain` votes (present, no preference).
    pub abstain: usize,
}

impl LiveQuorumTally {
    /// `|L|` — the number of members who voted.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live_set.len()
    }
}

/// Tally `participations` against `proposal` over the **standing** roster.
///
/// Each participation is cryptographically verified ([`AccordParticipation::verify`]),
/// and its signer is resolved **only** in `standing_roster` (`L ⊆ standing
/// roster`). A member counts once. **Fail-closed:** any participation that fails
/// verification, names a non-standing member, or duplicates a member rejects the
/// whole tally.
///
/// **Window boundary (C2):** `L` membership by arrival within `W` is the
/// caller's responsibility; this function is the cryptographic and
/// roster-membership core. `signed_at` is never trusted as the clock.
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
        let member = standing_roster
            .iter()
            .find(|m| m.member_id == p.member_id)
            .ok_or_else(|| LiveQuorumError::NotInStandingRoster {
                member_id: p.member_id.clone(),
            })?;
        p.verify(member, proposal)?;
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

/// Whether `yes` votes carry a roster change over a standing roster of
/// `n_standing` members: `2·yes > N_standing` (CC 4.2.6). Absent members are
/// in `n_standing` and are not yes-votes.
#[must_use]
pub fn roster_change_carries(yes: usize, n_standing: usize) -> bool {
    2 * yes > n_standing
}

/// The verdict of a roster change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterChangeVerdict {
    /// Whether the change carries: `2·yes > N_standing`.
    pub authorized: bool,
    /// The frozen tally (the record of the votes cast within `W`).
    pub tally: LiveQuorumTally,
    /// `N_standing` — every member at the roster head the change supersedes.
    pub standing_count: usize,
}

fn envelope_digest(env: &Value) -> Result<String, LiveQuorumError> {
    let bytes = crate::accord_genesis::accord_family_signing_bytes(env)
        .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn member_ids(env: &Value) -> Result<Vec<String>, LiveQuorumError> {
    crate::accord_genesis::envelope_member_key_ids(env)
        .map_err(|e| LiveQuorumError::Structure(e.to_string()))
}

/// Verify a **roster change** (add / remove / swap) of the accord family
/// (CC 4.2.6).
///
/// Checks, fail-closed:
/// 1. **structure** ([`crate::accord_genesis::validate_membership_change_structure`]):
///    distinct, strict-majority new roster, distinct pubkeys, entrenchment and
///    `family_key_id` preserved, `supersedes.prior_member_key_ids ==` the
///    standing roster (C3);
/// 2. the proposal binds the change: `payload_sha256 ==` the new envelope
///    digest and `prior_family_digest ==` the standing envelope digest (C3);
/// 3. the tally, with signers resolved only among the members at the standing
///    head (`prior_envelope`) through `directory`;
/// 4. **`N_min`**: the new roster has ≥ 2 members (H5).
///
/// Then the decision: **`2·yes > N_standing`**, where `N_standing` is the
/// number of members at the standing head — the whole roster, however many
/// proved life. Absence is not a yes and never shrinks the denominator. A
/// member named for removal need not vote.
///
/// `directory` is the authoritative `federation_keys` pin set covering the
/// standing members and any incoming ones.
///
/// # Errors
/// [`LiveQuorumError`] for a structural or binding violation, a bad
/// participation, or an undersized roster. Whether the change carries is
/// [`RosterChangeVerdict::authorized`].
pub fn verify_membership_change_by_live_quorum(
    proposal: &AccordProposal,
    participations: &[AccordParticipation],
    prior_envelope: &Value,
    new_envelope: &Value,
    directory: &[ThresholdMember],
) -> Result<RosterChangeVerdict, LiveQuorumError> {
    // 1. Structure.
    crate::accord_genesis::validate_membership_change_structure(
        prior_envelope,
        new_envelope,
        directory,
    )
    .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;

    // 2. The proposal binds the proposed change and the standing head.
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

    // 3. Tally over the members at the standing head (CC 2.7.4), never the
    //    directory at large: an incoming member has no vote on its own seating.
    let prior_ids = member_ids(prior_envelope)?;
    let standing: Vec<ThresholdMember> = directory
        .iter()
        .filter(|m| prior_ids.contains(&m.member_id))
        .cloned()
        .collect();
    let tally = tally_live_quorum(proposal, participations, &standing)?;

    // 4. N_min (H5).
    let new_ids = member_ids(new_envelope)?;
    if new_ids.len() < 2 {
        return Err(LiveQuorumError::RosterTooSmall {
            size: new_ids.len(),
        });
    }

    let standing_count = prior_ids.len();
    Ok(RosterChangeVerdict {
        authorized: roster_change_carries(tally.yes, standing_count),
        tally,
        standing_count,
    })
}

// --- holder recovery (CC 4.2.6 "Pre-committed recovery keys") ----------------

/// A recovery key's record fields as stored on its key record — exactly the
/// three members the CC 3.2 T3 commitment binds. There is no `valid_until`: a
/// recovery commitment states no end (CC 4.2.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryKeyRecord {
    /// The recovery key's `key_id`.
    pub key_id: String,
    /// Ed25519 public key, standard base64, as stored on the key record.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 public key, standard base64, as stored on the key record.
    pub pubkey_ml_dsa_65_base64: String,
}

impl RecoveryKeyRecord {
    /// The CC 4.2.6 per-holder recovery commitment over this one key:
    /// [`recovery_commitment`] of a one-element array.
    ///
    /// # Errors
    /// [`LiveQuorumError::Structure`] on a canonicalization fault.
    pub fn commitment(&self) -> Result<String, LiveQuorumError> {
        recovery_commitment(std::slice::from_ref(self))
    }

    fn as_member(&self) -> ThresholdMember {
        ThresholdMember {
            member_id: self.key_id.clone(),
            ed25519_public_key_base64: self.pubkey_ed25519_base64.clone(),
            mldsa65_public_key_base64: Some(self.pubkey_ml_dsa_65_base64.clone()),
            role: None,
        }
    }
}

/// The CC 3.2 T3 key commitment: lowercase-hex
/// `SHA-256(JCS([ {key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64}, … ]))`,
/// the array sorted by `key_id` as UTF-8 bytes. It binds key material, never a
/// name.
///
/// # Errors
/// [`LiveQuorumError::Structure`] on a canonicalization fault.
pub fn recovery_commitment(keys: &[RecoveryKeyRecord]) -> Result<String, LiveQuorumError> {
    let mut sorted: Vec<&RecoveryKeyRecord> = keys.iter().collect();
    sorted.sort_by(|a, b| a.key_id.as_bytes().cmp(b.key_id.as_bytes()));
    let array = Value::Array(
        sorted
            .iter()
            .map(|k| {
                serde_json::json!({
                    "key_id": k.key_id,
                    "pubkey_ed25519_base64": k.pubkey_ed25519_base64,
                    "pubkey_ml_dsa_65_base64": k.pubkey_ml_dsa_65_base64,
                })
            })
            .collect(),
    );
    let bytes =
        crate::jcs::canonicalize(&array).map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn check_commitment_form(value: &str) -> Result<(), LiveQuorumError> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(LiveQuorumError::MalformedCommitment {
            value: value.to_string(),
        })
    }
}

fn seat_of<'a>(env: &'a Value, key_id: &str) -> Option<(usize, &'a Value)> {
    env.get("members")?
        .as_array()?
        .iter()
        .enumerate()
        .find(|(_, m)| m.get("key_id").and_then(Value::as_str) == Some(key_id))
}

/// The recovery commitment **in force** for `holder_key_id` (CC 4.2.6): the
/// one named by the latest recovery version that seated their current key —
/// carried on their seat at the standing head as
/// [`SEAT_RECOVERY_COMMITMENT_FIELD`] — or, if they have never recovered, their
/// entry in the charter's [`CHARTER_RECOVERY_COMMITMENTS_FIELD`]. `None` when
/// neither exists: that holder cannot self-rotate, and their recovery is a
/// roster change.
#[must_use]
pub fn recovery_commitment_in_force(
    charter: &Value,
    standing_envelope: &Value,
    holder_key_id: &str,
) -> Option<String> {
    let (_, seat) = seat_of(standing_envelope, holder_key_id)?;
    if let Some(c) = seat
        .get(SEAT_RECOVERY_COMMITMENT_FIELD)
        .and_then(Value::as_str)
    {
        return Some(c.to_string());
    }
    charter
        .get(CHARTER_RECOVERY_COMMITMENTS_FIELD)?
        .get(holder_key_id)?
        .as_str()
        .map(str::to_string)
}

/// Build a holder's **recovery version** of `standing_envelope`: the same
/// record with only `holder_key_id`'s seat changed — its signing key becomes
/// `new_signing_key_id` and its next recovery commitment `next_commitment` —
/// and a `supersedes` naming the standing members, the standing threshold and
/// the seat it rotates. The holder signs the JCS bytes
/// ([`crate::accord_genesis::accord_family_signing_bytes`]) under their
/// recovery key alone.
///
/// # Errors
/// [`LiveQuorumError::HolderNotSeated`] if the holder has no seat;
/// [`LiveQuorumError::MalformedCommitment`] for a bad `next_commitment`;
/// [`LiveQuorumError::Structure`] for a malformed envelope.
pub fn build_holder_recovery(
    standing_envelope: &Value,
    holder_key_id: &str,
    new_signing_key_id: &str,
    next_commitment: &str,
) -> Result<Value, LiveQuorumError> {
    check_commitment_form(next_commitment)?;
    let prior_ids = member_ids(standing_envelope)?;
    let (index, _) = seat_of(standing_envelope, holder_key_id).ok_or_else(|| {
        LiveQuorumError::HolderNotSeated {
            holder_key_id: holder_key_id.to_string(),
        }
    })?;
    let mut out = standing_envelope.clone();
    let obj = out
        .as_object_mut()
        .ok_or_else(|| LiveQuorumError::Structure("envelope is not an object".to_string()))?;
    let seat = obj
        .get_mut("members")
        .and_then(Value::as_array_mut)
        .and_then(|a| a.get_mut(index))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| LiveQuorumError::Structure("seat is not an object".to_string()))?;
    seat.insert("key_id".to_string(), Value::from(new_signing_key_id));
    seat.insert(
        SEAT_RECOVERY_COMMITMENT_FIELD.to_string(),
        Value::from(next_commitment),
    );
    let prior_cp = standing_envelope
        .get("consensus_protocol")
        .cloned()
        .unwrap_or(Value::Null);
    obj.insert(
        "supersedes".to_string(),
        serde_json::json!({
            "prior_member_key_ids": prior_ids,
            "prior_consensus_protocol": prior_cp,
            SUPERSEDES_RECOVERY_OF_FIELD: holder_key_id,
        }),
    );
    Ok(out)
}

/// What a verified recovery version installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryVerdict {
    /// The seat that rotated (the holder's key id at the standing head).
    pub holder_key_id: String,
    /// The signing key the seat now names.
    pub new_signing_key_id: String,
    /// The holder's next recovery commitment, now in force.
    pub next_commitment: String,
}

fn outside(detail: impl Into<String>) -> LiveQuorumError {
    LiveQuorumError::RecoveryOutsideOwnSeat {
        detail: detail.into(),
    }
}

/// Check that `recovery` differs from `standing` only in the seat at `index`
/// (its `key_id` and [`SEAT_RECOVERY_COMMITMENT_FIELD`]) and in a `supersedes`
/// that names the standing head and `holder_key_id`.
fn check_only_own_seat(
    standing: &Value,
    recovery: &Value,
    index: usize,
    holder_key_id: &str,
) -> Result<(), LiveQuorumError> {
    let not_object = || LiveQuorumError::Structure("envelope is not an object".to_string());
    let prior_obj = standing.as_object().ok_or_else(not_object)?;
    let new_obj = recovery.as_object().ok_or_else(not_object)?;

    // The family, the threshold, the entrenchment flag: everything but the
    // seats and the supersedes pointer is unchanged, and nothing is added.
    let rest = |o: &serde_json::Map<String, Value>| -> Vec<(String, Value)> {
        o.iter()
            .filter(|(k, _)| k.as_str() != "members" && k.as_str() != "supersedes")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    if rest(prior_obj) != rest(new_obj) {
        return Err(outside("a record member other than the seats changed"));
    }

    let seats = |o: &serde_json::Map<String, Value>| -> Result<Vec<Value>, LiveQuorumError> {
        o.get("members")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| LiveQuorumError::Structure("missing `members`".to_string()))
    };
    let prior_seats = seats(prior_obj)?;
    let new_seats = seats(new_obj)?;
    if prior_seats.len() != new_seats.len() {
        return Err(outside("the number of seats changed"));
    }
    for (i, (p, n)) in prior_seats.iter().zip(&new_seats).enumerate() {
        if i != index && p != n {
            return Err(outside(format!(
                "seat {i} is not the rotating holder's and changed"
            )));
        }
    }
    let strip = |seat: &Value| -> Value {
        let mut s = seat.clone();
        if let Some(o) = s.as_object_mut() {
            o.remove("key_id");
            o.remove(SEAT_RECOVERY_COMMITMENT_FIELD);
        }
        s
    };
    if strip(&prior_seats[index]) != strip(&new_seats[index]) {
        return Err(outside(
            "the holder's seat changed beyond its signing key and commitment",
        ));
    }

    let expected_supersedes = serde_json::json!({
        "prior_member_key_ids": member_ids(standing)?,
        "prior_consensus_protocol": standing.get("consensus_protocol").cloned().unwrap_or(Value::Null),
        SUPERSEDES_RECOVERY_OF_FIELD: holder_key_id,
    });
    if new_obj.get("supersedes") != Some(&expected_supersedes) {
        return Err(outside(
            "`supersedes` does not name the standing head and this holder's seat",
        ));
    }
    Ok(())
}

/// Verify a holder's **recovery version** (CC 4.2.6 "Pre-committed recovery
/// keys"): a new version of the accord's roster record, signed under the
/// holder's recovery key alone, that changes **only** that holder's own seat.
///
/// Every check is fail-closed; a failure means the recovery concludes nothing.
/// 1. `recovery_envelope` is a structurally valid supersede of
///    `standing_envelope` ([`crate::accord_genesis::validate_membership_change_structure`]:
///    the new signing key resolves in `directory` to a distinct pubkey, the
///    anchor names the standing members, entrenchment is kept).
/// 2. **Only the holder's own seat changes.** Every top-level member other
///    than `members` and `supersedes` (the family, the threshold, the
///    entrenchment flag) is unchanged; every other seat is byte-identical and
///    in place; the holder's seat changes only `key_id` and
///    [`SEAT_RECOVERY_COMMITMENT_FIELD`]; `supersedes` names the standing
///    members, the standing threshold and, as
///    [`SUPERSEDES_RECOVERY_OF_FIELD`], this holder.
/// 3. **The next commitment is installed**: the seat carries a well-formed
///    [`SEAT_RECOVERY_COMMITMENT_FIELD`].
/// 4. **The recovery key matches the commitment in force**:
///    `recovery_key.commitment() == commitment_in_force` (constant time). The
///    caller resolves `commitment_in_force` with
///    [`recovery_commitment_in_force`].
/// 5. **Signed by the recovery key alone**: exactly one signature, by
///    `recovery_key.key_id`, a hybrid signature over the JCS bytes of
///    `recovery_envelope`. No quorum is consulted.
///
/// # Errors
/// [`LiveQuorumError`] naming the first failed check.
pub fn verify_holder_recovery(
    standing_envelope: &Value,
    recovery_envelope: &Value,
    holder_key_id: &str,
    commitment_in_force: &str,
    recovery_key: &RecoveryKeyRecord,
    recovery_signatures: &[ThresholdSignature],
    directory: &[ThresholdMember],
) -> Result<RecoveryVerdict, LiveQuorumError> {
    // 1. Structure.
    crate::accord_genesis::validate_membership_change_structure(
        standing_envelope,
        recovery_envelope,
        directory,
    )
    .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;

    // 2. Only the holder's own seat changes.
    let (index, _) = seat_of(standing_envelope, holder_key_id).ok_or_else(|| {
        LiveQuorumError::HolderNotSeated {
            holder_key_id: holder_key_id.to_string(),
        }
    })?;
    check_only_own_seat(standing_envelope, recovery_envelope, index, holder_key_id)?;

    // 3. The next commitment is installed.
    let new_seat = recovery_envelope
        .get("members")
        .and_then(Value::as_array)
        .and_then(|a| a.get(index))
        .ok_or_else(|| LiveQuorumError::Structure("missing seat".to_string()))?;
    let new_signing_key_id = new_seat
        .get("key_id")
        .and_then(Value::as_str)
        .ok_or_else(|| LiveQuorumError::Structure("seat has no `key_id`".to_string()))?
        .to_string();
    let next_commitment = new_seat
        .get(SEAT_RECOVERY_COMMITMENT_FIELD)
        .and_then(Value::as_str)
        .ok_or_else(|| outside("the recovery installs no next recovery commitment"))?
        .to_string();
    check_commitment_form(&next_commitment)?;

    // 4. The recovery key hashes to the commitment in force.
    check_commitment_form(commitment_in_force)?;
    let presented = recovery_key.commitment()?;
    if !crate::security::constant_time_eq(presented.as_bytes(), commitment_in_force.as_bytes()) {
        return Err(LiveQuorumError::RecoveryCommitmentMismatch);
    }

    // 5. Signed under the recovery key alone.
    if recovery_signatures.len() != 1 || recovery_signatures[0].member_id != recovery_key.key_id {
        return Err(LiveQuorumError::RecoveryNotSoleSigner {
            signers: recovery_signatures
                .iter()
                .map(|s| s.member_id.clone())
                .collect(),
        });
    }
    let bytes = crate::accord_genesis::accord_family_signing_bytes(recovery_envelope)
        .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
    verify_threshold_signatures(&bytes, &[recovery_key.as_member()], recovery_signatures, 1)
        .map_err(|e| LiveQuorumError::Signature(format!("{e:?}")))?;

    Ok(RecoveryVerdict {
        holder_key_id: holder_key_id.to_string(),
        new_signing_key_id,
        next_commitment,
    })
}

/// The frozen outcome of a roster-change decision (M2).
///
/// Once a window closes, `L` is **final**: it carries the immutable live-set
/// snapshot and tally for `proposal`. A later proof-of-life is only ever
/// admissible against a *new* proposal — it never re-opens a closed window
/// (re-enrollment is going-forward only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccordDecision {
    /// The proposal this decides.
    pub proposal: AccordProposal,
    /// The frozen live set `L` — the `member_id`s who proved life within `W`.
    pub live_set: Vec<String>,
    /// `yes` / `no` / `abstain` cast.
    pub yes: usize,
    /// See [`Self::yes`].
    pub no: usize,
    /// See [`Self::yes`].
    pub abstain: usize,
    /// Whether the change carried (`2·yes > N_standing`).
    pub authorized: bool,
}

impl AccordDecision {
    /// Assemble a decision from a proposal, its frozen tally and the verdict.
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
/// rosters** (`payload_sha256` differs). Two witnessed heads are equivocation
/// (CC 3.2 T6); a consumer admits neither rather than last-writer-wins.
///
/// (A re-proposal of the *same* outcome — identical `payload_sha256` — is not an
/// equivocation; that is the H4 coalescing case.)
#[must_use]
pub fn decisions_equivocate(a: &AccordDecision, b: &AccordDecision) -> bool {
    a.proposal.action == b.proposal.action
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
        fn record(&self) -> RecoveryKeyRecord {
            let m = self.member();
            RecoveryKeyRecord {
                key_id: m.member_id,
                pubkey_ed25519_base64: m.ed25519_public_key_base64,
                pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64.unwrap(),
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
            signature: ThresholdSignature {
                member_id: h.member_id.clone(),
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
        };
        p.signature = h.sign(&p.canonical_bytes());
        p
    }

    fn unsigned_participation(prop: &AccordProposal) -> AccordParticipation {
        AccordParticipation {
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
        }
    }

    #[test]
    fn proposal_digest_is_stable_and_field_sensitive() {
        let p = sample_proposal();
        assert_eq!(p.digest(), p.clone().digest(), "deterministic");
        let mut p2 = p.clone();
        p2.nonce = "different-nonce".to_string();
        assert_ne!(p.digest(), p2.digest(), "nonce change → different digest");
        let mut p3 = p.clone();
        p3.payload_sha256 = "d".repeat(64);
        assert_ne!(p.digest(), p3.digest(), "payload change → different digest");
        let mut p4 = p.clone();
        p4.prior_family_digest = "c".repeat(64);
        assert_ne!(p.digest(), p4.digest(), "anchor change → different digest");
    }

    #[test]
    fn the_only_proposal_action_is_a_roster_change() {
        // A fire is never a proposal (CC 4.2.1.1): `fire` / `resume` no longer parse.
        assert_eq!(
            serde_json::to_value(AccordAction::RosterChange).unwrap(),
            serde_json::json!("roster_change")
        );
        assert!(serde_json::from_value::<AccordAction>(serde_json::json!("fire")).is_err());
        assert!(serde_json::from_value::<AccordAction>(serde_json::json!("resume")).is_err());
    }

    #[test]
    fn participation_preimage_binds_the_vote() {
        let prop = sample_proposal();
        let base = unsigned_participation(&prop);
        let mut no = base.clone();
        no.vote = Vote::No;
        assert_ne!(base.canonical_bytes(), no.canonical_bytes());
        let s = String::from_utf8(base.canonical_bytes()).unwrap();
        assert!(s.contains("\nvote=yes\n"));
        assert!(s.starts_with("ciris.accord_participation.v1\n"));
    }

    #[test]
    fn participation_scope_is_isolated_from_proposal() {
        let prop = sample_proposal();
        let part = unsigned_participation(&prop);
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
        let h = Holder::new("A1");
        let prop_a = sample_proposal();
        let mut prop_b = sample_proposal();
        prop_b.nonce = "a-totally-different-nonce".to_string();
        let part_for_a = participate(&h, &prop_a, Vote::Yes);
        assert!(matches!(
            part_for_a.verify(&h.member(), &prop_b),
            Err(LiveQuorumError::ProposalMismatch { .. })
        ));
    }

    #[test]
    fn flipped_vote_breaks_the_signature() {
        let h = Holder::new("A1");
        let prop = sample_proposal();
        let mut part = participate(&h, &prop, Vote::Yes);
        part.vote = Vote::No;
        assert!(matches!(
            part.verify(&h.member(), &prop),
            Err(LiveQuorumError::Signature(_))
        ));
    }

    #[test]
    fn signature_from_a_different_holder_is_rejected() {
        let a = Holder::new("A1");
        let b = Holder::new("A1"); // same claimed id, different keys
        let prop = sample_proposal();
        let part = participate(&b, &prop, Vote::Yes);
        assert!(matches!(
            part.verify(&a.member(), &prop),
            Err(LiveQuorumError::Signature(_))
        ));
    }

    #[test]
    fn classical_only_participation_is_rejected_at_federation_tier() {
        let h = Holder::new("A1");
        let prop = sample_proposal();
        let mut part = participate(&h, &prop, Vote::Yes);
        part.signature.mldsa65_signature_base64 = None;
        assert!(matches!(
            part.verify(&h.member(), &prop),
            Err(LiveQuorumError::Signature(_))
        ));
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
        let prop = sample_proposal();
        let a = Holder::new("A1");
        let intruder = Holder::new("X9");
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
        let prop = sample_proposal();
        let a = Holder::new("A1");
        let roster = vec![a.member()];
        let parts = vec![
            participate(&a, &prop, Vote::Yes),
            participate(&a, &prop, Vote::No),
        ];
        assert!(matches!(
            tally_live_quorum(&prop, &parts, &roster),
            Err(LiveQuorumError::DuplicateParticipant { .. })
        ));
    }

    #[test]
    fn carries_is_a_strict_majority_of_the_standing_count() {
        assert!(!roster_change_carries(1, 3));
        assert!(roster_change_carries(2, 3));
        assert!(!roster_change_carries(2, 4), "a tie is not a majority");
        assert!(roster_change_carries(3, 4));
        assert!(!roster_change_carries(10, 21));
        assert!(roster_change_carries(11, 21));
    }

    // --- roster change -------------------------------------------------------

    use crate::accord_genesis::{accord_family_signing_bytes, build_membership_change};
    use crate::threshold::Role;
    use serde_json::json;

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
            "consensus_protocol": crate::accord_genesis::accord_consensus_protocol(ids.len()),
            "consensus_protocol_entrenched": true,
        })
    }

    fn env_digest(env: &Value) -> String {
        hex::encode(Sha256::digest(accord_family_signing_bytes(env).unwrap()))
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

    fn change(prior: &Value, ids: &[&str]) -> Value {
        let ids: Vec<String> = ids.iter().map(|s| (*s).to_string()).collect();
        build_membership_change(prior, &ids, Role::Founder, true, None)
    }

    /// Holders for `ids` and the directory over them.
    fn holders(ids: &[&str]) -> (Vec<Holder>, Vec<ThresholdMember>) {
        let hs: Vec<Holder> = ids.iter().map(|id| Holder::new(id)).collect();
        let dir = hs.iter().map(Holder::member).collect();
        (hs, dir)
    }

    #[test]
    fn roster_change_needs_a_strict_majority_of_the_full_standing_roster() {
        // Standing A..E (N=5), adding F. 3 yes of 5 carries; 2 yes does not, even
        // when those 2 are every member who showed up.
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1", "E1", "F1"]);
        let prior = family_envelope(&["A1", "B1", "C1", "D1", "E1"]);
        let new = change(&prior, &["A1", "B1", "C1", "D1", "E1", "F1"]);
        let prop = roster_proposal(&prior, &new);

        let three: Vec<_> = hs[..3]
            .iter()
            .map(|h| participate(h, &prop, Vote::Yes))
            .collect();
        let v = verify_membership_change_by_live_quorum(&prop, &three, &prior, &new, &dir).unwrap();
        assert!(v.authorized, "3 of 5 standing is a strict majority");
        assert_eq!(v.standing_count, 5);

        let two: Vec<_> = hs[..2]
            .iter()
            .map(|h| participate(h, &prop, Vote::Yes))
            .collect();
        let v = verify_membership_change_by_live_quorum(&prop, &two, &prior, &new, &dir).unwrap();
        assert!(
            !v.authorized,
            "2 of 5 standing is not, however many are absent"
        );
        assert_eq!(v.tally.live_count(), 2);
    }

    #[test]
    fn absence_does_not_help() {
        // Standing A1,B1,C1. Only A1 shows up and votes yes: |L| = 1, so a
        // majority of L would carry it. Absence is not a yes: it does not.
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1"]);
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = change(&prior, &["A1", "B1", "C1", "D1"]);
        let prop = roster_proposal(&prior, &new);
        let parts = vec![participate(&hs[0], &prop, Vote::Yes)];
        let v = verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir).unwrap();
        assert!(!v.authorized, "one yes of three standing, two absent");

        // Nor does it block: A1, B1 yes with C1 absent carries.
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::Yes),
        ];
        let v = verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir).unwrap();
        assert!(v.authorized);
    }

    #[test]
    fn a_no_vote_is_counted_but_does_not_veto() {
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1"]);
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = change(&prior, &["A1", "B1", "C1", "D1"]);
        let prop = roster_proposal(&prior, &new);
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::Yes),
            participate(&hs[2], &prop, Vote::No),
        ];
        let v = verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir).unwrap();
        assert!(v.authorized);
        assert_eq!((v.tally.yes, v.tally.no), (2, 1));

        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::No),
            participate(&hs[2], &prop, Vote::No),
        ];
        let v = verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir).unwrap();
        assert!(!v.authorized, "1 yes of 3 does not carry");
    }

    #[test]
    fn a_removal_passes_without_the_removed_member_voting() {
        // A1,B1,C1 → A1,B1. C1 is absent; nothing requires them in L.
        let (hs, dir) = holders(&["A1", "B1", "C1"]);
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = change(&prior, &["A1", "B1"]);
        let prop = roster_proposal(&prior, &new);
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::Yes),
        ];
        let v = verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir).unwrap();
        assert!(v.authorized, "2 of 3 standing removes C1 without C1");
        assert!(!v.tally.live_set.contains(&"C1".to_string()));
    }

    #[test]
    fn an_incoming_member_has_no_vote() {
        // D1 is in the directory (it is being seated) but not at the standing head.
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1"]);
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = change(&prior, &["A1", "B1", "C1", "D1"]);
        let prop = roster_proposal(&prior, &new);
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[3], &prop, Vote::Yes),
        ];
        assert!(matches!(
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir),
            Err(LiveQuorumError::NotInStandingRoster { member_id }) if member_id == "D1"
        ));
    }

    #[test]
    fn shrink_to_one_member_is_rejected_n_min() {
        let (hs, dir) = holders(&["A1", "B1", "C1"]);
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = change(&prior, &["A1"]);
        let prop = roster_proposal(&prior, &new);
        let parts: Vec<_> = hs
            .iter()
            .map(|h| participate(h, &prop, Vote::Yes))
            .collect();
        assert!(matches!(
            verify_membership_change_by_live_quorum(&prop, &parts, &prior, &new, &dir),
            Err(LiveQuorumError::RosterTooSmall { size: 1 })
        ));
    }

    #[test]
    fn roster_anchor_and_payload_must_bind() {
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1"]);
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = change(&prior, &["A1", "B1", "C1", "D1"]);
        let mut bad_anchor = roster_proposal(&prior, &new);
        bad_anchor.prior_family_digest = "f".repeat(64);
        let parts: Vec<_> = hs[..3]
            .iter()
            .map(|h| participate(h, &bad_anchor, Vote::Yes))
            .collect();
        assert!(matches!(
            verify_membership_change_by_live_quorum(&bad_anchor, &parts, &prior, &new, &dir),
            Err(LiveQuorumError::AnchorMismatch { .. })
        ));
        let mut bad_payload = roster_proposal(&prior, &new);
        bad_payload.payload_sha256 = "e".repeat(64);
        assert!(matches!(
            verify_membership_change_by_live_quorum(&bad_payload, &[], &prior, &new, &dir),
            Err(LiveQuorumError::PayloadMismatch { .. })
        ));
    }

    // --- decision + equivocation ---------------------------------------------

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
        let new = change(&prior, &["A1", "B1", "C1", "D1"]);
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
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new_x = change(&prior, &["A1", "B1", "C1", "D1"]);
        let new_y = change(&prior, &["A1", "B1", "C1", "E1"]);
        let dx = decision_for(roster_proposal(&prior, &new_x), 3, 0, true);
        let dy = decision_for(roster_proposal(&prior, &new_y), 3, 0, true);
        assert!(decisions_equivocate(&dx, &dy));
    }

    #[test]
    fn same_outcome_re_proposal_does_not_equivocate() {
        let prior = family_envelope(&["A1", "B1", "C1"]);
        let new = change(&prior, &["A1", "B1", "C1", "D1"]);
        let mut p1 = roster_proposal(&prior, &new);
        let mut p2 = roster_proposal(&prior, &new);
        p1.nonce = "nonce-one-aaaaaaaaaaaaaaaaaaaaaaaa".into();
        p2.nonce = "nonce-two-bbbbbbbbbbbbbbbbbbbbbbbb".into();
        let d1 = decision_for(p1, 2, 1, true);
        let d2 = decision_for(p2, 3, 0, true);
        assert!(!decisions_equivocate(&d1, &d2));
    }

    #[test]
    fn decisions_off_different_priors_do_not_equivocate() {
        let prior_a = family_envelope(&["A1", "B1", "C1"]);
        let prior_b = family_envelope(&["A1", "B1", "D1"]);
        let new_a = change(&prior_a, &["A1", "B1", "C1", "D1"]);
        let new_b = change(&prior_b, &["A1", "B1", "D1", "E1"]);
        let da = decision_for(roster_proposal(&prior_a, &new_a), 3, 0, true);
        let db = decision_for(roster_proposal(&prior_b, &new_b), 3, 0, true);
        assert!(!decisions_equivocate(&da, &db));
    }

    // --- holder recovery (CC 4.2.6 pre-committed recovery keys) ---------------

    /// Standing A1,B1,C1 with a charter committing each holder's recovery key.
    /// A1 has lost its signing key; its new signing key is `A1n` (registered).
    struct RecoveryFixture {
        standing: Value,
        charter: Value,
        directory: Vec<ThresholdMember>,
        recovery_a: Holder,
        recovery_b: Holder,
        old_a: Holder,
        next_commitment: String,
    }

    fn recovery_fixture() -> RecoveryFixture {
        let (seats, mut directory) = holders(&["A1", "B1", "C1"]);
        let new_a = Holder::new("A1n");
        let new_b = Holder::new("B1n");
        directory.push(new_a.member());
        directory.push(new_b.member());
        let recovery_a = Holder::new("RA1");
        let recovery_b = Holder::new("RB1");
        let recovery_c = Holder::new("RC1");
        let charter = json!({
            CHARTER_RECOVERY_COMMITMENTS_FIELD: {
                "A1": recovery_a.record().commitment().unwrap(),
                "B1": recovery_b.record().commitment().unwrap(),
                "C1": recovery_c.record().commitment().unwrap(),
            }
        });
        let next_commitment = Holder::new("RA2").record().commitment().unwrap();
        let mut seats = seats.into_iter();
        RecoveryFixture {
            standing: family_envelope(&["A1", "B1", "C1"]),
            charter,
            directory,
            recovery_a,
            recovery_b,
            old_a: seats.next().unwrap(),
            next_commitment,
        }
    }

    fn sign_env(h: &Holder, env: &Value) -> ThresholdSignature {
        h.sign(&accord_family_signing_bytes(env).unwrap())
    }

    fn verify_a(
        f: &RecoveryFixture,
        recovery: &Value,
        key: &RecoveryKeyRecord,
        sigs: &[ThresholdSignature],
    ) -> Result<RecoveryVerdict, LiveQuorumError> {
        let in_force = recovery_commitment_in_force(&f.charter, &f.standing, "A1").unwrap();
        verify_holder_recovery(
            &f.standing,
            recovery,
            "A1",
            &in_force,
            key,
            sigs,
            &f.directory,
        )
    }

    #[test]
    fn commitment_binds_key_material_and_sorts_by_key_id() {
        let a = Holder::new("A").record();
        let mut a_other = Holder::new("A").record(); // same id, other material
        assert_ne!(a.commitment().unwrap(), a_other.commitment().unwrap());
        a_other = a.clone();
        assert_eq!(a.commitment().unwrap(), a_other.commitment().unwrap());
        let b = Holder::new("B").record();
        assert_eq!(
            recovery_commitment(&[a.clone(), b.clone()]).unwrap(),
            recovery_commitment(&[b, a]).unwrap()
        );
    }

    #[test]
    fn a_recovery_changing_only_its_own_seat_passes() {
        let f = recovery_fixture();
        let rec = build_holder_recovery(&f.standing, "A1", "A1n", &f.next_commitment).unwrap();
        let sig = sign_env(&f.recovery_a, &rec);
        let v = verify_a(&f, &rec, &f.recovery_a.record(), &[sig]).unwrap();
        assert_eq!(v.new_signing_key_id, "A1n");
        assert_eq!(v.next_commitment, f.next_commitment);
        // The next commitment is now the one in force for the rotated seat.
        assert_eq!(
            recovery_commitment_in_force(&f.charter, &rec, "A1n").as_deref(),
            Some(f.next_commitment.as_str())
        );
    }

    #[test]
    fn a_recovery_touching_another_seat_fails() {
        let f = recovery_fixture();
        let mut rec = build_holder_recovery(&f.standing, "A1", "A1n", &f.next_commitment).unwrap();
        // Also rotate B1 → B1n (registered, distinct key: structurally valid).
        rec["members"][1]["key_id"] = json!("B1n");
        let sig = sign_env(&f.recovery_a, &rec);
        assert!(matches!(
            verify_a(&f, &rec, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryOutsideOwnSeat { .. })
        ));
    }

    #[test]
    fn a_recovery_changing_the_threshold_or_role_fails() {
        let f = recovery_fixture();
        let base = build_holder_recovery(&f.standing, "A1", "A1n", &f.next_commitment).unwrap();

        let mut cp = base.clone();
        cp["consensus_protocol"] = json!("quorum:3/3");
        let sig = sign_env(&f.recovery_a, &cp);
        assert!(verify_a(&f, &cp, &f.recovery_a.record(), &[sig]).is_err());

        let mut role = base.clone();
        role["members"][0]["role"] = json!("member");
        let sig = sign_env(&f.recovery_a, &role);
        assert!(matches!(
            verify_a(&f, &role, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryOutsideOwnSeat { .. })
        ));

        let mut extra = base;
        extra["charter_digest"] = json!("0".repeat(64));
        let sig = sign_env(&f.recovery_a, &extra);
        assert!(matches!(
            verify_a(&f, &extra, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryOutsideOwnSeat { .. })
        ));
    }

    #[test]
    fn a_recovery_without_a_next_commitment_fails() {
        let f = recovery_fixture();
        let mut rec = build_holder_recovery(&f.standing, "A1", "A1n", &f.next_commitment).unwrap();
        rec["members"][0]
            .as_object_mut()
            .unwrap()
            .remove(SEAT_RECOVERY_COMMITMENT_FIELD);
        let sig = sign_env(&f.recovery_a, &rec);
        assert!(matches!(
            verify_a(&f, &rec, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryOutsideOwnSeat { .. })
        ));
    }

    #[test]
    fn a_recovery_signed_by_the_wrong_key_fails() {
        let f = recovery_fixture();
        let rec = build_holder_recovery(&f.standing, "A1", "A1n", &f.next_commitment).unwrap();

        // B1's recovery key presented for A1's seat: it is not A1's commitment.
        let sig = sign_env(&f.recovery_b, &rec);
        assert_eq!(
            verify_a(&f, &rec, &f.recovery_b.record(), &[sig]),
            Err(LiveQuorumError::RecoveryCommitmentMismatch)
        );

        // A1's recovery key presented, but B1's recovery key signed.
        let sig = sign_env(&f.recovery_b, &rec);
        assert!(matches!(
            verify_a(&f, &rec, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryNotSoleSigner { .. })
        ));

        // A forged signature under A1's recovery key id by another key.
        let impostor = Holder::new("RA1");
        let sig = sign_env(&impostor, &rec);
        assert!(matches!(
            verify_a(&f, &rec, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::Signature(_))
        ));

        // The lost signing key alone is not the recovery key.
        let sig = sign_env(&f.old_a, &rec);
        assert!(matches!(
            verify_a(&f, &rec, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryNotSoleSigner { .. })
        ));
    }

    #[test]
    fn a_recovery_is_signed_under_the_recovery_key_alone() {
        let f = recovery_fixture();
        let rec = build_holder_recovery(&f.standing, "A1", "A1n", &f.next_commitment).unwrap();
        let sigs = vec![sign_env(&f.recovery_a, &rec), sign_env(&f.old_a, &rec)];
        assert!(matches!(
            verify_a(&f, &rec, &f.recovery_a.record(), &sigs),
            Err(LiveQuorumError::RecoveryNotSoleSigner { .. })
        ));
    }

    #[test]
    fn a_recovery_signature_does_not_cover_a_tampered_version() {
        let f = recovery_fixture();
        let rec = build_holder_recovery(&f.standing, "A1", "A1n", &f.next_commitment).unwrap();
        let sig = sign_env(&f.recovery_a, &rec);
        let other = Holder::new("RA3").record().commitment().unwrap();
        let tampered = build_holder_recovery(&f.standing, "A1", "A1n", &other).unwrap();
        assert!(matches!(
            verify_a(&f, &tampered, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::Signature(_))
        ));
    }

    #[test]
    fn a_holder_without_a_commitment_cannot_self_rotate() {
        let f = recovery_fixture();
        assert_eq!(
            recovery_commitment_in_force(&json!({}), &f.standing, "A1"),
            None
        );
        assert_eq!(
            recovery_commitment_in_force(&f.charter, &f.standing, "Z9"),
            None,
            "no seat, no commitment"
        );
    }

    #[test]
    fn build_refuses_an_unseated_holder_or_bad_commitment() {
        let f = recovery_fixture();
        assert!(matches!(
            build_holder_recovery(&f.standing, "Z9", "Z9n", &f.next_commitment),
            Err(LiveQuorumError::HolderNotSeated { .. })
        ));
        assert!(matches!(
            build_holder_recovery(&f.standing, "A1", "A1n", &"F".repeat(64)),
            Err(LiveQuorumError::MalformedCommitment { .. })
        ));
    }
}
