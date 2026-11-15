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
//!   [`seat_change_digest`](crate::accord_live_quorum::seat_change_digest) of
//!   the change, a **proposer-minted** nonce, the window `W`, anchored on the
//!   standing head's `persist_row_hash`), `AccordParticipation`s (proof-of-life **bundled with** a vote
//!   in one signed object), tallied by [`tally_live_quorum`](crate::accord_live_quorum::tally_live_quorum) and decided by
//!   [`verify_membership_change_by_live_quorum`](crate::accord_live_quorum::verify_membership_change_by_live_quorum). The change carries iff
//!   `2·yes > N_standing`, where `N_standing` is **every** member at the roster
//!   head the change supersedes. Absence neither blocks nor helps: it is simply
//!   not a yes. The live set `L` is the record of who voted, never a
//!   denominator.
//! - **Holder recovery** ([`verify_holder_recovery`](crate::accord_live_quorum::verify_holder_recovery)): a new version of the
//!   roster record carried by a recovery statement signed under one holder's
//!   pre-committed recovery key alone, changing only that holder's own seat
//!   (its signing key; the statement names its next recovery commitment). It
//!   needs no quorum. The commitment it must match is the one **in force**
//!   ([`recovery_commitment_in_force`](crate::accord_live_quorum::recovery_commitment_in_force)):
//!   the one named by the latest row of the roster lineage, in
//!   `prev_head_digest` link order, that names a commitment for the holder (a
//!   recovery version's next commitment, or a charter version's entry). A
//!   commitment a recovery has spent never comes back into force.
//!
//! **The records are CIRISPersist's.** A roster version is persist's `Family`
//! record ([`FamilyRecord`](crate::accord_live_quorum::FamilyRecord)); its
//! identity is persist's `persist_row_hash`
//! ([`crate::persist_canonical`]), and a version names its predecessor's as
//! `prev_head_digest` (CC 3.2 T6, annex 8.11). The roster-change envelope
//! ([`ROSTER_CHANGE_KIND`](crate::accord_live_quorum::ROSTER_CHANGE_KIND)) and
//! the recovery statement
//! ([`RECOVERY_STATEMENT_KIND`](crate::accord_live_quorum::RECOVERY_STATEMENT_KIND))
//! are persist's shapes, carrying `prior_persist_row_hash` /
//! `next_persist_row_hash`, and are signed over their JCS bytes. The vector
//! `tests/vectors/accord_lineage/accord_lineage_v1.json` pins all of it.
//!
//! There is no minimum roster size (CC 4.2.6 states none): a roster change may
//! leave one member, and a shrunken roster freezes but can still fire.
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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::threshold::{verify_threshold_signatures, ThresholdMember, ThresholdSignature};

/// Domain prefix for `AccordProposal` canonical bytes (trailing `\n` included).
pub const PROPOSAL_DOMAIN_PREFIX: &str = "ciris.accord_proposal.v1\n";
/// Domain prefix for `AccordParticipation` canonical bytes (trailing `\n`).
pub const PARTICIPATION_DOMAIN_PREFIX: &str = "ciris.accord_participation.v1\n";

/// The charter member holding every holder's recovery commitment (CC 2.1,
/// CC 4.2.6): `{holder_key_id: commitment}`.
pub const CHARTER_RECOVERY_COMMITMENTS_FIELD: &str = "recovery_commitments";
/// The roster-record member naming the version it succeeds: the predecessor's
/// `persist_row_hash` ([`roster_version_digest`]); absent at genesis (CC 3.2 T6,
/// annex 8.11).
pub const PREV_HEAD_DIGEST_FIELD: &str = "prev_head_digest";
/// The change-envelope `kind` of a roster change (CIRISPersist
/// `accord_roster::ROSTER_CHANGE_KIND`).
pub const ROSTER_CHANGE_KIND: &str = "ciris.accord_roster_change.v1";
/// The change-envelope `kind` of a holder recovery, the recovery statement
/// (CIRISPersist `accord_recovery::RECOVERY_STATEMENT_KIND`).
pub const RECOVERY_STATEMENT_KIND: &str = "ciris.accord_recovery.v1";

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
    /// No recovery commitment is in force for the holder: no row of the
    /// lineage names an unspent commitment for their current key. Their
    /// recovery is a roster change.
    NoCommitmentInForce {
        /// The holder key id.
        holder_key_id: String,
    },
    /// The roster lineage is incomplete: it is empty, does not start at a
    /// genesis version, or a version's `prev_head_digest` does not name the
    /// version before it. Fails closed; the charter is never consulted instead.
    LineageIncomplete {
        /// Index of the version whose link is missing or wrong.
        index: usize,
        /// What is wrong.
        detail: String,
    },
    /// A recovery's next commitment equals the commitment it spends
    /// (CC 4.2.6: the recovery concludes nothing).
    RecoveryReusesCommitment,
    /// A recovery names the signing key already seated (CC 4.2.6: the
    /// recovery concludes nothing).
    RecoveryReusesSigningKey {
        /// The key id already seated.
        key_id: String,
    },
    /// A recovery version is not signed under the recovery key alone.
    RecoveryNotSoleSigner {
        /// The `member_id`s on the presented signatures.
        signers: Vec<String>,
    },
    /// The hybrid signature did not verify over the recomputed canonical bytes.
    Signature(String),
    /// A stored record's `persist_row_hash` does not recompute from the record.
    RowHashMismatch {
        /// The stored value.
        stored: String,
        /// The recomputed `persist_row_hash`.
        computed: String,
    },
    /// A recovery statement does not name this family, the standing version it
    /// succeeds (`prior_persist_row_hash`, the offered `prev_head_digest`) or
    /// the offered version (`next_persist_row_hash`), or is not a recovery
    /// statement (CIRISPersist `accord_recovery_statement_unbound`).
    RecoveryStatementUnbound {
        /// What is wrong.
        detail: String,
    },
    /// A recovery seats a key that already holds a seat, or names none.
    RecoverySeatTaken {
        /// The key id.
        key_id: String,
    },
    /// The recovery key already rotated a seat in the lineage
    /// (CIRISPersist `accord_recovery_key_spent`).
    RecoveryKeySpent {
        /// The recovery key id.
        key_id: String,
    },
    /// A charter version of the lineage names a `charter_digest` that no
    /// supplied charter row hashes to; the walk fails closed rather than skip
    /// it (CC 4.2.6).
    CharterMissing {
        /// Index of the version naming the charter.
        index: usize,
        /// The `charter_digest` it names.
        charter_digest: String,
    },
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
            Self::NoCommitmentInForce { holder_key_id } => write!(
                f,
                "no recovery commitment is in force for {holder_key_id} (CC 4.2.6)"
            ),
            Self::LineageIncomplete { index, detail } => {
                write!(f, "roster lineage incomplete at version {index}: {detail}")
            },
            Self::RecoveryReusesCommitment => write!(
                f,
                "recovery's next commitment equals the one it spends (CC 4.2.6)"
            ),
            Self::RecoveryReusesSigningKey { key_id } => write!(
                f,
                "recovery names {key_id}, the signing key already seated (CC 4.2.6)"
            ),
            Self::RecoveryNotSoleSigner { signers } => write!(
                f,
                "recovery must be signed under the recovery key alone; signers {signers:?}"
            ),
            Self::Signature(e) => write!(f, "signature invalid: {e}"),
            Self::RowHashMismatch { stored, computed } => write!(
                f,
                "stored persist_row_hash {stored} does not recompute (computed {computed})"
            ),
            Self::RecoveryStatementUnbound { detail } => {
                write!(f, "recovery statement unbound: {detail}")
            },
            Self::RecoverySeatTaken { key_id } => {
                write!(f, "recovery seats {key_id:?}, which holds a seat or is empty")
            },
            Self::RecoveryKeySpent { key_id } => {
                write!(f, "recovery key {key_id} already rotated a seat (CC 4.2.6)")
            },
            Self::CharterMissing {
                index,
                charter_digest,
            } => write!(
                f,
                "roster version {index} adopts charter {charter_digest}, which no supplied charter row hashes to"
            ),
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

// --- the roster record (CIRISPersist's `Family`) --------------------------------

/// One seat of a [`FamilyRecord`]: CIRISPersist's `FamilyMember`, serialized as
/// persist serializes it (`role` absent when `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyRecordMember {
    /// The member's `federation_keys.key_id`.
    pub key_id: String,
    /// When the member joined (RFC 3339; serializes with `Z`).
    pub joined_at: DateTime<Utc>,
    /// `founder` / `member` / operator-defined; absent when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// A version of a family's roster record: CIRISPersist's `Family`, field for
/// field and serialized as persist serializes it. `dissolved_at` is absent when
/// `None`; `prev_head_digest` and `charter_digest` are absent when empty.
///
/// The record's identity is its `persist_row_hash`
/// ([`FamilyRecord::row_hash`], [`crate::persist_canonical::persist_row_hash`]),
/// and a successor names it as [`PREV_HEAD_DIGEST_FIELD`] (CC 3.2 T6, annex
/// 8.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyRecord {
    /// The family's own `federation_keys.key_id`.
    pub family_key_id: String,
    /// Human-readable name; non-unique.
    pub family_name: String,
    /// The roster, in order.
    pub members: Vec<FamilyRecordMember>,
    /// When the family was founded.
    pub founded_at: DateTime<Utc>,
    /// The family's `consensus_protocol` (e.g. `quorum:2/3`).
    pub consensus_protocol: String,
    /// Whether `consensus_protocol` is entrenched.
    #[serde(default)]
    pub consensus_protocol_entrenched: bool,
    /// Set iff a terminal amendment dissolved the family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dissolved_at: Option<DateTime<Utc>>,
    /// The `persist_row_hash` of the version this one succeeds; empty at
    /// genesis.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prev_head_digest: String,
    /// The `persist_row_hash` of the charter row this version adopts; empty
    /// when it adopts none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub charter_digest: String,
    /// Server-computed: empty on an offered version, the record's own
    /// [`FamilyRecord::row_hash`] once stored. Never part of the hash.
    #[serde(default)]
    pub persist_row_hash: String,
}

impl FamilyRecord {
    /// This version's `persist_row_hash` (CC 3.2 T6): computed, never read from
    /// the `persist_row_hash` field.
    ///
    /// # Errors
    /// [`LiveQuorumError::Structure`] on a serialization fault.
    pub fn row_hash(&self) -> Result<String, LiveQuorumError> {
        crate::persist_canonical::persist_row_hash(self)
            .map_err(|e| LiveQuorumError::Structure(e.to_string()))
    }

    /// [`Self::row_hash`], refusing a record whose stored `persist_row_hash`
    /// is set and does not recompute.
    fn checked_row_hash(&self) -> Result<String, LiveQuorumError> {
        let computed = self.row_hash()?;
        if !self.persist_row_hash.is_empty()
            && !crate::security::constant_time_eq(
                self.persist_row_hash.as_bytes(),
                computed.as_bytes(),
            )
        {
            return Err(LiveQuorumError::RowHashMismatch {
                stored: self.persist_row_hash.clone(),
                computed,
            });
        }
        Ok(computed)
    }

    /// The record's signing envelope: its JSON without `persist_row_hash`
    /// (persist's `Family::signing_envelope`, what the record's author signs).
    ///
    /// # Errors
    /// [`LiveQuorumError::Structure`] on a serialization fault.
    pub fn signing_envelope(&self) -> Result<Value, LiveQuorumError> {
        let mut v =
            serde_json::to_value(self).map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
        if let Some(obj) = v.as_object_mut() {
            obj.remove("persist_row_hash");
        }
        Ok(v)
    }

    /// JCS of [`Self::signing_envelope`]: the bytes the record's author signs.
    ///
    /// # Errors
    /// [`LiveQuorumError::Structure`] on a canonicalization fault.
    pub fn record_signing_bytes(&self) -> Result<Vec<u8>, LiveQuorumError> {
        jcs_bytes(&self.signing_envelope()?)
    }

    /// The seat holding `key_id`, with its index.
    #[must_use]
    pub fn seat(&self, key_id: &str) -> Option<(usize, &FamilyRecordMember)> {
        self.members
            .iter()
            .enumerate()
            .find(|(_, m)| m.key_id == key_id)
    }

    /// The roster's key ids, in order.
    #[must_use]
    pub fn member_key_ids(&self) -> Vec<String> {
        self.members.iter().map(|m| m.key_id.clone()).collect()
    }
}

fn jcs_bytes(v: &Value) -> Result<Vec<u8>, LiveQuorumError> {
    crate::jcs::canonicalize(v).map_err(|e| LiveQuorumError::Structure(e.to_string()))
}

/// The digest of a roster version (CC 3.2 T6, annex 8.11): its
/// `persist_row_hash` ([`FamilyRecord::row_hash`]). The successor names it as
/// [`PREV_HEAD_DIGEST_FIELD`] and an `accord_proposal` names the standing
/// head's as `prior_family_digest`.
///
/// # Errors
/// [`LiveQuorumError::Structure`] on a serialization fault.
pub fn roster_version_digest(version: &FamilyRecord) -> Result<String, LiveQuorumError> {
    version.row_hash()
}

// --- seat changes ---------------------------------------------------------------

/// One seat a roster change adds (CIRISPersist `SeatAdd`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeatAdd {
    /// The holder key seated.
    pub key_id: String,
    /// Its role on the roster (serialized, `null` when `None`).
    #[serde(default)]
    pub role: Option<String>,
}

/// One seat change as an accord decision binds it (CIRISPersist `SeatChange`):
/// the keys removed and the seats added.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeatChange {
    /// Holder keys removed.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Seats added.
    #[serde(default)]
    pub add: Vec<SeatAdd>,
}

/// A [`SeatChange`] with the digest of the accord decision that authorized it:
/// one element of a roster change envelope's `changes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecidedSeatChange {
    /// The seat change.
    pub change: SeatChange,
    /// The [`AccordProposal::digest`] of the decision binding it.
    pub decision: String,
}

/// The digest an accord `roster_change` proposal binds as `payload_sha256`
/// (CIRISPersist `seat_change_digest`): lowercase-hex SHA-256 of JCS
/// `{family_key_id, remove: [sorted], add: [{key_id, role}] sorted by key_id}`.
///
/// # Errors
/// [`LiveQuorumError::Structure`] on a canonicalization fault.
pub fn seat_change_digest(
    family_key_id: &str,
    change: &SeatChange,
) -> Result<String, LiveQuorumError> {
    let mut remove = change.remove.clone();
    remove.sort();
    let mut add: Vec<Value> = change
        .add
        .iter()
        .map(|m| serde_json::json!({ "key_id": m.key_id, "role": m.role }))
        .collect();
    add.sort_by(|a, b| a["key_id"].as_str().cmp(&b["key_id"].as_str()));
    let v = serde_json::json!({ "family_key_id": family_key_id, "remove": remove, "add": add });
    Ok(hex::encode(Sha256::digest(jcs_bytes(&v)?)))
}

/// Apply `change` to the seats `seats` (key id → role), in place: every removed
/// key must hold a seat and every added key must not.
pub(crate) fn apply_seat_change(
    seats: &mut std::collections::BTreeMap<String, Option<String>>,
    change: &SeatChange,
) -> Result<(), String> {
    for k in &change.remove {
        if seats.remove(k).is_none() {
            return Err(format!("{k} holds no seat"));
        }
    }
    for m in &change.add {
        if seats.insert(m.key_id.clone(), m.role.clone()).is_some() {
            return Err(format!("{} already holds a seat", m.key_id));
        }
    }
    Ok(())
}

/// Verify the **decision** of a roster change (add / remove / swap) of the
/// accord family (CC 4.2.6): the tally of the participations in `proposal`.
///
/// Checks, fail-closed:
/// 1. the proposal names the standing head's family, binds `change`
///    (`payload_sha256 ==` [`seat_change_digest`]) and anchors on the standing
///    head (`prior_family_digest ==` its `persist_row_hash`, C3);
/// 2. `change` applies to the standing roster (every removed key is seated,
///    no added key is);
/// 3. the tally, with signers resolved only among the members at the standing
///    head through `directory`.
///
/// There is no minimum roster size (CC 4.2.6 states none): a change may leave
/// a single member. A shrunken roster freezes but can still fire.
///
/// Then the decision: **`2·yes > N_standing`**, where `N_standing` is the
/// number of members at the standing head — the whole roster, however many
/// proved life. Absence is not a yes and never shrinks the denominator. A
/// member named for removal need not vote.
///
/// The version that carries the change is verified separately, against the
/// recorded decision ([`crate::accord_genesis::verify_membership_change`]).
///
/// # Conformance
/// This is a pure verifier of the vote. For a change that adds a holder it
/// does **not** check, and CC 4.2.6 requires of whoever admits the change, for
/// each key in `change.add`: the added holder's own hybrid signature over the
/// offered record's `record_signing_bytes()`; that the key is a registered
/// `accord_holder` key record; and that the charter the offered version names
/// by `charter_digest` covers the roster, listing the added holder's recovery
/// commitment. [`crate::accord_genesis::verify_membership_change`] does not
/// check them either (see its `# Conformance`). A caller that skips them does
/// not conform.
///
/// # Errors
/// [`LiveQuorumError`] for a binding violation or a bad participation. Whether
/// the change carries is [`RosterChangeVerdict::authorized`].
pub fn verify_membership_change_by_live_quorum(
    proposal: &AccordProposal,
    participations: &[AccordParticipation],
    standing: &FamilyRecord,
    change: &SeatChange,
    directory: &[ThresholdMember],
) -> Result<RosterChangeVerdict, LiveQuorumError> {
    // 1. The proposal binds the change and the standing head.
    if proposal.family_key_id != standing.family_key_id {
        return Err(LiveQuorumError::FamilyMismatch {
            proposal: proposal.family_key_id.clone(),
            participation: standing.family_key_id.clone(),
        });
    }
    let payload = seat_change_digest(&standing.family_key_id, change)?;
    if proposal.payload_sha256 != payload {
        return Err(LiveQuorumError::PayloadMismatch {
            expected: payload,
            got: proposal.payload_sha256.clone(),
        });
    }
    let prior_digest = standing.checked_row_hash()?;
    if proposal.prior_family_digest != prior_digest {
        return Err(LiveQuorumError::AnchorMismatch {
            expected: prior_digest,
            got: proposal.prior_family_digest.clone(),
        });
    }

    // 2. The change applies to the standing roster.
    let mut seats: std::collections::BTreeMap<String, Option<String>> = standing
        .members
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    apply_seat_change(&mut seats, change).map_err(LiveQuorumError::Structure)?;

    // 3. Tally over the members at the standing head (CC 2.7.4), never the
    //    directory at large: an incoming member has no vote on its own seating.
    let prior_ids = standing.member_key_ids();
    let standing_members: Vec<ThresholdMember> = directory
        .iter()
        .filter(|m| prior_ids.contains(&m.member_id))
        .cloned()
        .collect();
    let tally = tally_live_quorum(proposal, participations, &standing_members)?;

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
    Ok(hex::encode(Sha256::digest(jcs_bytes(&array)?)))
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

/// One version of the accord's roster lineage: the **stored** record and the
/// change envelope that admitted it (`None` only at genesis). For a roster
/// change that is the [`ROSTER_CHANGE_KIND`] envelope, for a recovery the
/// [`RECOVERY_STATEMENT_KIND`] statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterVersion {
    /// The stored family record of this version.
    pub family: FamilyRecord,
    /// The change envelope that admitted it; `None` at genesis.
    #[serde(default)]
    pub change_envelope: Option<Value>,
}

fn str_field<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn is_recovery_statement(v: &Value) -> bool {
    str_field(v, "kind") == RECOVERY_STATEMENT_KIND
}

/// Check that `lineage` is a complete chain and return each version's
/// `persist_row_hash`: non-empty, of one family, starting at a genesis version
/// (empty `prev_head_digest`), each stored hash recomputing, and every later
/// version naming the `persist_row_hash` of the one before it, with a change
/// envelope whose `prior_persist_row_hash` / `next_persist_row_hash` bind that
/// same link.
fn check_lineage(lineage: &[RosterVersion]) -> Result<Vec<String>, LiveQuorumError> {
    let broken = |index: usize, detail: &str| LiveQuorumError::LineageIncomplete {
        index,
        detail: detail.to_string(),
    };
    let first = lineage.first().ok_or_else(|| broken(0, "empty lineage"))?;
    if !first.family.prev_head_digest.is_empty() {
        return Err(broken(0, "the first version is not a genesis version"));
    }
    let mut hashes: Vec<String> = Vec::with_capacity(lineage.len());
    for (index, version) in lineage.iter().enumerate() {
        if version.family.family_key_id != first.family.family_key_id {
            return Err(broken(index, "the version is of another family"));
        }
        let hash = version
            .family
            .checked_row_hash()
            .map_err(|_| broken(index, "the stored persist_row_hash does not recompute"))?;
        if index > 0 {
            let prior = &hashes[index - 1];
            let named = &version.family.prev_head_digest;
            if named.is_empty() {
                return Err(broken(index, "the version names no predecessor"));
            }
            if !crate::security::constant_time_eq(named.as_bytes(), prior.as_bytes()) {
                return Err(broken(
                    index,
                    "prev_head_digest is not the preceding version's persist_row_hash",
                ));
            }
            let env = version
                .change_envelope
                .as_ref()
                .ok_or_else(|| broken(index, "the version carries no change envelope"))?;
            let binds = |k: &str, h: &str| {
                crate::security::constant_time_eq(str_field(env, k).as_bytes(), h.as_bytes())
            };
            if !binds("prior_persist_row_hash", prior) || !binds("next_persist_row_hash", &hash) {
                return Err(broken(
                    index,
                    "the change envelope does not bind this version to its predecessor",
                ));
            }
        }
        hashes.push(hash);
    }
    Ok(hashes)
}

/// Where the commitment walk reads charter `recovery_commitments` from.
enum CharterSource<'a> {
    /// One charter, read as the charter adopted at genesis (the single-charter
    /// entry points).
    Single(&'a Value),
    /// Charter rows by `persist_row_hash`: each version that adopts a new
    /// `charter_digest` reads that row's entries, in link order.
    ByDigest(std::collections::BTreeMap<String, &'a Value>),
}

impl<'a> CharterSource<'a> {
    fn by_digest(charters: &'a [Value]) -> Result<Self, LiveQuorumError> {
        let mut map = std::collections::BTreeMap::new();
        for c in charters {
            let digest = crate::persist_canonical::persist_row_hash(c)
                .map_err(|e| LiveQuorumError::Structure(e.to_string()))?;
            map.insert(digest, c);
        }
        Ok(Self::ByDigest(map))
    }
}

/// Every commitment the lineage names, per key id, in link order, and every
/// commitment a recovery in the lineage spent.
#[derive(Default)]
struct CommitmentWalk {
    named: std::collections::BTreeMap<String, Vec<String>>,
    spent: std::collections::BTreeSet<String>,
}

impl CommitmentWalk {
    /// The latest commitment named for `key_id` that no recovery has spent.
    fn in_force(&self, key_id: &str) -> Option<String> {
        self.named
            .get(key_id)?
            .iter()
            .rev()
            .find(|c| !self.spent.contains(*c))
            .cloned()
    }

    fn name_from_charter(&mut self, charter: &Value) {
        let Some(entries) = charter
            .get(CHARTER_RECOVERY_COMMITMENTS_FIELD)
            .and_then(Value::as_object)
        else {
            return;
        };
        for (key_id, c) in entries {
            if let Some(c) = c.as_str() {
                self.named
                    .entry(key_id.clone())
                    .or_default()
                    .push(c.to_string());
            }
        }
    }
}

/// Walk `lineage` in link order (checked first: an incomplete chain fails
/// closed), recording each commitment a row names and each one a recovery
/// spends.
///
/// A recovery version spends the commitment then in force for its old key and
/// names its `next_recovery_commitment` for the new key. A charter version
/// names every entry of its `recovery_commitments`.
fn walk_commitments(
    charters: &CharterSource<'_>,
    lineage: &[RosterVersion],
) -> Result<CommitmentWalk, LiveQuorumError> {
    check_lineage(lineage)?;
    let mut walk = CommitmentWalk::default();
    for (index, version) in lineage.iter().enumerate() {
        if let Some(statement) = version
            .change_envelope
            .as_ref()
            .filter(|e| is_recovery_statement(e))
        {
            let old = str_field(statement, "old_holder_key_id");
            let new = str_field(statement, "new_holder_key_id");
            if let Some(c) = walk.in_force(old) {
                walk.spent.insert(c);
            }
            let next = statement
                .get("next_recovery_commitment")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    LiveQuorumError::Structure(format!(
                        "the recovery statement that seated {new} carries no next_recovery_commitment"
                    ))
                })?;
            walk.named
                .entry(new.to_string())
                .or_default()
                .push(next.to_string());
        }
        match charters {
            CharterSource::Single(charter) => {
                if index == 0 {
                    walk.name_from_charter(charter);
                }
            },
            CharterSource::ByDigest(rows) => {
                let digest = &version.family.charter_digest;
                let adopts = index == 0 || *digest != lineage[index - 1].family.charter_digest;
                if adopts && !digest.is_empty() {
                    let charter =
                        rows.get(digest)
                            .ok_or_else(|| LiveQuorumError::CharterMissing {
                                index,
                                charter_digest: digest.clone(),
                            })?;
                    walk.name_from_charter(charter);
                }
            },
        }
    }
    Ok(walk)
}

fn in_force_at_head(
    charters: &CharterSource<'_>,
    lineage: &[RosterVersion],
    holder_key_id: &str,
) -> Result<Option<String>, LiveQuorumError> {
    let walk = walk_commitments(charters, lineage)?;
    let head = &lineage[lineage.len() - 1].family;
    if head.seat(holder_key_id).is_none() {
        return Ok(None);
    }
    Ok(walk.in_force(holder_key_id))
}

/// The recovery commitment **in force** for `holder_key_id` (CC 4.2.6, rc20):
/// the one named by the **latest** row of the accord's own roster lineage that
/// names a commitment for that holder, where "latest" follows the
/// `prev_head_digest` links, never instants. That row is a recovery version
/// (its statement's `next_recovery_commitment` for the key it seats) or a
/// charter version (its `recovery_commitments` entry for the key). A
/// commitment a recovery has spent never comes back into force: an entry equal
/// to a spent commitment concludes nothing, and the latest **unspent** one
/// stands.
///
/// This entry point takes **one** charter and reads it as the charter adopted
/// at genesis; it does not follow a superseding charter that a later version
/// names by `charter_digest`, since it has no row to read. To follow charter
/// versions in link order, use [`recovery_commitment_in_force_with_charters`].
///
/// `lineage` is the accord's **stored** roster versions **oldest first**: the
/// genesis version, then each successor in order, ending at the standing head,
/// each with the change envelope that admitted it. Each version after the
/// first names its predecessor's `persist_row_hash` as [`PREV_HEAD_DIGEST_FIELD`]
/// (CC 3.2 T6, annex 8.11), and its envelope binds the same link. The caller
/// supplies versions it has already admitted; this function checks only the
/// chain, not their signatures. A recovery whose old key had no commitment in
/// force (as the supplied charters read) spends nothing the walk can name;
/// [`verify_holder_recovery`] still refuses its recovery key by id.
///
/// Returns `Ok(None)` when the holder holds no seat at the head, or no row
/// names an unspent commitment for them: that holder cannot self-rotate, and
/// their recovery is a roster change.
///
/// # Errors
/// [`LiveQuorumError::LineageIncomplete`] when the chain is empty, does not
/// start at genesis, or a link is missing or wrong: it never falls back to an
/// earlier row across the gap. [`LiveQuorumError::Structure`] when a recovery
/// statement in the lineage carries no next commitment.
pub fn recovery_commitment_in_force(
    charter: &Value,
    lineage: &[RosterVersion],
    holder_key_id: &str,
) -> Result<Option<String>, LiveQuorumError> {
    in_force_at_head(&CharterSource::Single(charter), lineage, holder_key_id)
}

/// [`recovery_commitment_in_force`] following **every** charter version in
/// link order (CC 4.2.6, rc20).
///
/// `charters` are the charter rows as CIRISPersist stores them; each is
/// identified by its own `persist_row_hash`, recomputed here, never by a
/// caller-supplied label. A version is a charter version when it is the
/// genesis version or names a `charter_digest` other than its predecessor's;
/// at that point in the walk the row with that digest names its
/// `recovery_commitments` entries. An empty `charter_digest` adopts none.
///
/// # Errors
/// As [`recovery_commitment_in_force`], and
/// [`LiveQuorumError::CharterMissing`] when a charter version names a digest
/// no row in `charters` has: the walk fails closed rather than skip it.
pub fn recovery_commitment_in_force_with_charters(
    charters: &[Value],
    lineage: &[RosterVersion],
    holder_key_id: &str,
) -> Result<Option<String>, LiveQuorumError> {
    in_force_at_head(&CharterSource::by_digest(charters)?, lineage, holder_key_id)
}

/// What a holder asks a recovery for (CIRISPersist `AccordRecoveryRequest`
/// without the family, which is the standing record's).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderRecoveryRequest {
    /// The seat's lost signing key.
    pub old_holder_key_id: String,
    /// The new signing key (registered before the rotation).
    pub new_holder_key_id: String,
    /// The old holder's pre-committed recovery key (registered).
    pub recovery_key_id: String,
    /// The commitment ([`recovery_commitment`]) to the new key's recovery key.
    pub next_recovery_commitment: String,
    /// The new seat's `joined_at`, stamped once by the caller.
    pub joined_at: DateTime<Utc>,
}

/// A drafted recovery (CIRISPersist `AccordRecoveryDraft`): the offered
/// version, the recovery statement, and the bytes the two keys sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderRecoveryDraft {
    /// The offered version of the family record (`persist_row_hash` empty).
    pub next: FamilyRecord,
    /// The recovery statement (the supersede proof's change envelope).
    pub statement: Value,
    /// JCS of the statement: the recovery key signs these.
    pub statement_bytes: Vec<u8>,
    /// JCS of the offered record's signing envelope: the new key signs these.
    pub record_bytes: Vec<u8>,
}

/// Draft a holder's **recovery version** of `standing` (CC 4.2.6), exactly as
/// CIRISPersist's `draft_accord_recovery` does: the standing record with only
/// the old holder's seat replaced by `{new_holder_key_id, joined_at, the seat's
/// role}`, `prev_head_digest` = the standing version's `persist_row_hash`, and
/// the recovery statement
/// `{kind, family_key_id, prior_persist_row_hash, next_persist_row_hash,
/// old_holder_key_id, new_holder_key_id, recovery_key_id,
/// next_recovery_commitment}`. The recovery key alone signs the statement's
/// JCS bytes; the new key signs the record.
///
/// # Errors
/// [`LiveQuorumError::HolderNotSeated`] if the old key holds no seat;
/// [`LiveQuorumError::RecoverySeatTaken`] if the new key already does;
/// [`LiveQuorumError::RecoveryReusesSigningKey`] when the new key is the old;
/// [`LiveQuorumError::MalformedCommitment`] for a bad next commitment;
/// [`LiveQuorumError::RowHashMismatch`] when `standing`'s stored hash does not
/// recompute.
pub fn build_holder_recovery(
    standing: &FamilyRecord,
    req: &HolderRecoveryRequest,
) -> Result<HolderRecoveryDraft, LiveQuorumError> {
    check_commitment_form(&req.next_recovery_commitment)?;
    if req.new_holder_key_id == req.old_holder_key_id {
        return Err(LiveQuorumError::RecoveryReusesSigningKey {
            key_id: req.old_holder_key_id.clone(),
        });
    }
    let (index, seat) =
        standing
            .seat(&req.old_holder_key_id)
            .ok_or_else(|| LiveQuorumError::HolderNotSeated {
                holder_key_id: req.old_holder_key_id.clone(),
            })?;
    if req.new_holder_key_id.is_empty() || standing.seat(&req.new_holder_key_id).is_some() {
        return Err(LiveQuorumError::RecoverySeatTaken {
            key_id: req.new_holder_key_id.clone(),
        });
    }
    let standing_hash = standing.checked_row_hash()?;
    let mut next = standing.clone();
    next.persist_row_hash = String::new();
    next.prev_head_digest = standing_hash.clone();
    next.members[index] = FamilyRecordMember {
        key_id: req.new_holder_key_id.clone(),
        joined_at: req.joined_at,
        role: seat.role.clone(),
    };
    let statement = serde_json::json!({
        "kind": RECOVERY_STATEMENT_KIND,
        "family_key_id": standing.family_key_id,
        "prior_persist_row_hash": standing_hash,
        "next_persist_row_hash": next.row_hash()?,
        "old_holder_key_id": req.old_holder_key_id,
        "new_holder_key_id": req.new_holder_key_id,
        "recovery_key_id": req.recovery_key_id,
        "next_recovery_commitment": req.next_recovery_commitment,
    });
    Ok(HolderRecoveryDraft {
        statement_bytes: jcs_bytes(&statement)?,
        record_bytes: next.record_signing_bytes()?,
        next,
        statement,
    })
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

fn unbound(detail: impl Into<String>) -> LiveQuorumError {
    LiveQuorumError::RecoveryStatementUnbound {
        detail: detail.into(),
    }
}

/// Verify a holder's **recovery version** (CC 4.2.6 "Pre-committed recovery
/// keys"): `offered`, a new version of the accord's roster record carried by
/// the recovery `statement` ([`RECOVERY_STATEMENT_KIND`]) signed under the old
/// holder's recovery key alone, changing **only** that holder's own seat.
///
/// `lineage` is the accord's stored roster versions oldest first, ending at
/// the standing head the recovery succeeds (see
/// [`recovery_commitment_in_force`]); `charter` carries
/// [`CHARTER_RECOVERY_COMMITMENTS_FIELD`].
///
/// Every check is fail-closed; a failure means the recovery concludes nothing.
/// 1. **The statement is bound**: its `kind`, its `family_key_id` (the
///    standing record's and the offered one's), `prior_persist_row_hash` and
///    the offered `prev_head_digest` = the standing version's
///    `persist_row_hash`, `next_persist_row_hash` = the offered version's.
/// 2. **The seat**: `old_holder_key_id` holds a seat at the standing head; the
///    new key is not the old ([`LiveQuorumError::RecoveryReusesSigningKey`]),
///    holds no seat and resolves in `directory` to a pubkey no other standing
///    seat carries.
/// 3. **Only the holder's own seat changes**: the offered record is the
///    standing one with that seat replaced by `{new key, its joined_at, the
///    seat's role}` and the head link moved; nothing else.
/// 4. **The next commitment** is well formed.
/// 5. **The lineage** is walked in link order
///    ([`recovery_commitment_in_force`]); an incomplete lineage fails closed.
/// 6. **Unspent**: no recovery statement in `lineage` names this recovery key,
///    and no recovery there spent its commitment
///    ([`LiveQuorumError::RecoveryKeySpent`]).
/// 7. **The commitment in force** is the latest unspent one the lineage names
///    for the holder; none is [`LiveQuorumError::NoCommitmentInForce`].
/// 8. **A new commitment**: the next commitment is neither the one in force
///    nor one a recovery already spent
///    ([`LiveQuorumError::RecoveryReusesCommitment`]).
/// 9. **The recovery key matches the commitment in force**:
///    `recovery_key.commitment() == in force` (constant time).
/// 10. **Signed by the recovery key alone**: exactly one signature, by
///     `statement.recovery_key_id == recovery_key.key_id`, a hybrid signature
///     over the statement's JCS bytes (CIRISPersist's `ceg_produce_canonicalize`,
///     which is [`crate::jcs::canonicalize`]). No quorum is consulted.
///
/// No minimum roster size applies (CC 4.2.6 states none).
///
/// This entry point reads `charter` as the charter adopted at genesis (see
/// [`recovery_commitment_in_force`]); [`verify_holder_recovery_with_charters`]
/// follows every charter version of the lineage.
///
/// # Conformance
/// This is a pure verifier. A recovery seats a new signing key, and CC 4.2.6
/// requires of whoever admits the version checks this function does **not**
/// make; a caller that skips them does not conform:
/// - **The new key's own signature on the record**: a hybrid signature by
///   `new_holder_key_id`, resolved in the caller's key directory, over
///   `offered.record_signing_bytes()` (JCS of the record without
///   `persist_row_hash`, [`HolderRecoveryDraft::record_bytes`]).
/// - **Its key type**: `new_holder_key_id` is a registered key record of type
///   `accord_holder` (not merely present in `directory`, which this function
///   only uses for its public keys).
/// - **Charter coverage**: the charter the offered version names
///   (`charter_digest`, unchanged from the standing version by check 3) is the
///   stored charter row that covers this roster; this function never reads
///   the row behind a `charter_digest` except to resolve commitments.
///
/// # Errors
/// [`LiveQuorumError`] naming the first failed check.
pub fn verify_holder_recovery(
    charter: &Value,
    lineage: &[RosterVersion],
    offered: &FamilyRecord,
    statement: &Value,
    recovery_key: &RecoveryKeyRecord,
    recovery_signatures: &[ThresholdSignature],
    directory: &[ThresholdMember],
) -> Result<RecoveryVerdict, LiveQuorumError> {
    verify_recovery_against(
        &CharterSource::Single(charter),
        lineage,
        offered,
        statement,
        recovery_key,
        recovery_signatures,
        directory,
    )
}

/// [`verify_holder_recovery`] with the commitment in force resolved over
/// **every** charter version of `lineage` in link order
/// ([`recovery_commitment_in_force_with_charters`]): `charters` are the stored
/// charter rows, each identified by its recomputed `persist_row_hash`.
///
/// # Conformance
/// As [`verify_holder_recovery`]: the caller must still check the new key's
/// signature on the offered record, that it is an `accord_holder` key record,
/// and that the named charter covers the roster.
///
/// # Errors
/// As [`verify_holder_recovery`], and [`LiveQuorumError::CharterMissing`] when
/// a version adopts a charter not in `charters`.
pub fn verify_holder_recovery_with_charters(
    charters: &[Value],
    lineage: &[RosterVersion],
    offered: &FamilyRecord,
    statement: &Value,
    recovery_key: &RecoveryKeyRecord,
    recovery_signatures: &[ThresholdSignature],
    directory: &[ThresholdMember],
) -> Result<RecoveryVerdict, LiveQuorumError> {
    verify_recovery_against(
        &CharterSource::by_digest(charters)?,
        lineage,
        offered,
        statement,
        recovery_key,
        recovery_signatures,
        directory,
    )
}

fn verify_recovery_against(
    charters: &CharterSource<'_>,
    lineage: &[RosterVersion],
    offered: &FamilyRecord,
    statement: &Value,
    recovery_key: &RecoveryKeyRecord,
    recovery_signatures: &[ThresholdSignature],
    directory: &[ThresholdMember],
) -> Result<RecoveryVerdict, LiveQuorumError> {
    let standing = &lineage
        .last()
        .ok_or_else(|| LiveQuorumError::LineageIncomplete {
            index: 0,
            detail: "empty lineage".to_string(),
        })?
        .family;

    // 1. The statement is bound to this family, the standing head and this version.
    if !is_recovery_statement(statement) {
        return Err(unbound("the change envelope is not a recovery statement"));
    }
    let standing_hash = standing.checked_row_hash()?;
    let offered_hash = offered.row_hash()?;
    let eq = |a: &str, b: &str| crate::security::constant_time_eq(a.as_bytes(), b.as_bytes());
    if str_field(statement, "family_key_id") != standing.family_key_id
        || offered.family_key_id != standing.family_key_id
    {
        return Err(unbound("the statement does not name this family"));
    }
    if !eq(
        str_field(statement, "prior_persist_row_hash"),
        &standing_hash,
    ) || !eq(&offered.prev_head_digest, &standing_hash)
    {
        return Err(unbound(
            "the statement and the version must name the standing version",
        ));
    }
    if !eq(str_field(statement, "next_persist_row_hash"), &offered_hash) {
        return Err(unbound("the statement does not name the offered version"));
    }

    // 2. The seat.
    let holder_key_id = str_field(statement, "old_holder_key_id");
    let new_signing_key_id = str_field(statement, "new_holder_key_id");
    let (index, seat) =
        standing
            .seat(holder_key_id)
            .ok_or_else(|| LiveQuorumError::HolderNotSeated {
                holder_key_id: holder_key_id.to_string(),
            })?;
    if new_signing_key_id == holder_key_id {
        return Err(LiveQuorumError::RecoveryReusesSigningKey {
            key_id: new_signing_key_id.to_string(),
        });
    }
    if new_signing_key_id.is_empty() || standing.seat(new_signing_key_id).is_some() {
        return Err(LiveQuorumError::RecoverySeatTaken {
            key_id: new_signing_key_id.to_string(),
        });
    }
    let new_member = directory
        .iter()
        .find(|m| m.member_id == new_signing_key_id)
        .ok_or_else(|| {
            LiveQuorumError::Structure(format!(
                "the new signing key {new_signing_key_id} is not in the directory"
            ))
        })?;
    let shares_a_key = directory.iter().any(|m| {
        m.member_id != new_signing_key_id
            && m.member_id != holder_key_id
            && standing.seat(&m.member_id).is_some()
            && (m.ed25519_public_key_base64 == new_member.ed25519_public_key_base64
                || (m.mldsa65_public_key_base64.is_some()
                    && m.mldsa65_public_key_base64 == new_member.mldsa65_public_key_base64))
    });
    if shares_a_key {
        return Err(LiveQuorumError::Structure(format!(
            "the new signing key {new_signing_key_id} reuses another seat's public key"
        )));
    }

    // 3. Only the holder's own seat changes.
    let joined_at = offered
        .seat(new_signing_key_id)
        .map_or(seat.joined_at, |(_, m)| m.joined_at);
    let mut expected = standing.clone();
    expected.persist_row_hash = String::new();
    expected.prev_head_digest.clone_from(&standing_hash);
    expected.members[index] = FamilyRecordMember {
        key_id: new_signing_key_id.to_string(),
        joined_at,
        role: seat.role.clone(),
    };
    let mut bare = offered.clone();
    bare.persist_row_hash = String::new();
    if bare != expected {
        return Err(outside(
            "the offered version is not the standing one with only this holder's seat swapped",
        ));
    }

    // 4. The next commitment.
    let next_commitment = str_field(statement, "next_recovery_commitment").to_string();
    check_commitment_form(&next_commitment)?;

    // 5. The lineage, in link order: every commitment named, every one spent.
    let walk = walk_commitments(charters, lineage)?;

    // 6. The recovery key has not rotated a seat before; its commitment is unspent.
    let presented = recovery_key.commitment()?;
    let spent_by_id = lineage.iter().any(|v| {
        v.change_envelope.as_ref().is_some_and(|e| {
            is_recovery_statement(e) && str_field(e, "recovery_key_id") == recovery_key.key_id
        })
    });
    if spent_by_id || walk.spent.contains(&presented) {
        return Err(LiveQuorumError::RecoveryKeySpent {
            key_id: recovery_key.key_id.clone(),
        });
    }

    // 7. The commitment in force: the latest unspent one named for the holder.
    let in_force =
        walk.in_force(holder_key_id)
            .ok_or_else(|| LiveQuorumError::NoCommitmentInForce {
                holder_key_id: holder_key_id.to_string(),
            })?;
    check_commitment_form(&in_force)?;

    // 8. The next commitment is new: not the one spent here, nor one spent before.
    if eq(&next_commitment, &in_force) || walk.spent.contains(&next_commitment) {
        return Err(LiveQuorumError::RecoveryReusesCommitment);
    }

    // 9. The recovery key hashes to the commitment in force.
    if !eq(&presented, &in_force) {
        return Err(LiveQuorumError::RecoveryCommitmentMismatch);
    }

    // 10. Signed under the recovery key alone, over the statement.
    if str_field(statement, "recovery_key_id") != recovery_key.key_id
        || recovery_signatures.len() != 1
        || recovery_signatures[0].member_id != recovery_key.key_id
    {
        return Err(LiveQuorumError::RecoveryNotSoleSigner {
            signers: recovery_signatures
                .iter()
                .map(|s| s.member_id.clone())
                .collect(),
        });
    }
    let bytes = jcs_bytes(statement)?;
    verify_threshold_signatures(&bytes, &[recovery_key.as_member()], recovery_signatures, 1)
        .map_err(|e| LiveQuorumError::Signature(format!("{e:?}")))?;

    Ok(RecoveryVerdict {
        holder_key_id: holder_key_id.to_string(),
        new_signing_key_id: new_signing_key_id.to_string(),
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

    use crate::accord_genesis::build_membership_change;
    use serde_json::json;

    const T0: &str = "2026-01-01T00:00:00Z";
    const T1: &str = "2026-06-01T12:00:00.123456789Z";

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    /// A stored genesis accord record over `ids`, entrenched.
    fn family(ids: &[&str]) -> FamilyRecord {
        stored(FamilyRecord {
            family_key_id: "humanity-accord".to_string(),
            // Non-ASCII: on an ASCII-only record the SHA-256 of its JCS bytes
            // happens to equal its persist_row_hash, so the superseded link
            // definition would go unnoticed.
            family_name: "HUMANITY_ACCORD — Hüterinnen".to_string(),
            members: ids
                .iter()
                .map(|k| FamilyRecordMember {
                    key_id: (*k).to_string(),
                    joined_at: at(T0),
                    role: Some("founder".to_string()),
                })
                .collect(),
            founded_at: at(T0),
            consensus_protocol: crate::accord_genesis::accord_consensus_protocol(ids.len()),
            consensus_protocol_entrenched: true,
            dissolved_at: None,
            prev_head_digest: String::new(),
            charter_digest: "c".repeat(64),
            persist_row_hash: String::new(),
        })
    }

    /// `f` as the store holds it: its `persist_row_hash` stamped.
    fn stored(mut f: FamilyRecord) -> FamilyRecord {
        f.persist_row_hash = f.row_hash().unwrap();
        f
    }

    fn adding(ids: &[&str]) -> SeatChange {
        SeatChange {
            remove: vec![],
            add: ids
                .iter()
                .map(|k| SeatAdd {
                    key_id: (*k).to_string(),
                    role: Some("founder".to_string()),
                })
                .collect(),
        }
    }

    fn removing(ids: &[&str]) -> SeatChange {
        SeatChange {
            remove: ids.iter().map(|k| (*k).to_string()).collect(),
            add: vec![],
        }
    }

    fn roster_proposal(standing: &FamilyRecord, change: &SeatChange) -> AccordProposal {
        AccordProposal {
            family_key_id: "humanity-accord".to_string(),
            action: AccordAction::RosterChange,
            nonce: "roster-nonce-XXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            window_until: "2026-06-29T00:00:00.000Z".to_string(),
            prior_family_digest: standing.row_hash().unwrap(),
            payload_sha256: seat_change_digest(&standing.family_key_id, change).unwrap(),
        }
    }

    /// Holders for `ids` and the directory over them.
    fn holders(ids: &[&str]) -> (Vec<Holder>, Vec<ThresholdMember>) {
        let hs: Vec<Holder> = ids.iter().map(|id| Holder::new(id)).collect();
        let dir = hs.iter().map(Holder::member).collect();
        (hs, dir)
    }

    fn verify_change(
        prop: &AccordProposal,
        parts: &[AccordParticipation],
        standing: &FamilyRecord,
        change: &SeatChange,
        dir: &[ThresholdMember],
    ) -> Result<RosterChangeVerdict, LiveQuorumError> {
        verify_membership_change_by_live_quorum(prop, parts, standing, change, dir)
    }

    fn yes_from(hs: &[Holder], prop: &AccordProposal) -> Vec<AccordParticipation> {
        hs.iter().map(|h| participate(h, prop, Vote::Yes)).collect()
    }

    #[test]
    fn roster_change_needs_a_strict_majority_of_the_full_standing_roster() {
        // Standing A..E (N=5), adding F. 3 yes of 5 carries; 2 yes does not, even
        // when those 2 are every member who showed up.
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1", "E1", "F1"]);
        let standing = family(&["A1", "B1", "C1", "D1", "E1"]);
        let change = adding(&["F1"]);
        let prop = roster_proposal(&standing, &change);

        let v = verify_change(&prop, &yes_from(&hs[..3], &prop), &standing, &change, &dir).unwrap();
        assert!(v.authorized, "3 of 5 standing is a strict majority");
        assert_eq!(v.standing_count, 5);

        let v = verify_change(&prop, &yes_from(&hs[..2], &prop), &standing, &change, &dir).unwrap();
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
        let standing = family(&["A1", "B1", "C1"]);
        let change = adding(&["D1"]);
        let prop = roster_proposal(&standing, &change);
        let v = verify_change(&prop, &yes_from(&hs[..1], &prop), &standing, &change, &dir).unwrap();
        assert!(!v.authorized, "one yes of three standing, two absent");

        // Nor does it block: A1, B1 yes with C1 absent carries.
        let v = verify_change(&prop, &yes_from(&hs[..2], &prop), &standing, &change, &dir).unwrap();
        assert!(v.authorized);
    }

    #[test]
    fn a_no_vote_is_counted_but_does_not_veto() {
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1"]);
        let standing = family(&["A1", "B1", "C1"]);
        let change = adding(&["D1"]);
        let prop = roster_proposal(&standing, &change);
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::Yes),
            participate(&hs[2], &prop, Vote::No),
        ];
        let v = verify_change(&prop, &parts, &standing, &change, &dir).unwrap();
        assert!(v.authorized);
        assert_eq!((v.tally.yes, v.tally.no), (2, 1));

        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[1], &prop, Vote::No),
            participate(&hs[2], &prop, Vote::No),
        ];
        let v = verify_change(&prop, &parts, &standing, &change, &dir).unwrap();
        assert!(!v.authorized, "1 yes of 3 does not carry");
    }

    #[test]
    fn a_removal_passes_without_the_removed_member_voting() {
        // A1,B1,C1 → A1,B1. C1 is absent; nothing requires them in L.
        let (hs, dir) = holders(&["A1", "B1", "C1"]);
        let standing = family(&["A1", "B1", "C1"]);
        let change = removing(&["C1"]);
        let prop = roster_proposal(&standing, &change);
        let v = verify_change(&prop, &yes_from(&hs[..2], &prop), &standing, &change, &dir).unwrap();
        assert!(v.authorized, "2 of 3 standing removes C1 without C1");
        assert!(!v.tally.live_set.contains(&"C1".to_string()));
    }

    #[test]
    fn an_incoming_member_has_no_vote() {
        // D1 is in the directory (it is being seated) but not at the standing head.
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1"]);
        let standing = family(&["A1", "B1", "C1"]);
        let change = adding(&["D1"]);
        let prop = roster_proposal(&standing, &change);
        let parts = vec![
            participate(&hs[0], &prop, Vote::Yes),
            participate(&hs[3], &prop, Vote::Yes),
        ];
        assert!(matches!(
            verify_change(&prop, &parts, &standing, &change, &dir),
            Err(LiveQuorumError::NotInStandingRoster { member_id }) if member_id == "D1"
        ));
    }

    #[test]
    fn a_roster_change_to_one_member_is_not_refused_for_size() {
        // CC 4.2.6 states no minimum: A1,B1,C1 → A1 carries on 3 yes of 3.
        let (hs, dir) = holders(&["A1", "B1", "C1"]);
        let standing = family(&["A1", "B1", "C1"]);
        let change = removing(&["B1", "C1"]);
        let prop = roster_proposal(&standing, &change);
        let v = verify_change(&prop, &yes_from(&hs, &prop), &standing, &change, &dir).unwrap();
        assert!(v.authorized);
        assert_eq!(v.standing_count, 3);

        // And 2 → 1, the smallest step.
        let standing = family(&["A1", "B1"]);
        let change = removing(&["A1"]);
        let prop = roster_proposal(&standing, &change);
        let v = verify_change(&prop, &yes_from(&hs[..2], &prop), &standing, &change, &dir).unwrap();
        assert!(v.authorized);
    }

    #[test]
    fn roster_anchor_and_payload_must_bind() {
        let (hs, dir) = holders(&["A1", "B1", "C1", "D1"]);
        let standing = family(&["A1", "B1", "C1"]);
        let change = adding(&["D1"]);
        let mut bad_anchor = roster_proposal(&standing, &change);
        bad_anchor.prior_family_digest = "f".repeat(64);
        assert!(matches!(
            verify_change(
                &bad_anchor,
                &yes_from(&hs[..3], &bad_anchor),
                &standing,
                &change,
                &dir
            ),
            Err(LiveQuorumError::AnchorMismatch { .. })
        ));
        // The anchor is the standing head's persist_row_hash, not the digest of
        // its JCS bytes.
        let mut jcs_anchor = roster_proposal(&standing, &change);
        jcs_anchor.prior_family_digest =
            hex::encode(Sha256::digest(standing.record_signing_bytes().unwrap()));
        assert!(matches!(
            verify_change(&jcs_anchor, &[], &standing, &change, &dir),
            Err(LiveQuorumError::AnchorMismatch { .. })
        ));
        let mut bad_payload = roster_proposal(&standing, &change);
        bad_payload.payload_sha256 = "e".repeat(64);
        assert!(matches!(
            verify_change(&bad_payload, &[], &standing, &change, &dir),
            Err(LiveQuorumError::PayloadMismatch { .. })
        ));
        // A change that does not apply to the standing roster.
        let unseated = removing(&["Z9"]);
        let prop = roster_proposal(&standing, &unseated);
        assert!(matches!(
            verify_change(&prop, &[], &standing, &unseated, &dir),
            Err(LiveQuorumError::Structure(_))
        ));
    }

    #[test]
    fn seat_change_digest_sorts_and_binds_the_family() {
        let a = SeatChange {
            remove: vec!["B".into(), "A".into()],
            add: vec![
                SeatAdd {
                    key_id: "D".into(),
                    role: None,
                },
                SeatAdd {
                    key_id: "C".into(),
                    role: Some("founder".into()),
                },
            ],
        };
        let mut b = a.clone();
        b.remove.reverse();
        b.add.reverse();
        assert_eq!(
            seat_change_digest("f", &a).unwrap(),
            seat_change_digest("f", &b).unwrap()
        );
        assert_ne!(
            seat_change_digest("f", &a).unwrap(),
            seat_change_digest("g", &a).unwrap()
        );
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
        let standing = family(&["A1", "B1", "C1"]);
        let prop = roster_proposal(&standing, &adding(&["D1"]));
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
        let standing = family(&["A1", "B1", "C1"]);
        let dx = decision_for(roster_proposal(&standing, &adding(&["D1"])), 3, 0, true);
        let dy = decision_for(roster_proposal(&standing, &adding(&["E1"])), 3, 0, true);
        assert!(decisions_equivocate(&dx, &dy));
    }

    #[test]
    fn same_outcome_re_proposal_does_not_equivocate() {
        let standing = family(&["A1", "B1", "C1"]);
        let mut p1 = roster_proposal(&standing, &adding(&["D1"]));
        let mut p2 = p1.clone();
        p1.nonce = "nonce-one-aaaaaaaaaaaaaaaaaaaaaaaa".into();
        p2.nonce = "nonce-two-bbbbbbbbbbbbbbbbbbbbbbbb".into();
        let d1 = decision_for(p1, 2, 1, true);
        let d2 = decision_for(p2, 3, 0, true);
        assert!(!decisions_equivocate(&d1, &d2));
    }

    #[test]
    fn decisions_off_different_priors_do_not_equivocate() {
        let prior_a = family(&["A1", "B1", "C1"]);
        let prior_b = family(&["A1", "B1", "D1"]);
        let da = decision_for(roster_proposal(&prior_a, &adding(&["D1"])), 3, 0, true);
        let db = decision_for(roster_proposal(&prior_b, &adding(&["E1"])), 3, 0, true);
        assert!(!decisions_equivocate(&da, &db));
    }

    // --- holder recovery (CC 4.2.6 pre-committed recovery keys) ---------------

    /// Standing A1,B1,C1 with a charter committing each holder's recovery key.
    /// A1 has lost its signing key; its new signing key is `A1n` (registered).
    struct RecoveryFixture {
        standing: FamilyRecord,
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
            standing: family(&["A1", "B1", "C1"]),
            charter,
            directory,
            recovery_a,
            recovery_b,
            old_a: seats.next().unwrap(),
            next_commitment,
        }
    }

    fn request(old: &str, new: &str, recovery_key_id: &str, next: &str) -> HolderRecoveryRequest {
        HolderRecoveryRequest {
            old_holder_key_id: old.to_string(),
            new_holder_key_id: new.to_string(),
            recovery_key_id: recovery_key_id.to_string(),
            next_recovery_commitment: next.to_string(),
            joined_at: at(T1),
        }
    }

    /// A1 → A1n under RA1, naming `next`.
    fn draft_a(f: &RecoveryFixture, next: &str) -> HolderRecoveryDraft {
        build_holder_recovery(&f.standing, &request("A1", "A1n", "RA1", next)).unwrap()
    }

    /// Re-point `statement` at `next` (so only the seat rules can refuse it).
    fn rebind(statement: &mut Value, next: &FamilyRecord) {
        statement["next_persist_row_hash"] = json!(next.row_hash().unwrap());
    }

    fn sign_st(h: &Holder, statement: &Value) -> ThresholdSignature {
        h.sign(&crate::jcs::canonicalize(statement).unwrap())
    }

    fn genesis_lineage(f: &RecoveryFixture) -> Vec<RosterVersion> {
        vec![RosterVersion {
            family: f.standing.clone(),
            change_envelope: None,
        }]
    }

    fn verify_a(
        f: &RecoveryFixture,
        next: &FamilyRecord,
        statement: &Value,
        key: &RecoveryKeyRecord,
        sigs: &[ThresholdSignature],
    ) -> Result<RecoveryVerdict, LiveQuorumError> {
        verify_holder_recovery(
            &f.charter,
            &genesis_lineage(f),
            next,
            statement,
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
    fn the_draft_is_persists_shape() {
        let f = recovery_fixture();
        let d = draft_a(&f, &f.next_commitment);
        assert_eq!(d.next.prev_head_digest, f.standing.row_hash().unwrap());
        assert_eq!(d.next.persist_row_hash, "");
        assert_eq!(d.next.members[0].key_id, "A1n");
        assert_eq!(d.next.members[0].joined_at, at(T1));
        assert_eq!(d.next.members[0].role.as_deref(), Some("founder"));
        assert_eq!(d.next.members[1..], f.standing.members[1..]);
        assert_eq!(
            d.statement,
            json!({
                "kind": RECOVERY_STATEMENT_KIND,
                "family_key_id": "humanity-accord",
                "prior_persist_row_hash": f.standing.row_hash().unwrap(),
                "next_persist_row_hash": d.next.row_hash().unwrap(),
                "old_holder_key_id": "A1",
                "new_holder_key_id": "A1n",
                "recovery_key_id": "RA1",
                "next_recovery_commitment": f.next_commitment,
            })
        );
        assert_eq!(
            d.statement_bytes,
            crate::jcs::canonicalize(&d.statement).unwrap()
        );
        assert_eq!(d.record_bytes, d.next.record_signing_bytes().unwrap());
    }

    #[test]
    fn a_recovery_changing_only_its_own_seat_passes() {
        let f = recovery_fixture();
        let d = draft_a(&f, &f.next_commitment);
        let sig = sign_st(&f.recovery_a, &d.statement);
        let v = verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]).unwrap();
        assert_eq!(v.holder_key_id, "A1");
        assert_eq!(v.new_signing_key_id, "A1n");
        assert_eq!(v.next_commitment, f.next_commitment);
        // The next commitment is now the one in force for the rotated seat.
        let mut lineage = genesis_lineage(&f);
        lineage.push(RosterVersion {
            family: stored(d.next),
            change_envelope: Some(d.statement),
        });
        assert_eq!(
            recovery_commitment_in_force(&f.charter, &lineage, "A1n")
                .unwrap()
                .as_deref(),
            Some(f.next_commitment.as_str())
        );
    }

    #[test]
    fn a_recovery_touching_another_seat_fails() {
        let f = recovery_fixture();
        let mut d = draft_a(&f, &f.next_commitment);
        // Also rotate B1 → B1n (registered, distinct key).
        d.next.members[1].key_id = "B1n".to_string();
        rebind(&mut d.statement, &d.next);
        let sig = sign_st(&f.recovery_a, &d.statement);
        assert!(matches!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryOutsideOwnSeat { .. })
        ));
    }

    #[test]
    fn a_recovery_changing_the_threshold_role_or_charter_fails() {
        let f = recovery_fixture();
        let base = draft_a(&f, &f.next_commitment);
        let tweaks: [fn(&mut FamilyRecord); 4] = [
            |n| n.consensus_protocol = "quorum:3/3".to_string(),
            |n| n.members[0].role = Some("member".to_string()),
            |n| n.charter_digest = "0".repeat(64),
            |n| n.family_name = "renamed".to_string(),
        ];
        for tweak in tweaks {
            let mut d = base.clone();
            tweak(&mut d.next);
            rebind(&mut d.statement, &d.next);
            let sig = sign_st(&f.recovery_a, &d.statement);
            assert!(matches!(
                verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
                Err(LiveQuorumError::RecoveryOutsideOwnSeat { .. })
            ));
        }
    }

    #[test]
    fn a_recovery_without_a_next_commitment_fails() {
        let f = recovery_fixture();
        let mut d = draft_a(&f, &f.next_commitment);
        d.statement
            .as_object_mut()
            .unwrap()
            .remove("next_recovery_commitment");
        let sig = sign_st(&f.recovery_a, &d.statement);
        assert!(matches!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::MalformedCommitment { .. })
        ));
    }

    #[test]
    fn a_recovery_signed_by_the_wrong_key_fails() {
        let f = recovery_fixture();
        let d = draft_a(&f, &f.next_commitment);

        // B1's recovery key presented for A1's seat: it is not A1's commitment.
        let sig = sign_st(&f.recovery_b, &d.statement);
        assert_eq!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_b.record(), &[sig]),
            Err(LiveQuorumError::RecoveryCommitmentMismatch)
        );

        // A1's recovery key presented, but B1's recovery key signed.
        let sig = sign_st(&f.recovery_b, &d.statement);
        assert!(matches!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryNotSoleSigner { .. })
        ));

        // A forged signature under A1's recovery key id by another key.
        let impostor = Holder::new("RA1");
        let sig = sign_st(&impostor, &d.statement);
        assert!(matches!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::Signature(_))
        ));

        // The lost signing key alone is not the recovery key.
        let sig = sign_st(&f.old_a, &d.statement);
        assert!(matches!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryNotSoleSigner { .. })
        ));
    }

    #[test]
    fn a_recovery_is_signed_under_the_recovery_key_alone() {
        let f = recovery_fixture();
        let d = draft_a(&f, &f.next_commitment);
        let sigs = vec![
            sign_st(&f.recovery_a, &d.statement),
            sign_st(&f.old_a, &d.statement),
        ];
        assert!(matches!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &sigs),
            Err(LiveQuorumError::RecoveryNotSoleSigner { .. })
        ));
    }

    #[test]
    fn a_recovery_signature_does_not_cover_a_tampered_statement() {
        let f = recovery_fixture();
        let d = draft_a(&f, &f.next_commitment);
        let sig = sign_st(&f.recovery_a, &d.statement);
        let other = Holder::new("RA3").record().commitment().unwrap();
        let tampered = draft_a(&f, &other);
        assert!(matches!(
            verify_a(
                &f,
                &tampered.next,
                &tampered.statement,
                &f.recovery_a.record(),
                &[sig]
            ),
            Err(LiveQuorumError::Signature(_))
        ));
    }

    #[test]
    fn a_holder_without_a_commitment_cannot_self_rotate() {
        let f = recovery_fixture();
        let lineage = genesis_lineage(&f);
        assert_eq!(
            recovery_commitment_in_force(&json!({}), &lineage, "A1").unwrap(),
            None
        );
        assert_eq!(
            recovery_commitment_in_force(&f.charter, &lineage, "Z9").unwrap(),
            None,
            "no seat, no commitment"
        );
        let d = draft_a(&f, &f.next_commitment);
        let sig = sign_st(&f.recovery_a, &d.statement);
        assert_eq!(
            verify_holder_recovery(
                &json!({}),
                &lineage,
                &d.next,
                &d.statement,
                &f.recovery_a.record(),
                &[sig],
                &f.directory,
            ),
            Err(LiveQuorumError::NoCommitmentInForce {
                holder_key_id: "A1".to_string()
            })
        );
    }

    #[test]
    fn build_refuses_an_unseated_holder_a_taken_seat_or_bad_commitment() {
        let f = recovery_fixture();
        let n = &f.next_commitment;
        assert!(matches!(
            build_holder_recovery(&f.standing, &request("Z9", "Z9n", "RZ9", n)),
            Err(LiveQuorumError::HolderNotSeated { .. })
        ));
        assert!(matches!(
            build_holder_recovery(&f.standing, &request("A1", "B1", "RA1", n)),
            Err(LiveQuorumError::RecoverySeatTaken { .. })
        ));
        assert!(matches!(
            build_holder_recovery(&f.standing, &request("A1", "A1n", "RA1", &"F".repeat(64))),
            Err(LiveQuorumError::MalformedCommitment { .. })
        ));
        let mut stale = f.standing.clone();
        stale.persist_row_hash = "0".repeat(64);
        assert!(matches!(
            build_holder_recovery(&stale, &request("A1", "A1n", "RA1", n)),
            Err(LiveQuorumError::RowHashMismatch { .. })
        ));
    }

    /// genesis A1,B1,C1 → A1 recovers (A1 → A1n, next RA2) → an ordinary roster
    /// change adds D1 → A1n recovers again (A1n → A1nn under RA2).
    struct TwoRecoveries {
        charter: Value,
        lineage: Vec<RosterVersion>,
        directory: Vec<ThresholdMember>,
        recovery_a: Holder,
        recovery_a2: Holder,
        next2: String,
        second: HolderRecoveryDraft,
    }

    fn two_recoveries() -> TwoRecoveries {
        let f = recovery_fixture();
        let recovery_a2 = Holder::new("RA2");
        let next1 = recovery_a2.record().commitment().unwrap();
        let mut directory = f.directory.clone();
        directory.push(Holder::new("D1").member());
        directory.push(Holder::new("A1nn").member());

        let v0 = f.standing.clone();
        let first = draft_a(&f, &next1);
        verify_holder_recovery(
            &f.charter,
            &genesis_lineage(&f),
            &first.next,
            &first.statement,
            &f.recovery_a.record(),
            &[sign_st(&f.recovery_a, &first.statement)],
            &directory,
        )
        .unwrap();
        let v1 = stored(first.next);
        let change = build_membership_change(
            &v1,
            &[DecidedSeatChange {
                change: adding(&["D1"]),
                decision: "d".repeat(64),
            }],
            &v1.charter_digest,
            at(T1),
        )
        .unwrap();
        let v2 = stored(change.next);
        let next2 = Holder::new("RA3").record().commitment().unwrap();
        let second = build_holder_recovery(&v2, &request("A1n", "A1nn", "RA2", &next2)).unwrap();
        TwoRecoveries {
            charter: f.charter,
            lineage: vec![
                RosterVersion {
                    family: v0,
                    change_envelope: None,
                },
                RosterVersion {
                    family: v1,
                    change_envelope: Some(first.statement),
                },
                RosterVersion {
                    family: v2,
                    change_envelope: Some(change.change_envelope),
                },
            ],
            directory,
            recovery_a: f.recovery_a,
            recovery_a2,
            next2,
            second,
        }
    }

    fn verify_second(
        t: &TwoRecoveries,
        lineage: &[RosterVersion],
        key: &Holder,
    ) -> Result<RecoveryVerdict, LiveQuorumError> {
        let mut statement = t.second.statement.clone();
        statement["recovery_key_id"] = json!(key.member_id);
        verify_holder_recovery(
            &t.charter,
            lineage,
            &t.second.next,
            &statement,
            &key.record(),
            &[sign_st(key, &statement)],
            &t.directory,
        )
    }

    #[test]
    fn a_second_recovery_spends_the_first_recoverys_commitment() {
        let t = two_recoveries();
        // In force: RA2's commitment from the first recovery, not the charter's.
        let in_force = recovery_commitment_in_force(&t.charter, &t.lineage, "A1n")
            .unwrap()
            .unwrap();
        assert_eq!(in_force, t.recovery_a2.record().commitment().unwrap());
        assert_ne!(
            Some(in_force.as_str()),
            t.charter[CHARTER_RECOVERY_COMMITMENTS_FIELD]["A1"].as_str()
        );

        let v = verify_second(&t, &t.lineage, &t.recovery_a2).unwrap();
        assert_eq!(v.new_signing_key_id, "A1nn");
        assert_eq!(v.next_commitment, t.next2);

        // The charter's (spent) recovery key is refused.
        assert_eq!(
            verify_second(&t, &t.lineage, &t.recovery_a),
            Err(LiveQuorumError::RecoveryKeySpent {
                key_id: "RA1".to_string()
            })
        );
    }

    // --- charter versions in link order (CC 4.2.6, rc20) ---------------------

    /// genesis A1,B1,C1 adopting charter G → A1 recovers under RA1 (A1 → A1n,
    /// next RA2) → a roster change adding D1 adopts a new charter.
    struct CharterAfterRecovery {
        genesis_charter: Value,
        lineage: Vec<RosterVersion>,
        directory: Vec<ThresholdMember>,
        recovery_a: Holder,
        recovery_a2: Holder,
    }

    fn charter_row(entries: Value, version: u32) -> Value {
        json!({
            "charter_version": version,
            CHARTER_RECOVERY_COMMITMENTS_FIELD: entries,
        })
    }

    fn row_digest(charter: &Value) -> String {
        crate::persist_canonical::persist_row_hash(charter).unwrap()
    }

    /// The lineage, with the third version adopting `new_charter`.
    fn charter_after_recovery(
        new_charter: impl Fn(&RecoveryFixture, &Holder) -> Value,
    ) -> (CharterAfterRecovery, Value) {
        let f = recovery_fixture();
        let recovery_a2 = Holder::new("RA2");
        let genesis_charter = charter_row(f.charter[CHARTER_RECOVERY_COMMITMENTS_FIELD].clone(), 1);
        let mut v0 = f.standing.clone();
        v0.charter_digest = row_digest(&genesis_charter);
        let v0 = stored(v0);
        let first = build_holder_recovery(
            &v0,
            &request(
                "A1",
                "A1n",
                "RA1",
                &recovery_a2.record().commitment().unwrap(),
            ),
        )
        .unwrap();
        let v1 = stored(first.next);
        let charter2 = new_charter(&f, &recovery_a2);
        let change = build_membership_change(
            &v1,
            &[DecidedSeatChange {
                change: adding(&["D1"]),
                decision: "d".repeat(64),
            }],
            &row_digest(&charter2),
            at(T1),
        )
        .unwrap();
        let mut directory = f.directory.clone();
        directory.push(Holder::new("D1").member());
        directory.push(Holder::new("A1nn").member());
        let lineage = vec![
            RosterVersion {
                family: v0,
                change_envelope: None,
            },
            RosterVersion {
                family: v1,
                change_envelope: Some(first.statement),
            },
            RosterVersion {
                family: stored(change.next),
                change_envelope: Some(change.change_envelope),
            },
        ];
        (
            CharterAfterRecovery {
                genesis_charter,
                lineage,
                directory,
                recovery_a: f.recovery_a,
                recovery_a2,
            },
            charter2,
        )
    }

    /// A1n → A1nn under `key`, verified over both charters in link order.
    fn recover_a1n(
        t: &CharterAfterRecovery,
        charters: &[Value],
        key: &Holder,
        next: &str,
    ) -> Result<RecoveryVerdict, LiveQuorumError> {
        let head = &t.lineage[2].family;
        let d = build_holder_recovery(head, &request("A1n", "A1nn", &key.member_id, next)).unwrap();
        verify_holder_recovery_with_charters(
            charters,
            &t.lineage,
            &d.next,
            &d.statement,
            &key.record(),
            &[sign_st(key, &d.statement)],
            &t.directory,
        )
    }

    #[test]
    fn a_new_charter_listing_a_fresh_entry_after_a_recovery_is_in_force() {
        let fresh = Holder::new("RA9");
        let fresh_c = fresh.record().commitment().unwrap();
        let (t, charter2) = charter_after_recovery(|f, _| {
            let mut e = f.charter[CHARTER_RECOVERY_COMMITMENTS_FIELD].clone();
            e["A1n"] = json!(fresh_c);
            e["D1"] = json!("d".repeat(64));
            charter_row(e, 2)
        });
        let charters = [t.genesis_charter.clone(), charter2];
        assert_eq!(
            recovery_commitment_in_force_with_charters(&charters, &t.lineage, "A1n").unwrap(),
            Some(fresh_c.clone())
        );
        // Before the charter version, the recovery's next commitment stood.
        assert_eq!(
            recovery_commitment_in_force_with_charters(&charters, &t.lineage[..2], "A1n").unwrap(),
            Some(t.recovery_a2.record().commitment().unwrap())
        );
        // D1, listed by the new charter only, reads it.
        assert_eq!(
            recovery_commitment_in_force_with_charters(&charters, &t.lineage, "D1").unwrap(),
            Some("d".repeat(64))
        );
        let next = Holder::new("RA10").record().commitment().unwrap();
        assert_eq!(
            recover_a1n(&t, &charters, &fresh, &next)
                .unwrap()
                .new_signing_key_id,
            "A1nn"
        );
        // The commitment the charter superseded no longer matches.
        assert_eq!(
            recover_a1n(&t, &charters, &t.recovery_a2, &next),
            Err(LiveQuorumError::RecoveryCommitmentMismatch)
        );
    }

    #[test]
    fn a_new_charter_copying_a_spent_entry_concludes_nothing() {
        let (t, charter2) = charter_after_recovery(|f, _| {
            // The genesis entries copied, and the spent RA1 listed for A1n too.
            let mut e = f.charter[CHARTER_RECOVERY_COMMITMENTS_FIELD].clone();
            e["A1n"] = e["A1"].clone();
            charter_row(e, 2)
        });
        let charters = [t.genesis_charter.clone(), charter2];
        let ra2 = t.recovery_a2.record().commitment().unwrap();
        // The recovery's next commitment stays in force.
        assert_eq!(
            recovery_commitment_in_force_with_charters(&charters, &t.lineage, "A1n").unwrap(),
            Some(ra2)
        );
        let next = Holder::new("RA3").record().commitment().unwrap();
        // The spent key is refused...
        assert_eq!(
            recover_a1n(&t, &charters, &t.recovery_a, &next),
            Err(LiveQuorumError::RecoveryKeySpent {
                key_id: "RA1".to_string()
            })
        );
        // ...and the unspent one rotates the seat.
        assert_eq!(
            recover_a1n(&t, &charters, &t.recovery_a2, &next)
                .unwrap()
                .next_commitment,
            next
        );
        // A recovery naming the spent commitment as its next one is refused.
        let spent = t.recovery_a.record().commitment().unwrap();
        assert_eq!(
            recover_a1n(&t, &charters, &t.recovery_a2, &spent),
            Err(LiveQuorumError::RecoveryReusesCommitment)
        );
    }

    #[test]
    fn a_charter_version_without_its_row_fails_closed() {
        let (t, _) = charter_after_recovery(|f, _| charter_row(f.charter.clone(), 2));
        assert_eq!(
            recovery_commitment_in_force_with_charters(
                std::slice::from_ref(&t.genesis_charter),
                &t.lineage,
                "A1n"
            ),
            Err(LiveQuorumError::CharterMissing {
                index: 2,
                charter_digest: t.lineage[2].family.charter_digest.clone(),
            })
        );
        // A row whose content was altered no longer hashes to the digest named.
        let mut altered = t.genesis_charter.clone();
        altered["charter_version"] = json!(9);
        assert!(matches!(
            recovery_commitment_in_force_with_charters(&[altered], &t.lineage[..1], "A1"),
            Err(LiveQuorumError::CharterMissing { index: 0, .. })
        ));
        // A broken link still fails closed before any charter is read.
        assert!(matches!(
            recovery_commitment_in_force_with_charters(
                std::slice::from_ref(&t.genesis_charter),
                &[t.lineage[0].clone(), t.lineage[2].clone()],
                "A1n"
            ),
            Err(LiveQuorumError::LineageIncomplete { .. })
        ));
    }

    #[test]
    fn a_key_seated_by_an_ordinary_change_reads_the_charter() {
        let t = two_recoveries();
        // D1 was seated by the ordinary change at v2: no recovery seated it.
        let charter = json!({ CHARTER_RECOVERY_COMMITMENTS_FIELD: { "D1": "d".repeat(64) } });
        assert_eq!(
            recovery_commitment_in_force(&charter, &t.lineage, "D1").unwrap(),
            Some("d".repeat(64))
        );
        // B1, seated at genesis and never recovered, reads the charter too.
        assert_eq!(
            recovery_commitment_in_force(&t.charter, &t.lineage, "B1").unwrap(),
            t.charter[CHARTER_RECOVERY_COMMITMENTS_FIELD]["B1"]
                .as_str()
                .map(str::to_string)
        );
    }

    #[test]
    fn an_incomplete_lineage_fails_closed() {
        let t = two_recoveries();
        let lineage_err = |lineage: &[RosterVersion]| {
            assert!(matches!(
                recovery_commitment_in_force(&t.charter, lineage, "A1n"),
                Err(LiveQuorumError::LineageIncomplete { .. })
            ));
            assert!(matches!(
                verify_second(&t, lineage, &t.recovery_a2),
                Err(LiveQuorumError::LineageIncomplete { .. })
            ));
            // Never the charter instead.
            assert!(matches!(
                verify_second(&t, lineage, &t.recovery_a),
                Err(LiveQuorumError::LineageIncomplete { .. })
            ));
        };
        // The first recovery is missing: v2 does not name v0.
        lineage_err(&[t.lineage[0].clone(), t.lineage[2].clone()]);
        // The lineage starts after genesis.
        lineage_err(&t.lineage[1..]);
        // A version (the first recovery) with no predecessor link.
        let mut unlinked = t.lineage.clone();
        unlinked[1].family.prev_head_digest = String::new();
        unlinked[1].family = stored(unlinked[1].family.clone());
        lineage_err(&unlinked);
        // A version linked by the digest of its predecessor's JCS bytes (the
        // superseded definition), not its persist_row_hash.
        let mut jcs_linked = t.lineage.clone();
        jcs_linked[1].family.prev_head_digest = hex::encode(Sha256::digest(
            t.lineage[0].family.record_signing_bytes().unwrap(),
        ));
        jcs_linked[1].family = stored(jcs_linked[1].family.clone());
        lineage_err(&jcs_linked);
        // Only the link wrong: the envelope is rebound to the tampered version,
        // so the prev_head_digest check alone refuses it.
        let mut link_only = t.lineage[..2].to_vec();
        link_only[1].family.prev_head_digest = "0".repeat(64);
        link_only[1].family = stored(link_only[1].family.clone());
        link_only[1].change_envelope.as_mut().unwrap()["next_persist_row_hash"] =
            json!(link_only[1].family.row_hash().unwrap());
        assert!(matches!(
            recovery_commitment_in_force(&t.charter, &link_only, "A1n"),
            Err(LiveQuorumError::LineageIncomplete { index: 1, .. })
        ));
        // A version without the envelope that admitted it.
        let mut bare = t.lineage.clone();
        bare[1].change_envelope = None;
        lineage_err(&bare);
        // An envelope that binds another version.
        let mut rebound = t.lineage.clone();
        rebound[2].change_envelope.as_mut().unwrap()["next_persist_row_hash"] =
            json!("0".repeat(64));
        lineage_err(&rebound);
        assert!(matches!(
            recovery_commitment_in_force(&t.charter, &[], "A1"),
            Err(LiveQuorumError::LineageIncomplete { index: 0, .. })
        ));
    }

    #[test]
    fn a_recovery_reusing_the_commitment_it_spends_concludes_nothing() {
        let f = recovery_fixture();
        let spent = f.recovery_a.record().commitment().unwrap();
        let d = draft_a(&f, &spent);
        let sig = sign_st(&f.recovery_a, &d.statement);
        assert_eq!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryReusesCommitment)
        );
    }

    #[test]
    fn a_recovery_naming_the_seated_key_concludes_nothing() {
        let f = recovery_fixture();
        assert_eq!(
            build_holder_recovery(&f.standing, &request("A1", "A1", "RA1", &f.next_commitment)),
            Err(LiveQuorumError::RecoveryReusesSigningKey {
                key_id: "A1".to_string()
            })
        );
        // Hand-built: the key stays A1.
        let mut d = draft_a(&f, &f.next_commitment);
        d.statement["new_holder_key_id"] = json!("A1");
        d.next.members[0].key_id = "A1".to_string();
        rebind(&mut d.statement, &d.next);
        let sig = sign_st(&f.recovery_a, &d.statement);
        assert_eq!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryReusesSigningKey {
                key_id: "A1".to_string()
            })
        );
    }

    #[test]
    fn a_recovery_must_name_the_standing_version() {
        let f = recovery_fixture();
        let d = draft_a(&f, &f.next_commitment);
        let mut st = d.statement.clone();
        st["prior_persist_row_hash"] = json!("0".repeat(64));
        let sig = sign_st(&f.recovery_a, &st);
        assert!(matches!(
            verify_a(&f, &d.next, &st, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryStatementUnbound { .. })
        ));
        let mut next = d.next.clone();
        next.prev_head_digest = "0".repeat(64);
        let mut st = d.statement.clone();
        rebind(&mut st, &next);
        let sig = sign_st(&f.recovery_a, &st);
        assert!(matches!(
            verify_a(&f, &next, &st, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryStatementUnbound { .. })
        ));
        // And the version it offers.
        let mut st = d.statement.clone();
        st["next_persist_row_hash"] = json!("0".repeat(64));
        let sig = sign_st(&f.recovery_a, &st);
        assert!(matches!(
            verify_a(&f, &d.next, &st, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::RecoveryStatementUnbound { .. })
        ));
    }

    #[test]
    fn a_spent_recovery_key_is_refused() {
        // The charter commits one recovery key for both A1 and B1; A1 recovers
        // under it; B1 then presents it.
        let f = recovery_fixture();
        let shared = f.recovery_a.record().commitment().unwrap();
        let charter = json!({ CHARTER_RECOVERY_COMMITMENTS_FIELD: { "A1": shared, "B1": shared } });
        let first = draft_a(&f, &f.next_commitment);
        let lineage = vec![
            genesis_lineage(&f).remove(0),
            RosterVersion {
                family: stored(first.next.clone()),
                change_envelope: Some(first.statement.clone()),
            },
        ];
        let next_b = Holder::new("RB2").record().commitment().unwrap();
        let d = build_holder_recovery(&lineage[1].family, &request("B1", "B1n", "RA1", &next_b))
            .unwrap();
        assert_eq!(
            verify_holder_recovery(
                &charter,
                &lineage,
                &d.next,
                &d.statement,
                &f.recovery_a.record(),
                &[sign_st(&f.recovery_a, &d.statement)],
                &f.directory,
            ),
            Err(LiveQuorumError::RecoveryKeySpent {
                key_id: "RA1".to_string()
            })
        );
    }

    #[test]
    fn a_new_key_that_is_not_registered_or_shares_a_seat_key_is_refused() {
        let f = recovery_fixture();
        let d = build_holder_recovery(
            &f.standing,
            &request("A1", "A1x", "RA1", &f.next_commitment),
        )
        .unwrap();
        let sig = sign_st(&f.recovery_a, &d.statement);
        assert!(matches!(
            verify_a(&f, &d.next, &d.statement, &f.recovery_a.record(), &[sig]),
            Err(LiveQuorumError::Structure(_))
        ));
        // A1x registered with B1's public key: one key, two seats.
        let mut dup = f.directory[1].clone();
        dup.member_id = "A1x".to_string();
        let mut directory = f.directory.clone();
        directory.push(dup);
        let sig = sign_st(&f.recovery_a, &d.statement);
        assert!(matches!(
            verify_holder_recovery(
                &f.charter,
                &genesis_lineage(&f),
                &d.next,
                &d.statement,
                &f.recovery_a.record(),
                &[sig],
                &directory,
            ),
            Err(LiveQuorumError::Structure(_))
        ));
    }
}
