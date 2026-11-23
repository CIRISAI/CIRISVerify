//! Whether a build pipeline's manifest row stands (FSD-008 Phase 1b; the
//! shapes as settled with CIRISConstitution 2026-11-22).
//!
//! One root only: the lineage of a genesis bundle. A pipeline is an ordinary
//! machine key (`node` or `agent`) with an ordinary owner-binding; there is
//! no pipeline key kind. A build row stands when every link below holds:
//!
//! 1. **The build row** ([`read_build_row`]): a `scores` row of family
//!    `provenance:build_manifest:{target}`, authored by the pipeline
//!    (`author` = `iss` = CWT `sub`), dimension
//!    `provenance:build_manifest:{target}:v1`, a closed `build` of exactly
//!    `project`, `version`, `manifest_hash` and `manifest_size` (at least 1),
//!    `evidence_refs` holding `manifest_hash`, and `refs.head` the bundle in
//!    force when it was signed: the grant's, or a later bundle of the grant's
//!    lineage ([`BundleLookup::descends`]). A later row by the same signer at the same
//!    (project, version, target) is a `supersedes` naming the earlier in
//!    `refs.target`, read by the same rules.
//! 2. **Row against blob** ([`check_blob`]): the blob's length is
//!    `manifest_size` (checked before hashing), its SHA-256 is
//!    `manifest_hash`, it decodes ([`super::build_manifest::decode`]), and its
//!    project, version and target are the row's.
//! 3. **The grant** ([`grant_counted`]): a `delegates_to` row, dimension
//!    `trust:confers:v1`, COUNTED (no `author`), the grantee its CWT `sub`. Its
//!    voices are statements over one row id, counted at a strict majority
//!    (`2·yes > N`) of the holders of the bundle its `refs.head` names, each
//!    voice a holder of that bundle under the key that bundle seats for it.
//!    The bundle is the caller's ([`BundleLookup`]): held (in force or a
//!    predecessor in the held lineage: a grant is counted where it was made
//!    and stands until ended), not held (Waiting), or on a fork the reader
//!    holds void (refused).
//! 4. **Scope and projects** ([`grant_confers_build`]): CC 4.5.5's check "may
//!    this key attest family F" ([`scope_satisfies`]), F =
//!    `provenance:build_manifest`; a pipeline's grant (one carrying
//!    `projects`) may carry only `infra:attest` and
//!    `infra:attest:provenance:build_manifest`; `build.project` is among
//!    `projects`.
//! 5. **The owner's answer** ([`read_answer`]): the grantee's owner, read
//!    from the owner-binding the caller supplies ([`OwnerBinding`]), accepts
//!    the grant by a `membership:acceptance:v1` row whose `refs.answers` names
//!    it (the reply's shape is the statement reader's,
//!    `family_shapes::check_reply`). A `membership:decline:v1` alone is
//!    terminal for that grant (`grant_declined`; the holders grant again). An
//!    acceptance and a decline both standing are contested (`grant_contested`,
//!    CC 3.1.3.2, CC 2.7.7 rule 6): neither counts until the owner withdraws
//!    one, and then the other decides. Rows carry no arrival order, so an
//!    acceptance appearing after a decline is that same contested case.
//! 6. **How a grant ends**: a counted `withdraws` of the grant row by a strict
//!    majority of the holders of the bundle it names in `refs.head`
//!    ([`read_grant_withdrawal`]), or the owner's own `withdraws` of the
//!    acceptance ([`read_reply_withdrawal`]). Either ends that one grant.
//! 7. **Row state** ([`build_row_state`]): the pipeline's `withdraws` of the
//!    build row (withdrawn), a `supersedes` of it at the same
//!    (project, version, target) (superseded), or another standing row of the
//!    signer at the same three whose `build` differs outside one `supersedes`
//!    chain (`build_manifest_equivocation`, CC 2.7.7 rule 2). When the caller
//!    holds no view of the composers the verdict still stands on a verified
//!    manifest, and says `withdrawal_state: unknown` beside it.
//!
//! The two answers other callers want separately are public on their own:
//! [`grant_counted`] (is the grant counted?) and [`grant_in_force`] (is the
//! counted grant in force: links 5 and 6). Each reads the statements and
//! then asks one plain-id function for the decision,
//! [`super::count::strict_majority`] and [`super::count::conferral_in_force`].
//!
//! [`evaluate_build_standing`] runs them all and answers flat, measurement
//! named fields ([`BuildStanding`]) beside one `stands` and, when it does not
//! stand, one refusal token or the list of what it waits on.
//!
//! **The owner-binding** is a caller-supplied, already verified input. Verify
//! has no edition-2 reader of the owner-binding row (CC 3.2: a
//! `delegates_to(owner → K)` carrying `delegation_purpose: "owner_binding"`,
//! read by `owner_of(K)`), so the caller states `owner_of(K)` for the
//! pipeline's key and this module checks the acceptance against it.
//!
//! Pure: no clock, no randomness, no I/O. Key records reach the readers
//! through the caller's [`KeyDirectory`], which reads instants from the rows.

use super::accord_halt::{invalid_token, named_head, RosterHolder};
use super::build_manifest::{self, BinaryManifest, BlobError};
use super::count::InForce;
use super::family::select::Act;
use super::family::{
    row_leaf, verify_row_in_family, verify_row_in_family_with, FamilyFault, FamilyVerdict,
    SelectContext, TargetRow, VendoredFamilyModel,
};
use super::{
    identity_ref_thumbprint, is_identity_ref, Digest32, Invalid, KeyDirectory, KeyLookup, KeyOf,
    MissingKey, Value, VerifiedRow,
};
use crate::cde;
use crate::prelude::*;
use ciris_crypto::composite::CompositePublicKey;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

/// The family id of `provenance:build_manifest:{target}`.
pub const BUILD_FAMILY: &str = "provenance:build_manifest:.target";
/// The family a build row attests, as CC 4.5.5's scope check names it.
pub const BUILD_ATTEST_FAMILY: &str = "provenance:build_manifest";
/// The family id of `trust:{job}:{version}`, the grant's.
pub const GRANT_FAMILY: &str = "trust:.job:.version";
/// The grant's dimension.
pub const GRANT_DIMENSION: &str = "trust:confers:v1";
/// The family id of `membership:{stage}`, the owner's answer's.
pub const ANSWER_FAMILY: &str = "membership:.stage";
/// The acceptance's dimension.
pub const ACCEPTANCE_DIMENSION: &str = "membership:acceptance:v1";
/// The decline's dimension.
pub const DECLINE_DIMENSION: &str = "membership:decline:v1";
/// The capability to attest (CC 4.5.5): held bare, it satisfies every attest
/// family.
pub const SCOPE_ATTEST: &str = "infra:attest";
/// The narrowest scope a build pipeline's grant carries.
pub const SCOPE_ATTEST_BUILD: &str = "infra:attest:provenance:build_manifest";
/// The only scopes a pipeline's grant (one carrying `projects`) may carry.
pub const PIPELINE_SCOPES: [&str; 2] = [SCOPE_ATTEST, SCOPE_ATTEST_BUILD];

const DESCRIPTOR_MEMBERS: [&str; 4] = ["project", "version", "manifest_hash", "manifest_size"];

// ---------------------------------------------------------------- the scope

/// CC 4.5.5's check: may a key holding `held` attest family `family`?
///
/// A held `infra:attest` satisfies it, and a held `infra:attest:{family}`
/// satisfies it; nothing else does. The match is on whole tokens: a child
/// never satisfies its parent (`infra:attest:F:x` does not satisfy F), and a
/// prefix is not a token (`infra:attest_assurance` is another capability,
/// `infra:attest:F_x` another family).
#[must_use]
pub fn scope_satisfies(held: &str, family: &str) -> bool {
    held == SCOPE_ATTEST
        || held
            .strip_prefix(SCOPE_ATTEST)
            .and_then(|r| r.strip_prefix(':'))
            .is_some_and(|f| f == family)
}

// ---------------------------------------------------------------- readings

/// Which row a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// The build row, or a build row of the composers view.
    BuildRow,
    /// A statement of the grant.
    Grant,
    /// A statement of a counted withdrawal of the grant.
    GrantWithdrawal,
    /// The owner's acceptance or decline.
    Answer,
    /// The owner's withdrawal of the acceptance.
    AnswerWithdrawal,
    /// An owner-binding row ([`read_owner_binding`]).
    OwnerBinding,
}

impl Part {
    /// The part's name in tokens.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuildRow => "build_row",
            Self::Grant => "grant",
            Self::GrantWithdrawal => "grant_withdrawal",
            Self::Answer => "acceptance",
            Self::AnswerWithdrawal => "acceptance_withdrawal",
            Self::OwnerBinding => "owner_binding",
        }
    }
}

/// Why a build row does not stand. Every refusal has a stable
/// [`token`](StandingRefusal::token).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StandingRefusal {
    /// The statement itself is Invalid (CC 2.6.1):
    /// `{part}_statement_invalid:{reason}`.
    Statement {
        /// Which row.
        part: Part,
        /// The row reader's reason.
        invalid: Invalid,
    },
    /// The statement breaks its family's rules: `{part}_family:{fault}`.
    Family {
        /// Which row.
        part: Part,
        /// The family fault.
        fault: FamilyFault,
    },
    /// A member is missing, malformed, or outside the closed payload:
    /// `{part}_malformed:{member}`.
    Malformed {
        /// Which row.
        part: Part,
        /// The member.
        member: &'static str,
    },
    /// A set member is unsorted or repeats an element (CC 2.6.1.2):
    /// `{part}_set_order:{member}`.
    SetOrder {
        /// Which row.
        part: Part,
        /// The member.
        member: &'static str,
    },
    /// The row type or the family is not this reading's:
    /// `{part}_wrong_row`.
    WrongRow {
        /// Which row.
        part: Part,
    },
    /// A statement under a key the named bundle seats, whose `iss` is not
    /// the holder seated there: `{part}_voice_not_holder`.
    VoiceNotHolder {
        /// Which row.
        part: Part,
    },
    /// A statement over another row than the one counted: `{part}_other_row`.
    OtherRow {
        /// Which row.
        part: Part,
    },
    /// The bundle `refs.head` names is on a fork the reader holds void:
    /// `{part}_head_void_fork`.
    HeadVoidFork {
        /// Which row.
        part: Part,
    },
    /// The blob is not the one the row describes (length, digest, project,
    /// version or target): `build_manifest_descriptor_mismatch`.
    DescriptorMismatch {
        /// `manifest_size`, `manifest_hash`, `project`, `version` or `target`.
        member: &'static str,
    },
    /// The blob is refused by its codec: the codec's token.
    Blob(BlobError),
    /// The grant's grantee (CWT `sub`) is not the build row's signer:
    /// `grant_other_grantee`.
    GrantOtherGrantee,
    /// The build row's `refs.head` is neither the bundle the grant names nor
    /// a later bundle of its lineage: `build_row_other_head`.
    BuildRowOtherHead,
    /// A pipeline's grant carries a scope other than [`PIPELINE_SCOPES`]:
    /// `pipeline_grant_out_of_role`.
    PipelineGrantOutOfRole,
    /// No scope the grant carries satisfies `provenance:build_manifest`:
    /// `build_manifest_scope_not_granted`.
    ScopeNotGranted,
    /// `build.project` is not among the grant's `projects`, or the grant
    /// carries none: `build_manifest_project_not_granted`.
    ProjectNotGranted,
    /// A counted withdrawal of the grant by a strict majority of the holders
    /// of the bundle it names: `grant_withdrawn`.
    GrantWithdrawn,
    /// The owner declined the grant: `grant_declined`. A decline is terminal
    /// for that grant; the holders grant again.
    GrantDeclined,
    /// An acceptance and a decline of the grant by the owner both stand
    /// (CC 3.1.3.2, CC 2.7.7 rule 6): neither counts, so the grant confers
    /// nothing until the owner withdraws one: `grant_contested`.
    GrantContested,
    /// The owner withdrew the acceptance: `acceptance_withdrawn`.
    AcceptanceWithdrawn,
    /// The answer is signed by the grantee's own key, never its owner's:
    /// `acceptance_by_grantee`.
    AcceptanceByGrantee,
    /// The answer's author is not the owner the owner-binding names:
    /// `acceptance_not_by_owner`.
    AcceptanceNotByOwner,
    /// The owner-binding supplied names another key than the grantee:
    /// `owner_binding_other_key`.
    OwnerBindingOtherKey,
    /// The acceptance cites no owner-binding, another held binding of the
    /// key than the one supplied, or two of them (a re-binding needs a new
    /// acceptance): `acceptance_other_binding`.
    AcceptanceOtherBinding,
    /// The build row names no acceptance in `refs.also.stands_on`, or names
    /// a row that is not the owner's acceptance of this grant: it counts for
    /// nobody. `build_row_stands_on_nothing`.
    BuildRowStandsOnNothing,
    /// The answer's `refs.answers` names another row than the grant:
    /// `acceptance_other_grant`.
    AcceptanceOtherGrant,
    /// The answer's CWT `sub` is not the grantee: `acceptance_other_grantee`.
    AcceptanceOtherGrantee,
    /// The pipeline withdrew the build row: `build_manifest_withdrawn`.
    BuildWithdrawn,
    /// The build row is superseded at the same (project, version, target):
    /// `build_manifest_superseded`.
    BuildSuperseded,
    /// Another standing row of the signer at the same (project, version,
    /// target) with a different `build`, outside one `supersedes` chain:
    /// `build_manifest_equivocation`.
    Equivocation,
}

impl StandingRefusal {
    /// The stable token.
    #[must_use]
    pub fn token(&self) -> String {
        match self {
            Self::Statement { part, invalid } => {
                format!(
                    "{}_statement_invalid:{}",
                    part.as_str(),
                    invalid_token(invalid)
                )
            },
            Self::Family { part, fault } => format!("{}_family:{}", part.as_str(), fault.token()),
            Self::Malformed { part, member } => format!("{}_malformed:{member}", part.as_str()),
            Self::SetOrder { part, member } => format!("{}_set_order:{member}", part.as_str()),
            Self::WrongRow { part } => format!("{}_wrong_row", part.as_str()),
            Self::VoiceNotHolder { part } => format!("{}_voice_not_holder", part.as_str()),
            Self::OtherRow { part } => format!("{}_other_row", part.as_str()),
            Self::HeadVoidFork { part } => format!("{}_head_void_fork", part.as_str()),
            Self::DescriptorMismatch { .. } => "build_manifest_descriptor_mismatch".into(),
            Self::Blob(e) => e.token().into(),
            Self::GrantOtherGrantee => "grant_other_grantee".into(),
            Self::BuildRowOtherHead => "build_row_other_head".into(),
            Self::PipelineGrantOutOfRole => "pipeline_grant_out_of_role".into(),
            Self::ScopeNotGranted => "build_manifest_scope_not_granted".into(),
            Self::ProjectNotGranted => "build_manifest_project_not_granted".into(),
            Self::GrantWithdrawn => "grant_withdrawn".into(),
            Self::GrantDeclined => "grant_declined".into(),
            Self::GrantContested => "grant_contested".into(),
            Self::AcceptanceWithdrawn => "acceptance_withdrawn".into(),
            Self::AcceptanceByGrantee => "acceptance_by_grantee".into(),
            Self::AcceptanceNotByOwner => "acceptance_not_by_owner".into(),
            Self::OwnerBindingOtherKey => "owner_binding_other_key".into(),
            Self::AcceptanceOtherBinding => "acceptance_other_binding".into(),
            Self::BuildRowStandsOnNothing => "build_row_stands_on_nothing".into(),
            Self::AcceptanceOtherGrant => "acceptance_other_grant".into(),
            Self::AcceptanceOtherGrantee => "acceptance_other_grantee".into(),
            Self::BuildWithdrawn => "build_manifest_withdrawn".into(),
            Self::BuildSuperseded => "build_manifest_superseded".into(),
            Self::Equivocation => "build_manifest_equivocation".into(),
        }
    }

    /// The member a descriptor mismatch or a malformed member names, or the
    /// blob codec's detail.
    #[must_use]
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            Self::DescriptorMismatch { member }
            | Self::Malformed { member, .. }
            | Self::SetOrder { member, .. } => Some(member),
            Self::Blob(e) => e.detail(),
            _ => None,
        }
    }
}

/// What a reading that is not yet decided waits on. Waiting is retryable:
/// hold what it names and read again.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum StandingWait {
    /// A key, a covering record, a record link or a voice the row reader
    /// names ([`MissingKey`]). A grant short of its count waits on the
    /// [`MissingKey::Voice`] of each holder not yet heard (a counted row
    /// gains voices without changing its row id, CC 2.6.1.9).
    Key(MissingKey),
    /// A bundle `refs.head` names that the reader does not hold.
    Bundle(Digest32),
    /// No statement of the grant was supplied.
    Grant,
    /// No acceptance answering the grant was supplied.
    Acceptance,
    /// No owner-binding of the grantee was supplied.
    OwnerBinding,
}

impl StandingWait {
    /// A stable token: `key`, `voice`, `record`, `row`, `bundle`, `grant`,
    /// `acceptance` or `owner_binding`.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::Key(MissingKey::Voice { .. }) => "voice",
            Self::Key(MissingKey::Record(_)) => "record",
            Self::Key(MissingKey::Row(_)) => "row",
            Self::Key(_) => "key",
            Self::Bundle(_) => "bundle",
            Self::Grant => "grant",
            Self::Acceptance => "acceptance",
            Self::OwnerBinding => "owner_binding",
        }
    }
}

/// The answer of each reader here: Valid, Waiting (retryable) or Refused.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading<T> {
    /// The row verifies and holds every rule of this reading.
    Valid(T),
    /// The reading waits on what is named; sorted, once each.
    Waiting(Vec<StandingWait>),
    /// The row is refused.
    Refused(StandingRefusal),
}

impl<T> Reading<T> {
    /// `valid`, `waiting:{token+token}` or `refused:{token}`.
    #[must_use]
    pub fn token(&self) -> String {
        match self {
            Self::Valid(_) => "valid".into(),
            Self::Waiting(w) => format!("waiting:{}", wait_tokens(w)),
            Self::Refused(r) => format!("refused:{}", r.token()),
        }
    }
}

fn wait_tokens(w: &[StandingWait]) -> String {
    let set: BTreeSet<&str> = w.iter().map(StandingWait::token).collect();
    set.into_iter().collect::<Vec<_>>().join("+")
}

fn waiting<T>(mut w: Vec<StandingWait>) -> Reading<T> {
    w.sort_unstable();
    w.dedup();
    Reading::Waiting(w)
}

macro_rules! valid_or_return {
    ($e:expr) => {
        match $e {
            Reading::Valid(v) => v,
            Reading::Waiting(w) => return Reading::Waiting(w),
            Reading::Refused(r) => return Reading::Refused(r),
        }
    };
}

fn from_family(part: Part, v: FamilyVerdict) -> Reading<VerifiedRow> {
    match v {
        FamilyVerdict::Valid { row, .. } => Reading::Valid(*row),
        // A reply's shape is checked by the statement reader
        // (`family_shapes::check_reply`); its member is reported as the
        // reply's.
        FamilyVerdict::Invalid(Invalid::Malformed { member }) if part == Part::Answer => {
            Reading::Refused(StandingRefusal::Malformed { part, member })
        },
        FamilyVerdict::Invalid(invalid) => {
            Reading::Refused(StandingRefusal::Statement { part, invalid })
        },
        FamilyVerdict::FamilyInvalid(fault) => {
            Reading::Refused(StandingRefusal::Family { part, fault })
        },
        FamilyVerdict::Waiting(m) => waiting(m.into_iter().map(StandingWait::Key).collect()),
    }
}

// ---------------------------------------------------------------- members

fn closed(part: Part, p: &Value, allowed: &[&str]) -> Result<(), StandingRefusal> {
    let m = p.as_map().ok_or(StandingRefusal::Malformed {
        part,
        member: "payload",
    })?;
    for (k, _) in m {
        match k.as_text() {
            Some(n) if allowed.contains(&n) => {},
            _ => {
                return Err(StandingRefusal::Malformed {
                    part,
                    member: "closed_map",
                })
            },
        }
    }
    Ok(())
}

fn digest_of(v: &Value) -> Option<Digest32> {
    match v.as_array()? {
        [alg, d] if alg.as_i64() == Some(-16) => d.as_bytes()?.try_into().ok(),
        _ => None,
    }
}

fn row_ref_of(v: &Value) -> Option<Digest32> {
    match v.as_array()? {
        [ed, id] if ed.as_u64() == Some(super::EDITION) => digest_of(id),
        _ => None,
    }
}

fn refs_member(p: &Value, name: &str) -> Option<Digest32> {
    p.get_text("refs")?.get_text(name).and_then(row_ref_of)
}

/// A set of text in CC 2.6.1.2 set order: non-empty, each element's
/// deterministic encoding strictly increasing.
fn text_set(part: Part, v: &Value, member: &'static str) -> Result<Vec<String>, StandingRefusal> {
    let a = v
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or(StandingRefusal::Malformed { part, member })?;
    let mut out = Vec::with_capacity(a.len());
    for x in a {
        out.push(
            x.as_text()
                .ok_or(StandingRefusal::Malformed { part, member })?
                .to_owned(),
        );
    }
    let enc: Vec<Vec<u8>> = a.iter().map(cde::encode).collect();
    if enc.windows(2).all(|w| w[0] < w[1]) {
        Ok(out)
    } else {
        Err(StandingRefusal::SetOrder { part, member })
    }
}

// ---------------------------------------------------------------- build row

/// A build row that reads Valid under its family and its own rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRow {
    /// The verified statement.
    pub row: VerifiedRow,
    /// `scores` (the first row) or `supersedes` (a later one).
    pub superseding: Option<Digest32>,
    /// `build.project`.
    pub project: String,
    /// `build.version`.
    pub version: String,
    /// The dimension's `{target}`.
    pub target: String,
    /// `build.manifest_hash`.
    pub manifest_hash: Digest32,
    /// `build.manifest_size`.
    pub manifest_size: u64,
    /// `refs.head`.
    pub head: Digest32,
    /// `refs.also.stands_on`: the owner's acceptance of the grant the row
    /// stands on (CC 3.1.2.1, two standings). `None`: it stands on none.
    pub stands_on: Option<Digest32>,
}

impl BuildRow {
    /// The row id.
    #[must_use]
    pub fn row_id(&self) -> &Digest32 {
        &self.row.row_id
    }

    /// The signer's identity reference (`author` = `iss` = `sub`).
    #[must_use]
    pub fn pipeline(&self) -> &str {
        &self.row.iss
    }

    /// Whether `other` is a row of the same signer at the same (project,
    /// version, target).
    #[must_use]
    pub fn same_slot(&self, other: &BuildRow) -> bool {
        self.row.iss == other.row.iss
            && self.project == other.project
            && self.version == other.version
            && self.target == other.target
    }

    fn same_build(&self, other: &BuildRow) -> bool {
        self.project == other.project
            && self.version == other.version
            && self.manifest_hash == other.manifest_hash
            && self.manifest_size == other.manifest_size
    }

    fn as_target(&self) -> TargetRow {
        TargetRow {
            row_id: self.row.row_id,
            family_id: self.row.family.clone(),
            payload: self.row.payload.clone(),
        }
    }
}

/// Read one build-row statement (a `scores` row, or the `supersedes` of a
/// later build at the same (project, version, target)) under `keys`, which
/// holds the pipeline's key record: the row reader, CC's vendored family
/// model (authored, no second signer), then the row's own shape.
pub fn read_build_row(statement: &[u8], keys: &dyn KeyDirectory) -> Reading<BuildRow> {
    let part = Part::BuildRow;
    let row = valid_or_return!(from_family(
        part,
        verify_row_in_family(statement, keys, &VendoredFamilyModel)
    ));
    build_row_shape(row).into()
}

impl<T> From<Result<T, StandingRefusal>> for Reading<T> {
    fn from(r: Result<T, StandingRefusal>) -> Self {
        match r {
            Ok(v) => Self::Valid(v),
            Err(e) => Self::Refused(e),
        }
    }
}

fn build_row_shape(row: VerifiedRow) -> Result<BuildRow, StandingRefusal> {
    let part = Part::BuildRow;
    let m = |member| StandingRefusal::Malformed { part, member };
    if row.family != BUILD_FAMILY || !matches!(row.row_type.as_str(), "scores" | "supersedes") {
        return Err(StandingRefusal::WrongRow { part });
    }
    let p = &row.payload;
    // The family model already holds `author` = `iss`; the subject is the
    // signer too.
    if row.author.as_deref() != Some(row.sub.as_str()) {
        return Err(m("sub"));
    }
    // The dimension is the family's own, version 1: exactly
    // `provenance:build_manifest:{target}:v1`.
    let target = row_leaf(&row).ok_or(m("dimension"))?;
    let dim = p.get_text("dimension").and_then(Value::as_text);
    if dim != Some(format!("{BUILD_ATTEST_FAMILY}:{target}:v1").as_str()) {
        return Err(m("dimension"));
    }
    let build = p.get_text("build").ok_or(m("build"))?;
    // Closed and complete: exactly the four members.
    closed(part, build, &DESCRIPTOR_MEMBERS).map_err(|_| m("build"))?;
    if build.as_map().map(<[_]>::len) != Some(DESCRIPTOR_MEMBERS.len()) {
        return Err(m("build"));
    }
    let field = |k: &'static str| build.get_text(k).ok_or(m(k));
    let project = field("project")?
        .as_text()
        .filter(|s| {
            (1..=build_manifest::MAX_DESCRIPTOR_LEN).contains(&s.len())
                && s.bytes()
                    .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        })
        .ok_or(m("project"))?
        .to_owned();
    let version = field("version")?
        .as_text()
        .filter(|s| (1..=build_manifest::MAX_DESCRIPTOR_LEN).contains(&s.len()))
        .ok_or(m("version"))?
        .to_owned();
    let manifest_hash = digest_of(field("manifest_hash")?).ok_or(m("manifest_hash"))?;
    let manifest_size = field("manifest_size")?
        .as_u64()
        .filter(|n| *n >= 1)
        .ok_or(m("manifest_size"))?;
    let evidence = p
        .get_text("evidence_refs")
        .and_then(Value::as_array)
        .ok_or(m("evidence_refs"))?;
    if !evidence
        .iter()
        .any(|e| digest_of(e).is_some_and(|d| bool::from(d.ct_eq(&manifest_hash))))
    {
        return Err(m("evidence_refs"));
    }
    let head = refs_member(p, "head").ok_or(m("refs.head"))?;
    let superseding = match row.row_type.as_str() {
        "supersedes" => Some(refs_member(p, "target").ok_or(m("refs.target"))?),
        _ => None,
    };
    // A set of exactly one row-ref; the statement reader checks the shape.
    let stands_on = p
        .get_text("refs")
        .and_then(|r| r.get_text("also"))
        .and_then(|a| a.get_text("stands_on"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(row_ref_of);
    Ok(BuildRow {
        row,
        superseding,
        stands_on,
        project,
        version,
        target,
        manifest_hash,
        manifest_size,
        head,
    })
}

// ---------------------------------------------------------------- the blob

/// Check the blob against the row that cites it: its length is
/// `manifest_size` (before any hashing), its SHA-256 is `manifest_hash` (in
/// constant time), it decodes as `ciris-binary-manifest/1`, and its project,
/// version and target are the row's. Every mismatch is
/// `build_manifest_descriptor_mismatch`, naming the member.
pub fn check_blob(row: &BuildRow, blob: &[u8]) -> Result<BinaryManifest, StandingRefusal> {
    let mismatch = |member| StandingRefusal::DescriptorMismatch { member };
    if u64::try_from(blob.len()).ok() != Some(row.manifest_size) {
        return Err(mismatch("manifest_size"));
    }
    let d: Digest32 = Sha256::digest(blob).into();
    if !bool::from(d.ct_eq(&row.manifest_hash)) {
        return Err(mismatch("manifest_hash"));
    }
    let m = build_manifest::decode(blob).map_err(StandingRefusal::Blob)?;
    for (member, a, b) in [
        ("project", &m.project, &row.project),
        ("version", &m.version, &row.version),
        ("target", &m.target, &row.target),
    ] {
        if a.as_bytes() != b.as_bytes() {
            return Err(mismatch(member));
        }
    }
    Ok(m)
}

// ---------------------------------------------------------------- bundles

/// The holders of one bundle, as the grant and its withdrawal are counted
/// over them. A [`KeyDirectory`] of the holders' seated keys: a holder's key
/// is its holder's ([`KeyDirectory::key_of`]), and no other key is held.
#[derive(Debug, Clone)]
pub struct BundleRoster {
    bundle: Digest32,
    holders: Vec<(String, Digest32, CompositePublicKey)>,
}

impl BundleRoster {
    /// A roster from the bundle's object id and its holders, each at the
    /// composite key the bundle seats for it; a repeated identity reference
    /// is kept once.
    #[must_use]
    pub fn new(bundle: Digest32, holders: Vec<RosterHolder>) -> Self {
        let mut hs: Vec<(String, Digest32, CompositePublicKey)> = Vec::new();
        for h in holders {
            if !hs.iter().any(|(r, ..)| *r == h.identity_ref) {
                let kid = super::thumbprint(&h.key);
                hs.push((h.identity_ref, kid, h.key));
            }
        }
        Self {
            bundle,
            holders: hs,
        }
    }

    /// The roster of a valid bundle's placement.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn from_placement(p: &super::genesis::GenesisPlacement) -> Self {
        Self::new(
            p.object_id,
            p.holders
                .iter()
                .map(|h| RosterHolder {
                    identity_ref: h.identity_ref.clone(),
                    key: h.key.clone(),
                })
                .collect(),
        )
    }

    /// The bundle's object id.
    #[must_use]
    pub fn bundle(&self) -> &Digest32 {
        &self.bundle
    }

    /// N: the number of holders.
    #[must_use]
    pub fn len(&self) -> usize {
        self.holders.len()
    }

    /// Whether the roster has no holder.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.holders.is_empty()
    }

    fn holder_of_kid(&self, kid: &Digest32) -> Option<&str> {
        self.holders
            .iter()
            .find(|(_, k, _)| k == kid)
            .map(|(r, ..)| r.as_str())
    }
}

impl KeyDirectory for BundleRoster {
    fn lookup(&self, kid: &Digest32, _asserted_at: u64) -> KeyLookup {
        self.holders
            .iter()
            .find(|(_, k, _)| k == kid)
            .map_or(KeyLookup::NotHeld, |(.., pk)| {
                KeyLookup::Held(Box::new(pk.clone()))
            })
    }

    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> KeyOf {
        match self.holder_of_kid(kid).and_then(identity_ref_thumbprint) {
            Some(h) if bool::from(h.ct_eq(iss)) => KeyOf::Yes,
            _ => KeyOf::No,
        }
    }
}

/// What the reader holds of a bundle named in `refs.head`.
#[derive(Debug, Clone)]
pub enum BundleView {
    /// The bundle is held in the reader's lineage: the bundle in force or a
    /// predecessor of it. A row counted under it was counted where it was
    /// made.
    Holders(BundleRoster),
    /// The reader does not hold the bundle: a row counted over it waits.
    NotHeld,
    /// The bundle is on a fork the reader holds void: a row counted over it
    /// is refused.
    VoidFork,
}

/// Whether one bundle is the same as, or descends from, another in a
/// lineage the reader holds ([`BundleLookup::descends`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Descent {
    /// `head` is `from`, or a later bundle of `from`'s lineage (following
    /// `prev` from `head` reaches `from`).
    SameOrLater,
    /// `head` is held and is neither: an older bundle than `from`, or one on
    /// another lineage or another fork.
    Not,
    /// The reader does not hold `head` (or a bundle between it and `from`).
    NotHeld,
}

/// The caller's view of bundles by object id. Pure and caller-supplied: the
/// caller holds the lineages (from `edition2::genesis` under `std`).
pub trait BundleLookup {
    /// What the reader holds of the bundle `head`.
    fn view(&self, head: &Digest32) -> BundleView;

    /// Is `head` the same bundle as `from`, or a later bundle of the same
    /// lineage? A build row names the bundle in force when it was signed, so
    /// its `refs.head` is the grant's or descends from it (a grant counted
    /// under bundle 3 stands under bundle 5).
    fn descends(&self, head: &Digest32, from: &Digest32) -> Descent;
}

// ---------------------------------------------------------------- counting

/// A counted row: its voices met a strict majority of the bundle it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountedRow {
    /// One verified statement of the row (the first counted).
    pub row: VerifiedRow,
    /// `refs.head`: the bundle counted over.
    pub head: Digest32,
    /// The holders counted, sorted, once each.
    pub voices: Vec<String>,
    /// N, the holders of that bundle.
    pub roster_size: usize,
    /// Statements not counted, by input index, and why.
    pub refused: Vec<(usize, StandingRefusal)>,
    /// Statements under keys the named bundle does not seat: not voices.
    pub not_voices: usize,
}

/// A bundle's holders as (identity reference, seated key's thumbprint).
type HolderIds = Vec<(String, Digest32)>;

fn holder_ids(roster: &BundleRoster) -> HolderIds {
    roster
        .holders
        .iter()
        .map(|(r, k, _)| (r.clone(), *k))
        .collect()
}

/// The row id of a statement read without verifying it: only to name the
/// row a waited-on voice would be over.
fn unverified_row_id(statement: &[u8]) -> Option<Digest32> {
    let Value::Tag(18, inner) = cde::decode(statement).ok()? else {
        return None;
    };
    let a = inner.as_array()?;
    let prot = cde::decode(a.first()?.as_bytes()?).ok()?;
    let payload_b = a.get(2)?.as_bytes()?;
    let payload = cde::decode(payload_b).ok()?;
    let rtype = prot.get_int(-70001)?.as_text()?;
    let family = prot.get_int(-70002)?.as_text()?;
    let sub = prot.get_int(15)?.get_int(2)?.as_text()?;
    let author = payload.get_text("author").and_then(Value::as_text);
    Some(super::row_id(rtype, family, sub, author, payload_b))
}

/// Count the statements of one counted row over the bundles their `refs.head`
/// names. `shape` checks a valid voice's row beyond the family rules.
fn count_row(
    part: Part,
    statements: &[&[u8]],
    bundles: &dyn BundleLookup,
    ctx: &SelectContext,
    shape: &dyn Fn(&VerifiedRow) -> Result<(), StandingRefusal>,
) -> Reading<CountedRow> {
    let ctx = SelectContext {
        act: ctx.act.or(Some(Act::Group)),
        ..ctx.clone()
    };
    let mut refused: Vec<(usize, StandingRefusal)> = Vec::new();
    let mut waits: Vec<StandingWait> = Vec::new();
    let mut not_voices = 0usize;
    // Rows heard only from keys the named bundle does not seat: no voice
    // yet, but a holder's may still arrive (CC 2.6.1.9).
    let mut unheard_rows: Vec<(Digest32, HolderIds)> = Vec::new();
    let mut voices: Vec<(usize, VerifiedRow, Digest32, HolderIds)> = Vec::new();
    for (i, s) in statements.iter().enumerate() {
        let Some(head) = named_head(s) else {
            refused.push((
                i,
                StandingRefusal::Malformed {
                    part,
                    member: "refs.head",
                },
            ));
            continue;
        };
        let roster = match bundles.view(&head) {
            BundleView::Holders(r) => r,
            BundleView::NotHeld => {
                waits.push(StandingWait::Bundle(head));
                continue;
            },
            BundleView::VoidFork => {
                refused.push((i, StandingRefusal::HeadVoidFork { part }));
                continue;
            },
        };
        match verify_row_in_family_with(s, &roster, &VendoredFamilyModel, &ctx) {
            FamilyVerdict::Valid { row, .. } => {
                if roster.holder_of_kid(&row.kid) != Some(row.iss.as_str()) {
                    refused.push((i, StandingRefusal::VoiceNotHolder { part }));
                } else if let Err(r) = shape(&row) {
                    refused.push((i, r));
                } else {
                    let holders = holder_ids(&roster);
                    voices.push((i, *row, head, holders));
                }
            },
            // Under a held roster the only key not held is one the bundle
            // does not seat: that statement is not a voice.
            FamilyVerdict::Waiting(_) => {
                not_voices += 1;
                if let Some(id) = unverified_row_id(s) {
                    unheard_rows.push((id, holder_ids(&roster)));
                }
            },
            FamilyVerdict::Invalid(invalid) => {
                refused.push((i, StandingRefusal::Statement { part, invalid }));
            },
            FamilyVerdict::FamilyInvalid(fault) => {
                refused.push((i, StandingRefusal::Family { part, fault }));
            },
        }
    }
    // The row with the most distinct voices; a tie goes to the lowest row id.
    let mut by_row: BTreeMap<Digest32, BTreeSet<&str>> = BTreeMap::new();
    for (_, row, ..) in &voices {
        by_row
            .entry(row.row_id)
            .or_default()
            .insert(row.iss.as_str());
    }
    let chosen = by_row
        .iter()
        .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)))
        .map(|(id, _)| *id);
    let mut counted = Vec::new();
    for (i, row, head, holders) in voices {
        if Some(row.row_id) == chosen {
            counted.push((row, head, holders));
        } else {
            refused.push((i, StandingRefusal::OtherRow { part }));
        }
    }
    refused.sort_by_key(|(i, _)| *i);
    let names: BTreeSet<String> = counted.iter().map(|(r, ..)| r.iss.clone()).collect();
    let Some((first, head, holders)) = counted.into_iter().next() else {
        // No holder's voice yet: the same short count, waiting on every
        // holder of the bundle named. A statement's own fault refuses that
        // statement only; only where nothing else is held does it answer.
        for (row, hs) in unheard_rows {
            waits.extend(
                hs.into_iter()
                    .map(|(_, kid)| StandingWait::Key(MissingKey::Voice { kid, row })),
            );
        }
        if !waits.is_empty() {
            return waiting(waits);
        }
        return match refused.into_iter().next() {
            Some((_, r)) => Reading::Refused(r),
            None => Reading::Waiting(vec![StandingWait::Grant]),
        };
    };
    // The one count (`super::count::strict_majority`): the voices' signers
    // over the named bundle's holders, waiting on every holder not heard.
    let unheard: Vec<Digest32> = holders
        .iter()
        .filter(|(r, _)| !names.contains(r))
        .map(|(_, k)| *k)
        .collect();
    match super::count::strict_majority(
        names.iter().map(String::as_str),
        holders.iter().map(|(r, _)| r.as_str()),
        unheard.len(),
    ) {
        super::count::Count::Counted { n, .. } => Reading::Valid(CountedRow {
            row: first,
            head,
            voices: names.into_iter().collect(),
            roster_size: n,
            refused,
            not_voices,
        }),
        // Short of the count: the row gains voices without changing its row
        // id (CC 2.6.1.9), so it waits on the voice of each holder not heard.
        super::count::Count::Unmet {
            could_be_made_up: true,
            ..
        } => {
            let row_id = first.row_id;
            waits.extend(
                unheard
                    .into_iter()
                    .map(|kid| StandingWait::Key(MissingKey::Voice { kid, row: row_id })),
            );
            waiting(waits)
        },
        // No unheard holder could make it up (an empty roster): nothing to
        // wait on but the grant itself.
        super::count::Count::Unmet { .. } => Reading::Waiting(vec![StandingWait::Grant]),
    }
}

// ---------------------------------------------------------------- the grant

/// A counted grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The count.
    pub counted: CountedRow,
    /// The grantee: the CWT `sub`.
    pub grantee: String,
    /// `scope`, in set order.
    pub scope: Vec<String>,
    /// `projects`, in set order, when carried.
    pub projects: Option<Vec<String>>,
}

impl Grant {
    /// The grant's row id.
    #[must_use]
    pub fn row_id(&self) -> &Digest32 {
        &self.counted.row.row_id
    }

    /// The bundle the grant names and is counted over.
    #[must_use]
    pub fn head(&self) -> &Digest32 {
        &self.counted.head
    }

    fn as_target(&self) -> TargetRow {
        TargetRow {
            row_id: self.counted.row.row_id,
            family_id: self.counted.row.family.clone(),
            payload: self.counted.row.payload.clone(),
        }
    }
}

fn grant_shape(row: &VerifiedRow) -> Result<(), StandingRefusal> {
    let part = Part::Grant;
    let m = |member| StandingRefusal::Malformed { part, member };
    if row.row_type != "delegates_to" || row.family != GRANT_FAMILY {
        return Err(StandingRefusal::WrongRow { part });
    }
    let p = &row.payload;
    // Counted: the family model refuses an `author` under `act=group`; an
    // author named here is refused by name all the same.
    if row.author.is_some() {
        return Err(m("author"));
    }
    if p.get_text("dimension").and_then(Value::as_text) != Some(GRANT_DIMENSION) {
        return Err(m("dimension"));
    }
    if !is_identity_ref(&row.sub) {
        return Err(m("sub"));
    }
    let scope = text_set(part, p.get_text("scope").ok_or(m("scope"))?, "scope")?;
    let projects = p
        .get_text("projects")
        .map(|v| text_set(part, v, "projects"))
        .transpose()?;
    refs_member(p, "head").ok_or(m("refs.head"))?;
    // A pipeline's grant (one carrying `projects`) carries no scope but the
    // two attest scopes (CC 4.5.5, CC Q18).
    if projects.is_some() && scope.iter().any(|s| !PIPELINE_SCOPES.contains(&s.as_str())) {
        return Err(StandingRefusal::PipelineGrantOutOfRole);
    }
    Ok(())
}

/// Count a grant: the statements of one `trust:confers:v1` row, each a voice
/// of a holder of the bundle its `refs.head` names, under the key that bundle
/// seats for it, one voice per holder. Counted at `2·yes > N`.
///
/// A statement under a key the named bundle does not seat is not a voice. A
/// statement's own fault refuses that statement only. The answer is Valid
/// when the held voices meet the count; Waiting on a bundle not held, or,
/// short of the count, on the voices of the holders not heard; else Refused
/// (the first statement's refusal, or `grant_no_voice`).
pub fn grant_counted(statements: &[&[u8]], bundles: &dyn BundleLookup) -> Reading<Grant> {
    if statements.is_empty() {
        return Reading::Waiting(vec![StandingWait::Grant]);
    }
    let counted = valid_or_return!(count_row(
        Part::Grant,
        statements,
        bundles,
        &SelectContext::default(),
        &grant_shape
    ));
    let p = &counted.row.payload;
    // The shape check passed on this row: these reads cannot fail.
    let scope = p
        .get_text("scope")
        .and_then(|v| text_set(Part::Grant, v, "scope").ok())
        .unwrap_or_default();
    let projects = p
        .get_text("projects")
        .and_then(|v| text_set(Part::Grant, v, "projects").ok());
    Reading::Valid(Grant {
        grantee: counted.row.sub.clone(),
        counted,
        scope,
        projects,
    })
}

/// Whether a counted grant confers a build manifest for `project`: a scope it
/// carries satisfies `provenance:build_manifest` ([`scope_satisfies`]), and
/// `project` is among its `projects` (an absent `projects` grants no
/// project). Returns the scope that satisfied.
pub fn grant_confers_build<'g>(
    grant: &'g Grant,
    project: &str,
) -> Result<&'g str, StandingRefusal> {
    let scope = grant
        .scope
        .iter()
        .find(|s| scope_satisfies(s, BUILD_ATTEST_FAMILY))
        .ok_or(StandingRefusal::ScopeNotGranted)?;
    match &grant.projects {
        Some(ps) if ps.iter().any(|p| p == project) => Ok(scope),
        _ => Err(StandingRefusal::ProjectNotGranted),
    }
}

/// Count a withdrawal of `grant` (CC 2.4.1.1): a `withdraws` carrying the
/// grant's family id and `sub`, no `dimension` and no `author`,
/// `refs.target` the grant and `refs.head` the bundle it acts from, counted
/// at a strict majority of that bundle's holders as [`grant_counted`] counts.
/// Statements naming another target are refused
/// (`grant_withdrawal_malformed:refs.target`).
pub fn read_grant_withdrawal(
    statements: &[&[u8]],
    grant: &Grant,
    bundles: &dyn BundleLookup,
) -> Reading<CountedRow> {
    let part = Part::GrantWithdrawal;
    let target = grant.as_target();
    let ctx = SelectContext {
        target: Some(target.clone()),
        ..SelectContext::default()
    };
    let shape = |row: &VerifiedRow| -> Result<(), StandingRefusal> {
        let m = |member| StandingRefusal::Malformed { part, member };
        if row.row_type != "withdraws" || row.family != target.family_id {
            return Err(StandingRefusal::WrongRow { part });
        }
        if row.sub != grant.grantee {
            return Err(m("sub"));
        }
        if row.author.is_some() {
            return Err(m("author"));
        }
        if refs_member(&row.payload, "target") != Some(target.row_id) {
            return Err(m("refs.target"));
        }
        refs_member(&row.payload, "head").ok_or(m("refs.head"))?;
        Ok(())
    };
    count_row(part, statements, bundles, &ctx, &shape)
}

// ---------------------------------------------------------------- the answer

/// The owner-binding of the grantee, as the caller has read and verified it
/// (CC 3.2 `owner_of(K)`): `owner` is the one live owner the bindings of
/// `key` name. Verify has no edition-2 owner-binding reader yet; this input
/// is the caller's statement of that reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerBinding {
    /// The owner's identity reference (the binding's signer).
    pub owner: String,
    /// The owned key's identity reference (the binding's `sub`).
    pub key: String,
    /// The binding row's id: the acceptance cites it in `refs.also.cites`.
    /// The binding is a `delegates_to` from the owner to the key with the key
    /// as `sub`; its payload shape is CC's, still to come, so it is not read
    /// here.
    pub row_id: Digest32,
    /// The row ids of every other owner-binding of the same key the reader
    /// holds (an earlier owner's, a rival's). An acceptance citing one of
    /// these is made under another binding; one citing two bindings of the
    /// key is refused. A binding cited but not held is waited on.
    pub other_bindings: Vec<Digest32>,
}

/// Read one statement of an owner-binding row (CC 3.2) into the
/// [`OwnerBinding`] the walk takes: the owner (`author`), the key owned (the
/// CWT `sub`) and the row id. The statement is the owner's, or the key's own
/// first-binding cosign over the same payload (the same row id); either reads
/// the same binding.
///
/// It reads the row and its shape only (the statement reader applies
/// `family_shapes::check_owner_binding`) and checks the signer's key. It does
/// not decide which binding of a key is live, whether the first-binding cosign
/// is held, or whether the binding's window covers an instant: those are the
/// caller's fold. `other_bindings` is left empty for the caller to fill.
pub fn read_owner_binding(statement: &[u8], keys: &dyn KeyDirectory) -> Reading<OwnerBinding> {
    let part = Part::OwnerBinding;
    let row = valid_or_return!(from_family(
        part,
        verify_row_in_family(statement, keys, &VendoredFamilyModel)
    ));
    if row.row_type != "delegates_to" || row.family != super::family_shapes::OWNERSHIP_FAMILY {
        return Reading::Refused(StandingRefusal::WrongRow { part });
    }
    if !is_identity_ref(&row.sub) {
        return Reading::Refused(StandingRefusal::Malformed {
            part,
            member: "sub",
        });
    }
    let Some(owner) = row.author.clone() else {
        return Reading::Refused(StandingRefusal::Malformed {
            part,
            member: "author",
        });
    };
    Reading::Valid(OwnerBinding {
        owner,
        key: row.sub,
        row_id: row.row_id,
        other_bindings: Vec::new(),
    })
}

/// Accept or decline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerKind {
    /// `membership:acceptance:v1`.
    Acceptance,
    /// `membership:decline:v1`.
    Decline,
}

/// The owner's answer to a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The verified statement.
    pub row: VerifiedRow,
    /// Accept or decline.
    pub kind: AnswerKind,
}

impl Answer {
    fn as_target(&self) -> TargetRow {
        TargetRow {
            row_id: self.row.row_id,
            family_id: self.row.family.clone(),
            payload: self.row.payload.clone(),
        }
    }
}

/// Read the owner's answer to `grant` under `keys` (which hold the owner's
/// key record): a `scores` row of `membership:{stage}`, authored by the owner
/// `binding` names (never the grantee's own key), CWT `sub` the grantee,
/// `refs` exactly `{answers: the grant}`, dimension
/// `membership:acceptance:v1` or `membership:decline:v1`. `proposal_hash`
/// (the earlier form) and group members are refused by name.
pub fn read_answer(
    statement: &[u8],
    keys: &dyn KeyDirectory,
    grant: &Grant,
    binding: &OwnerBinding,
) -> Reading<Answer> {
    let part = Part::Answer;
    let row = valid_or_return!(from_family(
        part,
        verify_row_in_family(statement, keys, &VendoredFamilyModel)
    ));
    match answer_shape(row, grant, binding) {
        Ok(a) => match a.kind {
            AnswerKind::Acceptance => acceptance_binding(a, binding),
            AnswerKind::Decline => Reading::Valid(a),
        },
        Err(r) => Reading::Refused(r),
    }
}

/// An acceptance of a grant to a machine key names the owner-binding it is
/// made under in `refs.also.cites` (a set; it may cite other rows too). It
/// stands under `binding` when the bindings of the key it cites, among those
/// held, are exactly `binding`. Citing another held binding, or two of them,
/// is `acceptance_other_binding` (an acceptance is made under one binding; a
/// re-binding needs a new acceptance); citing nothing is the same. Citing
/// only rows the reader does not hold waits on them: one may be the binding.
fn acceptance_binding(a: Answer, binding: &OwnerBinding) -> Reading<Answer> {
    let cites: Vec<Digest32> = a
        .row
        .payload
        .get_text("refs")
        .and_then(|r| r.get_text("also"))
        .and_then(|x| x.get_text("cites"))
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(row_ref_of)
        .collect();
    let held = |c: &Digest32| *c == binding.row_id || binding.other_bindings.contains(c);
    let cited: Vec<Digest32> = cites.iter().copied().filter(|c| held(c)).collect();
    match cited.as_slice() {
        [one] if bool::from(one.ct_eq(&binding.row_id)) => Reading::Valid(a),
        [] if !cites.is_empty() => waiting(
            cites
                .into_iter()
                .map(|c| StandingWait::Key(MissingKey::Row(c)))
                .collect(),
        ),
        _ => Reading::Refused(StandingRefusal::AcceptanceOtherBinding),
    }
}

fn answer_shape(
    row: VerifiedRow,
    grant: &Grant,
    binding: &OwnerBinding,
) -> Result<Answer, StandingRefusal> {
    let part = Part::Answer;
    let m = |member| StandingRefusal::Malformed { part, member };
    if row.row_type != "scores" || row.family != ANSWER_FAMILY {
        return Err(StandingRefusal::WrongRow { part });
    }
    let p = &row.payload;
    let kind = match p.get_text("dimension").and_then(Value::as_text) {
        Some(ACCEPTANCE_DIMENSION) => AnswerKind::Acceptance,
        Some(DECLINE_DIMENSION) => AnswerKind::Decline,
        _ => return Err(m("dimension")),
    };
    // The reply's own shape (refs.answers, no refs.target or refs.head, no
    // proposal_hash) is the statement reader's (`family_shapes::check_reply`).
    let answers = refs_member(p, "answers").ok_or(m("refs"))?;
    if row.sub != grant.grantee {
        return Err(StandingRefusal::AcceptanceOtherGrantee);
    }
    let author = row.author.as_deref().unwrap_or_default();
    if author == grant.grantee {
        return Err(StandingRefusal::AcceptanceByGrantee);
    }
    if binding.key != grant.grantee {
        return Err(StandingRefusal::OwnerBindingOtherKey);
    }
    if author != binding.owner {
        return Err(StandingRefusal::AcceptanceNotByOwner);
    }
    if !bool::from(answers.ct_eq(grant.row_id())) {
        return Err(StandingRefusal::AcceptanceOtherGrant);
    }
    Ok(Answer { row, kind })
}

/// Read the owner's own withdrawal of `acceptance` under `keys`: an authored
/// `withdraws` carrying the acceptance's family id and `sub`, its author the
/// acceptance's, `refs` exactly `{target: the acceptance}` (no head). Valid
/// ends the grant from the grantee's side.
pub fn read_reply_withdrawal(
    statement: &[u8],
    keys: &dyn KeyDirectory,
    acceptance: &Answer,
) -> Reading<VerifiedRow> {
    let part = Part::AnswerWithdrawal;
    let target = acceptance.as_target();
    let ctx = SelectContext {
        target: Some(target.clone()),
        ..SelectContext::default()
    };
    let row = valid_or_return!(from_family(
        part,
        verify_row_in_family_with(statement, keys, &VendoredFamilyModel, &ctx)
    ));
    let m = |member| StandingRefusal::Malformed { part, member };
    let checked = (|| {
        if row.row_type != "withdraws" || row.family != target.family_id {
            return Err(StandingRefusal::WrongRow { part });
        }
        if row.author != acceptance.row.author || row.sub != acceptance.row.sub {
            return Err(m("author"));
        }
        let refs = row.payload.get_text("refs").ok_or(m("refs.target"))?;
        if refs.get_text("head").is_some() {
            return Err(m("refs.head"));
        }
        if refs_member(&row.payload, "target") != Some(target.row_id) {
            return Err(m("refs.target"));
        }
        Ok(())
    })();
    match checked {
        Ok(()) => Reading::Valid(row),
        Err(r) => Reading::Refused(r),
    }
}

// ---------------------------------------------------------------- row state

/// What the caller's view of the composers on the build row shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalState {
    /// No view was supplied: the verdict stands on a verified manifest and
    /// says so beside it.
    Unknown,
    /// A view was supplied and holds no composer naming the row.
    NoneHeld,
    /// The pipeline's `withdraws` of the row is held.
    Withdrawn,
    /// A `supersedes` of the row by its signer at the same (project, version,
    /// target) is held.
    Superseded,
}

impl WithdrawalState {
    /// `unknown`, `none_held`, `withdrawn` or `superseded`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NoneHeld => "none_held",
            Self::Withdrawn => "withdrawn",
            Self::Superseded => "superseded",
        }
    }
}

/// The state of a build row under a view of composers and peer rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowState {
    /// What the view shows.
    pub withdrawal_state: WithdrawalState,
    /// Whether another standing row of the signer at the same three, with a
    /// different `build`, lies outside one `supersedes` chain with the row;
    /// `None` without a view.
    pub equivocation: Option<bool>,
    /// Statements of the view that did not read Valid, or name nothing of
    /// this row: not counted.
    pub unread: usize,
}

/// The state of `row` under the caller's `view`: every `withdraws`,
/// `supersedes` and build row the caller holds by the same signer. `None`
/// (no view) answers [`WithdrawalState::Unknown`].
///
/// - a `withdraws` by the row's signer naming the row in `refs.target`:
///   withdrawn;
/// - a build row by the same signer at the same (project, version, target)
///   that is a `supersedes` naming the row: superseded;
/// - another build row by the same signer at the same three whose `build`
///   differs, not joined to the row by `supersedes` links among the rows
///   held: equivocation (CC 2.7.7 rule 2).
pub fn build_row_state(
    row: &BuildRow,
    view: Option<&[&[u8]]>,
    keys: &dyn KeyDirectory,
) -> RowState {
    let Some(view) = view else {
        return RowState {
            withdrawal_state: WithdrawalState::Unknown,
            equivocation: None,
            unread: 0,
        };
    };
    let mut unread = 0usize;
    let mut peers: Vec<BuildRow> = Vec::new();
    let mut others: Vec<&[u8]> = Vec::new();
    for s in view {
        match read_build_row(s, keys) {
            Reading::Valid(peer) if peer.same_slot(row) && peer.row.row_id != row.row.row_id => {
                peers.push(peer);
            },
            Reading::Valid(_) => unread += 1,
            _ => others.push(*s),
        }
    }
    // The signer's own `withdraws` of the row or of a peer: a withdrawn peer
    // is not standing.
    let mut withdrawn_ids: BTreeSet<Digest32> = BTreeSet::new();
    for s in others {
        let hit = core::iter::once(row).chain(peers.iter()).find(|cand| {
            let ctx = SelectContext {
                target: Some(cand.as_target()),
                ..SelectContext::default()
            };
            matches!(
                verify_row_in_family_with(s, keys, &VendoredFamilyModel, &ctx),
                FamilyVerdict::Valid { row: w, .. }
                    if w.row_type == "withdraws"
                        && w.iss == row.row.iss
                        && super::keys::target_in(&w.payload) == Some(cand.row.row_id)
            )
        });
        match hit {
            Some(c) => {
                withdrawn_ids.insert(c.row.row_id);
            },
            None => unread += 1,
        }
    }
    let withdrawn = withdrawn_ids.contains(&row.row.row_id);
    peers.retain(|p| !withdrawn_ids.contains(&p.row.row_id));
    let superseded = peers.iter().any(|p| p.superseding == Some(row.row.row_id));
    // One supersedes chain: the rows joined by `supersedes` links among the
    // rows held (the row and its peers), as an undirected graph.
    let ids: Vec<Digest32> = core::iter::once(row.row.row_id)
        .chain(peers.iter().map(|p| p.row.row_id))
        .collect();
    let mut chain: BTreeSet<Digest32> = BTreeSet::new();
    chain.insert(row.row.row_id);
    let links: Vec<(Digest32, Digest32)> = core::iter::once(row)
        .chain(peers.iter())
        .filter_map(|r| r.superseding.map(|t| (r.row.row_id, t)))
        .filter(|(_, t)| ids.contains(t))
        .collect();
    loop {
        let before = chain.len();
        for (a, b) in &links {
            if chain.contains(a) || chain.contains(b) {
                chain.insert(*a);
                chain.insert(*b);
            }
        }
        if chain.len() == before {
            break;
        }
    }
    let equivocation = peers
        .iter()
        .any(|p| !chain.contains(&p.row.row_id) && !p.same_build(row));
    RowState {
        withdrawal_state: if withdrawn {
            WithdrawalState::Withdrawn
        } else if superseded {
            WithdrawalState::Superseded
        } else {
            WithdrawalState::NoneHeld
        },
        equivocation: Some(equivocation),
        unread,
    }
}

// ---------------------------------------------------------------- evaluate

/// Everything [`evaluate_build_standing`] reads, all bytes the reader
/// re-verifies.
pub struct StandingInput<'a> {
    /// The build row's statement.
    pub build_row: &'a [u8],
    /// The manifest blob the row cites.
    pub blob: &'a [u8],
    /// The keys for the pipeline's and the owner's statements (their key
    /// records).
    pub keys: &'a dyn KeyDirectory,
    /// The grant's statements, every voice.
    pub grant: &'a [&'a [u8]],
    /// Statements of any counted withdrawal of the grant.
    pub grant_withdrawals: &'a [&'a [u8]],
    /// The owner's acceptance or decline statements.
    pub answers: &'a [&'a [u8]],
    /// The owner's withdrawals of the acceptance.
    pub answer_withdrawals: &'a [&'a [u8]],
    /// The owner-binding of the grantee, as the caller verified it.
    pub owner_binding: Option<&'a OwnerBinding>,
    /// The composers and peer rows the caller holds for the build row's
    /// signer; `None` when the caller has no view.
    pub composers: Option<&'a [&'a [u8]]>,
    /// The bundles named in `refs.head`.
    pub bundles: &'a dyn BundleLookup,
}

/// The verdict on one build row: flat measurements, one `stands`, and when it
/// does not stand one refusal or what it waits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildStanding {
    /// Every link holds.
    pub stands: bool,
    /// The first refusal, in the order of the links.
    pub refusal: Option<StandingRefusal>,
    /// What the reading waits on, when nothing is refused.
    pub waiting: Vec<StandingWait>,

    /// The build row's id.
    pub manifest_row_id: Option<Digest32>,
    /// The build row's verdict: `valid`, `waiting:{…}` or `refused:{token}`.
    pub manifest_row_verdict: String,
    /// The pipeline's identity reference (the row's `iss`).
    pub manifest_pipeline: Option<String>,
    /// The pipeline key's thumbprint (the row's `kid`).
    pub manifest_pipeline_kid: Option<Digest32>,
    /// The row's signed instant.
    pub manifest_asserted_at_ms: Option<u64>,
    /// `build.project`.
    pub manifest_project: Option<String>,
    /// `build.version`.
    pub manifest_version: Option<String>,
    /// The dimension's `{target}`.
    pub manifest_target: Option<String>,
    /// `build.manifest_hash`.
    pub manifest_hash: Option<Digest32>,
    /// `build.manifest_size`.
    pub manifest_size: Option<u64>,
    /// The blob's length equals `manifest_size`.
    pub manifest_size_matched: Option<bool>,
    /// The blob's SHA-256 equals `manifest_hash`.
    pub manifest_hash_matched: Option<bool>,
    /// The blob decodes and names the row's project, version and target.
    pub manifest_descriptor_matched: Option<bool>,
    /// The decoded blob, once every check against the row holds.
    pub manifest: Option<BinaryManifest>,

    /// The grant's verdict: `valid`, `waiting:{…}` or `refused:{token}`;
    /// `None` when not reached.
    pub grant_verdict: Option<String>,
    /// The grant's row id.
    pub grant_row_id: Option<Digest32>,
    /// The bundle the grant is counted over (its `refs.head`).
    pub grant_root: Option<Digest32>,
    /// Distinct holders whose voices counted.
    pub grant_voices: Option<usize>,
    /// N, the holders of that bundle.
    pub grant_roster_size: Option<usize>,
    /// The scope that satisfied `provenance:build_manifest`.
    pub grant_scope: Option<String>,
    /// `build.project` is among the grant's `projects`.
    pub grant_project_granted: Option<bool>,
    /// A counted withdrawal of the grant is held.
    pub grant_withdrawn: Option<bool>,

    /// The answer's verdict: `accepted`, `declined`, `waiting:{…}` or
    /// `refused:{token}`; `None` when not reached.
    pub acceptance_verdict: Option<String>,
    /// The acceptance's row id.
    pub acceptance_row_id: Option<Digest32>,
    /// The owner the binding names.
    pub owner: Option<String>,
    /// The owner's withdrawal of the acceptance is held.
    pub acceptance_withdrawn: Option<bool>,

    /// What the composers view shows; [`WithdrawalState::Unknown`] without
    /// one.
    pub withdrawal_state: WithdrawalState,
    /// Equivocation by the signer at the row's (project, version, target);
    /// `None` without a view.
    pub equivocation: Option<bool>,
}

impl BuildStanding {
    fn new() -> Self {
        Self {
            stands: false,
            refusal: None,
            waiting: Vec::new(),
            manifest_row_id: None,
            manifest_row_verdict: String::new(),
            manifest_pipeline: None,
            manifest_pipeline_kid: None,
            manifest_asserted_at_ms: None,
            manifest_project: None,
            manifest_version: None,
            manifest_target: None,
            manifest_hash: None,
            manifest_size: None,
            manifest_size_matched: None,
            manifest_hash_matched: None,
            manifest_descriptor_matched: None,
            manifest: None,
            grant_verdict: None,
            grant_row_id: None,
            grant_root: None,
            grant_voices: None,
            grant_roster_size: None,
            grant_scope: None,
            grant_project_granted: None,
            grant_withdrawn: None,
            acceptance_verdict: None,
            acceptance_row_id: None,
            owner: None,
            acceptance_withdrawn: None,
            withdrawal_state: WithdrawalState::Unknown,
            equivocation: None,
        }
    }

    /// `stands`, `refused:{token}` or `waiting:{token+token}`.
    #[must_use]
    pub fn token(&self) -> String {
        if self.stands {
            "stands".into()
        } else if let Some(r) = &self.refusal {
            format!("refused:{}", r.token())
        } else {
            format!("waiting:{}", wait_tokens(&self.waiting))
        }
    }

    fn refuse(&mut self, r: StandingRefusal) {
        if self.refusal.is_none() {
            self.refusal = Some(r);
        }
    }

    fn finish(mut self) -> Self {
        self.waiting.sort_unstable();
        self.waiting.dedup();
        if self.refusal.is_some() {
            self.waiting.clear();
        }
        self.stands = self.refusal.is_none() && self.waiting.is_empty();
        self
    }
}

/// Decide whether a build row stands, link by link (module docs): the build
/// row, the blob against it, the grant (count, grantee, head, scope,
/// projects), the grant's end by its holders, the owner's answer and its
/// withdrawal, and the row's state under the composers view.
///
/// The refusal reported is the first in that order. A link that waits does
/// not stop the later ones, so `waiting` lists everything missing; a refusal
/// anywhere clears it. Without a composers view the verdict can stand, with
/// `withdrawal_state` [`WithdrawalState::Unknown`] beside it.
#[must_use]
pub fn evaluate_build_standing(input: &StandingInput<'_>) -> BuildStanding {
    let mut out = BuildStanding::new();

    // 1. The build row.
    let reading = read_build_row(input.build_row, input.keys);
    out.manifest_row_verdict = reading.token();
    let row = match reading {
        Reading::Valid(r) => r,
        Reading::Waiting(w) => {
            out.waiting = w;
            return out.finish();
        },
        Reading::Refused(r) => {
            out.refuse(r);
            return out.finish();
        },
    };
    out.manifest_row_id = Some(row.row.row_id);
    out.manifest_pipeline = Some(row.row.iss.clone());
    out.manifest_pipeline_kid = Some(row.row.kid);
    out.manifest_asserted_at_ms = Some(row.row.asserted_at);
    out.manifest_project = Some(row.project.clone());
    out.manifest_version = Some(row.version.clone());
    out.manifest_target = Some(row.target.clone());
    out.manifest_hash = Some(row.manifest_hash);
    out.manifest_size = Some(row.manifest_size);

    // 2. The blob against the row.
    let size_ok = u64::try_from(input.blob.len()).ok() == Some(row.manifest_size);
    out.manifest_size_matched = Some(size_ok);
    if size_ok {
        let d: Digest32 = Sha256::digest(input.blob).into();
        out.manifest_hash_matched = Some(bool::from(d.ct_eq(&row.manifest_hash)));
    }
    match check_blob(&row, input.blob) {
        Ok(m) => {
            out.manifest_descriptor_matched = Some(true);
            out.manifest = Some(m);
        },
        Err(r) => {
            if out.manifest_hash_matched == Some(true) {
                out.manifest_descriptor_matched = Some(false);
            }
            out.refuse(r);
            return out.finish();
        },
    }

    // 3–4. The grant, its grantee and head, its scope and projects.
    let grant_reading = grant_counted(input.grant, input.bundles);
    out.grant_verdict = Some(grant_reading.token());
    let grant = match grant_reading {
        Reading::Valid(g) => Some(g),
        Reading::Waiting(w) => {
            out.waiting.extend(w);
            None
        },
        Reading::Refused(r) => {
            out.refuse(r);
            return out.finish();
        },
    };
    if let Some(g) = &grant {
        out.grant_row_id = Some(*g.row_id());
        out.grant_root = Some(*g.head());
        out.grant_voices = Some(g.counted.voices.len());
        out.grant_roster_size = Some(g.counted.roster_size);
        if g.grantee != row.row.iss {
            out.refuse(StandingRefusal::GrantOtherGrantee);
            return out.finish();
        }
        match input.bundles.descends(&row.head, g.head()) {
            Descent::SameOrLater => {},
            Descent::Not => {
                out.refuse(StandingRefusal::BuildRowOtherHead);
                return out.finish();
            },
            Descent::NotHeld => out.waiting.push(StandingWait::Bundle(row.head)),
        }
        out.grant_project_granted = Some(
            g.projects
                .as_ref()
                .is_some_and(|ps| ps.contains(&row.project)),
        );
        match grant_confers_build(g, &row.project) {
            Ok(s) => out.grant_scope = Some(s.to_owned()),
            Err(r) => {
                out.refuse(r);
                return out.finish();
            },
        }
    }

    // 5. Whether the counted grant is in force: its ends and the owner's answer.
    if let Some(g) = &grant {
        // The row stands on the owner's acceptance it names; naming none, it
        // counts for nobody, and nothing that could arrive changes that.
        let Some(stands_on) = row.stands_on else {
            out.refuse(StandingRefusal::BuildRowStandsOnNothing);
            return out.finish();
        };
        let f = grant_in_force(
            g,
            &GrantEndsInput {
                grant_withdrawals: input.grant_withdrawals,
                answers: input.answers,
                answer_withdrawals: input.answer_withdrawals,
                owner_binding: input.owner_binding,
                keys: input.keys,
                bundles: input.bundles,
                stands_on: Some(stands_on),
            },
        );
        out.grant_withdrawn = Some(f.grant_withdrawn);
        out.owner = input.owner_binding.map(|b| b.owner.clone());
        out.acceptance_verdict = f.acceptance_verdict;
        out.acceptance_row_id = f.acceptance_row_id;
        out.acceptance_withdrawn = f.acceptance_withdrawn;
        // Rows the reader holds by id: a `stands_on` naming one of them that
        // is not the acceptance read is final; naming a row not held waits on
        // it (a row waits for what it names).
        let mut held: Vec<Digest32> = vec![*g.row_id()];
        if let Some(b) = input.owner_binding {
            held.push(b.row_id);
            held.extend(b.other_bindings.iter().copied());
        }
        held.extend(
            input
                .answers
                .iter()
                .chain(input.answer_withdrawals)
                .chain(input.grant_withdrawals)
                .filter_map(|s| unverified_row_id(s)),
        );
        let answer_ids: Vec<Digest32> = input
            .answers
            .iter()
            .filter_map(|s| unverified_row_id(s))
            .collect();
        match f.reading {
            Reading::Valid(acc) if bool::from(acc.ct_eq(&stands_on)) => {},
            Reading::Valid(_) if held.contains(&stands_on) => {
                out.refuse(StandingRefusal::BuildRowStandsOnNothing);
                return out.finish();
            },
            Reading::Valid(_) => out
                .waiting
                .push(StandingWait::Key(MissingKey::Row(stands_on))),
            Reading::Waiting(w) => {
                // An acceptance still to be read may be the one named; any
                // other held row never is.
                if held.contains(&stands_on) && !answer_ids.contains(&stands_on) {
                    out.refuse(StandingRefusal::BuildRowStandsOnNothing);
                    return out.finish();
                }
                out.waiting.extend(w);
            },
            Reading::Refused(r) => {
                out.refuse(r);
                return out.finish();
            },
        }
    }

    // 6. The row's state under the composers view.
    let state = build_row_state(&row, input.composers, input.keys);
    out.withdrawal_state = state.withdrawal_state;
    out.equivocation = state.equivocation;
    match state.withdrawal_state {
        WithdrawalState::Withdrawn => out.refuse(StandingRefusal::BuildWithdrawn),
        WithdrawalState::Superseded => out.refuse(StandingRefusal::BuildSuperseded),
        _ => {},
    }
    if state.equivocation == Some(true) {
        out.refuse(StandingRefusal::Equivocation);
    }
    out.finish()
}

/// The statements [`grant_in_force`] reads beside a counted grant.
pub struct GrantEndsInput<'a> {
    /// Statements of any counted withdrawal of the grant.
    pub grant_withdrawals: &'a [&'a [u8]],
    /// The owner's acceptance or decline statements.
    pub answers: &'a [&'a [u8]],
    /// The owner's withdrawals of the acceptance.
    pub answer_withdrawals: &'a [&'a [u8]],
    /// The owner-binding of the grantee, as the caller verified it.
    pub owner_binding: Option<&'a OwnerBinding>,
    /// The keys for the owner's statements.
    pub keys: &'a dyn KeyDirectory,
    /// The bundles a withdrawal names in `refs.head`.
    pub bundles: &'a dyn BundleLookup,
    /// The acceptance the act stands on, when the caller knows it: among
    /// several valid acceptances, this one is read.
    pub stands_on: Option<Digest32>,
}

/// What [`grant_in_force`] answers, with what it measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantInForce {
    /// Valid (the acceptance's row id) when the grant is in force; Waiting on
    /// the owner-binding, the acceptance, its key, or a bundle a withdrawal
    /// names; Refused `grant_withdrawn`, `grant_declined`,
    /// `acceptance_withdrawn` or the acceptance's own fault.
    pub reading: Reading<Digest32>,
    /// The decision of [`super::count::conferral_in_force`], when reached.
    pub in_force: Option<super::count::InForce>,
    /// A counted withdrawal of the grant is held.
    pub grant_withdrawn: bool,
    /// `accepted`, `declined`, `waiting:{…}` or `refused:{token}`; `None` when
    /// the answers were not read (the grant ended by count).
    pub acceptance_verdict: Option<String>,
    /// The acceptance's row id.
    pub acceptance_row_id: Option<Digest32>,
    /// The owner's withdrawal of the acceptance is held.
    pub acceptance_withdrawn: Option<bool>,
}

/// Whether a counted grant is in force (CC 3.2 T3, CC 2.4.1.1): it has not
/// been withdrawn by a count of the holders ([`read_grant_withdrawal`]), the
/// owner `binding` names accepted it ([`read_answer`]) and has not declined
/// it, and the owner has not withdrawn that acceptance
/// ([`read_reply_withdrawal`]). The statements are read here; the
/// decision is the one [`super::count::conferral_in_force`] makes over their
/// row ids.
#[must_use]
pub fn grant_in_force(grant: &Grant, input: &GrantEndsInput<'_>) -> GrantInForce {
    let mut out = GrantInForce {
        reading: Reading::Waiting(Vec::new()),
        in_force: None,
        grant_withdrawn: false,
        acceptance_verdict: None,
        acceptance_row_id: None,
        acceptance_withdrawn: None,
    };
    let gid = *grant.row_id();
    // The holders' ends: the row ids the counted withdrawals name.
    let mut waits: Vec<StandingWait> = Vec::new();
    let mut counted_ends: Vec<Digest32> = Vec::new();
    if !input.grant_withdrawals.is_empty() {
        match read_grant_withdrawal(input.grant_withdrawals, grant, input.bundles) {
            Reading::Valid(c) => counted_ends.extend(refs_member(&c.row.payload, "target")),
            // A withdrawal over a bundle not held may be counted there; one
            // short of its count has not ended the grant.
            Reading::Waiting(w) => {
                waits.extend(
                    w.into_iter()
                        .filter(|x| matches!(x, StandingWait::Bundle(_))),
                );
            },
            Reading::Refused(_) => {},
        }
    }
    out.grant_withdrawn = counted_ends.contains(&gid);
    if out.grant_withdrawn {
        out.in_force = Some(super::count::InForce::EndedByCount);
        out.reading = Reading::Refused(StandingRefusal::GrantWithdrawn);
        return out;
    }
    let Some(binding) = input.owner_binding else {
        out.acceptance_verdict = Some("waiting:owner_binding".into());
        waits.push(StandingWait::OwnerBinding);
        out.reading = waiting(waits);
        return out;
    };
    // The owner's replies, and the row ids its own valid withdrawals name.
    let mut accepted: Option<Answer> = None;
    let mut decline: Option<Answer> = None;
    let mut first_refusal: Option<StandingRefusal> = None;
    let mut answer_waits: Vec<StandingWait> = Vec::new();
    for s in input.answers {
        match read_answer(s, input.keys, grant, binding) {
            Reading::Valid(a) => {
                let slot = match a.kind {
                    AnswerKind::Acceptance => &mut accepted,
                    AnswerKind::Decline => &mut decline,
                };
                let preferred =
                    a.kind == AnswerKind::Acceptance && input.stands_on == Some(a.row.row_id);
                if slot.is_none() || preferred {
                    *slot = Some(a);
                }
            },
            Reading::Waiting(w) => answer_waits.extend(w),
            Reading::Refused(r) => {
                if first_refusal.is_none() {
                    first_refusal = Some(r);
                }
            },
        }
    }
    let mut reply_ends: Vec<Digest32> = Vec::new();
    for reply in [&accepted, &decline].into_iter().flatten() {
        for s in input.answer_withdrawals {
            if let Reading::Valid(w) = read_reply_withdrawal(s, input.keys, reply) {
                reply_ends.extend(refs_member(&w.payload, "target"));
            }
        }
    }
    let acc_id = accepted.as_ref().map(|a| a.row.row_id);
    let dec_id = decline.as_ref().map(|a| a.row.row_id);
    let decision = super::count::conferral_in_force(
        &gid,
        &counted_ends,
        acc_id.as_ref(),
        dec_id.as_ref(),
        &reply_ends,
    );
    out.in_force = Some(decision);
    out.acceptance_row_id = acc_id;
    out.acceptance_withdrawn = acc_id.map(|a| reply_ends.contains(&a));
    out.reading = match decision {
        InForce::EndedByCount => Reading::Refused(StandingRefusal::GrantWithdrawn),
        InForce::Contested => {
            out.acceptance_verdict = Some("contested".into());
            Reading::Refused(StandingRefusal::GrantContested)
        },
        InForce::Declined => {
            out.acceptance_verdict = Some("declined".into());
            Reading::Refused(StandingRefusal::GrantDeclined)
        },
        InForce::AcceptanceWithdrawn => {
            out.acceptance_verdict = Some("accepted".into());
            Reading::Refused(StandingRefusal::AcceptanceWithdrawn)
        },
        InForce::NotAccepted => {
            if let Some(r) = first_refusal {
                out.acceptance_verdict = Some(format!("refused:{}", r.token()));
                Reading::Refused(r)
            } else {
                if answer_waits.is_empty() {
                    answer_waits.push(StandingWait::Acceptance);
                }
                out.acceptance_verdict = Some(format!("waiting:{}", wait_tokens(&answer_waits)));
                waits.extend(answer_waits);
                waiting(waits)
            }
        },
        InForce::InForce => {
            out.acceptance_verdict = Some("accepted".into());
            if waits.is_empty() {
                Reading::Valid(acc_id.unwrap_or_default())
            } else {
                waiting(waits)
            }
        },
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_match_is_on_whole_tokens() {
        let f = BUILD_ATTEST_FAMILY;
        assert!(scope_satisfies("infra:attest", f));
        assert!(scope_satisfies("infra:attest:provenance:build_manifest", f));
        for held in [
            "infra:attest_assurance",
            "infra:attest:provenance:build_manifest_x",
            "infra:attest:provenance:build_manifest:x86_64",
            "infra:attest:provenance",
            "infra:attest:other_family",
            "infra:attest:",
            "infra",
            "",
        ] {
            assert!(!scope_satisfies(held, f), "{held}");
        }
    }
}
