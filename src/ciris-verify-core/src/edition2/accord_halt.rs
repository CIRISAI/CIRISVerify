//! The accord halt of edition 2: the invocation rows and the lifecycle rows
//! (CC 4.2.1.1, CC 4.2.1.3, CC 4.2.6; CIRISConstitution rc20 64c5918).
//!
//! Every accord row is an ordinary row of the signed object (CC 2.6.1). There
//! is no inner signature and no text preimage; the text preimage is the earlier
//! form ([`crate::humanity_accord`], CC 8.11.29), which this module never reads.
//!
//! - An **invocation** (`constitutional`, `notify`, `drill`) is ONE statement:
//!   its holder's composite `COSE_Sign1` over the payload. The kind is the
//!   row's family (header -70002), so the payload carries no
//!   `invocation_kind`, and the row id reads the family: a `constitutional`
//!   statement never verifies as a `notify`, a `drill` or a lifecycle row.
//! - A **lifecycle** row (`confirmed`, `active`) is COUNTED: one statement per
//!   holder over one payload, no `author`. Its `dimension` names the kind
//!   (`accord:lifecycle:{kind}:vN`, the leaf), `refs.target` names the halt it
//!   confirms or ends by row id, and `refs.head` the bundle it is counted over.
//!   It counts at a strict majority of the roster, one voice per `iss`.
//!
//! The holders come from the bundle in force ([`HaltRoster`], built from a
//! [`super::genesis::GenesisPlacement`] under `std`, or from the holders'
//! composite keys directly); keys are never taken from the statement.
//!
//! The rows feed the latch through
//! [`crate::accord_halt_latch::HaltLatch::apply_forward`], whose state machine
//! is the earlier form's: one holder halts, a lone halt lapses `halt_fuse_secs`
//! after receipt unless confirmed, and a majority resumes.
//!
//! Every accord row's CWT `sub` is the accord's `family_key_id` (=
//! `accord_root`), and its `valid_until` is after its `asserted_at`.
//!
//! The bundle in force is the one the row names: `accord_root` for an
//! invocation ([`named_accord_root`]) and `refs.head` for a lifecycle row
//! ([`named_head`], [`HaltRoster::find_by_head`]); the reader refuses a row read
//! under another (`other_accord`, `other_bundle`). The clock is the caller's,
//! and the per-kind dedup of `invocation_id` and `nonce` within `valid_until`
//! is the store's.
//!
//! Pure: no clock, no randomness, no I/O.

use super::family::VendoredFamilyModel;
use super::family::{row_leaf, verify_row_in_family, FamilyFault, FamilyVerdict};
use super::{Digest32, Invalid, KeyDirectory, KeyLookup, Value, VerifiedRow};
use crate::prelude::*;
use ciris_crypto::composite::CompositePublicKey;

/// The row type of every accord row: an attestation, `scores`.
pub const ACCORD_ROW_TYPE: &str = "scores";
/// The family id of `accord:invoke:constitutional:{halt_id}`.
pub const FAMILY_CONSTITUTIONAL: &str = "accord:invoke:constitutional:.halt_id";
/// The family id of `accord:invoke:notify:{notify_id}`.
pub const FAMILY_NOTIFY: &str = "accord:invoke:notify:.notify_id";
/// The family id of `accord:invoke:drill:{drill_id}`.
pub const FAMILY_DRILL: &str = "accord:invoke:drill:.drill_id";
/// The family id of `accord:lifecycle:{kind}`.
pub const FAMILY_LIFECYCLE: &str = "accord:lifecycle:.kind";
/// `halt_fuse_secs` where the charter omits it (CC 4.2.1.1).
pub const DEFAULT_HALT_FUSE_SECS: u32 = 86_400;

const INVOCATION_MEMBERS: [&str; 7] = [
    "author",
    "accord_root",
    "invocation_id",
    "nonce",
    "asserted_at",
    "valid_until",
    "payload_digest",
];
const LIFECYCLE_MEMBERS: [&str; 7] = [
    "refs",
    "dimension",
    "accord_root",
    "invocation_id",
    "nonce",
    "asserted_at",
    "valid_until",
];

/// The kind of an invocation, read from its family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeKind {
    /// `accord:invoke:constitutional:{halt_id}`: the halt.
    Constitutional,
    /// `accord:invoke:notify:{notify_id}`.
    Notify,
    /// `accord:invoke:drill:{drill_id}`.
    Drill,
}

impl InvokeKind {
    /// The kind of a family id, if it is an invocation's.
    #[must_use]
    pub fn from_family(family: &str) -> Option<Self> {
        match family {
            FAMILY_CONSTITUTIONAL => Some(Self::Constitutional),
            FAMILY_NOTIFY => Some(Self::Notify),
            FAMILY_DRILL => Some(Self::Drill),
            _ => None,
        }
    }

    /// The kind's family id.
    #[must_use]
    pub fn family(self) -> &'static str {
        match self {
            Self::Constitutional => FAMILY_CONSTITUTIONAL,
            Self::Notify => FAMILY_NOTIFY,
            Self::Drill => FAMILY_DRILL,
        }
    }

    /// The lowercase kind (CC 4.2.1.1).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Constitutional => "constitutional",
            Self::Notify => "notify",
            Self::Drill => "drill",
        }
    }
}

/// The kind of a lifecycle row, read from its dimension's leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    /// `accord:lifecycle:confirmed`: keeps a lone halt past its fuse.
    Confirmed,
    /// `accord:lifecycle:active`: ends the named halt.
    Active,
}

impl LifecycleKind {
    /// The leaf (`confirmed` or `active`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Active => "active",
        }
    }
}

/// One holder of the bundle in force.
#[derive(Debug, Clone)]
pub struct RosterHolder {
    /// The holder's identity reference (the statement's `iss`).
    pub identity_ref: String,
    /// The composite key the bundle names for the holder.
    pub key: CompositePublicKey,
}

/// The holders a halt is verified against: those of the bundle in force
/// (CC 4.2.1.1), with the bundle's object id, the accord's `family_key_id` and
/// the charter's `halt_fuse_secs`.
#[derive(Debug, Clone)]
pub struct HaltRoster {
    accord_root: String,
    bundle: Digest32,
    holders: Vec<(String, Digest32, CompositePublicKey)>,
    halt_fuse_secs: Option<u32>,
}

impl HaltRoster {
    /// A roster from the bundle's parts. `holders` is the bundle's roster;
    /// a repeated identity reference is kept once.
    #[must_use]
    pub fn new(
        accord_root: impl Into<String>,
        bundle: Digest32,
        holders: Vec<RosterHolder>,
        halt_fuse_secs: Option<u32>,
    ) -> Self {
        let mut hs: Vec<(String, Digest32, CompositePublicKey)> = Vec::new();
        for h in holders {
            if !hs.iter().any(|(r, ..)| *r == h.identity_ref) {
                let kid = super::thumbprint(&h.key);
                hs.push((h.identity_ref, kid, h.key));
            }
        }
        Self {
            accord_root: accord_root.into(),
            bundle,
            holders: hs,
            halt_fuse_secs,
        }
    }

    /// The roster of a valid bundle's placement.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn from_placement(p: &super::genesis::GenesisPlacement) -> Self {
        Self::new(
            p.family_key_id.clone(),
            p.object_id,
            p.holders
                .iter()
                .map(|h| RosterHolder {
                    identity_ref: h.identity_ref.clone(),
                    key: h.key.clone(),
                })
                .collect(),
            p.charter.halt_fuse_secs,
        )
    }

    /// The accord's `family_key_id`.
    #[must_use]
    pub fn accord_root(&self) -> &str {
        &self.accord_root
    }

    /// The bundle's object id.
    #[must_use]
    pub fn bundle(&self) -> &Digest32 {
        &self.bundle
    }

    /// The holders' identity references, in roster order.
    pub fn holders(&self) -> impl Iterator<Item = &str> {
        self.holders.iter().map(|(r, ..)| r.as_str())
    }

    /// The fuse in force: the charter's `halt_fuse_secs`, or 86400.
    #[must_use]
    pub fn halt_fuse_secs(&self) -> u32 {
        self.halt_fuse_secs.unwrap_or(DEFAULT_HALT_FUSE_SECS)
    }

    /// A strict majority of the roster: `floor(N / 2) + 1`.
    #[must_use]
    pub fn majority(&self) -> usize {
        self.holders.len() / 2 + 1
    }

    /// The roster of the bundle a lifecycle row names in `refs.head` (see
    /// [`named_head`]): the bundle in force is the one named there.
    #[must_use]
    pub fn find_by_head<'a>(
        rosters: impl IntoIterator<Item = &'a HaltRoster>,
        head: &Digest32,
    ) -> Option<&'a HaltRoster> {
        rosters.into_iter().find(|r| r.bundle == *head)
    }

    /// The roster of the placement whose object id is `head`, from a set of
    /// valid bundles' placements.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn from_placements_by_head(
        placements: &[super::genesis::GenesisPlacement],
        head: &Digest32,
    ) -> Option<Self> {
        placements
            .iter()
            .find(|p| p.object_id == *head)
            .map(Self::from_placement)
    }

    fn holder_of_kid(&self, kid: &Digest32) -> Option<&str> {
        self.holders
            .iter()
            .find(|(_, k, _)| k == kid)
            .map(|(r, ..)| r.as_str())
    }
}

impl KeyDirectory for HaltRoster {
    fn lookup(&self, kid: &Digest32, _asserted_at: u64) -> KeyLookup {
        self.holders
            .iter()
            .find(|(_, k, _)| k == kid)
            .map_or(KeyLookup::NotHeld, |(.., pk)| {
                KeyLookup::Held(Box::new(pk.clone()))
            })
    }
}

/// Why an accord row (or one statement of it) is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HaltRefusal {
    /// The statement itself is Invalid (CC 2.6.1).
    Statement(Invalid),
    /// The signer's key is no holder's key in the bundle in force.
    NotAHolder,
    /// `iss` is not the identity reference of the holder whose key signed.
    IssNotHolder,
    /// The row type is not `scores`.
    WrongRowType,
    /// Header -70002 is not the family this reading expects (an invocation
    /// read as a lifecycle row, or the reverse).
    WrongFamily {
        /// The family the header carries.
        family: String,
    },
    /// The family's rules fail (the author column, `iss` against `author`).
    Family(FamilyFault),
    /// A member is missing, malformed, or outside the closed map.
    Member {
        /// The member.
        member: &'static str,
    },
    /// `accord_root` is not the roster's `family_key_id`.
    OtherAccord,
    /// `refs.head` is not the roster's bundle.
    OtherBundle,
    /// `refs.target` names another row than the halt presented.
    OtherHalt,
    /// The row `refs.target` names is not a `constitutional` halt.
    TargetNotAHalt,
    /// The statement is a voice of another row than the one counted.
    OtherRow,
    /// No statement was presented.
    NoStatements,
    /// `valid_until` is not after `asserted_at`: the row is Invalid.
    ValidUntilNotAfterAssertedAt,
    /// Fewer distinct holders than a strict majority of the roster.
    CountUnmet {
        /// Distinct holders whose statements count.
        have: usize,
        /// The strict majority.
        need: usize,
    },
}

impl HaltRefusal {
    /// A stable token for logs and vectors.
    #[must_use]
    pub fn token(&self) -> String {
        match self {
            Self::Statement(i) => format!("statement_invalid:{}", invalid_token(i)),
            Self::NotAHolder => "not_a_holder".into(),
            Self::IssNotHolder => "iss_not_holder".into(),
            Self::WrongRowType => "wrong_row_type".into(),
            Self::WrongFamily { .. } => "wrong_family".into(),
            Self::Family(f) => format!(
                "family:{}",
                match f {
                    FamilyFault::UnregisteredFamily => "unregistered_family",
                    FamilyFault::AuthorColumn => "author_column",
                    FamilyFault::IssNotInRole => "iss_not_in_role",
                    FamilyFault::DimensionMissing => "dimension_missing",
                    FamilyFault::AuthorshipUndetermined => "authorship_undetermined",
                    FamilyFault::NoArmHolds => "no_arm_holds",
                }
            ),
            Self::Member { member } => format!("member:{member}"),
            Self::OtherAccord => "other_accord".into(),
            Self::OtherBundle => "other_bundle".into(),
            Self::OtherHalt => "other_halt".into(),
            Self::TargetNotAHalt => "target_not_a_halt".into(),
            Self::OtherRow => "other_row".into(),
            Self::NoStatements => "no_statements".into(),
            Self::ValidUntilNotAfterAssertedAt => "valid_until_not_after_asserted_at".into(),
            Self::CountUnmet { .. } => "count_unmet".into(),
        }
    }
}

fn invalid_token(i: &Invalid) -> String {
    match i {
        Invalid::NotDeterministic { part, .. } => format!("not_deterministic:{part}"),
        Invalid::NotCoseSign1 => "not_cose_sign1".into(),
        Invalid::Malformed { member } => format!("malformed:{member}"),
        Invalid::UnexpectedMember { within } => format!("unexpected:{within}"),
        Invalid::TimeDisagreement { claim } => format!("time:{claim}"),
        Invalid::SetOrder { member } => format!("set_order:{member}"),
        Invalid::KidMismatch => "kid_mismatch".into(),
        Invalid::BadSignature => "bad_signature".into(),
        Invalid::KeyNotValid => "key_not_valid".into(),
        Invalid::DisclosureUnmatched => "disclosure_unmatched".into(),
        Invalid::DuplicateDigest => "duplicate_digest".into(),
        Invalid::UnregisteredFamily => "unregistered_family".into(),
        Invalid::DimensionFamily => "dimension_family".into(),
        Invalid::DimensionRefused { token } => format!("dimension_refused:{token}"),
        Invalid::DimensionUnregistered => "dimension_unregistered".into(),
    }
}

/// A verified invocation: one holder's statement under the bundle in force.
/// Only [`verify_invocation_row`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationRow {
    kind: InvokeKind,
    row_id: Digest32,
    statement_id: Digest32,
    author: String,
    invocation_id: String,
    nonce: [u8; 32],
    asserted_at: u64,
    valid_until: u64,
    payload_digest: Option<Digest32>,
}

impl InvocationRow {
    /// The kind, from the family.
    #[must_use]
    pub fn kind(&self) -> InvokeKind {
        self.kind
    }
    /// The row id: the name a lifecycle row's `refs.target` uses.
    #[must_use]
    pub fn row_id(&self) -> &Digest32 {
        &self.row_id
    }
    /// The statement id.
    #[must_use]
    pub fn statement_id(&self) -> &Digest32 {
        &self.statement_id
    }
    /// The holder who signs (`author` = `iss`).
    #[must_use]
    pub fn author(&self) -> &str {
        &self.author
    }
    /// `invocation_id`.
    #[must_use]
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }
    /// `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    /// `asserted_at`, POSIX ms. The fuse never reads it.
    #[must_use]
    pub fn asserted_at(&self) -> u64 {
        self.asserted_at
    }
    /// `valid_until`, POSIX ms: bounds the nonce's reuse, never the halt's reach.
    #[must_use]
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    /// `payload_digest`, on a notify.
    #[must_use]
    pub fn payload_digest(&self) -> Option<&Digest32> {
        self.payload_digest.as_ref()
    }
}

/// A statement refused while counting a lifecycle row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedStatement {
    /// Its index in the input.
    pub index: usize,
    /// Why.
    pub refusal: HaltRefusal,
}

/// A counted lifecycle row. Only [`verify_lifecycle_row`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRow {
    kind: LifecycleKind,
    row_id: Digest32,
    target: Digest32,
    head: Digest32,
    invocation_id: String,
    nonce: [u8; 32],
    asserted_at: u64,
    valid_until: u64,
    voices: Vec<String>,
    statement_ids: Vec<Digest32>,
    refused: Vec<RefusedStatement>,
}

impl LifecycleRow {
    /// The kind, from the dimension's leaf.
    #[must_use]
    pub fn kind(&self) -> LifecycleKind {
        self.kind
    }
    /// The row id, shared by every voice.
    #[must_use]
    pub fn row_id(&self) -> &Digest32 {
        &self.row_id
    }
    /// `refs.target`: the halt's row id.
    #[must_use]
    pub fn target(&self) -> &Digest32 {
        &self.target
    }
    /// `refs.head`: the bundle counted over.
    #[must_use]
    pub fn head(&self) -> &Digest32 {
        &self.head
    }
    /// The lifecycle row's own `invocation_id`.
    #[must_use]
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }
    /// `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    /// `asserted_at`, POSIX ms.
    #[must_use]
    pub fn asserted_at(&self) -> u64 {
        self.asserted_at
    }
    /// `valid_until`, POSIX ms.
    #[must_use]
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    /// The holders counted, sorted, one each.
    #[must_use]
    pub fn voices(&self) -> &[String] {
        &self.voices
    }
    /// The statement ids counted, in input order.
    #[must_use]
    pub fn statement_ids(&self) -> &[Digest32] {
        &self.statement_ids
    }
    /// The statements not counted, and why.
    #[must_use]
    pub fn refused(&self) -> &[RefusedStatement] {
        &self.refused
    }
}

/// Why a lifecycle row does not count, with the statements refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRefusal {
    /// The reason: where no statement is valid, the first statement's own
    /// refusal; otherwise [`HaltRefusal::CountUnmet`].
    pub reason: HaltRefusal,
    /// Every statement refused.
    pub refused: Vec<RefusedStatement>,
}

// ------------------------------------------------------------------ members

fn member(member: &'static str) -> HaltRefusal {
    HaltRefusal::Member { member }
}

fn closed(p: &Value, allowed: &[&str]) -> Result<(), HaltRefusal> {
    let m = p.as_map().ok_or(member("payload"))?;
    for (k, _) in m {
        match k.as_text() {
            Some(n) if allowed.contains(&n) => {},
            _ => return Err(member("closed_map")),
        }
    }
    Ok(())
}

fn text<'a>(p: &'a Value, k: &'static str) -> Result<&'a str, HaltRefusal> {
    p.get_text(k).and_then(Value::as_text).ok_or(member(k))
}

fn uint(p: &Value, k: &'static str) -> Result<u64, HaltRefusal> {
    p.get_text(k).and_then(Value::as_u64).ok_or(member(k))
}

fn nonce(p: &Value) -> Result<[u8; 32], HaltRefusal> {
    p.get_text("nonce")
        .and_then(Value::as_bytes)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(member("nonce"))
}

fn hash_digest(v: &Value) -> Option<Digest32> {
    match v.as_array()? {
        [alg, d] if alg.as_i64() == Some(-16) => d.as_bytes()?.try_into().ok(),
        _ => None,
    }
}

fn row_ref(v: &Value) -> Option<Digest32> {
    match v.as_array()? {
        [ed, id] if ed.as_u64() == Some(super::EDITION) => hash_digest(id),
        _ => None,
    }
}

/// One statement through the row reader, the family model and the roster.
fn read_statement(bytes: &[u8], roster: &HaltRoster) -> Result<VerifiedRow, HaltRefusal> {
    let row = match verify_row_in_family(bytes, roster, &VendoredFamilyModel) {
        FamilyVerdict::Valid { row, .. } => *row,
        FamilyVerdict::Invalid(i) => return Err(HaltRefusal::Statement(i)),
        FamilyVerdict::FamilyInvalid(f) => return Err(HaltRefusal::Family(f)),
        // The roster is the whole key directory: a key it does not hold is
        // no holder's.
        FamilyVerdict::Waiting(_) => return Err(HaltRefusal::NotAHolder),
    };
    if roster.holder_of_kid(&row.kid) != Some(row.iss.as_str()) {
        return Err(HaltRefusal::IssNotHolder);
    }
    if row.row_type != ACCORD_ROW_TYPE {
        return Err(HaltRefusal::WrongRowType);
    }
    Ok(row)
}

/// The rules every accord row shares past its members (CC rulings on
/// rc20 64c5918): `sub` is the accord's `family_key_id` (= `accord_root`),
/// and `valid_until` is after `asserted_at`. Returns `valid_until`.
fn sub_and_window(row: &VerifiedRow, roster: &HaltRoster) -> Result<u64, HaltRefusal> {
    if row.sub != roster.accord_root {
        return Err(member("sub"));
    }
    let valid_until = uint(&row.payload, "valid_until")?;
    if valid_until <= row.asserted_at {
        return Err(HaltRefusal::ValidUntilNotAfterAssertedAt);
    }
    Ok(valid_until)
}

/// The decoded payload of a statement, unverified: only for choosing which
/// roster to verify it under ([`named_head`], [`named_accord_root`]).
fn unverified_payload(statement: &[u8]) -> Option<Value> {
    let Value::Tag(18, inner) = crate::cde::decode(statement).ok()? else {
        return None;
    };
    let payload = inner.as_array()?.get(2)?.as_bytes()?;
    crate::cde::decode(payload).ok()
}

/// The bundle a lifecycle statement names in `refs.head`, read without
/// verifying it: the key for choosing the roster ([`HaltRoster::find_by_head`]).
/// The reader then verifies the statement under that roster, which checks the
/// head again ([`HaltRefusal::OtherBundle`]).
#[must_use]
pub fn named_head(statement: &[u8]) -> Option<Digest32> {
    unverified_payload(statement)?
        .get_text("refs")?
        .get_text("head")
        .and_then(row_ref)
}

/// The `accord_root` a statement names, read without verifying it: the key
/// for choosing the accord whose bundle in force verifies an invocation. The
/// reader checks it again ([`HaltRefusal::OtherAccord`]).
#[must_use]
pub fn named_accord_root(statement: &[u8]) -> Option<String> {
    unverified_payload(statement)?
        .get_text("accord_root")?
        .as_text()
        .map(str::to_owned)
}

// ------------------------------------------------------------------ readers

/// Verify one invocation statement (`constitutional`, `notify` or `drill`)
/// against the holders of the bundle in force (CC 4.2.1.1).
///
/// The statement must be a valid row under one holder's key with `iss` that
/// holder; its family one of the three invocation families (the kind); its
/// payload exactly the invocation's members, `author` the `iss`,
/// `accord_root` the roster's, `nonce` 32 bytes, and `payload_digest` present
/// on a notify and on nothing else.
///
/// # Errors
/// [`HaltRefusal`].
pub fn verify_invocation_row(
    bytes: &[u8],
    roster: &HaltRoster,
) -> Result<InvocationRow, HaltRefusal> {
    let row = read_statement(bytes, roster)?;
    let kind = InvokeKind::from_family(&row.family).ok_or_else(|| HaltRefusal::WrongFamily {
        family: row.family.clone(),
    })?;
    let p = &row.payload;
    closed(p, &INVOCATION_MEMBERS)?;
    // The family model already requires `author` == `iss` (authored, no roles).
    let author = row.author.clone().ok_or(member("author"))?;
    if text(p, "accord_root")? != roster.accord_root {
        return Err(HaltRefusal::OtherAccord);
    }
    let invocation_id = text(p, "invocation_id")?.to_owned();
    let nonce = nonce(p)?;
    let valid_until = sub_and_window(&row, roster)?;
    let payload_digest = match (kind, p.get_text("payload_digest")) {
        (InvokeKind::Notify, Some(d)) => Some(hash_digest(d).ok_or(member("payload_digest"))?),
        (InvokeKind::Notify, None) | (_, Some(_)) => return Err(member("payload_digest")),
        (_, None) => None,
    };
    Ok(InvocationRow {
        kind,
        row_id: row.row_id,
        statement_id: row.statement_id,
        author,
        invocation_id,
        nonce,
        asserted_at: row.asserted_at,
        valid_until,
        payload_digest,
    })
}

struct LifecycleVoice {
    kind: LifecycleKind,
    row: VerifiedRow,
    target: Digest32,
    head: Digest32,
    nonce: [u8; 32],
    valid_until: u64,
}

fn read_lifecycle_statement(
    bytes: &[u8],
    roster: &HaltRoster,
    halt: &InvocationRow,
) -> Result<LifecycleVoice, HaltRefusal> {
    let row = read_statement(bytes, roster)?;
    if row.family != FAMILY_LIFECYCLE {
        return Err(HaltRefusal::WrongFamily {
            family: row.family.clone(),
        });
    }
    let p = &row.payload;
    closed(p, &LIFECYCLE_MEMBERS)?;
    let kind = match row_leaf(&row).as_deref() {
        Some("confirmed") => LifecycleKind::Confirmed,
        Some("active") => LifecycleKind::Active,
        _ => return Err(member("dimension")),
    };
    if text(p, "accord_root")? != roster.accord_root {
        return Err(HaltRefusal::OtherAccord);
    }
    text(p, "invocation_id")?;
    let nonce = nonce(p)?;
    let valid_until = sub_and_window(&row, roster)?;
    let refs = p.get_text("refs").ok_or(member("refs"))?;
    closed(refs, &["head", "target"])?;
    let head = refs
        .get_text("head")
        .and_then(row_ref)
        .ok_or(member("head"))?;
    let target = refs
        .get_text("target")
        .and_then(row_ref)
        .ok_or(member("target"))?;
    if head != roster.bundle {
        return Err(HaltRefusal::OtherBundle);
    }
    if target != halt.row_id {
        return Err(HaltRefusal::OtherHalt);
    }
    if halt.kind != InvokeKind::Constitutional {
        return Err(HaltRefusal::TargetNotAHalt);
    }
    Ok(LifecycleVoice {
        kind,
        row,
        target,
        head,
        nonce,
        valid_until,
    })
}

/// Count a lifecycle row (`confirmed` or `active`) over the halt it names
/// (CC 4.2.1.3): each statement a holder's under the bundle in force, the
/// family `accord:lifecycle:{kind}`, the payload exactly the lifecycle
/// members with `refs.target` the halt's row id and `refs.head` the roster's
/// bundle, and the halt a `constitutional` one. The voices are the distinct
/// `iss` of the statements of one row; the row counts at a strict majority
/// of the roster.
///
/// A statement's own fault refuses that statement only. Statements of more
/// than one row: the row with the most voices is counted (on a tie, the
/// lowest row id) and the others are refused [`HaltRefusal::OtherRow`].
///
/// # Errors
/// [`LifecycleRefusal`]: the first statement's refusal where none is valid,
/// [`HaltRefusal::NoStatements`] on none, otherwise
/// [`HaltRefusal::CountUnmet`].
pub fn verify_lifecycle_row(
    statements: &[Vec<u8>],
    roster: &HaltRoster,
    halt: &InvocationRow,
) -> Result<LifecycleRow, LifecycleRefusal> {
    let mut refused = Vec::new();
    let mut voices: Vec<(usize, LifecycleVoice)> = Vec::new();
    for (index, s) in statements.iter().enumerate() {
        match read_lifecycle_statement(s, roster, halt) {
            Ok(v) => voices.push((index, v)),
            Err(refusal) => refused.push(RefusedStatement { index, refusal }),
        }
    }
    if voices.is_empty() {
        let reason = refused
            .first()
            .map_or(HaltRefusal::NoStatements, |r| r.refusal.clone());
        return Err(LifecycleRefusal { reason, refused });
    }
    // The row with the most distinct voices; a tie goes to the lowest row id.
    let mut by_row: BTreeMap<Digest32, BTreeSet<&str>> = BTreeMap::new();
    for (_, v) in &voices {
        by_row
            .entry(v.row.row_id)
            .or_default()
            .insert(v.row.iss.as_str());
    }
    let chosen = by_row
        .iter()
        .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)))
        .map(|(id, _)| *id)
        .expect("non-empty");
    let mut counted: Vec<(usize, LifecycleVoice)> = Vec::new();
    for (index, v) in voices {
        if v.row.row_id == chosen {
            counted.push((index, v));
        } else {
            refused.push(RefusedStatement {
                index,
                refusal: HaltRefusal::OtherRow,
            });
        }
    }
    refused.sort_by_key(|r| r.index);
    let names: BTreeSet<String> = counted.iter().map(|(_, v)| v.row.iss.clone()).collect();
    let need = roster.majority();
    // Strict majority of the standing roster: 2·have > N.
    if names.len() < need {
        return Err(LifecycleRefusal {
            reason: HaltRefusal::CountUnmet {
                have: names.len(),
                need,
            },
            refused,
        });
    }
    let first = &counted[0].1;
    let invocation_id = text(&first.row.payload, "invocation_id")
        .map(str::to_owned)
        .unwrap_or_default();
    Ok(LifecycleRow {
        kind: first.kind,
        row_id: chosen,
        target: first.target,
        head: first.head,
        invocation_id,
        nonce: first.nonce,
        asserted_at: first.row.asserted_at,
        valid_until: first.valid_until,
        voices: names.into_iter().collect(),
        statement_ids: counted.iter().map(|(_, v)| v.row.statement_id).collect(),
        refused,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{identity_ref, row_ref as rref, sign_row_statement};
    use super::*;
    use ciris_crypto::composite::CompositeSigningKey;

    fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
    }
    fn idr(k: &CompositeSigningKey) -> String {
        identity_ref(&super::super::thumbprint(k.public_key()))
    }
    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    #[test]
    fn the_families_are_registered() {
        for f in [
            FAMILY_CONSTITUTIONAL,
            FAMILY_NOTIFY,
            FAMILY_DRILL,
            FAMILY_LIFECYCLE,
        ] {
            assert!(crate::namespace_match::is_registered_family_id(f), "{f}");
        }
    }

    #[test]
    fn halt_then_confirmation_round_trip() {
        let (a, b, c) = (key(1), key(2), key(3));
        let roster = HaltRoster::new(
            "humanity-accord",
            [7; 32],
            [&a, &b, &c]
                .iter()
                .map(|k| RosterHolder {
                    identity_ref: idr(k),
                    key: k.public_key().clone(),
                })
                .collect(),
            None,
        );
        assert_eq!(roster.majority(), 2);
        assert_eq!(roster.halt_fuse_secs(), 86_400);
        let halt_p = Value::Map(vec![
            (t("author"), t(&idr(&a))),
            (t("accord_root"), t("humanity-accord")),
            (t("invocation_id"), t("halt-1")),
            (t("nonce"), Value::Bytes(vec![1; 32])),
            (t("asserted_at"), Value::Uint(1_763_200_000_000)),
            (t("valid_until"), Value::Uint(1_763_286_400_000)),
        ]);
        let st = sign_row_statement(
            &a,
            &idr(&a),
            "humanity-accord",
            "scores",
            FAMILY_CONSTITUTIONAL,
            &halt_p,
            vec![],
        )
        .unwrap();
        let halt = verify_invocation_row(&st, &roster).unwrap();
        assert_eq!(halt.kind(), InvokeKind::Constitutional);
        let life = Value::Map(vec![
            (
                t("refs"),
                Value::Map(vec![
                    (t("head"), rref(&[7; 32])),
                    (t("target"), rref(halt.row_id())),
                ]),
            ),
            (t("dimension"), t("accord:lifecycle:confirmed:v1")),
            (t("accord_root"), t("humanity-accord")),
            (t("invocation_id"), t("confirm-1")),
            (t("nonce"), Value::Bytes(vec![2; 32])),
            (t("asserted_at"), Value::Uint(1_763_200_100_000)),
            (t("valid_until"), Value::Uint(1_763_286_400_000)),
        ]);
        let sign = |k: &CompositeSigningKey| {
            sign_row_statement(
                k,
                &idr(k),
                "humanity-accord",
                "scores",
                FAMILY_LIFECYCLE,
                &life,
                vec![],
            )
            .unwrap()
        };
        let row = verify_lifecycle_row(&[sign(&a), sign(&b)], &roster, &halt).unwrap();
        assert_eq!(row.kind(), LifecycleKind::Confirmed);
        assert_eq!(row.voices().len(), 2);
        // One voice is short; the same voice twice is still one.
        let short = verify_lifecycle_row(&[sign(&a), sign(&a)], &roster, &halt).unwrap_err();
        assert_eq!(short.reason, HaltRefusal::CountUnmet { have: 1, need: 2 });
        // The halt's bytes presented as a lifecycle row.
        let replay = verify_lifecycle_row(&[st], &roster, &halt).unwrap_err();
        assert!(matches!(replay.reason, HaltRefusal::WrongFamily { .. }));
    }
}
