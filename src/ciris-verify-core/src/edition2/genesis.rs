//! The genesis bundle of edition 2, `ceg-genesis-bundle/2` (CC 2.6.1.11,
//! CC 5.3.4, CIRISConstitution rc20 ae09856).
//!
//! A bundle is a **counted** signed object that is not a row: one
//! `COSE_Sign1` per holder over one payload, with no `author`, so every voice
//! has the same object id (`["CEG-object/2", typ, null, payload]`). Its
//! payload names rows and never copies them: each holder's, seat's and
//! witness's `key:record` and each seat's `identity:occurrence` binding stand
//! in `refs.also.cites` by row id. The bundle's own count is the canonical
//! conferral of every seat in `serve_nodes` (CC 4.2.1).
//!
//! # Answers
//!
//! [`GenesisVerdict`] has four forms:
//!
//! - **Valid**, with the [`GenesisPlacement`]: the holders, the seats with
//!   their bindings' two X-Wing keys, the witnesses and the charter, so a
//!   consumer does not place rows again;
//! - **Invalid** (`genesis_bundle_malformed`, with a reason) for a fault in
//!   the payload bytes themselves, which is final;
//! - **Waiting** on a named row, the predecessor or a voice's key the reader
//!   does not hold, and on nothing else;
//! - **concludes nothing** ([`Inconclusive`]): not anchored, the predecessor
//!   not valid, a named row Invalid or unplaced, a holder failing the custody
//!   gate, or the count not met. The bundle is held, never refused for
//!   another row's fault.
//!
//! A statement's own fault (its header, its `iat`, its signature, a signer
//! with no role) refuses that statement only ([`RefusedStatement`]); the
//! other statements stand.
//!
//! # Order
//!
//! For each object (statements grouped by object id, never merged):
//!
//! 1. each statement: the object header (`verify_object_statement`'s
//!    structure), `typ` `ceg-genesis-bundle/2`, `iat` present;
//! 2. the payload: the closed CDDL map, the sets, then the prose checks
//!    (`version` 1 iff no `prev`; `holders` / `serve_nodes` / `witnesses`
//!    disjoint; the commitments keyed by exactly `holders`; `scope` holding
//!    `infra:attest` and `infra:serve`; the witness members together, with
//!    `witness_quorum = ⌊|witnesses| / 2⌋ + 1`). Then each statement's `iat`
//!    against `⌊asserted_at / 1000⌋`;
//! 3. a first bundle: the anchor;
//! 4. a later bundle: the predecessor, `version` = prev's + 1, the same
//!    `family_key_id`;
//! 5. the named rows: Waiting on any not held; then each placed by family and
//!    author, verified under its own key (a binding under its seat's), the
//!    seat bindings' X-Wing members and in-row separation, then the custody
//!    gate at each holder seat (CC 4.2.2.1);
//! 6. the voices: each statement's `kid` resolved to its `iss`'s key and its
//!    signature verified;
//! 7. the count: a first bundle every holder; a later one a strict majority
//!    of the predecessor's holders, plus each holder it adds and each whose
//!    recovery commitment it changes. Waiting is never counted.
//!
//! # Tier
//!
//! `std`: the custody gate verifies X.509 attestation chains
//! ([`crate::accord_custody_attestation::verify_yubikey_piv_attestation`])
//! against roots from a [`TrustAnchorStore`]. Production passes
//! [`crate::trust_anchor_store::baked::default_store`]; a test passes its own
//! mock root. No clock, no randomness, no I/O.

use super::keys::{check_key_record, KeyRecord, KeyRecordError, PqCustody, KEY_RECORD_FAMILY};
use super::{
    cde, identity_ref, is_identity_ref, object_id, row_id, thumbprint, verify_object_statement,
    verify_row_statement, Digest32, Invalid, KeyDirectory, KeyLookup, ObjectVerdict, Value,
    Verdict, VerifiedRow,
};
use crate::accord_custody_attestation::{verify_yubikey_piv_attestation, CustodyError};
use crate::prelude::*;
use crate::trust_anchor_store::{environments, Purpose, TrustAnchorStore};
use ciris_crypto::composite::{CompositePublicKey, MLDSA65_PK_LEN};

/// The `typ` of the genesis bundle.
pub const GENESIS_BUNDLE_TYP: &str = "ceg-genesis-bundle/2";
/// The family of a seat's binding (CC 3.3.6.2).
pub const BINDING_FAMILY: &str = "identity:occurrence";
/// The length of an X-Wing public key, `pk_M ‖ pk_X`.
pub const XWING_PUBKEY_LEN: usize = 1216;
/// The ML-KEM-768 half of an X-Wing public key, bytes `0..1184`.
pub const XWING_PK_M_LEN: usize = 1184;
/// `halt_fuse_secs` where the charter states none (CC 4.2.1.1).
pub const DEFAULT_HALT_FUSE_SECS: u32 = 86_400;
/// The scope every bundle's charter holds (CC 3.2 Rooted).
pub const REQUIRED_SCOPE: [&str; 2] = ["infra:attest", "infra:serve"];
/// The token of every [`GenesisVerdict::Invalid`].
pub const GENESIS_BUNDLE_MALFORMED: &str = "genesis_bundle_malformed";
/// The hardware class whose chain this reader verifies (YubiKey PIV).
pub const CLASS_YUBIKEY_5_FIPS: &str = "YubiKey_5_FIPS";

const C_ISS: i64 = 1;
const C_IAT: i64 = 6;
const H_KID: i64 = 4;
const H_CWT: i64 = 15;
const H_TYP: i64 = 16;
const H_FAMILY: i64 = -70002;
const H_ROW_TYPE: i64 = -70001;
const C_SUB: i64 = 2;

// ------------------------------------------------------------------ inputs

/// A reader's anchor: what it was built or configured to trust, never a
/// member of the wire (CC 5.3.4). The release default is the holders'
/// thumbprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// The set of the first bundle's holders' composite-key thumbprints. A
    /// first bundle verifies only where its `holders` equal this set and
    /// every one of them signed it.
    Thumbprints(BTreeSet<Digest32>),
    /// The object id of one first bundle. Any other first bundle is void for
    /// this reader.
    ObjectId(Digest32),
}

/// A predecessor bundle the reader holds, by its object id.
#[derive(Debug, Clone, Copy)]
pub enum Predecessor<'a> {
    /// Held and Valid.
    Valid(&'a GenesisPlacement),
    /// Held, and not Valid (Invalid, or concluding nothing).
    NotValid(Digest32),
}

impl Predecessor<'_> {
    fn object_id(&self) -> Digest32 {
        match self {
            Self::Valid(p) => p.object_id,
            Self::NotValid(id) => *id,
        }
    }
}

/// What the reader is given.
#[derive(Debug, Clone, Copy)]
pub struct GenesisInput<'a> {
    /// The bundle statements, each one `COSE_Sign1`; they may be over
    /// several payloads (each its own object).
    pub statements: &'a [Vec<u8>],
    /// The row statements the reader holds, by row id. The named rows are
    /// read from here; a held `key:record` that is not named may answer for
    /// a later bundle's voice (the key plane).
    pub rows: &'a BTreeMap<Digest32, Vec<u8>>,
    /// The reader's anchor, for a first bundle. `None`: nothing is rooted.
    pub anchor: Option<&'a Anchor>,
    /// The predecessor bundles held, for a later bundle.
    pub predecessors: &'a [Predecessor<'a>],
    /// The attestation roots of the custody gate: production passes
    /// [`crate::trust_anchor_store::baked::default_store`].
    pub attestation_roots: &'a TrustAnchorStore,
}

// ------------------------------------------------------------------ outputs

/// The charter a bundle carries (CC 2.1, CC 4.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisCharter {
    /// One commitment per holder (CC 3.2 T3), by identity reference.
    pub recovery_commitments: BTreeMap<String, Digest32>,
    /// The root's scope set.
    pub scope: Vec<String>,
    /// A lone halt's fuse, where stated ([`Self::halt_fuse`] applies the default).
    pub halt_fuse_secs: Option<u32>,
    /// The attach window, where stated.
    pub attach_window_secs: Option<u32>,
    /// The witness cadence, in witnessed mode.
    pub witness_cadence_secs: Option<u32>,
    /// The witness quorum, in witnessed mode.
    pub witness_quorum: Option<u32>,
    /// The witness directory (empty: witnessed mode off).
    pub witnesses: Vec<String>,
}

impl GenesisCharter {
    /// The fuse in force: `halt_fuse_secs`, or 86400 where absent.
    #[must_use]
    pub fn halt_fuse(&self) -> u32 {
        self.halt_fuse_secs.unwrap_or(DEFAULT_HALT_FUSE_SECS)
    }
}

/// A seated holder.
#[derive(Debug, Clone)]
pub struct PlacedHolder {
    /// The holder's identity reference.
    pub identity_ref: String,
    /// The thumbprint of the key its named record holds.
    pub kid: Digest32,
    /// That composite key.
    pub key: CompositePublicKey,
    /// The charter's recovery commitment for the holder.
    pub recovery_commitment: Digest32,
    /// The hardware class, admitted through the custody gate.
    pub hardware_class: String,
    /// The ML-DSA-65 half's custody (always `removable_offline` when seated).
    pub pq_custody: PqCustody,
    /// The named key record's row id.
    pub record: Digest32,
}

/// A seated serve node.
#[derive(Debug, Clone)]
pub struct PlacedSeat {
    /// The seat's identity reference.
    pub identity_ref: String,
    /// The thumbprint of the key its named record holds.
    pub kid: Digest32,
    /// That composite key.
    pub key: CompositePublicKey,
    /// The record's `valid_until`, POSIX ms.
    pub valid_until: u64,
    /// The binding's `transit_xwing_pubkey`, `pk_M ‖ pk_X`.
    pub transit_xwing_pubkey: [u8; XWING_PUBKEY_LEN],
    /// The binding's `onion_hop_xwing_pubkey`, `pk_M ‖ pk_X`.
    pub onion_hop_xwing_pubkey: [u8; XWING_PUBKEY_LEN],
    /// The named key record's row id.
    pub record: Digest32,
    /// The named binding's row id.
    pub binding: Digest32,
}

/// A witness in the charter's directory.
#[derive(Debug, Clone)]
pub struct PlacedWitness {
    /// The witness's identity reference.
    pub identity_ref: String,
    /// The thumbprint of the key its named record holds.
    pub kid: Digest32,
    /// That composite key.
    pub key: CompositePublicKey,
    /// The named key record's row id.
    pub record: Digest32,
}

/// What a Valid bundle yields (CC 2.6.1.11): a consumer does not place again.
#[derive(Debug, Clone)]
pub struct GenesisPlacement {
    /// The bundle's object id.
    pub object_id: Digest32,
    /// `version`.
    pub version: u32,
    /// `refs.prev`, on a later bundle.
    pub prev: Option<Digest32>,
    /// `asserted_at`, POSIX ms.
    pub asserted_at: u64,
    /// The accord's name.
    pub family_key_id: String,
    /// The roster, in `holders` order.
    pub holders: Vec<PlacedHolder>,
    /// The seats, in `serve_nodes` order; each canonical by this count.
    pub seats: Vec<PlacedSeat>,
    /// The witnesses, in directory order.
    pub witnesses: Vec<PlacedWitness>,
    /// The charter.
    pub charter: GenesisCharter,
    /// The identity references whose statements counted, sorted.
    pub counted: Vec<String>,
}

impl GenesisPlacement {
    /// Is `identity_ref` a seat of this bundle (its canonical conferral)?
    #[must_use]
    pub fn is_canonical(&self, identity_ref: &str) -> bool {
        self.seats.iter().any(|s| s.identity_ref == identity_ref)
    }

    fn holder(&self, identity_ref: &str) -> Option<&PlacedHolder> {
        self.holders.iter().find(|h| h.identity_ref == identity_ref)
    }
}

/// Why a payload is malformed (`genesis_bundle_malformed`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    /// A member is missing, unknown (the maps are closed), of the wrong type
    /// or out of its range.
    Schema {
        /// The member, as the CDDL names it.
        member: &'static str,
    },
    /// A set is unsorted or repeats an element.
    SetOrder {
        /// The member.
        member: &'static str,
    },
    /// `version` is 1 with a `prev`, not 1 without one, or not prev's + 1.
    VersionPrevMismatch,
    /// `holders`, `serve_nodes` and `witnesses` are not pairwise disjoint.
    HoldersSeatsOverlap,
    /// The keys of `recovery_commitments` are not exactly `holders`.
    RecoveryCommitmentsNotHolders,
    /// `scope` lacks `infra:attest` or `infra:serve`.
    ScopeMissingInfra,
    /// Some but not all of the three witness members.
    WitnessMembersPartial,
    /// `witness_quorum` is not `⌊|witnesses| / 2⌋ + 1`.
    WitnessQuorumMismatch,
    /// A later bundle changes `family_key_id` (CC 5.3.4).
    FamilyKeyIdChanged,
}

impl Malformed {
    /// The reason under `genesis_bundle_malformed`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Schema { .. } => "genesis_bundle_schema",
            Self::SetOrder { .. } => "federation_set_semantics_unsorted",
            Self::VersionPrevMismatch => "version_prev_mismatch",
            Self::HoldersSeatsOverlap => "holders_seats_overlap",
            Self::RecoveryCommitmentsNotHolders => "recovery_commitments_not_holders",
            Self::ScopeMissingInfra => "scope_missing_infra",
            Self::WitnessMembersPartial => "witness_members_partial",
            Self::WitnessQuorumMismatch => "witness_quorum_mismatch",
            Self::FamilyKeyIdChanged => "family_key_id_changed",
        }
    }
}

/// What a bundle waits on. Nothing else answers Waiting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenesisWaiting {
    /// Named rows not held, by row id, sorted.
    pub rows: Vec<Digest32>,
    /// The predecessor, by object id, where not held.
    pub prev: Option<Digest32>,
    /// Voices' keys not held, by kid, sorted (a later bundle only).
    pub kids: Vec<Digest32>,
}

/// Why a named row leaves the bundle concluding nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowFault {
    /// The row statement is Invalid as a row (CC 2.6.1.8).
    Row(Invalid),
    /// The key record's payload is refused.
    Record(KeyRecordError),
    /// The row is not signed by the key it records (a key record), or by its
    /// seat's recorded key (a binding).
    Signer,
    /// The statement's `iss` is not the payload's `author`.
    AuthorNotIss,
    /// A holder's record does not carry `accord_holder`.
    HolderNotAccordHolder,
    /// In a first bundle, a holder's record holds a key whose thumbprint is
    /// not the holder's identity reference.
    HolderNotGenesisKey,
    /// A seat's record's `identity_type` is not exactly `node`.
    SeatNotNode,
    /// The binding carries no `transport_destination` map.
    NoTransportDestination,
    /// The binding carries the earlier `transit_kex_pubkeys` pair.
    EarlierTransitPair,
    /// An X-Wing member is absent or not 1216 bytes.
    XWingMember {
        /// The member.
        member: &'static str,
    },
    /// An X-Wing half equals another key on the row (CC 3.3.6.2 in-row
    /// separation); the token names which half.
    XWingReuse {
        /// `onion_hop_ml_kem_768_reuse`, `onion_hop_x25519_reuse`,
        /// `transit_ml_kem_768_reuse` or `transit_x25519_reuse`.
        token: &'static str,
    },
    /// The seat carries `onion_relay.opt_out` (`seat_opted_out`).
    SeatOptedOut,
}

impl RowFault {
    /// A short name for the fault.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::Row(_) => "row_invalid",
            Self::Record(e) => e.token(),
            Self::Signer => "row_signer",
            Self::AuthorNotIss => "row_author_not_iss",
            Self::HolderNotAccordHolder => "holder_not_accord_holder",
            Self::HolderNotGenesisKey => "holder_not_genesis_key",
            Self::SeatNotNode => "seat_not_node",
            Self::NoTransportDestination => "binding_no_transport_destination",
            Self::EarlierTransitPair => "binding_earlier_transit_pair",
            Self::XWingMember { .. } => "binding_xwing_member",
            Self::XWingReuse { token } => token,
            Self::SeatOptedOut => "seat_opted_out",
        }
    }
}

/// Why a holder fails the custody gate (CC 4.2.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CustodyFault {
    /// The record carries no `hardware_class`.
    NoClass,
    /// The class's mechanism has no chain this reader verifies, or the
    /// record carries none: the class is unattested.
    Unattested,
    /// The chain does not verify to an attestation root the reader holds.
    ChainInvalid,
    /// The attested key is not the Ed25519 half of the record's key.
    AttestedKeyMismatch,
    /// The chain verifies but the mechanism's floor (FIPS, touch) is not met.
    FloorNotMet,
    /// `pq_custody` is not `removable_offline` (CC 4.2.3).
    PqCustody,
}

impl CustodyFault {
    /// A short name for the fault.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::NoClass => "custody_no_class",
            Self::Unattested => "custody_unattested",
            Self::ChainInvalid => "custody_chain_invalid",
            Self::AttestedKeyMismatch => "custody_attested_key_mismatch",
            Self::FloorNotMet => "custody_floor_not_met",
            Self::PqCustody => "custody_pq_not_removable_offline",
        }
    }
}

/// Why a bundle concludes nothing. It is held, never refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inconclusive {
    /// A first bundle the reader's anchor does not select (or no anchor).
    NotAnchored,
    /// The predecessor is held and not Valid.
    PrevNotValid,
    /// A named row with no place, two rows for one place, or a party with no row.
    RowUnplaced {
        /// The row, where one is at fault.
        row: Option<Digest32>,
        /// The party with no row, where one is.
        party: Option<String>,
    },
    /// A named row is Invalid, or breaks its place's rule.
    RowInvalid {
        /// The row.
        row: Digest32,
        /// Why.
        fault: RowFault,
    },
    /// A holder fails the custody gate.
    HolderCustody {
        /// The holder.
        holder: String,
        /// Why.
        fault: CustodyFault,
    },
    /// The count is not met.
    CountUnmet,
}

impl Inconclusive {
    /// The token.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::NotAnchored => "genesis_bundle_not_anchored",
            Self::PrevNotValid => "genesis_bundle_prev_not_valid",
            Self::RowUnplaced { .. } => "genesis_bundle_row_unplaced",
            Self::RowInvalid { .. } => "genesis_bundle_row_invalid",
            Self::HolderCustody { .. } => "genesis_holder_custody",
            Self::CountUnmet => "genesis_bundle_count_unmet",
        }
    }
}

/// The answer for one bundle (one object id).
#[derive(Debug, Clone)]
pub enum GenesisVerdict {
    /// Every rule holds and the count is met.
    Valid(Box<GenesisPlacement>),
    /// The payload is malformed (`genesis_bundle_malformed`): final.
    Invalid(Malformed),
    /// Something the reader does not hold.
    Waiting(GenesisWaiting),
    /// Held, not counted.
    Nothing(Inconclusive),
}

impl GenesisVerdict {
    /// The placement, if Valid.
    #[must_use]
    pub fn placement(&self) -> Option<&GenesisPlacement> {
        match self {
            Self::Valid(p) => Some(p),
            _ => None,
        }
    }
}

/// Why one statement is refused. The other statements stand.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatementFault {
    /// The object statement is Invalid (header, encoding, signature).
    Object(Invalid),
    /// Its `typ` is not `ceg-genesis-bundle/2`.
    NotGenesisBundle,
    /// It carries no `iat`.
    IatMissing,
    /// Its `iat` is not `⌊asserted_at / 1000⌋`.
    IatMismatch,
    /// In a first bundle, its `kid` is not the key the holder's named record
    /// holds.
    KidNotIss,
    /// Its `iss` is neither in the counting roster nor an added holder.
    NoRole,
}

impl StatementFault {
    /// A short name for the fault.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::Object(_) => "statement_invalid",
            Self::NotGenesisBundle => "statement_not_genesis_bundle",
            Self::IatMissing => "iat_missing",
            Self::IatMismatch => "iat_mismatch",
            Self::KidNotIss => "statement_kid_not_iss",
            Self::NoRole => "statement_no_role",
        }
    }
}

/// A refused statement, by its index in [`GenesisInput::statements`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedStatement {
    /// The index.
    pub index: usize,
    /// Why.
    pub fault: StatementFault,
}

/// One object's reading.
#[derive(Debug, Clone)]
pub struct BundleReading {
    /// The object id.
    pub object_id: Digest32,
    /// The verdict.
    pub verdict: GenesisVerdict,
    /// Its statements refused on their own.
    pub refused: Vec<RefusedStatement>,
}

/// Every object's reading, and the statements that name no object.
#[derive(Debug, Clone, Default)]
pub struct GenesisReading {
    /// One reading per object id, sorted by object id.
    pub bundles: Vec<BundleReading>,
    /// Statements refused before their object could be read.
    pub refused: Vec<RefusedStatement>,
}

// ------------------------------------------------------------------ entry points

/// Read every bundle the statements carry, each by CC 2.6.1.11's order.
#[must_use]
pub fn read_genesis_bundles(input: &GenesisInput<'_>) -> GenesisReading {
    let mut out = GenesisReading::default();
    let mut groups: BTreeMap<Digest32, (Vec<u8>, Vec<Voice>)> = BTreeMap::new();
    for (index, bytes) in input.statements.iter().enumerate() {
        match peek_voice(index, bytes) {
            Ok(v) => {
                groups
                    .entry(v.object_id)
                    .or_insert_with(|| (v.payload_bytes.clone(), Vec::new()))
                    .1
                    .push(v);
            },
            Err(fault) => out.refused.push(RefusedStatement { index, fault }),
        }
    }
    for (oid, (payload_bytes, voices)) in groups {
        let mut refused = Vec::new();
        let verdict = read_one(oid, &payload_bytes, voices, input, &mut refused);
        out.bundles.push(BundleReading {
            object_id: oid,
            verdict,
            refused,
        });
    }
    out
}

/// Read the one bundle named by `object_id`: statements over other payloads
/// are other objects, ignored here. `None` when no statement carries it.
#[must_use]
pub fn verify_genesis_bundle(
    object_id: &Digest32,
    input: &GenesisInput<'_>,
) -> Option<BundleReading> {
    read_genesis_bundles(input)
        .bundles
        .into_iter()
        .find(|b| b.object_id == *object_id)
}

/// A fork among Valid bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fork {
    /// Two or more Valid first bundles: a fork of the genesis.
    Genesis {
        /// Their object ids, sorted.
        bundles: Vec<Digest32>,
    },
    /// Two or more Valid bundles with one `prev`.
    Successors {
        /// The shared predecessor.
        prev: Digest32,
        /// Their object ids, sorted.
        bundles: Vec<Digest32>,
    },
}

/// Every fork among `valid` (CC 2.6.1.11: reported as a fork, never resolved
/// by a rank).
#[must_use]
pub fn find_forks(valid: &[&GenesisPlacement]) -> Vec<Fork> {
    let mut by_prev: BTreeMap<Option<Digest32>, BTreeSet<Digest32>> = BTreeMap::new();
    for p in valid {
        by_prev.entry(p.prev).or_default().insert(p.object_id);
    }
    by_prev
        .into_iter()
        .filter(|(_, s)| s.len() > 1)
        .map(|(prev, s)| {
            let bundles = s.into_iter().collect();
            match prev {
                None => Fork::Genesis { bundles },
                Some(prev) => Fork::Successors { prev, bundles },
            }
        })
        .collect()
}

/// Where following `prev` from the root ends.
#[derive(Debug, Clone)]
pub enum Head<'a> {
    /// The head of the one chain.
    Head(&'a GenesisPlacement),
    /// A fork: the reader holds the tips and roots on none.
    Fork(Vec<Fork>),
    /// No Valid first bundle.
    Nothing,
}

/// Follow `prev` from the Valid first bundle to the head. Any fork among
/// `valid` is reported as a fork.
#[must_use]
pub fn follow_to_head<'a>(valid: &[&'a GenesisPlacement]) -> Head<'a> {
    let forks = find_forks(valid);
    if !forks.is_empty() {
        return Head::Fork(forks);
    }
    let Some(mut cur) = valid.iter().copied().find(|p| p.prev.is_none()) else {
        return Head::Nothing;
    };
    while let Some(next) = valid
        .iter()
        .copied()
        .find(|p| p.prev == Some(cur.object_id))
    {
        cur = next;
    }
    Head::Head(cur)
}

// ------------------------------------------------------------------ statements

struct Voice {
    index: usize,
    bytes: Vec<u8>,
    object_id: Digest32,
    payload_bytes: Vec<u8>,
    iss: String,
    kid: Digest32,
    iat: u64,
}

/// A directory that holds no key: `verify_object_statement` under it is the
/// structure check alone (Invalid, or Waiting on the signer).
struct NoKeys;
impl KeyDirectory for NoKeys {
    fn lookup(&self, _: &Digest32, _: u64) -> KeyLookup {
        KeyLookup::NotHeld
    }
}

/// One key, under its kid.
struct OneKey<'a>(Digest32, &'a CompositePublicKey);
impl KeyDirectory for OneKey<'_> {
    fn lookup(&self, kid: &Digest32, _: u64) -> KeyLookup {
        if *kid == self.0 {
            KeyLookup::Held(Box::new(self.1.clone()))
        } else {
            KeyLookup::NotHeld
        }
    }
}

fn peek_voice(index: usize, bytes: &[u8]) -> Result<Voice, StatementFault> {
    match verify_object_statement(bytes, &NoKeys) {
        ObjectVerdict::Invalid(i) => return Err(StatementFault::Object(i)),
        ObjectVerdict::Valid(_) | ObjectVerdict::Waiting { .. } => {},
    }
    // The structure holds; read what the grouping and the count need.
    let bad = || StatementFault::Object(Invalid::NotCoseSign1);
    let Ok(Value::Tag(18, inner)) = cde::decode(bytes) else {
        return Err(bad());
    };
    let a = inner.as_array().ok_or_else(bad)?;
    let prot = cde::decode(a[0].as_bytes().ok_or_else(bad)?).map_err(|_| bad())?;
    let payload_bytes = a[2].as_bytes().ok_or_else(bad)?.to_vec();
    let typ = prot
        .get_int(H_TYP)
        .and_then(Value::as_text)
        .ok_or_else(bad)?;
    if typ != GENESIS_BUNDLE_TYP {
        return Err(StatementFault::NotGenesisBundle);
    }
    let kid: Digest32 = prot
        .get_int(H_KID)
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(bad)?;
    let cwt = prot.get_int(H_CWT).ok_or_else(bad)?;
    let iss = cwt
        .get_int(C_ISS)
        .and_then(Value::as_text)
        .ok_or_else(bad)?
        .to_owned();
    let iat = cwt
        .get_int(C_IAT)
        .and_then(Value::as_u64)
        .ok_or(StatementFault::IatMissing)?;
    let payload = cde::decode(&payload_bytes).map_err(|_| bad())?;
    let author = payload.get_text("author").and_then(Value::as_text);
    Ok(Voice {
        index,
        bytes: bytes.to_vec(),
        object_id: object_id(GENESIS_BUNDLE_TYP, author, &payload_bytes),
        payload_bytes,
        iss,
        kid,
        iat,
    })
}

// ------------------------------------------------------------------ the payload

struct Bundle {
    prev: Option<Digest32>,
    cites: Vec<Digest32>,
    version: u32,
    asserted_at: u64,
    family_key_id: String,
    holders: Vec<String>,
    serve_nodes: Vec<String>,
    charter: GenesisCharter,
}

fn schema(member: &'static str) -> Malformed {
    Malformed::Schema { member }
}

/// Admit exactly the text keys `required` ∪ `optional`, with `required` present.
fn closed_map(
    v: &Value,
    required: &[&str],
    optional: &[&str],
    within: &'static str,
) -> Result<(), Malformed> {
    let m = v.as_map().ok_or(schema(within))?;
    for (k, _) in m {
        match k.as_text() {
            Some(t) if required.contains(&t) || optional.contains(&t) => {},
            _ => return Err(schema(within)),
        }
    }
    if required.iter().any(|r| v.get_text(r).is_none()) {
        return Err(schema(within));
    }
    Ok(())
}

fn digest_of(v: &Value, member: &'static str) -> Result<Digest32, Malformed> {
    match v.as_array() {
        Some([alg, d]) if alg.as_i64() == Some(-16) => d
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .ok_or(schema(member)),
        _ => Err(schema(member)),
    }
}

/// An edition-2 `row-ref`: `[2, [-16, bstr .size 32]]`.
fn row_ref_of(v: &Value, member: &'static str) -> Result<Digest32, Malformed> {
    match v.as_array() {
        Some([ed, id]) if ed.as_u64() == Some(2) => digest_of(id, member),
        _ => Err(schema(member)),
    }
}

fn check_set_order(a: &[Value], member: &'static str) -> Result<(), Malformed> {
    let enc: Vec<Vec<u8>> = a.iter().map(cde::encode).collect();
    if enc.windows(2).all(|w| w[0] < w[1]) {
        Ok(())
    } else {
        Err(Malformed::SetOrder { member })
    }
}

fn identity_ref_set(v: &Value, member: &'static str) -> Result<Vec<String>, Malformed> {
    let a = v
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or(schema(member))?;
    let out = a
        .iter()
        .map(|x| {
            x.as_text()
                .filter(|s| is_identity_ref(s))
                .map(str::to_owned)
                .ok_or(schema(member))
        })
        .collect::<Result<Vec<_>, _>>()?;
    check_set_order(a, member)?;
    Ok(out)
}

fn u32_in(v: Option<&Value>, lo: u32, member: &'static str) -> Result<Option<u32>, Malformed> {
    match v {
        None => Ok(None),
        Some(x) => x
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n >= lo)
            .map(Some)
            .ok_or(schema(member)),
    }
}

/// The payload rule: the CDDL, then the prose checks, in the reference
/// reader's order.
fn parse_payload(p: &Value) -> Result<Bundle, Malformed> {
    closed_map(
        p,
        &[
            "refs",
            "version",
            "asserted_at",
            "family_key_id",
            "holders",
            "serve_nodes",
            "charter",
        ],
        &[],
        "ceg-genesis-bundle",
    )?;
    let refs = p.get_text("refs").expect("required");
    closed_map(refs, &["also"], &["prev"], "genesis-refs")?;
    let prev = refs
        .get_text("prev")
        .map(|v| row_ref_of(v, "prev"))
        .transpose()?;
    let also = refs.get_text("also").expect("required");
    closed_map(also, &["cites"], &[], "also")?;
    let cites_v = also
        .get_text("cites")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(schema("cites"))?;
    let cites = cites_v
        .iter()
        .map(|r| row_ref_of(r, "cites"))
        .collect::<Result<Vec<_>, _>>()?;
    check_set_order(cites_v, "cites")?;

    let version = u32_in(p.get_text("version"), 1, "version")?.expect("required");
    let asserted_at = p
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .ok_or(schema("asserted_at"))?;
    let family_key_id = p
        .get_text("family_key_id")
        .and_then(Value::as_text)
        .ok_or(schema("family_key_id"))?
        .to_owned();
    let holders = identity_ref_set(p.get_text("holders").expect("required"), "holders")?;
    let serve_nodes =
        identity_ref_set(p.get_text("serve_nodes").expect("required"), "serve_nodes")?;

    let ch = p.get_text("charter").expect("required");
    closed_map(
        ch,
        &["recovery_commitments", "scope"],
        &[
            "halt_fuse_secs",
            "attach_window_secs",
            "witness_cadence_secs",
            "witness_quorum",
            "witnesses",
        ],
        "genesis-charter",
    )?;
    let rc = ch
        .get_text("recovery_commitments")
        .and_then(Value::as_map)
        .filter(|m| !m.is_empty())
        .ok_or(schema("recovery_commitments"))?;
    let mut recovery_commitments = BTreeMap::new();
    for (k, v) in rc {
        let k = k
            .as_text()
            .filter(|s| is_identity_ref(s))
            .ok_or(schema("recovery_commitments"))?;
        recovery_commitments.insert(k.to_owned(), digest_of(v, "recovery_commitments")?);
    }
    let scope_v = ch
        .get_text("scope")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(schema("scope"))?;
    let scope = scope_v
        .iter()
        .map(|s| s.as_text().map(str::to_owned).ok_or(schema("scope")))
        .collect::<Result<Vec<_>, _>>()?;
    check_set_order(scope_v, "scope")?;
    let halt_fuse_secs = u32_in(ch.get_text("halt_fuse_secs"), 1, "halt_fuse_secs")?;
    let attach_window_secs = u32_in(ch.get_text("attach_window_secs"), 1, "attach_window_secs")?;
    let witness_cadence_secs = u32_in(
        ch.get_text("witness_cadence_secs"),
        1,
        "witness_cadence_secs",
    )?;
    let witness_quorum = u32_in(ch.get_text("witness_quorum"), 2, "witness_quorum")?;
    let witnesses = ch
        .get_text("witnesses")
        .map(|w| identity_ref_set(w, "witnesses"))
        .transpose()?;

    // The prose checks.
    if prev.is_some() == (version == 1) {
        return Err(Malformed::VersionPrevMismatch);
    }
    let (h, s): (BTreeSet<&String>, BTreeSet<&String>) =
        (holders.iter().collect(), serve_nodes.iter().collect());
    let w: BTreeSet<&String> = witnesses.iter().flatten().collect();
    if !h.is_disjoint(&s) || !h.is_disjoint(&w) || !s.is_disjoint(&w) {
        return Err(Malformed::HoldersSeatsOverlap);
    }
    if recovery_commitments.keys().collect::<BTreeSet<_>>() != h {
        return Err(Malformed::RecoveryCommitmentsNotHolders);
    }
    if !REQUIRED_SCOPE.iter().all(|r| scope.iter().any(|s| s == r)) {
        return Err(Malformed::ScopeMissingInfra);
    }
    match (&witnesses, witness_quorum, witness_cadence_secs) {
        (None, None, None) => {},
        (Some(ws), Some(q), Some(_)) => {
            let want = u32::try_from(ws.len() / 2 + 1).map_err(|_| schema("witnesses"))?;
            if q != want {
                return Err(Malformed::WitnessQuorumMismatch);
            }
        },
        _ => return Err(Malformed::WitnessMembersPartial),
    }
    Ok(Bundle {
        prev,
        cites,
        version,
        asserted_at,
        family_key_id,
        holders,
        serve_nodes,
        charter: GenesisCharter {
            recovery_commitments,
            scope,
            halt_fuse_secs,
            attach_window_secs,
            witness_cadence_secs,
            witness_quorum,
            witnesses: witnesses.unwrap_or_default(),
        },
    })
}

/// The thumbprint an identity reference names.
#[must_use]
pub fn identity_ref_thumbprint(s: &str) -> Option<Digest32> {
    use base64::Engine as _;
    let t = s.strip_prefix(super::IDENTITY_REF_PREFIX)?;
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(t)
        .ok()?;
    let d: Digest32 = b.try_into().ok()?;
    (identity_ref(&d) == s).then_some(d)
}

// ------------------------------------------------------------------ one bundle

fn read_one(
    oid: Digest32,
    payload_bytes: &[u8],
    voices: Vec<Voice>,
    input: &GenesisInput<'_>,
    refused: &mut Vec<RefusedStatement>,
) -> GenesisVerdict {
    // 2. The payload (verify_object_statement already refused a payload that
    //    is not its own deterministic encoding).
    let Ok(payload) = cde::decode(payload_bytes) else {
        return GenesisVerdict::Invalid(schema("payload"));
    };
    let b = match parse_payload(&payload) {
        Ok(b) => b,
        Err(m) => return GenesisVerdict::Invalid(m),
    };
    let want_iat = b.asserted_at / 1000;
    let voices: Vec<Voice> = voices
        .into_iter()
        .filter_map(|v| {
            if v.iat == want_iat {
                Some(v)
            } else {
                refused.push(RefusedStatement {
                    index: v.index,
                    fault: StatementFault::IatMismatch,
                });
                None
            }
        })
        .collect();

    // 3. The anchor (a first bundle), 4. the predecessor (a later one).
    let mut waiting = GenesisWaiting::default();
    let prev = match b.prev {
        None => {
            let anchored = match input.anchor {
                None => false,
                Some(Anchor::ObjectId(a)) => *a == oid,
                Some(Anchor::Thumbprints(set)) => {
                    let tps: Option<BTreeSet<Digest32>> = b
                        .holders
                        .iter()
                        .map(|h| identity_ref_thumbprint(h))
                        .collect();
                    tps.as_ref() == Some(set)
                },
            };
            if !anchored {
                return GenesisVerdict::Nothing(Inconclusive::NotAnchored);
            }
            None
        },
        Some(p) => match input.predecessors.iter().find(|x| x.object_id() == p) {
            None => {
                waiting.prev = Some(p);
                None
            },
            Some(Predecessor::NotValid(_)) => {
                return GenesisVerdict::Nothing(Inconclusive::PrevNotValid)
            },
            Some(Predecessor::Valid(pp)) => {
                if b.version != pp.version.saturating_add(1) {
                    return GenesisVerdict::Invalid(Malformed::VersionPrevMismatch);
                }
                if b.family_key_id != pp.family_key_id {
                    return GenesisVerdict::Invalid(Malformed::FamilyKeyIdChanged);
                }
                Some(*pp)
            },
        },
    };

    // 5. The named rows: Waiting on any not held.
    let mut held: Vec<(Digest32, &[u8], RowPeek)> = Vec::new();
    for id in &b.cites {
        match input.rows.get(id) {
            None => waiting.rows.push(*id),
            Some(bytes) => match peek_row(bytes) {
                // Filed under another id: the named row is not held.
                Some(pk) if pk.row_id != *id => waiting.rows.push(*id),
                Some(pk) => held.push((*id, bytes, pk)),
                None => {
                    let fault = match verify_row_statement(bytes, &NoKeys) {
                        Verdict::Invalid(i) => RowFault::Row(i),
                        _ => RowFault::Row(Invalid::NotCoseSign1),
                    };
                    return GenesisVerdict::Nothing(Inconclusive::RowInvalid { row: *id, fault });
                },
            },
        }
    }
    if !waiting.rows.is_empty() || waiting.prev.is_some() {
        waiting.rows.sort_unstable();
        return GenesisVerdict::Waiting(waiting);
    }
    let first = b.prev.is_none();
    let rows = match place_rows(&b, first, &held, input.attestation_roots) {
        Ok(r) => r,
        Err(i) => return GenesisVerdict::Nothing(i),
    };

    // 6. The voices.
    let added: BTreeSet<&String> = match prev {
        None => BTreeSet::new(),
        Some(pp) => b
            .holders
            .iter()
            .filter(|h| pp.holder(h).is_none())
            .collect(),
    };
    let roster: BTreeSet<&str> = match prev {
        None => b.holders.iter().map(String::as_str).collect(),
        Some(pp) => pp.holders.iter().map(|h| h.identity_ref.as_str()).collect(),
    };
    let mut counted: BTreeSet<String> = BTreeSet::new();
    let mut kids: BTreeSet<Digest32> = BTreeSet::new();
    for v in &voices {
        if !roster.contains(v.iss.as_str()) && !added.contains(&v.iss) {
            refused.push(RefusedStatement {
                index: v.index,
                fault: StatementFault::NoRole,
            });
            continue;
        }
        let key = voice_key(v, &rows, prev, first, input.rows, b.asserted_at);
        let key = match key {
            VoiceKey::Key(k) => k,
            VoiceKey::Refused(fault) => {
                refused.push(RefusedStatement {
                    index: v.index,
                    fault,
                });
                continue;
            },
            VoiceKey::Waiting => {
                kids.insert(v.kid);
                continue;
            },
        };
        match verify_object_statement(&v.bytes, &OneKey(v.kid, &key)) {
            ObjectVerdict::Valid(_) => {
                counted.insert(v.iss.clone());
            },
            ObjectVerdict::Invalid(i) => refused.push(RefusedStatement {
                index: v.index,
                fault: StatementFault::Object(i),
            }),
            ObjectVerdict::Waiting { .. } => {
                kids.insert(v.kid);
            },
        }
    }

    // 7. The count.
    let met = match prev {
        None => b.holders.iter().all(|h| counted.contains(h)),
        Some(pp) => {
            let n = pp.holders.len();
            let valid = pp
                .holders
                .iter()
                .filter(|h| counted.contains(&h.identity_ref))
                .count();
            let changed = b.holders.iter().filter(|h| {
                pp.holder(h).is_some_and(|ph| {
                    b.charter.recovery_commitments.get(*h) != Some(&ph.recovery_commitment)
                })
            });
            2 * valid > n
                && added.iter().all(|h| counted.contains(*h))
                && changed.into_iter().all(|h| counted.contains(h))
        },
    };
    if !met {
        if kids.is_empty() {
            return GenesisVerdict::Nothing(Inconclusive::CountUnmet);
        }
        return GenesisVerdict::Waiting(GenesisWaiting {
            kids: kids.into_iter().collect(),
            ..GenesisWaiting::default()
        });
    }

    let charter = b.charter.clone();
    GenesisVerdict::Valid(Box::new(GenesisPlacement {
        object_id: oid,
        version: b.version,
        prev: b.prev,
        asserted_at: b.asserted_at,
        family_key_id: b.family_key_id.clone(),
        holders: b
            .holders
            .iter()
            .map(|h| {
                let r = &rows.records[h];
                PlacedHolder {
                    identity_ref: h.clone(),
                    kid: r.rec.kid,
                    key: r.rec.key.clone(),
                    recovery_commitment: charter.recovery_commitments[h],
                    hardware_class: r.rec.hardware_class.clone().unwrap_or_default(),
                    pq_custody: PqCustody::RemovableOffline,
                    record: r.id,
                }
            })
            .collect(),
        seats: b
            .serve_nodes
            .iter()
            .map(|s| {
                let r = &rows.records[s];
                let x = &rows.bindings[s];
                PlacedSeat {
                    identity_ref: s.clone(),
                    kid: r.rec.kid,
                    key: r.rec.key.clone(),
                    valid_until: r.rec.valid_until.unwrap_or_default(),
                    transit_xwing_pubkey: x.transit,
                    onion_hop_xwing_pubkey: x.onion,
                    record: r.id,
                    binding: x.id,
                }
            })
            .collect(),
        witnesses: charter
            .witnesses
            .iter()
            .map(|w| {
                let r = &rows.records[w];
                PlacedWitness {
                    identity_ref: w.clone(),
                    kid: r.rec.kid,
                    key: r.rec.key.clone(),
                    record: r.id,
                }
            })
            .collect(),
        charter,
        counted: counted.into_iter().collect(),
    }))
}

// ------------------------------------------------------------------ rows

struct RowPeek {
    row_id: Digest32,
    family: String,
    author: Option<String>,
    /// The composite key a key record records.
    key: Option<CompositePublicKey>,
}

/// Read a row statement's family, author and (for a key record) key, and its
/// row id, without verifying it.
fn peek_row(bytes: &[u8]) -> Option<RowPeek> {
    let Value::Tag(18, inner) = cde::decode(bytes).ok()? else {
        return None;
    };
    let a = inner.as_array()?;
    let pb = a.first()?.as_bytes()?;
    let plb = a.get(2)?.as_bytes()?;
    let prot = cde::decode(pb).ok()?;
    let family = prot.get_int(H_FAMILY)?.as_text()?.to_owned();
    let row_type = prot.get_int(H_ROW_TYPE)?.as_text()?;
    let sub = prot.get_int(H_CWT)?.get_int(C_SUB)?.as_text()?;
    let payload = cde::decode(plb).ok()?;
    let author = payload
        .get_text("author")
        .and_then(Value::as_text)
        .map(str::to_owned);
    let key = payload
        .get_text("key")
        .and_then(|k| k.get_int(-1))
        .and_then(Value::as_bytes)
        .and_then(|b| CompositePublicKey::from_bytes(b).ok());
    Some(RowPeek {
        row_id: row_id(row_type, &family, sub, author.as_deref(), plb),
        family,
        author,
        key,
    })
}

struct PlacedRecord {
    id: Digest32,
    rec: KeyRecord,
}

struct PlacedBinding {
    id: Digest32,
    transit: [u8; XWING_PUBKEY_LEN],
    onion: [u8; XWING_PUBKEY_LEN],
}

struct Rows {
    records: BTreeMap<String, PlacedRecord>,
    bindings: BTreeMap<String, PlacedBinding>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Holder,
    Seat,
    Witness,
}

fn unplaced(row: Option<Digest32>, party: Option<&str>) -> Inconclusive {
    Inconclusive::RowUnplaced {
        row,
        party: party.map(str::to_owned),
    }
}

fn row_invalid(row: Digest32, fault: RowFault) -> Inconclusive {
    Inconclusive::RowInvalid { row, fault }
}

/// Verify a held row under one key: Valid with its iss and author agreeing,
/// or the fault.
fn verify_under(
    id: Digest32,
    bytes: &[u8],
    kid: Digest32,
    key: &CompositePublicKey,
) -> Result<VerifiedRow, Inconclusive> {
    match verify_row_statement(bytes, &OneKey(kid, key)) {
        Verdict::Valid(r) => {
            if r.author.as_deref() != Some(r.iss.as_str()) {
                return Err(row_invalid(id, RowFault::AuthorNotIss));
            }
            Ok(*r)
        },
        Verdict::Invalid(i) => Err(row_invalid(id, RowFault::Row(i))),
        Verdict::Waiting { .. } => Err(row_invalid(id, RowFault::Signer)),
    }
}

fn place_rows(
    b: &Bundle,
    first: bool,
    held: &[(Digest32, &[u8], RowPeek)],
    roots: &TrustAnchorStore,
) -> Result<Rows, Inconclusive> {
    let place_of = |p: &str| {
        if b.holders.iter().any(|h| h == p) {
            Some(Place::Holder)
        } else if b.serve_nodes.iter().any(|s| s == p) {
            Some(Place::Seat)
        } else if b.charter.witnesses.iter().any(|w| w == p) {
            Some(Place::Witness)
        } else {
            None
        }
    };

    // Slot each row by family and author alone.
    let mut record_slots: BTreeMap<&str, (Digest32, &[u8], &RowPeek)> = BTreeMap::new();
    let mut binding_slots: BTreeMap<&str, (Digest32, &[u8])> = BTreeMap::new();
    for (id, bytes, pk) in held {
        let author = pk.author.as_deref();
        let slot = author.and_then(|a| place_of(a).map(|p| (a, p)));
        match (pk.family.as_str(), slot) {
            (KEY_RECORD_FAMILY, Some((a, _))) => {
                if record_slots.insert(a, (*id, bytes, pk)).is_some() {
                    return Err(unplaced(Some(*id), None));
                }
            },
            (BINDING_FAMILY, Some((a, Place::Seat))) => {
                if binding_slots.insert(a, (*id, bytes)).is_some() {
                    return Err(unplaced(Some(*id), None));
                }
            },
            _ => return Err(unplaced(Some(*id), None)),
        }
    }
    let parties = b
        .holders
        .iter()
        .chain(&b.serve_nodes)
        .chain(&b.charter.witnesses);
    for p in parties {
        if !record_slots.contains_key(p.as_str()) {
            return Err(unplaced(None, Some(p)));
        }
    }
    for s in &b.serve_nodes {
        if !binding_slots.contains_key(s.as_str()) {
            return Err(unplaced(None, Some(s)));
        }
    }

    // Each record, verified under the key it records, then its place's rule.
    let mut records = BTreeMap::new();
    for (party, (id, bytes, pk)) in &record_slots {
        let Some(key) = &pk.key else {
            let fault = match verify_row_statement(bytes, &NoKeys) {
                Verdict::Invalid(i) => RowFault::Row(i),
                _ => RowFault::Record(KeyRecordError::BadKey),
            };
            return Err(row_invalid(*id, fault));
        };
        let row = verify_under(*id, bytes, thumbprint(key), key)?;
        let rec =
            check_key_record(&row.payload).map_err(|e| row_invalid(*id, RowFault::Record(e)))?;
        match place_of(party).expect("slotted") {
            Place::Holder => {
                if !rec.identity_type.iter().any(|r| r == "accord_holder") {
                    return Err(row_invalid(*id, RowFault::HolderNotAccordHolder));
                }
                if first && identity_ref_thumbprint(party) != Some(rec.kid) {
                    return Err(row_invalid(*id, RowFault::HolderNotGenesisKey));
                }
            },
            Place::Seat => {
                if rec.identity_type != ["node"] {
                    return Err(row_invalid(*id, RowFault::SeatNotNode));
                }
            },
            Place::Witness => {},
        }
        records.insert((*party).to_owned(), PlacedRecord { id: *id, rec });
    }

    // Each seat's binding, under the seat's recorded key.
    let mut bindings = BTreeMap::new();
    for (seat, (id, bytes)) in &binding_slots {
        let r = &records[*seat];
        let row = verify_under(*id, bytes, r.rec.kid, &r.rec.key)?;
        let (transit, onion) =
            seat_xwing(&row.payload, &r.rec.key).map_err(|f| row_invalid(*id, f))?;
        bindings.insert(
            (*seat).to_owned(),
            PlacedBinding {
                id: *id,
                transit,
                onion,
            },
        );
    }

    // The custody gate at each holder seat.
    for h in &b.holders {
        custody_gate(&records[h].rec, roots).map_err(|fault| Inconclusive::HolderCustody {
            holder: h.clone(),
            fault,
        })?;
    }
    Ok(Rows { records, bindings })
}

fn collect_bytes<'a>(v: &'a Value, skip: &[&str], out: &mut Vec<&'a [u8]>) {
    match v {
        Value::Bytes(b) => out.push(b),
        Value::Array(a) => a.iter().for_each(|x| collect_bytes(x, &[], out)),
        Value::Map(m) => {
            for (k, x) in m {
                if k.as_text().is_some_and(|t| skip.contains(&t)) {
                    continue;
                }
                collect_bytes(x, &[], out);
            }
        },
        Value::Tag(_, x) => collect_bytes(x, &[], out),
        _ => {},
    }
}

/// A seat binding's X-Wing keys (CC 3.3.6.2): the two 1216-byte members of
/// the signed payload, beside its `transport_destination`, passing the in-row
/// separation against each other, every other key on the row and the
/// signer's Ed25519 half.
fn seat_xwing(
    p: &Value,
    signer: &CompositePublicKey,
) -> Result<([u8; XWING_PUBKEY_LEN], [u8; XWING_PUBKEY_LEN]), RowFault> {
    if !p
        .get_text("transport_destination")
        .is_some_and(|t| t.as_map().is_some())
    {
        return Err(RowFault::NoTransportDestination);
    }
    if p.get_text("transit_kex_pubkeys").is_some() {
        return Err(RowFault::EarlierTransitPair);
    }
    if p.get_text("onion_relay")
        .and_then(|o| o.get_text("opt_out"))
        .is_some_and(|x| *x == Value::Bool(true))
    {
        return Err(RowFault::SeatOptedOut);
    }
    let member = |m: &'static str| -> Result<[u8; XWING_PUBKEY_LEN], RowFault> {
        p.get_text(m)
            .and_then(Value::as_bytes)
            .and_then(|b| b.try_into().ok())
            .ok_or(RowFault::XWingMember { member: m })
    };
    let transit = member("transit_xwing_pubkey")?;
    let onion = member("onion_hop_xwing_pubkey")?;
    let (tm, tx) = transit.split_at(XWING_PK_M_LEN);
    let (om, ox) = onion.split_at(XWING_PK_M_LEN);
    if om == tm {
        return Err(RowFault::XWingReuse {
            token: "onion_hop_ml_kem_768_reuse",
        });
    }
    if ox == tx {
        return Err(RowFault::XWingReuse {
            token: "onion_hop_x25519_reuse",
        });
    }
    let mut others: Vec<&[u8]> = Vec::new();
    collect_bytes(
        p,
        &["transit_xwing_pubkey", "onion_hop_xwing_pubkey"],
        &mut others,
    );
    let ed = &signer.as_bytes()[MLDSA65_PK_LEN..];
    others.push(ed);
    for o in others {
        if o == om {
            return Err(RowFault::XWingReuse {
                token: "onion_hop_ml_kem_768_reuse",
            });
        }
        if o == ox {
            return Err(RowFault::XWingReuse {
                token: "onion_hop_x25519_reuse",
            });
        }
        if o == tm {
            return Err(RowFault::XWingReuse {
                token: "transit_ml_kem_768_reuse",
            });
        }
        if o == tx {
            return Err(RowFault::XWingReuse {
                token: "transit_x25519_reuse",
            });
        }
    }
    Ok((transit, onion))
}

/// The gate at seating (CC 4.2.2.1): the chain verifies to the mechanism's
/// attestation root, the attested key is the record's Ed25519 half, and only
/// then are the class and `pq_custody` accepted; a seated holder carries
/// `removable_offline`.
fn custody_gate(rec: &KeyRecord, roots: &TrustAnchorStore) -> Result<(), CustodyFault> {
    let class = rec.hardware_class.as_deref().ok_or(CustodyFault::NoClass)?;
    if class != CLASS_YUBIKEY_5_FIPS || rec.chain.is_empty() {
        // Apple_Secure_Enclave and TPM_2_0 have chains this reader does not
        // verify yet: unattested, not seated.
        return Err(CustodyFault::Unattested);
    }
    let ed = &rec.key.as_bytes()[MLDSA65_PK_LEN..];
    let (leaf, above) = rec.chain.split_first().expect("non-empty");
    let above: Vec<&[u8]> = above.iter().map(Vec::as_slice).collect();
    let mut fault = CustodyFault::ChainInvalid;
    for root in roots.resolve_x509(Purpose::KeyAttestation, environments::YUBIKEY_PIV) {
        match verify_yubikey_piv_attestation(leaf, &above, root, ed) {
            Ok(v) if v.hardware_class == class => {
                return match rec.pq_custody {
                    Some(PqCustody::RemovableOffline) => Ok(()),
                    _ => Err(CustodyFault::PqCustody),
                };
            },
            Ok(_) => fault = CustodyFault::Unattested,
            Err(CustodyError::AttestedKeyMismatch) => fault = CustodyFault::AttestedKeyMismatch,
            Err(CustodyError::FloorNotMet { .. }) => fault = CustodyFault::FloorNotMet,
            Err(_) => {},
        }
    }
    Err(fault)
}

// ------------------------------------------------------------------ voices

enum VoiceKey {
    Key(Box<CompositePublicKey>),
    Refused(StatementFault),
    Waiting,
}

/// The key a voice's `kid` resolves to for its `iss`: the named record; in a
/// later bundle also the predecessor's record of a removed holder, or a held
/// `key:record` of the same `iss` (the key plane). Otherwise Waiting on the
/// kid; in a first bundle, Invalid.
fn voice_key(
    v: &Voice,
    rows: &Rows,
    prev: Option<&GenesisPlacement>,
    first: bool,
    held: &BTreeMap<Digest32, Vec<u8>>,
    at: u64,
) -> VoiceKey {
    if let Some(r) = rows.records.get(&v.iss) {
        if r.rec.kid == v.kid {
            return VoiceKey::Key(Box::new(r.rec.key.clone()));
        }
    }
    if first {
        return VoiceKey::Refused(StatementFault::KidNotIss);
    }
    if let Some(h) = prev.and_then(|p| p.holder(&v.iss)) {
        if h.kid == v.kid {
            return VoiceKey::Key(Box::new(h.key.clone()));
        }
    }
    for (id, bytes) in held {
        let Some(pk) = peek_row(bytes) else { continue };
        if pk.row_id != *id
            || pk.family != KEY_RECORD_FAMILY
            || pk.author.as_deref() != Some(v.iss.as_str())
        {
            continue;
        }
        let Some(key) = pk.key else { continue };
        if thumbprint(&key) != v.kid {
            continue;
        }
        let Ok(row) = verify_under(*id, bytes, v.kid, &key) else {
            continue;
        };
        if let Ok(rec) = check_key_record(&row.payload) {
            if rec.valid_until.is_none_or(|u| at <= u) {
                return VoiceKey::Key(Box::new(rec.key));
            }
        }
    }
    VoiceKey::Waiting
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_ref_round_trips() {
        let d = [7u8; 32];
        assert_eq!(identity_ref_thumbprint(&identity_ref(&d)), Some(d));
        assert_eq!(identity_ref_thumbprint("urn:x"), None);
    }

    #[test]
    fn forks_are_reported() {
        let p = |oid: u8, prev: Option<u8>| GenesisPlacement {
            object_id: [oid; 32],
            version: 1,
            prev: prev.map(|x| [x; 32]),
            asserted_at: 0,
            family_key_id: String::new(),
            holders: vec![],
            seats: vec![],
            witnesses: vec![],
            charter: GenesisCharter {
                recovery_commitments: BTreeMap::new(),
                scope: vec![],
                halt_fuse_secs: None,
                attach_window_secs: None,
                witness_cadence_secs: None,
                witness_quorum: None,
                witnesses: vec![],
            },
            counted: vec![],
        };
        let (a, b, c, d) = (p(1, None), p(2, Some(1)), p(3, Some(2)), p(4, Some(2)));
        assert!(matches!(follow_to_head(&[&a, &b]), Head::Head(h) if h.object_id == [2; 32]));
        assert_eq!(
            find_forks(&[&a, &b, &c, &d]),
            vec![Fork::Successors {
                prev: [2; 32],
                bundles: vec![[3; 32], [4; 32]]
            }]
        );
        let e = p(5, None);
        assert_eq!(
            find_forks(&[&a, &e]),
            vec![Fork::Genesis {
                bundles: vec![[1; 32], [5; 32]]
            }]
        );
        assert!(matches!(follow_to_head(&[]), Head::Nothing));
    }
}
