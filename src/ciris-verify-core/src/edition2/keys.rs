//! Edition-2 key records (CC 2.4.1.1, 2.6.1.7) and a key directory built on them.
//!
//! A key record is a row on family `key:record` whose payload carries
//! `key` (one AKP COSE_Key of the composite), `identity_type` (a set of
//! roles), `asserted_at` and, by the end rule, `valid_until`:
//!
//! - a set mixing `user` or `accord_holder` with `node` or `agent` is refused;
//! - a set containing `user` or `accord_holder` carries no `valid_until`;
//! - a set containing `node` or `agent` carries one (the private-room key
//!   exception is not pinned yet, so it fails closed);
//! - a role outside both groups (steward, witness, pipeline, pseudonym) takes
//!   no end rule of its own;
//! - where `valid_until` is present,
//!   `asserted_at < valid_until <= asserted_at + KEY_RECORD_MAX_SECS * 1000`
//!   (a record covers `[asserted_at, valid_until)`, so an end at its own
//!   instant would cover nothing).
//!
//! [`KeyRecordDirectory`] answers [`KeyLookup`]s from held key-record
//! statements: a record whose own signer is not held makes the key Waiting on
//! that deeper key, an Invalid record makes it Invalid, and a held record that
//! ends before the statement's instant makes it Waiting on a record of that
//! key covering the instant ([`MissingKey::CoveringRecord`]; CC 2.4.1.1: such
//! a row is retryable).

use super::{
    cde, identity_ref_thumbprint, row_id, thumbprint, verify_row_statement, Digest32, KeyDirectory,
    KeyLookup, KeyOf, MissingKey, Value, Verdict, VerifiedRow,
};
use crate::prelude::*;
use ciris_crypto::composite::{CompositePublicKey, COSE_ALG};
use subtle::ConstantTimeEq;

/// The key-record window of this edition, seconds (CC constants
/// `key_record_max_secs`). Conformance fixes it; no caller widens it.
pub const KEY_RECORD_MAX_SECS: u64 = 31_536_000;
/// The family of a key record.
pub const KEY_RECORD_FAMILY: &str = "key:record";
/// How deep a chain of key records is followed before the key is refused.
pub const MAX_RECORD_DEPTH: usize = 8;

const NO_END: [&str; 2] = ["user", "accord_holder"];
const MUST_END: [&str; 2] = ["node", "agent"];

/// Why a key record's payload is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRecordError {
    /// `key` is not `{1: 7, 3: -70100, -1: bstr .size 1984}` or does not decode.
    BadKey,
    /// `identity_type` is not a non-empty sorted set of text.
    BadIdentityType,
    /// The set mixes `user` / `accord_holder` with `node` / `agent`.
    MixedRoles,
    /// `key_record_out_of_window`: `valid_until` where none may stand, absent
    /// where one must, or outside `[asserted_at, asserted_at + max]`.
    OutOfWindow,
    /// `asserted_at` is missing or not an ms-time.
    BadTime,
    /// `attestation_evidence` is not a map, or its `pq_custody` is not one
    /// of the three values (CC 4.2.2).
    BadPqCustody,
    /// `attestation_evidence.hardware_class` is not text, or its `chain` is
    /// not a non-empty sequence of byte strings (CC 4.2.2.1).
    BadAttestationEvidence,
}

/// Where a composite key's ML-DSA-65 half is held, when the record's
/// `hardware_class` describes only the Ed25519 half (CC 4.2.2, rc20). The
/// weighting (`software_wrapped` caps the class multiplier at 0.8; missing
/// reads at 0.0) is the consumer's; the reader only carries the value and
/// refuses one outside the three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqCustody {
    /// In the same secure element as the Ed25519 half.
    SameElement,
    /// On a separate removable, offline element (an accord holder's USB key).
    RemovableOffline,
    /// Wrapped under a software-held key.
    SoftwareWrapped,
}

impl PqCustody {
    /// The wire value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameElement => "same_element",
            Self::RemovableOffline => "removable_offline",
            Self::SoftwareWrapped => "software_wrapped",
        }
    }
}

impl KeyRecordError {
    /// The refusal token, where CC names one.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::OutOfWindow => "key_record_out_of_window",
            Self::MixedRoles => "key_record_mixed_roles",
            Self::BadKey => "key_record_bad_key",
            Self::BadIdentityType => "key_record_bad_identity_type",
            Self::BadTime => "key_record_bad_time",
            Self::BadPqCustody => "key_record_bad_pq_custody",
            Self::BadAttestationEvidence => "key_record_bad_attestation_evidence",
        }
    }
}

/// A key record's payload, checked.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// The key.
    pub key: CompositePublicKey,
    /// Its thumbprint, the kid statements name it by.
    pub kid: Digest32,
    /// The roles.
    pub identity_type: Vec<String>,
    /// When the record was asserted, ms.
    pub asserted_at: u64,
    /// When the key stops, ms.
    pub valid_until: Option<u64>,
    /// `attestation_evidence.pq_custody`, where the record carries one.
    pub pq_custody: Option<PqCustody>,
    /// `attestation_evidence.hardware_class`, where the record carries one:
    /// the holder's claim, admitted only through the gate at seating.
    pub hardware_class: Option<String>,
    /// `attestation_evidence.chain`: X.509 DER, leaf first (CC 4.2.2.1);
    /// empty where the record carries none.
    pub chain: Vec<Vec<u8>>,
}

/// Check a key record's payload against the end rule.
///
/// # Errors
/// The first [`KeyRecordError`].
pub fn check_key_record(payload: &Value) -> Result<KeyRecord, KeyRecordError> {
    let k = payload.get_text("key").ok_or(KeyRecordError::BadKey)?;
    let km = k.as_map().ok_or(KeyRecordError::BadKey)?;
    if km.len() != 3
        || k.get_int(1).and_then(Value::as_u64) != Some(7)
        || k.get_int(3).and_then(Value::as_i64) != Some(COSE_ALG)
    {
        return Err(KeyRecordError::BadKey);
    }
    let pub_bytes = k
        .get_int(-1)
        .and_then(Value::as_bytes)
        .ok_or(KeyRecordError::BadKey)?;
    let key = CompositePublicKey::from_bytes(pub_bytes).map_err(|_| KeyRecordError::BadKey)?;

    let roles = payload
        .get_text("identity_type")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(KeyRecordError::BadIdentityType)?;
    let enc: Vec<Vec<u8>> = roles.iter().map(cde::encode).collect();
    if !enc.windows(2).all(|w| w[0] < w[1]) {
        return Err(KeyRecordError::BadIdentityType);
    }
    let identity_type = roles
        .iter()
        .map(|r| {
            r.as_text()
                .map(str::to_owned)
                .ok_or(KeyRecordError::BadIdentityType)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let asserted_at = payload
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .ok_or(KeyRecordError::BadTime)?;
    let valid_until = match payload.get_text("valid_until") {
        None => None,
        Some(v) => Some(v.as_u64().ok_or(KeyRecordError::BadTime)?),
    };

    let has = |g: &[&str]| identity_type.iter().any(|r| g.contains(&r.as_str()));
    let (no_end, must_end) = (has(&NO_END), has(&MUST_END));
    if no_end && must_end {
        return Err(KeyRecordError::MixedRoles);
    }
    match (no_end, must_end, valid_until) {
        (true, _, Some(_)) | (_, true, None) => return Err(KeyRecordError::OutOfWindow),
        _ => {},
    }
    if let Some(u) = valid_until {
        let max = asserted_at.saturating_add(KEY_RECORD_MAX_SECS * 1000);
        if u <= asserted_at || u > max {
            return Err(KeyRecordError::OutOfWindow);
        }
    }
    let mut hardware_class = None;
    let mut chain = Vec::new();
    let pq_custody = match payload.get_text("attestation_evidence") {
        None => None,
        Some(ev) => {
            ev.as_map().ok_or(KeyRecordError::BadPqCustody)?;
            if let Some(c) = ev.get_text("hardware_class") {
                let c = c.as_text().ok_or(KeyRecordError::BadAttestationEvidence)?;
                hardware_class = Some(c.to_owned());
            }
            if let Some(c) = ev.get_text("chain") {
                chain = c
                    .as_array()
                    .filter(|a| !a.is_empty())
                    .ok_or(KeyRecordError::BadAttestationEvidence)?
                    .iter()
                    .map(|d| {
                        d.as_bytes()
                            .map(<[u8]>::to_vec)
                            .ok_or(KeyRecordError::BadAttestationEvidence)
                    })
                    .collect::<Result<_, _>>()?;
            }
            match ev.get_text("pq_custody") {
                None => None,
                Some(v) => Some(match v.as_text() {
                    Some("same_element") => PqCustody::SameElement,
                    Some("removable_offline") => PqCustody::RemovableOffline,
                    Some("software_wrapped") => PqCustody::SoftwareWrapped,
                    _ => return Err(KeyRecordError::BadPqCustody),
                }),
            }
        },
    };
    Ok(KeyRecord {
        pq_custody,
        hardware_class,
        chain,
        kid: thumbprint(&key),
        key,
        identity_type,
        asserted_at,
        valid_until,
    })
}

/// A directory of key-record statements, answering by verifying them.
///
/// Every statement inserted is filed under the kid of the key its payload
/// records. Several statements over one record payload (a rotation record's
/// own statement by the new key and its predecessor's statement) are filed
/// together and all kept. [`KeyDirectory::lookup`] reads the key's own
/// latest statement, or, where the key signed none, the latest inserted;
/// [`KeyDirectory::key_of`] reads them all.
///
/// **Whose key it is** ([`KeyDirectory::key_of`]; CC 2.6.1.7, CC 2.4.1.1,
/// CC 3.1.3): `iss` names the signer's genesis key and stays when the key
/// rotates, so a key `K` other than the one `iss` names is the issuer's only
/// through a rotation chain held here:
///
/// 1. a statement by `K` itself (proof of possession) over a valid
///    `key:record` of `K`, whose `iss` is the issuer;
/// 2. whose payload names the predecessor's record by row-ref in
///    `refs.target`;
/// 3. a statement by the predecessor key `P` over the same row, of the same
///    `iss`, valid here (so `P` is in turn the issuer's: its genesis key, or
///    the next link down);
/// 4. the named record held, `P`'s own valid record, covering the rotation
///    record's `asserted_at` (the old key's signature "made at an instant
///    inside that record"; a record covers `[asserted_at, valid_until)`);
/// 5. no other held rotation of `P` to another key (two rotations of one
///    key, neither naming the other, hand on nothing).
///
/// A record of `K` signed only by another key never makes `K` that key's
/// issuer's. What is not held waits (CC 2.7, CC 2.6.1.9): the named record
/// ([`MissingKey::Record`]), or a voice of a held row
/// ([`MissingKey::Voice`]: the new key's own statement, the predecessor's
/// statement over the rotation, or the predecessor's own statement over the
/// named record), since a row gains voices without changing its row id. No
/// is fixed by bytes held: a record naming no predecessor, a named record of
/// another issuer or not covering the rotation's instant, a voice that fails,
/// or a rival.
#[derive(Debug, Default, Clone)]
pub struct KeyRecordDirectory {
    records: BTreeMap<Digest32, Vec<u8>>,
    statements: BTreeMap<Digest32, Vec<Vec<u8>>>,
    /// Admitted `identity:occurrence` statements, by the occurrence key.
    occurrences: BTreeMap<Digest32, Vec<Vec<u8>>>,
    /// `identity:occurrence_revocation` statements.
    evictions: Vec<Vec<u8>>,
    /// The bundle in force's seats: issuer thumbprint to the seated key.
    seats: BTreeMap<Digest32, CompositePublicKey>,
    /// A bundle in force the caller knows of and does not hold.
    pending_bundle: Option<Digest32>,
}

impl KeyRecordDirectory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold a key-record statement under the kid of the key it records. The
    /// statement is judged when a lookup reaches it, not here.
    ///
    /// Returns the kid it is filed under, or `None` if the bytes carry no
    /// payload `key` to file it under.
    pub fn insert(&mut self, statement: Vec<u8>) -> Option<Digest32> {
        let kid = record_kid(&statement)?;
        let all = self.statements.entry(kid).or_default();
        if !all.contains(&statement) {
            all.push(statement.clone());
        }
        self.records.insert(kid, statement);
        Some(kid)
    }

    /// Hold an admitted `identity:occurrence` statement (CC 3.3.6), filed
    /// under the key its `occurrence_key_id` names: way (d) of the key check.
    /// Both voices of the row are inserted this way, the identity's (a live
    /// roster key's) and the bound key's own (proof of possession).
    ///
    /// Admission is the caller's: an occurrence lands under the two paths of
    /// CC 3.3.6.4, and the lone path turns on when this node first held the
    /// proposal, which no row carries. The directory checks the row itself
    /// when a lookup reaches it: its payload, both voices, the guard that a
    /// machine's key is never a person's, its span over the statement's
    /// instant, and eviction.
    ///
    /// Returns the kid it is filed under, or `None` if `occurrence_key_id`
    /// names no key.
    pub fn insert_occurrence(&mut self, statement: Vec<u8>) -> Option<Digest32> {
        let p = payload_of(&statement)?;
        let kid = identity_ref_thumbprint(p.get_text("occurrence_key_id")?.as_text()?)?;
        let all = self.occurrences.entry(kid).or_default();
        if !all.contains(&statement) {
            all.push(statement);
        }
        Some(kid)
    }

    /// Hold an `identity:occurrence_revocation` statement: from its
    /// `effective_at` the occurrence it names binds nothing, where a key of
    /// the identity signs it.
    pub fn insert_occurrence_revocation(&mut self, statement: Vec<u8>) {
        if !self.evictions.contains(&statement) {
            self.evictions.push(statement);
        }
    }

    /// Hold the seats of the bundle in force of an accord lineage, as
    /// `(issuer's genesis thumbprint, seated key)`: way (c) of the key check
    /// (CC 2.6.1.7, CC 2.6.1.11). A recovery or a rotation by bundle seats a
    /// key with no rotation record. Replaces any earlier bundle's seats, so a
    /// seat ends at the first later bundle in force that does not seat it,
    /// and clears a pending bundle.
    pub fn hold_bundle_in_force(
        &mut self,
        seats: impl IntoIterator<Item = (Digest32, CompositePublicKey)>,
    ) {
        self.seats = seats.into_iter().collect();
        self.pending_bundle = None;
    }

    /// The caller knows the bundle in force `bundle` and does not hold it:
    /// a key no other way proves waits on it ([`MissingKey::Bundle`]).
    pub fn await_bundle_in_force(&mut self, bundle: Digest32) {
        self.pending_bundle = Some(bundle);
    }

    /// Ways (b), (c) and (d) for a statement asserted at `at`.
    fn key_of_full(&self, kid: &Digest32, iss: &Digest32, at: u64, depth: usize) -> KeyOf {
        if depth > MAX_RECORD_DEPTH {
            return KeyOf::No;
        }
        let mut waiting = None;
        for way in [
            self.chain(kid, iss, depth),
            self.seat(kid, iss),
            self.occurrence(kid, iss, at, depth),
        ] {
            match way {
                KeyOf::Yes => return KeyOf::Yes,
                KeyOf::Waiting(m) => {
                    waiting.get_or_insert(m);
                },
                _ => {},
            }
        }
        waiting.map_or(KeyOf::No, KeyOf::Waiting)
    }

    /// Way (c): the bundle in force seats `kid` for `iss`.
    fn seat(&self, kid: &Digest32, iss: &Digest32) -> KeyOf {
        if self
            .seats
            .get(iss)
            .is_some_and(|k| ct_eq(&thumbprint(k), kid))
        {
            return KeyOf::Yes;
        }
        self.pending_bundle
            .map_or(KeyOf::No, |b| KeyOf::Waiting(vec![MissingKey::Bundle(b)]))
    }

    /// Whether the identity whose genesis key is `iss` is a person (`user`
    /// or `accord_holder`) by its genesis record; `None` when not held.
    fn is_person(&self, iss: &Digest32) -> Option<bool> {
        let rec = check_key_record(&payload_of(self.records.get(iss)?)?).ok()?;
        Some(
            rec.identity_type
                .iter()
                .any(|t| t == "user" || t == "accord_holder"),
        )
    }

    /// Whether `kid`'s own record makes it a machine's key (`node` or
    /// `agent`); `false` when no record of it is held.
    fn is_machine(&self, kid: &Digest32) -> bool {
        self.records
            .get(kid)
            .and_then(|r| payload_of(r))
            .and_then(|p| check_key_record(&p).ok())
            .is_some_and(|r| r.identity_type.iter().any(|t| t == "node" || t == "agent"))
    }

    /// Way (d): an admitted `identity:occurrence` of `iss` binds `kid` at `at`.
    fn occurrence(&self, kid: &Digest32, iss: &Digest32, at: u64, depth: usize) -> KeyOf {
        let Some(all) = self.occurrences.get(kid) else {
            return KeyOf::No;
        };
        let rows: BTreeSet<Digest32> = all
            .iter()
            .filter_map(|s| peek(s))
            .map(|pk| pk.row_id)
            .collect();
        let mut waiting = None;
        for row_id in &rows {
            match self.occurrence_row(kid, iss, row_id, all, at, depth) {
                KeyOf::Yes => return KeyOf::Yes,
                KeyOf::Waiting(m) => {
                    waiting.get_or_insert(m);
                },
                _ => {},
            }
        }
        waiting.map_or(KeyOf::No, KeyOf::Waiting)
    }

    fn occurrence_row(
        &self,
        kid: &Digest32,
        iss: &Digest32,
        row_id: &Digest32,
        all: &[Vec<u8>],
        at: u64,
        depth: usize,
    ) -> KeyOf {
        let voices: Vec<&Vec<u8>> = all
            .iter()
            .filter(|s| peek(s).is_some_and(|pk| ct_eq(&pk.row_id, row_id)))
            .collect();
        let Some(p) = voices.first().and_then(|s| payload_of(s)) else {
            return KeyOf::No;
        };
        let text = |m: &str| p.get_text(m).and_then(Value::as_text);
        let thumb = |m: &str| text(m).and_then(identity_ref_thumbprint);
        // The payload (CC 3.3.6): of this identity, binding this key, authored
        // by the identity, a device class from the closed set.
        if !thumb("identity_key_id").is_some_and(|i| ct_eq(&i, iss))
            || !thumb("occurrence_key_id").is_some_and(|k| ct_eq(&k, kid))
            || text("author") != text("identity_key_id")
        {
            return KeyOf::No;
        }
        // The family's payload rule, the one the genesis reader applies.
        if super::check_identity_occurrence(&p).is_err() {
            return KeyOf::No;
        }
        let Some(class) = text("device_class") else {
            return KeyOf::No;
        };
        // A key is a person's or a machine's, never both (CC 2.4.1.1).
        if class == "agent" || self.is_machine(kid) {
            match self.is_person(iss) {
                Some(true) => return KeyOf::No,
                Some(false) => {},
                None => return KeyOf::Waiting(vec![MissingKey::Kid(*iss)]),
            }
        }
        // It covers the statement's instant, [asserted_at, valid_until).
        let Some(from) = p.get_text("asserted_at").and_then(Value::as_u64) else {
            return KeyOf::No;
        };
        if at < from {
            return KeyOf::No;
        }
        if p.get_text("valid_until")
            .and_then(Value::as_u64)
            .is_some_and(|u| at >= u)
        {
            return KeyOf::Waiting(vec![MissingKey::CoveringRecord {
                kid: *kid,
                at_ms: at,
            }]);
        }
        if self.evicted(kid, iss, at, depth) {
            return KeyOf::No;
        }
        // The bound key's own voice (possession), verified under its own key.
        let Some(own) = voices
            .iter()
            .find(|s| peek(s).is_some_and(|pk| ct_eq(&pk.kid, kid)))
        else {
            return KeyOf::Waiting(vec![MissingKey::Voice {
                kid: *kid,
                row: *row_id,
            }]);
        };
        let own_key = match self.resolve(kid, at, depth + 1) {
            KeyLookup::Held(k) => *k,
            KeyLookup::Waiting(m) => return KeyOf::Waiting(m),
            KeyLookup::NotHeld => return KeyOf::Waiting(vec![MissingKey::Kid(*kid)]),
            _ => return KeyOf::No,
        };
        let inner = Scoped {
            dir: self,
            depth: depth + 1,
            own: *kid,
            own_key: Some(own_key),
        };
        match verify_row_statement(own, &inner) {
            Verdict::Valid(_) => {},
            Verdict::Waiting { missing } => return KeyOf::Waiting(missing),
            Verdict::Invalid(_) => return KeyOf::No,
        }
        // The identity's voice: a statement by another key whose `iss` is the
        // identity, its key proved the identity's by step 8 one level deeper.
        let deeper = Deeper {
            dir: self,
            depth: depth + 1,
        };
        let mut waiting = None;
        for v in voices
            .iter()
            .filter(|s| peek(s).is_some_and(|pk| !ct_eq(&pk.kid, kid)))
        {
            match verify_row_statement(v, &deeper) {
                Verdict::Valid(r)
                    if identity_ref_thumbprint(&r.iss).is_some_and(|i| ct_eq(&i, iss)) =>
                {
                    return KeyOf::Yes;
                },
                Verdict::Waiting { missing } => {
                    waiting.get_or_insert(missing);
                },
                _ => {},
            }
        }
        KeyOf::Waiting(waiting.unwrap_or_else(|| {
            vec![MissingKey::Voice {
                kid: *iss,
                row: *row_id,
            }]
        }))
    }

    /// An `identity:occurrence_revocation` of (`iss`, `kid`), effective by
    /// `at`, signed by a key of `iss`.
    fn evicted(&self, kid: &Digest32, iss: &Digest32, at: u64, depth: usize) -> bool {
        let deeper = Deeper {
            dir: self,
            depth: depth + 1,
        };
        self.evictions.iter().any(|e| {
            let Some(p) = payload_of(e) else { return false };
            let thumb = |m: &str| p.get_text(m).and_then(Value::as_text).and_then(identity_ref_thumbprint);
            thumb("identity_key_id").is_some_and(|i| ct_eq(&i, iss))
                && thumb("occurrence_key_id").is_some_and(|k| ct_eq(&k, kid))
                && p.get_text("effective_at").and_then(Value::as_u64).is_some_and(|t| t <= at)
                && matches!(
                    verify_row_statement(e, &deeper),
                    Verdict::Valid(r) if identity_ref_thumbprint(&r.iss).is_some_and(|i| ct_eq(&i, iss))
                )
        })
    }

    fn scoped<'a>(&'a self, kid: &Digest32, st: &[u8], depth: usize) -> Scoped<'a> {
        Scoped {
            dir: self,
            depth: depth + 1,
            own: *kid,
            own_key: record_key(st),
        }
    }

    fn resolve(&self, kid: &Digest32, at: u64, depth: usize) -> KeyLookup {
        if depth > MAX_RECORD_DEPTH {
            return KeyLookup::Invalid;
        }
        // The key's own latest statement over a record of it, else the
        // latest statement filed under it.
        let own = self.statements.get(kid).and_then(|all| {
            all.iter()
                .rev()
                .find(|s| peek(s).is_some_and(|pk| ct_eq(&pk.kid, kid)))
        });
        let Some(st) = own.or_else(|| self.records.get(kid)) else {
            // A key the bundle in force seats is held by its seat: that
            // standing rides no key record (CC 2.6.1.11).
            return self
                .seats
                .values()
                .find(|k| ct_eq(&thumbprint(k), kid))
                .map_or(KeyLookup::NotHeld, |k| KeyLookup::Held(Box::new(k.clone())));
        };
        let inner = self.scoped(kid, st, depth);
        match verify_row_statement(st, &inner) {
            Verdict::Valid(row) => {
                if row.family != KEY_RECORD_FAMILY {
                    return KeyLookup::Invalid;
                }
                let Ok(rec) = check_key_record(&row.payload) else {
                    return KeyLookup::Invalid;
                };
                if rec.kid != *kid {
                    return KeyLookup::Invalid;
                }
                // The record is valid but ends before the instant: a newer
                // record of the key may cover it, so the row waits (CC 2.4.1.1).
                // A record covers [asserted_at, valid_until): the end
                // instant itself is not covered (CC 2.6.2; CWT `exp`).
                if rec.valid_until.is_some_and(|u| at >= u) {
                    return KeyLookup::Waiting(vec![MissingKey::CoveringRecord {
                        kid: *kid,
                        at_ms: at,
                    }]);
                }
                KeyLookup::Held(Box::new(rec.key))
            },
            Verdict::Waiting { missing } => KeyLookup::Waiting(missing),
            Verdict::Invalid(_) => KeyLookup::Invalid,
        }
    }

    /// Is `kid` a key of the issuer whose genesis key is `iss`, by a
    /// rotation chain held here? Asked with `kid != iss`.
    fn chain(&self, kid: &Digest32, iss: &Digest32, depth: usize) -> KeyOf {
        if depth > MAX_RECORD_DEPTH {
            return KeyOf::No;
        }
        let Some(all) = self.statements.get(kid) else {
            return KeyOf::No;
        };
        // Each record of `kid` some voice of which names this issuer, read
        // once over all of its voices held.
        let rows: BTreeSet<Digest32> = all
            .iter()
            .filter_map(|s| peek(s))
            .filter(|pk| pk.iss.is_some_and(|i| ct_eq(&i, iss)))
            .map(|pk| pk.row_id)
            .collect();
        let mut waiting = None;
        for row_id in &rows {
            match self.rotation(kid, iss, row_id, all, depth) {
                KeyOf::Yes => return KeyOf::Yes,
                KeyOf::Waiting(m) => {
                    waiting.get_or_insert(m);
                },
                KeyOf::No => {},
            }
        }
        waiting.map_or(KeyOf::No, KeyOf::Waiting)
    }

    /// One record of `kid` (row `row_id`) as a rotation from its
    /// predecessor. What is not held waits (a named row, or a voice of a
    /// held row: CC 2.7, CC 2.6.1.9); No is fixed by bytes held.
    fn rotation(
        &self,
        kid: &Digest32,
        iss: &Digest32,
        row_id: &Digest32,
        all: &[Vec<u8>],
        depth: usize,
    ) -> KeyOf {
        let voices: Vec<&Vec<u8>> = all
            .iter()
            .filter(|s| peek(s).is_some_and(|pk| ct_eq(&pk.row_id, row_id)))
            .collect();
        // The row's own bytes: what it names and its instant. Every voice
        // signs the same payload (the row id covers it).
        let Some(payload) = voices.first().and_then(|s| payload_of(s)) else {
            return KeyOf::No;
        };
        // A record naming no predecessor is a first record of another key.
        let Some(target) = target_in(&payload) else {
            return KeyOf::No;
        };
        let Some(at) = payload.get_text("asserted_at").and_then(Value::as_u64) else {
            return KeyOf::No;
        };
        // The named record, not held: the link the statement waits on.
        let Some(prev) = self.record_key_of_row(&target) else {
            return KeyOf::Waiting(vec![MissingKey::Record(target)]);
        };
        // The named record is the predecessor's own, by its own voice.
        let prev_own: Vec<&Vec<u8>> = self
            .statements
            .get(&prev)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter(|s| {
                peek(s).is_some_and(|pk| ct_eq(&pk.kid, &prev) && ct_eq(&pk.row_id, &target))
            })
            .collect();
        if prev_own.is_empty() {
            return KeyOf::Waiting(vec![MissingKey::Voice {
                kid: prev,
                row: target,
            }]);
        }
        // Of this issuer, and covering the rotation's instant: fixed by the
        // named record's own bytes (a later record of the predecessor never
        // puts the instant inside this one).
        let of_iss = prev_own
            .iter()
            .any(|s| peek(s).is_some_and(|pk| pk.iss.is_some_and(|i| ct_eq(&i, iss))));
        if !of_iss || !self.prev_record_covers(&prev, &target, at, depth) {
            return KeyOf::No;
        }
        // The new key's own voice (possession), of this issuer.
        let own: Vec<&Vec<u8>> = voices
            .iter()
            .copied()
            .filter(|s| peek(s).is_some_and(|pk| ct_eq(&pk.kid, kid)))
            .collect();
        if own.is_empty() {
            return KeyOf::Waiting(vec![MissingKey::Voice {
                kid: *kid,
                row: *row_id,
            }]);
        }
        let Some((row, _rec, inner)) = own.iter().find_map(|o| {
            let inner = self.scoped(kid, o, depth);
            valid_record(o, &inner, kid)
                .filter(|(r, _)| identity_ref_thumbprint(&r.iss).is_some_and(|i| ct_eq(&i, iss)))
                .map(|(r, rec)| (r, rec, inner))
        }) else {
            return KeyOf::No;
        };
        // The predecessor's voice over the same row, of the same iss.
        let co: Vec<&Vec<u8>> = voices
            .iter()
            .copied()
            .filter(|s| peek(s).is_some_and(|pk| ct_eq(&pk.kid, &prev)))
            .collect();
        if co.is_empty() {
            return KeyOf::Waiting(vec![MissingKey::Voice {
                kid: prev,
                row: *row_id,
            }]);
        }
        let mut waiting = None;
        for c in co {
            match verify_row_statement(c, &inner) {
                Verdict::Valid(v) if ct_eq(&v.row_id, &row.row_id) && v.iss == row.iss => {
                    // Two rotations of one key, neither naming the other,
                    // hand on nothing (CC 2.4.1.1).
                    return if self.rival_rotation(&prev, kid, depth) {
                        KeyOf::No
                    } else {
                        KeyOf::Yes
                    };
                },
                Verdict::Waiting { missing } => {
                    waiting.get_or_insert(missing);
                },
                // A voice that fails is refused alone.
                _ => {},
            }
        }
        waiting.map_or(KeyOf::No, KeyOf::Waiting)
    }

    /// The key the record `row` records, if any statement over it is held.
    fn record_key_of_row(&self, row: &Digest32) -> Option<Digest32> {
        self.statements
            .values()
            .flatten()
            .find(|s| peek(s).is_some_and(|pk| ct_eq(&pk.row_id, row)))
            .and_then(|s| record_kid(s))
    }

    /// Is `target` a valid record of `prev`, by `prev`'s own statement,
    /// covering the instant `at` (CC 2.4.1.1: the old key's signature is made
    /// at an instant inside that record)? The one test of a predecessor's
    /// record, for a rotation and for a rival alike.
    fn prev_record_covers(
        &self,
        prev: &Digest32,
        target: &Digest32,
        at: u64,
        depth: usize,
    ) -> bool {
        self.statements
            .get(prev)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .any(|p| {
                peek(p).is_some_and(|pk| ct_eq(&pk.kid, prev) && ct_eq(&pk.row_id, target))
                    && valid_record(p, &self.scoped(prev, p, depth), prev).is_some_and(
                        |(_, prec)| {
                            prec.asserted_at <= at && prec.valid_until.is_none_or(|u| at < u)
                        },
                    )
            })
    }

    /// Does `prev` have a held, valid rotation to a key other than `next`:
    /// that key's own statement over a record naming a record of `prev` in
    /// `refs.target`, with `prev`'s statement over the same row?
    fn rival_rotation(&self, prev: &Digest32, next: &Digest32, depth: usize) -> bool {
        self.statements.iter().any(|(k2, sts)| {
            if ct_eq(k2, prev) || ct_eq(k2, next) {
                return false;
            }
            sts.iter().any(|own| {
                if !peek(own).is_some_and(|pk| ct_eq(&pk.kid, k2)) {
                    return false;
                }
                let inner = self.scoped(k2, own, depth);
                let Some((row, rec)) = valid_record(own, &inner, k2) else {
                    return false;
                };
                // The rival must name a record of `prev` the chain itself
                // would accept: valid, and covering the rival's instant.
                if !target_of(&row)
                    .is_some_and(|t| self.prev_record_covers(prev, &t, rec.asserted_at, depth))
                {
                    return false;
                }
                sts.iter().any(|co| {
                    peek(co)
                        .is_some_and(|pk| ct_eq(&pk.kid, prev) && ct_eq(&pk.row_id, &row.row_id))
                        && matches!(
                            verify_row_statement(co, &inner),
                            Verdict::Valid(c) if c.iss == row.iss
                        )
                })
            })
        })
    }
}

impl KeyDirectory for KeyRecordDirectory {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        self.resolve(kid, asserted_at, 0)
    }

    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> KeyOf {
        self.key_of_full(kid, iss, u64::MAX, 0)
    }

    fn key_of_at(&self, kid: &Digest32, iss: &Digest32, at: u64) -> KeyOf {
        self.key_of_full(kid, iss, at, 0)
    }
}

/// The directory one level deeper, for a voice of a row a lookup is reading.
struct Deeper<'a> {
    dir: &'a KeyRecordDirectory,
    depth: usize,
}

impl KeyDirectory for Deeper<'_> {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        self.dir.resolve(kid, asserted_at, self.depth)
    }

    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> KeyOf {
        self.dir.key_of_full(kid, iss, u64::MAX, self.depth)
    }

    fn key_of_at(&self, kid: &Digest32, iss: &Digest32, at: u64) -> KeyOf {
        self.dir.key_of_full(kid, iss, at, self.depth)
    }
}

/// The view a key record's own statements are verified through: its own key
/// (a self-signed record) is taken from its payload, every other key from
/// the directory one level deeper.
struct Scoped<'a> {
    dir: &'a KeyRecordDirectory,
    depth: usize,
    own: Digest32,
    own_key: Option<CompositePublicKey>,
}

impl KeyDirectory for Scoped<'_> {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        if *kid == self.own {
            return self
                .own_key
                .clone()
                .map_or(KeyLookup::Invalid, |k| KeyLookup::Held(Box::new(k)));
        }
        self.dir.resolve(kid, asserted_at, self.depth)
    }

    /// A record's own statement names the issuer it claims. Here that claim
    /// only lets the record read as a record of its key (proof of
    /// possession); whether the key is the issuer's is the directory's chain
    /// to prove ([`KeyRecordDirectory`]), never the record's own word. Every
    /// other key is proved through the directory, one level deeper.
    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> KeyOf {
        self.key_of_at(kid, iss, u64::MAX)
    }

    fn key_of_at(&self, kid: &Digest32, iss: &Digest32, at: u64) -> KeyOf {
        if *kid == self.own {
            return KeyOf::Yes;
        }
        self.dir.key_of_full(kid, iss, at, self.depth)
    }
}

fn ct_eq(a: &Digest32, b: &Digest32) -> bool {
    bool::from(a.ct_eq(b))
}

/// A statement verified as a valid key record of `kid`.
fn valid_record(
    st: &[u8],
    dir: &dyn KeyDirectory,
    kid: &Digest32,
) -> Option<(VerifiedRow, KeyRecord)> {
    let Verdict::Valid(row) = verify_row_statement(st, dir) else {
        return None;
    };
    if row.family != KEY_RECORD_FAMILY {
        return None;
    }
    let rec = check_key_record(&row.payload).ok()?;
    ct_eq(&rec.kid, kid).then_some((*row, rec))
}

/// The row id a record's `refs.target` names (`[2, [-16, digest]]`).
fn target_of(row: &VerifiedRow) -> Option<Digest32> {
    target_in(&row.payload)
}

/// [`target_of`] over a payload.
fn target_in(payload: &Value) -> Option<Digest32> {
    let t = payload.get_text("refs")?.get_text("target")?;
    match t.as_array()? {
        [ed, id] if ed.as_u64() == Some(super::EDITION) => match id.as_array()? {
            [alg, d] if alg.as_i64() == Some(-16) => d.as_bytes()?.try_into().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// What the chain needs of a statement, read without verifying it: its
/// signer, the thumbprint inside its `iss`, and its row id.
struct Peek {
    kid: Digest32,
    iss: Option<Digest32>,
    row_id: Digest32,
}

fn peek(statement: &[u8]) -> Option<Peek> {
    let Value::Tag(18, inner) = cde::decode(statement).ok()? else {
        return None;
    };
    let a = inner.as_array()?;
    let prot = cde::decode(a.first()?.as_bytes()?).ok()?;
    let payload_bytes = a.get(2)?.as_bytes()?;
    let payload = cde::decode(payload_bytes).ok()?;
    // Protected labels: 4 kid, 15 CWT claims (1 iss, 2 sub), -70001 row
    // type, -70002 family (CC 2.6.1.3).
    let kid: Digest32 = prot.get_int(4)?.as_bytes()?.try_into().ok()?;
    let cwt = prot.get_int(15)?;
    let iss = cwt
        .get_int(1)
        .and_then(Value::as_text)
        .and_then(identity_ref_thumbprint);
    let sub = cwt.get_int(2)?.as_text()?;
    let row_type = prot.get_int(-70001)?.as_text()?;
    let family = prot.get_int(-70002)?.as_text()?;
    let author = payload.get_text("author").and_then(Value::as_text);
    Some(Peek {
        kid,
        iss,
        row_id: row_id(row_type, family, sub, author, payload_bytes),
    })
}

fn payload_of(statement: &[u8]) -> Option<Value> {
    let Value::Tag(18, inner) = cde::decode(statement).ok()? else {
        return None;
    };
    cde::decode(inner.as_array()?.get(2)?.as_bytes()?).ok()
}

fn record_key(statement: &[u8]) -> Option<CompositePublicKey> {
    let p = payload_of(statement)?;
    let pk = p.get_text("key")?.get_int(-1)?.as_bytes()?;
    CompositePublicKey::from_bytes(pk).ok()
}

fn record_kid(statement: &[u8]) -> Option<Digest32> {
    record_key(statement).as_ref().map(thumbprint)
}

#[cfg(test)]
mod tests {
    use super::super::{cose_key, identity_ref, sign_row_statement, Invalid};
    use super::*;
    use ciris_crypto::composite::CompositeSigningKey;

    const T0: u64 = 1_763_200_000_000;
    const MAX_MS: u64 = KEY_RECORD_MAX_SECS * 1000;

    fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
    }
    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }
    fn rec(k: &CompositeSigningKey, roles: &[&str], until: Option<u64>) -> Value {
        let mut m = vec![
            (t("key"), cose_key(k.public_key())),
            (
                t("identity_type"),
                Value::Array(roles.iter().map(|r| t(r)).collect()),
            ),
            (t("asserted_at"), Value::Uint(T0)),
        ];
        if let Some(u) = until {
            m.push((t("valid_until"), Value::Uint(u)));
        }
        Value::Map(m)
    }
    fn signed_record(
        signer: &CompositeSigningKey,
        subject: &CompositeSigningKey,
        p: &Value,
    ) -> Vec<u8> {
        let iss = identity_ref(&thumbprint(signer.public_key()));
        let sub = identity_ref(&thumbprint(subject.public_key()));
        sign_row_statement(signer, &iss, &sub, "scores", KEY_RECORD_FAMILY, p, vec![]).unwrap()
    }

    #[test]
    fn end_rule() {
        let k = key(1);
        let ok = |r: &[&str], u| check_key_record(&rec(&k, r, u)).map(|_| ());
        assert_eq!(ok(&["node"], Some(T0 + MAX_MS)), Ok(()));
        assert_eq!(
            ok(&["node"], Some(T0 + MAX_MS + 1)),
            Err(KeyRecordError::OutOfWindow)
        );
        assert_eq!(
            ok(&["node"], Some(T0 - 1)),
            Err(KeyRecordError::OutOfWindow)
        );
        // An end at the record's own instant covers nothing: refused.
        assert_eq!(ok(&["node"], Some(T0)), Err(KeyRecordError::OutOfWindow));
        assert_eq!(ok(&["node"], Some(T0 + 1)), Ok(()));
        assert_eq!(ok(&["agent"], None), Err(KeyRecordError::OutOfWindow));
        assert_eq!(ok(&["user"], None), Ok(()));
        assert_eq!(
            ok(&["user"], Some(T0 + 1)),
            Err(KeyRecordError::OutOfWindow)
        );
        assert_eq!(
            ok(&["accord_holder"], Some(T0 + 1)),
            Err(KeyRecordError::OutOfWindow)
        );
        assert_eq!(
            ok(&["node", "user"], Some(T0 + 1)),
            Err(KeyRecordError::MixedRoles)
        );
        assert_eq!(ok(&["pseudonym"], Some(T0 + 1)), Ok(()));
        assert_eq!(ok(&["steward"], None), Ok(()));
        assert_eq!(
            ok(&["user", "node"], None),
            Err(KeyRecordError::BadIdentityType)
        );
        assert_eq!(ok(&[], None), Err(KeyRecordError::BadIdentityType));
        assert_eq!(
            ok(&["node", "node"], Some(T0)),
            Err(KeyRecordError::BadIdentityType)
        );
    }

    #[test]
    fn pq_custody_is_carried_and_closed() {
        let k = key(1);
        let with = |ev: Value| {
            let Value::Map(mut m) = rec(&k, &["accord_holder"], None) else {
                panic!()
            };
            m.push((t("attestation_evidence"), ev));
            check_key_record(&Value::Map(m))
        };
        let ev = |pq: Option<&str>| {
            let mut m = vec![(t("hardware_class"), t("YubiKey_5_FIPS"))];
            if let Some(v) = pq {
                m.push((t("pq_custody"), t(v)));
            }
            Value::Map(m)
        };
        assert_eq!(
            with(ev(Some("removable_offline"))).unwrap().pq_custody,
            Some(PqCustody::RemovableOffline)
        );
        assert_eq!(
            with(ev(Some("same_element"))).unwrap().pq_custody,
            Some(PqCustody::SameElement)
        );
        assert_eq!(
            with(ev(Some("software_wrapped"))).unwrap().pq_custody,
            Some(PqCustody::SoftwareWrapped)
        );
        // Missing is carried as None (the consumer weighs it at 0.0), not refused.
        assert_eq!(with(ev(None)).unwrap().pq_custody, None);
        assert_eq!(
            with(ev(Some("tpm"))).unwrap_err(),
            KeyRecordError::BadPqCustody
        );
        assert_eq!(
            with(t("not-a-map")).unwrap_err(),
            KeyRecordError::BadPqCustody
        );
        assert_eq!(
            check_key_record(&rec(&k, &["user"], None))
                .unwrap()
                .pq_custody,
            None
        );
    }

    #[test]
    fn directory_self_signed_chain_and_waiting() {
        let root = key(1);
        let node = key(2);
        let mut d = KeyRecordDirectory::new();
        // Root: self-signed user record.
        d.insert(signed_record(&root, &root, &rec(&root, &["user"], None)))
            .unwrap();
        // Node: recorded by root.
        let node_kid = d
            .insert(signed_record(
                &root,
                &node,
                &rec(&node, &["node"], Some(T0 + 1000)),
            ))
            .unwrap();
        assert!(matches!(d.lookup(&node_kid, T0), KeyLookup::Held(_)));
        assert!(matches!(d.lookup(&node_kid, T0 + 999), KeyLookup::Held(_)));
        // The end instant is not covered: [asserted_at, valid_until).
        assert!(matches!(
            d.lookup(&node_kid, T0 + 1000),
            KeyLookup::Waiting(_)
        ));
        // Past valid_until: no held record covers the instant, so the key
        // waits on one that does (CC 2.4.1.1: retryable), never Invalid.
        match d.lookup(&node_kid, T0 + 1001) {
            KeyLookup::Waiting(m) => assert_eq!(
                m,
                vec![MissingKey::CoveringRecord {
                    kid: node_kid,
                    at_ms: T0 + 1001
                }]
            ),
            other => panic!("{other:?}"),
        }
        // A newer record of the same key, covering the instant, answers it.
        d.insert(signed_record(
            &root,
            &node,
            &Value::Map(vec![
                (t("key"), cose_key(node.public_key())),
                (t("identity_type"), Value::Array(vec![t("node")])),
                (t("asserted_at"), Value::Uint(T0 + 1000)),
                (t("valid_until"), Value::Uint(T0 + 5000)),
            ]),
        ))
        .unwrap();
        assert!(matches!(d.lookup(&node_kid, T0 + 1001), KeyLookup::Held(_)));

        // A record signed by a key nobody holds: Waiting on that deeper key.
        let ghost = key(9);
        let orphan = key(3);
        let mut d2 = KeyRecordDirectory::new();
        let o = d2
            .insert(signed_record(
                &ghost,
                &orphan,
                &rec(&orphan, &["node"], Some(T0 + 10)),
            ))
            .unwrap();
        match d2.lookup(&o, T0) {
            KeyLookup::Waiting(m) => {
                assert_eq!(m, vec![MissingKey::Kid(thumbprint(ghost.public_key()))])
            },
            other => panic!("{other:?}"),
        }
        // A statement under the orphan is Waiting on the ghost, the deepest key.
        let p = Value::Map(vec![(t("asserted_at"), Value::Uint(T0))]);
        let iss = identity_ref(&thumbprint(orphan.public_key()));
        let st = sign_row_statement(
            &orphan,
            &iss,
            "s",
            "scores",
            "evidence:.suite:.kind:.cell:.prefix",
            &p,
            vec![],
        )
        .unwrap();
        assert_eq!(
            verify_row_statement(&st, &d2),
            Verdict::Waiting {
                missing: vec![MissingKey::Kid(thumbprint(ghost.public_key()))]
            }
        );

        // A record breaking the end rule makes its key, and statements under it, Invalid.
        let bad = key(4);
        let b = d
            .insert(signed_record(&root, &bad, &rec(&bad, &["node"], None)))
            .unwrap();
        assert!(matches!(d.lookup(&b, T0), KeyLookup::Invalid));
        let iss = identity_ref(&b);
        let st = sign_row_statement(
            &bad,
            &iss,
            "s",
            "scores",
            "evidence:.suite:.kind:.cell:.prefix",
            &p,
            vec![],
        )
        .unwrap();
        assert_eq!(
            verify_row_statement(&st, &d),
            Verdict::Invalid(Invalid::KeyNotValid)
        );
    }

    /// Eric's ruling (CIRISConstitution rc20 e08bf05): a key is live in the
    /// forward model only by an edition-2 `key:record` row. An earlier-form
    /// (JSON) key record is not filed and never makes an edition-2 statement
    /// Valid; the statement waits on the edition-2 record.
    #[test]
    fn an_earlier_form_record_never_answers_for_an_edition_2_statement() {
        let k = key(5);
        let earlier = serde_json::to_vec(&serde_json::json!({
            "key_id": "node-1",
            "identity_type": "node",
            "pubkey_ed25519_base64": "AAAA",
            "registration_envelope": {"key_id": "node-1"},
            "scrub_signature_classical": "AAAA",
        }))
        .unwrap();
        let mut d = KeyRecordDirectory::new();
        assert_eq!(
            d.insert(earlier),
            None,
            "an earlier-form record is not filed"
        );
        let p = Value::Map(vec![(t("asserted_at"), Value::Uint(T0))]);
        let iss = identity_ref(&thumbprint(k.public_key()));
        let st = sign_row_statement(
            &k,
            &iss,
            "s",
            "scores",
            "evidence:.suite:.kind:.cell:.prefix",
            &p,
            vec![],
        )
        .unwrap();
        assert_eq!(
            verify_row_statement(&st, &d),
            Verdict::Waiting {
                missing: vec![MissingKey::Kid(thumbprint(k.public_key()))]
            }
        );
    }
}
