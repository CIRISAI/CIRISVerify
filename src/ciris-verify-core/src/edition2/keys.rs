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
//!   `asserted_at <= valid_until <= asserted_at + KEY_RECORD_MAX_SECS * 1000`.
//!
//! [`KeyRecordDirectory`] answers [`KeyLookup`]s from held key-record
//! statements: a record whose own signer is not held makes the key Waiting on
//! that deeper key, an Invalid record makes it Invalid, and a key held in part
//! (an earlier-form key whose ML-DSA half is known only by commitment) is
//! Waiting on that half.

use super::{
    cde, thumbprint, verify_row_statement, Digest32, KeyDirectory, KeyLookup, MissingKey, Value,
    Verdict,
};
use crate::prelude::*;
use ciris_crypto::composite::{CompositePublicKey, COSE_ALG};

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
        if u < asserted_at || u > max {
            return Err(KeyRecordError::OutOfWindow);
        }
    }
    Ok(KeyRecord {
        kid: thumbprint(&key),
        key,
        identity_type,
        asserted_at,
        valid_until,
    })
}

/// A directory of key-record statements, answering by verifying them.
#[derive(Debug, Default, Clone)]
pub struct KeyRecordDirectory {
    records: BTreeMap<Digest32, Vec<u8>>,
    partial: BTreeMap<Digest32, Digest32>,
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
        self.records.insert(kid, statement);
        Some(kid)
    }

    /// Record that `kid` is held in part: its ML-DSA half is known only by
    /// the SHA-256 `commitment`.
    pub fn insert_partial(&mut self, kid: Digest32, commitment: Digest32) {
        self.partial.insert(kid, commitment);
    }

    fn resolve(&self, kid: &Digest32, at: u64, depth: usize) -> KeyLookup {
        if depth > MAX_RECORD_DEPTH {
            return KeyLookup::Invalid;
        }
        let Some(st) = self.records.get(kid) else {
            return match self.partial.get(kid) {
                Some(c) => KeyLookup::Waiting(vec![MissingKey::MlDsaHalf {
                    kid: *kid,
                    commitment: *c,
                }]),
                None => KeyLookup::NotHeld,
            };
        };
        let inner = Scoped {
            dir: self,
            depth: depth + 1,
            own: *kid,
            own_key: record_key(st),
        };
        match verify_row_statement(st, &inner) {
            Verdict::Valid(row) => {
                if row.family != KEY_RECORD_FAMILY {
                    return KeyLookup::Invalid;
                }
                let Ok(rec) = check_key_record(&row.payload) else {
                    return KeyLookup::Invalid;
                };
                if rec.kid != *kid || rec.valid_until.is_some_and(|u| at > u) {
                    return KeyLookup::Invalid;
                }
                KeyLookup::Held(Box::new(rec.key))
            },
            Verdict::Waiting { missing } => KeyLookup::Waiting(missing),
            Verdict::Invalid(_) => KeyLookup::Invalid,
        }
    }
}

impl KeyDirectory for KeyRecordDirectory {
    fn lookup(&self, kid: &Digest32, asserted_at: u64) -> KeyLookup {
        self.resolve(kid, asserted_at, 0)
    }
}

/// The view a key record's own statement is verified through: its own key
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
        assert_eq!(ok(&["node"], Some(T0)), Ok(()));
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
        // Past valid_until: not in force.
        assert!(matches!(d.lookup(&node_kid, T0 + 1001), KeyLookup::Invalid));

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

    #[test]
    fn held_in_part_waits_on_the_half() {
        let mut d = KeyRecordDirectory::new();
        d.insert_partial([7; 32], [8; 32]);
        match d.lookup(&[7; 32], T0) {
            KeyLookup::Waiting(m) => assert_eq!(
                m,
                vec![MissingKey::MlDsaHalf {
                    kid: [7; 32],
                    commitment: [8; 32]
                }]
            ),
            other => panic!("{other:?}"),
        }
    }
}
