//! SD-CWT selective disclosure (draft-ietf-spice-sd-cwt-09) as CC 2.6.1 uses it.
//!
//! A blinded map member is absent from its map, and the SHA-256 digest of its
//! disclosure stands in that map's simple(59) array. A blinded array element
//! is tag 60 over that digest. The digest is taken over the disclosure's bytes
//! exactly as `sd_claims` carries them (no `sd_alg`; SHA-256 only).
//!
//! [`open`] checks a presented disclosure set against a payload:
//! - each disclosure is `[salt(16), value, key]` for a map member or
//!   `[salt(16), value]` for an array element;
//! - its digest opens exactly one place of its own kind that the payload, or a
//!   disclosure already opened, carries (a disclosed value may itself carry
//!   blinded members);
//! - a disclosed key is not already present in the map it opens into;
//! - no digest appears twice, and no place is opened twice.
//!
//! An undisclosed digest is fine: withholding is the point.

use super::{
    check_ceg_value, digest32, malformed, Digest32, Invalid, SIMPLE_REDACTED_KEYS,
    TAG_REDACTED_ELEMENT,
};
use crate::cde::{self, Value};
use crate::prelude::*;
use sha2::{Digest, Sha256};

/// One opened disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosed {
    /// SHA-256 of the disclosure's bytes.
    pub digest: Digest32,
    /// The member name for a map member; `None` for an array element.
    pub key: Option<String>,
    /// The disclosed value.
    pub value: Value,
}

#[derive(Debug)]
enum Place {
    /// A simple(59) entry in a map holding these text keys.
    Member(Vec<String>),
    /// A tag-60 array element.
    Element,
}

fn collect(v: &Value, out: &mut Vec<(Digest32, Place)>) -> Result<(), Invalid> {
    match v {
        Value::Map(m) => {
            let keys: Vec<String> = m
                .iter()
                .filter_map(|(k, _)| k.as_text().map(str::to_owned))
                .collect();
            for (k, x) in m {
                if *k == Value::Simple(SIMPLE_REDACTED_KEYS) {
                    for d in x.as_array().ok_or(malformed("redacted_claim_keys"))? {
                        out.push((
                            digest32(d, "redacted_claim_keys")?,
                            Place::Member(keys.clone()),
                        ));
                    }
                } else {
                    collect(x, out)?;
                }
            }
        },
        Value::Array(a) => {
            for x in a {
                match x {
                    Value::Tag(t, d) if *t == TAG_REDACTED_ELEMENT => {
                        out.push((digest32(d, "redacted-element")?, Place::Element));
                    },
                    _ => collect(x, out)?,
                }
            }
        },
        _ => {},
    }
    Ok(())
}

/// Open `sd_claims` (each a bstr) against `payload`.
///
/// # Errors
/// The [`Invalid`] reason of the first fault.
pub fn open(payload: &Value, sd_claims: &[Value]) -> Result<Vec<Disclosed>, Invalid> {
    let mut places = Vec::new();
    collect(payload, &mut places)?;

    let mut pending = Vec::with_capacity(sd_claims.len());
    for b in sd_claims {
        let bytes = b.as_bytes().ok_or(malformed("sd_claims"))?;
        let d = cde::decode(bytes).map_err(|error| Invalid::NotDeterministic {
            part: "sd_claims",
            error,
        })?;
        let (value, key) = match d {
            Value::Array(mut a)
                if (a.len() == 2 || a.len() == 3)
                    && a[0].as_bytes().map(<[u8]>::len) == Some(16) =>
            {
                let key = if a.len() == 3 {
                    match a.pop() {
                        Some(Value::Text(k)) => Some(k),
                        _ => return Err(malformed("sd-disclosure")),
                    }
                } else {
                    None
                };
                (a.pop().expect("len >= 2"), key)
            },
            _ => return Err(malformed("sd-disclosure")),
        };
        check_ceg_value(&value, false)?;
        let digest: Digest32 = Sha256::digest(bytes).into();
        pending.push(Disclosed { digest, key, value });
    }

    let mut opened: Vec<Disclosed> = Vec::with_capacity(pending.len());
    // Each round opens every pending disclosure whose place is now known; a
    // disclosed value may carry further places. Bounded by the set's size.
    loop {
        let mut digests: Vec<&Digest32> = places.iter().map(|(d, _)| d).collect();
        digests.sort_unstable();
        if digests.windows(2).any(|w| w[0] == w[1]) {
            return Err(Invalid::DuplicateDigest);
        }
        let before = pending.len();
        let mut i = 0;
        while i < pending.len() {
            let Some(pos) = places.iter().position(|(d, _)| *d == pending[i].digest) else {
                i += 1;
                continue;
            };
            let (_, place) = places.swap_remove(pos);
            let d = pending.swap_remove(i);
            match (&place, &d.key) {
                (Place::Member(keys), Some(k)) if !keys.contains(k) => {},
                (Place::Element, None) => {},
                _ => return Err(Invalid::DisclosureUnmatched),
            }
            collect(&d.value, &mut places)?;
            opened.push(d);
        }
        if pending.is_empty() {
            return Ok(opened);
        }
        if pending.len() == before {
            // A disclosure whose digest nothing carries, or one opened twice.
            return Err(Invalid::DisclosureUnmatched);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }
    fn claim(salt: u8, key: &str, v: Value) -> (Vec<u8>, Digest32) {
        let b = cde::encode(&Value::Array(vec![Value::Bytes(vec![salt; 16]), v, t(key)]));
        let d = Sha256::digest(&b).into();
        (b, d)
    }
    fn element(salt: u8, v: Value) -> (Vec<u8>, Digest32) {
        let b = cde::encode(&Value::Array(vec![Value::Bytes(vec![salt; 16]), v]));
        let d = Sha256::digest(&b).into();
        (b, d)
    }
    fn redacted(ds: &[Digest32]) -> (Value, Value) {
        (
            Value::Simple(59),
            Value::Array(ds.iter().map(|d| Value::Bytes(d.to_vec())).collect()),
        )
    }
    fn bs(v: &[&Vec<u8>]) -> Vec<Value> {
        v.iter().map(|b| Value::Bytes((*b).clone())).collect()
    }

    #[test]
    fn opens_members_elements_and_nested() {
        let (inner_b, inner_d) = claim(3, "deep", Value::Uint(9));
        let (note_b, note_d) = claim(1, "note", Value::Map(vec![redacted(&[inner_d])]));
        let (el_b, el_d) = element(2, t("x"));
        let (_, withheld) = claim(4, "kept", Value::Uint(0));
        let payload = Value::Map(vec![
            (t("asserted_at"), Value::Uint(1)),
            redacted(&[note_d, withheld]),
            (
                t("list"),
                Value::Array(vec![
                    Value::Uint(1),
                    Value::Tag(60, Box::new(Value::Bytes(el_d.to_vec()))),
                ]),
            ),
        ]);
        // Order does not matter; the nested one opens after its parent.
        let got = open(&payload, &bs(&[&inner_b, &el_b, &note_b])).unwrap();
        assert_eq!(got.len(), 3);
        assert!(got.iter().any(|d| d.key.as_deref() == Some("deep")));
        assert!(got.iter().any(|d| d.key.is_none()));
        // Withholding is fine: an empty set opens nothing.
        assert!(open(&payload, &[]).unwrap().is_empty());
    }

    #[test]
    fn refusals() {
        let (a_b, a_d) = claim(1, "a", Value::Uint(1));
        let (e_b, e_d) = element(2, Value::Uint(2));
        let p = |extra: Vec<(Value, Value)>| {
            let mut m = vec![(t("asserted_at"), Value::Uint(1))];
            m.extend(extra);
            Value::Map(m)
        };
        // A disclosure nothing carries.
        assert_eq!(
            open(&p(vec![]), &bs(&[&a_b])),
            Err(Invalid::DisclosureUnmatched)
        );
        // Opened twice.
        assert_eq!(
            open(&p(vec![redacted(&[a_d])]), &bs(&[&a_b, &a_b])),
            Err(Invalid::DisclosureUnmatched)
        );
        // Its key is already present in that map.
        assert_eq!(
            open(
                &p(vec![redacted(&[a_d]), (t("a"), Value::Uint(5))]),
                &bs(&[&a_b])
            ),
            Err(Invalid::DisclosureUnmatched)
        );
        // A member disclosure into an element place, and the reverse.
        let el_place = (
            t("l"),
            Value::Array(vec![Value::Tag(60, Box::new(Value::Bytes(a_d.to_vec())))]),
        );
        assert_eq!(
            open(&p(vec![el_place]), &bs(&[&a_b])),
            Err(Invalid::DisclosureUnmatched)
        );
        assert_eq!(
            open(&p(vec![redacted(&[e_d])]), &bs(&[&e_b])),
            Err(Invalid::DisclosureUnmatched)
        );
        // A digest carried twice.
        assert_eq!(
            open(&p(vec![redacted(&[a_d, a_d])]), &[]),
            Err(Invalid::DuplicateDigest)
        );
        // A short salt, a non-text key.
        let short = cde::encode(&Value::Array(vec![
            Value::Bytes(vec![0; 15]),
            Value::Uint(1),
            t("k"),
        ]));
        assert_eq!(
            open(&p(vec![]), &bs(&[&short])),
            Err(malformed("sd-disclosure"))
        );
        let numkey = cde::encode(&Value::Array(vec![
            Value::Bytes(vec![0; 16]),
            Value::Uint(1),
            Value::Uint(3),
        ]));
        assert_eq!(
            open(&p(vec![]), &bs(&[&numkey])),
            Err(malformed("sd-disclosure"))
        );
    }
}
