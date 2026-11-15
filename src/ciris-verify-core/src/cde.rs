//! CBOR Common Deterministic Encoding (draft-ietf-cbor-cde-13 over RFC 8949
//! §4.2.1), the encoding of every edition-2 signed object (CC 2.6.1, #326).
//!
//! [`decode`](crate::cde::decode) admits exactly one encoding of a value and refuses every other:
//! heads in the shortest form, definite lengths only, map keys in the bytewise
//! order of their encodings with no duplicate, text that is valid UTF-8, no
//! floats, no `undefined`, and no trailing bytes. A byte string that decodes
//! is therefore the [`encode`](crate::cde::encode) of its value, which is what lets a verifier sign
//! and name the bytes as received (CC 2.6.1.1) without re-encoding them.
//!
//! The family-level rules (where `null`, simple(59) and tags may appear) are
//! the reader's, not this codec's: here `null`, booleans, simple values and
//! tags decode as themselves.

use crate::prelude::*;

/// Nesting deeper than this is refused, so a hostile input cannot exhaust the stack.
pub const MAX_DEPTH: usize = 32;

/// A decoded CBOR data item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value is `-1 - n`.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5, in the deterministic order.
    Map(Vec<(Value, Value)>),
    /// Major type 6.
    Tag(u64, Box<Value>),
    /// `false` / `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// A simple value other than false, true, null and undefined.
    Simple(u8),
}

/// Why an input is not a deterministic encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CdeError {
    /// The input ended inside an item.
    #[error("truncated")]
    Truncated,
    /// Bytes follow the top-level item.
    #[error("trailing bytes")]
    TrailingBytes,
    /// A head is not in its shortest form.
    #[error("non-shortest head")]
    NonShortest,
    /// An indefinite length.
    #[error("indefinite length")]
    Indefinite,
    /// A reserved additional-information value (28..=30).
    #[error("reserved additional information")]
    Reserved,
    /// A floating-point value.
    #[error("float")]
    Float,
    /// `undefined`.
    #[error("undefined")]
    Undefined,
    /// A text string that is not UTF-8.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// Map keys out of the bytewise order of their encodings.
    #[error("map keys out of order")]
    KeyOrder,
    /// A repeated map key.
    #[error("duplicate map key")]
    DuplicateKey,
    /// Nesting beyond [`MAX_DEPTH`].
    #[error("too deep")]
    TooDeep,
}

/// Decode `input`, refusing anything that is not the deterministic encoding
/// of one item.
///
/// # Errors
/// The first [`CdeError`] met.
pub fn decode(input: &[u8]) -> Result<Value, CdeError> {
    let mut r = Reader { b: input, i: 0 };
    let v = r.item(0)?;
    if r.i != input.len() {
        return Err(CdeError::TrailingBytes);
    }
    Ok(v)
}

/// The deterministic encoding of `v`. Map entries are written in the bytewise
/// order of their encoded keys whatever order `v` holds them in.
#[must_use]
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, v);
    out
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn write(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Uint(n) => head(out, 0, *n),
        Value::Nint(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        },
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        },
        Value::Array(a) => {
            head(out, 4, a.len() as u64);
            for x in a {
                write(out, x);
            }
        },
        Value::Map(m) => {
            let mut entries: Vec<(Vec<u8>, &Value)> =
                m.iter().map(|(k, v)| (encode(k), v)).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, 5, entries.len() as u64);
            for (k, v) in entries {
                out.extend_from_slice(&k);
                write(out, v);
            }
        },
        Value::Tag(t, x) => {
            head(out, 6, *t);
            write(out, x);
        },
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Simple(s) => head(out, 7, u64::from(*s)),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CdeError> {
        let end = self.i.checked_add(n).ok_or(CdeError::Truncated)?;
        let s = self.b.get(self.i..end).ok_or(CdeError::Truncated)?;
        self.i = end;
        Ok(s)
    }

    /// The major type and argument of the next head, refusing a non-shortest form.
    fn head(&mut self) -> Result<(u8, u8, u64), CdeError> {
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let n = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let n = u64::from(self.take(1)?[0]);
                // Major 7 with ai 24 carries a simple value 32..=255; below 32 is ill-formed.
                if n < 24 || (major == 7 && n < 32) {
                    return Err(CdeError::NonShortest);
                }
                n
            },
            25..=27 if major == 7 => return Err(CdeError::Float),
            25 => {
                let n = u64::from(u16::from_be_bytes(self.take(2)?.try_into().expect("2")));
                if n <= 0xff {
                    return Err(CdeError::NonShortest);
                }
                n
            },
            26 => {
                let n = u64::from(u32::from_be_bytes(self.take(4)?.try_into().expect("4")));
                if n <= 0xffff {
                    return Err(CdeError::NonShortest);
                }
                n
            },
            27 => {
                let n = u64::from_be_bytes(self.take(8)?.try_into().expect("8"));
                if n <= 0xffff_ffff {
                    return Err(CdeError::NonShortest);
                }
                n
            },
            31 => return Err(CdeError::Indefinite),
            _ => return Err(CdeError::Reserved),
        };
        Ok((major, ai, n))
    }

    fn len(&self, n: u64) -> Result<usize, CdeError> {
        // Every element takes at least one byte, so a length past the rest of the input is truncated.
        let n = usize::try_from(n).map_err(|_| CdeError::Truncated)?;
        if n > self.b.len() - self.i {
            return Err(CdeError::Truncated);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Value, CdeError> {
        if depth > MAX_DEPTH {
            return Err(CdeError::TooDeep);
        }
        let (major, ai, n) = self.head()?;
        Ok(match major {
            0 => Value::Uint(n),
            1 => Value::Nint(n),
            2 => {
                let n = self.len(n)?;
                Value::Bytes(self.take(n)?.to_vec())
            },
            3 => {
                let n = self.len(n)?;
                let s = core::str::from_utf8(self.take(n)?).map_err(|_| CdeError::InvalidUtf8)?;
                Value::Text(s.to_owned())
            },
            4 => {
                let n = self.len(n)?;
                let mut a = Vec::with_capacity(n);
                for _ in 0..n {
                    a.push(self.item(depth + 1)?);
                }
                Value::Array(a)
            },
            5 => {
                let n = self.len(n)?;
                let mut m = Vec::with_capacity(n);
                let mut prev: Option<&[u8]> = None;
                let base = self.b;
                for _ in 0..n {
                    let start = self.i;
                    let k = self.item(depth + 1)?;
                    let key_bytes = &base[start..self.i];
                    if let Some(p) = prev {
                        match p.cmp(key_bytes) {
                            core::cmp::Ordering::Less => {},
                            core::cmp::Ordering::Equal => return Err(CdeError::DuplicateKey),
                            core::cmp::Ordering::Greater => return Err(CdeError::KeyOrder),
                        }
                    }
                    prev = Some(key_bytes);
                    let v = self.item(depth + 1)?;
                    m.push((k, v));
                }
                Value::Map(m)
            },
            6 => Value::Tag(n, Box::new(self.item(depth + 1)?)),
            _ => match (ai, n) {
                (_, 20) => Value::Bool(false),
                (_, 21) => Value::Bool(true),
                (_, 22) => Value::Null,
                (_, 23) => return Err(CdeError::Undefined),
                (_, s) => Value::Simple(s as u8),
            },
        })
    }
}

impl Value {
    /// A signed integer from `i64`.
    #[must_use]
    pub fn int(n: i64) -> Self {
        if n >= 0 {
            Value::Uint(n as u64)
        } else {
            Value::Nint(!(n as u64))
        }
    }

    /// The value as `i64`, if it is an integer in range.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Uint(n) => i64::try_from(n).ok(),
            Value::Nint(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// The value as `u64`, if it is an unsigned integer.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::Uint(n) => Some(n),
            _ => None,
        }
    }

    /// The bytes of a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text of a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The elements of an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The entries of a map.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// The value under `key` in a map.
    #[must_use]
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// The value under integer label `label` in a map.
    #[must_use]
    pub fn get_int(&self, label: i64) -> Option<&Value> {
        self.get(&Value::int(label))
    }

    /// The value under text key `key` in a map.
    #[must_use]
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 8949 Appendix A examples that are deterministic encodings.
    #[test]
    fn rfc8949_appendix_a_round_trips() {
        for x in [
            "00",
            "17",
            "1818",
            "1903e8",
            "1a000f4240",
            "1b000000e8d4a51000",
            "1bffffffffffffffff",
            "20",
            "3863",
            "3bffffffffffffffff",
            "40",
            "4401020304",
            "60",
            "6161",
            "62c3bc",
            "80",
            "83010203",
            "8301820203820405",
            "a0",
            "a201020304",
            "a26161016162820203",
            "c074323031332d30332d32315432303a30343a30305a",
            "f4",
            "f5",
            "f6",
            "f0",
            "f820",
            "f8ff",
        ] {
            let b = h(x);
            let v = decode(&b).unwrap_or_else(|e| panic!("{x}: {e}"));
            assert_eq!(encode(&v), b, "{x}");
        }
    }

    #[test]
    fn refusals() {
        for (x, e) in [
            ("1817", CdeError::NonShortest),
            ("190017", CdeError::NonShortest),
            ("1a0000ffff", CdeError::NonShortest),
            ("1b00000000ffffffff", CdeError::NonShortest),
            ("5800", CdeError::NonShortest),
            ("f817", CdeError::NonShortest),
            ("f97c00", CdeError::Float),
            ("fb3ff199999999999a", CdeError::Float),
            ("f7", CdeError::Undefined),
            ("5f4100ff", CdeError::Indefinite),
            ("9fff", CdeError::Indefinite),
            ("1c", CdeError::Reserved),
            ("a203040102", CdeError::KeyOrder),
            ("a201020103", CdeError::DuplicateKey),
            // 10 (0x0a) sorts before 100 (0x1864); -1 (0x20) after both.
            ("a2186401 0a02", CdeError::KeyOrder),
            ("62c328", CdeError::InvalidUtf8),
            ("0000", CdeError::TrailingBytes),
            ("83 0102", CdeError::Truncated),
            ("5a ffffffff00", CdeError::Truncated),
        ] {
            let b = h(&x.replace(' ', ""));
            assert_eq!(decode(&b), Err(e), "{x}");
        }
    }

    #[test]
    fn encode_sorts_keys_bytewise() {
        let v = Value::Map(vec![
            (Value::int(-1), Value::Uint(3)),
            (Value::Uint(3), Value::Uint(2)),
            (Value::Uint(1), Value::Uint(1)),
            (Value::Text("a".into()), Value::Uint(4)),
        ]);
        let b = encode(&v);
        assert_eq!(hex::encode(&b), "a40101030220036161 04".replace(' ', ""));
        assert_eq!(decode(&b).unwrap().get_int(-1), Some(&Value::Uint(3)));
    }

    #[test]
    fn depth_bound() {
        let mut b = vec![0x81; MAX_DEPTH + 1];
        b.push(0x00);
        assert_eq!(decode(&b), Err(CdeError::TooDeep));
        let mut ok = vec![0x81; MAX_DEPTH];
        ok.push(0x00);
        decode(&ok).unwrap();
    }

    #[test]
    fn int_helpers() {
        for n in [0i64, 1, 23, 24, -1, -24, -25, i64::MIN, i64::MAX, -70100] {
            assert_eq!(decode(&encode(&Value::int(n))).unwrap().as_i64(), Some(n));
        }
    }

    proptest::proptest! {
        /// One encoding per value: whatever decodes is the encoding of what it decodes to.
        #[test]
        fn whatever_decodes_reencodes_identically(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)) {
            if let Ok(v) = decode(&b) {
                proptest::prop_assert_eq!(encode(&v), b);
            }
        }

        /// Structured inputs, so the property reaches nested maps and arrays.
        #[test]
        fn encoded_values_decode_back(v in arb_value()) {
            let b = encode(&v);
            let d = decode(&b).unwrap();
            proptest::prop_assert_eq!(encode(&d), b);
        }
    }

    fn arb_value() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let leaf = prop_oneof![
            any::<u64>().prop_map(Value::Uint),
            any::<u64>().prop_map(Value::Nint),
            proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
            "[a-z\\u{e9}\\u{1f600}]{0,30}".prop_map(Value::Text),
            any::<bool>().prop_map(Value::Bool),
            Just(Value::Null),
            (32u8..=255).prop_map(Value::Simple),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                proptest::collection::btree_map(any::<i32>(), inner.clone(), 0..6).prop_map(|m| {
                    Value::Map(
                        m.into_iter()
                            .map(|(k, v)| (Value::int(i64::from(k)), v))
                            .collect(),
                    )
                }),
                (0u64..1000, inner).prop_map(|(t, v)| Value::Tag(t, Box::new(v))),
            ]
        })
    }
}
