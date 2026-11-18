//! JSON to CDE, as CC 2.7.11 maps it for every value hashed from JSON (a
//! call's `arguments`, a payload body).
//!
//! object → map (text keys, written in CDE order; a repeated key is refused),
//! array → array (order kept), string → text, `true` / `false` / `null` →
//! simple values 21 / 20 / 22. A number is read from its exact decimal text,
//! never through binary64 (CDE has no floats):
//!
//! - integral by value and within CBOR's integer range [-2^64, 2^64 - 1]:
//!   that integer (`1e2` → 100, `9007199254740993.0` → 9007199254740993,
//!   `-0.0` → 0);
//! - not integral: the tag-4 decimal fraction `4([exponent, mantissa])`,
//!   normalised (the exponent negative, the mantissa not divisible by 10), so
//!   `1.10` → `4([-1, 11])`;
//! - an integer, mantissa or exponent outside that range is refused
//!   ([`JsonError::NumberUnrepresentable`]; the caller names it,
//!   `call_argument_unrepresentable` or `body_number_unrepresentable`).
//!
//! The parser is this module's own (RFC 8259, strict), so no consumer's
//! `serde_json` features can change how a number reads.

use super::{Value, MAX_DEPTH};
use crate::prelude::*;

/// Why a JSON text has no CDE value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JsonError {
    /// Not JSON (RFC 8259), at this byte offset.
    #[error("not JSON at byte {at}")]
    Syntax {
        /// Byte offset of the fault.
        at: usize,
    },
    /// An object repeats a key.
    #[error("duplicate object key")]
    DuplicateKey,
    /// Nesting beyond [`MAX_DEPTH`].
    #[error("too deep")]
    TooDeep,
    /// A number whose integer, mantissa or exponent is outside CBOR's
    /// integer range.
    #[error("number not representable")]
    NumberUnrepresentable,
}

/// The CDE value of the JSON text `text` (CC 2.7.11).
///
/// # Errors
/// [`JsonError`].
pub fn from_json(text: &str) -> Result<Value, JsonError> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err());
    }
    Ok(v)
}

/// A map with its entries in CDE order (the bytewise order of the encoded
/// keys), so the value equals what [`super::decode`] gives for its encoding.
fn cde_map(mut m: Vec<(Value, Value)>) -> Value {
    m.sort_by_cached_key(|(k, _)| super::encode(k));
    Value::Map(m)
}

/// 2^64: the magnitude of CBOR's most negative integer.
const NEG_LIMIT: u128 = 1 << 64;

/// An integer of magnitude `mag` and sign `neg` as CBOR, if in range.
fn int_value(neg: bool, mag: u128) -> Option<Value> {
    if neg {
        (1..=NEG_LIMIT)
            .contains(&mag)
            .then(|| Value::Nint((mag - 1) as u64))
    } else {
        u64::try_from(mag).ok().map(Value::Uint)
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self) -> JsonError {
        JsonError::Syntax { at: self.i }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn lit(&mut self, word: &[u8], v: Value) -> Result<Value, JsonError> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err())
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::Text),
            Some(b't') => self.lit(b"true", Value::Bool(true)),
            Some(b'f') => self.lit(b"false", Value::Bool(false)),
            Some(b'n') => self.lit(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.err()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.i += 1;
        let mut m: Vec<(Value, Value)> = Vec::new();
        let mut keys: BTreeSet<String> = BTreeSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(cde_map(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err());
            }
            let k = self.string()?;
            if !keys.insert(k.clone()) {
                return Err(JsonError::DuplicateKey);
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.err());
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            m.push((Value::Text(k), v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(cde_map(m));
                },
                _ => return Err(self.err()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.i += 1;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(a));
        }
        loop {
            self.ws();
            a.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(a));
                },
                _ => return Err(self.err()),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let s = self.b.get(self.i..self.i + 4).ok_or_else(|| self.err())?;
        let mut n = 0u32;
        for &c in s {
            let d = (c as char)
                .to_digit(16)
                .ok_or(JsonError::Syntax { at: self.i })?;
            n = n * 16 + d;
        }
        self.i += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.i += 1; // the opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // The input is a &str, so any run between ASCII stops is UTF-8.
            out.push_str(core::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err())?);
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                },
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.err())?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                // A high surrogate must be followed by a low one.
                                if !self.b[self.i..].starts_with(b"\\u") {
                                    return Err(self.err());
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err());
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err());
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or_else(|| self.err())?);
                        },
                        _ => return Err(JsonError::Syntax { at: self.i - 1 }),
                    }
                },
                // An unescaped control character, or the end of input.
                _ => return Err(self.err()),
            }
        }
    }

    fn digits(&mut self) -> &[u8] {
        let s = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        &self.b[s..self.i]
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let neg = self.peek() == Some(b'-');
        if neg {
            self.i += 1;
        }
        let int_at = self.i;
        let int = self.digits().to_vec();
        if int.is_empty() || (int.len() > 1 && int[0] == b'0') {
            return Err(JsonError::Syntax { at: int_at });
        }
        let mut frac = Vec::new();
        if self.peek() == Some(b'.') {
            self.i += 1;
            frac = self.digits().to_vec();
            if frac.is_empty() {
                return Err(self.err());
            }
        }
        let mut exp: i128 = 0;
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            let eneg = match self.peek() {
                Some(b'-') => {
                    self.i += 1;
                    true
                },
                Some(b'+') => {
                    self.i += 1;
                    false
                },
                _ => false,
            };
            let ed = self.digits();
            if ed.is_empty() {
                return Err(self.err());
            }
            // Saturate: any exponent this large puts a non-zero number out of range.
            for &d in ed {
                exp = (exp * 10 + i128::from(d - b'0')).min(1 << 80);
            }
            if eneg {
                exp = -exp;
            }
        }
        // value = digits × 10^e, digits without leading or trailing zeros.
        let mut d: Vec<u8> = int.iter().chain(frac.iter()).copied().collect();
        let mut e = exp - frac.len() as i128;
        let lead = d.iter().take_while(|&&c| c == b'0').count();
        d.drain(..lead);
        if d.is_empty() {
            return Ok(Value::Uint(0)); // zero, -0.0 included
        }
        while d.last() == Some(&b'0') {
            d.pop();
            e += 1;
        }
        // 2^64 has 20 digits: a longer mantissa is out of range.
        let mag_of = |digits: &[u8]| -> Option<u128> {
            if digits.len() > 20 {
                return None;
            }
            Some(
                digits
                    .iter()
                    .fold(0u128, |n, &c| n * 10 + u128::from(c - b'0')),
            )
        };
        let unrep = JsonError::NumberUnrepresentable;
        if e >= 0 {
            if d.len() as i128 + e > 20 {
                return Err(unrep);
            }
            let mag = mag_of(&d).ok_or(unrep)? * 10u128.pow(e as u32);
            int_value(neg, mag).ok_or(unrep)
        } else {
            let mant = int_value(neg, mag_of(&d).ok_or(unrep)?).ok_or(unrep)?;
            let exp = int_value(true, (-e) as u128).ok_or(unrep)?;
            Ok(Value::Tag(4, Box::new(Value::Array(vec![exp, mant]))))
        }
    }
}
