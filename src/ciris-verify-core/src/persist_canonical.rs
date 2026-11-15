//! CIRISPersist's row identity, `persist_row_hash` (CC 3.2 T6, annex 8.11).
//!
//! A roster version names its predecessor as `prev_head_digest`, and that value
//! is the predecessor's `persist_row_hash`: the hash persist computes over every
//! stored row and enforces at every door. Verify reproduces it here so the
//! records it builds and the lineages it walks agree with persist byte for byte.
//!
//! The construction, as persist's `compute_persist_row_hash` defines it:
//!
//! 1. serialize the stored row to a JSON value (serde; a `None` or empty field
//!    the row type skips is absent, never `null`);
//! 2. remove the top-level members `persist_row_hash` and `consent_role`;
//! 3. truncate every RFC 3339 instant whose fraction is longer than six digits
//!    to microseconds ([`truncate_instants_to_microseconds`](crate::persist_canonical::truncate_instants_to_microseconds));
//! 4. write the value in persist's Python `json.dumps(sort_keys=True,
//!    separators=(",", ":"), ensure_ascii=True)` form ([`python_json_dumps`](crate::persist_canonical::python_json_dumps));
//! 5. SHA-256, lowercase hex.
//!
//! This is **not** JCS. The two differ on every non-ASCII character (escaped
//! here, raw UTF-8 in JCS), on key order above U+FFFF (code point here, UTF-16
//! units in JCS), on integers past 2^53 (exact here) and on float layout.
//! Signing bytes stay JCS ([`crate::jcs::canonicalize`]); only the row identity
//! uses this form.
//!
//! The vector `tests/vectors/accord_lineage/accord_lineage_v1.json` (persist
//! commit `e943482e`) pins every rule.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// The top-level members `persist_row_hash` never covers: the hash itself and
/// the mutable `consent_role` marker.
pub const EXCLUDED_MEMBERS: [&str; 2] = ["persist_row_hash", "consent_role"];

/// The bytes `persist_row_hash` hashes for `row`: its serde value without
/// [`EXCLUDED_MEMBERS`], every instant truncated to microseconds, written by
/// [`python_json_dumps`].
///
/// # Errors
/// A serialization fault from `serde_json`.
pub fn persist_row_hash_preimage<T: Serialize + ?Sized>(
    row: &T,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(row)?;
    if let Some(obj) = value.as_object_mut() {
        for member in EXCLUDED_MEMBERS {
            obj.remove(member);
        }
    }
    truncate_instants_to_microseconds(&mut value);
    Ok(python_json_dumps(&value))
}

/// `persist_row_hash` of `row`: lowercase-hex SHA-256 of
/// [`persist_row_hash_preimage`].
///
/// # Errors
/// A serialization fault from `serde_json`.
pub fn persist_row_hash<T: Serialize + ?Sized>(row: &T) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(persist_row_hash_preimage(row)?)))
}

// --- instants -----------------------------------------------------------------

/// Rewrite every RFC 3339 instant in `value` to microsecond precision,
/// recursively, as persist does before hashing.
///
/// A string is rewritten only when its fraction (the digits after its first
/// `.`) is longer than six digits and the whole string parses as RFC 3339. The
/// kept fraction is printed the way chrono prints a microsecond value: none
/// when it is zero, three digits when it is whole milliseconds, else six
/// (`.535897932` → `.535897`, `.123000789` → `.123`, `.000000789` → none). A
/// fraction of six digits or fewer is left exactly as written, and the offset
/// is kept as written (a typed `DateTime<Utc>` already serializes with `Z`).
pub fn truncate_instants_to_microseconds(value: &mut Value) {
    match value {
        Value::String(s) => {
            if let Some(truncated) = truncate_rfc3339_to_microseconds(s) {
                *s = truncated;
            }
        },
        Value::Array(items) => items.iter_mut().for_each(truncate_instants_to_microseconds),
        Value::Object(map) => map.values_mut().for_each(truncate_instants_to_microseconds),
        _ => {},
    }
}

fn truncate_rfc3339_to_microseconds(s: &str) -> Option<String> {
    let dot = s.find('.')?;
    let frac_start = dot + 1;
    let frac_len = s.as_bytes()[frac_start..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if frac_len <= 6 {
        return None;
    }
    // Only an actual instant is rewritten; a digest or a key id never parses.
    chrono::DateTime::parse_from_rfc3339(s).ok()?;
    let micros = &s[frac_start..frac_start + 6];
    let keep = if micros == "000000" {
        0
    } else if micros.ends_with("000") {
        3
    } else {
        6
    };
    let mut out = String::with_capacity(s.len());
    if keep == 0 {
        out.push_str(&s[..dot]);
    } else {
        out.push_str(&s[..frac_start + keep]);
    }
    out.push_str(&s[frac_start + frac_len..]);
    Some(out)
}

// --- the Python json.dumps form -------------------------------------------------

/// `value` in persist's Python `json.dumps(sort_keys=True, separators=(",",
/// ":"), ensure_ascii=True)` form:
///
/// - object members sorted by key **code point** (UTF-8 byte order), compact
///   separators;
/// - strings ASCII only: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`; other
///   controls and DEL as lowercase `\u00xx` / `\u007f`; non-ASCII as lowercase
///   `\uxxxx`, a surrogate pair above U+FFFF; `/` is not escaped;
/// - integers exact (`u64::MAX`, `i64::MIN`);
/// - floats as persist writes them ([`format_f64`]), which is not Python's
///   `repr` for small exponents (`1e-7`, not `1e-07`; `0.00001`, not `1e-05`).
#[must_use]
pub fn python_json_dumps(value: &Value) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    write_value(&mut out, value);
    out.into_bytes()
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        },
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, &map[k]);
            }
            out.push('}');
        },
    }
}

fn write_number(out: &mut String, n: &serde_json::Number) {
    if let Some(u) = n.as_u64() {
        let _ = write!(out, "{u}");
    } else if let Some(i) = n.as_i64() {
        let _ = write!(out, "{i}");
    } else if let Some(f) = n.as_f64() {
        out.push_str(&format_f64(f));
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (' '..'\u{7f}').contains(&c) => out.push(c),
            c if u32::from(c) <= 0xFFFF => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            },
            c => {
                let cp = u32::from(c) - 0x1_0000;
                let _ = write!(
                    out,
                    "\\u{:04x}\\u{:04x}",
                    0xD800 + (cp >> 10),
                    0xDC00 + (cp & 0x3FF)
                );
            },
        }
    }
    out.push('"');
}

/// A finite `f64` the way persist writes it: its `serde_json` float token,
/// which is `zmij`'s shortest round-trip form (ties to even). Fixed notation
/// when the decimal exponent `e` (value `d.ddd × 10^e`) is in `-5..=15`
/// (`1000000000000000.0`, `0.00001`, `123456.789`, always a fractional part),
/// otherwise `d[.ddd]e±x` with the exponent's sign and no padding (`1e-7`,
/// `1e+16`, `1.5e+300`). Zero is `0.0` / `-0.0`. Not Python's `repr`, which
/// writes `1e-07` and `1e-05`.
///
/// `zmij` is a direct, pinned dependency so the layout cannot drift with a
/// `serde_json` upgrade unnoticed; the tests pin the layout.
#[must_use]
pub fn format_f64(f: f64) -> String {
    zmij::Buffer::new().format_finite(f).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dumps(v: &Value) -> String {
        String::from_utf8(python_json_dumps(v)).unwrap()
    }

    #[test]
    fn keys_sort_by_code_point_not_utf16_units() {
        // U+FB01 sorts before U+1F980 by code point, after it by UTF-16 unit.
        assert_eq!(
            dumps(&json!({"\u{1f980}": 2, "\u{fb01}": 1})),
            r#"{"\ufb01":1,"\ud83e\udd80":2}"#
        );
    }

    #[test]
    fn strings_escape_like_python() {
        assert_eq!(
            dumps(&json!("a/b\u{7f}\u{1}\u{8}\u{c}\r")),
            r#""a/b\u007f\u0001\b\f\r""#
        );
    }

    #[test]
    fn floats_follow_persist_layout() {
        for (f, s) in [
            (1.0, "1.0"),
            (1e-7, "1e-7"),
            (1e-6, "1e-6"),
            (1e-5, "0.00001"),
            (1.25e-5, "0.0000125"),
            (1e15, "1000000000000000.0"),
            (1.5e15, "1500000000000000.0"),
            (1e16, "1e+16"),
            (123_456.789, "123456.789"),
            (-2.5, "-2.5"),
            (1.5e300, "1.5e+300"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (-0.0, "-0.0"),
        ] {
            assert_eq!(format_f64(f), s, "{f:e}");
        }
    }

    proptest::proptest! {
        /// The layout agrees with the `serde_json` float token persist writes.
        #[test]
        fn floats_agree_with_serde_json(bits in proptest::prelude::any::<u64>()) {
            let f = f64::from_bits(bits);
            proptest::prop_assume!(f.is_finite());
            let token = serde_json::Number::from_f64(f).unwrap().to_string();
            proptest::prop_assert_eq!(format_f64(f), token);
        }
    }

    #[test]
    fn instants_truncate_only_past_microseconds() {
        for (raw, out) in [
            (
                "2026-03-14T15:09:26.535897932Z",
                "2026-03-14T15:09:26.535897Z",
            ),
            ("2026-06-01T12:00:00.123000789Z", "2026-06-01T12:00:00.123Z"),
            ("2026-06-01T12:00:00.000000789Z", "2026-06-01T12:00:00Z"),
            ("2026-06-01T12:00:00.100Z", "2026-06-01T12:00:00.100Z"),
            (
                "2026-06-01T12:00:00.1234567+02:00",
                "2026-06-01T12:00:00.123456+02:00",
            ),
            ("not.1234567 an instant", "not.1234567 an instant"),
        ] {
            let mut v = json!({ "nested": [raw] });
            truncate_instants_to_microseconds(&mut v);
            assert_eq!(v["nested"][0], out, "{raw}");
        }
    }

    #[test]
    fn the_hash_drops_its_own_and_consent_role() {
        let a = json!({"k": 1, "persist_row_hash": "x", "consent_role": "y"});
        let b = json!({"k": 1});
        assert_eq!(persist_row_hash(&a).unwrap(), persist_row_hash(&b).unwrap());
        // Only at the top level.
        let nested = json!({"k": {"persist_row_hash": "x"}});
        assert_eq!(
            persist_row_hash_preimage(&nested).unwrap(),
            br#"{"k":{"persist_row_hash":"x"}}"#
        );
    }
}
