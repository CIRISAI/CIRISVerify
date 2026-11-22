//! A UTC instant with the text and serde behaviour of chrono 0.4's
//! `DateTime<Utc>`, which it replaces (RUSTSEC-2026-0543: chrono is
//! unmaintained).
//!
//! Every byte this type writes, and every string it accepts, is the one chrono
//! 0.4.44 wrote and accepted, because signed records, stored latches,
//! transparency heads and persist's typed columns were all produced through
//! chrono and must keep reading and re-rendering the same:
//!
//! - **serde** writes RFC 3339 with `Z` and the shortest SI fraction (none, 3,
//!   6 or 9 digits: chrono's `SecondsFormat::AutoSi`), and reads chrono's
//!   *relaxed* RFC 3339 (the `FromStr` grammar: a space or `T`/`t` between date
//!   and time, whitespace around the components, a signed year of any width, a
//!   one- or two-digit month, day, hour, minute and second, `Z`/`z`/`UTC` or a
//!   numeric offset with or without its colon, trailing whitespace).
//! - [`UtcDateTime::parse_from_rfc3339`] is chrono's strict parser of the same
//!   name: exactly `YYYY-MM-DD`, `T`/`t`/space, `HH:MM:SS`, an optional
//!   fraction of any length (digits past the ninth are ignored), and `Z`/`z` or
//!   `±HH:MM` (U+2212 MINUS SIGN accepted), within ±23:59.
//! - [`UtcDateTime::to_rfc3339`] is `+00:00` with the `AutoSi` fraction;
//!   [`UtcDateTime::to_rfc3339_opts`] takes a [`SecondsFormat`].
//! - `Debug` is the serde form; `Display` is `YYYY-MM-DD HH:MM:SS[.f] UTC`.
//!
//! A leap second (`…:60`, which both chrono parsers accept at any minute) is
//! kept as chrono keeps it: the POSIX second of `…:59` with a sub-second part
//! of one billion or more, so [`UtcDateTime::timestamp`] and
//! [`UtcDateTime::timestamp_subsec_nanos`] give chrono's values and the text
//! renders `:60` again.
//!
//! The range is chrono's: years −262143 to 262142. This module reads no clock;
//! [`UtcDateTime::now`] exists only with `std`.

#[allow(unused_imports)]
use crate::prelude::*;

use core::fmt::{self, Write};
use core::str::FromStr;

const NANOS: u32 = 1_000_000_000;
const SECS_PER_DAY: i64 = 86_400;
const MIN_YEAR: i64 = -262_143;
const MAX_YEAR: i64 = 262_142;
/// `days_from_civil(MIN_YEAR, 1, 1) * 86400`.
const MIN_SECS: i64 = days_from_civil(MIN_YEAR, 1, 1) * SECS_PER_DAY;
/// The last second of `MAX_YEAR-12-31`.
const MAX_SECS: i64 = days_from_civil(MAX_YEAR, 12, 31) * SECS_PER_DAY + SECS_PER_DAY - 1;

/// A UTC instant: POSIX seconds and a sub-second part in nanoseconds (one
/// billion or more only inside a leap second). Ordering and equality are
/// chrono's.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcDateTime {
    secs: i64,
    nanos: u32,
}

/// The fraction [`UtcDateTime::to_rfc3339_opts`] writes (chrono's
/// `SecondsFormat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondsFormat {
    /// No fraction.
    Secs,
    /// Exactly three digits.
    Millis,
    /// Exactly six digits.
    Micros,
    /// Exactly nine digits.
    Nanos,
    /// None, three, six or nine digits: the fewest that are exact.
    AutoSi,
}

/// Why a string is not an instant (chrono's `ParseError` kinds, with its
/// messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// A value is out of range, or the date does not exist.
    OutOfRange,
    /// The instant falls outside the representable range.
    Impossible,
    /// A character is not what the grammar allows.
    Invalid,
    /// The input ended early.
    TooShort,
    /// Input remains after the instant.
    TooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutOfRange => "input is out of range",
            Self::Impossible => "no possible date and time matching input",
            Self::Invalid => "input contains invalid characters",
            Self::TooShort => "premature end of input",
            Self::TooLong => "trailing input",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

type PResult<T> = Result<T, ParseError>;

impl UtcDateTime {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Self = Self { secs: 0, nanos: 0 };
    /// The earliest instant (chrono's `DateTime::<Utc>::MIN_UTC`).
    pub const MIN: Self = Self {
        secs: MIN_SECS,
        nanos: 0,
    };
    /// The latest instant (chrono's `DateTime::<Utc>::MAX_UTC`).
    pub const MAX: Self = Self {
        secs: MAX_SECS,
        nanos: NANOS - 1,
    };

    /// The instant `secs` POSIX seconds and `nanos` nanoseconds after the
    /// epoch, as chrono's `DateTime::from_timestamp`: `None` out of range, or
    /// if `nanos` is two billion or more, or one billion or more anywhere but
    /// the 59th second of a minute (a leap second).
    #[must_use]
    pub const fn from_timestamp(secs: i64, nanos: u32) -> Option<Self> {
        if secs < MIN_SECS || secs > MAX_SECS || nanos >= 2 * NANOS {
            return None;
        }
        if nanos >= NANOS && secs.rem_euclid(60) != 59 {
            return None;
        }
        Some(Self { secs, nanos })
    }

    /// The instant `ms` POSIX milliseconds after the epoch (`None` out of
    /// range).
    #[must_use]
    pub const fn from_timestamp_millis(ms: i64) -> Option<Self> {
        Self::from_timestamp(
            ms.div_euclid(1000),
            (ms.rem_euclid(1000) as u32) * 1_000_000,
        )
    }

    /// The system clock, now. Before the epoch reads as before the epoch.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Self::from_timestamp(d.as_secs() as i64, d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                let (s, n) = (d.as_secs() as i64, d.subsec_nanos());
                if n == 0 {
                    Self::from_timestamp(-s, 0)
                } else {
                    Self::from_timestamp(-s - 1, NANOS - n)
                }
            },
        };
        t.expect("system clock within chrono's range")
    }

    /// POSIX seconds (chrono's `timestamp`; a leap second is its `…:59`).
    #[must_use]
    pub const fn timestamp(&self) -> i64 {
        self.secs
    }

    /// The sub-second part in nanoseconds (chrono's `timestamp_subsec_nanos`;
    /// one billion or more inside a leap second).
    #[must_use]
    pub const fn timestamp_subsec_nanos(&self) -> u32 {
        self.nanos
    }

    /// POSIX milliseconds (chrono's `timestamp_millis`).
    #[must_use]
    pub const fn timestamp_millis(&self) -> i64 {
        self.secs * 1000 + (self.nanos / 1_000_000) as i64
    }

    /// `self + secs` seconds, `None` out of range (chrono's
    /// `checked_add_signed` with whole seconds, leap second rules included).
    #[must_use]
    pub const fn checked_add_secs(&self, secs: i64) -> Option<Self> {
        let (mut base, mut nanos) = (self.secs, self.nanos);
        if nanos >= NANOS {
            // Leaving a leap second: forwards it counts as the `:59`, backwards
            // as the second after it (chrono's `overflowing_add_signed`).
            if secs > 0 {
                nanos -= NANOS;
            } else if secs < 0 {
                nanos -= NANOS;
                base += 1;
            } else {
                return Some(*self);
            }
        }
        match base.checked_add(secs) {
            Some(s) => Self::from_timestamp(s, nanos),
            None => None,
        }
    }

    /// `self - rhs` in nanoseconds (chrono's `signed_duration_since`, leap
    /// second rules included).
    #[must_use]
    pub const fn signed_nanos_since(&self, rhs: &Self) -> i128 {
        let mut secs = (self.secs - rhs.secs) as i128;
        let frac = self.nanos as i128 - rhs.nanos as i128;
        let (a, b) = (
            self.secs.rem_euclid(SECS_PER_DAY),
            rhs.secs.rem_euclid(SECS_PER_DAY),
        );
        if a > b && rhs.nanos >= NANOS {
            secs += 1;
        } else if a < b && self.nanos >= NANOS {
            secs -= 1;
        }
        secs * NANOS as i128 + frac
    }

    /// chrono's `parse_from_rfc3339`: the strict RFC 3339 grammar (see the
    /// module docs).
    pub fn parse_from_rfc3339(s: &str) -> Result<Self, ParseError> {
        parse_rfc3339_strict(s)
    }

    /// RFC 3339 with `+00:00` and the `AutoSi` fraction (chrono's
    /// `to_rfc3339`).
    #[must_use]
    pub fn to_rfc3339(&self) -> String {
        self.to_rfc3339_opts(SecondsFormat::AutoSi, false)
    }

    /// RFC 3339 with the fraction `secform`, and `Z` for the offset if `use_z`
    /// else `+00:00` (chrono's `to_rfc3339_opts`).
    #[must_use]
    pub fn to_rfc3339_opts(&self, secform: SecondsFormat, use_z: bool) -> String {
        let mut out = String::with_capacity(38);
        self.write_rfc3339(&mut out, secform, use_z)
            .expect("writing to a String never fails");
        out
    }

    /// `(year, month, day, hour, minute, second, nanosecond)` with a leap
    /// second as second 60.
    fn fields(&self) -> (i64, u32, u32, u32, u32, u32, u32) {
        let days = self.secs.div_euclid(SECS_PER_DAY);
        let sod = self.secs.rem_euclid(SECS_PER_DAY) as u32;
        let (y, m, d) = civil_from_days(days);
        let (mut sec, mut nano) = (sod % 60, self.nanos);
        if nano >= NANOS {
            sec += 1;
            nano -= NANOS;
        }
        (y, m, d, sod / 3600, sod / 60 % 60, sec, nano)
    }

    fn write_date(&self, w: &mut impl Write) -> fmt::Result {
        let (y, m, d, ..) = self.fields();
        if (0..=9999).contains(&y) {
            write!(w, "{y:04}")?;
        } else {
            write!(w, "{y:+05}")?;
        }
        write!(w, "-{m:02}-{d:02}")
    }

    fn write_time(&self, w: &mut impl Write, secform: SecondsFormat) -> fmt::Result {
        let (_, _, _, h, mi, s, nano) = self.fields();
        write!(w, "{h:02}:{mi:02}:{s:02}")?;
        match secform {
            SecondsFormat::Secs => Ok(()),
            SecondsFormat::Millis => write!(w, ".{:03}", nano / 1_000_000),
            SecondsFormat::Micros => write!(w, ".{:06}", nano / 1000),
            SecondsFormat::Nanos => write!(w, ".{nano:09}"),
            SecondsFormat::AutoSi => {
                if nano == 0 {
                    Ok(())
                } else if nano % 1_000_000 == 0 {
                    write!(w, ".{:03}", nano / 1_000_000)
                } else if nano % 1000 == 0 {
                    write!(w, ".{:06}", nano / 1000)
                } else {
                    write!(w, ".{nano:09}")
                }
            },
        }
    }

    fn write_rfc3339(
        &self,
        w: &mut impl Write,
        secform: SecondsFormat,
        use_z: bool,
    ) -> fmt::Result {
        self.write_date(w)?;
        w.write_char('T')?;
        self.write_time(w, secform)?;
        w.write_str(if use_z { "Z" } else { "+00:00" })
    }
}

impl fmt::Debug for UtcDateTime {
    /// chrono's `Debug`: the serde form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_rfc3339(f, SecondsFormat::AutoSi, true)
    }
}

impl fmt::Display for UtcDateTime {
    /// chrono's `Display`: `YYYY-MM-DD HH:MM:SS[.f] UTC`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_date(f)?;
        f.write_char(' ')?;
        self.write_time(f, SecondsFormat::AutoSi)?;
        f.write_str(" UTC")
    }
}

impl FromStr for UtcDateTime {
    type Err = ParseError;

    /// chrono's `FromStr`: the relaxed RFC 3339 grammar (see the module docs).
    fn from_str(s: &str) -> Result<Self, ParseError> {
        parse_rfc3339_relaxed(s)
    }
}

impl serde::Serialize for UtcDateTime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{self:?}"))
    }
}

impl<'de> serde::Deserialize<'de> for UtcDateTime {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = UtcDateTime;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 formatted date and time string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<UtcDateTime, E> {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

// --- calendar ------------------------------------------------------------------

/// Days from 1970-01-01 to `y-m-d` (proleptic Gregorian).
const fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day)` of the day `z` days after 1970-01-01.
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

const fn is_leap(y: i64) -> bool {
    y.rem_euclid(4) == 0 && (y.rem_euclid(100) != 0 || y.rem_euclid(400) == 0)
}

/// chrono's `NaiveDate::from_ymd_opt`, as days since the epoch.
fn date_days(y: i64, m: u32, d: u32) -> PResult<i64> {
    if !(MIN_YEAR..=MAX_YEAR).contains(&y) || !(1..=12).contains(&m) || d == 0 {
        return Err(ParseError::OutOfRange);
    }
    let dim = match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if d > dim {
        return Err(ParseError::OutOfRange);
    }
    Ok(days_from_civil(y, m, d))
}

/// chrono's `NaiveTime::from_hms_nano_opt`, as `(seconds of day, nanos)`.
fn time_of_day(h: u32, mi: u32, s: u32, nano: u32) -> PResult<(i64, u32)> {
    if h >= 24 || mi >= 60 || s >= 60 || (nano >= NANOS && s != 59) || nano >= 2 * NANOS {
        return Err(ParseError::OutOfRange);
    }
    Ok((i64::from(h * 3600 + mi * 60 + s), nano))
}

/// The UTC instant of a local date and time at `offset` seconds east (chrono's
/// `FixedOffset::from_local_datetime`; `Impossible` out of range).
fn at_offset(days: i64, sod: i64, nanos: u32, offset: i32) -> PResult<UtcDateTime> {
    let secs = days * SECS_PER_DAY + sod - i64::from(offset);
    UtcDateTime::from_timestamp(secs, nanos).ok_or(ParseError::Impossible)
}

// --- chrono's scanners -----------------------------------------------------------

/// chrono `scan::number`: `min` to `max` ASCII digits, more left unread.
fn number(s: &str, min: usize, max: usize) -> PResult<(&str, i64)> {
    let bytes = s.as_bytes();
    if bytes.len() < min {
        return Err(ParseError::TooShort);
    }
    let mut n = 0i64;
    for (i, c) in bytes.iter().take(max).copied().enumerate() {
        if !c.is_ascii_digit() {
            return if i < min {
                Err(ParseError::Invalid)
            } else {
                Ok((&s[i..], n))
            };
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(i64::from(c - b'0')))
            .ok_or(ParseError::OutOfRange)?;
    }
    Ok((&s[max.min(bytes.len())..], n))
}

/// chrono `scan::nanosecond`: one or more digits of fraction, digits past
/// the ninth skipped.
fn nanosecond(s: &str) -> PResult<(&str, u32)> {
    const SCALE: [u32; 10] = [
        0,
        100_000_000,
        10_000_000,
        1_000_000,
        100_000,
        10_000,
        1_000,
        100,
        10,
        1,
    ];
    let origlen = s.len();
    let (s, v) = number(s, 1, 9)?;
    let consumed = origlen - s.len();
    let v = (v as u32)
        .checked_mul(SCALE[consumed])
        .ok_or(ParseError::OutOfRange)?;
    Ok((s.trim_start_matches(|c: char| c.is_ascii_digit()), v))
}

/// chrono `scan::timezone_offset` with `allow_zulu`, no missing minutes, and
/// U+2212 accepted as a minus sign.
fn timezone_offset(
    mut s: &str,
    consume_colon: impl Fn(&str) -> PResult<&str>,
) -> PResult<(&str, i32)> {
    if let Some(b'Z' | b'z') = s.as_bytes().first() {
        return Ok((&s[1..], 0));
    }
    fn digits(s: &str) -> PResult<(u8, u8)> {
        let b = s.as_bytes();
        if b.len() < 2 {
            Err(ParseError::TooShort)
        } else {
            Ok((b[0], b[1]))
        }
    }
    let negative = match s.chars().next() {
        Some('+') => {
            s = &s[1..];
            false
        },
        Some('-') => {
            s = &s[1..];
            true
        },
        Some('\u{2212}') => {
            s = &s['\u{2212}'.len_utf8()..];
            true
        },
        Some(_) => return Err(ParseError::Invalid),
        None => return Err(ParseError::TooShort),
    };
    let hours = match digits(s)? {
        (h1 @ b'0'..=b'9', h2 @ b'0'..=b'9') => i32::from((h1 - b'0') * 10 + (h2 - b'0')),
        _ => return Err(ParseError::Invalid),
    };
    s = consume_colon(&s[2..])?;
    let minutes = match digits(s) {
        Ok((m1 @ b'0'..=b'5', m2 @ b'0'..=b'9')) => i32::from((m1 - b'0') * 10 + (m2 - b'0')),
        Ok((b'6'..=b'9', b'0'..=b'9')) => return Err(ParseError::OutOfRange),
        Ok(_) => return Err(ParseError::Invalid),
        Err(_) => return Err(ParseError::TooShort),
    };
    let seconds = hours * 3600 + minutes * 60;
    Ok((&s[2..], if negative { -seconds } else { seconds }))
}

fn colon(s: &str) -> PResult<&str> {
    match s.as_bytes().first() {
        Some(b':') => Ok(&s[1..]),
        Some(_) => Err(ParseError::Invalid),
        None => Err(ParseError::TooShort),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn colon_or_space(s: &str) -> PResult<&str> {
    Ok(s.trim_start_matches(|c: char| c == ':' || c.is_whitespace()))
}

/// chrono `FixedOffset::east_opt`'s range.
fn check_offset(offset: i32) -> PResult<i32> {
    if -86_400 < offset && offset < 86_400 {
        Ok(offset)
    } else {
        Err(ParseError::OutOfRange)
    }
}

// --- chrono's two RFC 3339 parsers -------------------------------------------------

/// chrono `format::parse::parse_rfc3339` (behind `parse_from_rfc3339`).
fn parse_rfc3339_strict(s: &str) -> PResult<UtcDateTime> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return Err(ParseError::TooShort);
    }
    let digit = |i: usize| -> PResult<u32> {
        if bytes[i].is_ascii_digit() {
            Ok(u32::from(bytes[i] - b'0'))
        } else {
            Err(ParseError::Invalid)
        }
    };
    let year = digit(0)? * 1000 + digit(1)? * 100 + digit(2)? * 10 + digit(3)?;
    if bytes[4] != b'-' {
        return Err(ParseError::Invalid);
    }
    let month = digit(5)? * 10 + digit(6)?;
    if bytes[7] != b'-' {
        return Err(ParseError::Invalid);
    }
    let day = digit(8)? * 10 + digit(9)?;
    let days = date_days(i64::from(year), month, day)?;
    if !matches!(bytes[10], b't' | b'T' | b' ') {
        return Err(ParseError::Invalid);
    }
    let hour = digit(11)? * 10 + digit(12)?;
    if bytes[13] != b':' {
        return Err(ParseError::Invalid);
    }
    let min = digit(14)? * 10 + digit(15)?;
    if bytes[16] != b':' {
        return Err(ParseError::Invalid);
    }
    let sec = digit(17)? * 10 + digit(18)?;
    let (sec, extra) = if sec == 60 { (59, NANOS) } else { (sec, 0) };
    let (rest, nano) = if bytes.get(19) == Some(&b'.') {
        let (rest, n) = nanosecond(&s[20..])?;
        (rest, extra + n)
    } else {
        (&s[19..], extra)
    };
    let (sod, nano) = time_of_day(hour, min, sec, nano)?;
    let (rest, offset) = timezone_offset(rest, colon)?;
    if !rest.is_empty() {
        return Err(ParseError::TooLong);
    }
    at_offset(days, sod, nano, check_offset(offset)?)
}

/// chrono `format::parse::parse_rfc3339_relaxed` plus `FromStr`'s trailing
/// whitespace and `Parsed::to_datetime`.
fn parse_rfc3339_relaxed(s: &str) -> PResult<UtcDateTime> {
    fn literal(s: &str, c: char) -> PResult<&str> {
        if s.is_empty() {
            Err(ParseError::TooShort)
        } else if let Some(rest) = s.strip_prefix(c) {
            Ok(rest)
        } else {
            Err(ParseError::Invalid)
        }
    }
    /// An unsigned numeric item of at most `width` digits, set in `range`.
    fn field(s: &str, width: usize, range: core::ops::RangeInclusive<i64>) -> PResult<(&str, u32)> {
        let (s, v) = number(s.trim_start(), 1, width)?;
        if !range.contains(&v) {
            return Err(ParseError::OutOfRange);
        }
        Ok((s, v as u32))
    }

    // Year: signed of any width, or unsigned of at most four digits.
    let s = s.trim_start();
    let (s, year) = if let Some(r) = s.strip_prefix('-') {
        let (r, v) = number(r, 1, usize::MAX)?;
        (r, 0i64.checked_sub(v).ok_or(ParseError::OutOfRange)?)
    } else if let Some(r) = s.strip_prefix('+') {
        number(r, 1, usize::MAX)?
    } else {
        number(s, 1, 4)?
    };
    let year = i32::try_from(year).map_err(|_| ParseError::OutOfRange)?;
    let s = literal(s.trim_start(), '-')?;
    let (s, month) = field(s, 2, 1..=12)?;
    let s = literal(s.trim_start(), '-')?;
    let (s, day) = field(s, 2, 1..=31)?;
    let s = match s.as_bytes().first() {
        Some(b't' | b'T' | b' ') => &s[1..],
        Some(_) => return Err(ParseError::Invalid),
        None => return Err(ParseError::TooShort),
    };
    let (s, hour) = field(s, 2, 0..=23)?;
    let s = literal(s.trim_start(), ':')?;
    let (s, minute) = field(s, 2, 0..=59)?;
    let s = literal(s.trim_start(), ':')?;
    let (s, second) = field(s, 2, 0..=60)?;
    let (s, nano) = match s.strip_prefix('.') {
        Some(r) => nanosecond(r)?,
        None => (s, 0),
    };
    let s = s.trim_start();
    let (s, offset) = if s.len() >= 3 && s.as_bytes()[..3].eq_ignore_ascii_case(b"UTC") {
        (&s[3..], 0)
    } else {
        timezone_offset(s, colon_or_space)?
    };
    if !s.trim_start().is_empty() {
        return Err(ParseError::TooLong);
    }
    // `Parsed::to_datetime`: the date and time first, then the offset.
    let days = date_days(i64::from(year), month, day)?;
    let (second, extra) = if second == 60 {
        (59, NANOS)
    } else {
        (second, 0)
    };
    let (sod, nano) = time_of_day(hour, minute, second, extra + nano)?;
    at_offset(days, sod, nano, check_offset(offset)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict(s: &str) -> Option<String> {
        UtcDateTime::parse_from_rfc3339(s)
            .ok()
            .map(|t| format!("{t:?}"))
    }

    fn relaxed(s: &str) -> Option<String> {
        s.parse::<UtcDateTime>().ok().map(|t| format!("{t:?}"))
    }

    /// Strings chrono 0.4.44's serde wrote for `DateTime<Utc>` (whole second,
    /// ms, µs, ns), read back and re-written byte for byte.
    #[test]
    fn chrono_serde_strings_round_trip() {
        for s in [
            "2026-11-21T09:26:15Z",
            "2026-11-21T09:26:15.250Z",
            "2026-11-21T09:26:15.250001Z",
            "2026-11-21T09:26:15.123456789Z",
            "2026-11-21T09:26:15.100Z",
            "2026-11-21T09:26:15.000100Z",
            "2026-11-21T09:26:15.000000001Z",
            "1970-01-01T00:00:00Z",
            "1969-12-31T23:59:59.999999999Z",
            "0000-01-01T00:00:00Z",
            "9999-12-31T23:59:59.999Z",
            "+10000-01-01T00:00:00Z",
            "-0001-12-31T00:00:00Z",
            "+262142-12-31T23:59:59.999999999Z",
            "-262143-01-01T00:00:00Z",
            "2016-12-31T23:59:60.500Z",
        ] {
            let json = format!("\"{s}\"");
            let t: UtcDateTime = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(serde_json::to_string(&t).unwrap(), json, "{s}");
        }
    }

    /// chrono re-rendered every accepted spelling in its one form.
    #[test]
    fn serde_normalizes_as_chrono_did() {
        for (input, out) in [
            ("2026-11-21T09:26:15.000Z", "2026-11-21T09:26:15Z"),
            ("2026-11-21T09:26:15.250000Z", "2026-11-21T09:26:15.250Z"),
            (
                "2026-11-21T09:26:15.1234567Z",
                "2026-11-21T09:26:15.123456700Z",
            ),
            (
                "2026-11-21T09:26:15.1234567891234Z",
                "2026-11-21T09:26:15.123456789Z",
            ),
            ("2026-11-21T09:26:15+00:00", "2026-11-21T09:26:15Z"),
            ("2027-08-19T00:00:00+02:00", "2027-08-18T22:00:00Z"),
            ("2027-08-19T00:00:00-05:30", "2027-08-19T05:30:00Z"),
            ("2027-08-19T00:00:00\u{2212}05:30", "2027-08-19T05:30:00Z"),
            ("2027-08-19t00:00:00z", "2027-08-19T00:00:00Z"),
            ("2027-08-19 00:00:00Z", "2027-08-19T00:00:00Z"),
            // relaxed-only spellings
            ("2027-08-19T00:00:00+0200", "2027-08-18T22:00:00Z"),
            ("2027-08-19T00:00:00 UTC", "2027-08-19T00:00:00Z"),
            ("  2027 - 8 - 9T 1: 2 : 3 utc  ", "2027-08-09T01:02:03Z"),
            ("27-08-19T00:00:00Z", "0027-08-19T00:00:00Z"),
            ("+2027-08-19T00:00:00Z", "2027-08-19T00:00:00Z"),
            ("2016-12-31T23:59:60Z", "2016-12-31T23:59:60Z"),
            ("2016-12-31T12:30:60.25+01:00", "2016-12-31T11:30:60.250Z"),
        ] {
            assert_eq!(relaxed(input).as_deref(), Some(out), "{input:?}");
        }
    }

    #[test]
    fn strict_accepts_what_chrono_did() {
        for (input, out) in [
            ("2026-11-21T09:26:15Z", Some("2026-11-21T09:26:15Z")),
            ("2026-11-21t09:26:15z", Some("2026-11-21T09:26:15Z")),
            ("2026-11-21 09:26:15Z", Some("2026-11-21T09:26:15Z")),
            (
                "2026-11-21T09:26:15.5+23:59",
                Some("2026-11-20T09:27:15.500Z"),
            ),
            (
                "2026-11-21T09:26:15\u{2212}01:00",
                Some("2026-11-21T10:26:15Z"),
            ),
            ("2026-11-21T09:26:60Z", Some("2026-11-21T09:26:60Z")),
            ("2024-02-29T00:00:00Z", Some("2024-02-29T00:00:00Z")),
            // refused
            ("2026-11-21T09:26:15+0100", None),
            ("2026-11-21T09:26:15 UTC", None),
            ("2026-11-21T09:26:15", None),
            ("2026-11-21T09:26:15.Z", None),
            ("2026-11-21T09:26:15Z ", None),
            (" 2026-11-21T09:26:15Z", None),
            ("2026-11-21T09:26:15+24:00", None),
            ("2026-11-21T09:26:15+01:60", None),
            ("2026-11-21T24:00:00Z", None),
            ("2026-11-21T09:26:61Z", None),
            ("2023-02-29T00:00:00Z", None),
            ("2026-13-01T00:00:00Z", None),
            ("2026-00-01T00:00:00Z", None),
            ("2026-1-21T09:26:15Z", None),
            ("+2026-11-21T09:26:15Z", None),
            ("sha256:2026-11-21T09:26:15Z", None),
        ] {
            assert_eq!(strict(input).as_deref(), out, "{input:?}");
        }
    }

    #[test]
    fn relaxed_refuses_what_chrono_did() {
        for input in [
            "2026-11-21T09:26:15",
            "2026-11-21",
            "2026-11-21T09:26:15Zx",
            "2026-11-21T09:26:15+24:00",
            "2026-11-21T09:26:15+01",
            "2026-11-21T09:26:15+01:6",
            "20261-11-21T09:26:15Z",
            "2026-111-21T09:26:15Z",
            "2026-11-21X09:26:15Z",
            "2026-11-21T09:26:15 .5Z",
            "+262143-01-01T00:00:00Z",
            "+262142-12-31T23:59:59-01:00",
            "",
        ] {
            assert_eq!(relaxed(input), None, "{input:?}");
        }
    }

    #[test]
    fn rfc3339_forms() {
        let t = UtcDateTime::from_timestamp(1_700_000_000, 12_345).unwrap();
        assert_eq!(t.to_rfc3339(), "2023-11-14T22:13:20.000012345+00:00");
        assert_eq!(
            t.to_rfc3339_opts(SecondsFormat::Millis, true),
            "2023-11-14T22:13:20.000Z"
        );
        assert_eq!(
            t.to_rfc3339_opts(SecondsFormat::Micros, true),
            "2023-11-14T22:13:20.000012Z"
        );
        assert_eq!(
            t.to_rfc3339_opts(SecondsFormat::Secs, false),
            "2023-11-14T22:13:20+00:00"
        );
        assert_eq!(t.to_string(), "2023-11-14 22:13:20.000012345 UTC");
        assert_eq!(
            UtcDateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .to_string(),
            "2023-11-14 22:13:20 UTC"
        );
    }

    #[test]
    fn timestamps_and_ranges() {
        let t = UtcDateTime::parse_from_rfc3339("2016-12-31T23:59:60.5Z").unwrap();
        assert_eq!(t.timestamp(), 1_483_228_799);
        assert_eq!(t.timestamp_subsec_nanos(), 1_500_000_000);
        assert_eq!(t.timestamp_millis(), 1_483_228_800_500);
        assert_eq!(UtcDateTime::from_timestamp(1_483_228_798, NANOS), None);
        assert_eq!(UtcDateTime::from_timestamp(0, 2 * NANOS), None);
        assert_eq!(
            UtcDateTime::MIN.to_rfc3339(),
            "-262143-01-01T00:00:00+00:00"
        );
        assert_eq!(
            UtcDateTime::MAX.to_rfc3339(),
            "+262142-12-31T23:59:59.999999999+00:00"
        );
        assert_eq!(UtcDateTime::from_timestamp(MAX_SECS + 1, 0), None);
        assert_eq!(UtcDateTime::from_timestamp(MIN_SECS - 1, 0), None);
        assert_eq!(UtcDateTime::MAX.checked_add_secs(1), None);
        assert_eq!(
            UtcDateTime::from_timestamp_millis(-1).unwrap().to_rfc3339(),
            "1969-12-31T23:59:59.999+00:00"
        );
        // Leap second arithmetic, as chrono: forwards from `:59`.
        assert_eq!(
            format!("{:?}", t.checked_add_secs(1).unwrap()),
            "2017-01-01T00:00:00.500Z"
        );
        // chrono counts the leap second only when both instants' times of
        // day are ordered like the instants (its `signed_duration_since`).
        let leap = UtcDateTime::parse_from_rfc3339("2016-12-31T12:30:60.5Z").unwrap();
        let after = UtcDateTime::parse_from_rfc3339("2016-12-31T12:31:01Z").unwrap();
        assert_eq!(after.signed_nanos_since(&leap), 1_500_000_000);
        assert_eq!(leap.signed_nanos_since(&after), -1_500_000_000);
        let next_day = UtcDateTime::parse_from_rfc3339("2017-01-01T00:00:01Z").unwrap();
        assert_eq!(next_day.signed_nanos_since(&t), 500_000_000);
    }

    /// Every civil day in a wide window converts both ways.
    #[test]
    fn calendar_round_trips() {
        for days in -800_000..800_000i64 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(date_days(y, m, d), Ok(days));
        }
    }
}
