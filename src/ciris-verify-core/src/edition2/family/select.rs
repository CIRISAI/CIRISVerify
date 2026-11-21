//! The family model's selector arms, read by one rule: a port of
//! CIRISConstitution's reference evaluator `tools/cc_family_select.py`
//! (rc20 e08bf05; unchanged at v1.0-rc20 d4bd2a6).
//!
//! The port follows the Python, not the prose. It replays CC's
//! `manifests/family_select_vectors.json` (`tests/family_select_vectors.rs`).
//!
//! - an arm is `*` or tests joined by ` & `; a test is `key=v1|v2|...` on one
//!   of `leaf`, `verb`, `identity`, `group`, `seats`, `act`;
//! - `count` and `authorship` arms are read in order and the first whose tests
//!   all hold decides; `second_signers` entries are read each on its own, an
//!   entry with no `when` always applying;
//! - `leaf` is bound from the row's dimension under the cell's own family
//!   ([`crate::namespace_match::bind_leaf`]); a `{name}` segment of a selector
//!   value matches any one leaf segment, and the leaf and the value have the
//!   same number of segments;
//! - `verb`, `identity`, `group`, `seats` and `act` are supplied by the caller
//!   ([`SelectContext`]); no sentence of CC maps a row's members to them;
//! - a test on a key that is not supplied is unknown. An arm is false when any
//!   test is false, else unknown when any is unknown, else it holds. An unknown
//!   arm before the deciding arm makes the answer unknown; one after it changes
//!   nothing;
//! - a cell whose arms all read false answers null ([`Select::Null`]); a cell
//!   the model marks `gap` answers [`Select::Gap`]; a cell with no arms answers
//!   its own value.
//!
//! Pure: no clock, no I/O, `no_std` + `alloc`.

use crate::prelude::*;

/// The selector keys, in the reference's `KEYS` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    /// Bound from the dimension under the cell's family.
    Leaf,
    /// The row's verb (caller-supplied).
    Verb,
    /// The `identity_type` set of the identity the row concerns (caller-supplied).
    Identity,
    /// The `cohort_scope` of the group the row is about (caller-supplied).
    Group,
    /// The group's deciding-seat count at the head the row names (caller-supplied).
    Seats,
    /// How the row is signed (caller-supplied).
    Act,
}

impl Key {
    /// Every key, in the reference's order.
    pub const ALL: [Key; 6] = [
        Key::Leaf,
        Key::Verb,
        Key::Identity,
        Key::Group,
        Key::Seats,
        Key::Act,
    ];

    /// The key as a selector writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Key::Leaf => "leaf",
            Key::Verb => "verb",
            Key::Identity => "identity",
            Key::Group => "group",
            Key::Seats => "seats",
            Key::Act => "act",
        }
    }

    /// The key a selector names, if it is one.
    #[must_use]
    pub fn parse(s: &str) -> Option<Key> {
        Key::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// The `cohort_scope` of a group (CC 4.4.3.12): the reference's `GROUP_VALUES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// `family`.
    Family,
    /// `community`.
    Community,
    /// `affiliations`.
    Affiliations,
}

impl Group {
    /// The value as a selector writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Family => "family",
            Group::Community => "community",
            Group::Affiliations => "affiliations",
        }
    }

    /// The group a selector value names, if it is one.
    #[must_use]
    pub fn parse(s: &str) -> Option<Group> {
        [Group::Family, Group::Community, Group::Affiliations]
            .into_iter()
            .find(|g| g.as_str() == s)
    }
}

/// How a row is signed: the reference's `ACT_VALUES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    /// The act of a roster under its consensus_protocol, several statements
    /// over one payload (CC 2.6.1.9).
    Group,
    /// One signer's own row.
    Own,
}

impl Act {
    /// The value as a selector writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Act::Group => "group",
            Act::Own => "own",
        }
    }

    /// The act a selector value names, if it is one.
    #[must_use]
    pub fn parse(s: &str) -> Option<Act> {
        [Act::Group, Act::Own].into_iter().find(|a| a.as_str() == s)
    }
}

/// The seat-count tokens a `seats` test may name, and their counts.
pub const SEATS_TOKENS: &[(&str, u64)] = &[("one", 1)];

/// The keys a caller supplies. A `None` is not supplied: a test on it reads
/// unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectContext {
    /// The row's verb, one of the family model's verbs (`attest`, `authorize`,
    /// `replace`, `withdraw`, `recant`).
    pub verb: Option<String>,
    /// The `identity_type` set of the identity the row concerns (CC 3.1.3), read
    /// from a held key record; a test holds when the set contains a value.
    pub identity: Option<Vec<String>>,
    /// The `cohort_scope` of the group the row is about, from its record.
    pub group: Option<Group>,
    /// The group's deciding-seat count at the head the row names.
    pub seats: Option<u64>,
    /// How the row is signed, read from its statements and the roster they
    /// are counted over. Never a payload member: the family check derives it
    /// when this is `None` (`own` for a statement of a row with an author,
    /// `group` for the statements of one counted row read together; see
    /// `edition2::family`). A supplied value overrides the derivation.
    pub act: Option<Act>,
    /// For a composer (`withdraws` / `recants`), the row it
    /// names in `refs.target`, held by the caller: the composer's leaf is the
    /// target's. Ignored for any other row.
    pub target: Option<super::TargetRow>,
}

/// One test: `key=v1|v2|...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Test {
    /// The key tested.
    pub key: Key,
    /// The values, any of which holds.
    pub values: Vec<String>,
}

/// A selector: `*` (no tests) or tests joined by ` & `.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    /// The tests; empty for `*`.
    pub tests: Vec<Test>,
}

/// A selector the grammar does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorError {
    /// The test that does not read.
    pub test: String,
}

/// `[a-z]+`.
fn is_key_shape(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase())
}

/// `[a-z_:{}]+`.
fn is_value_shape(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || matches!(b, b'_' | b':' | b'{' | b'}'))
}

impl Selector {
    /// Parse a selector: the reference's `parse_selector`.
    ///
    /// # Errors
    /// [`SelectorError`] names a test that is not `key=v1|v2|...` on one of
    /// the six keys, a `seats` value that is not a seat token, or a `group` /
    /// `act` value outside its vocabulary.
    pub fn parse(sel: &str) -> Result<Selector, SelectorError> {
        if sel == "*" {
            return Ok(Selector { tests: Vec::new() });
        }
        let mut tests = Vec::new();
        for t in sel.split(" & ") {
            let err = || SelectorError { test: t.to_owned() };
            let (k, vs) = t.split_once('=').ok_or_else(err)?;
            if !is_key_shape(k) {
                return Err(err());
            }
            let values: Vec<&str> = vs.split('|').collect();
            if !values.iter().all(|v| is_value_shape(v)) {
                return Err(err());
            }
            let key = Key::parse(k).ok_or_else(err)?;
            let in_vocab = |v: &&str| match key {
                Key::Seats => SEATS_TOKENS.iter().any(|(tok, _)| tok == v),
                Key::Group => Group::parse(v).is_some(),
                Key::Act => Act::parse(v).is_some(),
                _ => true,
            };
            if !values.iter().all(in_vocab) {
                return Err(err());
            }
            tests.push(Test {
                key,
                values: values.into_iter().map(str::to_owned).collect(),
            });
        }
        Ok(Selector { tests })
    }

    /// Does the arm hold? `Some(true)`, `Some(false)`, or `None` (unknown):
    /// false if any test is false, else unknown if any is unknown.
    #[must_use]
    pub fn holds(&self, leaf: Option<&str>, ctx: &SelectContext) -> Option<bool> {
        let mut unknown = false;
        for t in &self.tests {
            match test_holds(t, leaf, ctx) {
                Some(false) => return Some(false),
                None => unknown = true,
                Some(true) => {},
            }
        }
        if unknown {
            None
        } else {
            Some(true)
        }
    }

    /// The keys the selector tests.
    pub fn keys(&self) -> impl Iterator<Item = Key> + '_ {
        self.tests.iter().map(|t| t.key)
    }
}

/// `value` names `leaf`: the same segment count, each segment equal or a
/// `{name}` wildcard (the reference's `leaf_holds`).
#[must_use]
pub fn leaf_holds(leaf: &str, value: &str) -> bool {
    let a: Vec<&str> = if leaf.is_empty() {
        Vec::new()
    } else {
        leaf.split(':').collect()
    };
    let b: Vec<&str> = value.split(':').collect();
    a.len() == b.len()
        && a.iter()
            .zip(&b)
            .all(|(x, y)| y == x || (y.starts_with('{') && y.ends_with('}')))
}

/// One test against a row: `None` when its key is not supplied.
fn test_holds(t: &Test, leaf: Option<&str>, ctx: &SelectContext) -> Option<bool> {
    let any = |f: &dyn Fn(&str) -> bool| t.values.iter().any(|v| f(v));
    Some(match t.key {
        Key::Leaf => {
            let l = leaf?;
            any(&|v| leaf_holds(l, v))
        },
        Key::Verb => {
            let got = ctx.verb.as_deref()?;
            any(&|v| v == got)
        },
        Key::Identity => {
            let got = ctx.identity.as_ref()?;
            any(&|v| got.iter().any(|g| g == v))
        },
        Key::Group => {
            let got = ctx.group?.as_str();
            any(&|v| v == got)
        },
        Key::Seats => {
            let got = ctx.seats?;
            any(&|v| SEATS_TOKENS.iter().any(|(tok, n)| *tok == v && *n == got))
        },
        Key::Act => {
            let got = ctx.act?.as_str();
            any(&|v| v == got)
        },
    })
}

/// One arm: a selector and the value it gives (a count's doors, `authored` or
/// `counted`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm {
    /// The selector as written.
    pub when: String,
    /// The selector, parsed.
    pub selector: Selector,
    /// The value the arm gives.
    pub value: String,
}

impl Arm {
    /// An arm from its selector text and value.
    ///
    /// # Errors
    /// [`SelectorError`] when the selector does not read.
    pub fn new(when: &str, value: &str) -> Result<Arm, SelectorError> {
        Ok(Arm {
            when: when.to_owned(),
            selector: Selector::parse(when)?,
            value: value.to_owned(),
        })
    }
}

/// Parse a cell's text, `selector => value` arms joined by ` ; ` with the last
/// `*` arm written as its bare value (how CC's `build_family_model.py` writes
/// the `value` of a cell with arms).
///
/// # Errors
/// [`SelectorError`] when an arm's selector does not read.
pub fn parse_cell(text: &str) -> Result<Vec<Arm>, SelectorError> {
    text.split(" ; ")
        .map(|part| match part.split_once(" => ") {
            Some((when, value)) => Arm::new(when, value),
            None => Arm::new("*", part),
        })
        .collect()
}

/// Which arm decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The index of the deciding arm.
    Arm(usize),
    /// An unknown arm comes before any arm that holds.
    Unknown,
    /// Every arm reads false.
    Null,
}

/// The deciding arm (the reference's `decide`).
#[must_use]
pub fn decide(arms: &[Arm], leaf: Option<&str>, ctx: &SelectContext) -> Decision {
    for (i, arm) in arms.iter().enumerate() {
        match arm.selector.holds(leaf, ctx) {
            None => return Decision::Unknown,
            Some(true) => return Decision::Arm(i),
            Some(false) => {},
        }
    }
    Decision::Null
}

/// A cell's answer for a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Select {
    /// The deciding arm's value, or the value of a cell with no arms:
    /// `authored`, `counted`, or a count's doors.
    Value(String),
    /// An arm before the decider is unknown.
    Unknown,
    /// Every arm reads false: the cell gives no answer for this row.
    Null,
    /// The model marks the cell `gap`.
    Gap,
}

/// The deciding arm's value (the reference's `evaluate`).
#[must_use]
pub fn evaluate(arms: &[Arm], leaf: Option<&str>, ctx: &SelectContext) -> Select {
    match decide(arms, leaf, ctx) {
        Decision::Arm(i) => Select::Value(arms[i].value.clone()),
        Decision::Unknown => Select::Unknown,
        Decision::Null => Select::Null,
    }
}

/// A `count` or `authorship` cell as the model states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// The cell's value (its text when it has arms); `None` for a null value.
    pub value: Option<String>,
    /// The cell's source tag (`cc-table`, `generic`, `gap`, ...).
    pub source: String,
    /// The arms, when the cell is written as arms.
    pub arms: Vec<Arm>,
}

impl Cell {
    /// The cell's answer and the deciding arm (the reference's `cell_answer`
    /// for a `count` or `authorship` cell).
    #[must_use]
    pub fn answer(&self, leaf: Option<&str>, ctx: &SelectContext) -> (Select, Option<Decision>) {
        if self.source == "gap" {
            return (Select::Gap, None);
        }
        if self.arms.is_empty() {
            return (self.value.clone().map_or(Select::Null, Select::Value), None);
        }
        let d = decide(&self.arms, leaf, ctx);
        let s = match d {
            Decision::Arm(i) => Select::Value(self.arms[i].value.clone()),
            Decision::Unknown => Select::Unknown,
            Decision::Null => Select::Null,
        };
        (s, Some(d))
    }
}

/// One `second_signers` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondSigner {
    /// The role.
    pub role: String,
    /// The payload member that names the party, `sub`, or `gap`.
    pub member: String,
    /// The condition; `None` always applies.
    pub when: Option<Selector>,
}

/// The `second_signers` answer for a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signers<'a> {
    /// The entries whose `when` holds (or that have none), in order.
    Roles(Vec<&'a SecondSigner>),
    /// Some entry's `when` is unknown: the reference answers `unknown` for the
    /// whole cell.
    Unknown,
}

/// The entries that apply to a row (the reference's `second_signers`).
#[must_use]
pub fn second_signers<'a>(
    entries: &'a [SecondSigner],
    leaf: Option<&str>,
    ctx: &SelectContext,
) -> Signers<'a> {
    let mut out = Vec::new();
    for e in entries {
        let h = e.when.as_ref().map_or(Some(true), |w| w.holds(leaf, ctx));
        match h {
            None => return Signers::Unknown,
            Some(true) => out.push(e),
            Some(false) => {},
        }
    }
    Signers::Roles(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SelectContext {
        SelectContext::default()
    }

    #[test]
    fn grammar() {
        assert!(Selector::parse("*").unwrap().tests.is_empty());
        let s = Selector::parse("leaf=removal & group=affiliations & seats=one").unwrap();
        assert_eq!(
            s.keys().collect::<Vec<_>>(),
            [Key::Leaf, Key::Group, Key::Seats]
        );
        // The reference's deliberate parser breaks.
        for bad in [
            "kind=x",
            "seats=two",
            "group=club",
            "act=club",
            "leaf=",
            "leaf=A",
            "leaf=a&verb=b",
            "",
            "leaf=a=b",
        ] {
            assert!(Selector::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn kleene_and_order() {
        assert!(parse_cell("kind=x => y ; z").is_err());
        let arms = parse_cell("leaf=removal & group=affiliations => x ; y").unwrap();
        // A false test beats an unknown one: the next arm is read.
        assert_eq!(
            evaluate(&arms, Some("widening"), &ctx()),
            Select::Value("y".into())
        );
        // Unknown before the decider.
        assert_eq!(evaluate(&arms, Some("removal"), &ctx()), Select::Unknown);
        let c = SelectContext {
            group: Some(Group::Affiliations),
            ..ctx()
        };
        assert_eq!(
            evaluate(&arms, Some("removal"), &c),
            Select::Value("x".into())
        );
        // Every arm false.
        let only = parse_cell("leaf=reported => m").unwrap();
        assert_eq!(evaluate(&only, Some("other"), &ctx()), Select::Null);
        // `{name}` matches one segment.
        assert!(leaf_holds("lifecycle:confirmed", "lifecycle:{kind}"));
        assert!(!leaf_holds("lifecycle", "lifecycle:{kind}"));
        assert!(!leaf_holds("", "x"));
    }
}
