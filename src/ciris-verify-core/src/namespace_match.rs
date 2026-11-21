//! The CC dimension-grammar matcher (CC 3.1.7 R3): a wire `dimension` resolved
//! to the registry family that claims it.
//!
//! This is a port of CIRISConstitution's one reference matcher,
//! `tools/cc_namespace_match.py`, read against the registry it ships,
//! `manifests/namespace_registry.json`. The port follows the Python's logic, not
//! the prose around it, and replays `manifests/namespace_match_vectors.json`
//! (`tests/namespace_match_vectors.rs`) so a drift fails the build.
//!
//! The grammar is data: the vocab and version patterns, the refusal tokens, the
//! exempt families, the reserved stems and the private-use prefix are all read
//! from the vendored registry; nothing here restates them.
//!
//! - segments split on `:` and compare byte-exactly (never case-folded);
//! - `literal` equals the row's stem; `vocab` matches the vocab pattern and, for a
//!   closed enumeration, one of its values; `hex` is lowercase hex; `external` and
//!   `value` are verbatim unless the row pins a pattern;
//! - a `multi` placeholder spans one or more segments; a trailing `*` is variadic;
//! - one trailing version segment follows the family's own segments (a row ending
//!   in `{version}` names it); exempt families need none;
//! - a closed family admits only its listed leaves;
//! - the most specific match wins: most literal segments, then a non-wildcard
//!   over a wildcard, then more segments.
//!
//! Every pattern is applied whole-segment (Python `re.fullmatch`).
//!
//! # Vendored registry
//!
//! `data/cc/namespace_registry.json` is CIRISConstitution rc22 (branch) at commit
//! v1.0-rc22-pre2 `bab3653`, SHA-256
//! `054ed9efc3c3f88dbe89f53453bdd43905b95592273d0e30742cf157389927bb`
//! (`data/cc/README.md`).

use crate::prelude::*;

use once_cell::race::OnceBox;
use regex::Regex;
use serde::Deserialize;

/// The vendored CC namespace registry (`manifests/namespace_registry.json`).
pub const NAMESPACE_REGISTRY_JSON: &str = include_str!("../data/cc/namespace_registry.json");

/// The CIRISConstitution commit the vendored registry was taken from.
pub const NAMESPACE_REGISTRY_CC_COMMIT: &str = "bab36531a36473d8c29f9c4023cbe821ae16311d";

/// SHA-256 (lowercase hex) of the vendored registry file, LF line endings.
pub const NAMESPACE_REGISTRY_SHA256: &str =
    "054ed9efc3c3f88dbe89f53453bdd43905b95592273d0e30742cf157389927bb";

/// A dimension resolved without refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// A registered family claims the dimension.
    Family {
        /// The family's registry `prefix` (e.g. `accord:lifecycle:{kind}`).
        prefix: &'static str,
        /// The family id: `prefix` with `{name}` written `.name` and `*` written `.`.
        family_id: String,
        /// Placeholder values by name; `*` binds a wildcard tail and `version`
        /// the trailing version segment.
        binds: BTreeMap<String, String>,
    },
    /// No row claims the dimension and no rule refuses it: CC's open vocabulary.
    OpenVocabulary,
}

/// A dimension the grammar refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The family the reference attributes the refusal to, where it names one.
    pub family: Option<&'static str>,
    /// The manifest's refusal token (`_meta.case_rule.refusal_tokens`).
    pub token: &'static str,
}

/// The reference's raw answer: `(family, binds, refusal)`, as
/// `cc_namespace_match.match_family` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The matched (or attributed) family prefix.
    pub family: Option<&'static str>,
    /// Placeholder values by name.
    pub binds: BTreeMap<String, String>,
    /// The refusal token, if any.
    pub refusal: Option<&'static str>,
}

/// The family id of a registry prefix: each `{name}` segment written `.name` and
/// each `*` written `.`; literal segments are kept.
///
/// `accord:lifecycle:{kind}` → `accord:lifecycle:.kind`; `accord:*` → `accord:.`.
pub fn family_id(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len());
    for (i, seg) in prefix.split(':').enumerate() {
        if i > 0 {
            out.push(':');
        }
        if seg == "*" {
            out.push('.');
        } else if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            out.push('.');
            out.push_str(name);
        } else {
            out.push_str(seg);
        }
    }
    out
}

/// Resolve a wire dimension to its registered family.
///
/// `Ok(Resolved::Family)` names the family, its id and the binds;
/// `Ok(Resolved::OpenVocabulary)` means no row claims it and nothing refuses it;
/// Is `id` the family id (CC 2.6: `{name}` written `.name`, `*` written `.`)
/// of a family the registry registers? A row's header -70002 must be one.
#[must_use]
pub fn is_registered_family_id(id: &str) -> bool {
    rules().families.iter().any(|f| family_id(&f.prefix) == id)
}

/// `Err(Refusal)` carries the manifest's refusal token.
pub fn resolve(dimension: &str) -> Result<Resolved, Refusal> {
    let m = match_family(dimension);
    if let Some(token) = m.refusal {
        return Err(Refusal {
            family: m.family,
            token,
        });
    }
    Ok(match m.family {
        Some(prefix) => Resolved::Family {
            prefix,
            family_id: family_id(prefix),
            binds: m.binds,
        },
        None => Resolved::OpenVocabulary,
    })
}

/// The reference matcher's answer for `dimension`, exactly as
/// `cc_namespace_match.match_family` gives it.
pub fn match_family(dimension: &str) -> Match {
    rules().match_family(dimension)
}

/// The registry prefix of a family id (the inverse of [`family_id`]), if the
/// registry registers it.
#[must_use]
pub fn prefix_of_family_id(id: &str) -> Option<&'static str> {
    rules()
        .families
        .iter()
        .find(|f| family_id(&f.prefix) == id)
        .map(|f| f.prefix.as_str())
}

/// A dimension's leaf, bound under a family named by a selector cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundLeaf {
    /// The values bound to the family's non-literal segments, in segment
    /// order, joined by `:`, the version segment left out.
    pub leaf: String,
    /// The family the matcher itself resolves the dimension to (it may be a
    /// more specific one than the family the leaf is bound under).
    pub matcher_family: Option<&'static str>,
}

/// Why a dimension binds no leaf under a family.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafError {
    /// The matcher refuses the dimension (the manifest's refusal token).
    Refused(&'static str),
    /// The family prefix is not registered.
    UnregisteredFamily,
    /// The dimension does not instantiate the family.
    NotAnInstance,
}

/// Bind the leaf of `dimension` under the family whose registry prefix is
/// `family_prefix`: the port of `cc_family_select.Registry.bind_leaf`.
///
/// The dimension must pass the matcher (whatever family it resolves to), and
/// its segments must instantiate `family_prefix`, a trailing version segment
/// stripped unless the family ends in `{version}`. Under `accord:*` the
/// dimension `accord:lifecycle:confirmed:v1` has the leaf `lifecycle:confirmed`.
///
/// # Errors
/// [`LeafError`].
pub fn bind_leaf(family_prefix: &str, dimension: &str) -> Result<BoundLeaf, LeafError> {
    let r = rules();
    let m = r.match_family(dimension);
    if let Some(token) = m.refusal {
        return Err(LeafError::Refused(token));
    }
    let fam = r
        .by_prefix
        .get(family_prefix)
        .map(|&i| &r.families[i])
        .ok_or(LeafError::UnregisteredFamily)?;
    let mut parts: Vec<&str> = dimension.split(':').collect();
    let ends_version = fam.last().segment == "{version}";
    if !ends_version && parts.len() > 1 && r.version.is_match(parts[parts.len() - 1]) {
        parts.pop();
    }
    match r.match_segments_ordered(&fam.segments, &parts) {
        Some((binds, None)) => Ok(BoundLeaf {
            leaf: binds
                .iter()
                .filter(|(k, _)| k != "version")
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
                .join(":"),
            matcher_family: m.family,
        }),
        _ => Err(LeafError::NotAnInstance),
    }
}

// ---- the grammar, read from the manifest --------------------------------------

#[derive(Deserialize)]
struct RawManifest {
    #[serde(rename = "_meta")]
    meta: RawMeta,
    families: Vec<RawFamily>,
}

#[derive(Deserialize)]
struct RawMeta {
    case_rule: RawCaseRule,
    private_use_prefix: String,
}

#[derive(Deserialize)]
struct RawCaseRule {
    vocab_pattern: String,
    version_segment: RawVersionSegment,
    refusal_tokens: BTreeMap<String, String>,
    #[serde(default)]
    external_standards: BTreeMap<String, RawExternal>,
    #[serde(default)]
    reserved_stems: Vec<RawReservedStem>,
}

#[derive(Deserialize)]
struct RawVersionSegment {
    pattern: String,
    #[serde(default)]
    required: Option<bool>,
    #[serde(default)]
    exempt: Vec<String>,
}

#[derive(Deserialize)]
struct RawExternal {
    #[serde(default)]
    pattern: Option<String>,
}

#[derive(Deserialize)]
struct RawReservedStem {
    stem: String,
}

#[derive(Deserialize)]
struct RawFamily {
    prefix: String,
    segments: Vec<RawSegment>,
    #[serde(default)]
    leaves_closed: Option<bool>,
    #[serde(default)]
    leaves: Vec<String>,
}

#[derive(Deserialize)]
struct RawSegment {
    class: String,
    segment: String,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    values: Option<Vec<String>>,
    #[serde(default)]
    open: Option<bool>,
    #[serde(default)]
    multi: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Literal,
    Wildcard,
    Vocab,
    Hex,
    External,
    /// `value`, and any class the reference does not name (its default branch).
    Value,
}

struct Segment {
    class: Class,
    /// The segment as written (`{kind}`, `accord`, `*`).
    segment: String,
    /// `segment` with `{` / `}` stripped from both ends.
    name: String,
    pattern: Option<Regex>,
    /// A non-empty enumeration (the reference tests `values` for truth).
    values: Option<Vec<String>>,
    open: bool,
    multi: bool,
}

struct Family {
    prefix: String,
    segments: Vec<Segment>,
    leaves_closed: bool,
    leaves: Vec<String>,
}

struct Tokens {
    case_malformed: String,
    vocab_value_unregistered: String,
    family_unregistered: String,
    missing_version_segment: String,
    private_use_not_federatable: String,
}

struct Rules {
    vocab: Regex,
    version: Regex,
    hex: Regex,
    version_like: Regex,
    version_attempt: Regex,
    private: String,
    version_required: bool,
    exempt: BTreeSet<String>,
    tokens: Tokens,
    external: BTreeMap<String, Regex>,
    reserved_stems: Vec<String>,
    /// Families in manifest order (the reference's `OrderedDict`).
    families: Vec<Family>,
    by_prefix: BTreeMap<String, usize>,
    closed_stems: Vec<String>,
}

/// The reference's `HEX_PATTERN`.
const HEX_PATTERN: &str = r"^[0-9a-f]+$";
/// The reference's `VERSION_LIKE`: a version tail in either case.
const VERSION_LIKE: &str = r"^[vV][0-9]+(\.[0-9]+)*$";
/// The reference's `VERSION_ATTEMPT`: a last segment that starts like a version.
const VERSION_ATTEMPT: &str = r"^[vV][0-9][0-9A-Za-z_.\-]*$";

/// Compile `pattern` for whole-segment matching (Python `re.fullmatch`).
fn full(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(&format!("^(?:{pattern})$"))
}

/// `str.strip()`'s whitespace: Rust's `White_Space` plus the four information
/// separators U+001C..U+001F, which Python's `str.isspace` also counts.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn rules() -> &'static Rules {
    static RULES: OnceBox<Rules> = OnceBox::new();
    RULES.get_or_init(|| {
        // The registry is a compile-time asset whose load is exercised by the
        // vector test; the same bytes through the same parser cannot fail later.
        Box::new(Rules::load(NAMESPACE_REGISTRY_JSON).expect("vendored CC namespace registry"))
    })
}

/// `(family index, binds, refusal, has_version)`: the reference's `_resolve` hit.
type Hit = (usize, BTreeMap<String, String>, Option<&'static str>, bool);

/// A scored [`Hit`]: the reference's candidate tuple.
type Candidate = (
    (usize, u8, usize),
    usize,
    BTreeMap<String, String>,
    Option<&'static str>,
    bool,
);

impl Rules {
    fn load(json: &str) -> Result<Rules, String> {
        let raw: RawManifest = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let cr = raw.meta.case_rule;
        let re = |p: &str| full(p).map_err(|e| format!("{p}: {e}"));
        let token = |k: &str| -> Result<String, String> {
            cr.refusal_tokens
                .get(k)
                .cloned()
                .ok_or_else(|| format!("refusal token {k} missing"))
        };
        let tokens = Tokens {
            case_malformed: token("case_malformed")?,
            vocab_value_unregistered: token("vocab_value_unregistered")?,
            family_unregistered: token("family_unregistered")?,
            missing_version_segment: token("missing_version_segment")?,
            private_use_not_federatable: token("private_use_not_federatable")?,
        };
        let mut external = BTreeMap::new();
        for (name, spec) in &cr.external_standards {
            if let Some(p) = spec.pattern.as_deref().filter(|p| !p.is_empty()) {
                external.insert(name.clone(), re(p)?);
            }
        }
        let mut families: Vec<Family> = Vec::new();
        let mut by_prefix = BTreeMap::new();
        for f in raw.families {
            if f.segments.is_empty() {
                return Err(format!("family {} has no segments", f.prefix));
            }
            let mut segments = Vec::with_capacity(f.segments.len());
            for s in f.segments {
                let class = match s.class.as_str() {
                    "literal" => Class::Literal,
                    "wildcard" => Class::Wildcard,
                    "vocab" => Class::Vocab,
                    "hex" => Class::Hex,
                    "external" => Class::External,
                    _ => Class::Value,
                };
                let pattern = match s.pattern.as_deref().filter(|p| !p.is_empty()) {
                    Some(p) => Some(re(p)?),
                    None => None,
                };
                let name = s.segment.trim_matches(|c| c == '{' || c == '}').to_owned();
                segments.push(Segment {
                    class,
                    segment: s.segment,
                    name,
                    pattern,
                    values: s.values.filter(|v| !v.is_empty()),
                    open: s.open.unwrap_or(false),
                    multi: s.multi.unwrap_or(false),
                });
            }
            let fam = Family {
                prefix: f.prefix,
                segments,
                leaves_closed: f.leaves_closed.unwrap_or(false),
                leaves: f.leaves,
            };
            // OrderedDict semantics: a repeated prefix replaces the value in place.
            match by_prefix.get(&fam.prefix) {
                Some(&i) => families[i] = fam,
                None => {
                    by_prefix.insert(fam.prefix.clone(), families.len());
                    families.push(fam);
                },
            }
        }
        // Stems of CLOSED families: an unmatched descendant beneath one is
        // unregistered, never open vocabulary.
        let closed_stems: BTreeSet<String> = families
            .iter()
            .filter(|f| f.leaves_closed)
            .map(|f| {
                if f.last().class == Class::Wildcard {
                    f.prefix[..f.prefix.len() - 1].to_owned()
                } else {
                    format!("{}:", f.prefix.split(':').next().unwrap_or(""))
                }
            })
            .collect();
        let vs = cr.version_segment;
        Ok(Rules {
            vocab: re(&cr.vocab_pattern)?,
            version: re(&vs.pattern)?,
            hex: re(HEX_PATTERN)?,
            version_like: re(VERSION_LIKE)?,
            version_attempt: re(VERSION_ATTEMPT)?,
            private: raw.meta.private_use_prefix,
            version_required: vs.required.unwrap_or(true),
            exempt: vs.exempt.into_iter().collect(),
            tokens,
            external,
            reserved_stems: cr.reserved_stems.into_iter().map(|s| s.stem).collect(),
            families,
            by_prefix,
            closed_stems: closed_stems.into_iter().collect(),
        })
    }

    fn prefix_of(&'static self, i: usize) -> &'static str {
        &self.families[i].prefix
    }

    /// The refusal a single placeholder value earns under its class, or `None`.
    fn check_seg(&'static self, seg: &Segment, got: &str) -> Option<&'static str> {
        let t = &self.tokens;
        if got.is_empty() {
            return Some(t.case_malformed.as_str());
        }
        if seg.segment == "{version}" {
            return if self.version.is_match(got) {
                None
            } else {
                Some(t.case_malformed.as_str())
            };
        }
        match seg.class {
            Class::Vocab => {
                if !self.vocab.is_match(got) {
                    return Some(t.case_malformed.as_str());
                }
                if let Some(values) = &seg.values {
                    if !seg.open && !values.iter().any(|v| v == got) {
                        return Some(t.vocab_value_unregistered.as_str());
                    }
                }
                None
            },
            Class::Hex => {
                let pat = seg.pattern.as_ref().unwrap_or(&self.hex);
                if pat.is_match(got) {
                    None
                } else {
                    Some(t.case_malformed.as_str())
                }
            },
            Class::External => {
                let pat = seg
                    .pattern
                    .as_ref()
                    .or_else(|| self.external.get(&seg.name));
                match pat {
                    Some(p) if !p.is_match(got) => Some(t.case_malformed.as_str()),
                    _ => None,
                }
            },
            // value (and the reference's default branch): verbatim unless pinned
            _ => match &seg.pattern {
                Some(p) if !p.is_match(got) => Some(t.case_malformed.as_str()),
                _ => None,
            },
        }
    }

    /// `(ok, binds, refusal)` for `parts` against one family's `segs`.
    fn match_segments(
        &'static self,
        segs: &[Segment],
        parts: &[&str],
    ) -> Option<(BTreeMap<String, String>, Option<&'static str>)> {
        self.match_segments_ordered(segs, parts)
            .map(|(binds, refusal)| (binds.into_iter().collect(), refusal))
    }

    /// [`Rules::match_segments`] with the binds in the order the reference's
    /// dict holds them: segment order, a repeated name keeping its first place,
    /// the wildcard tail `*` last.
    fn match_segments_ordered(
        &'static self,
        segs: &[Segment],
        parts: &[&str],
    ) -> Option<(OrderedBinds, Option<&'static str>)> {
        let last_seg = segs.last()?;
        let wildcard = last_seg.class == Class::Wildcard;
        let fixed = if wildcard {
            &segs[..segs.len() - 1]
        } else {
            segs
        };
        let multi = fixed.iter().position(|s| s.multi);
        let extra = if wildcard {
            if parts.len() < fixed.len() + 1 {
                return None; // variadic: at least one further segment
            }
            0
        } else if multi.is_some() {
            // the surplus belongs to the multi placeholder
            parts.len().checked_sub(fixed.len())?
        } else if parts.len() != fixed.len() {
            return None;
        } else {
            0
        };
        let mut binds: OrderedBinds = Vec::new();
        let mut refusal: Option<&'static str> = None;
        let mut pi = 0usize;
        for (i, seg) in fixed.iter().enumerate() {
            if multi == Some(i) {
                let span = &parts[pi..pi + 1 + extra];
                pi += 1 + extra;
                for got in span {
                    // every component of a multi-segment value is verbatim: no
                    // version-shape test applies inside the span
                    refusal = refusal.or_else(|| self.check_seg(seg, got));
                }
                put(&mut binds, &seg.name, span.join(":"));
                continue;
            }
            let got = parts[pi];
            pi += 1;
            if seg.class == Class::Literal {
                if seg.segment != got {
                    return None; // not this family at all
                }
                continue;
            }
            refusal = refusal.or_else(|| self.check_seg(seg, got));
            put(&mut binds, &seg.name, got.to_owned());
        }
        let tail = &parts[pi..];
        for (k, got) in tail.iter().enumerate() {
            // a version-like token below a variadic tail is a duplicated or
            // uppercase version tail; a version attempt in last place likewise
            let last = pi + k == parts.len() - 1;
            if got.is_empty()
                || !self.vocab.is_match(got)
                || self.version_like.is_match(got)
                || (last && self.version_attempt.is_match(got))
            {
                refusal = refusal.or(Some(self.tokens.case_malformed.as_str()));
            }
        }
        if !tail.is_empty() {
            put(&mut binds, "*", tail.join(":"));
        }
        Some((binds, refusal))
    }

    /// A last segment shaped like a version tail but not one.
    fn mutated_tail(&'static self, seg: &str) -> bool {
        (self.version_like.is_match(seg) && !self.version.is_match(seg))
            || self.version_attempt.is_match(seg)
    }

    /// Best candidate for `parts`: `(family index, binds, refusal, has_version)`.
    fn resolve_parts(&'static self, parts: &[&str]) -> Option<Hit> {
        let last_part = *parts.last()?;
        let versioned = self.version.is_match(last_part);
        let mut candidates: Vec<Candidate> = Vec::new();
        for (fi, fam) in self.families.iter().enumerate() {
            let score = fam.score();
            let ends_version = fam.last().segment == "{version}";
            if ends_version && !versioned {
                // recognise the family by its other segments (missing tail), and
                // also as written (a malformed tail such as `V1` is then refused)
                let headless = &fam.segments[..fam.segments.len() - 1];
                if let Some((binds, refusal)) = self.match_segments(headless, parts) {
                    candidates.push((score, fi, binds, refusal, false));
                }
                if let Some((binds, refusal)) = self.match_segments(&fam.segments, parts) {
                    candidates.push((score, fi, binds, refusal, true));
                }
            } else if ends_version || !versioned {
                if let Some((binds, mut refusal)) = self.match_segments(&fam.segments, parts) {
                    if !versioned && self.mutated_tail(last_part) {
                        refusal = refusal.or(Some(self.tokens.case_malformed.as_str()));
                    }
                    candidates.push((score, fi, binds, refusal, ends_version));
                }
            } else if parts.len() > 1 {
                // the trailing version segment is the version
                if let Some((binds, refusal)) =
                    self.match_segments(&fam.segments, &parts[..parts.len() - 1])
                {
                    candidates.push((score, fi, binds, refusal, true));
                }
            }
        }
        if candidates.is_empty() && versioned {
            // a version-SHAPED last segment that may be a VALUE (`config:v1`):
            // read it as an unversioned instance so the family is recognised
            for (fi, fam) in self.families.iter().enumerate() {
                if fam.last().segment == "{version}" {
                    continue;
                }
                if let Some((binds, refusal)) = self.match_segments(&fam.segments, parts) {
                    candidates.push((fam.score(), fi, binds, refusal, false));
                }
            }
        }
        // Python's `sort(key=score, reverse=True)` is stable: ties keep order.
        candidates.sort_by_key(|c| core::cmp::Reverse(c.0));
        candidates
            .into_iter()
            .next()
            .map(|(_, fi, binds, refusal, has_version)| (fi, binds, refusal, has_version))
    }

    /// A dimension no row claims may still be a MALFORMED form of a registered
    /// family; fold and strip only to detect, never to admit.
    fn detect_malformed(&'static self, parts: &[&str], clean_only: bool) -> Option<usize> {
        let low_owned: Vec<String> = parts.iter().map(|p| p.to_lowercase()).collect();
        let low: Vec<&str> = low_owned.iter().map(String::as_str).collect();
        let n = parts.len();
        let mut variants: Vec<&[&str]> = Vec::new();
        if low.as_slice() != parts {
            variants.push(&low);
        }
        if n > 1
            && (self.version_like.is_match(parts[n - 1])
                || self.version_attempt.is_match(parts[n - 1]))
        {
            variants.push(&parts[..n - 1]);
            variants.push(&low[..n - 1]);
            if n > 2 && self.version_like.is_match(parts[n - 2]) {
                variants.push(&parts[..n - 2]);
                variants.push(&low[..n - 2]);
            }
        }
        for v in variants {
            if let Some((fi, _, refusal, _)) = self.resolve_parts(v) {
                if refusal.is_none() || !clean_only {
                    return Some(fi);
                }
            }
        }
        None
    }

    fn match_family(&'static self, dimension: &str) -> Match {
        let t = &self.tokens;
        let refuse = |family: Option<&'static str>, token: &'static str| Match {
            family,
            binds: BTreeMap::new(),
            refusal: Some(token),
        };
        if dimension.is_empty() || dimension != dimension.trim_matches(py_space) {
            return refuse(None, t.case_malformed.as_str());
        }
        if dimension.starts_with(self.private.as_str()) {
            return refuse(None, t.private_use_not_federatable.as_str());
        }
        let parts: Vec<&str> = dimension.split(':').collect();
        if parts.iter().any(|p| p.is_empty()) {
            return refuse(None, t.case_malformed.as_str());
        }
        let n = parts.len();
        let Some((fi, binds, refusal, has_version)) = self.resolve_parts(&parts) else {
            if let Some(mutated) = self.detect_malformed(&parts, false) {
                return refuse(Some(self.prefix_of(mutated)), t.case_malformed.as_str());
            }
            // a reserved stem, or the stem of a CLOSED family: an unclaimed leaf
            // beneath it is unregistered, never open vocabulary
            let fenced = || self.reserved_stems.iter().chain(self.closed_stems.iter());
            if fenced().any(|stem| dimension.starts_with(stem.as_str())) {
                return refuse(None, t.family_unregistered.as_str());
            }
            // a case-mutated reserved or closed stem is malformed, never a bypass
            let low = dimension.to_lowercase();
            if low != dimension && fenced().any(|stem| low.starts_with(stem.as_str())) {
                return refuse(None, t.case_malformed.as_str());
            }
            // open vocabulary still owes exactly one trailing version segment
            if self.version_required && !self.version.is_match(parts[n - 1]) {
                if self.mutated_tail(parts[n - 1]) {
                    return refuse(None, t.case_malformed.as_str());
                }
                return refuse(None, t.missing_version_segment.as_str());
            }
            if n >= 2 && self.version_like.is_match(parts[n - 2]) {
                return refuse(None, t.case_malformed.as_str());
            }
            if n < 2 {
                return refuse(None, t.case_malformed.as_str());
            }
            return Match {
                family: None,
                binds: BTreeMap::new(),
                refusal: None,
            };
        };
        let prefix = self.prefix_of(fi);
        let fam = &self.families[fi];
        if let Some(token) = refusal {
            // a refused hit may be a MALFORMED form of a different row that
            // resolves cleanly once folded or stripped: that row is the family
            if let Some(mutated) = self.detect_malformed(&parts, true) {
                if mutated != fi {
                    return refuse(Some(self.prefix_of(mutated)), t.case_malformed.as_str());
                }
            }
            return Match {
                family: Some(prefix),
                binds,
                refusal: Some(token),
            };
        }
        let versioned = self.version.is_match(parts[n - 1]);
        // closed leaves: only the leaves CC names
        if fam.leaves_closed && matches!(fam.last().class, Class::Wildcard | Class::Vocab) {
            let leaf_parts = if versioned && has_version {
                &parts[..n - 1]
            } else {
                &parts[..]
            };
            let ok_leaf = fam.leaves.iter().any(|l| {
                self.by_prefix.get(l).is_some_and(|&li| {
                    self.match_segments(&self.families[li].segments, leaf_parts)
                        .is_some()
                })
            });
            if !ok_leaf {
                return Match {
                    family: Some(prefix),
                    binds,
                    refusal: Some(t.family_unregistered.as_str()),
                };
            }
        }
        if self.version_required && !self.exempt.contains(&fam.prefix) && !has_version {
            return Match {
                family: Some(prefix),
                binds,
                refusal: Some(t.missing_version_segment.as_str()),
            };
        }
        let mut binds = binds;
        if has_version {
            binds.insert("version".to_owned(), parts[n - 1].to_owned());
        }
        Match {
            family: Some(prefix),
            binds,
            refusal: None,
        }
    }
}

/// Placeholder binds in the order the reference's dict holds them.
type OrderedBinds = Vec<(String, String)>;

/// A Python dict assignment: a new key goes last, a repeated one keeps its place.
fn put(binds: &mut OrderedBinds, key: &str, value: String) {
    match binds.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => binds.push((key.to_owned(), value)),
    }
}

impl Family {
    fn last(&self) -> &Segment {
        // non-empty: `Rules::load` refuses a family without segments
        &self.segments[self.segments.len() - 1]
    }

    /// The reference's `_score`: (literal count, non-wildcard, segment count).
    fn score(&self) -> (usize, u8, usize) {
        let literals = self
            .segments
            .iter()
            .filter(|s| s.class == Class::Literal)
            .count();
        let non_wildcard = u8::from(self.last().class != Class::Wildcard);
        (literals, non_wildcard, self.segments.len())
    }
}
