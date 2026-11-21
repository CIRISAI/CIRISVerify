//! Family-level rules of an edition-2 row (CC 2.6.1): the author column and
//! the second consent.
//!
//! The rules come from the family model the caller supplies
//! ([`FamilyModel`]), so this module states the check, not the table:
//!
//! - a row's family (header -70002) must be one the model registers;
//! - an authored family's payload carries `author`, a counted family's never does;
//! - a statement whose `iss` is not the payload's `author` is accepted only in a
//!   role the family names, and only when `iss` is the party that role names in
//!   the payload, or the CWT `sub` where the role is the attested key.
//!
//! CC's own model is vendored ([`VendoredFamilyModel`]): its selector cells
//! are read by [`select`], the port of CC's reference evaluator, against the
//! row's leaf (its `dimension` bound under the family) and the keys the
//! caller supplies in a [`SelectContext`] ([`verify_row_in_family_with`]).
//!
//! `act` is never a payload member: the reader derives it from the statements
//! it reads (CC 2.6.1.9). One statement read alone is `own` when its row
//! carries an `author` ([`statement_act`]): the author's own statement, or a
//! second signer's consent to the author's row. The statements of one counted
//! row read together ([`verify_group_row_in_family`]) are `group`. A caller's
//! `SelectContext::act` overrides the derivation; only
//! [`verify_row_in_family_as_given`] reads the context with nothing derived
//! (a harness withholding `act`).

pub mod select;

use super::{verify_row_statement, Digest32, Invalid, KeyDirectory, Value, Verdict, VerifiedRow};
use crate::prelude::*;
pub use select::SelectContext;
use select::{Act, Arm, Cell, SecondSigner, Select, Selector, Signers};

/// Where a second-consent role names its party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleParty {
    /// A payload member holding an identity reference, or a set of them.
    Member(String),
    /// The CWT `sub` (the attested key).
    Sub,
}

/// The role marking a family whose authorship cell reads `subject` (CC
/// 2.6.1.3): the row is authored by the attested key, so `author` MUST be the
/// CWT `sub` and the statement's `iss` MUST be that author; no second signer
/// is admitted. Carried as `(AUTHOR_IS_SUBJECT, RoleParty::Sub)` in
/// [`FamilyRule::roles`] of an authored rule.
pub const AUTHOR_IS_SUBJECT: &str = "author_is_subject";

/// One family's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyRule {
    /// Authored (`author` present) or counted (`author` absent).
    pub authored: bool,
    /// The roles in which a signer other than the author may sign.
    pub roles: Vec<(String, RoleParty)>,
    /// Whether the family scores a dimension (then `dimension` is required).
    pub scores_dimension: bool,
}

/// The family model a reader applies.
pub trait FamilyModel {
    /// The rule of the registered family `family_id`, if registered, read
    /// without any row keys.
    fn rule(&self, family_id: &str) -> Option<FamilyRule>;

    /// The rule of `family_id` for one row: `leaf` is the row's dimension
    /// bound under the family (`None`: no dimension), `ctx` the keys the
    /// caller supplies. A model whose rules do not depend on the row keeps the
    /// default, which answers [`FamilyModel::rule`].
    fn rule_for(&self, family_id: &str, leaf: Option<&str>, ctx: &SelectContext) -> RuleAnswer {
        let _ = (leaf, ctx);
        self.rule(family_id)
            .map_or(RuleAnswer::Unregistered, RuleAnswer::Rule)
    }
}

/// A model's answer for one row of a family.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleAnswer {
    /// The family's rule for this row.
    Rule(FamilyRule),
    /// The model does not register the family.
    Unregistered,
    /// Registered, but the authorship is not decided for this row: the cell
    /// is a `gap`, or an arm before the decider reads a key that is not
    /// supplied.
    Undetermined,
    /// Registered, and every arm of the authorship cell reads false.
    NoArmHolds,
}

impl FamilyModel for BTreeMap<String, FamilyRule> {
    fn rule(&self, family_id: &str) -> Option<FamilyRule> {
        self.get(family_id).cloned()
    }
}

/// CC's canonical extract of the family model's `authorship` and
/// `second_signers` cells (`manifests/family_authorship.json`,
/// CIRISConstitution rc22 8c436b8), vendored at
/// `data/cc/family_authorship.json`.
pub const FAMILY_AUTHORSHIP_JSON: &str = include_str!("../../data/cc/family_authorship.json");
/// The CC commit the extract comes from.
pub const FAMILY_MODEL_CC_COMMIT: &str = "8c436b8";
/// SHA-256 (lowercase hex) of the vendored extract, LF line endings.
pub const FAMILY_AUTHORSHIP_SHA256: &str =
    "4a3304165c6cfbe5247cad2195c0f284a434789354c462da0e67638e8d2b79a6";
/// SHA-256 of the family model the extract is cut from (its
/// `_meta.source_sha256`).
pub const FAMILY_MODEL_SHA256: &str =
    "43f8ad5378aa70cdacf4287445789dfc3611c8a29204c66444cbce6ffe1a2f95";

/// Second-signer members the vendored model cannot resolve from the row: a
/// `gap` (the text names no member), `owner_of_sub` (the owner the
/// owner-binding of the row's `sub` names, which only a held binding tells),
/// and `target` (`key:record`'s `predecessor_key`: the issuer of the row its
/// `refs.target` names, CC 3.1.3, which only that held row tells). A role
/// naming one is never admitted from the vendored model; a caller holding
/// the row or binding admits it through its own [`FamilyModel`]
/// ([`WithVendored`]).
pub const UNRESOLVED_MEMBERS: &[&str] = &["gap", "owner_of_sub", "target"];

/// One family of the vendored extract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendoredFamily {
    /// The family's registry prefix (`accord:*`).
    pub prefix: String,
    /// The `authorship` cell.
    pub authorship: Cell,
    /// The `second_signers` entries.
    pub second_signers: Vec<SecondSigner>,
}

fn load_vendored(json: &str) -> Result<BTreeMap<String, VendoredFamily>, String> {
    let j: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let fams = j["families"]
        .as_object()
        .ok_or_else(|| "families".to_owned())?;
    let text = |v: &serde_json::Value, what: &str| -> Result<String, String> {
        v.as_str().map(str::to_owned).ok_or_else(|| what.to_owned())
    };
    let mut out = BTreeMap::new();
    for (prefix, f) in fams {
        let a = &f["authorship"];
        let arms = a["arms"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|x| {
                Arm::new(&text(&x["when"], "when")?, &text(&x["value"], "value")?)
                    .map_err(|e| format!("{prefix}: {}", e.test))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authorship = Cell {
            value: a["value"].as_str().map(str::to_owned),
            source: text(&a["source"], "source")?,
            arms,
        };
        let second_signers = f["second_signers"]["value"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| {
                Ok(SecondSigner {
                    role: text(&e["role"], "role")?,
                    member: text(&e["member"], "member")?,
                    when: match e["when"].as_str() {
                        None => None,
                        Some(w) => {
                            Some(Selector::parse(w).map_err(|e| format!("{prefix}: {}", e.test))?)
                        },
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        out.insert(
            crate::namespace_match::family_id(prefix),
            VendoredFamily {
                prefix: prefix.clone(),
                authorship,
                second_signers,
            },
        );
    }
    Ok(out)
}

fn vendored() -> &'static BTreeMap<String, VendoredFamily> {
    static V: once_cell::race::OnceBox<BTreeMap<String, VendoredFamily>> =
        once_cell::race::OnceBox::new();
    // A compile-time asset whose load the tests exercise; the same bytes
    // through the same parser cannot fail later.
    V.get_or_init(|| {
        Box::new(load_vendored(FAMILY_AUTHORSHIP_JSON).expect("vendored family authorship"))
    })
}

/// The vendored extract's cells for a family id (`accord:.`), if CC's model
/// lists it.
#[must_use]
pub fn vendored_family(family_id: &str) -> Option<&'static VendoredFamily> {
    vendored().get(family_id)
}

/// Every family id the vendored extract lists, in order.
pub fn vendored_family_ids() -> impl Iterator<Item = &'static str> {
    vendored().keys().map(String::as_str)
}

/// What the vendored model says of one family with no row keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendoredRule {
    /// The cells decide without any row key: a plain cell, or arms whose first
    /// arm is `*`.
    Known(FamilyRule),
    /// Registered, but the rule needs row keys ([`VendoredFamilyModel`]'s
    /// [`FamilyModel::rule_for`] with the row's leaf and a [`SelectContext`]),
    /// or the cell is a `gap` the caller must decide.
    CallerMustSupply,
}

/// The vendored model's answer for a family id read without row keys, if CC's
/// model lists it.
#[must_use]
pub fn vendored_rule(family_id: &str) -> Option<VendoredRule> {
    vendored_family(family_id)?;
    Some(
        match VendoredFamilyModel.rule_for(family_id, None, &SelectContext::default()) {
            RuleAnswer::Rule(r) => VendoredRule::Known(r),
            _ => VendoredRule::CallerMustSupply,
        },
    )
}

/// CC's vendored family model as a [`FamilyModel`], its selector arms read by
/// [`select`] against the row's leaf and the caller's [`SelectContext`].
///
/// A `when`-conditioned second signer is admitted when its `when` holds; when
/// any entry's `when` is unknown the cell is unknown and no second signer is
/// admitted. A role whose member is in [`UNRESOLVED_MEMBERS`] is never
/// admitted. `scores_dimension` is false here (a `dimension` that is present
/// is still resolved against -70002 by the row reader).
#[derive(Debug, Clone, Copy, Default)]
pub struct VendoredFamilyModel;

impl FamilyModel for VendoredFamilyModel {
    fn rule(&self, family_id: &str) -> Option<FamilyRule> {
        match self.rule_for(family_id, None, &SelectContext::default()) {
            RuleAnswer::Rule(r) => Some(r),
            _ => None,
        }
    }

    fn rule_for(&self, family_id: &str, leaf: Option<&str>, ctx: &SelectContext) -> RuleAnswer {
        let Some(f) = vendored_family(family_id) else {
            return RuleAnswer::Unregistered;
        };
        let mut subject = false;
        let authored = match f.authorship.answer(leaf, ctx).0 {
            Select::Value(v) if v == "authored" => true,
            Select::Value(v) if v == "counted" => false,
            Select::Value(v) if v == "subject" => {
                subject = true;
                true
            },
            Select::Null => return RuleAnswer::NoArmHolds,
            // unknown, gap, or a value outside the authorship vocabulary
            _ => return RuleAnswer::Undetermined,
        };
        let roles = match select::second_signers(&f.second_signers, leaf, ctx) {
            // Authored by the attested key alone: no second signer.
            _ if subject => vec![(AUTHOR_IS_SUBJECT.to_owned(), RoleParty::Sub)],
            Signers::Roles(rs) => rs
                .into_iter()
                .filter(|r| !UNRESOLVED_MEMBERS.contains(&r.member.as_str()))
                .map(|r| {
                    let party = if r.member == "sub" {
                        RoleParty::Sub
                    } else {
                        RoleParty::Member(r.member.clone())
                    };
                    (r.role.clone(), party)
                })
                .collect(),
            Signers::Unknown => Vec::new(),
        };
        RuleAnswer::Rule(FamilyRule {
            authored,
            roles,
            scores_dimension: false,
        })
    }
}

/// The caller's model first, then CC's vendored one.
pub struct WithVendored<'a>(pub &'a dyn FamilyModel);

impl FamilyModel for WithVendored<'_> {
    fn rule(&self, family_id: &str) -> Option<FamilyRule> {
        self.0
            .rule(family_id)
            .or_else(|| VendoredFamilyModel.rule(family_id))
    }

    fn rule_for(&self, family_id: &str, leaf: Option<&str>, ctx: &SelectContext) -> RuleAnswer {
        match self.0.rule_for(family_id, leaf, ctx) {
            RuleAnswer::Unregistered => VendoredFamilyModel.rule_for(family_id, leaf, ctx),
            a => a,
        }
    }
}

/// Why a Valid statement fails its family's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FamilyFault {
    /// -70002 names no registered family.
    UnregisteredFamily,
    /// `author` absent on an authored family, or present on a counted one.
    AuthorColumn,
    /// `iss` is not the author and fills no role the family names.
    IssNotInRole,
    /// A family that scores a dimension carries none.
    DimensionMissing,
    /// The family is registered but no model decides its authorship for
    /// this row: CC's cell is a `gap`, or an arm before the decider reads a
    /// key the row and the caller's [`SelectContext`] leave unknown.
    AuthorshipUndetermined,
    /// The family's authorship cell answers null for this row: every arm
    /// reads false.
    NoArmHolds,
}

/// A row read under its family's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyVerdict {
    /// Valid, and the family's rules hold; `role` names the role the signer
    /// filled when it is not the author.
    Valid {
        /// The row.
        row: Box<VerifiedRow>,
        /// The role filled, if the signer is not the author.
        role: Option<String>,
    },
    /// The statement itself is Invalid.
    Invalid(Invalid),
    /// The statement is valid but breaks its family's rules.
    FamilyInvalid(FamilyFault),
    /// The statement waits on keys; family rules are not reached.
    Waiting(Vec<super::MissingKey>),
}

fn names(v: &Value, iss: &str) -> bool {
    match v {
        Value::Text(t) => t == iss,
        Value::Array(a) => a.iter().any(|x| x.as_text() == Some(iss)),
        _ => false,
    }
}

/// Apply `rule` to a Valid row.
///
/// # Errors
/// The [`FamilyFault`].
pub fn check_family(row: &VerifiedRow, rule: &FamilyRule) -> Result<Option<String>, FamilyFault> {
    if rule.authored != row.author.is_some() {
        return Err(FamilyFault::AuthorColumn);
    }
    if rule.scores_dimension && row.payload.get_text("dimension").is_none() {
        return Err(FamilyFault::DimensionMissing);
    }
    // A `subject` family (CC 2.6.1.3): the author is the CWT `sub`, and only
    // the author signs.
    if rule
        .roles
        .iter()
        .any(|(r, p)| r == AUTHOR_IS_SUBJECT && *p == RoleParty::Sub)
    {
        return match &row.author {
            Some(a) if *a == row.sub && *a == row.iss => Ok(None),
            _ => Err(FamilyFault::IssNotInRole),
        };
    }
    match &row.author {
        Some(a) if *a == row.iss => Ok(None),
        // A counted family has no author; each voice signs as itself.
        None => Ok(None),
        Some(_) => rule
            .roles
            .iter()
            .find(|(_, party)| match party {
                RoleParty::Sub => row.sub == row.iss,
                RoleParty::Member(m) => row.payload.get_text(m).is_some_and(|v| names(v, &row.iss)),
            })
            .map(|(role, _)| Some(role.clone()))
            .ok_or(FamilyFault::IssNotInRole),
    }
}

/// A row's leaf: its `dimension` bound under its own family (header -70002)
/// by [`crate::namespace_match::bind_leaf`]. `None` (unknown) when the row
/// carries no dimension. [`dimension_leaf`] over the row's family and payload.
#[must_use]
pub fn row_leaf(row: &VerifiedRow) -> Option<String> {
    dimension_leaf(&row.family, &row.payload)
}

/// The leaf of a payload's `dimension` under a family id (header -70002),
/// for a caller that holds the family and the payload before, or without, a
/// verdict: the dimension bound by [`crate::namespace_match::bind_leaf`], its
/// version stripped. `None` when there is no text `dimension`, the family id
/// names no registered prefix, or the dimension does not bind under it.
#[must_use]
pub fn dimension_leaf(family_id: &str, payload: &crate::cde::Value) -> Option<String> {
    let dimension = payload.get_text("dimension")?.as_text()?;
    let prefix = crate::namespace_match::prefix_of_family_id(family_id)?;
    crate::namespace_match::bind_leaf(prefix, dimension)
        .ok()
        .map(|b| b.leaf)
}

/// Read a row statement and apply its family's rules, with no caller-supplied
/// selector keys: [`verify_row_in_family_with`] under an empty
/// [`SelectContext`] (the leaf is still bound from the row's dimension, and
/// the act derived from the statement, [`statement_act`]).
#[must_use]
pub fn verify_row_in_family(
    bytes: &[u8],
    keys: &dyn KeyDirectory,
    model: &dyn FamilyModel,
) -> FamilyVerdict {
    verify_row_in_family_with(bytes, keys, model, &SelectContext::default())
}

/// The act a reader derives from one statement read alone (CC 2.6.1.9): `own`
/// when the row carries an `author`, whether the statement is the author's
/// (`iss` = `author`) or a second signer's consent to the author's row (the
/// act is still the author's; the role is checked by [`check_family`]). A row
/// without an author is a voice of a counted row; read alone it gives no act
/// (`None`, unknown): its act is `group` only when read with the other
/// statements of its row ([`verify_group_row_in_family`]).
#[must_use]
pub fn statement_act(row: &VerifiedRow) -> Option<Act> {
    row.author.as_ref().map(|_| Act::Own)
}

/// Read a row statement and apply its family's rules for this row: the
/// model's [`FamilyModel::rule_for`] with the row's leaf ([`row_leaf`]) and
/// the caller's `ctx` (`verb`, `identity`, `group`, `seats`, `act`; a key
/// left `None` reads unknown). When `ctx.act` is `None` the act is derived
/// from the statement ([`statement_act`]); a supplied `ctx.act` is used as
/// given.
///
/// An undecided authorship is [`FamilyFault::AuthorshipUndetermined`]; an
/// authorship cell whose every arm reads false is [`FamilyFault::NoArmHolds`].
#[must_use]
pub fn verify_row_in_family_with(
    bytes: &[u8],
    keys: &dyn KeyDirectory,
    model: &dyn FamilyModel,
    ctx: &SelectContext,
) -> FamilyVerdict {
    read_in_family(bytes, keys, model, ctx, true)
}

/// [`verify_row_in_family_with`] with `ctx` read exactly as given: no act is
/// derived, so a `ctx.act` left `None` reads unknown. A reader always has the
/// act (CC 2.6.1.9); this is for a harness that withholds it, where a cell
/// that reads `act` is [`FamilyFault::AuthorshipUndetermined`].
#[must_use]
pub fn verify_row_in_family_as_given(
    bytes: &[u8],
    keys: &dyn KeyDirectory,
    model: &dyn FamilyModel,
    ctx: &SelectContext,
) -> FamilyVerdict {
    read_in_family(bytes, keys, model, ctx, false)
}

fn read_in_family(
    bytes: &[u8],
    keys: &dyn KeyDirectory,
    model: &dyn FamilyModel,
    ctx: &SelectContext,
    derive_act: bool,
) -> FamilyVerdict {
    match verify_row_statement(bytes, keys) {
        Verdict::Invalid(i) => FamilyVerdict::Invalid(i),
        Verdict::Waiting { missing } => FamilyVerdict::Waiting(missing),
        Verdict::Valid(row) => {
            let derived;
            let ctx = if derive_act && ctx.act.is_none() {
                derived = SelectContext {
                    act: statement_act(&row),
                    ..ctx.clone()
                };
                &derived
            } else {
                ctx
            };
            let leaf = row_leaf(&row);
            let leaf = leaf.as_deref();
            let rule = match model.rule_for(&row.family, leaf, ctx) {
                RuleAnswer::Rule(r) => r,
                RuleAnswer::Undetermined => {
                    return FamilyVerdict::FamilyInvalid(FamilyFault::AuthorshipUndetermined)
                },
                RuleAnswer::NoArmHolds => {
                    return FamilyVerdict::FamilyInvalid(FamilyFault::NoArmHolds)
                },
                // Not the caller's family: say whether CC's model would have
                // left it undecided for this row too.
                RuleAnswer::Unregistered => {
                    let fault = match VendoredFamilyModel.rule_for(&row.family, leaf, ctx) {
                        RuleAnswer::Undetermined => FamilyFault::AuthorshipUndetermined,
                        RuleAnswer::NoArmHolds => FamilyFault::NoArmHolds,
                        _ => FamilyFault::UnregisteredFamily,
                    };
                    return FamilyVerdict::FamilyInvalid(fault);
                },
            };
            match check_family(&row, &rule) {
                Ok(role) => FamilyVerdict::Valid { row, role },
                Err(f) => FamilyVerdict::FamilyInvalid(f),
            }
        },
    }
}

/// The statements of one counted row read together (CC 2.6.1.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupReading {
    /// The row id every valid statement shares; `None` when none is valid.
    pub row_id: Option<Digest32>,
    /// Each statement's verdict, in the order given.
    pub voices: Vec<FamilyVerdict>,
}

/// Why statements read as one group are not one row's voices.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupFault {
    /// No statement was given.
    NoStatements,
    /// The valid statements name more than one row (different payloads).
    SeveralRows,
}

/// Read several statements over one payload, the voices of one counted row,
/// and apply the family's rules to each with `act` = `group` (a supplied
/// `ctx.act` is used as given).
///
/// Counting the distinct voices against the roster they name, under its
/// `consensus_protocol`, is the caller's: this reads the act, not the count.
///
/// # Errors
/// [`GroupFault::NoStatements`] for an empty slice; [`GroupFault::SeveralRows`]
/// when the valid statements do not share one row id.
pub fn verify_group_row_in_family(
    statements: &[&[u8]],
    keys: &dyn KeyDirectory,
    model: &dyn FamilyModel,
    ctx: &SelectContext,
) -> Result<GroupReading, GroupFault> {
    if statements.is_empty() {
        return Err(GroupFault::NoStatements);
    }
    let ctx = SelectContext {
        act: ctx.act.or(Some(Act::Group)),
        ..ctx.clone()
    };
    let voices: Vec<FamilyVerdict> = statements
        .iter()
        .map(|s| verify_row_in_family_with(s, keys, model, &ctx))
        .collect();
    let mut row_id = None;
    for v in &voices {
        if let FamilyVerdict::Valid { row, .. } = v {
            match row_id {
                None => row_id = Some(row.row_id),
                Some(id) if id == row.row_id => {},
                Some(_) => return Err(GroupFault::SeveralRows),
            }
        }
    }
    Ok(GroupReading { row_id, voices })
}

#[cfg(test)]
mod tests {
    use super::super::{identity_ref, sign_row_statement, thumbprint};
    use super::*;
    use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};

    fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
    }
    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }
    fn idr(k: &CompositeSigningKey) -> String {
        identity_ref(&thumbprint(k.public_key()))
    }
    fn model() -> BTreeMap<String, FamilyRule> {
        let mut m = BTreeMap::new();
        m.insert(
            "conscience:coherence".into(),
            FamilyRule {
                authored: true,
                roles: vec![
                    ("delegate".into(), RoleParty::Member("delegate".into())),
                    ("attested".into(), RoleParty::Sub),
                ],
                scores_dimension: false,
            },
        );
        m.insert(
            "accord:lifecycle:.kind".into(),
            FamilyRule {
                authored: false,
                roles: vec![],
                scores_dimension: true,
            },
        );
        m
    }

    fn run(
        signer: &CompositeSigningKey,
        sub: &str,
        family: &str,
        p: Value,
        held: &[&CompositeSigningKey],
    ) -> FamilyVerdict {
        let st =
            sign_row_statement(signer, &idr(signer), sub, "scores", family, &p, vec![]).unwrap();
        let d: BTreeMap<_, CompositePublicKey> = held
            .iter()
            .map(|k| (thumbprint(k.public_key()), k.public_key().clone()))
            .collect();
        verify_row_in_family(&st, &d, &model())
    }

    #[test]
    fn vendored_model_cells() {
        // Plain cells.
        assert!(matches!(
            vendored_rule("evidence:.suite:.kind:.cell:.prefix"),
            Some(VendoredRule::Known(FamilyRule { authored: true, .. }))
        ));
        assert!(matches!(
            vendored_rule("group:roster"),
            Some(VendoredRule::Known(FamilyRule {
                authored: false,
                ..
            }))
        ));
        // Selectors (rc20: key:record and licensure read `act`): the row's
        // keys decide.
        for f in [
            "accord:.",
            "key:record",
            "licensure:.authority_id",
            "self:delegates_to",
        ] {
            assert_eq!(
                vendored_rule(f),
                Some(VendoredRule::CallerMustSupply),
                "{f}"
            );
        }
        // Roles (rc21-wire: self:delegates_to's read `act`): under `act=own`,
        // `sub` admitted and the unresolved `owner_of_sub` dropped.
        let own = SelectContext {
            act: Some(Act::Own),
            ..SelectContext::default()
        };
        let RuleAnswer::Rule(d) = VendoredFamilyModel.rule_for("self:delegates_to", None, &own)
        else {
            panic!()
        };
        assert!(d.authored);
        assert_eq!(d.roles, vec![("delegate".to_owned(), RoleParty::Sub)]);
        // key:record's one role, predecessor_key, is by `target` (rc20): the
        // issuer of the row `refs.target` names, which the row does not carry,
        // so the vendored model admits no second signer.
        let kr = vendored_family("key:record").unwrap();
        assert_eq!(
            kr.second_signers
                .iter()
                .map(|e| (e.role.as_str(), e.member.as_str()))
                .collect::<Vec<_>>(),
            vec![("predecessor_key", "target")]
        );
        let own = SelectContext {
            act: Some(select::Act::Own),
            ..SelectContext::default()
        };
        let RuleAnswer::Rule(k) = VendoredFamilyModel.rule_for("key:record", None, &own) else {
            panic!()
        };
        assert!(k.authored);
        assert!(k.roles.is_empty());
        // group:roster's listed_member is by `members` (rc20).
        let Some(VendoredRule::Known(g)) = vendored_rule("group:roster") else {
            panic!()
        };
        assert_eq!(
            g.roles,
            vec![(
                "listed_member".to_owned(),
                RoleParty::Member("members".into())
            )]
        );
        // rc21 adds the two families rc20's registry listed: location_proof is
        // authored by its subject alone, trust:blessing counted.
        let Some(VendoredRule::Known(lp)) = vendored_rule("location_proof:.version") else {
            panic!()
        };
        assert!(lp.authored);
        assert_eq!(
            lp.roles,
            vec![(AUTHOR_IS_SUBJECT.to_owned(), RoleParty::Sub)]
        );
        assert!(matches!(
            vendored_rule("trust:blessing"),
            Some(VendoredRule::Known(FamilyRule {
                authored: false,
                ..
            }))
        ));
        assert!(vendored_rule("nobody:fam").is_none());
    }

    #[test]
    fn vendored_selectors_decide_with_row_keys() {
        let none = SelectContext::default();
        let v = VendoredFamilyModel;
        let authored = |a: RuleAnswer| match a {
            RuleAnswer::Rule(r) => Some(r.authored),
            _ => None,
        };
        // accord:* by leaf.
        assert_eq!(
            authored(v.rule_for("accord:.", Some("lifecycle:confirmed"), &none)),
            Some(false)
        );
        assert_eq!(
            authored(v.rule_for("accord:.", Some("human_dignity"), &none)),
            Some(true)
        );
        assert_eq!(
            v.rule_for("accord:.", None, &none),
            RuleAnswer::Undetermined
        );
        // A caller-supplied key.
        let group = SelectContext {
            act: Some(select::Act::Group),
            ..SelectContext::default()
        };
        assert_eq!(
            authored(v.rule_for("collection:.kind", Some("x"), &group)),
            Some(false)
        );
        assert_eq!(
            v.rule_for("collection:.kind", Some("x"), &none),
            RuleAnswer::Undetermined
        );
        // key:record and licensure (rc20): group counts, an act withheld
        // is undetermined.
        for f in ["key:record", "licensure:.authority_id"] {
            assert_eq!(authored(v.rule_for(f, None, &group)), Some(false), "{f}");
            assert_eq!(v.rule_for(f, None, &none), RuleAnswer::Undetermined, "{f}");
        }
        // `when`-conditioned second signers: admitted when the `when` holds,
        // never `owner_of_sub` or a `gap` member, none while unknown.
        let own = SelectContext {
            act: Some(select::Act::Own),
            ..SelectContext::default()
        };
        let roles = |leaf| match v.rule_for("trust:.job:.version", leaf, &own) {
            RuleAnswer::Rule(r) => r.roles,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            roles(Some("confers")),
            vec![("delegate".to_owned(), RoleParty::Sub)]
        );
        assert!(roles(Some("accepts")).is_empty());
        let RuleAnswer::Rule(r) = v.rule_for("trust:.job:.version", None, &own) else {
            panic!()
        };
        assert!(r.roles.is_empty());
        // retirement:{state}'s custodian is by `custodian` (rc20) when the
        // leaf is retired.
        let RuleAnswer::Rule(r) = v.rule_for("retirement:.state", Some("retired"), &none) else {
            panic!()
        };
        assert_eq!(
            r.roles,
            vec![(
                "custodian".to_owned(),
                RoleParty::Member("custodian".into())
            )]
        );
        // ... and own authors.
        for f in ["key:record", "licensure:.authority_id"] {
            assert_eq!(authored(v.rule_for(f, None, &own)), Some(true), "{f}");
        }
    }

    #[test]
    fn author_column_and_roles() {
        let (a, b, c) = (key(1), key(2), key(3));
        let p = |extra: Vec<(Value, Value)>| {
            let mut m = vec![(t("asserted_at"), Value::Uint(1))];
            m.extend(extra);
            Value::Map(m)
        };
        // Author signs its own authored row.
        assert!(matches!(
            run(
                &a,
                "s",
                "conscience:coherence",
                p(vec![(t("author"), t(&idr(&a)))]),
                &[&a]
            ),
            FamilyVerdict::Valid { role: None, .. }
        ));
        // Authored family without author / counted family with one.
        assert_eq!(
            run(&a, "s", "conscience:coherence", p(vec![]), &[&a]),
            FamilyVerdict::FamilyInvalid(FamilyFault::AuthorColumn)
        );
        assert_eq!(
            run(
                &a,
                "s",
                "accord:lifecycle:.kind",
                p(vec![
                    (t("author"), t(&idr(&a))),
                    (t("dimension"), t("accord:lifecycle:confirmed:v1"))
                ]),
                &[&a]
            ),
            FamilyVerdict::FamilyInvalid(FamilyFault::AuthorColumn)
        );
        // Another signer in no role: refused. Named as the delegate: accepted in that role.
        let authored = |extra: Vec<(Value, Value)>| {
            let mut v = vec![(t("author"), t(&idr(&a)))];
            v.extend(extra);
            p(v)
        };
        assert_eq!(
            run(&b, "s", "conscience:coherence", authored(vec![]), &[&b]),
            FamilyVerdict::FamilyInvalid(FamilyFault::IssNotInRole)
        );
        assert!(matches!(
            run(&b, "s", "conscience:coherence", authored(vec![(t("delegate"), t(&idr(&b)))]), &[&b]),
            FamilyVerdict::Valid { role: Some(r), .. } if r == "delegate"
        ));
        // The delegate member names someone else: refused.
        assert_eq!(
            run(
                &b,
                "s",
                "conscience:coherence",
                authored(vec![(t("delegate"), t(&idr(&c)))]),
                &[&b]
            ),
            FamilyVerdict::FamilyInvalid(FamilyFault::IssNotInRole)
        );
        // The attested key (CWT sub) consents.
        assert!(matches!(
            run(&b, &idr(&b), "conscience:coherence", authored(vec![]), &[&b]),
            FamilyVerdict::Valid { role: Some(r), .. } if r == "attested"
        ));
        // Unregistered family; a counted family that scores a dimension without one.
        assert_eq!(
            run(&a, "s", "other:fam", p(vec![]), &[&a]),
            FamilyVerdict::Invalid(Invalid::UnregisteredFamily)
        );
        assert_eq!(
            run(&a, "s", "accord:lifecycle:.kind", p(vec![]), &[&a]),
            FamilyVerdict::FamilyInvalid(FamilyFault::DimensionMissing)
        );
    }

    fn signed(signer: &CompositeSigningKey, sub: &str, family: &str, p: &Value) -> Vec<u8> {
        sign_row_statement(signer, &idr(signer), sub, "scores", family, p, vec![]).unwrap()
    }

    fn held(keys: &[&CompositeSigningKey]) -> BTreeMap<Digest32, CompositePublicKey> {
        keys.iter()
            .map(|k| (thumbprint(k.public_key()), k.public_key().clone()))
            .collect()
    }

    /// CC 2.6.1.9: the reader derives `act` from the statements it reads.
    #[test]
    fn act_is_derived_from_the_statements() {
        let (a, b) = (key(1), key(2));
        let none = SelectContext::default();
        let v = &VendoredFamilyModel;
        let authored = Value::Map(vec![
            (t("asserted_at"), Value::Uint(1)),
            (t("author"), t(&idr(&a))),
            (t("target"), t(&idr(&b))),
        ]);
        let counted = Value::Map(vec![(t("asserted_at"), Value::Uint(1))]);
        let ab = held(&[&a, &b]);
        for f in ["key:record", "licensure:.authority_id"] {
            // The author's own statement: own, authored.
            let st = signed(&a, "s", f, &authored);
            let FamilyVerdict::Valid { row, role: None } = verify_row_in_family(&st, &ab, v) else {
                panic!("{f}")
            };
            assert_eq!(statement_act(&row), Some(Act::Own), "{f}");
            // Withheld by a harness: undetermined.
            assert_eq!(
                verify_row_in_family_as_given(&st, &ab, v, &none),
                FamilyVerdict::FamilyInvalid(FamilyFault::AuthorshipUndetermined),
                "{f}"
            );
            // A supplied act overrides: group is counted, and the row has an author.
            let group = SelectContext {
                act: Some(Act::Group),
                ..SelectContext::default()
            };
            assert_eq!(
                verify_row_in_family_with(&st, &ab, v, &group),
                FamilyVerdict::FamilyInvalid(FamilyFault::AuthorColumn),
                "{f}"
            );
            // One voice of a counted row read alone gives no act.
            let voice = signed(&a, "s", f, &counted);
            assert_eq!(
                verify_row_in_family(&voice, &ab, v),
                FamilyVerdict::FamilyInvalid(FamilyFault::AuthorshipUndetermined),
                "{f}"
            );
            // The voices of one counted row read together: group, one row.
            let voices = [voice.clone(), signed(&b, "s", f, &counted)];
            let refs: Vec<&[u8]> = voices.iter().map(Vec::as_slice).collect();
            let g = verify_group_row_in_family(&refs, &ab, v, &none).unwrap();
            assert!(g.row_id.is_some(), "{f}");
            assert!(
                g.voices
                    .iter()
                    .all(|x| matches!(x, FamilyVerdict::Valid { role: None, .. })),
                "{f}: {g:?}"
            );
            // Read as a group, an authored row breaks the author column.
            let g = verify_group_row_in_family(&[st.as_slice()], &ab, v, &none).unwrap();
            assert_eq!(
                g.voices,
                vec![FamilyVerdict::FamilyInvalid(FamilyFault::AuthorColumn)],
                "{f}"
            );
        }
        // key:record's predecessor_key is the issuer of the row `refs.target`
        // names; a payload member `target` naming the signer does not admit
        // it from the vendored model.
        let st = signed(&b, "s", "key:record", &authored);
        assert_eq!(
            verify_row_in_family(&st, &ab, v),
            FamilyVerdict::FamilyInvalid(FamilyFault::IssNotInRole)
        );
        // A second signer's consent to an authored row still derives own: a
        // caller model that admits the role (it holds the target row) accepts it.
        let mut m = BTreeMap::new();
        m.insert(
            "key:record".to_owned(),
            FamilyRule {
                authored: true,
                roles: vec![("predecessor_key".into(), RoleParty::Member("target".into()))],
                scores_dimension: false,
            },
        );
        assert!(matches!(
            verify_row_in_family(&st, &ab, &m),
            FamilyVerdict::Valid { role: Some(r), ref row } if r == "predecessor_key"
                && statement_act(row) == Some(Act::Own)
        ));
        // Different payloads are not one row.
        let other = Value::Map(vec![(t("asserted_at"), Value::Uint(2))]);
        let two = [
            signed(&a, "s", "key:record", &counted),
            signed(&b, "s", "key:record", &other),
        ];
        let refs: Vec<&[u8]> = two.iter().map(Vec::as_slice).collect();
        assert_eq!(
            verify_group_row_in_family(&refs, &ab, v, &none),
            Err(GroupFault::SeveralRows)
        );
        assert_eq!(
            verify_group_row_in_family(&[], &ab, v, &none),
            Err(GroupFault::NoStatements)
        );
    }

    /// rc20's registry lists `location_proof:{version}` and `trust:blessing`;
    /// rc21's family model reads `location_proof` as authored by its
    /// subject (CC 2.6.1.3): `author` is the CWT `sub` and the only signer.
    #[test]
    fn location_proof_is_authored_by_its_subject() {
        use crate::namespace_match::{resolve, Resolved};
        let id = |d: &str| match resolve(d) {
            Ok(Resolved::Family { family_id, .. }) => family_id,
            other => panic!("{d}: {other:?}"),
        };
        let fam = id("location_proof:v1");
        assert_eq!(fam, "location_proof:.version");
        assert_eq!(id("trust:blessing:v1"), "trust:blessing");
        assert!(vendored_family(&fam).is_some());
        assert!(vendored_family("trust:blessing").is_some());

        let a = key(1);
        let p = Value::Map(vec![
            (t("asserted_at"), Value::Uint(1)),
            (t("author"), t(&idr(&a))),
            (t("dimension"), t("location_proof:v1")),
        ]);
        let st = signed(&a, &idr(&a), &fam, &p);
        let d = held(&[&a]);
        assert!(matches!(
            verify_row_statement(&st, &d),
            Verdict::Valid(ref row) if row.family == fam
        ));
        assert!(matches!(
            verify_row_in_family(&st, &d, &VendoredFamilyModel),
            FamilyVerdict::Valid { role: None, .. }
        ));
        // About another subject: the author is not the subject, refused.
        let b = key(2);
        let st = signed(&a, &idr(&b), &fam, &p);
        assert_eq!(
            verify_row_in_family(&st, &d, &VendoredFamilyModel),
            FamilyVerdict::FamilyInvalid(FamilyFault::IssNotInRole)
        );
    }
}
