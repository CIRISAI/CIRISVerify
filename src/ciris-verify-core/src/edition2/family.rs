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

pub mod select;

use super::{verify_row_statement, Invalid, KeyDirectory, Value, Verdict, VerifiedRow};
use crate::prelude::*;
pub use select::SelectContext;
use select::{Arm, Cell, SecondSigner, Select, Selector, Signers};

/// Where a second-consent role names its party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleParty {
    /// A payload member holding an identity reference, or a set of them.
    Member(String),
    /// The CWT `sub` (the attested key).
    Sub,
}

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
/// CIRISConstitution rc20 e08bf05), vendored at
/// `data/cc/family_authorship.json`.
pub const FAMILY_AUTHORSHIP_JSON: &str = include_str!("../../data/cc/family_authorship.json");
/// The CC commit the extract comes from.
pub const FAMILY_MODEL_CC_COMMIT: &str = "e08bf05";
/// SHA-256 (lowercase hex) of the vendored extract, LF line endings.
pub const FAMILY_AUTHORSHIP_SHA256: &str =
    "334027850f9c2d7fd382249b5bb188533a25307082794bce168625d1e5cfaf93";
/// SHA-256 of the family model the extract is cut from (its
/// `_meta.source_sha256`).
pub const FAMILY_MODEL_SHA256: &str =
    "3c64403a56b0da0138433041af972ee552ead95d5f129f1f5fad26df6a8d1caf";

/// Second-signer members the vendored model cannot resolve from the row: a
/// `gap` (the text names no member), and `owner_of_sub` (the owner the
/// owner-binding of the row's `sub` names, which only a held binding tells).
/// A role naming one is never admitted from the vendored model.
pub const UNRESOLVED_MEMBERS: &[&str] = &["gap", "owner_of_sub"];

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
        let authored = match f.authorship.answer(leaf, ctx).0 {
            Select::Value(v) if v == "authored" => true,
            Select::Value(v) if v == "counted" => false,
            Select::Null => return RuleAnswer::NoArmHolds,
            // unknown, gap, or a value outside the authorship vocabulary
            _ => return RuleAnswer::Undetermined,
        };
        let roles = match select::second_signers(&f.second_signers, leaf, ctx) {
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
/// carries no dimension.
#[must_use]
pub fn row_leaf(row: &VerifiedRow) -> Option<String> {
    let dimension = row.payload.get_text("dimension")?.as_text()?;
    let prefix = crate::namespace_match::prefix_of_family_id(&row.family)?;
    crate::namespace_match::bind_leaf(prefix, dimension)
        .ok()
        .map(|b| b.leaf)
}

/// Read a row statement and apply its family's rules, with no caller-supplied
/// selector keys: [`verify_row_in_family_with`] under an empty
/// [`SelectContext`] (the leaf is still bound from the row's dimension).
#[must_use]
pub fn verify_row_in_family(
    bytes: &[u8],
    keys: &dyn KeyDirectory,
    model: &dyn FamilyModel,
) -> FamilyVerdict {
    verify_row_in_family_with(bytes, keys, model, &SelectContext::default())
}

/// Read a row statement and apply its family's rules for this row: the
/// model's [`FamilyModel::rule_for`] with the row's leaf ([`row_leaf`]) and
/// the caller's `ctx` (`verb`, `identity`, `group`, `seats`, `act`; a key
/// left `None` reads unknown).
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
    match verify_row_statement(bytes, keys) {
        Verdict::Invalid(i) => FamilyVerdict::Invalid(i),
        Verdict::Waiting { missing } => FamilyVerdict::Waiting(missing),
        Verdict::Valid(row) => {
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
            vendored_rule("key:record"),
            Some(VendoredRule::Known(FamilyRule { authored: true, .. }))
        ));
        assert!(matches!(
            vendored_rule("group:roster"),
            Some(VendoredRule::Known(FamilyRule {
                authored: false,
                ..
            }))
        ));
        // A selector and a gap: the caller decides.
        assert_eq!(
            vendored_rule("accord:."),
            Some(VendoredRule::CallerMustSupply)
        );
        assert_eq!(
            vendored_rule("licensure:.authority_id"),
            Some(VendoredRule::CallerMustSupply)
        );
        // Roles: `sub` admitted, `gap` dropped.
        let Some(VendoredRule::Known(d)) = vendored_rule("self:delegates_to") else {
            panic!()
        };
        assert_eq!(d.roles, vec![("delegate".to_owned(), RoleParty::Sub)]);
        // key:record's two roles are both gap.
        let Some(VendoredRule::Known(k)) = vendored_rule("key:record") else {
            panic!()
        };
        assert!(k.roles.is_empty());
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
        // A gap stays undetermined whatever is supplied.
        assert_eq!(
            v.rule_for("licensure:.authority_id", Some("x"), &group),
            RuleAnswer::Undetermined
        );
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
        let RuleAnswer::Rule(r) = v.rule_for("retirement:.state", Some("retired"), &none) else {
            panic!()
        };
        assert!(r.roles.is_empty());
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
}
