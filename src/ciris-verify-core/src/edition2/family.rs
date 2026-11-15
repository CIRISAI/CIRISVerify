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

use super::{verify_row_statement, Invalid, KeyDirectory, Value, Verdict, VerifiedRow};
use crate::prelude::*;

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
    /// The rule of the registered family `family_id`, if registered.
    fn rule(&self, family_id: &str) -> Option<FamilyRule>;
}

impl FamilyModel for BTreeMap<String, FamilyRule> {
    fn rule(&self, family_id: &str) -> Option<FamilyRule> {
        self.get(family_id).cloned()
    }
}

/// The family-model columns vendored from CC (`authorship`, `second_signers`;
/// CIRISConstitution rc20 a15ce94), extracted to `data/cc/family_columns.json`.
pub const FAMILY_COLUMNS_JSON: &str = include_str!("../../data/cc/family_columns.json");
/// The CC commit the columns come from.
pub const FAMILY_MODEL_CC_COMMIT: &str = "a15ce94";

/// What the vendored model says of one family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendoredRule {
    /// A plain `authored` / `counted` cell.
    Known(FamilyRule),
    /// Registered, but the caller must decide: a `gap` cell, or a per-leaf
    /// selector (no reference evaluator yet; CC will publish
    /// `tools/cc_family_select.py`).
    CallerMustSupply,
}

fn vendored() -> &'static BTreeMap<String, VendoredRule> {
    static V: once_cell::race::OnceBox<BTreeMap<String, VendoredRule>> =
        once_cell::race::OnceBox::new();
    V.get_or_init(|| {
        let j: serde_json::Value =
            serde_json::from_str(FAMILY_COLUMNS_JSON).expect("vendored family columns parse");
        let mut out = BTreeMap::new();
        for (prefix, f) in j["families"].as_object().expect("families") {
            let roles = f["second_signers"]
                .as_array()
                .into_iter()
                .flatten()
                // A `gap` member cannot be admitted; a `when`-conditioned role
                // waits on the selector evaluator.
                .filter(|r| r.get("when").is_none())
                .filter_map(|r| {
                    let role = r["role"].as_str()?.to_owned();
                    match r["member"].as_str()? {
                        "gap" => None,
                        "sub" => Some((role, RoleParty::Sub)),
                        m => Some((role, RoleParty::Member(m.to_owned()))),
                    }
                })
                .collect();
            let rule = match f["authorship"].as_str() {
                Some("authored") => VendoredRule::Known(FamilyRule {
                    authored: true,
                    roles,
                    scores_dimension: false,
                }),
                Some("counted") => VendoredRule::Known(FamilyRule {
                    authored: false,
                    roles,
                    scores_dimension: false,
                }),
                _ => VendoredRule::CallerMustSupply,
            };
            out.insert(crate::namespace_match::family_id(prefix), rule);
        }
        Box::new(out)
    })
}

/// The vendored model's answer for a family id, if CC's model lists it.
#[must_use]
pub fn vendored_rule(family_id: &str) -> Option<VendoredRule> {
    vendored().get(family_id).cloned()
}

/// CC's vendored family model as a [`FamilyModel`]: plain cells only.
/// `scores_dimension` is false here (a `dimension` that is present is still
/// resolved against -70002 by the row reader).
#[derive(Debug, Clone, Copy, Default)]
pub struct VendoredFamilyModel;

impl FamilyModel for VendoredFamilyModel {
    fn rule(&self, family_id: &str) -> Option<FamilyRule> {
        match vendored_rule(family_id)? {
            VendoredRule::Known(r) => Some(r),
            VendoredRule::CallerMustSupply => None,
        }
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
    /// The family is registered but no model decides its authorship: CC's
    /// cell is a `gap` or a selector the vendored model does not evaluate,
    /// and the caller's model does not cover it.
    AuthorshipUndetermined,
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

/// Read a row statement and apply its family's rules.
#[must_use]
pub fn verify_row_in_family(
    bytes: &[u8],
    keys: &dyn KeyDirectory,
    model: &dyn FamilyModel,
) -> FamilyVerdict {
    match verify_row_statement(bytes, keys) {
        Verdict::Invalid(i) => FamilyVerdict::Invalid(i),
        Verdict::Waiting { missing } => FamilyVerdict::Waiting(missing),
        Verdict::Valid(row) => {
            let Some(rule) = model.rule(&row.family) else {
                let fault = match vendored_rule(&row.family) {
                    Some(VendoredRule::CallerMustSupply) => FamilyFault::AuthorshipUndetermined,
                    _ => FamilyFault::UnregisteredFamily,
                };
                return FamilyVerdict::FamilyInvalid(fault);
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
