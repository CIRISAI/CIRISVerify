//! The two decisions every counted conferral turns on, each behind one small
//! pure function over plain ids, so a caller (or a later kernel fold) holds
//! one implementation of each:
//!
//! - [`strict_majority`]: is a counted row counted? A strict majority of a
//!   roster (`2·yes > N`, CC 4.2.6; no minimum roster), one voice per holder,
//!   over the holders the caller names. The caller has already decided which
//!   statements are voices: verified, over one row, each at a key the named
//!   bundle seats for its holder.
//! - [`conferral_in_force`]: is a counted conferral in force? It is two
//!   consents (CC 3.2 T3, CC 2.4.1.1), so either side ends it: a counted end
//!   of the conferral row, or the grantee side's decline or its own
//!   withdrawal of its acceptance.
//!
//! Neither function knows rows, keys or families: ids are any `Ord` / `Eq`
//! type (identity references, row-id digests). Pure: no clock, no I/O.

use crate::prelude::*;

/// What [`strict_majority`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    /// `2·yes > N`.
    Counted {
        /// Distinct holders among the voices.
        yes: usize,
        /// N, the distinct holders of the roster.
        n: usize,
    },
    /// Short of the count.
    Unmet {
        /// Distinct holders among the voices.
        yes: usize,
        /// The strict majority, `floor(N / 2) + 1`.
        need: usize,
        /// `yes + pending >= need`: the `pending` voices the caller is still
        /// waiting on could make up the count, so the row waits rather than
        /// being refused.
        could_be_made_up: bool,
    },
}

impl Count {
    /// Whether the row is counted.
    #[must_use]
    pub fn is_counted(self) -> bool {
        matches!(self, Self::Counted { .. })
    }
}

/// Count `voices` (the signer ids of the statements read as voices of one
/// row; a repeat counts once, an id not in `roster` counts for nothing)
/// against `roster` (the holder ids of the bundle the row names; a repeat is
/// one holder). `pending` is the number of distinct further voices the caller
/// is waiting on (keys or records not held), used only for
/// [`Count::Unmet::could_be_made_up`].
#[must_use]
pub fn strict_majority<T: Ord>(
    voices: impl IntoIterator<Item = T>,
    roster: impl IntoIterator<Item = T>,
    pending: usize,
) -> Count {
    let roster: BTreeSet<T> = roster.into_iter().collect();
    let yes = voices
        .into_iter()
        .filter(|v| roster.contains(v))
        .collect::<BTreeSet<T>>()
        .len();
    let n = roster.len();
    if super::is_strict_majority(yes, n) {
        Count::Counted { yes, n }
    } else {
        let need = super::strict_majority(n);
        Count::Unmet {
            yes,
            need,
            could_be_made_up: yes + pending >= need,
        }
    }
}

/// What [`conferral_in_force`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InForce {
    /// Counted, accepted, and neither side has ended it.
    InForce,
    /// A counted end names the conferral.
    EndedByCount,
    /// An acceptance and a decline by the grantee side both stand (CC
    /// 3.1.3.2, CC 2.7.7 rule 6): neither counts while both stand, so the
    /// conferral confers nothing. It lifts when one of the two is withdrawn.
    Contested,
    /// A decline stands alone. A decline is terminal for that conferral: an
    /// acceptance of it held beside the decline is [`InForce::Contested`],
    /// never a revival (rows carry no arrival order); the grantors confer
    /// again instead.
    Declined,
    /// No acceptance of it stands, and no decline.
    NotAccepted,
    /// The acceptance held was withdrawn by the grantee side, and no decline
    /// stands.
    AcceptanceWithdrawn,
}

/// Is the counted conferral `conferral` in force?
///
/// - `counted_ends`: the row ids named by the counted ends held (each a
///   `withdraws` already counted, e.g. by [`strict_majority`]);
/// - `acceptance` / `decline`: the row ids of a valid acceptance and a valid
///   decline of it by the grantee side, if held;
/// - `reply_ends`: the row ids named by the grantee side's own valid
///   withdrawals of its replies.
///
/// A reply stands when held and not named in `reply_ends`. Checked in this
/// order: a counted end; both replies standing (contested); a decline
/// standing; an acceptance standing (in force); an acceptance withdrawn; none.
#[must_use]
pub fn conferral_in_force<T: Eq>(
    conferral: &T,
    counted_ends: &[T],
    acceptance: Option<&T>,
    decline: Option<&T>,
    reply_ends: &[T],
) -> InForce {
    if counted_ends.contains(conferral) {
        return InForce::EndedByCount;
    }
    let stands = |r: Option<&T>| r.is_some_and(|r| !reply_ends.contains(r));
    match (stands(acceptance), stands(decline)) {
        (true, true) => InForce::Contested,
        (_, true) => InForce::Declined,
        (true, false) => InForce::InForce,
        (false, false) if acceptance.is_some() => InForce::AcceptanceWithdrawn,
        (false, false) => InForce::NotAccepted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn majority() {
        let r = ["a", "b", "c"];
        assert!(strict_majority(["a", "b"], r, 0).is_counted());
        assert_eq!(
            strict_majority(["a", "a", "x"], r, 0),
            Count::Unmet {
                yes: 1,
                need: 2,
                could_be_made_up: false
            }
        );
        assert_eq!(
            strict_majority(["a"], r, 1),
            Count::Unmet {
                yes: 1,
                need: 2,
                could_be_made_up: true
            }
        );
        assert!(strict_majority(["a"], ["a"], 0).is_counted());
        assert!(!strict_majority(["a", "b"], ["a", "b", "c", "d"], 0).is_counted());
        assert!(!strict_majority::<&str>([], [], 0).is_counted());
    }

    #[test]
    fn in_force() {
        let (g, a, d) = (1u8, 2u8, 3u8);
        let f = conferral_in_force;
        assert_eq!(f(&g, &[], Some(&a), None, &[]), InForce::InForce);
        assert_eq!(f(&g, &[g], Some(&a), None, &[]), InForce::EndedByCount);
        assert_eq!(f(&g, &[], Some(&a), Some(&d), &[]), InForce::Contested);
        assert_eq!(f(&g, &[], Some(&a), Some(&d), &[d]), InForce::InForce);
        assert_eq!(f(&g, &[], Some(&a), Some(&d), &[a]), InForce::Declined);
        assert_eq!(f(&g, &[], None, Some(&d), &[]), InForce::Declined);
        assert_eq!(f(&g, &[], None, Some(&d), &[d]), InForce::NotAccepted);
        assert_eq!(f(&g, &[], None, None, &[]), InForce::NotAccepted);
        assert_eq!(
            f(&g, &[], Some(&a), None, &[a]),
            InForce::AcceptanceWithdrawn
        );
        assert_eq!(f(&g, &[9], Some(&a), None, &[9]), InForce::InForce);
    }
}
