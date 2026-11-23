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
    /// The grantee side declined it.
    Declined,
    /// No acceptance of it is held.
    NotAccepted,
    /// The grantee side withdrew its acceptance.
    AcceptanceWithdrawn,
}

/// Is the counted conferral `conferral` in force?
///
/// - `counted_ends`: the row ids named by the counted ends held (each a
///   `withdraws` already counted, e.g. by [`strict_majority`]);
/// - `declined`: a valid decline of the conferral is held;
/// - `acceptance`: the row id of a valid acceptance of it, if held;
/// - `acceptance_ends`: the row ids named by the grantee side's own valid
///   withdrawals.
///
/// Checked in that order: a counted end, a decline, no acceptance, the
/// acceptance withdrawn.
#[must_use]
pub fn conferral_in_force<T: Eq>(
    conferral: &T,
    counted_ends: &[T],
    declined: bool,
    acceptance: Option<&T>,
    acceptance_ends: &[T],
) -> InForce {
    if counted_ends.contains(conferral) {
        return InForce::EndedByCount;
    }
    if declined {
        return InForce::Declined;
    }
    let Some(a) = acceptance else {
        return InForce::NotAccepted;
    };
    if acceptance_ends.contains(a) {
        return InForce::AcceptanceWithdrawn;
    }
    InForce::InForce
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
        let (g, a) = (1u8, 2u8);
        assert_eq!(
            conferral_in_force(&g, &[], false, Some(&a), &[]),
            InForce::InForce
        );
        assert_eq!(
            conferral_in_force(&g, &[g], false, Some(&a), &[]),
            InForce::EndedByCount
        );
        assert_eq!(
            conferral_in_force(&g, &[], true, Some(&a), &[]),
            InForce::Declined
        );
        assert_eq!(
            conferral_in_force(&g, &[], false, None, &[]),
            InForce::NotAccepted
        );
        assert_eq!(
            conferral_in_force(&g, &[], false, Some(&a), &[a]),
            InForce::AcceptanceWithdrawn
        );
        assert_eq!(
            conferral_in_force(&g, &[9], false, Some(&a), &[9]),
            InForce::InForce
        );
    }
}
