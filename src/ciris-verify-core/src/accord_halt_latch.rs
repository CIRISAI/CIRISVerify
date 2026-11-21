//! The constitutional halt latch: what a node does with a verified accord row
//! (CC 4.2.1.1 / 4.2.1.3; model `formal/accord_halt/AccordHaltFuse.tla`).
//!
//! A `constitutional` halt is an **agent pause**: it stops the effectful acts
//! of AI agents, with their state preserved, and touches nothing else. The
//! latch is read by exactly one thing — the agent's act gate, before every
//! effectful act — which is why "zero data disruption" holds by construction.
//!
//! ## The rules, as transitions
//!
//! | event (verified row)       | latch clear            | paused, lone (unconfirmed)                      | paused, confirmed |
//! |----------------------------|------------------------|-------------------------------------------------|-------------------|
//! | `constitutional` (1 holder)| **pause**, record receipt | ignored (idempotent)                         | ignored           |
//! | `lifecycle:confirmed` (M/N) | ignored                | **confirm**, if it names this halt and the fuse has not run | ignored |
//! | `lifecycle:active` (M/N)    | ignored                | **resume**, if it names this halt               | **resume**, if it names this halt |
//! | time passes                 | —                      | **lapses** at `receipt + halt_fuse_secs`        | never lapses      |
//!
//! - **The fuse counts from receipt on this node's clock**, never from the
//!   signed `asserted_at`: that instant is the signer's choice, so it could
//!   neither let a sealed, pre-signed halt work when it is finally published
//!   nor stop a future-dated one from pausing agents for years.
//! - **A majority `lifecycle:active` ends any halt**, confirmed or not, so a
//!   stolen sealed row (a false halt) need not run its whole fuse.
//! - **A second halt while paused changes nothing.** It does not reset the
//!   fuse; a fresh halt fired *after* a lapse pauses again with a fresh fuse.
//!
//! ## Only verified rows reach the latch
//!
//! [`crate::accord_halt_latch::HaltLatch::apply_forward`] takes a
//! [`crate::accord_halt_latch::ForwardRow`], which holds an edition-2 row read
//! by [`crate::edition2::accord_halt`]; its lifecycle rows name the halt by row
//! id. A call site cannot pause or un-pause agents with a row it did not verify
//! against the roster of the bundle in force. (The latch's reader of the
//! earlier, invocation-id form was removed in 23.3.3.)
//!
//! ## What stays the caller's
//!
//! The clock (`now`), persisting the latch across restarts (it is
//! `Serialize`), the roster, and dedup of `invocation_id` / `nonce` (the
//! store's).

#[allow(unused_imports)]
use crate::prelude::*;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::edition2::accord_halt::{InvocationRow, InvokeKind, LifecycleKind, LifecycleRow};
use crate::edition2::Digest32;

/// `halt_fuse_secs` when the charter does not carry it (CC 5.3.4: the shipped
/// default; the 2026-10-04 genesis charter omits it, and that is not an error).
pub const DEFAULT_HALT_FUSE_SECS: u64 = 86_400;

/// The halt currently latched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatchedHalt {
    /// The halt's `invocation_id`.
    pub halt_id: String,
    /// When THIS node received it — the fuse's origin.
    pub received_at: DateTime<Utc>,
    /// Whether a strict majority confirmed it before the fuse ran out.
    pub confirmed: bool,
    /// The halt's row id (its lifecycle rows name it by this). `None` only in
    /// a latch persisted by a release that still read the earlier form; no
    /// lifecycle row names such a halt, so it ends only by lapsing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_row: Option<Digest32>,
}

/// What [`HaltLatch::apply_forward`] did with a verified row.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LatchOutcome {
    /// The node is now paused by this halt.
    Paused,
    /// A lone halt is now confirmed and no longer lapses.
    Confirmed,
    /// The named halt is ended; agents resume from their paused state.
    Resumed,
    /// The row changed nothing. `why` says so in words a log can carry.
    Unchanged {
        /// Why the row changed nothing.
        why: &'static str,
    },
}

/// The node's halt latch. `Default` is clear.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltLatch {
    halt: Option<LatchedHalt>,
    /// The halts (by row id) an edition-2 `lifecycle:active` this node has
    /// applied names, whether or not that halt was in force: a halt past its
    /// `valid_until` that one of them names does not fire (CC 4.2.1.1).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    held_resumptions: BTreeSet<Digest32>,
}

impl HaltLatch {
    /// A clear latch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The halt in force at `now`, if any. A lone halt past its fuse is not in
    /// force.
    #[must_use]
    pub fn active_halt(&self, now: DateTime<Utc>, halt_fuse_secs: u64) -> Option<&LatchedHalt> {
        self.halt
            .as_ref()
            .filter(|h| h.confirmed || now < lapses_at(h, halt_fuse_secs))
    }

    /// **The act gate's question:** are agents paused at `now`? Read before
    /// every effectful act (CC 4.2.1.1, CC 1.13.6).
    #[must_use]
    pub fn is_paused(&self, now: DateTime<Utc>, halt_fuse_secs: u64) -> bool {
        self.active_halt(now, halt_fuse_secs).is_some()
    }

    /// When the latched halt lapses — `None` if clear or confirmed.
    #[must_use]
    pub fn lapses_at(&self, halt_fuse_secs: u64) -> Option<DateTime<Utc>> {
        self.halt
            .as_ref()
            .filter(|h| !h.confirmed)
            .map(|h| lapses_at(h, halt_fuse_secs))
    }

    /// Apply a verified edition-2 row received at `now` (CC 4.2.1.1,
    /// CC 4.2.1.3): a `constitutional` [`InvocationRow`] halts, a counted
    /// `confirmed` / `active` [`LifecycleRow`] confirms or ends the halt whose
    /// row id its `refs.target` names, and a notify or a drill changes
    /// nothing. `halt_fuse_secs` is the bundle in force's ([`HaltRoster::halt_fuse_secs`]).
    ///
    /// One check comes before it, and only here: the latch keeps the row id
    /// each applied `lifecycle:active` names (held or not against a halt in
    /// force), and a halt received after its `valid_until` that one of them
    /// names does not fire (CC 4.2.1.1). A halt received within its
    /// `valid_until` fires as before; a held resumption ends it only when it is
    /// applied again.
    ///
    /// [`HaltRoster::halt_fuse_secs`]: crate::edition2::accord_halt::HaltRoster::halt_fuse_secs
    pub fn apply_forward(
        &mut self,
        row: ForwardRow<'_>,
        now: DateTime<Utc>,
        halt_fuse_secs: u64,
    ) -> LatchOutcome {
        let step = match row {
            ForwardRow::Invocation(inv) => match inv.kind() {
                // A halt that arrives after its valid_until still fires, unless
                // the node already holds a resumption that names it. Within its
                // valid_until it fires whatever is held (CC 4.2.1.1).
                InvokeKind::Constitutional
                    if received_after(now, inv.valid_until())
                        && self.held_resumptions.contains(inv.row_id()) =>
                {
                    return LatchOutcome::Unchanged {
                        why:
                            "a halt past its valid_until that a held resumption names does not fire",
                    };
                },
                InvokeKind::Constitutional => Step::Halt {
                    halt_id: inv.invocation_id(),
                    halt_row: *inv.row_id(),
                },
                InvokeKind::Notify | InvokeKind::Drill => Step::Inert,
            },
            ForwardRow::Lifecycle(l) => match l.kind() {
                LifecycleKind::Confirmed => Step::Confirm(*l.target()),
                LifecycleKind::Active => {
                    self.held_resumptions.insert(*l.target());
                    Step::Resume(*l.target())
                },
            },
        };
        self.step(step, now, halt_fuse_secs)
    }

    /// The one state machine.
    fn step(&mut self, step: Step<'_>, now: DateTime<Utc>, halt_fuse_secs: u64) -> LatchOutcome {
        // A lone halt whose fuse has run is gone before anything else is judged:
        // a fresh halt may then pause again, and a late confirmation finds
        // nothing to confirm.
        if self.halt.is_some() && !self.is_paused(now, halt_fuse_secs) {
            self.halt = None;
        }
        match step {
            Step::Halt { halt_id, halt_row } => {
                if self.halt.is_some() {
                    return LatchOutcome::Unchanged {
                        why: "already paused; a second halt changes nothing and does not reset the fuse",
                    };
                }
                self.halt = Some(LatchedHalt {
                    halt_id: halt_id.to_owned(),
                    received_at: now,
                    confirmed: false,
                    halt_row: Some(halt_row),
                });
                LatchOutcome::Paused
            },
            Step::Confirm(target) => {
                let Some(h) = self.halt.as_mut() else {
                    return LatchOutcome::Unchanged {
                        why: "no halt in force; a confirmation after the fuse confirms nothing",
                    };
                };
                if !names(target, h) {
                    return LatchOutcome::Unchanged {
                        why: "confirmation names a different halt",
                    };
                }
                if h.confirmed {
                    return LatchOutcome::Unchanged {
                        why: "already confirmed",
                    };
                }
                h.confirmed = true;
                LatchOutcome::Confirmed
            },
            Step::Resume(target) => {
                let Some(h) = self.halt.as_ref() else {
                    return LatchOutcome::Unchanged {
                        why: "no halt in force",
                    };
                };
                if !names(target, h) {
                    return LatchOutcome::Unchanged {
                        why: "resumption names a different halt",
                    };
                }
                self.halt = None;
                LatchOutcome::Resumed
            },
            Step::Inert => LatchOutcome::Unchanged {
                why: "notify and drill never touch the latch",
            },
        }
    }
}

/// A verified edition-2 accord row, for [`HaltLatch::apply_forward`]. Both
/// variants are made only by the `edition2::accord_halt` readers.
#[derive(Debug, Clone, Copy)]
pub enum ForwardRow<'a> {
    /// An invocation: one holder's statement.
    Invocation(&'a InvocationRow),
    /// A counted lifecycle row.
    Lifecycle(&'a LifecycleRow),
}

/// What a row does to the latch.
enum Step<'a> {
    Halt {
        halt_id: &'a str,
        halt_row: Digest32,
    },
    Confirm(Digest32),
    Resume(Digest32),
    Inert,
}

/// Does a lifecycle row naming `target` (a row id) name the latched halt?
fn names(target: Digest32, h: &LatchedHalt) -> bool {
    h.halt_row == Some(target)
}

/// Was `now` after `valid_until_ms` (POSIX ms)?
fn received_after(now: DateTime<Utc>, valid_until_ms: u64) -> bool {
    u64::try_from(now.timestamp_millis()).is_ok_and(|n| n > valid_until_ms)
}

fn lapses_at(h: &LatchedHalt, halt_fuse_secs: u64) -> DateTime<Utc> {
    let secs = i64::try_from(halt_fuse_secs).unwrap_or(i64::MAX);
    h.received_at
        .checked_add_signed(Duration::try_seconds(secs).unwrap_or(Duration::MAX))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// Steps are driven directly here: the latch's transitions are what is
    /// under test. `apply_forward` over rows read by `edition2::accord_halt` is
    /// replayed in `tests/accord_halt_vectors_v2.rs`.
    fn halt(id: &'static str, row: u8) -> Step<'static> {
        Step::Halt {
            halt_id: id,
            halt_row: [row; 32],
        }
    }

    fn apply(l: &mut HaltLatch, step: Step<'_>, now: &str, fuse: u64) -> LatchOutcome {
        l.step(step, t(now), fuse)
    }

    const FUSE: u64 = DEFAULT_HALT_FUSE_SECS;
    const T0: &str = "2026-10-05T12:00:00Z";

    /// F1: a lone halt pauses on receipt and lapses one fuse after RECEIPT.
    #[test]
    fn a_lone_halt_lapses_one_fuse_after_receipt() {
        let mut l = HaltLatch::new();
        assert_eq!(apply(&mut l, halt("h1", 1), T0, FUSE), LatchOutcome::Paused);
        assert!(l.is_paused(t(T0), FUSE));
        assert!(l.is_paused(t("2026-10-06T11:59:59Z"), FUSE));
        assert!(
            !l.is_paused(t("2026-10-06T12:00:00Z"), FUSE),
            "lapses at receipt + 86400"
        );
        assert_eq!(l.lapses_at(FUSE), Some(t("2026-10-06T12:00:00Z")));
    }

    /// F4: a confirmed halt does not lapse; only a resumption ends it.
    #[test]
    fn a_confirmed_halt_stands_until_resumed() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), T0, FUSE);
        assert_eq!(
            apply(&mut l, Step::Confirm([1; 32]), "2026-10-05T18:00:00Z", FUSE),
            LatchOutcome::Confirmed
        );
        assert!(l.is_paused(t("2030-01-01T00:00:00Z"), FUSE));
        assert_eq!(l.lapses_at(FUSE), None);
        assert_eq!(
            apply(&mut l, Step::Resume([1; 32]), "2030-01-01T00:00:00Z", FUSE),
            LatchOutcome::Resumed
        );
        assert!(!l.is_paused(t("2030-01-01T00:00:00Z"), FUSE));
    }

    /// A confirmation that arrives after the fuse confirms nothing, and a
    /// fresh halt then pauses again with a fresh fuse.
    #[test]
    fn a_late_confirmation_confirms_nothing() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), T0, FUSE);
        let late = "2026-10-06T12:00:01Z";
        assert!(matches!(
            apply(&mut l, Step::Confirm([1; 32]), late, FUSE),
            LatchOutcome::Unchanged { .. }
        ));
        assert!(!l.is_paused(t(late), FUSE));
        assert_eq!(
            apply(&mut l, halt("h2", 2), late, FUSE),
            LatchOutcome::Paused
        );
        assert_eq!(l.lapses_at(FUSE), Some(t(late) + Duration::seconds(86_400)));
    }

    /// A majority resumption ends a lone halt too (a stolen sealed row need not
    /// run its fuse).
    #[test]
    fn a_majority_resumption_ends_an_unconfirmed_halt() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), T0, FUSE);
        assert_eq!(
            apply(&mut l, Step::Resume([1; 32]), T0, FUSE),
            LatchOutcome::Resumed
        );
        assert!(!l.is_paused(t(T0), FUSE));
    }

    /// Idempotence and binding: a second halt neither re-pauses nor resets the
    /// fuse; rows naming another halt change nothing; notify/drill never touch
    /// the latch.
    #[test]
    fn only_the_named_halt_moves_and_repeats_change_nothing() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), T0, FUSE);
        let later = "2026-10-06T00:00:00Z";
        assert!(matches!(
            apply(&mut l, halt("h2", 2), later, FUSE),
            LatchOutcome::Unchanged { .. }
        ));
        assert_eq!(
            l.lapses_at(FUSE),
            Some(t("2026-10-06T12:00:00Z")),
            "fuse not reset"
        );
        for step in [Step::Confirm([2; 32]), Step::Resume([2; 32]), Step::Inert] {
            assert!(matches!(
                apply(&mut l, step, later, FUSE),
                LatchOutcome::Unchanged { .. }
            ));
            assert!(l.is_paused(t(later), FUSE));
        }
    }

    /// A halt latched without a row id (persisted by a release that read the
    /// earlier form) is named by no lifecycle row; it ends by lapsing.
    #[test]
    fn a_halt_without_a_row_id_is_named_by_no_row() {
        let mut l: HaltLatch = serde_json::from_value(serde_json::json!({
            "halt": {
                "halt_id": "h1",
                "received_at": "2026-10-05T12:00:00Z",
                "confirmed": false
            }
        }))
        .unwrap();
        assert!(l.is_paused(t(T0), FUSE));
        assert!(matches!(
            apply(&mut l, Step::Resume([0; 32]), T0, FUSE),
            LatchOutcome::Unchanged { .. }
        ));
        assert!(!l.is_paused(t("2026-10-06T12:00:00Z"), FUSE));
    }

    /// The latch survives a restart: it is the caller's to persist.
    #[test]
    fn the_latch_round_trips_through_serde() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), T0, FUSE);
        let back: HaltLatch = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back, l);
        assert!(back.is_paused(t(T0), FUSE));
    }

    /// An absurd fuse saturates rather than overflowing into the past.
    #[test]
    fn an_enormous_fuse_does_not_wrap() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), T0, u64::MAX);
        assert!(l.is_paused(t("9999-01-01T00:00:00Z"), u64::MAX));
    }
}
