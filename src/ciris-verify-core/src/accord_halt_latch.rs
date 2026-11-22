//! The constitutional halt latch: what a node does with a verified accord row
//! (CC 4.2.1.1 / 4.2.1.3; FSD-007 §3; CC's halt models are
//! `formal/accord_halt/AccordHaltRow.tla` and `AccordHaltReach.tla` in
//! CIRISConstitution).
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
//! | `constitutional` (1 holder)| **pause**, fuse at zero | ignored (idempotent)                           | ignored           |
//! | `lifecycle:confirmed` (M/N) | ignored                | **confirm**, if it names this halt and the fuse has not run | ignored |
//! | `lifecycle:active` (M/N)    | ignored                | **resume**, if it names this halt               | **resume**, if it names this halt |
//! | elapsed time is counted     | —                      | **lapses** once `halt_fuse_secs` have been counted | never lapses   |
//!
//! ## The fuse is elapsed time, not a wall-clock deadline
//!
//! CC 4.2.1.1 counts the fuse "from receipt on the node's own clock". The
//! signed `asserted_at` is the signer's to choose, and the wall clock is the
//! operator's to set: setting it forward a day would lapse a real halt at once,
//! and a missed halt is the one unrecoverable failure. So the fuse is a
//! **duration** counted on a monotonic clock that no setting moves:
//!
//! - each latched halt carries `elapsed_ms`, the time this node has counted
//!   since it received the halt; a lone halt lapses when
//!   `elapsed_ms >= halt_fuse_secs × 1000`;
//! - [`crate::accord_halt_latch::HaltLatch::advance`] adds `m − m_prev` between two readings of the same
//!   boot, and **zero** across a boot change or when the clock reads lower than
//!   it did within one boot (reported as a tamper signal): an unaccounted gap
//!   only ever extends a halt;
//! - the latch state (with the checkpoint) is the caller's to persist, as
//!   before; a latch that is lost, or rolled back to an earlier copy, carries
//!   less elapsed time and extends the halt.
//!
//! The wall clock stays only where CC puts it: whether a halt was received
//! after its signed `valid_until` (the held-resumption rule below), a
//! comparison of two wall instants. An unknown receipt instant reads as within
//! `valid_until`, so the halt fires.
//!
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
//! against the roster of the bundle in force.
//!
//! ## What stays the caller's
//!
//! The monotonic readings ([`crate::accord_halt_latch::MonotonicReading`]; the host tier's
//! `FuseMeter` reads the platform's), persisting the latch across restarts
//! (it is `Serialize`), the roster, and dedup of `invocation_id` / `nonce`
//! (the store's). This module reads no clock.

#[allow(unused_imports)]
use crate::prelude::*;

use serde::{Deserialize, Serialize};

use crate::edition2::accord_halt::{InvocationRow, InvokeKind, LifecycleKind, LifecycleRow};
use crate::edition2::Digest32;

/// `halt_fuse_secs` when the charter does not carry it (CC 5.3.4: the shipped
/// default; the 2026-10-04 genesis charter omits it, and that is not an error).
pub const DEFAULT_HALT_FUSE_SECS: u64 = 86_400;

/// One reading of a monotonic clock: milliseconds since an origin fixed for
/// one boot, and that boot's identity. Two readings count elapsed time only
/// when their `boot` is the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonotonicReading {
    /// Milliseconds on the boot's monotonic clock.
    pub monotonic_ms: u64,
    /// The boot's identity; every process start counts as a new boot where
    /// the platform gives none.
    #[serde(with = "hex_bytes16")]
    pub boot: [u8; 16],
}

/// Something a reading showed that no honest clock does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FuseSignal {
    /// Within one boot, the clock read lower than at the last checkpoint:
    /// nothing was counted.
    MonotonicRegressed,
}

impl FuseSignal {
    /// The stable token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::MonotonicRegressed => "monotonic_regressed",
        }
    }
}

/// The halt currently latched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatchedHalt {
    /// The halt's `invocation_id`.
    pub halt_id: String,
    /// The halt's row id (its lifecycle rows name it by this).
    pub halt_row: Digest32,
    /// The time this node has counted since it received the halt, in
    /// milliseconds: the fuse.
    pub elapsed_ms: u64,
    /// The wall instant of receipt (POSIX ms), as a report for logs; nothing
    /// decides on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_wall_ms: Option<u64>,
    /// Whether a strict majority confirmed it before the fuse ran out.
    pub confirmed: bool,
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

/// The node's halt latch. `Default` is clear. A latch of the 23.4 shape (a
/// `received_at` instant, no `elapsed_ms`) does not deserialize: the host
/// re-applies its held accord rows, which re-latches a halt at zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaltLatch {
    halt: Option<LatchedHalt>,
    /// The halts (by row id) an edition-2 `lifecycle:active` this node has
    /// applied names, whether or not that halt was in force: a halt past its
    /// `valid_until` that one of them names does not fire (CC 4.2.1.1).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    held_resumptions: BTreeSet<Digest32>,
    /// The last reading counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<MonotonicReading>,
}

impl HaltLatch {
    /// A clear latch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count the time since the last reading into a latched lone halt's fuse.
    /// Between two readings of the same boot it adds `m − m_prev`; across a
    /// boot change, or when `m < m_prev` within one boot, it adds zero (the
    /// second case is returned as a signal). The reading becomes the
    /// checkpoint either way.
    pub fn advance(&mut self, now: MonotonicReading) -> Option<FuseSignal> {
        let mut signal = None;
        let add = match self.checkpoint {
            Some(prev) if prev.boot == now.boot => {
                if now.monotonic_ms < prev.monotonic_ms {
                    signal = Some(FuseSignal::MonotonicRegressed);
                    0
                } else {
                    now.monotonic_ms - prev.monotonic_ms
                }
            },
            _ => 0,
        };
        if let Some(h) = self.halt.as_mut().filter(|h| !h.confirmed) {
            h.elapsed_ms = h.elapsed_ms.saturating_add(add);
        }
        self.checkpoint = Some(now);
        signal
    }

    /// The halt in force, if any, on the time counted so far. A lone halt
    /// whose fuse has run is not in force.
    #[must_use]
    pub fn active_halt(&self, halt_fuse_secs: u64) -> Option<&LatchedHalt> {
        self.halt
            .as_ref()
            .filter(|h| h.confirmed || fuse_ms(halt_fuse_secs).is_none_or(|f| h.elapsed_ms < f))
    }

    /// **The act gate's question:** are agents paused? Read before every
    /// effectful act (CC 4.2.1.1, CC 1.13.6), after [`Self::advance`].
    #[must_use]
    pub fn is_paused(&self, halt_fuse_secs: u64) -> bool {
        self.active_halt(halt_fuse_secs).is_some()
    }

    /// The fuse time a lone halt in force has left, in milliseconds; `None`
    /// if clear, lapsed or confirmed.
    #[must_use]
    pub fn remaining_ms(&self, halt_fuse_secs: u64) -> Option<u64> {
        self.active_halt(halt_fuse_secs)
            .filter(|h| !h.confirmed)
            .map(|h| fuse_ms(halt_fuse_secs).map_or(u64::MAX, |f| f - h.elapsed_ms))
    }

    /// Apply a verified edition-2 row received at `now` (CC 4.2.1.1,
    /// CC 4.2.1.3): the latch first [`advance`](Self::advance)s to `now`;
    /// then a `constitutional` [`InvocationRow`] halts, a counted
    /// `confirmed` / `active` [`LifecycleRow`] confirms or ends the halt whose
    /// row id its `refs.target` names, and a notify or a drill changes
    /// nothing. `received_wall_ms` is the wall instant of receipt, if known;
    /// `halt_fuse_secs` is the bundle in force's ([`HaltRoster::halt_fuse_secs`]).
    ///
    /// One check comes before it, and only here: the latch keeps the row id
    /// each applied `lifecycle:active` names (held or not against a halt in
    /// force), and a halt received after its `valid_until` that one of them
    /// names does not fire (CC 4.2.1.1). A halt received within its
    /// `valid_until`, or at an unknown wall instant, fires as before; a held
    /// resumption ends it only when it is applied again.
    ///
    /// [`HaltRoster::halt_fuse_secs`]: crate::edition2::accord_halt::HaltRoster::halt_fuse_secs
    pub fn apply_forward(
        &mut self,
        row: ForwardRow<'_>,
        now: MonotonicReading,
        received_wall_ms: Option<u64>,
        halt_fuse_secs: u64,
    ) -> LatchOutcome {
        // A regression is the caller's to surface (it reads `advance`); the
        // row is judged on the time counted either way.
        let _ = self.advance(now);
        let step = match row {
            ForwardRow::Invocation(inv) => match inv.kind() {
                InvokeKind::Constitutional
                    if received_wall_ms.is_some_and(|w| w > inv.valid_until())
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
        self.step(step, received_wall_ms, halt_fuse_secs)
    }

    /// The one state machine, on the time already counted.
    fn step(
        &mut self,
        step: Step<'_>,
        received_wall_ms: Option<u64>,
        halt_fuse_secs: u64,
    ) -> LatchOutcome {
        // A lone halt whose fuse has run is gone before anything else is judged:
        // a fresh halt may then pause again, and a late confirmation finds
        // nothing to confirm.
        if self.halt.is_some() && !self.is_paused(halt_fuse_secs) {
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
                    halt_row,
                    elapsed_ms: 0,
                    received_wall_ms,
                    confirmed: false,
                });
                LatchOutcome::Paused
            },
            Step::Confirm(target) => {
                let Some(h) = self.halt.as_mut() else {
                    return LatchOutcome::Unchanged {
                        why: "no halt in force; a confirmation after the fuse confirms nothing",
                    };
                };
                if h.halt_row != target {
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
                if h.halt_row != target {
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

/// The fuse in milliseconds; `None` (it never lapses) when it is too large
/// to state.
fn fuse_ms(halt_fuse_secs: u64) -> Option<u64> {
    halt_fuse_secs.checked_mul(1000)
}

/// The boot identity as 32 lowercase hex digits in JSON.
mod hex_bytes16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let t = <alloc::string::String as Deserialize>::deserialize(d)?;
        let v = hex::decode(&t).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("boot is 16 bytes"))
    }
}

/// The host's monotonic clock and boot identity (FSD-007 §3.3).
#[cfg(feature = "host")]
mod meter;
#[cfg(feature = "host")]
pub use meter::FuseMeter;

#[cfg(test)]
mod tests {
    use super::*;

    /// Steps are driven directly here: the latch's transitions are what is
    /// under test. `apply_forward` over rows read by `edition2::accord_halt` is
    /// replayed in `tests/accord_halt_vectors_v2.rs`.
    fn halt(id: &'static str, row: u8) -> Step<'static> {
        Step::Halt {
            halt_id: id,
            halt_row: [row; 32],
        }
    }

    const BOOT_A: [u8; 16] = [0xa; 16];
    const BOOT_B: [u8; 16] = [0xb; 16];
    const H: u64 = 3_600_000;
    const FUSE: u64 = DEFAULT_HALT_FUSE_SECS;

    fn at(ms: u64, boot: [u8; 16]) -> MonotonicReading {
        MonotonicReading {
            monotonic_ms: ms,
            boot,
        }
    }

    /// Advance to `ms` on boot A, then apply `step`.
    fn apply(l: &mut HaltLatch, step: Step<'_>, ms: u64) -> LatchOutcome {
        l.advance(at(ms, BOOT_A));
        l.step(step, None, FUSE)
    }

    fn paused_at(l: &mut HaltLatch, ms: u64, boot: [u8; 16]) -> bool {
        l.advance(at(ms, boot));
        l.is_paused(FUSE)
    }

    /// F1: a lone halt pauses on receipt and lapses once one fuse has been
    /// COUNTED since receipt.
    #[test]
    fn a_lone_halt_lapses_after_one_counted_fuse() {
        let mut l = HaltLatch::new();
        assert_eq!(apply(&mut l, halt("h1", 1), 1_000), LatchOutcome::Paused);
        assert_eq!(l.remaining_ms(FUSE), Some(FUSE * 1000));
        assert!(paused_at(&mut l, 1_000 + 24 * H - 1, BOOT_A));
        assert_eq!(l.remaining_ms(FUSE), Some(1));
        assert!(
            !paused_at(&mut l, 1_000 + 24 * H, BOOT_A),
            "lapses at 86400 s counted"
        );
        assert_eq!(l.remaining_ms(FUSE), None);
    }

    /// FSD-007 TT-1: no wall-clock change moves the fuse. The latch reads no
    /// wall clock; only counted monotonic time lapses it.
    #[test]
    fn setting_the_wall_clock_forward_does_not_lapse_a_halt() {
        let mut l = HaltLatch::new();
        l.advance(at(0, BOOT_A));
        l.step(halt("h1", 1), Some(1_763_200_000_000), FUSE);
        // The operator sets the wall clock 48 hours ahead; the monotonic clock
        // has run one minute.
        assert!(paused_at(&mut l, 60_000, BOOT_A));
        assert_eq!(l.remaining_ms(FUSE), Some(FUSE * 1000 - 60_000));
    }

    /// A boot change adds zero: after 20 hours counted, a restart under a new
    /// boot (whatever the gap) leaves 4 hours still to count.
    #[test]
    fn a_reboot_counts_nothing_across_the_gap() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), 0);
        assert!(paused_at(&mut l, 20 * H, BOOT_A));
        // New boot: its clock starts low; the gap is unknown.
        assert!(paused_at(&mut l, 5_000, BOOT_B));
        assert_eq!(l.remaining_ms(FUSE), Some(4 * H));
        assert!(paused_at(&mut l, 5_000 + 4 * H - 1, BOOT_B));
        assert!(!paused_at(&mut l, 5_000 + 4 * H, BOOT_B));
    }

    /// A clock that reads lower within one boot adds zero and says so.
    #[test]
    fn a_regressed_clock_counts_nothing_and_is_reported() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), 10 * H);
        assert_eq!(
            l.advance(at(5 * H, BOOT_A)),
            Some(FuseSignal::MonotonicRegressed)
        );
        assert_eq!(l.remaining_ms(FUSE), Some(FUSE * 1000));
        assert_eq!(
            FuseSignal::MonotonicRegressed.token(),
            "monotonic_regressed"
        );
        // Counting resumes from the new checkpoint.
        assert_eq!(l.advance(at(6 * H, BOOT_A)), None);
        assert_eq!(l.remaining_ms(FUSE), Some(FUSE * 1000 - H));
    }

    /// A latch rolled back to an earlier copy carries less counted time: the
    /// halt is extended, never shortened.
    #[test]
    fn a_rolled_back_latch_extends_the_halt() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), 0);
        paused_at(&mut l, 2 * H, BOOT_A);
        let early = l.clone();
        paused_at(&mut l, 20 * H, BOOT_A);
        let mut restored = early;
        // Restored after a reboot: nothing is counted across it.
        assert!(paused_at(&mut restored, 1_000, BOOT_B));
        assert_eq!(restored.remaining_ms(FUSE), Some(22 * H));
    }

    /// F4: a confirmed halt does not lapse; only a resumption ends it.
    #[test]
    fn a_confirmed_halt_stands_until_resumed() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), 0);
        assert_eq!(
            apply(&mut l, Step::Confirm([1; 32]), 6 * H),
            LatchOutcome::Confirmed
        );
        assert!(paused_at(&mut l, 10_000 * H, BOOT_A));
        assert_eq!(l.remaining_ms(FUSE), None);
        assert_eq!(
            apply(&mut l, Step::Resume([1; 32]), 10_000 * H),
            LatchOutcome::Resumed
        );
        assert!(!l.is_paused(FUSE));
    }

    /// A confirmation that arrives after the fuse confirms nothing, and a
    /// fresh halt then pauses again with a fresh fuse.
    #[test]
    fn a_late_confirmation_confirms_nothing() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), 0);
        let late = 24 * H + 1_000;
        assert!(matches!(
            apply(&mut l, Step::Confirm([1; 32]), late),
            LatchOutcome::Unchanged { .. }
        ));
        assert!(!l.is_paused(FUSE));
        assert_eq!(apply(&mut l, halt("h2", 2), late), LatchOutcome::Paused);
        assert_eq!(l.remaining_ms(FUSE), Some(FUSE * 1000));
    }

    /// A majority resumption ends a lone halt too (a stolen sealed row need not
    /// run its fuse).
    #[test]
    fn a_majority_resumption_ends_an_unconfirmed_halt() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), 0);
        assert_eq!(
            apply(&mut l, Step::Resume([1; 32]), 0),
            LatchOutcome::Resumed
        );
        assert!(!l.is_paused(FUSE));
    }

    /// Idempotence and binding: a second halt neither re-pauses nor resets the
    /// fuse; rows naming another halt change nothing; notify/drill never touch
    /// the latch.
    #[test]
    fn only_the_named_halt_moves_and_repeats_change_nothing() {
        let mut l = HaltLatch::new();
        apply(&mut l, halt("h1", 1), 0);
        let later = 12 * H;
        assert!(matches!(
            apply(&mut l, halt("h2", 2), later),
            LatchOutcome::Unchanged { .. }
        ));
        assert_eq!(l.remaining_ms(FUSE), Some(12 * H), "fuse not reset");
        for step in [Step::Confirm([2; 32]), Step::Resume([2; 32]), Step::Inert] {
            assert!(matches!(
                apply(&mut l, step, later),
                LatchOutcome::Unchanged { .. }
            ));
            assert!(l.is_paused(FUSE));
        }
    }

    /// The latch survives a restart: it is the caller's to persist, checkpoint
    /// and counted time included.
    #[test]
    fn the_latch_round_trips_through_serde() {
        let mut l = HaltLatch::new();
        l.advance(at(0, BOOT_A));
        l.step(halt("h1", 1), Some(1_763_200_000_000), FUSE);
        paused_at(&mut l, H, BOOT_A);
        let json = serde_json::to_value(&l).unwrap();
        assert_eq!(json["checkpoint"]["boot"], "0a".repeat(16));
        assert_eq!(json["halt"]["elapsed_ms"], H);
        let back: HaltLatch = serde_json::from_value(json).unwrap();
        assert_eq!(back, l);
    }

    /// Hard cut: a latch of the 23.4 shape (`received_at`, no `elapsed_ms`)
    /// does not deserialize; the host re-applies its held rows instead.
    #[test]
    fn a_latch_of_the_earlier_shape_is_refused() {
        let old = serde_json::json!({
            "halt": {
                "halt_id": "h1",
                "received_at": "2026-10-05T12:00:00Z",
                "confirmed": false,
                "halt_row": vec![1u8; 32]
            }
        });
        assert!(serde_json::from_value::<HaltLatch>(old).is_err());
    }

    /// A fuse too large to state in milliseconds never lapses.
    #[test]
    fn an_enormous_fuse_does_not_wrap() {
        let mut l = HaltLatch::new();
        l.advance(at(0, BOOT_A));
        l.step(halt("h1", 1), None, u64::MAX);
        l.advance(at(u64::MAX, BOOT_A));
        assert!(l.is_paused(u64::MAX));
    }
}
