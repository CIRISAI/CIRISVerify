//! The constitutional halt latch: what a node does with a verified accord row
//! (CIRISVerify#305; CIRISConstitution#146 as amended, CC 4.2.1.1 / 4.2.1.3
//! rc7; model `formal/accord_halt/AccordHaltFuse.tla`).
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
//! [`crate::accord_halt_latch::HaltLatch::apply`] takes a
//! [`crate::accord_halt_latch::VerifiedInvocation`], which only
//! [`crate::accord_halt_latch::verify_for_latch`] can produce — the same discipline as
//! `storage::HigherTierMint`. A call site cannot pause or un-pause agents with
//! a row it did not verify against its own pinned roster.
//!
//! ## What stays the caller's
//!
//! The clock (`now`), persisting the latch across restarts (it is
//! `Serialize`), the roster, and per-kind dedup of `invocation_id` within
//! `valid_until` ([`crate::humanity_accord::InvocationDedup`]).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::humanity_accord::{verify_invocation, Invocation, InvocationError, InvocationKind};
use crate::threshold::{ThresholdMember, ThresholdSignature};

/// `halt_fuse_secs` when the charter does not carry it (CC 5.3.4: the shipped
/// default; the 2026-10-04 genesis charter omits it, and that is not an error).
pub const DEFAULT_HALT_FUSE_SECS: u64 = 86_400;

/// An invocation that passed [`verify_invocation`] against the caller's pinned
/// roster. Only [`verify_for_latch`] constructs one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInvocation {
    invocation: Invocation,
}

impl VerifiedInvocation {
    /// The verified invocation.
    #[must_use]
    pub fn invocation(&self) -> &Invocation {
        &self.invocation
    }
}

/// Verify an invocation for the latch: [`verify_invocation`] at its kind's
/// threshold, against `roster` — which MUST be the caller's own pinned roster.
///
/// # Errors
///
/// Whatever [`verify_invocation`] refuses.
pub fn verify_for_latch(
    invocation: &Invocation,
    roster: &[ThresholdMember],
    signatures: &[ThresholdSignature],
) -> Result<VerifiedInvocation, InvocationError> {
    verify_invocation(invocation, roster, signatures)?;
    Ok(VerifiedInvocation {
        invocation: invocation.clone(),
    })
}

/// The halt currently latched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatchedHalt {
    /// The halt's `invocation_id`.
    pub halt_id: String,
    /// When THIS node received it — the fuse's origin.
    pub received_at: DateTime<Utc>,
    /// Whether a strict majority confirmed it before the fuse ran out.
    pub confirmed: bool,
}

/// What [`HaltLatch::apply`] did with a verified row.
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

    /// Apply a verified row received at `now`.
    pub fn apply(
        &mut self,
        row: &VerifiedInvocation,
        now: DateTime<Utc>,
        halt_fuse_secs: u64,
    ) -> LatchOutcome {
        // A lone halt whose fuse has run is gone before anything else is judged:
        // a fresh halt may then pause again, and a late confirmation finds
        // nothing to confirm.
        if self.halt.is_some() && !self.is_paused(now, halt_fuse_secs) {
            self.halt = None;
        }
        let inv = &row.invocation;
        match inv.invocation_kind {
            InvocationKind::Constitutional => {
                if self.halt.is_some() {
                    return LatchOutcome::Unchanged {
                        why: "already paused; a second halt changes nothing and does not reset the fuse",
                    };
                }
                self.halt = Some(LatchedHalt {
                    halt_id: inv.invocation_id.clone(),
                    received_at: now,
                    confirmed: false,
                });
                LatchOutcome::Paused
            },
            InvocationKind::LifecycleConfirmed => {
                let Some(h) = self.halt.as_mut() else {
                    return LatchOutcome::Unchanged {
                        why: "no halt in force; a confirmation after the fuse confirms nothing",
                    };
                };
                if inv.confirms_halt_id.as_deref() != Some(h.halt_id.as_str()) {
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
            InvocationKind::LifecycleActive => {
                let Some(h) = self.halt.as_ref() else {
                    return LatchOutcome::Unchanged {
                        why: "no halt in force",
                    };
                };
                if inv.resumes_halt_id.as_deref() != Some(h.halt_id.as_str()) {
                    return LatchOutcome::Unchanged {
                        why: "resumption names a different halt",
                    };
                }
                self.halt = None;
                LatchOutcome::Resumed
            },
            InvocationKind::Notify | InvocationKind::Drill => LatchOutcome::Unchanged {
                why: "notify and drill never touch the latch",
            },
        }
    }
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

    /// Rows are built directly here: the latch's transitions are what is under
    /// test, and `verify_for_latch` is exercised with real signatures in
    /// `accord_genesis`'s tests.
    fn row(kind: InvocationKind, id: &str, names: Option<&str>) -> VerifiedInvocation {
        VerifiedInvocation {
            invocation: Invocation {
                invocation_kind: kind,
                invocation_id: id.to_string(),
                resumes_halt_id: matches!(kind, InvocationKind::LifecycleActive)
                    .then(|| names.unwrap().to_string()),
                confirms_halt_id: matches!(kind, InvocationKind::LifecycleConfirmed)
                    .then(|| names.unwrap().to_string()),
                nonce: "N".repeat(43),
                // Deliberately absurd: the fuse must not read this.
                asserted_at: "1999-01-01T00:00:00.000Z".to_string(),
                valid_until: "2999-01-01T00:00:00.000Z".to_string(),
                payload_sha256: "00".repeat(32),
            },
        }
    }

    const FUSE: u64 = DEFAULT_HALT_FUSE_SECS;
    const T0: &str = "2026-10-05T12:00:00Z";

    /// F1: a lone halt pauses on receipt and lapses one fuse after RECEIPT —
    /// regardless of the signed asserted_at (1999 here).
    #[test]
    fn a_lone_halt_lapses_one_fuse_after_receipt() {
        let mut l = HaltLatch::new();
        let halt = row(InvocationKind::Constitutional, "h1", None);
        assert_eq!(l.apply(&halt, t(T0), FUSE), LatchOutcome::Paused);
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
        l.apply(
            &row(InvocationKind::Constitutional, "h1", None),
            t(T0),
            FUSE,
        );
        assert_eq!(
            l.apply(
                &row(InvocationKind::LifecycleConfirmed, "c1", Some("h1")),
                t("2026-10-05T18:00:00Z"),
                FUSE
            ),
            LatchOutcome::Confirmed
        );
        assert!(l.is_paused(t("2030-01-01T00:00:00Z"), FUSE));
        assert_eq!(l.lapses_at(FUSE), None);
        assert_eq!(
            l.apply(
                &row(InvocationKind::LifecycleActive, "r1", Some("h1")),
                t("2030-01-01T00:00:00Z"),
                FUSE
            ),
            LatchOutcome::Resumed
        );
        assert!(!l.is_paused(t("2030-01-01T00:00:00Z"), FUSE));
    }

    /// A confirmation that arrives after the fuse confirms nothing, and a
    /// fresh halt then pauses again with a fresh fuse.
    #[test]
    fn a_late_confirmation_confirms_nothing() {
        let mut l = HaltLatch::new();
        l.apply(
            &row(InvocationKind::Constitutional, "h1", None),
            t(T0),
            FUSE,
        );
        let late = t("2026-10-06T12:00:01Z");
        assert!(matches!(
            l.apply(
                &row(InvocationKind::LifecycleConfirmed, "c1", Some("h1")),
                late,
                FUSE
            ),
            LatchOutcome::Unchanged { .. }
        ));
        assert!(!l.is_paused(late, FUSE));
        assert_eq!(
            l.apply(&row(InvocationKind::Constitutional, "h2", None), late, FUSE),
            LatchOutcome::Paused
        );
        assert_eq!(l.lapses_at(FUSE), Some(late + Duration::seconds(86_400)));
    }

    /// A majority resumption ends a lone halt too (a stolen sealed row need not
    /// run its fuse).
    #[test]
    fn a_majority_resumption_ends_an_unconfirmed_halt() {
        let mut l = HaltLatch::new();
        l.apply(
            &row(InvocationKind::Constitutional, "h1", None),
            t(T0),
            FUSE,
        );
        assert_eq!(
            l.apply(
                &row(InvocationKind::LifecycleActive, "r1", Some("h1")),
                t(T0),
                FUSE
            ),
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
        l.apply(
            &row(InvocationKind::Constitutional, "h1", None),
            t(T0),
            FUSE,
        );
        let later = t("2026-10-06T00:00:00Z");
        assert!(matches!(
            l.apply(
                &row(InvocationKind::Constitutional, "h2", None),
                later,
                FUSE
            ),
            LatchOutcome::Unchanged { .. }
        ));
        assert_eq!(
            l.lapses_at(FUSE),
            Some(t("2026-10-06T12:00:00Z")),
            "fuse not reset"
        );
        for r in [
            row(InvocationKind::LifecycleConfirmed, "c", Some("h2")),
            row(InvocationKind::LifecycleActive, "r", Some("h2")),
            row(InvocationKind::Notify, "n", None),
            row(InvocationKind::Drill, "d", None),
        ] {
            assert!(matches!(
                l.apply(&r, later, FUSE),
                LatchOutcome::Unchanged { .. }
            ));
            assert!(l.is_paused(later, FUSE));
        }
    }

    /// The latch survives a restart: it is the caller's to persist.
    #[test]
    fn the_latch_round_trips_through_serde() {
        let mut l = HaltLatch::new();
        l.apply(
            &row(InvocationKind::Constitutional, "h1", None),
            t(T0),
            FUSE,
        );
        let back: HaltLatch = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back, l);
        assert!(back.is_paused(t(T0), FUSE));
    }

    /// An absurd fuse saturates rather than overflowing into the past.
    #[test]
    fn an_enormous_fuse_does_not_wrap() {
        let mut l = HaltLatch::new();
        l.apply(
            &row(InvocationKind::Constitutional, "h1", None),
            t(T0),
            u64::MAX,
        );
        assert!(l.is_paused(t("9999-01-01T00:00:00Z"), u64::MAX));
    }
}
