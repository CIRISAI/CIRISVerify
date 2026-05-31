//! F-AV-RECONSIDER-DOS primitives — defense surface for P11
//! reconsideration weaponization (CIRISVerify#46, v4.5.0+).
//!
//! Per `docs/FEDERATION_THREAT_MODEL.md` §6.5 F-AV-RECONSIDER-DOS, the
//! attack shape is an organized bloc filing up to 9 reconsiderations
//! per SlashingAttestation against every moderation event affecting
//! their members. The §4.10 recursion bound (CIRISNodeCore `MISSION.md`)
//! is per-SlashingAttestation — it does not bound cross-event
//! harassment from a bloc.
//!
//! This module ships three additive defense primitives the
//! CIRISNodeCore P11 dispatcher consumes at admit-time (CIRISNodeCore#28):
//!
//! 1. [`EventRateLimit`] — max R concurrent reconsiderations active
//!    per moderation event across all filers.
//! 2. [`ActorBudget`] — rolling-window cumulative filing budget per
//!    `requester_id`; depletes per filing, refills on successful
//!    filings.
//! 3. [`HarassmentClusterSignal`] — RATCHET-bound cluster scorer on
//!    `(requester_id, targeted_actor_id)` pairs; fires before §4.10's
//!    existing 3rd-unsuccessful-filing trigger.
//!
//! The composed [`ReconsiderDosGuard`] runs all three at admit-time
//! and returns a typed [`ReconsiderRejection`] on any failure — the
//! CIRISNodeCore P11 dispatcher converts this into a CEG §10.0.1
//! envelope via the new `CegErrorCode::ReconsiderationRateLimited` /
//! `ActorBudgetExhausted` / `HarassmentClusterDetected` codes.
//!
//! ## Clock surface
//!
//! All time-bound primitives accept an injectable `now_ms: u64`
//! parameter rather than reading the wall clock internally. This
//! preserves the existing CIRISVerify discipline (no `Date.now()` in
//! libraries; tests inject deterministic clocks).
//!
//! ## What this module does NOT do
//!
//! - Persist the budget / counters — caller is responsible for the
//!   storage backend (in-process for tests, persist-backed in
//!   production via CIRISPersist's federation_directory surface).
//! - Wire CEG error envelope translation — that's the P11
//!   dispatcher's job at the HTTP boundary (CIRISNodeCore#28).
//! - Score harassment clusters across the full RATCHET signal
//!   matrix — this module ships the local cluster scorer; the
//!   RATCHET cross-event correlation runs separately at
//!   `CIRISLensCore` (CIRISLensCore#29 multimedia detector path is
//!   parallel surface).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Default per-event concurrent-reconsideration limit. The §4.10
/// upper bound (3 grounds × 3 evidence-hashes per filer) means R=10
/// admits one full filing-set from one filer + headroom; an
/// organized bloc hitting R=10 from multiple filers gets rejected.
pub const DEFAULT_EVENT_RATE_LIMIT: usize = 10;

/// Default per-actor budget. A budget of 30 reconsiderations
/// rolling over 7 days admits a steady-state honest filer at ~1
/// per 6 hours (legitimate participation rate) while bounding the
/// bloc's per-actor harassment scale.
pub const DEFAULT_ACTOR_BUDGET: u32 = 30;

/// Default rolling window (7 days, in milliseconds).
pub const DEFAULT_BUDGET_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Default cluster-score threshold for harassment detection. The
/// sub-3-per-event threshold (§6.5 F-AV-RECONSIDER-DOS mitigation
/// rule 3) is encoded as a cluster score of 2.0 — two filings from
/// the same `requester_id` against the same `target_id` across any
/// number of distinct events is the floor.
pub const DEFAULT_HARASSMENT_CLUSTER_THRESHOLD: f64 = 2.0;

/// Per-event concurrent-reconsideration limit.
///
/// Tracks active filings per `event_id`; admission rejects when
/// the active count would exceed `limit`. Caller releases on
/// outcome via [`Self::release`].
#[derive(Debug, Clone)]
pub struct EventRateLimit {
    active: HashMap<String, usize>,
    limit: usize,
}

impl EventRateLimit {
    /// Construct with a custom limit.
    #[must_use]
    pub fn with_limit(limit: usize) -> Self {
        Self {
            active: HashMap::new(),
            limit,
        }
    }

    /// Construct with [`DEFAULT_EVENT_RATE_LIMIT`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_EVENT_RATE_LIMIT)
    }

    /// Attempt to admit one filing for `event_id`.
    pub fn admit(&mut self, event_id: &str) -> Result<(), EventRateLimited> {
        let entry = self.active.entry(event_id.to_string()).or_insert(0);
        if *entry >= self.limit {
            return Err(EventRateLimited {
                event_id: event_id.to_string(),
                active: *entry,
                limit: self.limit,
            });
        }
        *entry += 1;
        Ok(())
    }

    /// Release one filing slot for `event_id` (called when the
    /// filing's adjudication completes, regardless of outcome).
    pub fn release(&mut self, event_id: &str) {
        if let Some(entry) = self.active.get_mut(event_id) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                self.active.remove(event_id);
            }
        }
    }

    /// Currently active filing count for `event_id`.
    #[must_use]
    pub fn active(&self, event_id: &str) -> usize {
        self.active.get(event_id).copied().unwrap_or(0)
    }
}

impl Default for EventRateLimit {
    fn default() -> Self {
        Self::new()
    }
}

/// Rejection from [`EventRateLimit::admit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRateLimited {
    /// Which event hit the limit.
    pub event_id: String,
    /// Active count at the moment of rejection.
    pub active: usize,
    /// The configured limit.
    pub limit: usize,
}

/// Rolling-window cumulative filing budget per `requester_id`.
///
/// Tracks filing timestamps per actor; the budget for an actor at a
/// given moment is `budget_cap - count(filings within window_ms of now)`.
/// Old filings fall out of the window opportunistically on admit.
#[derive(Debug, Clone)]
pub struct ActorBudget {
    filings: HashMap<String, Vec<u64>>, // requester_id → ascending timestamps_ms
    budget_cap: u32,
    window_ms: u64,
}

impl ActorBudget {
    /// Construct with custom cap + window.
    #[must_use]
    pub fn with_config(budget_cap: u32, window_ms: u64) -> Self {
        Self {
            filings: HashMap::new(),
            budget_cap,
            window_ms,
        }
    }

    /// Construct with [`DEFAULT_ACTOR_BUDGET`] + [`DEFAULT_BUDGET_WINDOW_MS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DEFAULT_ACTOR_BUDGET, DEFAULT_BUDGET_WINDOW_MS)
    }

    /// Attempt to admit one filing for `requester_id` at `now_ms`.
    /// Opportunistically evicts filings older than `window_ms`.
    pub fn admit(&mut self, requester_id: &str, now_ms: u64) -> Result<(), ActorBudgetExhausted> {
        let window = self.window_ms;
        let cap = self.budget_cap;
        let entry = self.filings.entry(requester_id.to_string()).or_default();
        // Evict expired entries.
        let cutoff = now_ms.saturating_sub(window);
        entry.retain(|&ts| ts >= cutoff);
        let used = u32::try_from(entry.len()).unwrap_or(u32::MAX);
        if used >= cap {
            return Err(ActorBudgetExhausted {
                requester_id: requester_id.to_string(),
                used,
                budget: cap,
                window_ms: window,
            });
        }
        entry.push(now_ms);
        Ok(())
    }

    /// Refill some budget for `requester_id` when a filing reverses
    /// a moderation decision (successful outcome). Removes the
    /// most-recent filing timestamp from the actor's window so the
    /// actor regains one filing slot.
    pub fn refill_on_success(&mut self, requester_id: &str) {
        if let Some(entry) = self.filings.get_mut(requester_id) {
            entry.pop();
            if entry.is_empty() {
                self.filings.remove(requester_id);
            }
        }
    }

    /// Currently-used budget for `requester_id` at `now_ms`.
    #[must_use]
    pub fn used(&self, requester_id: &str, now_ms: u64) -> u32 {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.filings
            .get(requester_id)
            .map(|v| {
                u32::try_from(v.iter().filter(|&&ts| ts >= cutoff).count()).unwrap_or(u32::MAX)
            })
            .unwrap_or(0)
    }
}

impl Default for ActorBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// Rejection from [`ActorBudget::admit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorBudgetExhausted {
    /// Which actor exhausted their budget.
    pub requester_id: String,
    /// Filings counted within the rolling window.
    pub used: u32,
    /// The configured budget cap.
    pub budget: u32,
    /// The rolling-window size in milliseconds.
    pub window_ms: u64,
}

/// Cross-event harassment-pattern signal on
/// `(requester_id, targeted_actor_id)` pairs.
///
/// Maintains a per-pair counter; the cluster score is the number
/// of distinct events the requester has filed against the target
/// within the rolling window. Fires when the cluster score reaches
/// or exceeds the threshold — sub-3-per-event by design (the §4.10
/// 3rd-filing trigger handles the per-SlashingAttestation case;
/// this scorer catches the cross-event "1 per target × K targets"
/// shape).
#[derive(Debug, Clone)]
pub struct HarassmentClusterSignal {
    // (requester_id, target_id) → set of distinct event_ids with their timestamps
    pairs: HashMap<(String, String), HashMap<String, u64>>,
    threshold: f64,
    window_ms: u64,
}

impl HarassmentClusterSignal {
    /// Construct with custom threshold + window.
    #[must_use]
    pub fn with_config(threshold: f64, window_ms: u64) -> Self {
        Self {
            pairs: HashMap::new(),
            threshold,
            window_ms,
        }
    }

    /// Construct with [`DEFAULT_HARASSMENT_CLUSTER_THRESHOLD`] +
    /// [`DEFAULT_BUDGET_WINDOW_MS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_HARASSMENT_CLUSTER_THRESHOLD,
            DEFAULT_BUDGET_WINDOW_MS,
        )
    }

    /// Record a filing observation. The pair counter increments
    /// once per distinct `(requester_id, target_id, event_id)`
    /// triple within the window. Returns the cluster score after
    /// the record.
    pub fn record(
        &mut self,
        requester_id: &str,
        target_id: &str,
        event_id: &str,
        now_ms: u64,
    ) -> f64 {
        let key = (requester_id.to_string(), target_id.to_string());
        let entry = self.pairs.entry(key).or_default();
        // Evict expired event observations.
        let cutoff = now_ms.saturating_sub(self.window_ms);
        entry.retain(|_, &mut ts| ts >= cutoff);
        entry.insert(event_id.to_string(), now_ms);
        entry.len() as f64
    }

    /// Cluster score for `(requester_id, target_id)` at `now_ms`,
    /// without recording a new observation.
    #[must_use]
    pub fn score(&self, requester_id: &str, target_id: &str, now_ms: u64) -> f64 {
        let key = (requester_id.to_string(), target_id.to_string());
        self.pairs
            .get(&key)
            .map(|m| {
                let cutoff = now_ms.saturating_sub(self.window_ms);
                m.values().filter(|&&ts| ts >= cutoff).count() as f64
            })
            .unwrap_or(0.0)
    }

    /// Check whether a (requester, target) pair has reached the
    /// harassment threshold. Doesn't record a new observation —
    /// use [`Self::record`] followed by [`Self::score`] for the
    /// record-then-check pattern.
    pub fn check(
        &self,
        requester_id: &str,
        target_id: &str,
        now_ms: u64,
    ) -> Result<(), HarassmentClusterDetected> {
        let score = self.score(requester_id, target_id, now_ms);
        if score >= self.threshold {
            Err(HarassmentClusterDetected {
                requester_id: requester_id.to_string(),
                target_id: target_id.to_string(),
                cluster_score: score,
                threshold: self.threshold,
            })
        } else {
            Ok(())
        }
    }
}

impl Default for HarassmentClusterSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Rejection from [`HarassmentClusterSignal::check`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarassmentClusterDetected {
    /// Filing actor.
    pub requester_id: String,
    /// Targeted actor.
    pub target_id: String,
    /// Cluster score at rejection time.
    pub cluster_score: f64,
    /// The configured threshold.
    pub threshold: f64,
}

/// Composed defense — runs all three primitives at admit-time.
/// Returns the first rejection encountered, or `Ok(())` after
/// committing the filing across all three trackers.
#[derive(Debug, Default)]
pub struct ReconsiderDosGuard {
    /// Per-event concurrent-reconsideration limit.
    pub rate_limit: EventRateLimit,
    /// Per-actor rolling-window cumulative budget.
    pub actor_budget: ActorBudget,
    /// Cross-event harassment-pattern signal.
    pub harassment: HarassmentClusterSignal,
}

/// Typed rejection from [`ReconsiderDosGuard::admit_filing`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReconsiderRejection {
    /// Event-bound rate limit exceeded.
    EventRateLimited(EventRateLimited),
    /// Actor's rolling budget exhausted.
    ActorBudgetExhausted(ActorBudgetExhausted),
    /// Harassment cluster detected.
    HarassmentClusterDetected(HarassmentClusterDetected),
}

impl ReconsiderDosGuard {
    /// Construct with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Composed pre-admit check. Order:
    /// 1. Harassment cluster check (cheapest; no state mutation
    ///    until all three pass);
    /// 2. Actor budget check;
    /// 3. Event rate-limit check.
    ///
    /// On success, all three trackers commit the filing in one
    /// transaction. On failure, no state is mutated — the caller
    /// may retry with different parameters.
    pub fn admit_filing(
        &mut self,
        event_id: &str,
        requester_id: &str,
        target_id: &str,
        now_ms: u64,
    ) -> Result<(), ReconsiderRejection> {
        // 1. Harassment cluster — read-only check first.
        self.harassment
            .check(requester_id, target_id, now_ms)
            .map_err(ReconsiderRejection::HarassmentClusterDetected)?;

        // 2. Actor budget — commits a filing; must rollback if rate
        // limit fires.
        self.actor_budget
            .admit(requester_id, now_ms)
            .map_err(ReconsiderRejection::ActorBudgetExhausted)?;

        // 3. Event rate limit — last check.
        if let Err(e) = self.rate_limit.admit(event_id) {
            // Rollback the budget consumption.
            self.actor_budget.refill_on_success(requester_id);
            return Err(ReconsiderRejection::EventRateLimited(e));
        }

        // 4. Commit the cluster observation now that all gates passed.
        self.harassment
            .record(requester_id, target_id, event_id, now_ms);
        Ok(())
    }

    /// Record an outcome on an admitted filing.
    ///
    /// - [`FilingOutcome::Successful`] refills one budget slot for
    ///   the requester (the filing reversed a moderation decision).
    /// - [`FilingOutcome::Rejected`] does not refill.
    ///
    /// Both outcomes release the event rate-limit slot.
    pub fn record_outcome(&mut self, event_id: &str, requester_id: &str, outcome: FilingOutcome) {
        self.rate_limit.release(event_id);
        if outcome == FilingOutcome::Successful {
            self.actor_budget.refill_on_success(requester_id);
        }
    }
}

/// Outcome of an admitted filing — drives the budget-refill rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilingOutcome {
    /// The reconsideration reversed the underlying moderation decision.
    Successful,
    /// The reconsideration was adjudicated against the filer.
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: u64 = 60 * 60 * 1000;
    const DAY_MS: u64 = 24 * HOUR_MS;
    const T0: u64 = 1_700_000_000_000; // arbitrary base time

    // ---- EventRateLimit ----

    #[test]
    fn event_rate_limit_admits_up_to_cap_then_rejects() {
        let mut rl = EventRateLimit::with_limit(3);
        for _ in 0..3 {
            rl.admit("evt-1").unwrap();
        }
        let err = rl.admit("evt-1").unwrap_err();
        assert_eq!(err.event_id, "evt-1");
        assert_eq!(err.active, 3);
        assert_eq!(err.limit, 3);
    }

    #[test]
    fn event_rate_limit_release_frees_slot() {
        let mut rl = EventRateLimit::with_limit(2);
        rl.admit("evt-1").unwrap();
        rl.admit("evt-1").unwrap();
        assert!(rl.admit("evt-1").is_err());
        rl.release("evt-1");
        // Slot freed — admit succeeds again.
        rl.admit("evt-1").unwrap();
    }

    #[test]
    fn event_rate_limit_separate_events_dont_interfere() {
        let mut rl = EventRateLimit::with_limit(2);
        rl.admit("evt-1").unwrap();
        rl.admit("evt-1").unwrap();
        // Different event has its own budget.
        rl.admit("evt-2").unwrap();
        rl.admit("evt-2").unwrap();
        assert!(rl.admit("evt-1").is_err());
        assert!(rl.admit("evt-2").is_err());
    }

    // ---- ActorBudget ----

    #[test]
    fn actor_budget_admits_up_to_cap_then_rejects() {
        let mut b = ActorBudget::with_config(3, DAY_MS);
        for i in 0..3 {
            b.admit("alice", T0 + i * HOUR_MS).unwrap();
        }
        let err = b.admit("alice", T0 + 4 * HOUR_MS).unwrap_err();
        assert_eq!(err.requester_id, "alice");
        assert_eq!(err.used, 3);
        assert_eq!(err.budget, 3);
    }

    #[test]
    fn actor_budget_evicts_expired_entries() {
        let mut b = ActorBudget::with_config(3, DAY_MS);
        for i in 0..3 {
            b.admit("alice", T0 + i * HOUR_MS).unwrap();
        }
        // Move past the window — all three should evict.
        let future = T0 + 2 * DAY_MS;
        b.admit("alice", future).unwrap();
        assert_eq!(b.used("alice", future), 1);
    }

    #[test]
    fn actor_budget_refill_on_success_returns_one_slot() {
        let mut b = ActorBudget::with_config(2, DAY_MS);
        b.admit("alice", T0).unwrap();
        b.admit("alice", T0 + HOUR_MS).unwrap();
        assert!(b.admit("alice", T0 + 2 * HOUR_MS).is_err());
        b.refill_on_success("alice");
        // One slot freed — admit succeeds again.
        b.admit("alice", T0 + 2 * HOUR_MS).unwrap();
    }

    // ---- HarassmentClusterSignal ----

    #[test]
    fn harassment_cluster_fires_at_threshold() {
        let mut s = HarassmentClusterSignal::with_config(2.0, DAY_MS);
        // Single (requester, target) hit on one event — below threshold.
        s.record("alice", "bob", "evt-1", T0);
        assert!(s.check("alice", "bob", T0).is_ok());
        // Second event from same alice against same bob — threshold hit.
        s.record("alice", "bob", "evt-2", T0 + HOUR_MS);
        assert!(s.check("alice", "bob", T0 + HOUR_MS).is_err());
    }

    #[test]
    fn harassment_cluster_distinct_events_not_repeated_filings() {
        let mut s = HarassmentClusterSignal::with_config(3.0, DAY_MS);
        // Three filings against the SAME event count as one (the
        // §4.10 per-SlashingAttestation case is not what this
        // detector targets).
        s.record("alice", "bob", "evt-1", T0);
        s.record("alice", "bob", "evt-1", T0 + HOUR_MS);
        s.record("alice", "bob", "evt-1", T0 + 2 * HOUR_MS);
        assert!(s.check("alice", "bob", T0 + 2 * HOUR_MS).is_ok());
        // A second distinct event lifts the score.
        s.record("alice", "bob", "evt-2", T0 + 3 * HOUR_MS);
        assert!(s.check("alice", "bob", T0 + 3 * HOUR_MS).is_ok()); // 2 < 3
                                                                    // Third event trips the threshold.
        s.record("alice", "bob", "evt-3", T0 + 4 * HOUR_MS);
        assert!(s.check("alice", "bob", T0 + 4 * HOUR_MS).is_err());
    }

    #[test]
    fn harassment_cluster_different_targets_independent() {
        let mut s = HarassmentClusterSignal::with_config(2.0, DAY_MS);
        s.record("alice", "bob", "evt-1", T0);
        s.record("alice", "carol", "evt-1", T0);
        // (alice, bob) and (alice, carol) are separate pairs.
        assert!(s.check("alice", "bob", T0).is_ok());
        assert!(s.check("alice", "carol", T0).is_ok());
    }

    // ---- Composed ReconsiderDosGuard ----

    /// §6.5 F-AV-RECONSIDER-DOS bloc-of-9 mitigation: an organized
    /// bloc that mass-files against ONE event hits the per-event
    /// rate limit even before §4.10 fires.
    #[test]
    fn bloc_against_one_event_hits_rate_limit() {
        let mut g = ReconsiderDosGuard::default();
        // 10 distinct filers (bloc members) against same event.
        for i in 0..DEFAULT_EVENT_RATE_LIMIT {
            let actor = format!("bloc-actor-{i}");
            g.admit_filing("event-X", &actor, "victim-1", T0 + i as u64 * 1000)
                .unwrap();
        }
        let err = g
            .admit_filing("event-X", "bloc-actor-11", "victim-1", T0 + 100_000)
            .unwrap_err();
        assert!(matches!(err, ReconsiderRejection::EventRateLimited(_)));
    }

    /// §6.5 F-AV-RECONSIDER-DOS cross-event harassment mitigation:
    /// one actor filing against K distinct events targeting the
    /// same victim hits the harassment cluster signal at threshold.
    #[test]
    fn single_actor_cross_event_targeting_hits_harassment_cluster() {
        let mut g = ReconsiderDosGuard::default();
        // First filing — admitted, increments cluster.
        g.admit_filing("event-A", "harasser", "victim-1", T0)
            .unwrap();
        // Second filing against same victim, different event — admitted,
        // increments cluster to threshold.
        g.admit_filing("event-B", "harasser", "victim-1", T0 + HOUR_MS)
            .unwrap();
        // Third filing now rejected: cluster check fires BEFORE
        // budget or rate limit.
        let err = g
            .admit_filing("event-C", "harasser", "victim-1", T0 + 2 * HOUR_MS)
            .unwrap_err();
        assert!(matches!(
            err,
            ReconsiderRejection::HarassmentClusterDetected(_)
        ));
    }

    /// §6.5 F-AV-RECONSIDER-DOS budget exhaustion: a single actor
    /// filing many low-coordination reconsiderations (different
    /// targets each time, staying below harassment cluster) hits
    /// the rolling budget.
    #[test]
    fn single_actor_high_volume_hits_budget() {
        let mut g = ReconsiderDosGuard::default();
        // Fill budget by filing against different targets +
        // different events (so harassment cluster doesn't fire).
        for i in 0..DEFAULT_ACTOR_BUDGET {
            let event = format!("event-{i}");
            let target = format!("target-{i}");
            g.admit_filing(&event, "high-volume-actor", &target, T0 + i as u64 * 1000)
                .unwrap();
        }
        let err = g
            .admit_filing(
                "event-final",
                "high-volume-actor",
                "target-final",
                T0 + 100_000,
            )
            .unwrap_err();
        assert!(matches!(err, ReconsiderRejection::ActorBudgetExhausted(_)));
    }

    /// Outcome refills: a successful filing returns budget; a
    /// rejected filing does not.
    #[test]
    fn outcome_success_refills_budget_failure_does_not() {
        let mut g = ReconsiderDosGuard::default();
        for i in 0..DEFAULT_ACTOR_BUDGET {
            let event = format!("event-{i}");
            let target = format!("target-{i}");
            g.admit_filing(&event, "actor", &target, T0 + i as u64 * 1000)
                .unwrap();
        }
        // At cap.
        assert!(g
            .admit_filing("event-next", "actor", "target-next", T0 + 100_000)
            .is_err());

        // Rejected outcome — budget NOT refilled.
        g.record_outcome("event-0", "actor", FilingOutcome::Rejected);
        // Still rejected at next event due to budget.
        // (Cluster won't fire because target-next is fresh.)
        let err = g
            .admit_filing("event-next", "actor", "target-next", T0 + 200_000)
            .unwrap_err();
        assert!(matches!(err, ReconsiderRejection::ActorBudgetExhausted(_)));

        // Successful outcome — budget refilled.
        g.record_outcome("event-1", "actor", FilingOutcome::Successful);
        g.admit_filing("event-next-2", "actor", "target-next-2", T0 + 300_000)
            .unwrap();
    }

    /// Atomicity: if event-rate-limit fires after budget commit,
    /// the budget must roll back so the actor isn't charged for a
    /// rejected admission.
    #[test]
    fn guard_admit_is_atomic_under_rate_limit_failure() {
        let mut g = ReconsiderDosGuard {
            rate_limit: EventRateLimit::with_limit(1),
            actor_budget: ActorBudget::with_config(5, DAY_MS),
            harassment: HarassmentClusterSignal::with_config(100.0, DAY_MS),
        };
        // Fill the rate limit with a different actor's filing.
        g.admit_filing("event-X", "other-actor", "v1", T0).unwrap();
        // Now alice tries — rate-limited.
        let err = g
            .admit_filing("event-X", "alice", "v2", T0 + 1000)
            .unwrap_err();
        assert!(matches!(err, ReconsiderRejection::EventRateLimited(_)));
        // Alice's budget should be untouched (rolled back).
        assert_eq!(g.actor_budget.used("alice", T0 + 1000), 0);
    }

    /// JSON round-trip of the rejection envelope (the CIRISNodeCore
    /// P11 dispatcher serializes this to a CEG §10.0.1 envelope at
    /// the HTTP boundary).
    #[test]
    fn rejection_envelope_json_round_trip() {
        let r = ReconsiderRejection::EventRateLimited(EventRateLimited {
            event_id: "evt-1".into(),
            active: 10,
            limit: 10,
        });
        let j = serde_json::to_string(&r).unwrap();
        let back: ReconsiderRejection = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
