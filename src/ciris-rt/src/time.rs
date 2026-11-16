//! Time over `ciris:node/clock.monotonic-us` (FSD §5.2: `std::time::Instant`
//! panics on wasm32-unknown-unknown, and `web-time` imports through
//! wasm-bindgen, which the gate refuses).
//!
//! * [`Instant`] is a mechanical swap for `std::time::Instant`, at
//!   microsecond resolution: durations added to it are truncated to whole
//!   microseconds.
//! * [`sleep`], [`sleep_until`], [`timeout`], [`timeout_at`] and
//!   [`interval`] have tokio's shapes. Timers live in the runtime's ordered
//!   timer map and fire on [`crate::Runtime::tick`]; a sleep never ends
//!   early (its deadline is rounded UP to the next microsecond).
//! * [`Interval`]'s default missed-tick behaviour is
//!   [`MissedTickBehavior::Skip`], NOT tokio's `Burst`: a browser tab is
//!   throttled to one timer a minute when hidden and a suspended host does
//!   not tick at all (FSD §2.4 D2), and a burst of every missed tick on
//!   resume is the wrong default for a node. Set `Burst` explicitly where it
//!   is wanted.

use core::fmt;
use core::future::{Future, IntoFuture};
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::pin::Pin;
use core::task::{Context, Poll};
pub use core::time::Duration;

use ciris_host_abi::clock;

use crate::Runtime;

/// A point on `clock.monotonic-us`, in microseconds. Opaque and only
/// comparable within one run of one node, like `std::time::Instant`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Instant({}us)", self.0)
    }
}

fn whole_micros(d: Duration) -> Option<u64> {
    u64::try_from(d.as_micros()).ok()
}

fn ceil_micros(d: Duration) -> u64 {
    let floor = whole_micros(d).unwrap_or(u64::MAX);
    if d.subsec_nanos().is_multiple_of(1_000) {
        floor
    } else {
        floor.saturating_add(1)
    }
}

impl Instant {
    /// Now, from `clock.monotonic-us`.
    #[must_use]
    pub fn now() -> Self {
        Self(clock::monotonic_us())
    }

    /// The instant `us` microseconds after the clock's origin.
    #[must_use]
    pub const fn from_micros(us: u64) -> Self {
        Self(us)
    }

    /// Microseconds since the clock's origin (the raw `monotonic-us`).
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Time from `earlier` to `self`; zero if `earlier` is later (std's
    /// current saturating behaviour).
    #[must_use]
    pub fn duration_since(&self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }

    /// Time from `earlier` to `self`, or `None` if `earlier` is later.
    #[must_use]
    pub fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_micros)
    }

    /// Time from `earlier` to `self`, or zero if `earlier` is later.
    #[must_use]
    pub fn saturating_duration_since(&self, earlier: Self) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }

    /// Time since `self` (reads the clock).
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        Self::now().saturating_duration_since(*self)
    }

    /// `self + d`, or `None` on overflow.
    #[must_use]
    pub fn checked_add(&self, d: Duration) -> Option<Self> {
        whole_micros(d)
            .and_then(|us| self.0.checked_add(us))
            .map(Self)
    }

    /// `self - d`, or `None` on underflow.
    #[must_use]
    pub fn checked_sub(&self, d: Duration) -> Option<Self> {
        whole_micros(d)
            .and_then(|us| self.0.checked_sub(us))
            .map(Self)
    }
}

impl Add<Duration> for Instant {
    type Output = Self;
    /// # Panics
    /// On overflow, as std does.
    fn add(self, d: Duration) -> Self {
        self.checked_add(d)
            .expect("overflow when adding duration to instant")
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        *self = *self + d;
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;
    /// # Panics
    /// On underflow, as std does.
    fn sub(self, d: Duration) -> Self {
        self.checked_sub(d)
            .expect("overflow when subtracting duration from instant")
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, d: Duration) {
        *self = *self - d;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    /// Saturating, as std's `Instant - Instant` is.
    fn sub(self, other: Self) -> Duration {
        self.duration_since(other)
    }
}

/// Wait `d` (rounded up to the next microsecond).
pub fn sleep(d: Duration) -> Sleep {
    Sleep::new(Instant::now().0.saturating_add(ceil_micros(d)))
}

/// Wait until `deadline`.
pub fn sleep_until(deadline: Instant) -> Sleep {
    Sleep::new(deadline.0)
}

/// The future of [`sleep`] / [`sleep_until`]. `Unpin`.
///
/// The first poll reads the clock and finishes at once if the deadline has
/// passed; otherwise it registers a timer, and later polls only check
/// whether the timer fired (no clock read). Dropping it cancels the timer.
#[must_use = "futures do nothing unless awaited"]
pub struct Sleep {
    deadline: u64,
    key: Option<(u64, u64)>,
    rt: Option<Runtime>,
    done: bool,
}

impl fmt::Debug for Sleep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sleep")
            .field("deadline", &Instant(self.deadline))
            .field("done", &self.done)
            .finish()
    }
}

impl Sleep {
    fn new(deadline: u64) -> Self {
        Self {
            deadline,
            key: None,
            rt: None,
            done: false,
        }
    }

    /// The deadline.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        Instant(self.deadline)
    }

    /// Whether the sleep has completed.
    #[must_use]
    pub fn is_elapsed(&self) -> bool {
        self.done
    }

    /// Move the deadline (re-arming a completed sleep).
    pub fn reset(&mut self, deadline: Instant) {
        self.cancel();
        self.deadline = deadline.0;
        self.done = false;
    }

    fn cancel(&mut self) {
        if let (Some(key), Some(rt)) = (self.key.take(), self.rt.as_ref()) {
            rt.timer_remove(key);
        }
    }
}

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.done {
            return Poll::Ready(());
        }
        if let Some(key) = self.key {
            let rt = self
                .rt
                .as_ref()
                .expect("a registered sleep has its runtime");
            if rt.timer_update(key, cx.waker()) {
                return Poll::Pending;
            }
            self.key = None;
            self.done = true;
            return Poll::Ready(());
        }
        if clock::monotonic_us() >= self.deadline {
            self.done = true;
            return Poll::Ready(());
        }
        let rt = Runtime::current();
        self.key = Some(rt.timer_insert(self.deadline, cx.waker().clone()));
        self.rt = Some(rt);
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// [`timeout`] ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed(());

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("deadline has elapsed")
    }
}

impl core::error::Error for Elapsed {}

pin_project_lite::pin_project! {
    /// The future of [`timeout`] / [`timeout_at`].
    #[must_use = "futures do nothing unless awaited"]
    #[derive(Debug)]
    pub struct Timeout<F> {
        #[pin]
        future: F,
        sleep: Sleep,
    }
}

/// Run `future` for at most `d`. The future is polled first, so one that
/// is already ready wins even with a zero `d`.
pub fn timeout<F: IntoFuture>(d: Duration, future: F) -> Timeout<F::IntoFuture> {
    Timeout {
        future: future.into_future(),
        sleep: sleep(d),
    }
}

/// Run `future` until `deadline` at most.
pub fn timeout_at<F: IntoFuture>(deadline: Instant, future: F) -> Timeout<F::IntoFuture> {
    Timeout {
        future: future.into_future(),
        sleep: sleep_until(deadline),
    }
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<F::Output, Elapsed>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Poll::Ready(v) = this.future.poll(cx) {
            return Poll::Ready(Ok(v));
        }
        match Pin::new(this.sleep).poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed(()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// What an [`Interval`] does about ticks it missed (the task was not
/// polled, or the host did not tick, until after them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MissedTickBehavior {
    /// Fire every missed tick at once, then keep the original schedule
    /// (tokio's default).
    Burst,
    /// Fire once now, and schedule the next tick a full period from now.
    Delay,
    /// Fire once now, skip the missed ticks, and keep the original phase:
    /// the next tick is the first scheduled one after now. **The default
    /// here.**
    #[default]
    Skip,
}

/// A periodic timer; see [`interval`].
#[derive(Debug)]
pub struct Interval {
    next: Instant,
    period: Duration,
    period_us: u64,
    sleep: Option<Sleep>,
    behavior: MissedTickBehavior,
}

/// Ticks every `period`; the first tick completes immediately. Missed
/// ticks are [`MissedTickBehavior::Skip`]ped by default (module docs).
///
/// # Panics
/// If `period` is shorter than one microsecond.
#[must_use]
pub fn interval(period: Duration) -> Interval {
    interval_at(Instant::now(), period)
}

/// As [`interval`], with the first tick at `start`.
///
/// # Panics
/// If `period` is shorter than one microsecond.
#[must_use]
pub fn interval_at(start: Instant, period: Duration) -> Interval {
    let period_us = whole_micros(period).unwrap_or(u64::MAX);
    assert!(period_us > 0, "interval period must be at least 1us");
    Interval {
        next: start,
        period,
        period_us,
        sleep: None,
        behavior: MissedTickBehavior::default(),
    }
}

impl Interval {
    /// Wait for the next tick; returns its scheduled instant.
    pub async fn tick(&mut self) -> Instant {
        core::future::poll_fn(|cx| self.poll_tick(cx)).await
    }

    /// Poll for the next tick.
    pub fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<Instant> {
        let next = self.next;
        let sleep = self.sleep.get_or_insert_with(|| sleep_until(next));
        if Pin::new(sleep).poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.sleep = None;
        let now = Instant::now().0;
        let scheduled = self.next.0;
        let p = self.period_us;
        let following = match self.behavior {
            MissedTickBehavior::Burst => scheduled.saturating_add(p),
            MissedTickBehavior::Delay => now.saturating_add(p),
            MissedTickBehavior::Skip => {
                let behind = now.saturating_sub(scheduled);
                scheduled.saturating_add(p.saturating_mul(behind / p + 1))
            },
        };
        self.next = Instant(following);
        Poll::Ready(Instant(scheduled))
    }

    /// Restart the schedule: the next tick is one period from now.
    pub fn reset(&mut self) {
        self.sleep = None;
        self.next = Instant::now() + self.period;
    }

    /// The period.
    #[must_use]
    pub fn period(&self) -> Duration {
        self.period
    }

    /// The missed-tick behaviour.
    #[must_use]
    pub fn missed_tick_behavior(&self) -> MissedTickBehavior {
        self.behavior
    }

    /// Set the missed-tick behaviour.
    pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
        self.behavior = behavior;
    }
}
