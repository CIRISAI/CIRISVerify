use std::cell::{Cell, RefCell};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use ciris_rt::time::{
    interval, interval_at, sleep, sleep_until, timeout, Duration, Instant, MissedTickBehavior,
};
use ciris_rt::{spawn, Runtime};

use crate::support::Scripted;

#[test]
fn instant_is_a_std_shaped_swap() {
    let h = Scripted::new(0);
    h.install();
    h.set_now(10_000);
    let a = Instant::now();
    assert_eq!(a.as_micros(), 10_000);
    let b = a + Duration::from_millis(5);
    assert_eq!(b - a, Duration::from_millis(5));
    assert_eq!(
        a - b,
        Duration::ZERO,
        "Instant - Instant saturates like std"
    );
    assert_eq!(b.duration_since(a), Duration::from_millis(5));
    assert_eq!(a.checked_duration_since(b), None);
    assert_eq!(a.saturating_duration_since(b), Duration::ZERO);
    assert_eq!(
        a.checked_add(Duration::from_micros(1)),
        Some(Instant::from_micros(10_001))
    );
    assert_eq!(a.checked_sub(Duration::from_millis(11)), None);
    assert_eq!(
        Instant::from_micros(u64::MAX).checked_add(Duration::from_micros(1)),
        None
    );
    let mut c = a;
    c += Duration::from_micros(3);
    c -= Duration::from_micros(1);
    assert_eq!(c - Duration::from_micros(2), a);
    assert!(a < b && b > a);
    let hash = |i: Instant| {
        let mut s = DefaultHasher::new();
        i.hash(&mut s);
        s.finish()
    };
    assert_eq!(hash(a), hash(Instant::from_micros(10_000)));
    assert_eq!(format!("{a:?}"), "Instant(10000us)");
    h.set_now(12_500);
    assert_eq!(a.elapsed(), Duration::from_micros(2_500));
    // Sub-microsecond durations truncate on add.
    assert_eq!(a + Duration::from_nanos(999), a);
}

#[test]
#[should_panic(expected = "overflow when adding duration to instant")]
fn instant_add_overflow_panics_like_std() {
    let _ = Instant::from_micros(u64::MAX) + Duration::from_micros(1);
}

#[test]
fn sleep_fires_on_tick_once_the_clock_passes() {
    let h = Scripted::new(1);
    h.install();
    let rt = Runtime::new();
    let woke = Rc::new(Cell::new(0u64));
    let w = woke.clone();
    let start = h.now();
    spawn(async move {
        sleep(Duration::from_millis(10)).await;
        w.set(Instant::now().as_micros());
    });
    let d = rt.tick(1_000);
    assert!(d >= start + 10_000, "deadline reported: {d}");
    assert_eq!(woke.get(), 0);
    h.set_now(d - 1);
    rt.tick(1_000);
    assert_eq!(woke.get(), 0, "not early");
    h.set_now(d);
    rt.tick(1_000);
    assert!(woke.get() >= start + 10_000);
}

#[test]
fn sleep_rounds_up_sub_microsecond_durations() {
    let h = Scripted::new(0);
    h.install();
    let _rt = Runtime::new();
    let s = sleep(Duration::from_nanos(1));
    assert_eq!(s.deadline().as_micros(), h.now() + 1);
    assert_eq!(
        sleep_until(Instant::from_micros(5)).deadline().as_micros(),
        5
    );
}

#[test]
fn timeout_elapses_or_passes_through() {
    let h = Scripted::new(1);
    h.install();
    let rt = Runtime::new();
    let out = Rc::new(RefCell::new(Vec::new()));
    let o = out.clone();
    spawn(async move {
        let fast = timeout(Duration::from_millis(10), async { 7 }).await;
        let slow = timeout(Duration::from_millis(10), sleep(Duration::from_secs(1))).await;
        o.borrow_mut().push(format!("{fast:?} {slow:?}"));
    });
    h.drive(&rt, 1_000, 10, || !out.borrow().is_empty());
    assert_eq!(out.borrow()[0], "Ok(7) Err(Elapsed(()))");
    assert_eq!(rt.timers(), 0, "the losing sleep was cancelled");
}

fn ticks_with(behavior: MissedTickBehavior) -> Vec<u64> {
    let h = Scripted::new(0);
    h.install();
    let rt = Runtime::new();
    h.set_now(0);
    let got = Rc::new(RefCell::new(Vec::new()));
    let g = got.clone();
    spawn(async move {
        let mut iv = interval_at(Instant::from_micros(0), Duration::from_micros(100));
        iv.set_missed_tick_behavior(behavior);
        for _ in 0..5 {
            let t = iv.tick().await.as_micros();
            g.borrow_mut().push(t);
        }
    });
    rt.tick(1_000); // first tick at 0
    h.set_now(350); // miss the ticks at 100, 200, 300
    for _ in 0..4 {
        rt.tick(1_000);
    }
    h.set_now(1_000);
    for _ in 0..4 {
        rt.tick(1_000);
    }
    let v = got.borrow().clone();
    v
}

#[test]
fn interval_missed_tick_behaviours() {
    // Period 100us; the task sees the clock at 0, then 350 (missing 100,
    // 200, 300), then 1000.
    // Skip (the default): fire once late (100), then keep the phase: the
    // next tick is 400, the first scheduled one after 350.
    assert_eq!(ticks_with(MissedTickBehavior::Skip), [0, 100, 400]);
    // Burst (tokio's default): every missed tick fires at once.
    assert_eq!(
        ticks_with(MissedTickBehavior::Burst),
        [0, 100, 200, 300, 400]
    );
    // Delay: one late tick, then a full period from when it fired (450).
    assert_eq!(ticks_with(MissedTickBehavior::Delay), [0, 100, 450]);
}

#[test]
fn interval_first_tick_is_immediate_and_default_is_skip() {
    let h = Scripted::new(0);
    h.install();
    let rt = Runtime::new();
    let n = Rc::new(Cell::new(0));
    let c = n.clone();
    spawn(async move {
        let mut iv = interval(Duration::from_millis(1));
        assert_eq!(iv.missed_tick_behavior(), MissedTickBehavior::Skip);
        assert_eq!(iv.period(), Duration::from_millis(1));
        iv.tick().await;
        c.set(1);
    });
    rt.tick(1_000);
    assert_eq!(n.get(), 1);
}
