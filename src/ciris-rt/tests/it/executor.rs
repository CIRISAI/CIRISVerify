use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ciris_rt::{spawn, spawn_blocking, yield_now, JoinError, Runtime};

use crate::support::Scripted;

fn setup() -> (Scripted, Runtime) {
    let h = Scripted::new(1);
    h.install();
    (h, Runtime::new())
}

#[test]
fn spawn_runs_not_send_futures_and_join_handle_yields_output() {
    let (h, rt) = setup();
    // Rc is !Send: the executor needs no Send bound.
    let shared = Rc::new(Cell::new(0));
    let s = shared.clone();
    let inner = spawn(async move {
        s.set(s.get() + 1);
        41
    });
    let out = Rc::new(Cell::new(None));
    let o = out.clone();
    spawn(async move {
        o.set(Some(inner.await.unwrap() + 1));
    });
    h.drive(&rt, 10_000, 10, || out.get().is_some());
    assert_eq!(out.get(), Some(42));
    assert_eq!(shared.get(), 1);
    assert_eq!(rt.tasks(), 0);
}

struct DropFlag(Rc<Cell<bool>>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[test]
fn abort_cancels_and_drops_the_future() {
    let (h, rt) = setup();
    let dropped = Rc::new(Cell::new(false));
    let flag = DropFlag(dropped.clone());
    let task = spawn(async move {
        let _keep = flag;
        ciris_rt::time::sleep(ciris_rt::time::Duration::from_secs(3600)).await;
        1
    });
    rt.tick(1_000);
    assert!(!task.is_finished());
    assert_eq!(rt.timers(), 1);
    task.abort();
    assert!(task.is_finished());
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    spawn(async move { *g.borrow_mut() = Some(task.await) });
    h.drive(&rt, 1_000, 5, || got.borrow().is_some());
    assert_eq!(*got.borrow(), Some(Err(JoinError::Cancelled)));
    assert!(dropped.get(), "the aborted future was dropped");
    assert_eq!(rt.timers(), 0, "dropping the sleep cancelled its timer");
    assert_eq!(rt.tasks(), 0);
}

#[test]
fn a_task_can_abort_itself_through_its_handle() {
    let (h, rt) = setup();
    let slot: Rc<RefCell<Option<ciris_rt::JoinHandle<()>>>> = Rc::default();
    let s = slot.clone();
    let reached = Rc::new(Cell::new(false));
    let r = reached.clone();
    let t = spawn(async move {
        s.borrow().as_ref().unwrap().abort();
        yield_now().await;
        r.set(true);
    });
    *slot.borrow_mut() = Some(t);
    h.drive(&rt, 1_000, 5, || false);
    assert!(!reached.get());
    assert_eq!(rt.tasks(), 0);
}

#[test]
fn dropping_the_handle_detaches() {
    let (h, rt) = setup();
    let ran = Rc::new(Cell::new(false));
    let r = ran.clone();
    drop(spawn(async move { r.set(true) }));
    h.drive(&rt, 1_000, 3, || ran.get());
    assert!(ran.get());
}

#[test]
fn blocking_runs_inline() {
    let (h, rt) = setup();
    let h2 = spawn_blocking(|| 7);
    assert!(h2.is_finished());
    let out = Rc::new(Cell::new(0));
    let o = out.clone();
    spawn(async move {
        let a = ciris_rt::blocking(|| 5).await;
        o.set(a + h2.await.unwrap());
    });
    h.drive(&rt, 1_000, 3, || out.get() != 0);
    assert_eq!(out.get(), 12);
}

#[test]
fn tick_reports_the_next_deadline_to_wake() {
    let (h, rt) = setup();
    assert_eq!(rt.tick(1_000), u64::MAX, "nothing to do");
    spawn(ciris_rt::time::sleep(
        ciris_rt::time::Duration::from_millis(5),
    ));
    let d = rt.tick(1_000);
    assert!(d > h.now() && d < u64::MAX);
    assert_eq!(h.0.borrow().deadlines.last().copied(), Some(d));
}

#[test]
fn a_clock_that_never_moves_still_returns_from_tick() {
    let h = Scripted::new(0);
    h.install();
    let rt = Runtime::new();
    spawn(async {
        loop {
            yield_now().await;
        }
    });
    let next = rt.tick(1_000);
    assert_eq!(next, h.now(), "still ready: tick me again now");
    assert_eq!(rt.polls(), u64::from(ciris_rt::MAX_ROUNDS_PER_TICK));
}

#[test]
fn lifecycle_and_clock_trusted_are_routed() {
    use ciris_host_abi::types::Phase;
    let (h, rt) = setup();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let s = seen.clone();
    spawn(async move {
        ciris_rt::lifecycle::wait_clock_trusted().await;
        s.borrow_mut().push("trusted".to_owned());
        loop {
            let p = ciris_rt::lifecycle::next().await;
            s.borrow_mut().push(match p {
                Phase::Background => "background".to_owned(),
                Phase::Shutdown => "shutdown".to_owned(),
                _ => "other".to_owned(),
            });
            if p == Phase::Shutdown {
                break;
            }
        }
    });
    rt.tick(1_000);
    h.push_event(ciris_rt::Event::Lifecycle(Phase::Background));
    h.push_event(ciris_rt::Event::ClockTrusted);
    h.push_event(ciris_rt::Event::Lifecycle(Phase::Shutdown));
    h.drive(&rt, 1_000, 5, || seen.borrow().len() == 3);
    assert_eq!(*seen.borrow(), ["trusted", "background", "shutdown"]);
    assert!(ciris_rt::lifecycle::clock_trusted());
    assert_eq!(ciris_rt::lifecycle::current(), Some(Phase::Shutdown));
}
