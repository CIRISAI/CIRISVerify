//! FSD §5.4: `tick` honours `budget_us`.

use std::cell::RefCell;
use std::rc::Rc;

use ciris_rt::{spawn, yield_now, Runtime};

use crate::support::Scripted;

#[test]
fn tick_stops_when_the_budget_is_spent_and_resumes_next_tick() {
    // Every clock read advances 1000us: one read at tick start, one after
    // each poll. With a 3500us budget the 4th poll ends at +4000us >= 3500.
    let h = Scripted::new(1_000);
    h.install();
    let rt = Runtime::new();
    let order: Rc<RefCell<Vec<(u8, u8)>>> = Rc::default();
    for task in 0..5u8 {
        let o = order.clone();
        spawn(async move {
            for step in 0..3u8 {
                o.borrow_mut().push((task, step));
                yield_now().await; // yield between polls
            }
        });
    }

    let before = h.now();
    let next = rt.tick(3_500);
    assert_eq!(rt.polls(), 4, "stops once the budget is spent");
    assert_eq!(*order.borrow(), [(0, 0), (1, 0), (2, 0), (3, 0)]);
    assert_eq!(
        next,
        h.now() - 1_000,
        "work is still ready: deadline is now"
    );
    assert!(h.now() - before <= 3_500 + 2_000);

    rt.tick(3_500);
    assert_eq!(rt.polls(), 8, "resumes on the next tick");
    assert_eq!(
        order.borrow()[4..],
        [(4, 0), (0, 1), (1, 1), (2, 1)],
        "round-robin: woken tasks go behind the ready ones"
    );

    let mut ticks = 2;
    while rt.tasks() > 0 {
        rt.tick(3_500);
        ticks += 1;
        assert!(ticks < 20);
    }
    // 15 steps + 5 final polls that return Ready = 20 polls at 4 per tick.
    assert_eq!(rt.polls(), 20);
    assert_eq!(ticks, 5);
    assert_eq!(order.borrow().len(), 15);
}

#[test]
fn a_zero_budget_still_makes_progress() {
    let h = Scripted::new(1_000);
    h.install();
    let rt = Runtime::new();
    spawn(async {});
    spawn(async {});
    rt.tick(0);
    assert_eq!(rt.polls(), 1);
    rt.tick(0);
    assert_eq!(rt.tasks(), 0);
}
