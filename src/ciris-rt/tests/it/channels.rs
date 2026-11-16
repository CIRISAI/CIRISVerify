//! Channels are not ciris-rt's: executor-agnostic ones run under it.

use std::cell::RefCell;
use std::rc::Rc;

use ciris_rt::{spawn, time, Runtime};

use crate::support::Scripted;

fn setup() -> (Scripted, Runtime) {
    let h = Scripted::new(1);
    h.install();
    (h, Runtime::new())
}

#[test]
fn futures_channel_oneshot_and_mpsc() {
    let (h, rt) = setup();
    let (otx, orx) = futures_channel::oneshot::channel::<u32>();
    let (mut mtx, mut mrx) = futures_channel::mpsc::channel::<u32>(0);
    let got = Rc::new(RefCell::new(Vec::new()));
    let g = got.clone();
    spawn(async move {
        let first = orx.await.unwrap();
        g.borrow_mut().push(first);
        while let Ok(v) = mrx.recv().await {
            g.borrow_mut().push(v);
        }
    });
    spawn(async move {
        time::sleep(time::Duration::from_millis(1)).await;
        otx.send(1).unwrap();
        for v in 2..5 {
            // Bounded: parks on poll_ready until the receiver drains.
            std::future::poll_fn(|cx| mtx.poll_ready(cx)).await.unwrap();
            mtx.start_send(v).unwrap();
        }
    });
    h.drive(&rt, 10_000, 30, || {
        got.borrow().len() == 4 && rt.tasks() == 0
    });
    assert_eq!(*got.borrow(), [1, 2, 3, 4]);
}

#[test]
fn tokio_sync_oneshot_mpsc_notify() {
    let (h, rt) = setup();
    let (otx, orx) = tokio::sync::oneshot::channel::<u32>();
    let (mtx, mut mrx) = tokio::sync::mpsc::channel::<u32>(1);
    let notify = Rc::new(tokio::sync::Notify::new());
    let got = Rc::new(RefCell::new(Vec::new()));
    let g = got.clone();
    let n = notify.clone();
    spawn(async move {
        n.notified().await;
        let first = orx.await.unwrap();
        g.borrow_mut().push(first);
        while let Some(v) = mrx.recv().await {
            g.borrow_mut().push(v);
        }
    });
    spawn(async move {
        time::sleep(time::Duration::from_millis(1)).await;
        notify.notify_one();
        otx.send(10).unwrap();
        for v in 11..14 {
            mtx.send(v).await.unwrap(); // capacity 1: parks until received
        }
    });
    h.drive(&rt, 10_000, 30, || {
        got.borrow().len() == 4 && rt.tasks() == 0
    });
    assert_eq!(*got.borrow(), [10, 11, 12, 13]);
}
