use std::cell::RefCell;
use std::rc::Rc;

use ciris_rt::seal::{self, Errno, KeyKind};
use ciris_rt::{spawn, Runtime};

use crate::support::{fake_sig, Scripted};

fn setup(auto: bool) -> (Scripted, Runtime) {
    let h = Scripted::new(1);
    h.0.borrow_mut().seal_auto = auto;
    h.install();
    (h, Runtime::new())
}

#[test]
fn sign_composite_parks_until_sealed_then_takes() {
    let (h, rt) = setup(true);
    let out = Rc::new(RefCell::new(None));
    let o = out.clone();
    spawn(async move { *o.borrow_mut() = Some(seal::sign_composite("id", b"msg").await) });
    h.drive(&rt, 1_000, 5, || out.borrow().is_some());
    let sig = out.borrow().clone().unwrap().unwrap();
    assert_eq!(sig.len(), seal::COMPOSITE_SIGNATURE_LEN);
    assert_eq!(sig, fake_sig(b"msg", 3373));
    let tok = h.0.borrow().seal_started[0];
    assert_eq!(tok >> 56, 4, "seal tokens are kind 4");
    assert_eq!(h.0.borrow().taken, [tok]);
}

#[test]
fn many_in_flight_complete_in_any_order() {
    let (h, rt) = setup(false);
    let out: Rc<RefCell<Vec<(u8, usize)>>> = Rc::default();
    for (i, m) in [b"a", b"b", b"c"].into_iter().enumerate() {
        let o = out.clone();
        spawn(async move {
            let s = seal::sign_composite("id", m).await.unwrap();
            o.borrow_mut().push((i as u8, s.len()));
        });
    }
    rt.tick(10_000);
    let started = h.0.borrow().seal_started.clone();
    assert_eq!(started.len(), 3, "all three outstanding at once");
    h.complete_seal(started[2]);
    h.complete_seal(started[0]);
    h.drive(&rt, 10_000, 3, || false);
    assert_eq!(*out.borrow(), [(2, 3373), (0, 3373)]);
    h.complete_seal(started[1]);
    h.drive(&rt, 10_000, 3, || false);
    assert_eq!(out.borrow().len(), 3);
}

#[test]
fn generate_kem_decap_wrap_unwrap() {
    let (h, rt) = setup(true);
    let out = Rc::new(RefCell::new(Vec::new()));
    let o = out.clone();
    spawn(async move {
        // First run: public-key says not-found, so generate.
        assert_eq!(seal::public_key("missing"), Err(Errno::NotFound));
        let pk = seal::generate("transit-kex:v1:t", KeyKind::TransitKex)
            .await
            .unwrap();
        let ikm = seal::kem_decap("transit-kex:v1:t", &[9; 32], &[1; 1088])
            .await
            .unwrap();
        let bad = seal::kem_decap("transit-kex:v1:t", &[9; 31], &[1; 1088]).await;
        let blob = seal::wrap("rns-transport-identity/v1", b"secret")
            .await
            .unwrap();
        let pt = seal::unwrap("rns-transport-identity/v1", &blob)
            .await
            .unwrap();
        let cross = seal::unwrap("rns-ratchets/v1", &blob).await;
        assert_eq!(bad.map(|_| ()), Err(Errno::Invalid));
        assert_eq!(cross.map(|_| ()), Err(Errno::Denied));
        o.borrow_mut().push(format!(
            "{} {} {}",
            pk.len(),
            ikm.len(),
            String::from_utf8(pt.to_vec()).unwrap(),
        ));
    });
    h.drive(&rt, 10_000, 20, || !out.borrow().is_empty());
    assert_eq!(out.borrow()[0], "1216 64 secret");
}

#[test]
fn a_dropped_seal_future_does_not_leak_the_result() {
    let (h, rt) = setup(false);
    let t = spawn(async { seal::sign_composite("id", b"x").await });
    rt.tick(1_000);
    let tok = h.0.borrow().seal_started[0];
    t.abort();
    rt.tick(1_000); // the task is dropped: its token is orphaned
    h.complete_seal(tok);
    h.drive(&rt, 1_000, 2, || false);
    assert_eq!(
        h.0.borrow().taken,
        [tok],
        "runtime took the orphaned result"
    );
    assert!(h.0.borrow().seal_done.is_empty());
}
