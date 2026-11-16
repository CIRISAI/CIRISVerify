use std::cell::RefCell;
use std::collections::VecDeque;
use std::pin::Pin;
use std::rc::Rc;

use ciris_rt::net::{self, Carrier, FailReason, Framing, ListenOptions, NetError};
use ciris_rt::{spawn, Event, Runtime};

use crate::support::{Scripted, StreamState};

fn setup() -> (Scripted, Runtime) {
    let h = Scripted::new(1);
    h.install();
    (h, Runtime::new())
}

#[test]
fn dial_write_all_and_read_drive_from_edge_triggered_events() {
    let (h, rt) = setup();
    h.0.borrow_mut().dial_script.push_back(Ok(StreamState {
        scripted: VecDeque::from([(50_000, b"pong".to_vec())]),
        send_cap: 3,
        ..StreamState::default()
    }));
    let out = Rc::new(RefCell::new(None));
    let o = out.clone();
    spawn(async move {
        let c = net::dial(Carrier::Tcp, "peer:4242", &[]).await.unwrap();
        assert_eq!(c.conn_info().peer.as_deref(), Some("203.0.113.7:4242"));
        assert_eq!(c.conn_info().recv_buffer, 65536);
        c.write_all(b"hello world").await.unwrap();
        let mut buf = [0u8; 16];
        let n = c.read(&mut buf).await.unwrap();
        *o.borrow_mut() = Some((c.token(), buf[..n].to_vec()));
    });
    h.drive(&rt, 10_000, 50, || out.borrow().is_some());
    let (token, got) = out.borrow().clone().unwrap();
    assert_eq!(got, b"pong");
    assert_eq!(token >> 56, 1, "connection tokens are kind 1");
    let s = h.stream(token);
    let sent: Vec<u8> = s.borrow().sent.concat();
    assert_eq!(
        sent, b"hello world",
        "partial writes and would-block reassembled"
    );
    assert!(s.borrow().send_calls > 4, "every other send would-blocked");
}

#[test]
fn a_failed_dial_carries_its_reason() {
    let (h, rt) = setup();
    h.0.borrow_mut()
        .dial_script
        .push_back(Err(FailReason::NameNotResolved));
    let out = Rc::new(RefCell::new(None));
    let o = out.clone();
    spawn(async move {
        let failed = net::dial(Carrier::Tcp, "nowhere", &[]).await.map(|_| ());
        let refused = net::dial(Carrier::Tcp, "", &[]).await.map(|_| ());
        assert_eq!(
            refused,
            Err(NetError::Host(ciris_rt::net::Errno::Invalid)),
            "a host refusal is immediate"
        );
        *o.borrow_mut() = Some(failed);
    });
    h.drive(&rt, 1_000, 10, || out.borrow().is_some());
    assert_eq!(
        *out.borrow(),
        Some(Err(NetError::Failed(FailReason::NameNotResolved)))
    );
}

#[test]
fn messages_are_all_or_nothing_and_eof_is_none() {
    let (h, rt) = setup();
    h.0.borrow_mut().dial_script.push_back(Ok(StreamState {
        framing: Some(Framing::Message),
        scripted: VecDeque::from([(10, b"m1".to_vec()), (20_000, b"m2".to_vec())]),
        peer_closed_after_read: true,
        ..StreamState::default()
    }));
    let out = Rc::new(RefCell::new(Vec::new()));
    let o = out.clone();
    spawn(async move {
        let c = net::dial(Carrier::Ws, "wss://relay/rns", &["rns.raw".into()])
            .await
            .unwrap();
        c.send_message(b"a").await.unwrap();
        c.send_message(b"bb").await.unwrap(); // second send would-blocks once
        let big = vec![0u8; 1201];
        let too_big = c.send_message(&big).await;
        o.borrow_mut().push(format!(
            "{}",
            too_big == Err(NetError::Host(ciris_rt::net::Errno::Invalid))
        ));
        while let Some(m) = c.recv_message().await.unwrap() {
            o.borrow_mut().push(String::from_utf8(m).unwrap());
        }
        o.borrow_mut().push("eof".into());
    });
    h.drive(&rt, 10_000, 50, || {
        out.borrow().last().is_some_and(|s| s == "eof")
    });
    assert_eq!(*out.borrow(), ["true", "m1", "m2", "eof"]);
    let tok = *h.0.borrow().streams.keys().next().unwrap();
    assert_eq!(h.stream(tok).borrow().sent, [b"a".to_vec(), b"bb".to_vec()]);
}

#[test]
fn listener_accepts_until_none_then_parks() {
    let (h, rt) = setup();
    let opts = ListenOptions {
        bind: Some("0.0.0.0".into()),
        port: 4242,
        subprotocols: vec![],
        ws_path: None,
    };
    let l = net::listen(Carrier::Tcp, &opts).unwrap();
    assert_eq!(l.token() >> 56, 2);
    let ltoken = l.token();
    let got = Rc::new(RefCell::new(Vec::new()));
    let g = got.clone();
    spawn(async move {
        for _ in 0..3 {
            let c = l.accept().await.unwrap();
            g.borrow_mut().push(c.token());
        }
    });
    {
        let mut st = h.0.borrow_mut();
        let q = st.accept_queue.get_mut(&1).unwrap();
        q.push_back(StreamState::default());
        q.push_back(StreamState::default());
    }
    rt.tick(10_000);
    assert_eq!(got.borrow().len(), 2, "drained both pending before parking");
    h.0.borrow_mut()
        .accept_queue
        .get_mut(&1)
        .unwrap()
        .push_back(StreamState::default());
    rt.tick(10_000);
    assert_eq!(got.borrow().len(), 2, "parked: waits for readable");
    rt.on_event(Event::Readable(ltoken));
    rt.tick(10_000);
    let toks = got.borrow().clone();
    assert_eq!(toks.len(), 3);
    assert!(toks.windows(2).all(|w| w[0] < w[1]), "fresh tokens");
    assert!(
        h.0.borrow().listeners.is_empty(),
        "dropping the listener unlistened"
    );
}

#[test]
fn listener_failure_is_reported() {
    let (_h, rt) = setup();
    let opts = ListenOptions {
        bind: None,
        port: 80,
        subprotocols: vec![],
        ws_path: Some("/rns".into()),
    };
    let l = net::listen(Carrier::Ws, &opts).unwrap();
    let t = l.token();
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    spawn(async move { *g.borrow_mut() = Some(l.accept().await.map(|_| ())) });
    rt.tick(1_000);
    rt.on_event(Event::ListenerFailed(ciris_host_abi::types::FailInfo {
        token: t,
        reason: FailReason::Denied,
    }));
    rt.tick(1_000);
    assert_eq!(
        *got.borrow(),
        Some(Err(NetError::ListenerFailed(FailReason::Denied)))
    );
}

#[test]
fn futures_io_traits_work() {
    use futures_io::{AsyncRead, AsyncWrite};
    let (h, rt) = setup();
    h.0.borrow_mut().dial_script.push_back(Ok(StreamState {
        scripted: VecDeque::from([(0, b"xyz".to_vec())]),
        send_cap: 100,
        ..StreamState::default()
    }));
    let out = Rc::new(RefCell::new(None));
    let o = out.clone();
    spawn(async move {
        let mut c = net::dial(Carrier::Tcp, "p", &[]).await.unwrap();
        let mut buf = [0u8; 8];
        let n = std::future::poll_fn(|cx| Pin::new(&mut c).poll_read(cx, &mut buf))
            .await
            .unwrap();
        let w = std::future::poll_fn(|cx| Pin::new(&mut c).poll_write(cx, b"ab"))
            .await
            .unwrap();
        std::future::poll_fn(|cx| Pin::new(&mut c).poll_close(cx))
            .await
            .unwrap();
        *o.borrow_mut() = Some((buf[..n].to_vec(), w));
    });
    h.drive(&rt, 10_000, 20, || out.borrow().is_some());
    assert_eq!(*out.borrow(), Some((b"xyz".to_vec(), 2)));
}

#[test]
fn datagrams_send_and_park_until_readable() {
    let (h, rt) = setup();
    assert!(net::can_datagram());
    let d = net::bind(None, 0).unwrap();
    assert_eq!(d.local_addr().as_deref(), Some("0.0.0.0:4242"));
    assert_eq!(d.max_datagram(), 1472);
    let t = d.token();
    assert_eq!(t >> 56, 3);
    let got = Rc::new(RefCell::new(None));
    let g = got.clone();
    spawn(async move {
        d.send_to("198.51.100.1:4965", b"hi").await.unwrap();
        *g.borrow_mut() = Some(d.recv_from().await.unwrap());
    });
    rt.tick(1_000);
    assert!(h.0.borrow().datagram_blocked);
    h.0.borrow_mut()
        .datagram_in
        .push_back(("198.51.100.1:4965".into(), b"yo".to_vec()));
    rt.on_event(Event::Readable(t));
    rt.tick(1_000);
    assert_eq!(
        *got.borrow(),
        Some(("198.51.100.1:4965".to_owned(), b"yo".to_vec()))
    );
    assert_eq!(h.0.borrow().datagram_out.len(), 1);
}
