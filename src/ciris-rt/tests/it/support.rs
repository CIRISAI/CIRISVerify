//! A scripted, deterministic native host for the tests.
//!
//! * The clock is a counter: every `monotonic-us` read returns the current
//!   value and then advances it by `step` (so a tick's own clock reads move
//!   time, which the §5.4 budget test relies on). The driver can also jump
//!   it to a deadline.
//! * Randomness is a counter-derived byte stream (deterministic, NOT
//!   random: test only).
//! * Streams are scripted: inbound chunks become readable at a time;
//!   `send` accepts at most `send_cap` bytes and answers `would-block`
//!   every other call. Readiness is edge-triggered like a real host:
//!   `readable` is queued only after a `recv` returned `would-block` and data
//!   then arrived; `writable` only after a `send` returned `would-block`.
//! * Seal operations complete when the driver says (or at once), queuing
//!   `sealed(token)`; `take` returns a pattern derived from the input.
//!
//! Events the host produces go to `outbox`; the driver delivers them.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use ciris_host_abi::host::{Host, HostDatagram, HostStream};
use ciris_host_abi::seal::{
    COMPOSITE_SIGNATURE_LEN, KEM_IKM_LEN, KEX_PUBLIC_KEY_LEN, PUBLIC_KEY_LEN,
};
use ciris_host_abi::types::{
    Carrier, CloseInfo, CloseReason, ConnInfo, Errno, Event, FailInfo, FailReason, Framing,
    KeyKind, ListenOptions,
};
use ciris_rt::Runtime;

#[derive(Default)]
pub struct StreamState {
    pub token: u64,
    pub framing: Option<Framing>,
    /// (available-at-us, bytes) not yet delivered to the stream.
    pub scripted: VecDeque<(u64, Vec<u8>)>,
    /// Bytes / messages readable now.
    pub inbound: VecDeque<Vec<u8>>,
    pub sent: Vec<Vec<u8>>,
    pub read_blocked: bool,
    pub write_blocked: bool,
    pub send_calls: u32,
    pub send_cap: usize,
    pub closed: bool,
    pub peer_closed_after_read: bool,
}

#[derive(Default)]
pub struct State {
    pub now: u64,
    pub step: u64,
    pub rng: u64,
    pub outbox: VecDeque<Event>,
    pub deadlines: Vec<u64>,
    pub logs: Vec<String>,
    pub streams: BTreeMap<u64, Rc<RefCell<StreamState>>>,
    /// Script for the next dials, in order: Ok(stream script) or a failure.
    pub dial_script: VecDeque<Result<StreamState, FailReason>>,
    /// Pending accepts per listener id.
    pub accept_queue: BTreeMap<u32, VecDeque<StreamState>>,
    pub listeners: BTreeMap<u32, u64>,
    pub next_listener: u32,
    /// Seal operations started, by token, with their result.
    pub seal_pending: BTreeMap<u64, Vec<u8>>,
    pub seal_done: BTreeMap<u64, Vec<u8>>,
    pub seal_auto: bool,
    pub seal_started: Vec<u64>,
    pub taken: Vec<u64>,
    pub datagram_in: VecDeque<(String, Vec<u8>)>,
    pub datagram_out: Vec<(String, Vec<u8>)>,
    pub datagram_token: u64,
    pub datagram_blocked: bool,
}

#[derive(Clone, Default)]
pub struct Scripted(pub Rc<RefCell<State>>);

impl Scripted {
    pub fn new(step: u64) -> Self {
        let s = Self::default();
        s.0.borrow_mut().step = step;
        s.0.borrow_mut().seal_auto = true;
        s.0.borrow_mut().now = 1_000;
        s
    }

    /// Move scripted inbound data that is due into its stream, queuing an
    /// edge-triggered `readable` where the node is waiting on it.
    pub fn pump(&self) {
        let mut st = self.0.borrow_mut();
        let now = st.now;
        let mut evs = Vec::new();
        for s in st.streams.values() {
            let mut s = s.borrow_mut();
            let mut arrived = false;
            while s.scripted.front().is_some_and(|(at, _)| *at <= now) {
                let (_, b) = s.scripted.pop_front().unwrap();
                s.inbound.push_back(b);
                arrived = true;
            }
            if s.scripted.is_empty()
                && s.peer_closed_after_read
                && !s.closed
                && s.inbound.is_empty()
            {
                s.closed = true;
                evs.push(Event::Closed(CloseInfo {
                    token: s.token,
                    reason: CloseReason::PeerClose,
                }));
            }
            if arrived && s.read_blocked {
                s.read_blocked = false;
                evs.push(Event::Readable(s.token));
            }
        }
        st.outbox.extend(evs);
    }

    /// Complete seal operation `token` (when `seal_auto` is off).
    pub fn complete_seal(&self, token: u64) {
        let mut st = self.0.borrow_mut();
        let v = st.seal_pending.remove(&token).expect("pending seal op");
        st.seal_done.insert(token, v);
        st.outbox.push_back(Event::Sealed(token));
    }

    pub fn push_event(&self, e: Event) {
        self.0.borrow_mut().outbox.push_back(e);
    }

    pub fn now(&self) -> u64 {
        self.0.borrow().now
    }

    pub fn set_now(&self, t: u64) {
        self.0.borrow_mut().now = t;
    }

    pub fn install(&self) {
        ciris_host_abi::host::install(self.clone());
    }

    /// Drive `rt` the way a host loop does: deliver events, tick, and when
    /// nothing is pending jump the clock to the returned deadline. Stops
    /// when `done()` or after `max` iterations; returns the iterations.
    pub fn drive(
        &self,
        rt: &Runtime,
        budget: u32,
        max: usize,
        mut done: impl FnMut() -> bool,
    ) -> usize {
        self.drive_with(budget, max, &mut done, |e| rt.on_event(e), |b| rt.tick(b))
    }

    pub fn drive_with(
        &self,
        budget: u32,
        max: usize,
        done: &mut dyn FnMut() -> bool,
        mut on_event: impl FnMut(Event),
        mut tick: impl FnMut(u32) -> u64,
    ) -> usize {
        for i in 0..max {
            self.pump();
            loop {
                let e = self.0.borrow_mut().outbox.pop_front();
                let Some(e) = e else { break };
                on_event(e);
            }
            let deadline = tick(budget);
            if done() {
                return i + 1;
            }
            let idle = self.0.borrow().outbox.is_empty();
            if idle && deadline != u64::MAX && deadline > self.now() {
                self.set_now(deadline);
            } else if idle && deadline == u64::MAX {
                // Nothing scheduled: let scripted data arrive.
                let next = {
                    let st = self.0.borrow();
                    st.streams
                        .values()
                        .filter_map(|s| s.borrow().scripted.front().map(|(at, _)| *at))
                        .min()
                };
                if let Some(t) = next {
                    self.set_now(t.max(self.now()));
                }
            }
        }
        max
    }

    pub fn stream(&self, token: u64) -> Rc<RefCell<StreamState>> {
        self.0.borrow().streams[&token].clone()
    }
}

struct FakeStream(Rc<RefCell<StreamState>>, Rc<RefCell<State>>);

impl HostStream for FakeStream {
    fn info(&self) -> ConnInfo {
        let s = self.0.borrow();
        let framing = s.framing.unwrap_or(Framing::Stream);
        ConnInfo {
            carrier: Carrier::Tcp,
            framing,
            max_message: matches!(framing, Framing::Message).then_some(1200),
            reliable: true,
            subprotocol: None,
            peer_subprotocols: Vec::new(),
            peer: Some("203.0.113.7:4242".into()),
            bitrate_hint: None,
            recv_buffer: 65536,
        }
    }
    fn send(&self, data: &[u8]) -> Result<u32, Errno> {
        let mut s = self.0.borrow_mut();
        if s.closed {
            return Err(Errno::Closed);
        }
        s.send_calls += 1;
        if s.send_calls.is_multiple_of(2) {
            s.write_blocked = true;
            let t = s.token;
            self.1.borrow_mut().outbox.push_back(Event::Writable(t));
            return Err(Errno::WouldBlock);
        }
        match s.framing.unwrap_or(Framing::Stream) {
            Framing::Stream => {
                let n = data.len().min(s.send_cap.max(1));
                s.sent.push(data[..n].to_vec());
                Ok(u32::try_from(n).unwrap())
            },
            Framing::Message => {
                if data.len() > 1200 {
                    return Err(Errno::Invalid);
                }
                s.sent.push(data.to_vec());
                Ok(1)
            },
        }
    }
    fn recv(&self, max: u32) -> Result<Vec<u8>, Errno> {
        let mut s = self.0.borrow_mut();
        let framing = s.framing.unwrap_or(Framing::Stream);
        match s.inbound.pop_front() {
            Some(mut b) => {
                if framing == Framing::Stream && b.len() > max as usize {
                    let rest = b.split_off(max as usize);
                    s.inbound.push_front(rest);
                } else if framing == Framing::Message && b.len() > max as usize {
                    s.inbound.push_front(b);
                    return Err(Errno::Invalid);
                }
                Ok(b)
            },
            None if s.closed => Err(Errno::Closed),
            None => {
                s.read_blocked = true;
                Err(Errno::WouldBlock)
            },
        }
    }
    fn close(&self) {
        self.0.borrow_mut().closed = true;
    }
}

struct FakeDatagram(Rc<RefCell<State>>);

impl HostDatagram for FakeDatagram {
    fn send_to(&self, addr: &str, data: &[u8]) -> Result<(), Errno> {
        self.0
            .borrow_mut()
            .datagram_out
            .push((addr.into(), data.to_vec()));
        Ok(())
    }
    fn recv_from(&self) -> Result<(String, Vec<u8>), Errno> {
        let mut st = self.0.borrow_mut();
        match st.datagram_in.pop_front() {
            Some(d) => Ok(d),
            None => {
                st.datagram_blocked = true;
                Err(Errno::WouldBlock)
            },
        }
    }
    fn local_addr(&self) -> Option<String> {
        Some("0.0.0.0:4242".into())
    }
    fn max_datagram(&self) -> u32 {
        1472
    }
}

/// A deterministic stand-in "signature" over `msg` (test only).
pub fn fake_sig(msg: &[u8], len: usize) -> Vec<u8> {
    let mut acc: u8 = 0x5a;
    (0..len)
        .map(|i| {
            acc = acc
                .wrapping_mul(31)
                .wrapping_add(msg.get(i % msg.len().max(1)).copied().unwrap_or(0));
            acc ^ (i as u8)
        })
        .collect()
}

impl Scripted {
    fn seal_start(&self, token: u64, result: Vec<u8>) -> Result<(), Errno> {
        let mut st = self.0.borrow_mut();
        st.seal_started.push(token);
        if st.seal_auto {
            st.seal_done.insert(token, result);
            st.outbox.push_back(Event::Sealed(token));
        } else {
            st.seal_pending.insert(token, result);
        }
        Ok(())
    }
}

impl Host for Scripted {
    fn monotonic_us(&self) -> u64 {
        let mut st = self.0.borrow_mut();
        let t = st.now;
        st.now += st.step;
        t
    }
    fn wall_ms(&self) -> Option<i64> {
        None
    }
    fn random_fill(&self, len: u32) -> Vec<u8> {
        let mut st = self.0.borrow_mut();
        (0..len)
            .map(|_| {
                st.rng = st
                    .rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (st.rng >> 56) as u8
            })
            .collect()
    }
    fn log_record(&self, level: u8, target: &str, msg: &str) {
        self.0
            .borrow_mut()
            .logs
            .push(format!("{level} {target}: {msg}"));
    }
    fn net_carriers(&self) -> Vec<Carrier> {
        vec![Carrier::Tcp, Carrier::Ws]
    }
    fn net_can_listen(&self, _c: Carrier) -> bool {
        true
    }
    fn net_can_datagram(&self) -> bool {
        true
    }
    fn net_dial(
        &self,
        _c: Carrier,
        target: &str,
        _subprotocols: &[String],
        token: u64,
    ) -> Result<Box<dyn HostStream>, Errno> {
        if target.is_empty() {
            return Err(Errno::Invalid);
        }
        let mut st = self.0.borrow_mut();
        let script = st
            .dial_script
            .pop_front()
            .unwrap_or_else(|| Ok(StreamState::default()));
        match script {
            Ok(mut s) => {
                s.token = token;
                if s.send_cap == 0 {
                    s.send_cap = 4;
                }
                let s = Rc::new(RefCell::new(s));
                st.streams.insert(token, s.clone());
                st.outbox.push_back(Event::Connected(token));
                Ok(Box::new(FakeStream(s, self.0.clone())))
            },
            Err(reason) => {
                let s = Rc::new(RefCell::new(StreamState {
                    token,
                    closed: true,
                    ..StreamState::default()
                }));
                st.outbox
                    .push_back(Event::Failed(FailInfo { token, reason }));
                Ok(Box::new(FakeStream(s, self.0.clone())))
            },
        }
    }
    fn net_listen(&self, _c: Carrier, _opts: &ListenOptions, token: u64) -> Result<u32, Errno> {
        let mut st = self.0.borrow_mut();
        st.next_listener += 1;
        let id = st.next_listener;
        st.listeners.insert(id, token);
        st.accept_queue.entry(id).or_default();
        Ok(id)
    }
    fn net_accept(&self, listener: u32, token: u64) -> Result<Option<Box<dyn HostStream>>, Errno> {
        let mut st = self.0.borrow_mut();
        let Some(q) = st.accept_queue.get_mut(&listener) else {
            return Err(Errno::NotFound);
        };
        match q.pop_front() {
            Some(mut s) => {
                s.token = token;
                if s.send_cap == 0 {
                    s.send_cap = 4;
                }
                let s = Rc::new(RefCell::new(s));
                st.streams.insert(token, s.clone());
                Ok(Some(Box::new(FakeStream(s, self.0.clone()))))
            },
            None => Ok(None),
        }
    }
    fn net_unlisten(&self, listener: u32) {
        self.0.borrow_mut().listeners.remove(&listener);
    }
    fn net_bind(
        &self,
        _bind: Option<&str>,
        _port: u16,
        token: u64,
    ) -> Result<Box<dyn HostDatagram>, Errno> {
        self.0.borrow_mut().datagram_token = token;
        Ok(Box::new(FakeDatagram(self.0.clone())))
    }
    fn seal_public_key(&self, id: &str) -> Result<Vec<u8>, Errno> {
        if id == "missing" {
            Err(Errno::NotFound)
        } else {
            Ok(fake_sig(id.as_bytes(), PUBLIC_KEY_LEN))
        }
    }
    fn seal_generate(&self, id: &str, kind: KeyKind, token: u64) -> Result<(), Errno> {
        let len = match kind {
            KeyKind::Composite => PUBLIC_KEY_LEN,
            KeyKind::TransitKex | KeyKind::OnionHop => KEX_PUBLIC_KEY_LEN,
        };
        self.seal_start(token, fake_sig(id.as_bytes(), len))
    }
    fn seal_kem_decap(&self, _id: &str, peer: &[u8], ct: &[u8], token: u64) -> Result<(), Errno> {
        if peer.len() != 32 || ct.len() != 1088 {
            return Err(Errno::Invalid);
        }
        self.seal_start(token, fake_sig(peer, KEM_IKM_LEN))
    }
    fn seal_sign_composite(&self, _id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
        self.seal_start(token, fake_sig(msg, COMPOSITE_SIGNATURE_LEN))
    }
    fn seal_sign_classical(&self, _id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
        self.seal_start(token, fake_sig(msg, 64))
    }
    fn seal_wrap(&self, label: &str, pt: &[u8], token: u64) -> Result<(), Errno> {
        let mut blob = label.as_bytes().to_vec();
        blob.push(0);
        blob.extend(pt);
        self.seal_start(token, blob)
    }
    fn seal_unwrap(&self, label: &str, wrapped: &[u8], token: u64) -> Result<(), Errno> {
        let mut prefix = label.as_bytes().to_vec();
        prefix.push(0);
        let r = wrapped.strip_prefix(prefix.as_slice()).map(<[u8]>::to_vec);
        match r {
            Some(pt) => self.seal_start(token, pt),
            None => {
                // An authentication failure is reported through take.
                let mut st = self.0.borrow_mut();
                st.seal_started.push(token);
                st.seal_done.insert(token, Vec::new());
                st.outbox.push_back(Event::Sealed(token));
                st.seal_pending.insert(u64::MAX - token, Vec::new()); // marker
                Ok(())
            },
        }
    }
    fn seal_take(&self, token: u64) -> Result<Vec<u8>, Errno> {
        let mut st = self.0.borrow_mut();
        if st.seal_pending.remove(&(u64::MAX - token)).is_some() {
            st.seal_done.remove(&token);
            st.taken.push(token);
            return Err(Errno::Denied);
        }
        if st.seal_pending.contains_key(&token) {
            return Err(Errno::WouldBlock);
        }
        match st.seal_done.remove(&token) {
            Some(v) => {
                st.taken.push(token);
                Ok(v)
            },
            None => Err(Errno::NotFound),
        }
    }
    fn wake_next_deadline(&self, us: u64) {
        self.0.borrow_mut().deadlines.push(us);
    }
}
