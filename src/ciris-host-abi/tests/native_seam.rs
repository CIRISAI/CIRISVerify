//! The same node code, linked natively against an installed `Host`.

use std::cell::RefCell;
use std::rc::Rc;

use ciris_host_abi::host::{self, Host};
use ciris_host_abi::log::Level;
use ciris_host_abi::types::{
    Carrier, Durability, Errno, FailInfo, FailReason, KeyKind, ListenOptions, MetricKind,
};
use ciris_host_abi::{clock, log, net, random, seal, storage, Event, Node};

/// One `log.metric` sample as the test host saw it.
type Metric = (String, MetricKind, f64, Vec<(String, String)>);

#[derive(Default)]
struct Recorded {
    logs: Vec<(u8, String, String)>,
    metrics: Vec<Metric>,
}

struct TestHost {
    now: u64,
    short_random: bool,
    rec: Rc<RefCell<Recorded>>,
}

impl Host for TestHost {
    fn monotonic_us(&self) -> u64 {
        self.now
    }
    fn wall_ms(&self) -> Option<i64> {
        None
    }
    fn random_fill(&self, len: u32) -> Vec<u8> {
        let n = if self.short_random { len - 1 } else { len };
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect()
    }
    fn log_record(&self, level: u8, target: &str, msg: &str) {
        self.rec
            .borrow_mut()
            .logs
            .push((level, target.into(), msg.into()));
    }
    fn log_metric(&self, name: &str, kind: MetricKind, value: f64, labels: &[(String, String)]) {
        self.rec
            .borrow_mut()
            .metrics
            .push((name.into(), kind, value, labels.to_vec()));
    }
}

fn install(short_random: bool) -> Rc<RefCell<Recorded>> {
    let rec = Rc::new(RefCell::new(Recorded::default()));
    host::install(TestHost {
        now: 42,
        short_random,
        rec: rec.clone(),
    });
    rec
}

struct N;
impl Node for N {
    fn init() -> Result<(), String> {
        let mut b = [0u8; 8];
        random::fill_bytes(&mut b);
        log::record(
            Level::Info,
            "n",
            &format!("{} {:?} {b:?}", clock::monotonic_us(), clock::wall_ms()),
        );
        Ok(())
    }
    fn tick(budget_us: u32) -> u64 {
        log::metric(
            "budget",
            MetricKind::Gauge,
            f64::from(budget_us),
            &[("plane".into(), "test".into())],
        );
        clock::monotonic_us() + 10
    }
    fn on_event(_e: Event) {}
    fn api(req: Vec<u8>, _local: bool) -> Vec<u8> {
        req
    }
}
ciris_host_abi::export_node!(N);

#[test]
fn node_runs_natively() {
    let rec = install(false);
    N::init().unwrap();
    assert_eq!(N::tick(500), 52);
    let rec = rec.borrow();
    assert_eq!(rec.logs[0].0, 2);
    assert!(rec.logs[0].2.starts_with("42 None [7, 38, 69"));
    assert_eq!(
        rec.metrics,
        vec![(
            "budget".to_owned(),
            MetricKind::Gauge,
            500.0,
            vec![("plane".to_owned(), "test".to_owned())]
        )]
    );
}

#[test]
fn defaults_are_runtime_answers() {
    let _rec = install(false);
    assert!(net::carriers().is_empty());
    assert!(!net::can_listen(Carrier::Tcp));
    assert!(matches!(
        net::dial(Carrier::Ws, "x", &[], 1),
        Err(Errno::Unsupported)
    ));
    let v = storage::primary();
    assert_eq!(v.durability(), Durability::Evictable);
    assert_eq!(v.open("db", true), Err(Errno::Unsupported));
    assert_eq!(seal::sign_composite("k", b"m", 7), Err(Errno::Unsupported));
    assert_eq!(seal::take(7), Err(Errno::NotFound));
    assert_eq!(
        seal::generate("k", KeyKind::TransitKex, 8),
        Err(Errno::Unsupported)
    );
    assert_eq!(
        seal::kem_decap("k", &[1; 32], &[2; seal::MLKEM768_CIPHERTEXT_LEN], 9),
        Err(Errno::Unsupported)
    );
    assert!(!net::can_datagram());
    assert!(!net::can_multicast());
    assert!(net::interfaces().is_empty());
    assert!(matches!(net::bind(None, 0, 10), Err(Errno::Unsupported)));
    let opts = ListenOptions {
        bind: Some("::1".into()),
        port: 4242,
        subprotocols: vec!["rns.hdlc".into()],
        ws_path: Some("/rns".into()),
    };
    assert_eq!(net::listen(Carrier::Ws, &opts, 11), Err(Errno::Unsupported));
}

#[test]
#[should_panic(expected = "refusing weak or short randomness")]
fn short_random_traps() {
    let _rec = install(true);
    let _ = random::fill(16);
}

#[test]
#[should_panic(expected = "no Host installed")]
fn no_host_is_an_unsatisfied_import() {
    host::uninstall();
    let _ = clock::monotonic_us();
}

// ---------------------------------------------------------------------------
// `seal.wrap` / `seal.unwrap`: a TEST-ONLY native implementation.
//
// key   = HKDF-SHA256(ikm = TEST_ROOT, salt = "ciris-host-abi/test-wrap/v1",
//                     info = label)          (one key per label)
// AEAD  = XChaCha20-Poly1305, a fresh random 24-byte nonce per wrap
// blob  = nonce(24) || ciphertext || tag(16)
//
// A real host derives the key from its seal root (TPM, WebAuthn PRF,
// keystore) and keeps it out of node memory; this one keeps a constant.
// ---------------------------------------------------------------------------

mod wrap_host {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use ciris_crypto::{kdf, random, xchacha};
    use ciris_host_abi::host::Host;
    use ciris_host_abi::seal::{WRAP_LABEL_MAX, WRAP_PLAINTEXT_MIN_MAX};
    use ciris_host_abi::types::Errno;

    /// TEST ONLY. Never a seal root.
    const TEST_ROOT: &[u8; 32] = b"ciris-host-abi TEST ROOT, unsafe";
    const SALT: &[u8] = b"ciris-host-abi/test-wrap/v1";

    #[derive(Default)]
    pub struct WrapHost {
        done: RefCell<HashMap<u64, Result<Vec<u8>, Errno>>>,
    }

    fn key(label: &str) -> [u8; 32] {
        kdf::hkdf_sha256(TEST_ROOT, SALT, label.as_bytes(), 32)
            .unwrap()
            .try_into()
            .unwrap()
    }

    impl Host for WrapHost {
        fn monotonic_us(&self) -> u64 {
            0
        }
        fn wall_ms(&self) -> Option<i64> {
            None
        }
        fn random_fill(&self, len: u32) -> Vec<u8> {
            random::bytes(len as usize).unwrap()
        }
        fn log_record(&self, _: u8, _: &str, _: &str) {}
        fn seal_wrap(&self, label: &str, plaintext: &[u8], token: u64) -> Result<(), Errno> {
            if label.len() > WRAP_LABEL_MAX || plaintext.len() > WRAP_PLAINTEXT_MIN_MAX {
                return Err(Errno::Invalid);
            }
            let nonce: [u8; xchacha::NONCE_LEN] = random::bytes(xchacha::NONCE_LEN)
                .unwrap()
                .try_into()
                .unwrap();
            let mut blob = nonce.to_vec();
            blob.extend(xchacha::seal(&key(label), &nonce, plaintext).unwrap());
            self.done.borrow_mut().insert(token, Ok(blob));
            Ok(())
        }
        fn seal_unwrap(&self, label: &str, wrapped: &[u8], token: u64) -> Result<(), Errno> {
            if label.len() > WRAP_LABEL_MAX {
                return Err(Errno::Invalid);
            }
            let out = if wrapped.len() < xchacha::NONCE_LEN + xchacha::TAG_LEN {
                Err(Errno::Invalid)
            } else {
                let (nonce, ct) = wrapped.split_at(xchacha::NONCE_LEN);
                xchacha::open(&key(label), nonce.try_into().unwrap(), ct).map_err(|_| Errno::Denied)
            };
            self.done.borrow_mut().insert(token, out);
            Ok(())
        }
        fn seal_take(&self, token: u64) -> Result<Vec<u8>, Errno> {
            self.done
                .borrow_mut()
                .remove(&token)
                .unwrap_or(Err(Errno::NotFound))
        }
    }
}

fn wrap(label: &str, pt: &[u8], token: u64) -> Result<Vec<u8>, Errno> {
    seal::wrap(label, pt, token)?;
    seal::take(token)
}
fn unwrap(label: &str, blob: &[u8], token: u64) -> Result<Vec<u8>, Errno> {
    seal::unwrap(label, blob, token)?;
    seal::take(token)
}

#[test]
fn wrap_labels_do_not_cross_unwrap() {
    host::install(wrap_host::WrapHost::default());
    let blob = wrap("rns-transport-identity/v1", b"identity", 1).unwrap();
    assert_eq!(
        unwrap("rns-transport-identity/v1", &blob, 2).unwrap(),
        b"identity"
    );
    assert_eq!(unwrap("rns-ratchets/v1", &blob, 3), Err(Errno::Denied));
}

#[test]
fn wrap_nonces_are_fresh() {
    host::install(wrap_host::WrapHost::default());
    let a = wrap("rns-ratchets/v1", b"ratchet", 1).unwrap();
    let b = wrap("rns-ratchets/v1", b"ratchet", 2).unwrap();
    assert_ne!(a, b, "two wraps of one plaintext must differ");
    assert_eq!(unwrap("rns-ratchets/v1", &a, 3).unwrap(), b"ratchet");
    assert_eq!(unwrap("rns-ratchets/v1", &b, 4).unwrap(), b"ratchet");
}

#[test]
fn wrap_64k_round_trips() {
    host::install(wrap_host::WrapHost::default());
    let pt: Vec<u8> = (0..seal::WRAP_PLAINTEXT_MIN_MAX)
        .map(|i| (i % 251) as u8)
        .collect();
    let blob = wrap("big/v1", &pt, 1).unwrap();
    assert_eq!(unwrap("big/v1", &blob, 2).unwrap(), pt);
}

#[test]
fn wrap_tampered_blob_is_refused() {
    host::install(wrap_host::WrapHost::default());
    let mut blob = wrap("rns-transport-identity/v1", b"identity", 1).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 1;
    assert_eq!(
        unwrap("rns-transport-identity/v1", &blob, 2),
        Err(Errno::Denied)
    );
}

#[test]
fn wrap_overlong_label_is_refused() {
    host::install(wrap_host::WrapHost::default());
    let label = "x".repeat(seal::WRAP_LABEL_MAX + 1);
    assert_eq!(seal::wrap(&label, b"s", 1), Err(Errno::Invalid));
    assert_eq!(seal::unwrap(&label, &[0; 64], 2), Err(Errno::Invalid));
    assert!(wrap(&"x".repeat(seal::WRAP_LABEL_MAX), b"s", 3).is_ok());
}

// ---------------------------------------------------------------------------
// Seal: many outstanding tokens, completions in any order (README "seal").
// ---------------------------------------------------------------------------

mod pipelined {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use ciris_host_abi::host::Host;
    use ciris_host_abi::seal::{COMPOSITE_SIGNATURE_LEN, KEX_PUBLIC_KEY_LEN};
    use ciris_host_abi::types::{Errno, KeyKind};

    /// Accepts operations, completes them only when the test says, in the
    /// order the test chooses.
    #[derive(Default)]
    pub struct Pipelined {
        pub started: RefCell<Vec<u64>>,
        pending: RefCell<BTreeMap<u64, Vec<u8>>>,
        done: RefCell<BTreeMap<u64, Vec<u8>>>,
    }
    impl Pipelined {
        pub fn complete(&self, token: u64) {
            let v = self.pending.borrow_mut().remove(&token).unwrap();
            self.done.borrow_mut().insert(token, v);
        }
    }
    impl Host for Pipelined {
        fn monotonic_us(&self) -> u64 {
            0
        }
        fn wall_ms(&self) -> Option<i64> {
            None
        }
        fn random_fill(&self, len: u32) -> Vec<u8> {
            vec![1; len as usize]
        }
        fn log_record(&self, _: u8, _: &str, _: &str) {}
        fn seal_sign_composite(&self, _id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
            self.started.borrow_mut().push(token);
            self.pending
                .borrow_mut()
                .insert(token, vec![msg[0]; COMPOSITE_SIGNATURE_LEN]);
            Ok(())
        }
        fn seal_generate(&self, _id: &str, kind: KeyKind, token: u64) -> Result<(), Errno> {
            assert_eq!(kind, KeyKind::OnionHop);
            self.started.borrow_mut().push(token);
            self.pending
                .borrow_mut()
                .insert(token, vec![0xAA; KEX_PUBLIC_KEY_LEN]);
            Ok(())
        }
        fn seal_take(&self, token: u64) -> Result<Vec<u8>, Errno> {
            if self.pending.borrow().contains_key(&token) {
                return Err(Errno::WouldBlock);
            }
            self.done.borrow_mut().remove(&token).ok_or(Errno::NotFound)
        }
    }
}

#[test]
fn seal_tokens_pipeline_and_complete_out_of_order() {
    use std::rc::Rc;
    struct Shared(Rc<pipelined::Pipelined>);
    impl Host for Shared {
        fn monotonic_us(&self) -> u64 {
            self.0.monotonic_us()
        }
        fn wall_ms(&self) -> Option<i64> {
            None
        }
        fn random_fill(&self, len: u32) -> Vec<u8> {
            self.0.random_fill(len)
        }
        fn log_record(&self, _: u8, _: &str, _: &str) {}
        fn seal_sign_composite(&self, id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
            self.0.seal_sign_composite(id, msg, token)
        }
        fn seal_generate(&self, id: &str, kind: KeyKind, token: u64) -> Result<(), Errno> {
            self.0.seal_generate(id, kind, token)
        }
        fn seal_take(&self, token: u64) -> Result<Vec<u8>, Errno> {
            self.0.seal_take(token)
        }
    }
    let h = Rc::new(pipelined::Pipelined::default());
    host::install(Shared(h.clone()));
    seal::sign_composite("id", b"a", 1).unwrap();
    seal::sign_composite("id", b"b", 2).unwrap();
    seal::generate("onion-hop:v1:x", KeyKind::OnionHop, 3).unwrap();
    assert_eq!(*h.started.borrow(), [1, 2, 3]);
    assert_eq!(seal::take(1), Err(Errno::WouldBlock));
    h.complete(3);
    h.complete(2);
    assert_eq!(
        seal::take(2).unwrap(),
        vec![b'b'; seal::COMPOSITE_SIGNATURE_LEN]
    );
    assert_eq!(seal::take(3).unwrap().len(), seal::KEX_PUBLIC_KEY_LEN);
    assert_eq!(seal::take(1), Err(Errno::WouldBlock));
    h.complete(1);
    assert_eq!(
        seal::take(1).unwrap(),
        vec![b'a'; seal::COMPOSITE_SIGNATURE_LEN]
    );
    assert_eq!(seal::take(1), Err(Errno::NotFound));
}

#[test]
fn new_event_variants_exist() {
    let evs = [
        Event::Failed(FailInfo {
            token: 1,
            reason: FailReason::NameNotResolved,
        }),
        Event::ListenerFailed(FailInfo {
            token: 2,
            reason: FailReason::Denied,
        }),
        Event::ClockTrusted,
    ];
    assert_eq!(evs.len(), 3);
}
