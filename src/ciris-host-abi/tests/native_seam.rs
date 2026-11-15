//! The same node code, linked natively against an installed `Host`.

use std::cell::RefCell;
use std::rc::Rc;

use ciris_host_abi::host::{self, Host};
use ciris_host_abi::log::Level;
use ciris_host_abi::types::{Carrier, Durability, Errno};
use ciris_host_abi::{clock, log, net, random, seal, storage, Event, Node};

#[derive(Default)]
struct Recorded {
    logs: Vec<(u8, String, String)>,
    metrics: Vec<(String, f64)>,
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
    fn log_metric(&self, name: &str, value: f64) {
        self.rec.borrow_mut().metrics.push((name.into(), value));
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
        log::metric("budget", f64::from(budget_us));
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
    assert_eq!(rec.metrics, vec![("budget".to_owned(), 500.0)]);
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
