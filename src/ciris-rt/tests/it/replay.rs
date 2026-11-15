//! FSD §5.1 / §11.4: record a small async node under a scripted host, then
//! replay it with no host at all: byte-identical results, identical
//! import sequence, and a loud failure on divergence.

use std::cell::RefCell;
use std::collections::VecDeque;

use ciris_host_abi::random;
use ciris_rt::net::{self, Carrier};
use ciris_rt::replay::{self, Log, Session};
use ciris_rt::time::{sleep, timeout, Duration, Instant};
use ciris_rt::{seal, spawn, RtNode};

use crate::support::{Scripted, StreamState};

std::thread_local! {
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

struct Demo;
impl RtNode for Demo {
    fn init() -> Result<(), String> {
        OUT.with(|o| o.borrow_mut().clear());
        spawn(async {
            let nonce = random::fill(16);
            let t0 = Instant::now();
            sleep(Duration::from_millis(5)).await;
            let conn = net::dial(Carrier::Tcp, "peer:4242", &[]).await.unwrap();
            conn.write_all(b"hello, replay").await.unwrap();
            let mut buf = [0u8; 32];
            let n = timeout(Duration::from_secs(1), conn.read(&mut buf))
                .await
                .expect("reply in time")
                .unwrap();
            let mut msg = nonce.clone();
            msg.extend_from_slice(&buf[..n]);
            let sig = seal::sign_composite("node", &msg).await.unwrap();
            let waited = t0.elapsed().as_micros() as u64;
            OUT.with(|o| {
                let mut o = o.borrow_mut();
                o.extend_from_slice(&nonce);
                o.extend_from_slice(&buf[..n]);
                o.extend_from_slice(&sig);
                o.extend_from_slice(&waited.to_be_bytes());
            });
        });
        // A second task: a timer that races the first.
        spawn(async {
            sleep(Duration::from_millis(2)).await;
            let r = random::fill(4);
            OUT.with(|o| o.borrow_mut().extend_from_slice(&r));
        });
        Ok(())
    }
    fn api(_req: Vec<u8>, _local: bool) -> Vec<u8> {
        OUT.with(|o| o.borrow().clone())
    }
}
ciris_rt::node!(Demo);

fn record() -> (Log, Vec<u8>) {
    let h = Scripted::new(7);
    h.0.borrow_mut().dial_script.push_back(Ok(StreamState {
        scripted: VecDeque::from([(30_000, b"ack".to_vec())]),
        send_cap: 5,
        ..StreamState::default()
    }));
    let s = Session::<__CirisRtNode>::record(h.clone());
    s.init().unwrap();
    let mut done = || OUT.with(|o| o.borrow().len() > 4 + 16);
    h.drive_with(5_000, 100, &mut done, |e| s.on_event(e), |b| s.tick(b));
    let out = s.api(b"", true);
    (s.finish(), out)
}

#[test]
fn record_then_replay_is_byte_identical() {
    let (log, out) = record();
    assert_eq!(out.len(), 4 + 16 + 3 + 3373 + 8, "the node finished");
    let imports = log.import_calls();
    for want in [
        "clock.monotonic-us",
        "random.fill",
        "net.dial",
        "[method]stream.send",
        "[method]stream.recv",
        "seal.sign-composite",
        "seal.take",
        "wake.next-deadline",
    ] {
        assert!(imports.contains(&want), "recorded {want}");
    }

    // Round-trip the documented format, then replay with no host.
    let text = log.to_jsonl();
    assert!(text.starts_with("{\"format\":\"ciris-rt-replay\",\"version\":1}\n"));
    let parsed = Log::from_jsonl(&text).unwrap();
    assert_eq!(parsed, log);
    OUT.with(|o| o.borrow_mut().clear());
    let replayed = replay::replay::<__CirisRtNode>(&parsed);

    assert_eq!(
        replayed.import_calls(),
        imports,
        "identical import sequence"
    );
    assert_eq!(
        replayed.to_jsonl(),
        text,
        "byte-identical log, results included"
    );
    let last = replayed.entries().last().unwrap();
    assert_eq!(last.call, "api");
    assert_eq!(last.ret, serde_json_hex(&out), "byte-identical node output");
}

fn serde_json_hex(b: &[u8]) -> replay::Value {
    replay::Value::String(b.iter().map(|x| format!("{x:02x}")).collect())
}

#[test]
#[should_panic(expected = "replay divergence")]
fn a_changed_import_result_fails_loudly() {
    let (log, _) = record();
    // Change the first random byte the node drew: its signature input, and
    // so the seal call's arguments, diverge.
    let mut text = String::new();
    let mut done = false;
    for line in log.to_jsonl().lines() {
        if !done && line.contains("\"call\":\"random.fill\"") {
            let i = line.find("\"ret\":\"").unwrap() + 7;
            let mut l = line.to_owned();
            let flip = if &l[i..=i] == "0" { "1" } else { "0" };
            l.replace_range(i..=i, flip);
            text.push_str(&l);
            done = true;
        } else {
            text.push_str(line);
        }
        text.push('\n');
    }
    let tampered = Log::from_jsonl(&text).unwrap();
    let _ = replay::replay::<__CirisRtNode>(&tampered);
}

#[test]
#[should_panic(expected = "replay divergence")]
fn a_truncated_log_fails_loudly() {
    let (log, _) = record();
    let text = log.to_jsonl();
    let lines: Vec<&str> = text.lines().collect();
    // Cut right after an import in the middle of the run, so an export's
    // return (and everything after) is missing.
    let at = (1..lines.len() / 2)
        .rev()
        .find(|&i| lines[i].contains("\"dir\":\"import\""))
        .unwrap();
    let short = lines[..=at].join("\n");
    let _ = replay::replay::<__CirisRtNode>(&Log::from_jsonl(&short).unwrap());
}
