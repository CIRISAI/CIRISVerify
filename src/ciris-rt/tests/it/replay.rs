//! FSD §5.1 / §11.4: record a small async node under a scripted host, then
//! replay it with no host: byte-identical results, identical import
//! sequence, a loud failure on divergence, and no secret bytes in the log.

use std::cell::RefCell;
use std::collections::VecDeque;

use ciris_host_abi::random;
use ciris_rt::net::{self, Carrier};
use ciris_rt::replay::{
    self, Log, RecordOptions, SecretOp, SecretSource, Secrets, SeededRandom, Session, TestSecrets,
};
use ciris_rt::time::{sleep, timeout, Duration, Instant};
use ciris_rt::{seal, spawn, RtNode};

use crate::support::{fake_sig, Scripted, StreamState};

std::thread_local! {
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

const SEED: &[u8] = b"replay test seed";
const SECRET_PT: &[u8] = b"rns transport identity: SECRET!!";
const HOP_CT: [u8; 1120] = [0x11; 1120];
const TRANSIT_CT: [u8; 1120] = [0x22; 1120];

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
            let sig = seal::sign_composite("node", &buf[..n]).await.unwrap();
            // Node-held secrets: wrapped at rest, unwrapped, and X-Wing
            // decapsulations to an onion-hop and a transit static. None of
            // them may reach the log.
            let blob = seal::wrap("rns-transport-identity/v1", SECRET_PT)
                .await
                .unwrap();
            let back = seal::unwrap("rns-transport-identity/v1", &blob)
                .await
                .unwrap();
            let ss = seal::xwing_decap("onion-hop:v1:me", &HOP_CT).await.unwrap();
            let tss = seal::xwing_decap("transit:v1:me", &TRANSIT_CT)
                .await
                .unwrap();
            let waited = t0.elapsed().as_micros() as u64;
            OUT.with(|o| {
                let mut o = o.borrow_mut();
                o.push(u8::try_from(nonce.len()).unwrap());
                o.extend_from_slice(&buf[..n]);
                o.extend_from_slice(&sig);
                o.extend_from_slice(&blob);
                o.push(u8::from(&back[..] == SECRET_PT));
                o.push(u8::try_from(ss.len()).unwrap());
                o.push(u8::try_from(tss.len()).unwrap());
                o.extend_from_slice(&waited.to_be_bytes());
            });
        });
        spawn(async {
            sleep(Duration::from_millis(2)).await;
            let r = random::fill(4);
            OUT.with(|o| o.borrow_mut().push(u8::try_from(r.len()).unwrap()));
        });
        Ok(())
    }
    fn api(_req: Vec<u8>, _local: bool) -> Vec<u8> {
        OUT.with(|o| o.borrow().clone())
    }
}
ciris_rt::node!(Demo);

fn scripted() -> Scripted {
    let h = Scripted::seeded(7, SEED);
    h.0.borrow_mut().dial_script.push_back(Ok(StreamState {
        scripted: VecDeque::from([(30_000, b"ack".to_vec())]),
        send_cap: 5,
        ..StreamState::default()
    }));
    h
}

fn record_with(opts: RecordOptions) -> (Log, Vec<u8>, Scripted) {
    let h = scripted();
    let s = Session::<__CirisRtNode>::record_with(h.clone(), opts);
    s.init().unwrap();
    let mut done = || OUT.with(|o| o.borrow().len() > 8);
    h.drive_with(5_000, 200, &mut done, |e| s.on_event(e), |b| s.tick(b));
    let out = s.api(b"", true);
    (s.finish(), out, h)
}

fn record() -> (Log, Vec<u8>) {
    let (log, out, _) = record_with(RecordOptions::default());
    (log, out)
}

/// The test SecretSource: the same seeded stream and a fresh copy of the
/// scripted host as the vault.
fn secrets() -> TestSecrets<Scripted> {
    TestSecrets::new(SeededRandom::new(SEED), Scripted::new(1))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn redacted_record_then_replay_is_byte_identical() {
    let (log, out) = record();
    assert_eq!(log.secrets(), Secrets::Redacted);
    assert!(out.len() > 3373, "the node finished");
    assert_eq!(out[..2], [4, 16], "both tasks ran (the 2 ms one first)");
    let imports = log.import_calls();
    for want in [
        "clock.monotonic-us",
        "random.fill",
        "net.dial",
        "[method]stream.send",
        "[method]stream.recv",
        "seal.sign-composite",
        "seal.wrap",
        "seal.unwrap",
        "seal.xwing-decap",
        "seal.take",
        "wake.next-deadline",
    ] {
        assert!(imports.contains(&want), "recorded {want}");
    }

    let text = log.to_jsonl();
    assert!(text
        .starts_with("{\"format\":\"ciris-rt-replay\",\"secrets\":\"redacted\",\"version\":2}\n"));
    let parsed = Log::from_jsonl(&text).unwrap();
    assert_eq!(parsed, log);
    OUT.with(|o| o.borrow_mut().clear());
    let replayed = replay::replay_with::<__CirisRtNode>(&parsed, secrets());

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
    assert_eq!(
        last.ret,
        replay::Value::String(hex(&out)),
        "byte-identical output"
    );
}

#[test]
fn the_redacted_log_holds_no_secret_bytes() {
    let (log, _) = record();
    let text = log.to_jsonl();
    let mut stream = SeededRandom::new(SEED);
    let draw16 = stream.fill(16);
    let draw4 = stream.fill(4);
    let decap = fake_sig(&HOP_CT, 32);
    let transit_decap = fake_sig(&TRANSIT_CT, 32);
    for (what, bytes) in [
        ("the wrap plaintext", SECRET_PT.to_vec()),
        ("the onion-hop xwing-decap secret", decap),
        ("the transit xwing-decap secret", transit_decap),
        ("the 16-byte random draw", draw16),
        ("the 4-byte random draw", draw4),
    ] {
        assert!(!text.contains(&hex(&bytes)), "{what} leaked into the log");
    }
    // What redaction looks like, and what stays raw.
    let redacted: Vec<_> = log
        .entries()
        .iter()
        .filter(|e| e.to_owned_value_has_redaction())
        .map(|e| e.call.as_str())
        .collect();
    assert_eq!(
        redacted,
        [
            "random.fill",
            "random.fill",
            "seal.wrap",
            "seal.take",
            "seal.take",
            "seal.take"
        ],
        "random.fill results, wrap's plaintext, unwrap's and both xwing-decaps' take"
    );
    let sig_take = log.entries().iter().find(|e| {
        e.call == "seal.take" && e.ret["ok"].as_str().is_some_and(|h| h.len() == 3373 * 2)
    });
    assert!(sig_take.is_some(), "the signature stays raw");
}

trait HasRedaction {
    fn to_owned_value_has_redaction(&self) -> bool;
}
impl HasRedaction for replay::Entry {
    fn to_owned_value_has_redaction(&self) -> bool {
        let r = |v: &replay::Value| v.get("redacted") == Some(&replay::Value::Bool(true));
        r(&self.ret) || r(&self.ret["ok"]) || r(&self.args["plaintext"])
    }
}

#[test]
#[should_panic(expected = "re-supplied a different random.fill")]
fn a_wrongly_seeded_secret_source_is_caught_by_the_hash() {
    let (log, _) = record();
    let _ = replay::replay_with::<__CirisRtNode>(
        &log,
        TestSecrets::new(SeededRandom::new(b"another seed"), Scripted::new(1)),
    );
}

/// Right randomness, but a vault that answers one decapsulation wrongly.
struct TamperedVault(TestSecrets<Scripted>);
impl SecretSource for TamperedVault {
    fn random_fill(&mut self, len: u32) -> Vec<u8> {
        self.0.random_fill(len)
    }
    fn seal_result(&mut self, op: &SecretOp) -> Result<Vec<u8>, ciris_rt::seal::Errno> {
        let mut v = self.0.seal_result(op)?;
        if matches!(op, SecretOp::XwingDecap { .. }) {
            v[0] ^= 1;
        }
        Ok(v)
    }
}

#[test]
#[should_panic(expected = "re-supplied a different seal.take")]
fn a_tampered_vault_is_caught_by_the_hash() {
    let (log, _) = record();
    let _ = replay::replay_with::<__CirisRtNode>(&log, TamperedVault(secrets()));
}

#[test]
#[should_panic(expected = "replay this log with a SecretSource")]
fn a_redacted_log_needs_a_secret_source() {
    let (log, _) = record();
    let _ = replay::replay::<__CirisRtNode>(&log);
}

#[test]
#[should_panic(expected = "replay divergence")]
fn a_changed_import_result_fails_loudly() {
    let (log, _) = record();
    // Change the bytes the peer sent: the signature input, and so the seal
    // call's arguments, diverge.
    let text = log.to_jsonl().replacen(&hex(b"ack"), &hex(b"acx"), 1);
    let _ = replay::replay_with::<__CirisRtNode>(&Log::from_jsonl(&text).unwrap(), secrets());
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
    let _ = replay::replay_with::<__CirisRtNode>(&Log::from_jsonl(&short).unwrap(), secrets());
}

// Raw capture: only with the `replay-capture-secrets` feature (and a
// debug build). `cargo test -p ciris-rt --features replay-capture-secrets`.

#[cfg(not(feature = "replay-capture-secrets"))]
#[test]
#[should_panic(expected = "raw secret capture refused")]
fn raw_capture_is_refused_without_the_feature() {
    assert!(replay::raw_capture_allowed().is_err());
    let _ = record_with(RecordOptions {
        capture_raw_secrets: true,
    });
}

#[cfg(all(feature = "replay-capture-secrets", not(debug_assertions)))]
#[test]
#[should_panic(expected = "refused in a build without debug_assertions")]
fn raw_capture_is_refused_in_release_even_with_the_feature() {
    let _ = record_with(RecordOptions {
        capture_raw_secrets: true,
    });
}

#[cfg(all(feature = "replay-capture-secrets", debug_assertions))]
#[test]
fn raw_capture_with_the_feature_writes_secrets_and_warns() {
    let (log, out, host) = record_with(RecordOptions {
        capture_raw_secrets: true,
    });
    assert_eq!(log.secrets(), Secrets::Raw);
    let text = log.to_jsonl();
    assert!(
        text.starts_with("{\"format\":\"ciris-rt-replay\",\"secrets\":\"raw\",\"version\":2}\n")
    );
    assert!(
        text.contains(&hex(SECRET_PT)),
        "raw: the plaintext is in the log"
    );
    assert!(
        host.0.borrow().logs[0].starts_with("0 ciris-rt::replay: RAW SECRET CAPTURE IS ON"),
        "a loud error-level warning at start"
    );
    // A raw log replays without a SecretSource.
    OUT.with(|o| o.borrow_mut().clear());
    let replayed = replay::replay::<__CirisRtNode>(&Log::from_jsonl(&text).unwrap());
    assert_eq!(replayed.to_jsonl(), text);
    assert_eq!(
        replayed.entries().last().unwrap().ret,
        replay::Value::String(hex(&out))
    );
}
