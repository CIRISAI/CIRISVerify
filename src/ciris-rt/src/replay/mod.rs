//! Record and replay at the ABI boundary (FSD §5.1 "Deterministic tick",
//! §11.4 rule 3).
//!
//! Every source of non-determinism crosses `ciris-host-abi`: time,
//! randomness, I/O, seal results and the order of events. A [`Session`]
//! drives a node's exports (`init`, `tick`, `on-event`, `api`) through a
//! [`ciris_host_abi::host::Host`] that either
//!
//! * **records**: forwards every import to the real host and appends the
//!   call, its arguments and its result to a [`Log`]; or
//! * **replays**: serves each import's result from a recorded log, never
//!   touching a host, and panics at the first divergence (a different
//!   call, different arguments, a different export return value, or an
//!   import the recording did not make).
//!
//! [`replay`] re-runs a whole log and returns the log the replay itself
//! produced, which equals the input byte for byte when the run is
//! deterministic.
//!
//! # Format: JSON lines, append-only
//!
//! Line 1 is a header, `{"format":"ciris-rt-replay","secrets":"redacted","version":2}`
//! (`"secrets":"raw"` only for a raw capture, below). Each further line is
//! one [`Entry`], an object with sorted keys:
//!
//! ```text
//! {"args":{"budget_us":5000},"call":"tick","dir":"export","ret":null,"seq":3}
//! {"args":{},"call":"clock.monotonic-us","dir":"import","ret":1000,"seq":4}
//! {"args":{"len":32},"call":"random.fill","dir":"import","ret":{"len":32,"redacted":true,"sha256":"5e…"},"seq":5}
//! {"args":{"max":4096,"stream":1},"call":"[method]stream.recv","dir":"import","ret":{"err":"would-block"},"seq":9}
//! {"args":null,"call":"tick","dir":"return","ret":2000,"seq":12}
//! ```
//!
//! * `dir`: `export` (the host called the node; `args` are the export's
//!   arguments), `return` (the export returned `ret`), or `import` (the node
//!   called the host). Imports appear between their export and its return.
//! * `call`: the WIT name: `clock.monotonic-us`, `net.dial`,
//!   `[method]stream.recv`, `[method]volume.read`, `[method]datagram.send-to`,
//!   `seal.sign-composite`, ...; exports `init`, `tick`, `on-event`, `api`.
//! * Byte strings are lowercase hex; enums are their WIT names;
//!   `result<T, errno>` is `{"ok":T}` / `{"err":"<errno>"}`; options are
//!   `null` or the value. Resources returned by the host (a stream, a
//!   volume, a datagram socket) are numbered in the order they appear, from
//!   1 (`{"ok":{"stream":1}}`), and later method calls name that number.
//!
//! # Secrets are redacted by default
//!
//! Ephemeral keys are never persisted in plaintext, and a log is a file. So
//! these values are written as `{"redacted":true,"sha256":"<hex>","len":<n>}`
//! (SHA-256 of the bytes), never as the bytes:
//!
//! * the result of `random.fill` (its bytes become ephemeral keys and
//!   nonces);
//! * the `seal.take` result of a `seal.unwrap`, `seal.kem-decap` or
//!   `seal.xwing-decap` (the token is remembered when the operation starts);
//! * the `plaintext` argument of `seal.wrap`.
//!
//! Signatures, public keys, wrapped blobs and everything else stay raw.
//! A node that logs a secret through `log.record`, or sends one in clear
//! over a stream, puts it in the log itself; that is the node's bug.
//!
//! Replaying a redacted log needs a [`SecretSource`] ([`replay_with`],
//! [`Session::replaying_with`]) that re-supplies each redacted value: a
//! seeded RNG for `random.fill` and a test vault for the seal operations
//! ([`TestSecrets`]). Each re-supplied value is checked against the recorded
//! `sha256` and `len`, and a mismatch panics.
//!
//! # Raw capture (never in release)
//!
//! [`Session::record_with`] with [`RecordOptions::capture_raw_secrets`]
//! writes the secrets raw (hex) and marks the header `"secrets":"raw"`. It
//! needs BOTH the cargo feature `replay-capture-secrets` (off by default) and
//! the runtime flag, and it is refused (panics) in a build without
//! `debug_assertions`, i.e. any `--release` build, even with the feature on.
//! When it starts it logs an error-level `log.record` warning through the
//! live host. **Never enable `replay-capture-secrets` in a release or
//! production build.**

mod codec;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::fmt;
use core::marker::PhantomData;

use ciris_host_abi::host::{Host, HostDatagram, HostStream, HostVolume};
use ciris_host_abi::types::{
    Carrier, ConnInfo, Custody, Durability, Errno, Event, KeyKind, ListenOptions, MetricKind,
    NetInterface,
};
use ciris_host_abi::Node;
use serde_json::json;
/// The JSON value type entries carry (`serde_json::Value`).
pub use serde_json::Value;

use codec as c;

/// The header line's format name.
pub const FORMAT: &str = "ciris-rt-replay";
/// The header line's version. 2: secrets are redacted (or marked raw).
pub const VERSION: u64 = 2;

/// How a log carries secret values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Secrets {
    /// `{"redacted":true,"sha256":…,"len":…}` (the default).
    #[default]
    Redacted,
    /// Raw hex: a debug capture only (module docs).
    Raw,
}

impl Secrets {
    fn name(self) -> &'static str {
        match self {
            Self::Redacted => "redacted",
            Self::Raw => "raw",
        }
    }
}

/// Options for [`Session::record_with`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordOptions {
    /// Write secrets raw. Needs the `replay-capture-secrets` feature and a
    /// build with `debug_assertions`; refused (panics) otherwise. Never in
    /// release or production.
    pub capture_raw_secrets: bool,
}

/// Whether raw secret capture may run in this build.
///
/// # Errors
/// Why not: the `replay-capture-secrets` feature is off, or the build has
/// no `debug_assertions` (a release build).
pub fn raw_capture_allowed() -> Result<(), &'static str> {
    if !cfg!(feature = "replay-capture-secrets") {
        return Err("ciris-rt was built without the replay-capture-secrets feature");
    }
    if !cfg!(debug_assertions) {
        return Err("raw secret capture is refused in a build without debug_assertions");
    }
    Ok(())
}

/// A secret seal operation as the node started it; a [`SecretSource`]
/// re-runs it to re-supply the redacted result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretOp {
    /// `seal.unwrap(label, wrapped)`.
    Unwrap {
        /// The label.
        label: String,
        /// The wrapped blob.
        wrapped: Vec<u8>,
    },
    /// `seal.kem-decap(id, x25519-peer-pub, mlkem-ct)`.
    KemDecap {
        /// The key id.
        id: String,
        /// The peer's X25519 public key.
        x25519_peer_pub: Vec<u8>,
        /// The ML-KEM-768 ciphertext.
        mlkem_ct: Vec<u8>,
    },
    /// `seal.xwing-decap(id, ct)`.
    XwingDecap {
        /// The key id.
        id: String,
        /// The X-Wing ciphertext.
        ct: Vec<u8>,
    },
}

/// Re-supplies the values a redacted log does not hold, for replay.
pub trait SecretSource {
    /// The next `random.fill(len)` result.
    fn random_fill(&mut self, len: u32) -> Vec<u8>;
    /// The result of `op` (what `seal.take` returned for it).
    ///
    /// # Errors
    /// The vault's own failure; a recorded success then diverges.
    fn seal_result(&mut self, op: &SecretOp) -> Result<Vec<u8>, Errno>;
}

/// A deterministic byte stream: SHA-256 in counter mode over a seed, block
/// `i` = SHA-256("ciris-rt/seeded-random/v1" || u32_be(len(seed)) || seed ||
/// u64_be(i)). **TEST ONLY**: for scripted hosts whose `random.fill` must be
/// re-suppliable on replay. Never a node's RNG.
#[derive(Clone, Debug)]
pub struct SeededRandom {
    seed: Vec<u8>,
    counter: u64,
    buf: Vec<u8>,
}

impl SeededRandom {
    /// A stream from `seed`.
    #[must_use]
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
            buf: Vec::new(),
        }
    }

    /// The next `len` bytes.
    pub fn fill(&mut self, len: usize) -> Vec<u8> {
        use sha2::Digest as _;
        while self.buf.len() < len {
            let mut h = sha2::Sha256::new();
            h.update(b"ciris-rt/seeded-random/v1");
            h.update(
                u32::try_from(self.seed.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            h.update(&self.seed);
            h.update(self.counter.to_be_bytes());
            self.counter += 1;
            self.buf.extend_from_slice(&h.finalize());
        }
        let rest = self.buf.split_off(len);
        core::mem::replace(&mut self.buf, rest)
    }
}

impl Default for SeededRandom {
    fn default() -> Self {
        Self::new(b"")
    }
}

/// The test [`SecretSource`]: a [`SeededRandom`] for `random.fill`, and a
/// test vault (any [`Host`] implementing the seal operations, e.g. a fresh
/// copy of the scripted host the recording used) that re-runs each secret
/// seal operation. **TEST ONLY.**
pub struct TestSecrets<V> {
    /// The random stream; seeded as the recorded host's was.
    pub random: SeededRandom,
    /// The vault that re-runs the seal operations.
    pub vault: V,
    next_token: u64,
}

impl<V> fmt::Debug for TestSecrets<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestSecrets").finish_non_exhaustive()
    }
}

impl<V: Host> TestSecrets<V> {
    /// A source over `random` and `vault`.
    pub fn new(random: SeededRandom, vault: V) -> Self {
        Self {
            random,
            vault,
            next_token: u64::MAX,
        }
    }
}

impl<V: Host> SecretSource for TestSecrets<V> {
    fn random_fill(&mut self, len: u32) -> Vec<u8> {
        self.random.fill(len as usize)
    }
    fn seal_result(&mut self, op: &SecretOp) -> Result<Vec<u8>, Errno> {
        let t = self.next_token;
        self.next_token -= 1;
        match op {
            SecretOp::Unwrap { label, wrapped } => self.vault.seal_unwrap(label, wrapped, t)?,
            SecretOp::KemDecap {
                id,
                x25519_peer_pub,
                mlkem_ct,
            } => self
                .vault
                .seal_kem_decap(id, x25519_peer_pub, mlkem_ct, t)?,
            SecretOp::XwingDecap { id, ct } => self.vault.seal_xwing_decap(id, ct, t)?,
        }
        self.vault.seal_take(t)
    }
}

fn redact(b: &[u8]) -> Value {
    use sha2::Digest as _;
    json!({
        "redacted": true,
        "sha256": hex::encode(sha2::Sha256::digest(b)),
        "len": b.len(),
    })
}

fn is_redacted(v: &Value) -> bool {
    v.get("redacted") == Some(&Value::Bool(true))
}

/// Which way a logged call went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// The node called the host.
    Import,
    /// The host called the node.
    Export,
    /// A node export returned.
    Return,
}

impl Dir {
    fn name(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
            Self::Return => "return",
        }
    }
}

/// One logged call.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Position in the log, from 0.
    pub seq: u64,
    /// Which way it went.
    pub dir: Dir,
    /// The WIT name of the call.
    pub call: String,
    /// Its arguments (`null` on a return).
    pub args: Value,
    /// Its result (`null` on an export).
    pub ret: Value,
}

impl Entry {
    fn to_value(&self) -> Value {
        json!({
            "seq": self.seq,
            "dir": self.dir.name(),
            "call": self.call,
            "args": self.args,
            "ret": self.ret,
        })
    }
}

/// An append-only log of one run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Log {
    entries: Vec<Entry>,
    secrets: Secrets,
}

impl Log {
    /// How this log carries secrets.
    #[must_use]
    pub fn secrets(&self) -> Secrets {
        self.secrets
    }

    /// The entries, in order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The import call names, in order: the node's import sequence.
    #[must_use]
    pub fn import_calls(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.dir == Dir::Import)
            .map(|e| e.call.as_str())
            .collect()
    }

    /// Serialize as JSON lines (header first, one entry per line, each
    /// line ending in `\n`).
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let header =
            json!({ "format": FORMAT, "version": VERSION, "secrets": self.secrets.name() });
        let mut out = format!("{header}\n");
        for e in &self.entries {
            out.push_str(&e.to_value().to_string());
            out.push('\n');
        }
        out
    }

    /// Parse JSON lines written by [`to_jsonl`](Self::to_jsonl).
    ///
    /// # Errors
    /// A description of the first malformed line.
    pub fn from_jsonl(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        let header: Value = serde_json::from_str(lines.next().ok_or("empty log")?)
            .map_err(|e| format!("header: {e}"))?;
        if header["format"] != FORMAT || header["version"] != VERSION {
            return Err(format!("not a {FORMAT} v{VERSION} log: {header}"));
        }
        let secrets = match header["secrets"].as_str() {
            Some("redacted") => Secrets::Redacted,
            Some("raw") => Secrets::Raw,
            other => return Err(format!("header: bad secrets {other:?}")),
        };
        let mut entries = Vec::new();
        for (i, line) in lines.enumerate() {
            let v: Value =
                serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 2))?;
            let dir = match v["dir"].as_str() {
                Some("import") => Dir::Import,
                Some("export") => Dir::Export,
                Some("return") => Dir::Return,
                other => return Err(format!("line {}: bad dir {other:?}", i + 2)),
            };
            entries.push(Entry {
                seq: v["seq"]
                    .as_u64()
                    .ok_or_else(|| format!("line {}: seq", i + 2))?,
                dir,
                call: v["call"]
                    .as_str()
                    .ok_or_else(|| format!("line {}: call", i + 2))?
                    .to_owned(),
                args: v["args"].clone(),
                ret: v["ret"].clone(),
            });
        }
        Ok(Self { entries, secrets })
    }
}

/// The real host and the resources it handed out (record mode only).
struct Live {
    host: Box<dyn Host>,
    streams: RefCell<BTreeMap<u64, Box<dyn HostStream>>>,
    volumes: RefCell<BTreeMap<u64, Box<dyn HostVolume>>>,
    datagrams: RefCell<BTreeMap<u64, Box<dyn HostDatagram>>>,
}

struct Tape {
    live: Option<Live>,
    expected: Option<Log>,
    cursor: Cell<usize>,
    out: RefCell<Log>,
    next_handle: Cell<u64>,
    /// Seal tokens whose `take` result is secret.
    secret_ops: RefCell<BTreeMap<u64, SecretOp>>,
    source: RefCell<Option<Box<dyn SecretSource>>>,
}

impl Tape {
    fn push(&self, dir: Dir, call: &str, args: Value, ret: Value) {
        let mut out = self.out.borrow_mut();
        let seq = out.entries.len() as u64;
        out.entries.push(Entry {
            seq,
            dir,
            call: call.to_owned(),
            args,
            ret,
        });
    }

    /// In replay mode: the expected entry at the cursor must be `dir call
    /// args`; returns its `ret` and advances. Panics loudly otherwise.
    fn expect(&self, dir: Dir, call: &str, args: &Value) -> Value {
        let log = self.expected.as_ref().expect("replay mode");
        if std::thread::panicking() {
            // Unwinding from a divergence already reported: a drop that
            // calls the host must not panic again (that would abort).
            return Value::Null;
        }
        let i = self.cursor.get();
        let Some(e) = log.entries.get(i) else {
            panic!(
                "replay divergence at seq {i}: the node made {} {call} {args} after the recording ended",
                dir.name()
            );
        };
        if e.dir != dir || e.call != call || (dir != Dir::Return && &e.args != args) {
            panic!(
                "replay divergence at seq {i}:\n  recorded: {} {} {}\n  replayed: {} {call} {args}",
                e.dir.name(),
                e.call,
                e.args,
                dir.name()
            );
        }
        self.cursor.set(i + 1);
        e.ret.clone()
    }

    /// One import: record it (calling the real host) or serve it from the
    /// log.
    fn import(&self, call: &str, args: Value, live: impl FnOnce(&Live, &Self) -> Value) -> Value {
        let ret = match &self.live {
            Some(l) => live(l, self),
            None => self.expect(Dir::Import, call, &args),
        };
        self.push(Dir::Import, call, args, ret.clone());
        ret
    }

    fn handle(&self) -> u64 {
        let h = self.next_handle.get() + 1;
        self.next_handle.set(h);
        h
    }

    /// How a secret is written to this tape's log.
    fn secret(&self, b: &[u8]) -> Value {
        match self.out.borrow().secrets {
            Secrets::Redacted => redact(b),
            Secrets::Raw => c::bytes(b),
        }
    }

    /// Replay: the bytes behind a recorded secret value. Raw: decode it.
    /// Redacted: ask the source, and check its answer against the recorded
    /// hash and length (panics on a mismatch).
    fn resolve(
        &self,
        call: &str,
        recorded: &Value,
        supply: impl FnOnce(&mut dyn SecretSource) -> Vec<u8>,
    ) -> Vec<u8> {
        if !is_redacted(recorded) {
            return c::de_bytes(recorded);
        }
        let seq = self.cursor.get() - 1;
        let mut src = self.source.borrow_mut();
        let Some(src) = src.as_mut() else {
            panic!(
                "replay divergence at seq {seq}: {call} is redacted; replay this log with a SecretSource (replay_with)"
            );
        };
        let bytes = supply(src.as_mut());
        let got = redact(&bytes);
        assert!(
            &got == recorded,
            "replay divergence at seq {seq}: the SecretSource re-supplied a different {call} value: recorded {recorded}, got {got}"
        );
        bytes
    }

    /// One seal operation start, remembering secret-result tokens.
    fn start(
        &self,
        call: &str,
        args: Value,
        token: u64,
        op: Option<SecretOp>,
        live: impl FnOnce(&Live) -> Result<(), Errno>,
    ) -> Result<(), Errno> {
        let v = self.import(call, args, |l, _| c::result(&live(l), c::unit));
        let r = c::de_result(&v, |_| ());
        if let (Ok(()), Some(op)) = (&r, op) {
            self.secret_ops.borrow_mut().insert(token, op);
        }
        r
    }
}

/// The `Host` a [`Session`] installs: records through to a live host, or
/// replays from a log.
#[derive(Clone)]
pub struct TapeHost {
    tape: Rc<Tape>,
}

impl fmt::Debug for TapeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TapeHost")
            .field("replaying", &self.tape.live.is_none())
            .field("entries", &self.tape.out.borrow().entries.len())
            .finish()
    }
}

fn live_stream<R>(l: &Live, id: u64, f: impl FnOnce(&dyn HostStream) -> R) -> R {
    let s = l.streams.borrow();
    f(s.get(&id).expect("recorded stream").as_ref())
}
fn live_volume<R>(l: &Live, id: u64, f: impl FnOnce(&dyn HostVolume) -> R) -> R {
    let v = l.volumes.borrow();
    f(v.get(&id).expect("recorded volume").as_ref())
}
fn live_datagram<R>(l: &Live, id: u64, f: impl FnOnce(&dyn HostDatagram) -> R) -> R {
    let d = l.datagrams.borrow();
    f(d.get(&id).expect("recorded datagram").as_ref())
}

fn handle_of(v: &Value, kind: &str) -> u64 {
    c::de_u64(&v[kind])
}

struct TapeStream {
    tape: Rc<Tape>,
    id: u64,
}
struct TapeVolume {
    tape: Rc<Tape>,
    id: u64,
}
struct TapeDatagram {
    tape: Rc<Tape>,
    id: u64,
}

impl HostStream for TapeStream {
    fn info(&self) -> ConnInfo {
        let v = self
            .tape
            .import("[method]stream.info", json!({"stream": self.id}), |l, _| {
                c::conn_info(&live_stream(l, self.id, |s| s.info()))
            });
        c::de_conn_info(&v)
    }
    fn send(&self, data: &[u8]) -> Result<u32, Errno> {
        let v = self.tape.import(
            "[method]stream.send",
            json!({"stream": self.id, "data": c::bytes(data)}),
            |l, _| c::result(&live_stream(l, self.id, |s| s.send(data)), |n| (*n).into()),
        );
        c::de_result(&v, |x| u32::try_from(c::de_u64(x)).expect("u32"))
    }
    fn recv(&self, max: u32) -> Result<Vec<u8>, Errno> {
        let v = self.tape.import(
            "[method]stream.recv",
            json!({"stream": self.id, "max": max}),
            |l, _| c::result(&live_stream(l, self.id, |s| s.recv(max)), |b| c::bytes(b)),
        );
        c::de_result(&v, c::de_bytes)
    }
    fn close(&self) {
        self.tape.import(
            "[method]stream.close",
            json!({"stream": self.id}),
            |l, _| {
                live_stream(l, self.id, |s| s.close());
                Value::Null
            },
        );
    }
}

impl HostVolume for TapeVolume {
    fn read(&self, file: u32, offset: u64, len: u32) -> Result<Vec<u8>, Errno> {
        let v = self.tape.import(
            "[method]volume.read",
            json!({"volume": self.id, "file": file, "offset": offset, "len": len}),
            |l, _| {
                c::result(
                    &live_volume(l, self.id, |x| x.read(file, offset, len)),
                    |b| c::bytes(b),
                )
            },
        );
        c::de_result(&v, c::de_bytes)
    }
    fn write(&self, file: u32, offset: u64, data: &[u8]) -> Result<(), Errno> {
        let v = self.tape.import(
            "[method]volume.write",
            json!({"volume": self.id, "file": file, "offset": offset, "data": c::bytes(data)}),
            |l, _| {
                c::result(
                    &live_volume(l, self.id, |x| x.write(file, offset, data)),
                    c::unit,
                )
            },
        );
        c::de_result(&v, |_| ())
    }
    fn sync(&self, file: u32) -> Result<(), Errno> {
        let v = self.tape.import(
            "[method]volume.sync",
            json!({"volume": self.id, "file": file}),
            |l, _| c::result(&live_volume(l, self.id, |x| x.sync(file)), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn truncate(&self, file: u32, size: u64) -> Result<(), Errno> {
        let v = self.tape.import(
            "[method]volume.truncate",
            json!({"volume": self.id, "file": file, "size": size}),
            |l, _| {
                c::result(
                    &live_volume(l, self.id, |x| x.truncate(file, size)),
                    c::unit,
                )
            },
        );
        c::de_result(&v, |_| ())
    }
    fn size(&self, file: u32) -> Result<u64, Errno> {
        let v = self.tape.import(
            "[method]volume.size",
            json!({"volume": self.id, "file": file}),
            |l, _| c::result(&live_volume(l, self.id, |x| x.size(file)), |n| (*n).into()),
        );
        c::de_result(&v, c::de_u64)
    }
    fn open(&self, name: &str, create: bool) -> Result<u32, Errno> {
        let v = self.tape.import(
            "[method]volume.open",
            json!({"volume": self.id, "name": name, "create": create}),
            |l, _| {
                c::result(&live_volume(l, self.id, |x| x.open(name, create)), |n| {
                    (*n).into()
                })
            },
        );
        c::de_result(&v, |x| u32::try_from(c::de_u64(x)).expect("u32"))
    }
    fn delete(&self, name: &str) -> Result<(), Errno> {
        let v = self.tape.import(
            "[method]volume.delete",
            json!({"volume": self.id, "name": name}),
            |l, _| c::result(&live_volume(l, self.id, |x| x.delete(name)), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn free_bytes(&self) -> Option<u64> {
        let v = self.tape.import(
            "[method]volume.free-bytes",
            json!({"volume": self.id}),
            |l, _| c::opt(live_volume(l, self.id, |x| x.free_bytes()), Value::from),
        );
        c::de_opt(&v, c::de_u64)
    }
    fn durability(&self) -> Durability {
        let v = self.tape.import(
            "[method]volume.durability",
            json!({"volume": self.id}),
            |l, _| c::durability(live_volume(l, self.id, |x| x.durability())),
        );
        c::de_durability(&v)
    }
}

impl HostDatagram for TapeDatagram {
    fn send_to(&self, addr: &str, data: &[u8]) -> Result<(), Errno> {
        let v = self.tape.import(
            "[method]datagram.send-to",
            json!({"datagram": self.id, "addr": addr, "data": c::bytes(data)}),
            |l, _| {
                c::result(
                    &live_datagram(l, self.id, |d| d.send_to(addr, data)),
                    c::unit,
                )
            },
        );
        c::de_result(&v, |_| ())
    }
    fn recv_from(&self) -> Result<(String, Vec<u8>), Errno> {
        let v = self.tape.import(
            "[method]datagram.recv-from",
            json!({"datagram": self.id}),
            |l, _| {
                c::result(&live_datagram(l, self.id, |d| d.recv_from()), |(a, b)| {
                    json!([a, c::bytes(b)])
                })
            },
        );
        c::de_result(&v, |x| (c::de_str(&x[0]), c::de_bytes(&x[1])))
    }
    fn local_addr(&self) -> Option<String> {
        let v = self.tape.import(
            "[method]datagram.local-addr",
            json!({"datagram": self.id}),
            |l, _| c::opt(live_datagram(l, self.id, |d| d.local_addr()), Value::String),
        );
        c::de_opt(&v, c::de_str)
    }
    fn max_datagram(&self) -> u32 {
        let v = self.tape.import(
            "[method]datagram.max-datagram",
            json!({"datagram": self.id}),
            |l, _| live_datagram(l, self.id, |d| d.max_datagram()).into(),
        );
        u32::try_from(c::de_u64(&v)).expect("u32")
    }
    fn multicast_join(&self, group: &str, interface: Option<&str>) -> Result<(), Errno> {
        let v = self.tape.import(
            "[method]datagram.multicast-join",
            json!({"datagram": self.id, "group": group, "interface": interface}),
            |l, _| {
                c::result(
                    &live_datagram(l, self.id, |d| d.multicast_join(group, interface)),
                    c::unit,
                )
            },
        );
        c::de_result(&v, |_| ())
    }
    fn multicast_leave(&self, group: &str, interface: Option<&str>) -> Result<(), Errno> {
        let v = self.tape.import(
            "[method]datagram.multicast-leave",
            json!({"datagram": self.id, "group": group, "interface": interface}),
            |l, _| {
                c::result(
                    &live_datagram(l, self.id, |d| d.multicast_leave(group, interface)),
                    c::unit,
                )
            },
        );
        c::de_result(&v, |_| ())
    }
}

impl TapeHost {
    fn stream(&self, v: &Value) -> Box<dyn HostStream> {
        Box::new(TapeStream {
            tape: self.tape.clone(),
            id: handle_of(v, "stream"),
        })
    }
}

/// Register a live resource under a fresh handle and encode it.
fn reg_stream(l: &Live, t: &Tape, s: Box<dyn HostStream>) -> Value {
    let id = t.handle();
    l.streams.borrow_mut().insert(id, s);
    json!({ "stream": id })
}

impl Host for TapeHost {
    fn monotonic_us(&self) -> u64 {
        let v = self.tape.import("clock.monotonic-us", json!({}), |l, _| {
            l.host.monotonic_us().into()
        });
        c::de_u64(&v)
    }
    fn wall_ms(&self) -> Option<i64> {
        let v = self.tape.import("clock.wall-ms", json!({}), |l, _| {
            c::opt(l.host.wall_ms(), Value::from)
        });
        c::de_opt(&v, |x| x.as_i64().expect("i64"))
    }
    fn random_fill(&self, len: u32) -> Vec<u8> {
        let t = &self.tape;
        let args = json!({ "len": len });
        let bytes = match &t.live {
            Some(l) => l.host.random_fill(len),
            None => {
                let rec = t.expect(Dir::Import, "random.fill", &args);
                t.resolve("random.fill", &rec, |s| s.random_fill(len))
            },
        };
        t.push(Dir::Import, "random.fill", args, t.secret(&bytes));
        bytes
    }
    fn log_record(&self, level: u8, target: &str, msg: &str) {
        self.tape.import(
            "log.record",
            json!({"level": level, "target": target, "msg": msg}),
            |l, _| {
                l.host.log_record(level, target, msg);
                Value::Null
            },
        );
    }
    fn log_metric(&self, name: &str, kind: MetricKind, value: f64, labels: &[(String, String)]) {
        self.tape.import(
            "log.metric",
            json!({"name": name, "kind": c::metric_kind(kind), "value": value, "labels": c::labels(labels)}),
            |l, _| {
                l.host.log_metric(name, kind, value, labels);
                Value::Null
            },
        );
    }
    fn storage_primary(&self) -> Box<dyn HostVolume> {
        let v = self.tape.import("storage.primary", json!({}), |l, t| {
            let id = t.handle();
            l.volumes.borrow_mut().insert(id, l.host.storage_primary());
            json!({ "volume": id })
        });
        Box::new(TapeVolume {
            tape: self.tape.clone(),
            id: handle_of(&v, "volume"),
        })
    }
    fn net_carriers(&self) -> Vec<Carrier> {
        let v = self.tape.import("net.carriers", json!({}), |l, _| {
            Value::Array(l.host.net_carriers().into_iter().map(c::carrier).collect())
        });
        v.as_array()
            .expect("array")
            .iter()
            .map(c::de_carrier)
            .collect()
    }
    fn net_can_listen(&self, carrier: Carrier) -> bool {
        let v = self.tape.import(
            "net.can-listen",
            json!({"c": c::carrier(carrier)}),
            |l, _| l.host.net_can_listen(carrier).into(),
        );
        v.as_bool().expect("bool")
    }
    fn net_can_datagram(&self) -> bool {
        let v = self.tape.import("net.can-datagram", json!({}), |l, _| {
            l.host.net_can_datagram().into()
        });
        v.as_bool().expect("bool")
    }
    fn net_can_multicast(&self) -> bool {
        let v = self.tape.import("net.can-multicast", json!({}), |l, _| {
            l.host.net_can_multicast().into()
        });
        v.as_bool().expect("bool")
    }
    fn net_interfaces(&self) -> Vec<NetInterface> {
        let v = self.tape.import("net.interfaces", json!({}), |l, _| {
            Value::Array(
                l.host
                    .net_interfaces()
                    .iter()
                    .map(c::net_interface)
                    .collect(),
            )
        });
        v.as_array()
            .expect("array")
            .iter()
            .map(c::de_net_interface)
            .collect()
    }
    fn net_dial(
        &self,
        carrier: Carrier,
        target: &str,
        subprotocols: &[String],
        token: u64,
    ) -> Result<Box<dyn HostStream>, Errno> {
        let v = self.tape.import(
            "net.dial",
            json!({"c": c::carrier(carrier), "target": target, "subprotocols": c::strs(subprotocols), "token": token}),
            |l, t| match l.host.net_dial(carrier, target, subprotocols, token) {
                Ok(s) => json!({ "ok": reg_stream(l, t, s) }),
                Err(e) => json!({ "err": c::errno(e) }),
            },
        );
        c::de_result(&v, |x| self.stream(x))
    }
    fn net_listen(&self, carrier: Carrier, opts: &ListenOptions, token: u64) -> Result<u32, Errno> {
        let v = self.tape.import(
            "net.listen",
            json!({"c": c::carrier(carrier), "opts": c::listen_options(opts), "token": token}),
            |l, _| c::result(&l.host.net_listen(carrier, opts, token), |n| (*n).into()),
        );
        c::de_result(&v, |x| u32::try_from(c::de_u64(x)).expect("u32"))
    }
    fn net_accept(&self, listener: u32, token: u64) -> Result<Option<Box<dyn HostStream>>, Errno> {
        let v = self.tape.import(
            "net.accept",
            json!({"listener": listener, "token": token}),
            |l, t| match l.host.net_accept(listener, token) {
                Ok(Some(s)) => json!({ "ok": reg_stream(l, t, s) }),
                Ok(None) => json!({ "ok": null }),
                Err(e) => json!({ "err": c::errno(e) }),
            },
        );
        c::de_result(&v, |x| c::de_opt(x, |s| self.stream(s)))
    }
    fn net_unlisten(&self, listener: u32) {
        self.tape
            .import("net.unlisten", json!({"listener": listener}), |l, _| {
                l.host.net_unlisten(listener);
                Value::Null
            });
    }
    fn net_bind(
        &self,
        bind: Option<&str>,
        port: u16,
        token: u64,
    ) -> Result<Box<dyn HostDatagram>, Errno> {
        let v = self.tape.import(
            "net.bind",
            json!({"bind": bind, "port": port, "token": token}),
            |l, t| match l.host.net_bind(bind, port, token) {
                Ok(d) => {
                    let id = t.handle();
                    l.datagrams.borrow_mut().insert(id, d);
                    json!({ "ok": { "datagram": id } })
                },
                Err(e) => json!({ "err": c::errno(e) }),
            },
        );
        c::de_result(&v, |x| -> Box<dyn HostDatagram> {
            Box::new(TapeDatagram {
                tape: self.tape.clone(),
                id: handle_of(x, "datagram"),
            })
        })
    }
    fn seal_describe(&self, id: &str) -> Result<Custody, Errno> {
        let v = self
            .tape
            .import("seal.describe", json!({"id": id}), |l, _| {
                c::result(&l.host.seal_describe(id), c::custody)
            });
        c::de_result(&v, c::de_custody)
    }
    fn seal_public_key(&self, id: &str) -> Result<Vec<u8>, Errno> {
        let v = self
            .tape
            .import("seal.public-key", json!({"id": id}), |l, _| {
                c::result(&l.host.seal_public_key(id), |b| c::bytes(b))
            });
        c::de_result(&v, c::de_bytes)
    }
    fn seal_generate(&self, id: &str, kind: KeyKind, token: u64) -> Result<(), Errno> {
        let v = self.tape.import(
            "seal.generate",
            json!({"id": id, "kind": c::key_kind(kind), "token": token}),
            |l, _| c::result(&l.host.seal_generate(id, kind, token), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn seal_kem_decap(
        &self,
        id: &str,
        x25519_peer_pub: &[u8],
        mlkem_ct: &[u8],
        token: u64,
    ) -> Result<(), Errno> {
        let op = SecretOp::KemDecap {
            id: id.to_owned(),
            x25519_peer_pub: x25519_peer_pub.to_vec(),
            mlkem_ct: mlkem_ct.to_vec(),
        };
        self.tape.start(
            "seal.kem-decap",
            json!({"id": id, "x25519-peer-pub": c::bytes(x25519_peer_pub), "mlkem-ct": c::bytes(mlkem_ct), "token": token}),
            token,
            Some(op),
            |l| l.host.seal_kem_decap(id, x25519_peer_pub, mlkem_ct, token),
        )
    }
    fn seal_xwing_decap(&self, id: &str, ct: &[u8], token: u64) -> Result<(), Errno> {
        let op = SecretOp::XwingDecap {
            id: id.to_owned(),
            ct: ct.to_vec(),
        };
        self.tape.start(
            "seal.xwing-decap",
            json!({"id": id, "ct": c::bytes(ct), "token": token}),
            token,
            Some(op),
            |l| l.host.seal_xwing_decap(id, ct, token),
        )
    }
    fn seal_sign_classical(&self, id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
        let v = self.tape.import(
            "seal.sign-classical",
            json!({"id": id, "msg": c::bytes(msg), "token": token}),
            |l, _| c::result(&l.host.seal_sign_classical(id, msg, token), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn seal_sign_pqc(&self, id: &str, ctx: &[u8], msg: &[u8], token: u64) -> Result<(), Errno> {
        let v = self.tape.import(
            "seal.sign-pqc",
            json!({"id": id, "ctx": c::bytes(ctx), "msg": c::bytes(msg), "token": token}),
            |l, _| c::result(&l.host.seal_sign_pqc(id, ctx, msg, token), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn seal_sign_composite(&self, id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
        let v = self.tape.import(
            "seal.sign-composite",
            json!({"id": id, "msg": c::bytes(msg), "token": token}),
            |l, _| c::result(&l.host.seal_sign_composite(id, msg, token), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn seal_wrap(&self, label: &str, plaintext: &[u8], token: u64) -> Result<(), Errno> {
        // The plaintext argument is secret; the wrapped result is not.
        let args =
            json!({"label": label, "plaintext": self.tape.secret(plaintext), "token": token});
        self.tape.start("seal.wrap", args, token, None, |l| {
            l.host.seal_wrap(label, plaintext, token)
        })
    }
    fn seal_unwrap(&self, label: &str, wrapped: &[u8], token: u64) -> Result<(), Errno> {
        let op = SecretOp::Unwrap {
            label: label.to_owned(),
            wrapped: wrapped.to_vec(),
        };
        self.tape.start(
            "seal.unwrap",
            json!({"label": label, "wrapped": c::bytes(wrapped), "token": token}),
            token,
            Some(op),
            |l| l.host.seal_unwrap(label, wrapped, token),
        )
    }
    fn seal_take(&self, token: u64) -> Result<Vec<u8>, Errno> {
        let t = &self.tape;
        let args = json!({ "token": token });
        let op = t.secret_ops.borrow().get(&token).cloned();
        let r = match &t.live {
            Some(l) => l.host.seal_take(token),
            None => {
                let rec = t.expect(Dir::Import, "seal.take", &args);
                match (rec.get("ok"), &op) {
                    (Some(v), Some(op)) => Ok(t.resolve("seal.take", v, |s| {
                        s.seal_result(op).unwrap_or_else(|e| {
                            panic!("replay divergence: the SecretSource failed {op:?} with {e:?}, recorded a success")
                        })
                    })),
                    _ => c::de_result(&rec, c::de_bytes),
                }
            },
        };
        let ret = match (&r, &op) {
            (Ok(b), Some(_)) => json!({ "ok": t.secret(b) }),
            _ => c::result(&r, |b| c::bytes(b)),
        };
        if !matches!(r, Err(Errno::WouldBlock)) {
            t.secret_ops.borrow_mut().remove(&token);
        }
        t.push(Dir::Import, "seal.take", args, ret);
        r
    }
    fn wake_next_deadline(&self, us: u64) {
        self.tape
            .import("wake.next-deadline", json!({"us": us}), |l, _| {
                l.host.wake_next_deadline(us);
                Value::Null
            });
    }
    fn wake_keep_alive(&self, reason: &str, on: bool) {
        self.tape.import(
            "wake.keep-alive",
            json!({"reason": reason, "on": on}),
            |l, _| {
                l.host.wake_keep_alive(reason, on);
                Value::Null
            },
        );
    }
}

/// Drives node `N`'s exports through a recording or replaying host.
///
/// Creating a session installs its [`TapeHost`] on this thread
/// (`ciris_host_abi::host::install`, native) and gives the thread a fresh
/// [`Runtime`](crate::Runtime), so a recording and its replay start from
/// the same executor state. `N`'s own state must start equal too (reset it
/// in `init`).
pub struct Session<N> {
    host: TapeHost,
    _node: PhantomData<fn() -> N>,
}

impl<N> fmt::Debug for Session<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session").field("host", &self.host).finish()
    }
}

impl<N: Node> Session<N> {
    fn start(tape: Tape) -> Self {
        let host = TapeHost {
            tape: Rc::new(tape),
        };
        ciris_host_abi::host::install(host.clone());
        let _ = crate::Runtime::new();
        Self {
            host,
            _node: PhantomData,
        }
    }

    /// Record `N` running on `host`, secrets redacted.
    pub fn record(host: impl Host + 'static) -> Self {
        Self::record_with(host, RecordOptions::default())
    }

    /// Record `N` running on `host` with `opts`.
    ///
    /// # Panics
    /// If `opts.capture_raw_secrets` is set and [`raw_capture_allowed`]
    /// refuses (the `replay-capture-secrets` feature is off, or this is a
    /// build without `debug_assertions`).
    pub fn record_with(host: impl Host + 'static, opts: RecordOptions) -> Self {
        let secrets = if opts.capture_raw_secrets {
            if let Err(why) = raw_capture_allowed() {
                panic!("ciris-rt replay: raw secret capture refused: {why}");
            }
            host.log_record(
                0,
                "ciris-rt::replay",
                "RAW SECRET CAPTURE IS ON: this replay log will hold random bytes, unwrapped \
                 plaintexts and decapsulated secrets in the clear. Debug only; never in a \
                 release or production build.",
            );
            Secrets::Raw
        } else {
            Secrets::Redacted
        };
        Self::start(Tape {
            live: Some(Live {
                host: Box::new(host),
                streams: RefCell::new(BTreeMap::new()),
                volumes: RefCell::new(BTreeMap::new()),
                datagrams: RefCell::new(BTreeMap::new()),
            }),
            expected: None,
            cursor: Cell::new(0),
            out: RefCell::new(Log {
                entries: Vec::new(),
                secrets,
            }),
            next_handle: Cell::new(0),
            secret_ops: RefCell::new(BTreeMap::new()),
            source: RefCell::new(None),
        })
    }

    /// Replay `N` against `log` (no live host). A redacted secret in the
    /// log panics: use [`replaying_with`](Self::replaying_with).
    #[must_use]
    pub fn replaying(log: Log) -> Self {
        Self::replaying_inner(log, None)
    }

    /// Replay `N` against `log`, re-supplying redacted secrets from
    /// `source` (each checked against the recorded hash and length).
    #[must_use]
    pub fn replaying_with(log: Log, source: impl SecretSource + 'static) -> Self {
        Self::replaying_inner(log, Some(Box::new(source)))
    }

    fn replaying_inner(log: Log, source: Option<Box<dyn SecretSource>>) -> Self {
        let secrets = log.secrets;
        Self::start(Tape {
            live: None,
            expected: Some(log),
            cursor: Cell::new(0),
            out: RefCell::new(Log {
                entries: Vec::new(),
                secrets,
            }),
            next_handle: Cell::new(0),
            secret_ops: RefCell::new(BTreeMap::new()),
            source: RefCell::new(source),
        })
    }

    fn export<R>(
        &self,
        call: &str,
        args: Value,
        run: impl FnOnce() -> R,
        enc: impl Fn(&R) -> Value,
    ) -> R {
        let t = &self.host.tape;
        if t.live.is_none() {
            t.expect(Dir::Export, call, &args);
        }
        t.push(Dir::Export, call, args, Value::Null);
        let r = run();
        let ret = enc(&r);
        if t.live.is_none() {
            let want = t.expect(Dir::Return, call, &Value::Null);
            assert!(
                want == ret,
                "replay divergence at seq {}: export {call} returned {ret}, recorded {want}",
                t.cursor.get() - 1
            );
        }
        t.push(Dir::Return, call, Value::Null, ret);
        r
    }

    /// The `init` export.
    ///
    /// # Errors
    /// The node's own.
    pub fn init(&self) -> Result<(), String> {
        self.export("init", json!({}), N::init, |r| match r {
            Ok(()) => json!({ "ok": null }),
            Err(e) => json!({ "err": e }),
        })
    }

    /// The `tick` export.
    pub fn tick(&self, budget_us: u32) -> u64 {
        self.export(
            "tick",
            json!({ "budget_us": budget_us }),
            || N::tick(budget_us),
            |d| (*d).into(),
        )
    }

    /// The `on-event` export.
    pub fn on_event(&self, e: Event) {
        let args = json!({ "event": c::event(&e) });
        self.export("on-event", args, || N::on_event(e), |()| Value::Null);
    }

    /// The `api` export.
    pub fn api(&self, req: &[u8], local: bool) -> Vec<u8> {
        let args = json!({ "req": c::bytes(req), "local": local });
        self.export("api", args, || N::api(req.to_vec(), local), |r| c::bytes(r))
    }

    /// The log so far.
    #[must_use]
    pub fn log(&self) -> Log {
        self.host.tape.out.borrow().clone()
    }

    /// In replay mode, the next recorded export to drive, if any.
    fn next_export(&self) -> Option<Entry> {
        let t = &self.host.tape;
        let log = t.expected.as_ref()?;
        let e = log.entries.get(t.cursor.get())?;
        assert!(
            e.dir == Dir::Export,
            "replay divergence at seq {}: recorded {} {} {} was never made by the node",
            e.seq,
            e.dir.name(),
            e.call,
            e.args
        );
        Some(e.clone())
    }

    /// End the session: the thread's host is uninstalled; in replay mode,
    /// every recorded entry must have been consumed.
    ///
    /// # Panics
    /// If a replay left recorded calls unmade.
    pub fn finish(self) -> Log {
        let t = &self.host.tape;
        if let Some(log) = &t.expected {
            assert!(
                t.cursor.get() == log.entries.len(),
                "replay divergence: {} recorded entries were never reached (next: {:?})",
                log.entries.len() - t.cursor.get(),
                log.entries.get(t.cursor.get())
            );
        }
        ciris_host_abi::host::uninstall();
        self.log()
    }
}

/// Replay `log` against node `N` from a fresh runtime, driving every
/// recorded export in order and serving every import from the log.
/// Returns the log the replay produced, equal to `log` for a deterministic
/// node.
///
/// # Panics
/// Loudly, at the first divergence: a different import call or argument,
/// an import the recording did not make, a recorded import the replay did
/// not make, or a different export return value.
#[must_use]
pub fn replay<N: Node>(log: &Log) -> Log {
    drive(Session::<N>::replaying(log.clone()))
}

/// [`replay`] a redacted log, re-supplying each redacted value from
/// `source` and checking it against the recorded SHA-256 and length.
///
/// # Panics
/// As [`replay`], and when a re-supplied secret does not match.
#[must_use]
pub fn replay_with<N: Node>(log: &Log, source: impl SecretSource + 'static) -> Log {
    drive(Session::<N>::replaying_with(log.clone(), source))
}

fn drive<N: Node>(s: Session<N>) -> Log {
    while let Some(e) = s.next_export() {
        match e.call.as_str() {
            "init" => {
                let _ = s.init();
            },
            "tick" => {
                let b = u32::try_from(c::de_u64(&e.args["budget_us"])).expect("u32");
                s.tick(b);
            },
            "on-event" => s.on_event(c::de_event(&e.args["event"])),
            "api" => {
                let req = c::de_bytes(&e.args["req"]);
                let local = e.args["local"].as_bool().expect("bool");
                s.api(&req, local);
            },
            other => panic!("replay log: unknown export {other}"),
        }
    }
    s.finish()
}
