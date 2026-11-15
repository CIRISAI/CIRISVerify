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
//! Line 1 is a header, `{"format":"ciris-rt-replay","version":1}`. Each
//! further line is one [`Entry`], an object with sorted keys:
//!
//! ```text
//! {"args":{"budget_us":5000},"call":"tick","dir":"export","ret":null,"seq":3}
//! {"args":{},"call":"clock.monotonic-us","dir":"import","ret":1000,"seq":4}
//! {"args":{"len":32},"call":"random.fill","dir":"import","ret":"9f…","seq":5}
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
//! **A log holds every secret that crossed the boundary**: random bytes,
//! `unwrap` plaintexts, `kem-decap` key material. Treat it as secret.

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
/// The header line's version.
pub const VERSION: u64 = 1;

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
}

impl Log {
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
        let mut out = format!("{}\n", json!({ "format": FORMAT, "version": VERSION }));
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
        Ok(Self { entries })
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
        let v = self
            .tape
            .import("random.fill", json!({"len": len}), |l, _| {
                c::bytes(&l.host.random_fill(len))
            });
        c::de_bytes(&v)
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
        let v = self.tape.import(
            "seal.kem-decap",
            json!({"id": id, "x25519-peer-pub": c::bytes(x25519_peer_pub), "mlkem-ct": c::bytes(mlkem_ct), "token": token}),
            |l, _| c::result(&l.host.seal_kem_decap(id, x25519_peer_pub, mlkem_ct, token), c::unit),
        );
        c::de_result(&v, |_| ())
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
        let v = self.tape.import(
            "seal.wrap",
            json!({"label": label, "plaintext": c::bytes(plaintext), "token": token}),
            |l, _| c::result(&l.host.seal_wrap(label, plaintext, token), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn seal_unwrap(&self, label: &str, wrapped: &[u8], token: u64) -> Result<(), Errno> {
        let v = self.tape.import(
            "seal.unwrap",
            json!({"label": label, "wrapped": c::bytes(wrapped), "token": token}),
            |l, _| c::result(&l.host.seal_unwrap(label, wrapped, token), c::unit),
        );
        c::de_result(&v, |_| ())
    }
    fn seal_take(&self, token: u64) -> Result<Vec<u8>, Errno> {
        let v = self
            .tape
            .import("seal.take", json!({"token": token}), |l, _| {
                c::result(&l.host.seal_take(token), |b| c::bytes(b))
            });
        c::de_result(&v, c::de_bytes)
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

    /// Record `N` running on `host`.
    pub fn record(host: impl Host + 'static) -> Self {
        Self::start(Tape {
            live: Some(Live {
                host: Box::new(host),
                streams: RefCell::new(BTreeMap::new()),
                volumes: RefCell::new(BTreeMap::new()),
                datagrams: RefCell::new(BTreeMap::new()),
            }),
            expected: None,
            cursor: Cell::new(0),
            out: RefCell::new(Log::default()),
            next_handle: Cell::new(0),
        })
    }

    /// Replay `N` against `log` (no live host).
    #[must_use]
    pub fn replaying(log: Log) -> Self {
        Self::start(Tape {
            live: None,
            expected: Some(log),
            cursor: Cell::new(0),
            out: RefCell::new(Log::default()),
            next_handle: Cell::new(0),
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
    let s = Session::<N>::replaying(log.clone());
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
