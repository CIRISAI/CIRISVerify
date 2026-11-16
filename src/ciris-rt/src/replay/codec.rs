//! JSON encodings of the ABI's values, shared by the recorder and the
//! replayer so both read and write one format.
//!
//! Byte strings are lowercase hex strings. Enums are their WIT names.
//! `result<T, errno>` is `{"ok": T}` or `{"err": "<errno>"}`. `option<T>` is
//! `null` or `T`. Objects serialize with sorted keys (serde_json's
//! `BTreeMap`), so an encoding is canonical.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use ciris_host_abi::types::{
    AtRest, AtUse, Carrier, CloseInfo, CloseReason, ConnInfo, Custody, Durability, Errno, Event,
    FailInfo, FailReason, Framing, KeyKind, ListenOptions, MetricKind, NetInterface, Phase,
    SealRoot,
};
use serde_json::{json, Map, Value};

macro_rules! names {
    ($enc:ident, $dec:ident, $ty:ty { $($v:ident = $n:literal),+ $(,)? }) => {
        pub(crate) fn $enc(x: $ty) -> Value {
            Value::String(match x { $(<$ty>::$v => $n),+ }.to_owned())
        }
        #[allow(dead_code)] // not every enum is ever decoded
        pub(crate) fn $dec(v: &Value) -> $ty {
            match v.as_str() {
                $(Some($n) => <$ty>::$v,)+
                other => panic!(concat!("replay log: bad ", stringify!($ty), ": {:?}"), other),
            }
        }
    };
}

names!(errno, de_errno, Errno {
    WouldBlock = "would-block", Closed = "closed", Refused = "refused",
    NotFound = "not-found", NoSpace = "no-space", Denied = "denied",
    Invalid = "invalid", Unsupported = "unsupported", Io = "io",
});
names!(carrier, de_carrier, Carrier {
    Tcp = "tcp", Udp = "udp", Ws = "ws", Webtransport = "webtransport",
    Webrtc = "webrtc", Serial = "serial", Ble = "ble", HttpFetch = "http-fetch",
});
names!(framing, de_framing, Framing { Stream = "stream", Message = "message" });
names!(durability, de_durability, Durability {
    Persisted = "persisted", BestEffort = "best-effort", Evictable = "evictable",
});
names!(phase, de_phase, Phase {
    Foreground = "foreground", Background = "background", Suspend = "suspend",
    Resume = "resume", Shutdown = "shutdown",
});
names!(close_reason, de_close_reason, CloseReason {
    PeerClose = "peer-close", Error = "error", HostShutdown = "host-shutdown",
});
names!(fail_reason, de_fail_reason, FailReason {
    Refused = "refused", Unreachable = "unreachable", Timeout = "timeout",
    NameNotResolved = "name-not-resolved", Denied = "denied", Error = "error",
});
names!(key_kind, de_key_kind, KeyKind {
    Composite = "composite", Transit = "transit", OnionHop = "onion-hop",
});
names!(metric_kind, de_metric_kind, MetricKind {
    Counter = "counter", Gauge = "gauge", Histogram = "histogram",
});
names!(at_use, de_at_use, AtUse { Hardware = "hardware", Vault = "vault", Software = "software" });
names!(at_rest, de_at_rest, AtRest {
    Hardware = "hardware", Sealed = "sealed", Wrapped = "wrapped",
    SoftwareSealed = "software-sealed", Unprotected = "unprotected",
});
names!(seal_root, de_seal_root, SealRoot {
    Tpm = "tpm", TpmMeasured = "tpm-measured", TokenSignature = "token-signature",
    WebauthnPrf = "webauthn-prf", PlatformKeystore = "platform-keystore", Software = "software",
});

pub(crate) fn bytes(b: &[u8]) -> Value {
    Value::String(hex::encode(b))
}
pub(crate) fn de_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("replay log: bytes are a hex string"))
        .expect("replay log: bad hex")
}
pub(crate) fn de_u64(v: &Value) -> u64 {
    v.as_u64()
        .expect("replay log: expected an unsigned integer")
}
pub(crate) fn de_str(v: &Value) -> String {
    v.as_str()
        .expect("replay log: expected a string")
        .to_owned()
}
pub(crate) fn opt<T>(x: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    x.map_or(Value::Null, f)
}
pub(crate) fn de_opt<T>(v: &Value, f: impl FnOnce(&Value) -> T) -> Option<T> {
    if v.is_null() {
        None
    } else {
        Some(f(v))
    }
}
pub(crate) fn strs(xs: &[String]) -> Value {
    Value::Array(xs.iter().map(|s| Value::String(s.clone())).collect())
}
pub(crate) fn de_strs(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("replay log: expected an array")
        .iter()
        .map(de_str)
        .collect()
}

pub(crate) fn result<T>(r: &Result<T, Errno>, f: impl FnOnce(&T) -> Value) -> Value {
    match r {
        Ok(v) => json!({ "ok": f(v) }),
        Err(e) => json!({ "err": errno(*e) }),
    }
}
pub(crate) fn de_result<T>(v: &Value, f: impl FnOnce(&Value) -> T) -> Result<T, Errno> {
    if let Some(e) = v.get("err") {
        return Err(de_errno(e));
    }
    Ok(f(v
        .get("ok")
        .expect("replay log: result has neither ok nor err")))
}
pub(crate) fn unit(_: &()) -> Value {
    Value::Null
}

pub(crate) fn conn_info(c: &ConnInfo) -> Value {
    json!({
        "carrier": carrier(c.carrier),
        "framing": framing(c.framing),
        "max-message": opt(c.max_message, Value::from),
        "reliable": c.reliable,
        "subprotocol": opt(c.subprotocol.clone(), Value::String),
        "peer-subprotocols": strs(&c.peer_subprotocols),
        "peer": opt(c.peer.clone(), Value::String),
        "bitrate-hint": opt(c.bitrate_hint, Value::from),
        "recv-buffer": c.recv_buffer,
    })
}
pub(crate) fn de_conn_info(v: &Value) -> ConnInfo {
    ConnInfo {
        carrier: de_carrier(&v["carrier"]),
        framing: de_framing(&v["framing"]),
        max_message: de_opt(&v["max-message"], |x| {
            u32::try_from(de_u64(x)).expect("u32")
        }),
        reliable: v["reliable"].as_bool().expect("bool"),
        subprotocol: de_opt(&v["subprotocol"], de_str),
        peer_subprotocols: de_strs(&v["peer-subprotocols"]),
        peer: de_opt(&v["peer"], de_str),
        bitrate_hint: de_opt(&v["bitrate-hint"], de_u64),
        recv_buffer: u32::try_from(de_u64(&v["recv-buffer"])).expect("u32"),
    }
}

pub(crate) fn custody(c: &Custody) -> Value {
    json!({
        "classical-at-use": at_use(c.classical_at_use),
        "classical-at-rest": at_rest(c.classical_at_rest),
        "pqc-at-use": at_use(c.pqc_at_use),
        "pqc-at-rest": at_rest(c.pqc_at_rest),
        "seal-root": seal_root(c.seal_root),
        "platform": opt(c.platform.clone(), Value::String),
    })
}
pub(crate) fn de_custody(v: &Value) -> Custody {
    Custody {
        classical_at_use: de_at_use(&v["classical-at-use"]),
        classical_at_rest: de_at_rest(&v["classical-at-rest"]),
        pqc_at_use: de_at_use(&v["pqc-at-use"]),
        pqc_at_rest: de_at_rest(&v["pqc-at-rest"]),
        seal_root: de_seal_root(&v["seal-root"]),
        platform: de_opt(&v["platform"], de_str),
    }
}

pub(crate) fn listen_options(o: &ListenOptions) -> Value {
    json!({
        "bind": opt(o.bind.clone(), Value::String),
        "port": o.port,
        "subprotocols": strs(&o.subprotocols),
        "ws-path": opt(o.ws_path.clone(), Value::String),
    })
}

pub(crate) fn net_interface(i: &NetInterface) -> Value {
    json!({
        "name": i.name,
        "addresses": strs(&i.addresses),
        "link-local": i.link_local,
        "up": i.up,
    })
}
pub(crate) fn de_net_interface(v: &Value) -> NetInterface {
    NetInterface {
        name: de_str(&v["name"]),
        addresses: de_strs(&v["addresses"]),
        link_local: v["link-local"].as_bool().expect("bool"),
        up: v["up"].as_bool().expect("bool"),
    }
}

pub(crate) fn labels(ls: &[(String, String)]) -> Value {
    Value::Array(ls.iter().map(|(k, v)| json!([k, v])).collect())
}

fn fail_info(f: &FailInfo) -> Value {
    json!({ "token": f.token, "reason": fail_reason(f.reason) })
}
fn de_fail_info(v: &Value) -> FailInfo {
    FailInfo {
        token: de_u64(&v["token"]),
        reason: de_fail_reason(&v["reason"]),
    }
}

/// `{"readable": 7}`, `{"failed": {"token": 7, "reason": "refused"}}`,
/// `{"lifecycle": "suspend"}`, `"timer"`, `"clock-trusted"`, ...
pub(crate) fn event(e: &Event) -> Value {
    let one = |k: &str, v: Value| {
        let mut m = Map::new();
        m.insert(k.to_owned(), v);
        Value::Object(m)
    };
    match e {
        Event::Readable(t) => one("readable", (*t).into()),
        Event::Writable(t) => one("writable", (*t).into()),
        Event::Connected(t) => one("connected", (*t).into()),
        Event::Failed(f) => one("failed", fail_info(f)),
        Event::ListenerFailed(f) => one("listener-failed", fail_info(f)),
        Event::Closed(c) => one(
            "closed",
            json!({ "token": c.token, "reason": close_reason(c.reason) }),
        ),
        Event::Sealed(t) => one("sealed", (*t).into()),
        Event::Lifecycle(p) => one("lifecycle", phase(*p)),
        Event::Timer => Value::String("timer".to_owned()),
        Event::ClockTrusted => Value::String("clock-trusted".to_owned()),
    }
}
pub(crate) fn de_event(v: &Value) -> Event {
    match v {
        Value::String(s) if s == "timer" => return Event::Timer,
        Value::String(s) if s == "clock-trusted" => return Event::ClockTrusted,
        _ => {},
    }
    let (k, x) = v
        .as_object()
        .and_then(|m| m.iter().next())
        .unwrap_or_else(|| panic!("replay log: bad event {v}"));
    match k.as_str() {
        "readable" => Event::Readable(de_u64(x)),
        "writable" => Event::Writable(de_u64(x)),
        "connected" => Event::Connected(de_u64(x)),
        "failed" => Event::Failed(de_fail_info(x)),
        "listener-failed" => Event::ListenerFailed(de_fail_info(x)),
        "closed" => Event::Closed(CloseInfo {
            token: de_u64(&x["token"]),
            reason: de_close_reason(&x["reason"]),
        }),
        "sealed" => Event::Sealed(de_u64(x)),
        "lifecycle" => Event::Lifecycle(de_phase(x)),
        other => panic!("replay log: unknown event {other}"),
    }
}
