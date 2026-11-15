//! The native host seam.
//!
//! On wasm32 the host implements the `ciris:node/*` imports outside the
//! module. On native targets there is no import section, so a native host
//! (or a test) implements [`Host`] and installs it on the thread that runs
//! the node with `install` (native only). The wrappers then route every call to it,
//! so the same node code runs natively.
//!
//! The node is single-threaded (§5.1), so the host is installed per
//! thread, which also lets tests install different hosts in parallel.
//! Calling a wrapper on a thread with no host installed panics, as a wasm
//! module with an unsatisfied import would fail to instantiate.
//!
//! Defaults are the "this host does not offer it" answers: no storage, no
//! carriers, no seal. Clock, random and log have no default, because the
//! node cannot run without them and random has no weak fallback.

use crate::types::{
    Carrier, ConnInfo, Custody, Durability, Errno, KeyKind, ListenOptions, MetricKind, NetInterface,
};

/// One opened volume (`ciris:node/storage.volume`).
pub trait HostVolume {
    /// `read`.
    ///
    /// # Errors
    /// The host's failure.
    fn read(&self, file: u32, offset: u64, len: u32) -> Result<Vec<u8>, Errno>;
    /// `write`.
    ///
    /// # Errors
    /// The host's failure.
    fn write(&self, file: u32, offset: u64, data: &[u8]) -> Result<(), Errno>;
    /// `sync`.
    ///
    /// # Errors
    /// The host's failure.
    fn sync(&self, file: u32) -> Result<(), Errno>;
    /// `truncate`.
    ///
    /// # Errors
    /// The host's failure.
    fn truncate(&self, file: u32, size: u64) -> Result<(), Errno>;
    /// `size`.
    ///
    /// # Errors
    /// The host's failure.
    fn size(&self, file: u32) -> Result<u64, Errno>;
    /// `open`.
    ///
    /// # Errors
    /// The host's failure.
    fn open(&self, name: &str, create: bool) -> Result<u32, Errno>;
    /// `delete`.
    ///
    /// # Errors
    /// The host's failure.
    fn delete(&self, name: &str) -> Result<(), Errno>;
    /// `free-bytes`.
    fn free_bytes(&self) -> Option<u64>;
    /// `durability`.
    fn durability(&self) -> Durability;
}

/// One connection (`ciris:node/net.stream`).
pub trait HostStream {
    /// `info`.
    fn info(&self) -> ConnInfo;
    /// `send`: bytes accepted (stream framing) or 1 (message framing).
    ///
    /// # Errors
    /// `would-block`, `closed`, `invalid`, ...
    fn send(&self, data: &[u8]) -> Result<u32, Errno>;
    /// `recv`.
    ///
    /// # Errors
    /// `would-block`, `closed`, `invalid`, ...
    fn recv(&self, max: u32) -> Result<Vec<u8>, Errno>;
    /// `close`.
    fn close(&self);
}

/// One unconnected datagram socket (`ciris:node/net.datagram`).
pub trait HostDatagram {
    /// `send-to`.
    ///
    /// # Errors
    /// `would-block`, `invalid`, ...
    fn send_to(&self, addr: &str, data: &[u8]) -> Result<(), Errno>;
    /// `recv-from`: `(source address, datagram)`.
    ///
    /// # Errors
    /// `would-block`, ...
    fn recv_from(&self) -> Result<(String, Vec<u8>), Errno>;
    /// `local-addr`.
    fn local_addr(&self) -> Option<String>;
    /// `max-datagram`.
    fn max_datagram(&self) -> u32;
    /// `multicast-join`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn multicast_join(&self, _group: &str, _interface: Option<&str>) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `multicast-leave`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn multicast_leave(&self, _group: &str, _interface: Option<&str>) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
}

/// Everything the `node` world imports, for a native host.
pub trait Host {
    /// `clock.monotonic-us`.
    fn monotonic_us(&self) -> u64;
    /// `clock.wall-ms`.
    fn wall_ms(&self) -> Option<i64>;
    /// `random.fill`: exactly `len` CSPRNG bytes. Panic rather than return
    /// fewer or weaker bytes.
    fn random_fill(&self, len: u32) -> Vec<u8>;
    /// `log.record`.
    fn log_record(&self, level: u8, target: &str, msg: &str);

    /// `log.metric`.
    fn log_metric(
        &self,
        _name: &str,
        _kind: MetricKind,
        _value: f64,
        _labels: &[(String, String)],
    ) {
    }
    /// `storage.primary`. Default: a volume that answers `unsupported`.
    fn storage_primary(&self) -> Box<dyn HostVolume> {
        Box::new(NoVolume)
    }
    /// `net.carriers`. Default: none.
    fn net_carriers(&self) -> Vec<Carrier> {
        Vec::new()
    }
    /// `net.can-listen`. Default: false.
    fn net_can_listen(&self, _c: Carrier) -> bool {
        false
    }
    /// `net.can-datagram`. Default: false.
    fn net_can_datagram(&self) -> bool {
        false
    }
    /// `net.can-multicast`. Default: false.
    fn net_can_multicast(&self) -> bool {
        false
    }
    /// `net.interfaces`. Default: none.
    fn net_interfaces(&self) -> Vec<NetInterface> {
        Vec::new()
    }
    /// `net.bind`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn net_bind(
        &self,
        _bind: Option<&str>,
        _port: u16,
        _token: u64,
    ) -> Result<Box<dyn HostDatagram>, Errno> {
        Err(Errno::Unsupported)
    }
    /// `net.dial`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn net_dial(
        &self,
        _c: Carrier,
        _target: &str,
        _subprotocols: &[String],
        _token: u64,
    ) -> Result<Box<dyn HostStream>, Errno> {
        Err(Errno::Unsupported)
    }
    /// `net.listen`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn net_listen(&self, _c: Carrier, _opts: &ListenOptions, _token: u64) -> Result<u32, Errno> {
        Err(Errno::Unsupported)
    }
    /// `net.accept`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn net_accept(
        &self,
        _listener: u32,
        _token: u64,
    ) -> Result<Option<Box<dyn HostStream>>, Errno> {
        Err(Errno::Unsupported)
    }
    /// `net.unlisten`.
    fn net_unlisten(&self, _listener: u32) {}
    /// `seal.describe`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_describe(&self, _id: &str) -> Result<Custody, Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.public-key`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_public_key(&self, _id: &str) -> Result<Vec<u8>, Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.generate`: generate key `id` of `kind` inside the seal; the
    /// seed never reaches the node (§8.5).
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_generate(&self, _id: &str, _kind: KeyKind, _token: u64) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.kem-decap`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_kem_decap(
        &self,
        _id: &str,
        _x25519_peer_pub: &[u8],
        _mlkem_ct: &[u8],
        _token: u64,
    ) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.sign-classical`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_sign_classical(&self, _id: &str, _msg: &[u8], _token: u64) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.sign-pqc`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_sign_pqc(&self, _id: &str, _ctx: &[u8], _msg: &[u8], _token: u64) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.sign-composite`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_sign_composite(&self, _id: &str, _msg: &[u8], _token: u64) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.wrap`: AEAD under a key derived from the seal root,
    /// domain-separated by `label`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_wrap(&self, _label: &str, _plaintext: &[u8], _token: u64) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.unwrap`; an authentication failure is reported through
    /// `take` as `denied` or `invalid`.
    ///
    /// # Errors
    /// Default: `unsupported`.
    fn seal_unwrap(&self, _label: &str, _wrapped: &[u8], _token: u64) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    /// `seal.take`.
    ///
    /// # Errors
    /// Default: `not-found`.
    fn seal_take(&self, _token: u64) -> Result<Vec<u8>, Errno> {
        Err(Errno::NotFound)
    }
    /// `wake.next-deadline`.
    fn wake_next_deadline(&self, _us: u64) {}
    /// `wake.keep-alive`.
    fn wake_keep_alive(&self, _reason: &str, _on: bool) {}
}

/// The default volume of a host that offers no storage.
struct NoVolume;

impl HostVolume for NoVolume {
    fn read(&self, _: u32, _: u64, _: u32) -> Result<Vec<u8>, Errno> {
        Err(Errno::Unsupported)
    }
    fn write(&self, _: u32, _: u64, _: &[u8]) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    fn sync(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    fn truncate(&self, _: u32, _: u64) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    fn size(&self, _: u32) -> Result<u64, Errno> {
        Err(Errno::Unsupported)
    }
    fn open(&self, _: &str, _: bool) -> Result<u32, Errno> {
        Err(Errno::Unsupported)
    }
    fn delete(&self, _: &str) -> Result<(), Errno> {
        Err(Errno::Unsupported)
    }
    fn free_bytes(&self) -> Option<u64> {
        None
    }
    fn durability(&self) -> Durability {
        Durability::Evictable
    }
}

// `install` / `uninstall`: the thread's host on native; on wasm32 they exist
// (so node-side test tooling compiles without a target cfg) and panic.
#[allow(unused_imports)]
pub use crate::sys::host_exports::*;
