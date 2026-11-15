//! wasm32: the wrappers are the wit-bindgen import stubs.

use crate::bindings::ciris::node::{clock, log, net, random, seal, storage, wake};
use crate::types::{
    Carrier, ConnInfo, Custody, Durability, Errno, KeyKind, ListenOptions, MetricKind, NetInterface,
};

/// On wasm32 the host implements the imports outside the module, so there
/// is no seam to install into. These exist so node-side tooling (tests,
/// `ciris-rt`'s replay) compiles on every target without a target `cfg`;
/// calling them is a bug and panics.
pub mod host_exports {
    use std::rc::Rc;

    use crate::host::Host;

    /// Not available on wasm32: the host implements the imports.
    ///
    /// # Panics
    /// Always.
    pub fn install(_host: impl Host + 'static) -> Option<Rc<dyn Host>> {
        panic!("ciris-host-abi: host::install is native-only; on wasm32 the host implements the ciris:node imports")
    }

    /// Not available on wasm32.
    ///
    /// # Panics
    /// Always.
    pub fn uninstall() -> Option<Rc<dyn Host>> {
        panic!("ciris-host-abi: host::uninstall is native-only")
    }
}

pub fn monotonic_us() -> u64 {
    clock::monotonic_us()
}
pub fn wall_ms() -> Option<i64> {
    clock::wall_ms()
}
pub fn random_fill(len: u32) -> Vec<u8> {
    random::fill(len)
}

/// An opened volume (`ciris:node/storage.volume`).
pub struct Volume(storage::Volume);

impl Volume {
    /// Read `len` bytes at `offset`.
    ///
    /// # Errors
    /// The host's failure.
    pub fn read(&self, file: u32, offset: u64, len: u32) -> Result<Vec<u8>, Errno> {
        self.0.read(file, offset, len)
    }
    /// Write `data` at `offset`.
    ///
    /// # Errors
    /// The host's failure.
    pub fn write(&self, file: u32, offset: u64, data: &[u8]) -> Result<(), Errno> {
        self.0.write(file, offset, data)
    }
    /// Make `file` durable to the volume's [`Durability`].
    ///
    /// # Errors
    /// The host's failure.
    pub fn sync(&self, file: u32) -> Result<(), Errno> {
        self.0.sync(file)
    }
    /// Set `file`'s size.
    ///
    /// # Errors
    /// The host's failure.
    pub fn truncate(&self, file: u32, size: u64) -> Result<(), Errno> {
        self.0.truncate(file, size)
    }
    /// `file`'s size.
    ///
    /// # Errors
    /// The host's failure.
    pub fn size(&self, file: u32) -> Result<u64, Errno> {
        self.0.size(file)
    }
    /// Open (or create) `name` inside the volume.
    ///
    /// # Errors
    /// The host's failure.
    pub fn open(&self, name: &str, create: bool) -> Result<u32, Errno> {
        self.0.open(name, create)
    }
    /// Delete `name`.
    ///
    /// # Errors
    /// The host's failure.
    pub fn delete(&self, name: &str) -> Result<(), Errno> {
        self.0.delete(name)
    }
    /// Free space, when the host knows it.
    #[must_use]
    pub fn free_bytes(&self) -> Option<u64> {
        self.0.free_bytes()
    }
    /// What the host promises about this volume.
    #[must_use]
    pub fn durability(&self) -> Durability {
        self.0.durability()
    }
}

pub fn storage_primary() -> Volume {
    Volume(storage::primary())
}

/// One connection (`ciris:node/net.stream`).
pub struct Stream(net::Stream);

impl Stream {
    /// What the host knows about the connection.
    #[must_use]
    pub fn info(&self) -> ConnInfo {
        self.0.info()
    }
    /// Non-blocking send; see the WIT for framing.
    ///
    /// # Errors
    /// `would-block`, `closed`, `invalid`, ...
    pub fn send(&self, data: &[u8]) -> Result<u32, Errno> {
        self.0.send(data)
    }
    /// Non-blocking receive; see the WIT for framing.
    ///
    /// # Errors
    /// `would-block`, `closed`, `invalid`, ...
    pub fn recv(&self, max: u32) -> Result<Vec<u8>, Errno> {
        self.0.recv(max)
    }
    /// Close the connection.
    pub fn close(&self) {
        self.0.close();
    }
}

/// One unconnected datagram socket (`ciris:node/net.datagram`).
pub struct Datagram(net::Datagram);

impl Datagram {
    /// Non-blocking send of one datagram to `addr`.
    ///
    /// # Errors
    /// `would-block`, `invalid`, ...
    pub fn send_to(&self, addr: &str, data: &[u8]) -> Result<(), Errno> {
        self.0.send_to(addr, data)
    }
    /// Non-blocking receive: `(source address, datagram)`.
    ///
    /// # Errors
    /// `would-block`, ...
    pub fn recv_from(&self) -> Result<(String, Vec<u8>), Errno> {
        self.0.recv_from()
    }
    /// The bound address, when the host knows it.
    #[must_use]
    pub fn local_addr(&self) -> Option<String> {
        self.0.local_addr()
    }
    /// The largest datagram `send_to` accepts.
    #[must_use]
    pub fn max_datagram(&self) -> u32 {
        self.0.max_datagram()
    }
    /// Join multicast `group`.
    ///
    /// # Errors
    /// `unsupported` unless `net::can_multicast`.
    pub fn multicast_join(&self, group: &str, interface: Option<&str>) -> Result<(), Errno> {
        self.0.multicast_join(group, interface)
    }
    /// Leave multicast `group`.
    ///
    /// # Errors
    /// The host's failure.
    pub fn multicast_leave(&self, group: &str, interface: Option<&str>) -> Result<(), Errno> {
        self.0.multicast_leave(group, interface)
    }
}

pub fn net_carriers() -> Vec<Carrier> {
    net::carriers()
}
pub fn net_can_listen(c: Carrier) -> bool {
    net::can_listen(c)
}
pub fn net_dial(
    c: Carrier,
    target: &str,
    subprotocols: &[String],
    token: u64,
) -> Result<Stream, Errno> {
    net::dial(c, target, subprotocols, token).map(Stream)
}
pub fn net_listen(c: Carrier, opts: &ListenOptions, token: u64) -> Result<u32, Errno> {
    net::listen(c, opts, token)
}
pub fn net_can_datagram() -> bool {
    net::can_datagram()
}
pub fn net_can_multicast() -> bool {
    net::can_multicast()
}
pub fn net_interfaces() -> Vec<NetInterface> {
    net::interfaces()
}
pub fn net_bind(bind: Option<&str>, port: u16, token: u64) -> Result<Datagram, Errno> {
    net::bind(bind, port, token).map(Datagram)
}
pub fn net_accept(listener: u32, token: u64) -> Result<Option<Stream>, Errno> {
    net::accept(listener, token).map(|s| s.map(Stream))
}
pub fn net_unlisten(listener: u32) {
    net::unlisten(listener);
}

pub fn seal_describe(id: &str) -> Result<Custody, Errno> {
    seal::describe(id)
}
pub fn seal_public_key(id: &str) -> Result<Vec<u8>, Errno> {
    seal::public_key(id)
}
pub fn seal_generate(id: &str, kind: KeyKind, token: u64) -> Result<(), Errno> {
    seal::generate(id, kind, token)
}
pub fn seal_kem_decap(
    id: &str,
    x25519_peer_pub: &[u8],
    mlkem_ct: &[u8],
    token: u64,
) -> Result<(), Errno> {
    seal::kem_decap(id, x25519_peer_pub, mlkem_ct, token)
}
pub fn seal_sign_classical(id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
    seal::sign_classical(id, msg, token)
}
pub fn seal_sign_pqc(id: &str, ctx: &[u8], msg: &[u8], token: u64) -> Result<(), Errno> {
    seal::sign_pqc(id, ctx, msg, token)
}
pub fn seal_sign_composite(id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
    seal::sign_composite(id, msg, token)
}
pub fn seal_wrap(label: &str, plaintext: &[u8], token: u64) -> Result<(), Errno> {
    seal::wrap(label, plaintext, token)
}
pub fn seal_unwrap(label: &str, wrapped: &[u8], token: u64) -> Result<(), Errno> {
    seal::unwrap(label, wrapped, token)
}
pub fn seal_take(token: u64) -> Result<Vec<u8>, Errno> {
    seal::take(token)
}

pub fn wake_next_deadline(us: u64) {
    wake::next_deadline(us);
}
pub fn wake_keep_alive(reason: &str, on: bool) {
    wake::keep_alive(reason, on);
}

pub fn log_record(level: u8, target: &str, msg: &str) {
    log::record(level, target, msg);
}
pub fn log_metric(name: &str, kind: MetricKind, value: f64, labels: &[(String, String)]) {
    log::metric(name, kind, value, labels);
}

/// wasm32: export `$ty: Node` as the `node` world's exports.
#[doc(hidden)]
#[macro_export]
macro_rules! __ciris_export_node {
    ($ty:ty) => {
        const _: () = {
            struct __CirisNodeExport;
            impl $crate::bindings::Guest for __CirisNodeExport {
                fn init() -> ::core::result::Result<(), ::std::string::String> {
                    <$ty as $crate::Node>::init()
                }
                fn tick(budget_us: u32) -> u64 {
                    <$ty as $crate::Node>::tick(budget_us)
                }
                fn on_event(e: $crate::Event) {
                    <$ty as $crate::Node>::on_event(e)
                }
                fn api(req: ::std::vec::Vec<u8>, local: bool) -> ::std::vec::Vec<u8> {
                    <$ty as $crate::Node>::api(req, local)
                }
            }
            $crate::bindings::__export_node_world!(__CirisNodeExport with_types_in $crate::bindings);
        };
    };
}

/// getrandom's custom backend over `ciris:node/random.fill`, so every
/// crate in the module (`rand_core::OsRng`, keygen, leviculum) draws
/// CSPRNG bytes with no wasm-bindgen or WASI import. Never returns weak
/// bytes: a short fill traps in [`crate::random::fill`].
#[cfg(feature = "getrandom-backend")]
mod getrandom_backend {
    use zeroize::Zeroize as _;

    /// Write `len` host CSPRNG bytes to `dest` without forming a reference
    /// to (possibly uninitialised) memory.
    unsafe fn fill_raw(dest: *mut u8, len: usize) {
        let mut off = 0usize;
        while off < len {
            #[allow(clippy::cast_possible_truncation)] // bounded by u32::MAX
            let n = (len - off).min(u32::MAX as usize) as u32;
            let mut bytes = crate::random::fill(n);
            // SAFETY: the caller gives `len` writable bytes at `dest`;
            // `bytes` is exactly `n` long (checked in `random::fill`).
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dest.add(off), n as usize) };
            bytes.zeroize();
            off += n as usize;
        }
    }

    // getrandom 0.2 (feature `custom`).
    #[allow(clippy::unnecessary_wraps)]
    fn getrandom02_custom(dest: &mut [u8]) -> Result<(), getrandom02::Error> {
        crate::random::fill_bytes(dest);
        Ok(())
    }
    getrandom02::register_custom_getrandom!(getrandom02_custom);

    /// getrandom 0.3 and 0.4 both call this one symbol when built with
    /// `--cfg getrandom_backend="custom"` (both `src/backends/custom.rs`
    /// declare `__getrandom_v03_custom`). The two `Error` types are the
    /// same single non-zero integer; this backend only ever returns `Ok`.
    ///
    /// # Safety
    /// getrandom passes `len` writable bytes at `dest`.
    #[unsafe(no_mangle)]
    unsafe extern "Rust" fn __getrandom_v03_custom(
        dest: *mut u8,
        len: usize,
    ) -> Result<(), getrandom04::Error> {
        unsafe { fill_raw(dest, len) };
        Ok(())
    }
}
