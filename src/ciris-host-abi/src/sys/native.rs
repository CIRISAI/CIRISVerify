//! Native: the wrappers call the [`Host`] installed on this thread.

use std::cell::RefCell;
use std::rc::Rc;

use crate::host::{Host, HostStream, HostVolume};
use crate::types::{Carrier, ConnInfo, Custody, Durability, Errno};

thread_local! {
    static HOST: RefCell<Option<Rc<dyn Host>>> = const { RefCell::new(None) };
}

/// Native-only host installation.
pub mod host_exports {
    use super::{Host, Rc, HOST};

    /// Install `host` for the calling thread, returning the previous one.
    pub fn install(host: impl Host + 'static) -> Option<Rc<dyn Host>> {
        HOST.with(|h| h.borrow_mut().replace(Rc::new(host)))
    }

    /// Remove the calling thread's host.
    pub fn uninstall() -> Option<Rc<dyn Host>> {
        HOST.with(|h| h.borrow_mut().take())
    }
}

fn host() -> Rc<dyn Host> {
    HOST.with(|h| h.borrow().clone()).expect(
        "ciris-host-abi: no Host installed on this thread (ciris_host_abi::host::install); \
         on wasm this is an unsatisfied ciris:node import",
    )
}

pub fn monotonic_us() -> u64 {
    host().monotonic_us()
}
pub fn wall_ms() -> Option<i64> {
    host().wall_ms()
}
pub fn random_fill(len: u32) -> Vec<u8> {
    host().random_fill(len)
}

/// An opened volume (`ciris:node/storage.volume`).
pub struct Volume(Box<dyn HostVolume>);

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
    Volume(host().storage_primary())
}

/// One connection (`ciris:node/net.stream`).
pub struct Stream(Box<dyn HostStream>);

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

pub fn net_carriers() -> Vec<Carrier> {
    host().net_carriers()
}
pub fn net_can_listen(c: Carrier) -> bool {
    host().net_can_listen(c)
}
pub fn net_dial(
    c: Carrier,
    target: &str,
    subprotocols: &[String],
    token: u64,
) -> Result<Stream, Errno> {
    host().net_dial(c, target, subprotocols, token).map(Stream)
}
pub fn net_listen(
    c: Carrier,
    port: u16,
    subprotocols: &[String],
    token: u64,
) -> Result<u32, Errno> {
    host().net_listen(c, port, subprotocols, token)
}
pub fn net_accept(listener: u32, token: u64) -> Result<Option<Stream>, Errno> {
    host().net_accept(listener, token).map(|s| s.map(Stream))
}
pub fn net_unlisten(listener: u32) {
    host().net_unlisten(listener);
}

pub fn seal_describe(id: &str) -> Result<Custody, Errno> {
    host().seal_describe(id)
}
pub fn seal_public_key(id: &str) -> Result<Vec<u8>, Errno> {
    host().seal_public_key(id)
}
pub fn seal_provision(id: &str, material: &[u8], token: u64) -> Result<(), Errno> {
    host().seal_provision(id, material, token)
}
pub fn seal_sign_classical(id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
    host().seal_sign_classical(id, msg, token)
}
pub fn seal_sign_pqc(id: &str, ctx: &[u8], msg: &[u8], token: u64) -> Result<(), Errno> {
    host().seal_sign_pqc(id, ctx, msg, token)
}
pub fn seal_sign_composite(id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
    host().seal_sign_composite(id, msg, token)
}
pub fn seal_take(token: u64) -> Result<Vec<u8>, Errno> {
    host().seal_take(token)
}

pub fn wake_next_deadline(us: u64) {
    host().wake_next_deadline(us);
}
pub fn wake_keep_alive(reason: &str, on: bool) {
    host().wake_keep_alive(reason, on);
}

pub fn log_record(level: u8, target: &str, msg: &str) {
    host().log_record(level, target, msg);
}
pub fn log_metric(name: &str, value: f64) {
    host().log_metric(name, value);
}

/// Native: nothing to export; a native host calls the [`crate::Node`]
/// methods directly. Still checks that `$ty: Node`.
#[doc(hidden)]
#[macro_export]
macro_rules! __ciris_export_node {
    ($ty:ty) => {
        const _: fn() = || {
            fn assert_node<T: $crate::Node>() {}
            assert_node::<$ty>();
        };
    };
}
