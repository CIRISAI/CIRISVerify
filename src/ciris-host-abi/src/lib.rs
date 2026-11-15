//! `ciris-host-abi`: the `ciris:node` host interface of the CIRIS WASM node
//! (CIRISServer `FSD/WASM_NODE.md` §4, work item 1).
//!
//! * `wit/ciris-node.wit` is normative. [`bindings`] is its wit-bindgen
//!   lowering to a **core** wasm module (§4.2).
//! * The modules [`clock`], [`random`], [`storage`], [`net`], [`seal`],
//!   [`wake`] and [`log`] are the safe wrappers node crates call. They have
//!   one signature on every target.
//! * A node implements [`Node`] and calls [`export_node!`] once.
//! * On wasm32 the wrappers call the `ciris:node/*` imports. On native
//!   targets they call the [`host::Host`] that the native host installed on
//!   the calling thread with `host::install`, so the same node code links and
//!   is tested natively.
//!
//! **This crate is the one place allowed to branch on target** (§4.1.2).
//! All of that branching is behind the private `sys` boundary module (plus
//! the native-only tool modules [`gate`] and [`cfg_lint`]); node crates contain
//! no `cfg(target_*)`, and `ciris-cfg-lint` enforces it.

pub mod bindings;
pub mod host;
mod sys;

#[cfg(not(target_arch = "wasm32"))]
pub mod cfg_lint;
#[cfg(not(target_arch = "wasm32"))]
pub mod gate;

/// The normative WIT text, as compiled into this crate.
pub const WIT: &str = include_str!("../wit/ciris-node.wit");

/// The types the interfaces exchange, re-exported from [`bindings`].
pub mod types {
    pub use crate::bindings::ciris::node::log::MetricKind;
    pub use crate::bindings::ciris::node::net::{
        Carrier, CloseInfo, CloseReason, ConnInfo, FailInfo, FailReason, Framing, ListenOptions,
        NetInterface,
    };
    pub use crate::bindings::ciris::node::types::{
        AtRest, AtUse, Custody, Durability, Errno, KeyKind, Phase, SealRoot,
    };
    pub use crate::bindings::Event;
}

pub use types::Event;

/// What a node exports (§4.4 `world node`). Methods are associated
/// functions, as the world's exports are: node state lives in the node.
pub trait Node {
    /// Called once, before any tick.
    ///
    /// # Errors
    /// A message the host reports and then refuses to run the node.
    fn init() -> Result<(), String>;
    /// Run for at most `budget_us`; returns the next deadline in
    /// `clock::monotonic_us` time (§5.1).
    fn tick(budget_us: u32) -> u64;
    /// Deliver one host event.
    fn on_event(e: Event);
    /// The in-process `/v1` API.
    fn api(req: Vec<u8>, local: bool) -> Vec<u8>;
}

/// `ciris:node/clock`.
pub mod clock {
    /// Microseconds since an arbitrary origin; never goes back.
    #[must_use]
    pub fn monotonic_us() -> u64 {
        crate::sys::monotonic_us()
    }
    /// Unix time in milliseconds, or `None` until the host trusts its time.
    #[must_use]
    pub fn wall_ms() -> Option<i64> {
        crate::sys::wall_ms()
    }
}

/// `ciris:node/random`. CSPRNG bytes or a trap; never weak bytes.
pub mod random {
    use zeroize::Zeroize as _;

    /// Exactly `len` bytes from the host CSPRNG.
    ///
    /// # Panics
    /// Panics (a trap on wasm) if the host returns any other length. There
    /// is no fallback.
    #[must_use]
    pub fn fill(len: u32) -> Vec<u8> {
        let out = crate::sys::random_fill(len);
        assert!(
            out.len() == len as usize,
            "ciris:node/random.fill returned {} bytes for {len}; refusing weak or short randomness",
            out.len()
        );
        out
    }

    /// Fill `dest` from the host CSPRNG, clearing the intermediate copy.
    ///
    /// # Panics
    /// As [`fill`].
    pub fn fill_bytes(dest: &mut [u8]) {
        for chunk in dest.chunks_mut(u32::MAX as usize) {
            #[allow(clippy::cast_possible_truncation)] // chunk.len() <= u32::MAX
            let mut bytes = fill(chunk.len() as u32);
            chunk.copy_from_slice(&bytes);
            bytes.zeroize();
        }
    }
}

/// `ciris:node/storage`. Synchronous on every host (§6).
pub mod storage {
    pub use crate::sys::Volume;
    /// The volume the host opened for this node.
    #[must_use]
    pub fn primary() -> Volume {
        crate::sys::storage_primary()
    }
}

/// `ciris:node/net`. Non-blocking; progress is reported as events.
/// Readiness is edge-triggered: drain to `would-block` before waiting for
/// the next `readable` / `writable`.
pub mod net {
    pub use crate::sys::{Datagram, Stream};
    use crate::types::{Carrier, Errno, ListenOptions, NetInterface};

    /// The carriers this host offers (a runtime answer, never a `cfg`).
    #[must_use]
    pub fn carriers() -> Vec<Carrier> {
        crate::sys::net_carriers()
    }
    /// Whether this host can listen on `c`.
    #[must_use]
    pub fn can_listen(c: Carrier) -> bool {
        crate::sys::net_can_listen(c)
    }
    /// Whether this host offers unconnected datagram sockets ([`bind`]).
    #[must_use]
    pub fn can_datagram() -> bool {
        crate::sys::net_can_datagram()
    }
    /// Whether this host offers [`Datagram::multicast_join`].
    #[must_use]
    pub fn can_multicast() -> bool {
        crate::sys::net_can_multicast()
    }
    /// The host's network interfaces (empty when it will not say).
    #[must_use]
    pub fn interfaces() -> Vec<NetInterface> {
        crate::sys::net_interfaces()
    }
    /// Bind an unconnected datagram socket on `port` (0 = any) at the IP
    /// literal `bind` (`None` = all addresses). Its `readable` / `writable`
    /// events carry `token`.
    ///
    /// # Errors
    /// `unsupported` unless [`can_datagram`]; the host's refusal.
    pub fn bind(bind: Option<&str>, port: u16, token: u64) -> Result<Datagram, Errno> {
        crate::sys::net_bind(bind, port, token)
    }
    /// Start a connection; `connected(token)` or `failed({token, reason})`
    /// follows.
    ///
    /// # Errors
    /// The host's refusal; no event follows.
    pub fn dial(
        c: Carrier,
        target: &str,
        subprotocols: &[String],
        token: u64,
    ) -> Result<Stream, Errno> {
        crate::sys::net_dial(c, target, subprotocols, token)
    }
    /// Listen as `opts` says. `readable(token)` is edge-triggered:
    /// [`accept`] until it returns `None`. A later failure is
    /// `Event::ListenerFailed`.
    ///
    /// # Errors
    /// The host's refusal.
    pub fn listen(c: Carrier, opts: &ListenOptions, token: u64) -> Result<u32, Errno> {
        crate::sys::net_listen(c, opts, token)
    }
    /// Take one pending connection, whose events will carry `token`.
    /// Call until it returns `None` after each listener `readable`.
    ///
    /// # Errors
    /// The host's refusal.
    pub fn accept(listener: u32, token: u64) -> Result<Option<Stream>, Errno> {
        crate::sys::net_accept(listener, token)
    }
    /// Stop listening.
    pub fn unlisten(listener: u32) {
        crate::sys::net_unlisten(listener);
    }
}

/// `ciris:node/seal` (§8). Signing is asynchronous: start with a token,
/// wait for `Event::Sealed(token)`, then [`take`](seal::take).
///
/// Seeds never pass through node memory (§8.5): keys are generated inside
/// the seal ([`generate`](seal::generate)) or provisioned by the host
/// through its own seal root. This covers keys held through `seal` (the
/// CIRIS composite identity and signing keys). The Reticulum transport
/// identity (X25519 + Ed25519) is held by the node in node memory while
/// in use (reported SoftwareOnly at use) and is stored only wrapped, via
/// [`wrap`](seal::wrap) / [`unwrap`](seal::unwrap), under a key the host
/// derives from its seal root. Its plaintext never touches `storage`.
pub mod seal {
    use crate::types::{Custody, Errno, KeyKind};

    /// Composite public key length (mldsaPK || ed25519PK).
    pub const PUBLIC_KEY_LEN: usize = 1952 + 32;
    /// Transit-KEX / onion-hop public key length (x25519PK || mlkem768EK).
    pub const KEX_PUBLIC_KEY_LEN: usize = 32 + 1184;
    /// ML-KEM-768 ciphertext length `kem_decap` takes.
    pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
    /// `kem_decap` output: shared_x25519(32) || ss_mlkem768(32).
    pub const KEM_IKM_LEN: usize = 64;
    /// Composite signature length (mldsaSig || ed25519Sig).
    pub const COMPOSITE_SIGNATURE_LEN: usize = 3309 + 64;
    /// Longest `wrap` / `unwrap` label, in bytes; longer is `invalid`.
    pub const WRAP_LABEL_MAX: usize = 128;
    /// Plaintext size every host MUST accept for `wrap` (64 KiB); larger
    /// MAY be `invalid`.
    pub const WRAP_PLAINTEXT_MIN_MAX: usize = 64 * 1024;
    /// The FIPS 204 context ML-DSA-65 signs under inside the composite.
    pub const COMPOSITE_LABEL: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

    /// Per-half custody of key `id`.
    ///
    /// # Errors
    /// `not-found`, `unsupported`.
    pub fn describe(id: &str) -> Result<Custody, Errno> {
        crate::sys::seal_describe(id)
    }
    /// The composite public key of `id`.
    ///
    /// # Errors
    /// `not-found`, `unsupported`.
    pub fn public_key(id: &str) -> Result<Vec<u8>, Errno> {
        crate::sys::seal_public_key(id)
    }
    /// Start generating key `id` of `kind` inside the seal; after
    /// `Sealed(token)`, [`take`] returns only its public key. Call only
    /// after [`public_key`] answered `not-found` (first run); never
    /// regenerate an identity-class key on any other error.
    ///
    /// # Errors
    /// The operation never started.
    pub fn generate(id: &str, kind: KeyKind, token: u64) -> Result<(), Errno> {
        crate::sys::seal_generate(id, kind, token)
    }
    /// Start key agreement against transit-kex / onion-hop key `id`; after
    /// `Sealed(token)`, [`take`] returns `shared_x25519 || ss_mlkem768`
    /// (64 bytes), the `ikm` of `ciris_crypto::transit_kex::respond`.
    ///
    /// # Errors
    /// The operation never started.
    pub fn kem_decap(
        id: &str,
        x25519_peer_pub: &[u8],
        mlkem_ct: &[u8],
        token: u64,
    ) -> Result<(), Errno> {
        crate::sys::seal_kem_decap(id, x25519_peer_pub, mlkem_ct, token)
    }
    /// Start an Ed25519 signature over `msg` as it is.
    ///
    /// # Errors
    /// The operation never started.
    pub fn sign_classical(id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
        crate::sys::seal_sign_classical(id, msg, token)
    }
    /// Start an ML-DSA-65 signature over `msg` with FIPS 204 context `ctx`.
    ///
    /// # Errors
    /// The operation never started.
    pub fn sign_pqc(id: &str, ctx: &[u8], msg: &[u8], token: u64) -> Result<(), Errno> {
        crate::sys::seal_sign_pqc(id, ctx, msg, token)
    }
    /// Start the CC 2.6.1.7 composite signature over `msg`.
    ///
    /// # Errors
    /// The operation never started.
    pub fn sign_composite(id: &str, msg: &[u8], token: u64) -> Result<(), Errno> {
        crate::sys::seal_sign_composite(id, msg, token)
    }
    /// Start AEAD-wrapping a node-held secret under a host key derived from
    /// the seal root and domain-separated by `label`; after
    /// `Sealed(token)`, [`take`] returns the wrapped bytes. Never for CIRIS
    /// composite seeds (those are [`generate`]d in the seal).
    ///
    /// `label` is at most [`WRAP_LABEL_MAX`] bytes; plaintext up to
    /// [`WRAP_PLAINTEXT_MIN_MAX`] bytes is always accepted. Every wrap uses
    /// a fresh random nonce, so two wraps of one plaintext differ.
    ///
    /// # Errors
    /// The operation never started.
    pub fn wrap(label: &str, plaintext: &[u8], token: u64) -> Result<(), Errno> {
        crate::sys::seal_wrap(label, plaintext, token)
    }
    /// Start unwrapping a [`wrap`]ped blob under the same `label`; after
    /// `Sealed(token)`, [`take`] returns the plaintext, or `denied` /
    /// `invalid` on an authentication failure.
    ///
    /// # Errors
    /// The operation never started.
    pub fn unwrap(label: &str, wrapped: &[u8], token: u64) -> Result<(), Errno> {
        crate::sys::seal_unwrap(label, wrapped, token)
    }
    /// The result of the completed operation `token`.
    ///
    /// # Errors
    /// `would-block` before `Sealed(token)`, `not-found` for an unknown or
    /// already-taken token, or the operation's own failure.
    pub fn take(token: u64) -> Result<Vec<u8>, Errno> {
        crate::sys::seal_take(token)
    }
}

/// `ciris:node/wake`.
pub mod wake {
    /// Ask to be ticked by `us` (monotonic).
    pub fn next_deadline(us: u64) {
        crate::sys::wake_next_deadline(us);
    }
    /// Advisory: ask the host to keep the node running.
    pub fn keep_alive(reason: &str, on: bool) {
        crate::sys::wake_keep_alive(reason, on);
    }
}

/// `ciris:node/log`.
pub mod log {
    pub use crate::types::MetricKind;
    /// Log levels as the WIT numbers them.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(u8)]
    pub enum Level {
        /// 0
        Error = 0,
        /// 1
        Warn = 1,
        /// 2
        Info = 2,
        /// 3
        Debug = 3,
        /// 4
        Trace = 4,
    }
    /// Write one log record.
    pub fn record(level: Level, target: &str, msg: &str) {
        crate::sys::log_record(level as u8, target, msg);
    }
    /// Report one sample of series `name` with `(key, value)` labels.
    pub fn metric(name: &str, kind: MetricKind, value: f64, labels: &[(String, String)]) {
        crate::sys::log_metric(name, kind, value, labels);
    }
}

/// Export `$ty: Node` as the module's `node` world exports (`init`,
/// `tick`, `on-event`, `api`). Call once, in the node's final crate.
/// On native targets it only checks that `$ty: Node`.
#[macro_export]
macro_rules! export_node {
    ($ty:ty) => {
        $crate::__ciris_export_node!($ty);
    };
}
