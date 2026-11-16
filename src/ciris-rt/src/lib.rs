//! `ciris-rt`: the single-threaded cooperative executor inside the CIRIS
//! WASM node (CIRISServer `FSD/WASM_NODE.md` §5, work item 2).
//!
//! The node is one thread under a host loop (§5.1):
//!
//! ```text
//! loop:
//!     poll host I/O; deliver events with on-event   -> Runtime::on_event
//!     deadline = tick(budget)                        -> Runtime::tick
//!     sleep until deadline or host event
//! ```
//!
//! * [`spawn`] takes `!Send` futures and returns a [`JoinHandle`] (a future
//!   of `Result<T, JoinError>`, with `abort()`). There is no `Send` bound
//!   anywhere.
//! * [`Runtime::tick`] runs ready tasks until the budget (read from
//!   `clock.monotonic-us`) is spent or nothing is ready, and returns the
//!   earliest timer deadline (also sent to `wake.next-deadline`).
//! * [`Runtime::on_event`] routes `ciris:node` events to the futures parked
//!   on their tokens.
//! * [`time`] (Instant, sleep, timeout, interval), [`net`] (dial / listen /
//!   accept / datagram, edge-triggered), [`seal`] (sign, generate,
//!   xwing-decap, wrap), [`lifecycle`], [`blocking`].
//! * [`node!`] wires a node's exports in one line.
//! * `replay` (default feature): record every import and event at the ABI
//!   boundary and replay it, failing loudly on divergence (§5.1, §11.4).
//!
//! **Tokens.** Every asynchronous ABI operation takes a node-chosen token.
//! ciris-rt allocates them per runtime as `kind << 56 | n`, `n` counting
//! from 1 and never reused, with kind 1 = connection, 2 = listener,
//! 3 = datagram socket, 4 = seal operation. They are deterministic, so a
//! replay issues the same tokens.
//!
//! **Channels** are not ciris-rt's. Any executor-agnostic channel works,
//! because they only use the `Waker` contract: `futures-channel`
//! (`oneshot`, `mpsc`) and `tokio::sync` (`oneshot`, `mpsc`, `watch`,
//! `Mutex`, `Notify`, ...) with tokio's `sync` feature alone, which builds
//! for wasm32-unknown-unknown without mio. Both are tested here.
//!
//! **No target cfg** (§4.1): the host is reached only through
//! `ciris-host-abi`'s wrappers, and `ciris-cfg-lint` passes on this crate.
//!
//! **`no_std`.** The crate is `#![no_std]` + `alloc`, and links `std` for
//! three things only, all present on wasm32-unknown-unknown and
//! x86_64-unknown-uefi: `thread_local!` (the per-thread current runtime:
//! native hosts and tests run nodes on several threads), `std::sync::Mutex`
//! (the run queue behind the `Send + Sync` waker contract), and
//! `std::io::Error` (for `futures_io::AsyncRead` / `AsyncWrite`).
//! `ciris-host-abi` itself already requires `std`.

#![no_std]

extern crate alloc;
extern crate std;

mod executor;
pub mod lifecycle;
pub mod net;
#[cfg(feature = "replay")]
pub mod replay;
pub mod seal;
pub mod time;

pub use ciris_host_abi::Event;
pub use executor::{
    blocking, spawn, spawn_blocking, yield_now, JoinError, JoinHandle, Runtime, YieldNow,
    MAX_ROUNDS_PER_TICK,
};

use alloc::string::String;
use alloc::vec::Vec;

/// What a node built on ciris-rt supplies; [`node!`] adds `tick` and
/// `on-event` from the runtime.
pub trait RtNode {
    /// Called once before any tick. Spawn the node's tasks here.
    ///
    /// # Errors
    /// A message the host reports, after which it refuses to run the node.
    fn init() -> Result<(), String>;

    /// The in-process `/v1` API (synchronous; spawn work and answer later
    /// through state if it must wait).
    fn api(req: Vec<u8>, local: bool) -> Vec<u8>;

    /// Called for every event, after ciris-rt routed it. Default: nothing.
    fn on_event(_e: &Event) {}
}

/// Export `$ty: RtNode` as the module's `node` world exports, in one line:
/// `init` / `api` from the node, `tick` / `on-event` from this thread's
/// [`Runtime`]. Wraps `ciris_host_abi::export_node!`.
///
/// ```ignore
/// struct MyNode;
/// impl ciris_rt::RtNode for MyNode {
///     fn init() -> Result<(), String> {
///         ciris_rt::spawn(async { /* ... */ });
///         Ok(())
///     }
///     fn api(req: Vec<u8>, _local: bool) -> Vec<u8> { req }
/// }
/// ciris_rt::node!(MyNode);
/// ```
///
/// The generated type is `__CirisRtNode`, a `ciris_host_abi::Node`, so a
/// native host (or [`replay`]) can drive it the same way.
#[macro_export]
macro_rules! node {
    ($ty:ty) => {
        /// The `ciris_host_abi::Node` that [`ciris_rt::node!`] generated.
        pub struct __CirisRtNode;
        impl $crate::__private::Node for __CirisRtNode {
            fn init() -> ::core::result::Result<(), $crate::__private::String> {
                <$ty as $crate::RtNode>::init()
            }
            fn tick(budget_us: u32) -> u64 {
                $crate::__private::tick(budget_us)
            }
            fn on_event(e: $crate::Event) {
                $crate::__private::on_event::<$ty>(e)
            }
            fn api(req: $crate::__private::Vec<u8>, local: bool) -> $crate::__private::Vec<u8> {
                <$ty as $crate::RtNode>::api(req, local)
            }
        }
        $crate::__private::ciris_host_abi::export_node!(__CirisRtNode);
    };
}

#[doc(hidden)]
pub mod __private {
    pub use alloc::string::String;
    pub use alloc::vec::Vec;
    pub use ciris_host_abi;
    pub use ciris_host_abi::Node;

    pub fn tick(budget_us: u32) -> u64 {
        crate::Runtime::current().tick(budget_us)
    }

    pub fn on_event<N: crate::RtNode>(e: crate::Event) {
        N::on_event(&e);
        crate::Runtime::current().on_event(e);
    }
}
