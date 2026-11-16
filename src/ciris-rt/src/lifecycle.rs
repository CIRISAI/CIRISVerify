//! Host lifecycle and clock trust, as routed events (FSD §5.2: the
//! `node_lifecycle` mapping; `sigterm-broker` becomes `lifecycle`).

use ciris_host_abi::types::Phase;

use crate::Runtime;

/// The most recent phase the host delivered, if any.
#[must_use]
pub fn current() -> Option<Phase> {
    Runtime::current().lifecycle_current()
}

/// The next delivered phase, oldest first (phases are queued, up to 64,
/// until read). One reader: a second concurrent waiter replaces the first.
pub async fn next() -> Phase {
    let rt = Runtime::current();
    core::future::poll_fn(|cx| rt.lifecycle_poll(cx)).await
}

/// Whether `event.clock-trusted` has arrived: `clock.wall-ms` is trusted,
/// and signed rows may be stamped.
#[must_use]
pub fn clock_trusted() -> bool {
    Runtime::current().clock_trusted()
}

/// Wait for `event.clock-trusted` (at once if it already came). A node
/// MUST NOT stamp signed rows before this.
pub async fn wait_clock_trusted() {
    let rt = Runtime::current();
    core::future::poll_fn(|cx| rt.clock_trusted_poll(cx)).await;
}
