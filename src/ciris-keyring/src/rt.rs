//! Reentrancy-safe blocking bridge for the keyring's synchronous surface
//! (CIRISVerify#204).
//!
//! Parts of the keyring are synchronous by contract — `SecureBlobStorage::store`
//! / `load`, the `AndroidKeystoreSecureBlobStorage` constructor, the hardware
//! fan-out in `software.rs` — yet must drive async hardware ops. The old pattern
//! built a fresh current-thread runtime and `block_on`'d it:
//!
//! ```ignore
//! let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
//! rt.block_on(hw.key_exists())?;
//! ```
//!
//! `Runtime::block_on` **panics** — `Cannot start a runtime from within a
//! runtime` — whenever the calling thread is already inside a runtime. On the
//! CIRISAgent embedded topology (Python asyncio + the in-process Engine runtime)
//! that thread ALWAYS carries an ambient runtime by the time a mobile fold boot
//! reaches the keyring, so every one of these sites was a latent panic. It was
//! FATAL at `storage/android.rs` (the wrapper-key ensure aborted the node fold →
//! `Agent Init Failed`) and non-fatal-but-degrading at the secrets-service
//! hardware-master path (fell back to a software key). See CIRISVerify#204;
//! mirrors the entry-level shield in CIRISServer#264.
//!
//! [`keyring_block_on`] is the single safe bridge used at every such site:
//!   * **No runtime on this thread** → build one and block here (the old path,
//!     now taken only when it is actually safe).
//!   * **A runtime IS active** → hop the future to a scratch thread that carries
//!     none, and block there. [`std::thread::scope`] is used (not
//!     [`std::thread::spawn`]) so the future may borrow the caller's locals —
//!     e.g. `&self`, `&[u8]` — and the scope joins before returning.
//!
//! The `Send` bounds are satisfied everywhere it is used: the `HardwareSigner`
//! trait is `#[async_trait]` over `Send + Sync`, so its futures are boxed
//! `+ Send`; the inherent android storage `async fn`s have no `.await` points
//! (JNI is blocking), so the only state that must be `Send` is their captured
//! `&self` / `&[u8]` args, which are.

use std::future::Future;

/// Run `fut` to completion from a synchronous context, safe to call whether or
/// not the current thread already drives a tokio runtime.
///
/// Never construct or enter a runtime on a thread that already has one — this
/// checks [`tokio::runtime::Handle::try_current`] first, always.
pub(crate) fn keyring_block_on<F>(fut: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    if tokio::runtime::Handle::try_current().is_err() {
        // No ambient runtime — safe to build + block on this very thread.
        return build_and_block(fut);
    }
    // An ambient runtime is present; building/entering another here would panic.
    // Hop to a scratch thread that has none. Scoped so `fut` may borrow locals.
    std::thread::scope(|s| {
        s.spawn(|| build_and_block(fut))
            .join()
            .expect("keyring_block_on: scratch runtime thread panicked")
    })
}

/// Build a fresh current-thread runtime and block on `fut`. Only ever called on
/// a thread known to carry no ambient runtime (directly, or via the scratch
/// thread in [`keyring_block_on`]).
fn build_and_block<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("keyring_block_on: build current-thread tokio runtime")
        .block_on(fut)
}

#[cfg(test)]
mod tests {
    use super::keyring_block_on;

    #[test]
    fn works_with_no_ambient_runtime() {
        // The historically-safe case: a plain sync caller.
        assert_eq!(keyring_block_on(async { 41 + 1 }), 42);
    }

    #[test]
    fn works_inside_a_current_thread_runtime() {
        // The case that PANICKED before #204: a caller already inside a runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt.block_on(async {
            // Simulate the keyring being reached from within an ambient runtime.
            keyring_block_on(async { 7 * 6 })
        });
        assert_eq!(out, 42);
    }

    #[test]
    fn works_inside_a_multi_thread_runtime() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let out = rt.block_on(async { keyring_block_on(async { 6 * 7 }) });
        assert_eq!(out, 42);
    }

    #[test]
    fn future_may_borrow_a_local() {
        // The scoped-thread hop must accept a future that borrows a caller local.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let data = [1u8, 2, 3];
        let sum = rt.block_on(async { keyring_block_on(async { data.iter().sum::<u8>() }) });
        assert_eq!(sum, 6);
    }
}
