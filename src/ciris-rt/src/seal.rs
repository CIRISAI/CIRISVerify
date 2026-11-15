//! Async wrappers over `ciris:node/seal` (FSD §8).
//!
//! Each call allocates a seal token, starts the operation, parks until
//! `event.sealed(token)`, then calls `seal.take(token)` once. Many may be
//! in flight at once and complete in any order: pipeline a backfill by
//! spawning (or joining) the futures instead of awaiting them one by one.
//!
//! Dropping a future before it completes does not leak the host's result:
//! the token is marked orphaned and the runtime takes and zeroizes the
//! result when `sealed` arrives.
//!
//! Results that are secret (the `kem-decap` ikm, `unwrap`'s plaintext)
//! come back as [`Zeroizing`] buffers.

use alloc::vec::Vec;
use core::future::poll_fn;
use core::task::Poll;

use ciris_host_abi::seal as abi;
pub use ciris_host_abi::seal::{
    describe, public_key, COMPOSITE_LABEL, COMPOSITE_SIGNATURE_LEN, KEM_IKM_LEN,
    KEX_PUBLIC_KEY_LEN, MLKEM768_CIPHERTEXT_LEN, PUBLIC_KEY_LEN, WRAP_LABEL_MAX,
    WRAP_PLAINTEXT_MIN_MAX,
};
pub use ciris_host_abi::types::{Custody, Errno, KeyKind};
pub use zeroize::Zeroizing;

use crate::executor::{Interest, TokenKind};
use crate::Runtime;

/// Marks the token orphaned if the operation future is dropped early.
struct Guard {
    rt: Runtime,
    token: u64,
    done: bool,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let sealed = self
            .rt
            .with_entry(self.token, |e| {
                e.orphan = true;
                e.sealed
            })
            .unwrap_or(false);
        if sealed {
            // Completed but never taken: take and wipe it now.
            self.rt.unregister(self.token);
            if let Ok(mut v) = abi::take(self.token) {
                zeroize::Zeroize::zeroize(&mut v);
            }
        }
    }
}

async fn run(start: impl FnOnce(u64) -> Result<(), Errno>) -> Result<Vec<u8>, Errno> {
    let rt = Runtime::current();
    let token = rt.alloc_token(TokenKind::Seal);
    if let Err(e) = start(token) {
        rt.unregister(token);
        return Err(e);
    }
    let mut guard = Guard {
        rt,
        token,
        done: false,
    };
    poll_fn(|cx| {
        let sealed = guard.rt.with_entry(token, |e| e.sealed).unwrap_or(false);
        if sealed {
            match abi::take(token) {
                // A spurious `sealed`: wait for the real one.
                Err(Errno::WouldBlock) => {
                    guard.rt.with_entry(token, |e| e.sealed = false);
                },
                r => {
                    guard.done = true;
                    guard.rt.unregister(token);
                    return Poll::Ready(r);
                },
            }
        }
        guard.rt.park(token, Interest::Done, cx.waker());
        Poll::Pending
    })
    .await
}

/// Generate key `id` of `kind` inside the seal; returns only its public key
/// ([`PUBLIC_KEY_LEN`] for composite, [`KEX_PUBLIC_KEY_LEN`] otherwise).
/// Call only after [`public_key`] answered `not-found` (first run); never
/// regenerate an identity-class key on any other error.
///
/// # Errors
/// The host's refusal or failure.
pub async fn generate(id: &str, kind: KeyKind) -> Result<Vec<u8>, Errno> {
    run(|t| abi::generate(id, kind, t)).await
}

/// The CC 2.6.1.7 composite signature over `msg` ([`COMPOSITE_SIGNATURE_LEN`]
/// = 3373 bytes, `mldsaSig || ed25519Sig`).
///
/// # Errors
/// The host's refusal or failure.
pub async fn sign_composite(id: &str, msg: &[u8]) -> Result<Vec<u8>, Errno> {
    run(|t| abi::sign_composite(id, msg, t)).await
}

/// Ed25519 over `msg` as it is (64 bytes).
///
/// # Errors
/// The host's refusal or failure.
pub async fn sign_classical(id: &str, msg: &[u8]) -> Result<Vec<u8>, Errno> {
    run(|t| abi::sign_classical(id, msg, t)).await
}

/// ML-DSA-65 over `msg` with FIPS 204 context `ctx` (3309 bytes).
///
/// # Errors
/// The host's refusal or failure.
pub async fn sign_pqc(id: &str, ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>, Errno> {
    run(|t| abi::sign_pqc(id, ctx, msg, t)).await
}

/// Key agreement against transit-kex / onion-hop key `id`: returns
/// `shared_x25519(32) || ss_mlkem768(32)`, the `ikm` of
/// `ciris_crypto::transit_kex::respond`, for the node's own
/// `derive_transit_keys`.
///
/// # Errors
/// `invalid` (low-order peer key, wrong lengths, a composite id); the
/// host's refusal or failure.
pub async fn kem_decap(
    id: &str,
    x25519_peer_pub: &[u8],
    mlkem_ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Errno> {
    run(|t| abi::kem_decap(id, x25519_peer_pub, mlkem_ct, t))
        .await
        .map(Zeroizing::new)
}

/// AEAD-wrap a node-held secret under a host key derived from the seal
/// root, domain-separated by `label`; returns the blob to write to
/// storage. Never for identity seeds.
///
/// # Errors
/// `invalid` for a label over [`WRAP_LABEL_MAX`] bytes; the host's failure.
pub async fn wrap(label: &str, plaintext: &[u8]) -> Result<Vec<u8>, Errno> {
    run(|t| abi::wrap(label, plaintext, t)).await
}

/// Reverse [`wrap`] under the same `label`.
///
/// # Errors
/// `denied` / `invalid` when authentication fails.
pub async fn unwrap(label: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, Errno> {
    run(|t| abi::unwrap(label, wrapped, t))
        .await
        .map(Zeroizing::new)
}
