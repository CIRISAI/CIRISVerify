//! A [`HardwareSigner`] whose Ed25519 signature is produced by a **caller-supplied
//! C callback** — the seam for hardware that the Rust core cannot reach directly.
//!
//! Motivation: on mobile a YubiKey is reached over NFC/USB by the app's native
//! layer (YubiKit), not by this library. To mint a YubiKey-backed federation
//! identity (`ciris_verify_create_federation_identity_with_callback`), the core
//! composes the record and the ML-DSA half as usual but **delegates the one
//! classical Ed25519 signature** to the tapped token via this callback. The public
//! key + the optional PIV attestation are read by the caller and passed in, so the
//! core never touches the token.
//!
//! The callback is invoked synchronously (blocking) from `sign`, on the same thread
//! that drives the mint — the established pattern for the device-bound flows.

use std::os::raw::c_void;

use async_trait::async_trait;
use ciris_keyring::{
    ClassicalAlgorithm, HardwareSigner, HardwareType, KeyGenConfig, KeyringError,
    PlatformAttestation, SoftwareAttestation, StorageDescriptor,
};

/// C ABI for the Ed25519 sign delegate.
///
/// Writes a 64-byte EdDSA signature over `msg[0..msg_len]` into `out_sig` (capacity
/// `out_sig_cap`, must be ≥ 64), sets `*out_sig_len`, and returns `0` on success
/// (non-zero ⇒ the signer reports a hardware fault). `ctx` is the opaque pointer
/// passed to [`CallbackHardwareSigner::new`] (e.g. the native YubiKit session).
pub type FfiEd25519SignCallback = unsafe extern "C" fn(
    ctx: *mut c_void,
    msg: *const u8,
    msg_len: usize,
    out_sig: *mut u8,
    out_sig_cap: usize,
    out_sig_len: *mut usize,
) -> i32;

/// Wraps the opaque callback context so the signer can be `Send + Sync` (required by
/// the trait). The pointer is only ever dereferenced by the caller's own callback,
/// on the single thread that drives the mint — never shared or moved across threads
/// by this type.
struct CallbackCtx(*mut c_void);
// SAFETY: the raw pointer is opaque to us; it is handed back verbatim to the
// caller's callback, which owns its thread-safety. The mint that uses this signer
// runs the callback on one thread within a single tap/connection window.
unsafe impl Send for CallbackCtx {}
unsafe impl Sync for CallbackCtx {}

/// A [`HardwareSigner`] backed by an external Ed25519 token via a C callback.
pub struct CallbackHardwareSigner {
    alias: String,
    public_key: Vec<u8>,
    /// Optional slot-9c PIV attestation cert (DER), supplied by the caller.
    attestation_der: Vec<u8>,
    ctx: CallbackCtx,
    cb: FfiEd25519SignCallback,
}

impl CallbackHardwareSigner {
    /// `public_key` must be the 32-byte Ed25519 key the callback signs with.
    pub fn new(
        alias: String,
        public_key: Vec<u8>,
        attestation_der: Vec<u8>,
        ctx: *mut c_void,
        cb: FfiEd25519SignCallback,
    ) -> Self {
        Self {
            alias,
            public_key,
            attestation_der,
            ctx: CallbackCtx(ctx),
            cb,
        }
    }
}

#[async_trait]
impl HardwareSigner for CallbackHardwareSigner {
    fn algorithm(&self) -> ClassicalAlgorithm {
        ClassicalAlgorithm::Ed25519
    }

    fn hardware_type(&self) -> HardwareType {
        HardwareType::ExternalSecureElement
    }

    async fn public_key(&self) -> Result<Vec<u8>, KeyringError> {
        Ok(self.public_key.clone())
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyringError> {
        let mut out = vec![0u8; 64];
        let mut out_len: usize = 0;
        let rc = unsafe {
            (self.cb)(
                self.ctx.0,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len as *mut usize,
            )
        };
        if rc != 0 {
            return Err(KeyringError::HardwareError {
                reason: format!("external Ed25519 sign callback failed (rc={rc})"),
            });
        }
        if out_len > out.len() {
            return Err(KeyringError::HardwareError {
                reason: format!("sign callback over-wrote the buffer ({out_len} > 64)"),
            });
        }
        out.truncate(out_len);
        Ok(out)
    }

    async fn attestation(&self) -> Result<PlatformAttestation, KeyringError> {
        Ok(PlatformAttestation::Software(SoftwareAttestation {
            key_derivation: "external-token-callback".into(),
            storage: "external-secure-element".into(),
            security_warning: if self.attestation_der.is_empty() {
                "external Ed25519 token; no PIV attestation supplied".into()
            } else {
                "external YubiKey PIV slot-9c attestation supplied by caller".into()
            },
        }))
    }

    async fn generate_key(&self, _config: &KeyGenConfig) -> Result<(), KeyringError> {
        Err(KeyringError::NotSupported {
            operation: "in-band keygen — the external token owns the private key".into(),
        })
    }

    async fn key_exists(&self, alias: &str) -> Result<bool, KeyringError> {
        Ok(alias == self.alias)
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), KeyringError> {
        Err(KeyringError::NotSupported {
            operation: "key deletion — manage the external token out of band".into(),
        })
    }

    fn current_alias(&self) -> &str {
        &self.alias
    }

    fn storage_descriptor(&self) -> StorageDescriptor {
        StorageDescriptor::Hardware {
            hardware_type: HardwareType::ExternalSecureElement,
            blob_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A stub delegate: writes a deterministic 64-byte "signature" whose first byte
    // encodes the message length, so the test can assert the callback saw the right
    // bytes and that `sign` returns them verbatim (plumbing test — no real crypto).
    unsafe extern "C" fn echo_sign(
        _ctx: *mut c_void,
        _msg: *const u8,
        msg_len: usize,
        out_sig: *mut u8,
        out_sig_cap: usize,
        out_sig_len: *mut usize,
    ) -> i32 {
        if out_sig_cap < 64 {
            return 1;
        }
        for i in 0..64 {
            *out_sig.add(i) = 0xAB;
        }
        *out_sig.add(0) = (msg_len & 0xff) as u8;
        *out_sig_len = 64;
        0
    }

    unsafe extern "C" fn failing_sign(
        _ctx: *mut c_void,
        _msg: *const u8,
        _msg_len: usize,
        _out_sig: *mut u8,
        _out_sig_cap: usize,
        _out_sig_len: *mut usize,
    ) -> i32 {
        7
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn delegates_sign_and_reports_pubkey() {
        let pk = vec![9u8; 32];
        let s = CallbackHardwareSigner::new(
            "tester".into(),
            pk.clone(),
            vec![1, 2, 3],
            std::ptr::null_mut(),
            echo_sign,
        );
        assert_eq!(block_on(s.public_key()).unwrap(), pk);
        assert_eq!(s.algorithm(), ClassicalAlgorithm::Ed25519);
        assert_eq!(s.current_alias(), "tester");

        let sig = block_on(s.sign(b"hello")).unwrap(); // 5 bytes
        assert_eq!(sig.len(), 64);
        assert_eq!(sig[0], 5); // callback saw msg_len == 5
        assert_eq!(sig[1], 0xAB);
    }

    #[test]
    fn surfaces_callback_failure() {
        let s = CallbackHardwareSigner::new(
            "tester".into(),
            vec![0u8; 32],
            vec![],
            std::ptr::null_mut(),
            failing_sign,
        );
        let err = block_on(s.sign(b"x")).unwrap_err();
        assert!(matches!(err, KeyringError::HardwareError { .. }));
    }
}
