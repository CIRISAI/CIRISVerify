//! CIRISVerify#202 — test-only trust-root / custody relaxation, **compile-time
//! fenced**.
//!
//! A **local mesh reproduction** (two nodes on one Docker bridge, no operator
//! keys) needs to root a freshly-minted software canonical under an accord
//! anchor, and admit a **software-only accord holder** — neither of which the
//! real, hardware-rooted trust path allows (the anchor's private keys live on
//! the operators' FIPS YubiKeys; the custody floor requires a YubiKey PIV chain
//! with FIPS + touch). This module is the *only* place those requirements are
//! relaxed, and only for a test build.
//!
//! ## Why the boundary is compile-time, not runtime
//!
//! The production `ciris-server` container is **zero-env by design** — since
//! v0.5.0 all behaviour is configured through signed CEG objects, and the
//! compose file sets no `environment:` block. So at runtime **"no env signal"
//! and "production" are indistinguishable** — a runtime env allowlist cannot be
//! the outer wall, because prod legitimately sets nothing to allowlist against.
//!
//! Therefore the real boundary is the **`test-anchor` Cargo feature**. Prod
//! artifacts (the `release.yml` / PyPI wheel lane) build **without** it, so the
//! bypass code is **physically absent** from the shipped binary — verifiable
//! with `nm` / `test_anchor_compiled_in` on probe before a deploy. Without the
//! feature, every hook here is the inert `#[cfg(not(...))]` twin that returns
//! "off", byte-for-byte identical to the pre-#202 behaviour.
//!
//! ## Runtime AND-gate (defense-in-depth, *inside* the feature)
//!
//! Even in a `test-anchor` build, activation additionally requires
//! `CIRIS_TESTING_MODE == "true"` (CIRISAgent's own QA flag), and an
//! **anti-production tripwire** hard-refuses (loudly) if any explicit
//! environment signal reads `production` / `prod` / `staging`. This catches
//! operator error — a `test-anchor` build accidentally run with prod config —
//! but it is a second line of defense, *not* the wall.

/// Environment variables that, if they name a production-like value, mean we are
/// certainly NOT in a test context — the anti-production tripwire.
#[cfg(feature = "test-anchor")]
const PROD_ENV_VARS: &[&str] = &["ENVIRONMENT", "CIRIS_ENV", "CIRIS_ENVIRONMENT"];

/// Values of [`PROD_ENV_VARS`] that trip the anti-production refusal.
#[cfg(feature = "test-anchor")]
const PROD_ENV_VALUES: &[&str] = &["production", "prod", "staging"];

/// Whether the test-anchor code was compiled into this binary at all.
///
/// This is `true` **iff** the crate was built with `--features test-anchor`. It
/// does not consult the environment — it exists so a deployer can *prove* a
/// production artifact does not carry the bypass (the wheel-probe check in the
/// release checklist calls the FFI wrapper of this).
#[must_use]
pub const fn test_anchor_compiled_in() -> bool {
    cfg!(feature = "test-anchor")
}

/// Whether the test-anchor relaxations are **active right now**: compiled in
/// (feature on) AND enabled at runtime (`CIRIS_TESTING_MODE == "true"`) AND no
/// production environment signal is set.
///
/// This is the single gate both the trust-root override
/// ([`crate::accord_genesis::accord_holder_bootstrap_anchor`]) and the
/// software-only custody path
/// ([`crate::accord_custody_attestation::verify_accord_custody_attestation`])
/// consult, so the two can never diverge on what "test mode" means.
#[cfg(feature = "test-anchor")]
#[must_use]
pub fn test_anchor_active() -> bool {
    // Anti-production tripwire FIRST: an explicit prod signal alongside the test
    // flag is misconfiguration (or attack) — refuse LOUDLY, never bypass.
    for var in PROD_ENV_VARS {
        if let Ok(value) = std::env::var(var) {
            let value = value.trim().to_ascii_lowercase();
            if PROD_ENV_VALUES.contains(&value.as_str()) {
                tracing::error!(
                    env_var = var,
                    value = %value,
                    "REFUSING test-anchor mode: a production environment signal is set. \
                     The test trust-root / software-holder bypass will NOT engage. \
                     (This build carries the test-anchor feature and MUST NOT be a prod artifact.)"
                );
                return false;
            }
        }
    }
    std::env::var("CIRIS_TESTING_MODE").ok().as_deref() == Some("true")
}

/// Inert twin for production builds — the feature is off, so the relaxations do
/// not exist. Const-foldable to `false`, so every caller's test-mode branch is
/// dead code the optimizer removes.
#[cfg(not(feature = "test-anchor"))]
#[must_use]
#[inline(always)]
pub fn test_anchor_active() -> bool {
    false
}

/// The software test trust root(s) from `CIRIS_TEST_TRUST_ROOT`, iff
/// [`test_anchor_active`] — a comma-separated list of base64 Ed25519 pubkeys
/// (32 bytes each; more than one allowed for an M-of-N test root). Returns
/// `None` when the mode is off or the var is unset/undecodable, so the caller
/// falls through to the baked path.
///
/// Because [`crate::provenance::verify_provenance_chain`] roots on 1-of-N
/// set-membership, a single software key here is a valid rooting anchor.
#[cfg(feature = "test-anchor")]
#[must_use]
pub fn test_trust_root_override() -> Option<Vec<[u8; 32]>> {
    use base64::Engine;
    if !test_anchor_active() {
        return None;
    }
    let raw = std::env::var("CIRIS_TEST_TRUST_ROOT").ok()?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let keys: Vec<[u8; 32]> = raw
        .split(',')
        .filter_map(|k| b64.decode(k.trim()).ok())
        .filter_map(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .collect();
    if keys.is_empty() {
        return None;
    }
    tracing::warn!(
        test_root_keys = keys.len(),
        "CIRIS_TESTING_MODE: TEST TRUST ROOT active — the accord bootstrap anchor is a \
         SOFTWARE test key, NOT the humanity-accord roster. This MUST NOT appear in a \
         production deployment."
    );
    Some(keys)
}

/// Inert twin for production builds.
#[cfg(not(feature = "test-anchor"))]
#[must_use]
#[inline(always)]
pub fn test_trust_root_override() -> Option<Vec<[u8; 32]>> {
    None
}

/// Serializes EVERY test in the crate that mutates or reads the test-anchor env
/// vars — env is process-global, so e.g. `accord_genesis`'s baked-anchor test
/// (which asserts the roster is the 3 seated holders) must not run while a
/// test-mode test has `CIRIS_TESTING_MODE` set. Any such test must acquire this
/// FIRST. Crate-visible so cross-module env tests share the one lock.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use base64::Engine as _;

    /// RAII: snapshot + restore the three env vars this module reads, so a test
    /// can never leak `CIRIS_TESTING_MODE` into a sibling and flake it.
    struct EnvSandbox {
        saved: Vec<(&'static str, Option<String>)>,
    }
    impl EnvSandbox {
        fn new() -> Self {
            let vars = [
                "CIRIS_TESTING_MODE",
                "CIRIS_TEST_TRUST_ROOT",
                "ENVIRONMENT",
                "CIRIS_ENV",
            ];
            let saved = vars.iter().map(|v| (*v, std::env::var(v).ok())).collect();
            for v in vars {
                std::env::remove_var(v);
            }
            Self { saved }
        }
    }
    impl Drop for EnvSandbox {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    #[cfg(not(feature = "test-anchor"))]
    fn without_feature_everything_is_inert() {
        // No feature ⇒ no override regardless of env. This is the production
        // shape: the bypass code is not compiled in.
        let _g = super::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _sandbox = EnvSandbox::new();
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var(
            "CIRIS_TEST_TRUST_ROOT",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode([7u8; 32]),
        );
        assert!(!test_anchor_compiled_in());
        assert!(!test_anchor_active());
        assert!(test_trust_root_override().is_none());
    }

    #[test]
    #[cfg(feature = "test-anchor")]
    fn feature_on_but_testing_mode_off_is_inert() {
        let _g = super::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _sandbox = EnvSandbox::new();
        // CIRIS_TESTING_MODE not set.
        std::env::set_var(
            "CIRIS_TEST_TRUST_ROOT",
            base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        );
        assert!(test_anchor_compiled_in());
        assert!(!test_anchor_active(), "no CIRIS_TESTING_MODE ⇒ off");
        assert!(test_trust_root_override().is_none());
    }

    #[test]
    #[cfg(feature = "test-anchor")]
    fn feature_on_and_testing_mode_yields_override() {
        let _g = super::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _sandbox = EnvSandbox::new();
        let key = [0x42u8; 32];
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var(
            "CIRIS_TEST_TRUST_ROOT",
            base64::engine::general_purpose::STANDARD.encode(key),
        );
        assert!(test_anchor_active());
        assert_eq!(test_trust_root_override(), Some(vec![key]));
    }

    #[test]
    #[cfg(feature = "test-anchor")]
    fn anti_prod_tripwire_refuses_even_with_testing_mode() {
        let _g = super::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for prod in ["production", "prod", "STAGING", "Prod"] {
            let _sandbox = EnvSandbox::new();
            std::env::set_var("CIRIS_TESTING_MODE", "true");
            std::env::set_var(
                "CIRIS_TEST_TRUST_ROOT",
                base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
            );
            std::env::set_var("ENVIRONMENT", prod);
            assert!(
                !test_anchor_active(),
                "ENVIRONMENT={prod} must trip the anti-prod refusal"
            );
            assert!(test_trust_root_override().is_none());
        }
    }

    #[test]
    #[cfg(feature = "test-anchor")]
    fn multi_key_test_root_parses() {
        let _g = super::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _sandbox = EnvSandbox::new();
        let b64 = base64::engine::general_purpose::STANDARD;
        let (a, b) = ([1u8; 32], [2u8; 32]);
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var(
            "CIRIS_TEST_TRUST_ROOT",
            format!("{}, {}", b64.encode(a), b64.encode(b)),
        );
        assert_eq!(test_trust_root_override(), Some(vec![a, b]));
    }

    #[test]
    #[cfg(feature = "test-anchor")]
    fn garbage_test_root_is_none_not_partial() {
        let _g = super::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _sandbox = EnvSandbox::new();
        std::env::set_var("CIRIS_TESTING_MODE", "true");
        std::env::set_var("CIRIS_TEST_TRUST_ROOT", "not-base64-!!!");
        assert!(test_trust_root_override().is_none());
    }
}
