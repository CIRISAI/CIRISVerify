//! Configuration for the verification engine.

use std::path::PathBuf;
use std::time::Duration;

/// Configuration for CIRISVerify.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Primary HTTPS endpoint (registry API base URL). Also the first
    /// trust-root host (CC 5.3.4).
    pub https_endpoint: String,
    /// Further trust-root hosts, queried alongside `https_endpoint`. Every
    /// host's GenesisBundle is verified on its own against the baked accord
    /// holders; extra hosts add availability, not trust. DNS is not a source.
    pub https_endpoints: Vec<String>,
    /// Certificate fingerprint for pinning.
    pub cert_pin: Option<String>,
    /// Request timeout.
    pub timeout: Duration,
    /// Cache TTL.
    pub cache_ttl: Duration,
    /// Offline grace period.
    pub offline_grace: Duration,
    /// Key alias for hardware signer.
    pub key_alias: String,
    /// Directory for persistent cache storage.
    /// If None, uses XDG cache dir or temp directory.
    pub cache_dir: Option<PathBuf>,
    /// CIRIS primitive project this engine speaks for (e.g., `"ciris-agent"`,
    /// `"ciris-verify"`, `"ciris-lens"`). Threaded into the registry client
    /// as a mandatory `?project=<project>` query string on all project-scoped
    /// reads. Required since v1.11.0 — eliminates the years-old class of
    /// bugs where omitting the project defaulted to `"ciris-agent"`
    /// server-side and silently polluted namespaces.
    ///
    /// Default `"ciris-verify"` — verifying its OWN binary is the only
    /// project a default-built engine can sensibly check; callers from
    /// other primitives MUST override this. The FFI layer threads this
    /// field through from the constructor's `project` argument.
    pub project: String,
    /// Override for the v4.8.0+ network-reachability probe target list.
    /// `None` (default) means the probe races `https_endpoint` plus
    /// every entry in [`crate::registry::FALLBACK_REGISTRY_URLS`].
    /// `Some(v)` replaces that list with exactly `v` — used by tests
    /// to point the probe at known-unreachable IPs without having to
    /// also patch the registry fallback constant.
    pub probe_targets_override: Option<Vec<String>>,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            https_endpoint: "https://api.registry.ciris-services-1.ai".into(),
            https_endpoints: vec![
                "https://us.registry.ciris-services-1.ai".into(),
                "https://eu.registry.ciris-services-1.ai".into(),
            ],
            cert_pin: None,
            timeout: Duration::from_secs(10), // Must be < Python's 30s timeout
            cache_ttl: Duration::from_secs(300),
            offline_grace: Duration::from_secs(72 * 60 * 60), // 72 hours
            key_alias: "ciris_verify_key".into(),
            cache_dir: Self::default_cache_dir(),
            project: "ciris-verify".into(),
            probe_targets_override: None,
        }
    }
}

impl VerifyConfig {
    /// Every trust-root host: `https_endpoint` then `https_endpoints`,
    /// duplicates dropped.
    #[must_use]
    pub fn trust_root_endpoints(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for ep in std::iter::once(&self.https_endpoint).chain(&self.https_endpoints) {
            let ep = ep.trim_end_matches('/').to_string();
            if !out.contains(&ep) {
                out.push(ep);
            }
        }
        out
    }

    /// Get the default cache directory path.
    ///
    /// Uses XDG cache directory on Linux, Application Support on macOS,
    /// Local AppData on Windows, or falls back to a temp directory.
    fn default_cache_dir() -> Option<PathBuf> {
        // Try XDG_CACHE_HOME on Linux/Unix
        #[cfg(target_os = "linux")]
        {
            if let Ok(cache_home) = std::env::var("XDG_CACHE_HOME") {
                return Some(PathBuf::from(cache_home).join("ciris-verify"));
            }
            if let Ok(home) = std::env::var("HOME") {
                return Some(PathBuf::from(home).join(".cache").join("ciris-verify"));
            }
        }

        // Use Application Support on macOS
        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                return Some(
                    PathBuf::from(home)
                        .join("Library")
                        .join("Caches")
                        .join("ai.ciris.verify"),
                );
            }
        }

        // Use Local AppData on Windows
        #[cfg(target_os = "windows")]
        {
            if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                return Some(
                    PathBuf::from(local_app_data)
                        .join("CIRISVerify")
                        .join("cache"),
                );
            }
        }

        // Fallback to temp directory
        Some(std::env::temp_dir().join("ciris-verify-cache"))
    }
}
