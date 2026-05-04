//! Configuration for the verification engine.

use std::path::PathBuf;
use std::time::Duration;

/// Trust model for multi-source validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustModel {
    /// HTTPS is authoritative when reachable; DNS is advisory cross-check.
    /// Multiple HTTPS endpoints at different domains provide redundancy.
    HttpsAuthoritative,
    /// All sources weighted equally (legacy 2-of-3 consensus).
    EqualWeight,
}

/// DNS transport preference for multi-source validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsTransportPreference {
    /// Auto-detect based on platform (default).
    #[default]
    Auto,
    /// Always use DNS-over-HTTPS (DoH) - more reliable, slightly slower.
    DnsOverHttps,
    /// Always use native DNS - faster, may be filtered.
    Native,
}

/// Configuration for CIRISVerify.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// DNS resolver for US source.
    pub dns_us_host: String,
    /// DNS resolver for EU source.
    pub dns_eu_host: String,
    /// HTTPS endpoint URL.
    pub https_endpoint: String,
    /// Additional HTTPS endpoints at different domains for redundancy.
    pub https_endpoints: Vec<String>,
    /// Trust model for multi-source validation.
    pub trust_model: TrustModel,
    /// DNS transport preference (Auto, DoH, or Native).
    pub dns_transport: DnsTransportPreference,
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
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            dns_us_host: "us.registry.ciris-services-1.ai".into(),
            dns_eu_host: "eu.registry.ciris-services-eu-1.com".into(),
            https_endpoint: "https://api.registry.ciris-services-1.ai".into(),
            https_endpoints: Vec::new(),
            trust_model: TrustModel::HttpsAuthoritative,
            dns_transport: DnsTransportPreference::Auto,
            cert_pin: None,
            timeout: Duration::from_secs(10), // Must be < Python's 30s timeout
            cache_ttl: Duration::from_secs(300),
            offline_grace: Duration::from_secs(72 * 60 * 60), // 72 hours
            key_alias: "ciris_verify_key".into(),
            cache_dir: Self::default_cache_dir(),
            project: "ciris-verify".into(),
        }
    }
}

impl VerifyConfig {
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
