//! Configuration for the verification engine.

use std::time::Duration;

/// Configuration for CIRISVerify.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// DNS resolver for US source.
    pub dns_us_host: String,
    /// DNS resolver for EU source.
    pub dns_eu_host: String,
    /// HTTPS endpoint URL.
    pub https_endpoint: String,
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
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            dns_us_host: "registry-us.ciris.ai".into(),
            dns_eu_host: "registry-eu.ciris.ai".into(),
            https_endpoint: "https://verify.ciris.ai".into(),
            cert_pin: None,
            timeout: Duration::from_secs(30),
            cache_ttl: Duration::from_secs(300),
            offline_grace: Duration::from_secs(72 * 60 * 60), // 72 hours
            key_alias: "ciris_verify_key".into(),
        }
    }
}
