//! Configuration for the verification engine.

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
            dns_us_host: "us.registry.ciris-services-1.ai".into(),
            dns_eu_host: "eu.registry.ciris-services-1.ai".into(),
            https_endpoint: "https://api.registry.ciris-services-1.ai".into(),
            https_endpoints: Vec::new(),
            trust_model: TrustModel::HttpsAuthoritative,
            cert_pin: None,
            timeout: Duration::from_secs(30),
            cache_ttl: Duration::from_secs(300),
            offline_grace: Duration::from_secs(72 * 60 * 60), // 72 hours
            key_alias: "ciris_verify_key".into(),
        }
    }
}
