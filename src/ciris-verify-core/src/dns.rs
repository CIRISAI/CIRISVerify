//! DNS-based multi-source validation.
//!
//! Queries DNS TXT records from multiple independent sources to retrieve
//! steward public key information and revocation revision.
//!
//! ## Record Format
//!
//! ```text
//! _ciris-verify.{host} TXT "v=ciris2 key=ed25519:{base64} pqc_fp=sha256:{hex} rev={revision} ts={timestamp}"
//! ```
//!
//! ## Fields
//!
//! - `v`: Protocol version (must be `ciris2` for hybrid mode)
//! - `key`: Ed25519 steward public key (base64-encoded)
//! - `pqc_fp`: SHA-256 fingerprint of ML-DSA public key (hex)
//! - `rev`: Revocation list revision number
//! - `ts`: Last update timestamp (Unix seconds)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tracing::{debug, info, instrument, warn};

use crate::error::VerifyError;

/// DNS transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsTransport {
    /// Standard UDP DNS (port 53) - may be blocked on mobile networks.
    #[default]
    Udp,
    /// DNS-over-HTTPS (DoH) - works everywhere HTTPS works.
    /// Uses Cloudflare 1.1.1.1 as the resolver.
    DnsOverHttps,
}

/// DNS validator for multi-source verification.
///
/// Queries TXT records from independent DNS servers to retrieve
/// steward key information and revocation status.
pub struct DnsValidator {
    /// Resolver for the US source.
    resolver: TokioAsyncResolver,
    /// DNS timeout (stored for future retry logic).
    #[allow(dead_code)]
    timeout: Duration,
}

/// Parsed data from a DNS TXT record.
#[derive(Debug, Clone)]
pub struct DnsTxtRecord {
    /// Protocol version (should be "ciris2").
    pub version: String,
    /// Ed25519 steward public key (raw bytes).
    pub steward_key_classical: Vec<u8>,
    /// SHA-256 fingerprint of ML-DSA public key.
    pub pqc_fingerprint: Vec<u8>,
    /// Revocation list revision number.
    pub revocation_revision: u64,
    /// Last update timestamp (Unix seconds).
    pub timestamp: i64,
}

impl DnsValidator {
    /// Create a new DNS validator with default system resolver.
    ///
    /// On Android, uses Google's public DNS (8.8.8.8) because Android doesn't have
    /// /etc/resolv.conf and hickory-dns can't discover system DNS servers.
    /// See: <https://github.com/hickory-dns/hickory-dns/issues/652>
    ///
    /// # Errors
    ///
    /// Returns error if resolver initialization fails.
    pub async fn new(timeout: Duration) -> Result<Self, VerifyError> {
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2; // Reduced for faster timeout
        opts.use_hosts_file = false;

        // On Android, ResolverConfig::default() fails because there's no /etc/resolv.conf.
        // Use Google's public DNS servers instead.
        #[cfg(target_os = "android")]
        let config = {
            info!("Android: using Google public DNS (8.8.8.8) - no /etc/resolv.conf");
            ResolverConfig::google()
        };
        #[cfg(not(target_os = "android"))]
        let config = ResolverConfig::default();

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self { resolver, timeout })
    }

    /// Create a DNS validator with a specific DNS server.
    ///
    /// # Arguments
    ///
    /// * `dns_server` - IP address of the DNS server to use
    /// * `timeout` - Query timeout
    ///
    /// # Errors
    ///
    /// Returns error if resolver initialization fails.
    pub async fn with_server(dns_server: IpAddr, timeout: Duration) -> Result<Self, VerifyError> {
        use hickory_resolver::config::{NameServerConfig, Protocol};
        use std::net::SocketAddr;

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(dns_server, 53),
            Protocol::Udp,
        ));

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2; // Reduced for faster timeout
        opts.use_hosts_file = false;

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self { resolver, timeout })
    }

    /// Create a DNS validator using DNS-over-HTTPS (DoH).
    ///
    /// This works on all platforms including mobile where UDP port 53 may be blocked.
    /// Uses Cloudflare's 1.1.1.1 DoH resolver.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Query timeout
    ///
    /// # Errors
    ///
    /// Returns error if resolver initialization fails.
    pub async fn with_doh(timeout: Duration) -> Result<Self, VerifyError> {
        info!("Creating DNS-over-HTTPS resolver (Cloudflare 1.1.1.1)");

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2; // Fewer attempts for DoH (already reliable)
        opts.use_hosts_file = false;

        // Build rustls ClientConfig with bundled Mozilla CA certs (webpki-roots)
        // This ensures DoH works even when native-certs fails (containers, some Linux distros)
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.to_vec(),
                ta.spki.to_vec(),
                ta.name_constraints.map(|nc| nc.to_vec()),
            )
        }));

        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Use Cloudflare's DoH endpoint with explicit TLS config
        let name_servers =
            NameServerConfigGroup::cloudflare_https().with_client_config(Arc::new(tls_config));
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self { resolver, timeout })
    }

    /// Create a DNS validator with the specified transport mode.
    ///
    /// # Arguments
    ///
    /// * `transport` - DNS transport mode (UDP or DoH)
    /// * `timeout` - Query timeout
    ///
    /// # Errors
    ///
    /// Returns error if resolver initialization fails.
    pub async fn with_transport(
        transport: DnsTransport,
        timeout: Duration,
    ) -> Result<Self, VerifyError> {
        match transport {
            DnsTransport::Udp => Self::new(timeout).await,
            DnsTransport::DnsOverHttps => Self::with_doh(timeout).await,
        }
    }

    /// Query a DNS TXT record for steward key information.
    ///
    /// # Arguments
    ///
    /// * `host` - The host to query (e.g., "registry-us.ciris.ai")
    ///
    /// # Returns
    ///
    /// Parsed TXT record data or error.
    #[instrument(skip(self), fields(host = %host))]
    pub async fn query_steward_record(&self, host: &str) -> Result<DnsTxtRecord, VerifyError> {
        let query_name = format!("_ciris-verify.{}", host);
        info!(
            query_name = %query_name,
            host = %host,
            "DNS: Querying TXT record..."
        );

        let lookup = self.resolver.txt_lookup(&query_name).await.map_err(|e| {
            warn!(
                query_name = %query_name,
                error = %e,
                "DNS: Lookup failed"
            );
            VerifyError::DnsError {
                message: format!("DNS lookup failed for {}: {}", query_name, e),
            }
        })?;

        info!(
            query_name = %query_name,
            record_count = lookup.iter().count(),
            "DNS: Lookup succeeded"
        );

        // Collect all TXT record data
        let mut txt_data = String::new();
        for txt in lookup.iter() {
            for data in txt.txt_data() {
                if let Ok(s) = std::str::from_utf8(data) {
                    txt_data.push_str(s);
                }
            }
        }

        if txt_data.is_empty() {
            warn!(query_name = %query_name, "DNS: Empty TXT record");
            return Err(VerifyError::DnsError {
                message: format!("Empty TXT record at {}", query_name),
            });
        }

        info!(
            query_name = %query_name,
            txt_length = txt_data.len(),
            "DNS: Parsing TXT record..."
        );
        debug!("DNS TXT data: {}", txt_data);

        let record = Self::parse_txt_record(&txt_data)?;
        info!(
            query_name = %query_name,
            version = %record.version,
            revision = record.revocation_revision,
            "DNS: TXT record parsed successfully"
        );
        Ok(record)
    }

    /// Parse a CIRIS TXT record string.
    ///
    /// Expected format:
    /// `v=ciris2 key=ed25519:{base64} pqc_fp=sha256:{hex} rev={revision} ts={timestamp}`
    fn parse_txt_record(txt: &str) -> Result<DnsTxtRecord, VerifyError> {
        let fields: HashMap<&str, &str> = txt
            .split_whitespace()
            .filter_map(|part| {
                let mut split = part.splitn(2, '=');
                match (split.next(), split.next()) {
                    (Some(key), Some(value)) => Some((key, value)),
                    _ => None,
                }
            })
            .collect();

        // Validate version
        let version = fields
            .get("v")
            .ok_or_else(|| VerifyError::DnsError {
                message: "Missing version field in TXT record".into(),
            })?
            .to_string();

        if version != "ciris2" {
            return Err(VerifyError::DnsError {
                message: format!(
                    "Unsupported protocol version: {} (expected ciris2)",
                    version
                ),
            });
        }

        // Parse key field: ed25519:{base64}
        let key_field = fields.get("key").ok_or_else(|| VerifyError::DnsError {
            message: "Missing key field in TXT record".into(),
        })?;

        let steward_key_classical = if let Some(b64) = key_field.strip_prefix("ed25519:") {
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| VerifyError::DnsError {
                    message: format!("Invalid base64 in key field: {}", e),
                })?
        } else {
            return Err(VerifyError::DnsError {
                message: "Key field must be prefixed with 'ed25519:'".into(),
            });
        };

        // Validate Ed25519 key size (32 bytes)
        if steward_key_classical.len() != 32 {
            return Err(VerifyError::DnsError {
                message: format!(
                    "Invalid Ed25519 key size: {} bytes (expected 32)",
                    steward_key_classical.len()
                ),
            });
        }

        // Parse pqc_fp field: sha256:{hex}
        let pqc_fp_field = fields.get("pqc_fp").ok_or_else(|| VerifyError::DnsError {
            message: "Missing pqc_fp field in TXT record".into(),
        })?;

        let pqc_fingerprint = if let Some(hex) = pqc_fp_field.strip_prefix("sha256:") {
            hex::decode(hex).map_err(|e| VerifyError::DnsError {
                message: format!("Invalid hex in pqc_fp field: {}", e),
            })?
        } else {
            return Err(VerifyError::DnsError {
                message: "pqc_fp field must be prefixed with 'sha256:'".into(),
            });
        };

        // Validate SHA-256 fingerprint size (32 bytes)
        if pqc_fingerprint.len() != 32 {
            return Err(VerifyError::DnsError {
                message: format!(
                    "Invalid SHA-256 fingerprint size: {} bytes (expected 32)",
                    pqc_fingerprint.len()
                ),
            });
        }

        // Parse revision
        let revocation_revision = fields
            .get("rev")
            .ok_or_else(|| VerifyError::DnsError {
                message: "Missing rev field in TXT record".into(),
            })?
            .parse()
            .map_err(|e| VerifyError::DnsError {
                message: format!("Invalid revision number: {}", e),
            })?;

        // Parse timestamp
        let timestamp = fields
            .get("ts")
            .ok_or_else(|| VerifyError::DnsError {
                message: "Missing ts field in TXT record".into(),
            })?
            .parse()
            .map_err(|e| VerifyError::DnsError {
                message: format!("Invalid timestamp: {}", e),
            })?;

        Ok(DnsTxtRecord {
            version,
            steward_key_classical,
            pqc_fingerprint,
            revocation_revision,
            timestamp,
        })
    }
}

/// Query result from multiple DNS sources.
#[derive(Debug, Clone)]
pub struct MultiDnsResult {
    /// Result from US source.
    pub us_result: Result<DnsTxtRecord, String>,
    /// Result from EU source.
    pub eu_result: Result<DnsTxtRecord, String>,
}

/// Query multiple DNS sources in parallel with automatic fallback.
///
/// Tries the primary transport first, then falls back to the secondary
/// transport for any failed queries. This handles cases where DoH is
/// blocked but UDP works, or vice versa.
///
/// # Arguments
///
/// * `us_host` - US DNS source host
/// * `eu_host` - EU DNS source host
/// * `timeout` - Query timeout
///
/// # Returns
///
/// Results from both sources (may contain errors).
#[instrument(skip_all, fields(us_host = %us_host, eu_host = %eu_host))]
pub async fn query_multiple_sources(
    us_host: &str,
    eu_host: &str,
    timeout: Duration,
) -> MultiDnsResult {
    let primary = default_dns_transport();
    let fallback = match primary {
        DnsTransport::DnsOverHttps => DnsTransport::Udp,
        DnsTransport::Udp => DnsTransport::DnsOverHttps,
    };

    // Try primary transport first
    info!(transport = ?primary, "Trying primary DNS transport");
    let mut result =
        query_multiple_sources_with_transport(us_host, eu_host, timeout, primary).await;

    // Check if we need fallback
    let us_failed = result.us_result.is_err();
    let eu_failed = result.eu_result.is_err();

    if us_failed || eu_failed {
        info!(
            us_failed = us_failed,
            eu_failed = eu_failed,
            fallback_transport = ?fallback,
            "Primary DNS failed, trying fallback transport"
        );

        // Create fallback validator
        if let Ok(fallback_validator) = DnsValidator::with_transport(fallback, timeout).await {
            // Retry failed queries with fallback transport
            if us_failed {
                info!(host = %us_host, "Retrying US source with fallback");
                if let Ok(record) = fallback_validator.query_steward_record(us_host).await {
                    info!(host = %us_host, "US fallback succeeded");
                    result.us_result = Ok(record);
                }
            }

            if eu_failed {
                info!(host = %eu_host, "Retrying EU source with fallback");
                if let Ok(record) = fallback_validator.query_steward_record(eu_host).await {
                    info!(host = %eu_host, "EU fallback succeeded");
                    result.eu_result = Ok(record);
                }
            }
        } else {
            warn!("Failed to create fallback DNS validator");
        }
    }

    result
}

/// Query multiple DNS sources with explicit transport mode.
#[instrument(skip_all, fields(us_host = %us_host, eu_host = %eu_host, transport = ?transport))]
pub async fn query_multiple_sources_with_transport(
    us_host: &str,
    eu_host: &str,
    timeout: Duration,
    transport: DnsTransport,
) -> MultiDnsResult {
    info!(
        transport = ?transport,
        us_host = %us_host,
        eu_host = %eu_host,
        "Starting DNS queries"
    );

    let validator = match DnsValidator::with_transport(transport, timeout).await {
        Ok(v) => v,
        Err(e) => {
            let err = format!("Failed to create DNS validator: {}", e);
            warn!("DNS validator creation failed: {}", err);
            return MultiDnsResult {
                us_result: Err(err.clone()),
                eu_result: Err(err),
            };
        },
    };

    info!("DNS validator created, querying both sources...");

    // Query both sources in parallel
    let (us_result, eu_result) = tokio::join!(
        validator.query_steward_record(us_host),
        validator.query_steward_record(eu_host),
    );

    info!(
        us_ok = us_result.is_ok(),
        eu_ok = eu_result.is_ok(),
        "DNS queries complete"
    );

    MultiDnsResult {
        us_result: us_result.map_err(|e| e.to_string()),
        eu_result: eu_result.map_err(|e| e.to_string()),
    }
}

/// Get the default DNS transport for the current platform.
///
/// - Android/iOS: DNS-over-HTTPS (mobile networks often block UDP:53)
/// - Desktop: Standard UDP DNS
pub fn default_dns_transport() -> DnsTransport {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        info!("Mobile platform detected, using DNS-over-HTTPS");
        DnsTransport::DnsOverHttps
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        // On desktop, try DoH first as it's more reliable
        // TODO: Make this configurable
        info!("Desktop platform, using DNS-over-HTTPS for reliability");
        DnsTransport::DnsOverHttps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_txt_record() {
        let txt = "v=ciris2 key=ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
                   pqc_fp=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
                   rev=2026012501 ts=1737763200";

        let record = DnsValidator::parse_txt_record(txt).unwrap();

        assert_eq!(record.version, "ciris2");
        assert_eq!(record.steward_key_classical.len(), 32);
        assert_eq!(record.pqc_fingerprint.len(), 32);
        assert_eq!(record.revocation_revision, 2026012501);
        assert_eq!(record.timestamp, 1737763200);
    }

    #[test]
    fn test_parse_missing_version() {
        let txt = "key=ed25519:AAAA= pqc_fp=sha256:0000 rev=1 ts=1";

        let result = DnsValidator::parse_txt_record(txt);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing version"));
    }

    #[test]
    fn test_parse_wrong_version() {
        let txt = "v=ciris1 key=ed25519:AAAA= pqc_fp=sha256:0000 rev=1 ts=1";

        let result = DnsValidator::parse_txt_record(txt);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported protocol version"));
    }

    #[test]
    fn test_parse_invalid_key_format() {
        let txt = "v=ciris2 key=rsa:AAAA= pqc_fp=sha256:0000 rev=1 ts=1";

        let result = DnsValidator::parse_txt_record(txt);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ed25519"));
    }

    #[test]
    fn test_parse_invalid_key_size() {
        // Too short (only 8 bytes when decoded)
        let txt = "v=ciris2 key=ed25519:AAAAAAAAAAA= \
                   pqc_fp=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
                   rev=1 ts=1";

        let result = DnsValidator::parse_txt_record(txt);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid Ed25519 key size"));
    }
}
