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
//!
//! ## Resolution Approaches
//!
//! ### Desktop (async tokio)
//! 1. **DoH with native-certs** - hickory-resolver default, works on most systems
//! 2. **DoH with bundled webpki-roots** - fallback for containers/emulators
//! 3. **DNS JSON API via HTTPS** - Google/Cloudflare JSON API using reqwest
//!
//! ### Mobile (blocking ureq - tokio async I/O broken on JNI/iOS threads)
//! 1. **DNS JSON API via HTTPS** - Google/Cloudflare JSON API using blocking ureq

use std::collections::HashMap;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::net::IpAddr;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hickory_resolver::TokioAsyncResolver;
use tracing::{debug, error, info, instrument, warn};

use crate::error::VerifyError;

// Mobile blocking HTTP for DNS JSON API (tokio async I/O broken on JNI/iOS threads)
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::mobile_http;

/// Google DNS JSON API endpoint (uses reqwest with bundled certs)
const GOOGLE_DNS_JSON_API: &str = "https://dns.google/resolve";
/// Cloudflare DNS JSON API endpoint (backup)
const CLOUDFLARE_DNS_JSON_API: &str = "https://cloudflare-dns.com/dns-query";

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
///
/// NOTE: Desktop only. Mobile uses blocking JSON API directly.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone)]
pub struct DnsValidator {
    /// Resolver for the US source.
    resolver: TokioAsyncResolver,
    /// DNS timeout (stored for future retry logic).
    #[allow(dead_code)]
    timeout: Duration,
}

/// Mobile stub for DnsValidator (only static methods used).
#[cfg(any(target_os = "android", target_os = "ios"))]
pub struct DnsValidator;

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

// Desktop-only async methods (use TokioAsyncResolver)
#[cfg(not(any(target_os = "android", target_os = "ios")))]
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

        // Use default Cloudflare DoH config (uses native-certs when available)
        // This is the PRIMARY path - works on most systems
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), opts);

        Ok(Self { resolver, timeout })
    }

    /// Create a DNS validator using DNS-over-HTTPS with bundled Mozilla CA certs.
    /// This is the FALLBACK path for environments where native-certs fails
    /// (containers, some Linux distros, Android emulators).
    pub async fn with_doh_bundled_certs(timeout: Duration) -> Result<Self, VerifyError> {
        info!("Creating DNS-over-HTTPS resolver with bundled certs (fallback)");

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;
        opts.use_hosts_file = false;

        // Build rustls ClientConfig with bundled Mozilla CA certs (webpki-roots)
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

        // Use Cloudflare's DoH endpoint with explicit bundled TLS config
        let name_servers =
            NameServerConfigGroup::cloudflare_https().with_client_config(Arc::new(tls_config));
        let config = ResolverConfig::from_parts(None, vec![], name_servers);

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self { resolver, timeout })
    }

    /// Query a TXT record using Google/Cloudflare DNS JSON API via plain HTTPS.
    /// This bypasses hickory-resolver entirely and uses reqwest (which has bundled certs).
    /// Returns the first successful result from Google or Cloudflare.
    /// NOTE: Desktop only - mobile uses blocking version via ureq.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub async fn query_txt_via_json_api(
        hostname: &str,
        timeout: Duration,
    ) -> Result<Vec<String>, VerifyError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| VerifyError::DnsError {
                message: format!("Failed to create HTTP client: {}", e),
            })?;

        // Try Google first, then Cloudflare in parallel
        let google_url = format!("{}?name={}&type=TXT", GOOGLE_DNS_JSON_API, hostname);
        let cloudflare_url = format!("{}?name={}&type=TXT", CLOUDFLARE_DNS_JSON_API, hostname);

        info!(hostname = %hostname, "DNS JSON API: querying Google and Cloudflare in parallel");

        let google_fut = client
            .get(&google_url)
            .header("Accept", "application/dns-json")
            .send();
        let cloudflare_fut = client
            .get(&cloudflare_url)
            .header("Accept", "application/dns-json")
            .send();

        // Race both requests
        tokio::select! {
            google_result = google_fut => {
                match google_result {
                    Ok(resp) if resp.status().is_success() => {
                        info!("DNS JSON API: Google responded first");
                        return Self::parse_dns_json_response(resp).await;
                    }
                    Ok(resp) => {
                        warn!("DNS JSON API: Google returned status {}", resp.status());
                    }
                    Err(e) => {
                        warn!("DNS JSON API: Google failed: {}", e);
                    }
                }
            }
            cloudflare_result = cloudflare_fut => {
                match cloudflare_result {
                    Ok(resp) if resp.status().is_success() => {
                        info!("DNS JSON API: Cloudflare responded first");
                        return Self::parse_dns_json_response(resp).await;
                    }
                    Ok(resp) => {
                        warn!("DNS JSON API: Cloudflare returned status {}", resp.status());
                    }
                    Err(e) => {
                        warn!("DNS JSON API: Cloudflare failed: {}", e);
                    }
                }
            }
        }

        // If select returned without success, try the other one
        // (This handles the case where the first one failed)
        let fallback_url = format!("{}?name={}&type=TXT", CLOUDFLARE_DNS_JSON_API, hostname);
        match client
            .get(&fallback_url)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => Self::parse_dns_json_response(resp).await,
            Ok(resp) => Err(VerifyError::DnsError {
                message: format!("DNS JSON API fallback returned status {}", resp.status()),
            }),
            Err(e) => Err(VerifyError::DnsError {
                message: format!("DNS JSON API fallback failed: {}", e),
            }),
        }
    }

    /// Query TXT record using DNS JSON API with blocking HTTP (mobile).
    /// Uses ureq instead of reqwest to avoid tokio async I/O issues on JNI/iOS threads.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn query_txt_via_json_api_blocking(
        hostname: &str,
        timeout: Duration,
    ) -> Result<Vec<String>, VerifyError> {
        let agent = mobile_http::create_tls_agent(timeout)?;

        // Try Google first
        let google_url = format!("{}?name={}&type=TXT", GOOGLE_DNS_JSON_API, hostname);
        info!(hostname = %hostname, "DNS JSON API (blocking): trying Google");

        match agent
            .get(&google_url)
            .set("Accept", "application/dns-json")
            .call()
        {
            Ok(resp) if resp.status() == 200 => {
                info!("DNS JSON API (blocking): Google succeeded");
                return Self::parse_dns_json_response_blocking(resp);
            }
            Ok(resp) => {
                warn!(
                    "DNS JSON API (blocking): Google returned status {}",
                    resp.status()
                );
            }
            Err(e) => {
                warn!("DNS JSON API (blocking): Google failed: {}", e);
            }
        }

        // Fallback to Cloudflare
        let cloudflare_url = format!("{}?name={}&type=TXT", CLOUDFLARE_DNS_JSON_API, hostname);
        info!(hostname = %hostname, "DNS JSON API (blocking): trying Cloudflare");

        match agent
            .get(&cloudflare_url)
            .set("Accept", "application/dns-json")
            .call()
        {
            Ok(resp) if resp.status() == 200 => {
                info!("DNS JSON API (blocking): Cloudflare succeeded");
                Self::parse_dns_json_response_blocking(resp)
            }
            Ok(resp) => Err(VerifyError::DnsError {
                message: format!(
                    "DNS JSON API (blocking): Cloudflare returned status {}",
                    resp.status()
                ),
            }),
            Err(e) => Err(VerifyError::DnsError {
                message: format!("DNS JSON API (blocking): Cloudflare failed: {}", e),
            }),
        }
    }

    /// Parse DNS JSON API response from blocking ureq response.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn parse_dns_json_response_blocking(
        resp: ureq::Response,
    ) -> Result<Vec<String>, VerifyError> {
        let json: serde_json::Value = resp.into_json().map_err(|e| VerifyError::DnsError {
            message: format!("Failed to parse DNS JSON response: {}", e),
        })?;

        // Check for DNS error status
        if let Some(status) = json.get("Status").and_then(|s| s.as_i64()) {
            if status != 0 {
                return Err(VerifyError::DnsError {
                    message: format!("DNS JSON API returned error status: {}", status),
                });
            }
        }

        // Extract TXT records from Answer array
        let mut txt_records = Vec::new();
        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for answer in answers {
                if let Some(data) = answer.get("data").and_then(|d| d.as_str()) {
                    // Remove surrounding quotes if present
                    let clean = data.trim_matches('"');
                    txt_records.push(clean.to_string());
                }
            }
        }

        if txt_records.is_empty() {
            return Err(VerifyError::DnsError {
                message: "No TXT records found in DNS JSON response".to_string(),
            });
        }

        debug!(
            count = txt_records.len(),
            "DNS JSON API (blocking): parsed TXT records"
        );
        Ok(txt_records)
    }

    /// Parse DNS JSON API response (Google/Cloudflare compatible format)
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn parse_dns_json_response(resp: reqwest::Response) -> Result<Vec<String>, VerifyError> {
        let json: serde_json::Value = resp.json().await.map_err(|e| VerifyError::DnsError {
            message: format!("Failed to parse DNS JSON response: {}", e),
        })?;

        // Check for DNS error status
        if let Some(status) = json.get("Status").and_then(|s| s.as_i64()) {
            if status != 0 {
                return Err(VerifyError::DnsError {
                    message: format!("DNS JSON API returned error status: {}", status),
                });
            }
        }

        // Extract TXT records from Answer array
        let mut txt_records = Vec::new();
        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for answer in answers {
                if let Some(data) = answer.get("data").and_then(|d| d.as_str()) {
                    // Remove surrounding quotes if present
                    let clean = data.trim_matches('"');
                    txt_records.push(clean.to_string());
                }
            }
        }

        if txt_records.is_empty() {
            return Err(VerifyError::DnsError {
                message: "No TXT records found in DNS JSON response".to_string(),
            });
        }

        debug!(
            count = txt_records.len(),
            "DNS JSON API: parsed TXT records"
        );
        Ok(txt_records)
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
}

// Shared methods available on all platforms
impl DnsValidator {
    /// Parse a CIRIS TXT record string.
    ///
    /// Expected format:
    /// `v=ciris2 key=ed25519:{base64} pqc_fp=sha256:{hex} rev={revision} ts={timestamp}`
    pub fn parse_txt_record(txt: &str) -> Result<DnsTxtRecord, VerifyError> {
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

/// Query multiple DNS sources.
///
/// ## Desktop (async tokio)
/// Runs 6+ parallel queries across 3 approaches:
/// 1. DoH with native-certs (PRIMARY) - works on most systems
/// 2. DoH with bundled webpki-roots (FALLBACK) - for containers/emulators
/// 3. DNS JSON API via HTTPS - Google/Cloudflare JSON API using reqwest
///
/// ## Mobile (blocking ureq)
/// Uses DNS JSON API with blocking HTTP (tokio async I/O broken on JNI/iOS threads).
/// Queries Google then Cloudflare sequentially for each source.
///
/// # Arguments
///
/// * `us_host` - US DNS source host
/// * `eu_host` - EU DNS source host
/// * `timeout` - Individual query timeout (total capped at 10s)
///
/// # Returns
///
/// Results from both sources (may contain errors).
#[instrument(skip_all, fields(us_host = %us_host, eu_host = %eu_host))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn query_multiple_sources(
    us_host: &str,
    eu_host: &str,
    timeout: Duration,
) -> MultiDnsResult {
    use tokio::time::timeout as tokio_timeout;

    // Cap individual timeout at 8 seconds to leave room for overhead
    let per_query_timeout = timeout.min(Duration::from_secs(8));
    // Total operation capped at 10 seconds
    let total_timeout = Duration::from_secs(10);

    info!(
        us_host = %us_host,
        eu_host = %eu_host,
        per_query_timeout_ms = per_query_timeout.as_millis(),
        total_timeout_ms = total_timeout.as_millis(),
        "Starting parallel DNS resolution (3 approaches × 2 sources)"
    );

    // Run the parallel query with a total timeout
    match tokio_timeout(
        total_timeout,
        query_all_approaches_parallel(us_host, eu_host, per_query_timeout),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            error!(
                us_host = %us_host,
                eu_host = %eu_host,
                "DNS resolution timed out after 10 seconds"
            );
            MultiDnsResult {
                us_result: Err("Total timeout (10s) exceeded".to_string()),
                eu_result: Err("Total timeout (10s) exceeded".to_string()),
            }
        },
    }
}

/// Mobile version: Query multiple DNS sources using blocking HTTP.
///
/// Uses DNS JSON API with blocking ureq (tokio async I/O broken on JNI/iOS threads).
/// This function is async for API compatibility but internally uses blocking I/O.
#[instrument(skip_all, fields(us_host = %us_host, eu_host = %eu_host))]
#[cfg(any(target_os = "android", target_os = "ios"))]
pub async fn query_multiple_sources(
    us_host: &str,
    eu_host: &str,
    timeout: Duration,
) -> MultiDnsResult {
    info!(
        us_host = %us_host,
        eu_host = %eu_host,
        timeout_ms = timeout.as_millis(),
        "Mobile DNS: Using blocking JSON API (tokio async broken on JNI)"
    );

    // Query both sources using blocking HTTP
    let us_query_name = format!("_ciris-verify.{}", us_host);
    let eu_query_name = format!("_ciris-verify.{}", eu_host);

    // US query
    let us_result = match DnsValidator::query_txt_via_json_api_blocking(&us_query_name, timeout) {
        Ok(txt_records) => {
            if let Some(txt) = txt_records.first() {
                match DnsValidator::parse_txt_record(txt) {
                    Ok(record) => {
                        info!(
                            "Mobile DNS US: success, rev={}",
                            record.revocation_revision
                        );
                        Ok(record)
                    }
                    Err(e) => {
                        warn!("Mobile DNS US: parse error: {}", e);
                        Err(e.to_string())
                    }
                }
            } else {
                Err("No TXT records in response".to_string())
            }
        }
        Err(e) => {
            warn!("Mobile DNS US: query failed: {}", e);
            Err(e.to_string())
        }
    };

    // EU query
    let eu_result = match DnsValidator::query_txt_via_json_api_blocking(&eu_query_name, timeout) {
        Ok(txt_records) => {
            if let Some(txt) = txt_records.first() {
                match DnsValidator::parse_txt_record(txt) {
                    Ok(record) => {
                        info!(
                            "Mobile DNS EU: success, rev={}",
                            record.revocation_revision
                        );
                        Ok(record)
                    }
                    Err(e) => {
                        warn!("Mobile DNS EU: parse error: {}", e);
                        Err(e.to_string())
                    }
                }
            } else {
                Err("No TXT records in response".to_string())
            }
        }
        Err(e) => {
            warn!("Mobile DNS EU: query failed: {}", e);
            Err(e.to_string())
        }
    };

    info!(
        us_ok = us_result.is_ok(),
        eu_ok = eu_result.is_ok(),
        "Mobile DNS resolution complete"
    );

    MultiDnsResult {
        us_result,
        eu_result,
    }
}

/// Run all DNS approaches in parallel and return first successful results.
/// Desktop only - mobile uses blocking JSON API.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn query_all_approaches_parallel(
    us_host: &str,
    eu_host: &str,
    timeout: Duration,
) -> MultiDnsResult {
    use futures::future::join_all;

    // Create all validators in parallel
    let (doh_native, doh_bundled) = tokio::join!(
        DnsValidator::with_doh(timeout),
        DnsValidator::with_doh_bundled_certs(timeout),
    );

    let us_query_name = format!("_ciris-verify.{}", us_host);
    let eu_query_name = format!("_ciris-verify.{}", eu_host);

    // Spawn all queries in parallel (6 queries total: 3 approaches × 2 sources)
    let mut us_futures = Vec::new();
    let mut eu_futures = Vec::new();

    // Approach 1: DoH with native-certs (PRIMARY)
    if let Ok(validator) = &doh_native {
        info!("DoH native-certs: validator created successfully");
        let us_host_owned = us_host.to_string();
        let eu_host_owned = eu_host.to_string();
        let validator_clone = validator.clone();
        us_futures.push(tokio::spawn({
            let host = us_host_owned.clone();
            let v = validator_clone.clone();
            async move {
                let result = v.query_steward_record(&host).await;
                ("doh-native", host, result)
            }
        }));
        eu_futures.push(tokio::spawn({
            let host = eu_host_owned.clone();
            let v = validator_clone;
            async move {
                let result = v.query_steward_record(&host).await;
                ("doh-native", host, result)
            }
        }));
    } else {
        warn!("DoH native-certs: failed to create validator");
    }

    // Approach 2: DoH with bundled webpki-roots (FALLBACK)
    if let Ok(validator) = &doh_bundled {
        info!("DoH bundled-certs: validator created successfully");
        let us_host_owned = us_host.to_string();
        let eu_host_owned = eu_host.to_string();
        let validator_clone = validator.clone();
        us_futures.push(tokio::spawn({
            let host = us_host_owned.clone();
            let v = validator_clone.clone();
            async move {
                let result = v.query_steward_record(&host).await;
                ("doh-bundled", host, result)
            }
        }));
        eu_futures.push(tokio::spawn({
            let host = eu_host_owned.clone();
            let v = validator_clone;
            async move {
                let result = v.query_steward_record(&host).await;
                ("doh-bundled", host, result)
            }
        }));
    } else {
        warn!("DoH bundled-certs: failed to create validator");
    }

    // Approach 3: DNS JSON API via HTTPS (reqwest with bundled certs)
    {
        let us_query = us_query_name.clone();
        let eu_query = eu_query_name.clone();
        let us_host_owned = us_host.to_string();
        let eu_host_owned = eu_host.to_string();
        let timeout_clone = timeout;

        us_futures.push(tokio::spawn({
            let query = us_query.clone();
            let host = us_host_owned;
            async move {
                match DnsValidator::query_txt_via_json_api(&query, timeout_clone).await {
                    Ok(txt_records) => {
                        // Parse the first TXT record
                        if let Some(txt) = txt_records.first() {
                            match DnsValidator::parse_txt_record(txt) {
                                Ok(record) => ("json-api", host, Ok(record)),
                                Err(e) => ("json-api", host, Err(e)),
                            }
                        } else {
                            (
                                "json-api",
                                host,
                                Err(VerifyError::DnsError {
                                    message: "No TXT records in JSON API response".to_string(),
                                }),
                            )
                        }
                    },
                    Err(e) => ("json-api", host, Err(e)),
                }
            }
        }));
        eu_futures.push(tokio::spawn({
            let query = eu_query;
            let host = eu_host_owned;
            async move {
                match DnsValidator::query_txt_via_json_api(&query, timeout_clone).await {
                    Ok(txt_records) => {
                        if let Some(txt) = txt_records.first() {
                            match DnsValidator::parse_txt_record(txt) {
                                Ok(record) => ("json-api", host, Ok(record)),
                                Err(e) => ("json-api", host, Err(e)),
                            }
                        } else {
                            (
                                "json-api",
                                host,
                                Err(VerifyError::DnsError {
                                    message: "No TXT records in JSON API response".to_string(),
                                }),
                            )
                        }
                    },
                    Err(e) => ("json-api", host, Err(e)),
                }
            }
        }));
    }

    info!(
        us_queries = us_futures.len(),
        eu_queries = eu_futures.len(),
        "Launched {} parallel DNS queries",
        us_futures.len() + eu_futures.len()
    );

    // Wait for all queries and collect results
    let us_results = join_all(us_futures).await;
    let eu_results = join_all(eu_futures).await;

    // Collect ALL successful results for cross-checking
    let mut us_successes: Vec<(&str, DnsTxtRecord)> = Vec::new();
    let mut us_failures: Vec<(&str, String)> = Vec::new();

    for result in &us_results {
        match result {
            Ok((approach, _host, Ok(record))) => {
                us_successes.push((approach, record.clone()));
            },
            Ok((approach, _host, Err(e))) => {
                us_failures.push((approach, e.to_string()));
            },
            Err(e) => {
                us_failures.push(("task", format!("panic: {}", e)));
            },
        }
    }

    let mut eu_successes: Vec<(&str, DnsTxtRecord)> = Vec::new();
    let mut eu_failures: Vec<(&str, String)> = Vec::new();

    for result in &eu_results {
        match result {
            Ok((approach, _host, Ok(record))) => {
                eu_successes.push((approach, record.clone()));
            },
            Ok((approach, _host, Err(e))) => {
                eu_failures.push((approach, e.to_string()));
            },
            Err(e) => {
                eu_failures.push(("task", format!("panic: {}", e)));
            },
        }
    }

    // Log matrix header for UI parsing
    info!("┌─────────────────────────────────────────────────────────────────┐");
    info!("│ DNS Resolution Matrix (3 approaches × 2 sources = 6 queries)   │");
    info!("├──────────┬─────────────┬────────┬──────────┬──────────────────┤");
    info!("│ Source   │ Approach    │ Status │ Revision │ Details          │");
    info!("├──────────┼─────────────┼────────┼──────────┼──────────────────┤");

    // Log each US result
    for (approach, record) in &us_successes {
        info!(
            "│ US       │ {:11} │ OK     │ {:>8} │ ts={:<13} │",
            approach, record.revocation_revision, record.timestamp
        );
    }
    for (approach, error) in &us_failures {
        let short_err: String = error.chars().take(16).collect();
        info!(
            "│ US       │ {:11} │ FAIL   │        - │ {:<16} │",
            approach, short_err
        );
    }

    // Log each EU result
    for (approach, record) in &eu_successes {
        info!(
            "│ EU       │ {:11} │ OK     │ {:>8} │ ts={:<13} │",
            approach, record.revocation_revision, record.timestamp
        );
    }
    for (approach, error) in &eu_failures {
        let short_err: String = error.chars().take(16).collect();
        info!(
            "│ EU       │ {:11} │ FAIL   │        - │ {:<16} │",
            approach, short_err
        );
    }

    info!("└──────────┴─────────────┴────────┴──────────┴──────────────────┘");

    // Cross-check: verify all successful results agree
    let all_successes: Vec<(&str, &str, &DnsTxtRecord)> = us_successes
        .iter()
        .map(|(a, r)| ("US", *a, r))
        .chain(eu_successes.iter().map(|(a, r)| ("EU", *a, r)))
        .collect();

    if all_successes.len() > 1 {
        // Check for disagreement on revision
        let first_rev = all_successes[0].2.revocation_revision;
        let mut disagreement = false;
        for (source, approach, record) in &all_successes[1..] {
            if record.revocation_revision != first_rev {
                warn!(
                    first_source = all_successes[0].0,
                    first_approach = all_successes[0].1,
                    first_rev = first_rev,
                    this_source = *source,
                    this_approach = *approach,
                    this_rev = record.revocation_revision,
                    "DNS DISAGREEMENT: {}/{} rev={} vs {}/{} rev={}",
                    all_successes[0].0,
                    all_successes[0].1,
                    first_rev,
                    source,
                    approach,
                    record.revocation_revision
                );
                disagreement = true;
            }
        }
        if !disagreement {
            info!(
                success_count = all_successes.len(),
                revision = first_rev,
                "DNS cross-check: {} sources agree on rev={}",
                all_successes.len(),
                first_rev
            );
        }
    }

    // Summary log
    info!(
        us_success = us_successes.len(),
        us_failed = us_failures.len(),
        eu_success = eu_successes.len(),
        eu_failed = eu_failures.len(),
        total_success = all_successes.len(),
        "DNS resolution complete: {}/{} US, {}/{} EU ({} total successes)",
        us_successes.len(),
        us_successes.len() + us_failures.len(),
        eu_successes.len(),
        eu_successes.len() + eu_failures.len(),
        all_successes.len()
    );

    // Return first successful result for each source
    let us_result = us_successes
        .first()
        .map(|(_, r)| Ok(r.clone()))
        .unwrap_or_else(|| Err("No DNS approaches succeeded for US".to_string()));

    let eu_result = eu_successes
        .first()
        .map(|(_, r)| Ok(r.clone()))
        .unwrap_or_else(|| Err("No DNS approaches succeeded for EU".to_string()));

    MultiDnsResult {
        us_result,
        eu_result,
    }
}

/// Query multiple DNS sources with explicit transport mode.
/// Desktop only - mobile uses blocking JSON API via query_multiple_sources.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
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
