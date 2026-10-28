//! iOS-specific synchronous validation using blocking I/O.
//!
//! iOS has the same fundamental networking constraints as Android:
//! 1. `getaddrinfo()` can hang for 30s on iOS (IPv6 AAAA query timeout)
//! 2. hickory-resolver's DoH bootstrap triggers this hang
//! 3. tokio async I/O from FFI threads is unreliable
//!
//! This module mirrors `android_sync.rs`: blocking ureq + rustls with
//! bundled Mozilla CA certificates (webpki-roots). The trust-root check
//! itself is shared (`mobile_trust_root`, CC 5.3.4).
//!
//! BSD sockets work fine on iOS for outbound TCP — no need for
//! Network.framework or NSURLSession. rustls meets all App Transport
//! Security requirements (TLS 1.2+, forward secrecy, SHA-256 certs).

#![cfg(target_os = "ios")]

use std::sync::Arc;
use std::time::Duration;

use ciris_keyring::PlatformAttestation;
use ciris_verify_core::license::LicenseStatus;
use ciris_verify_core::types::{
    DisclosureSeverity, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    ResponseAttestation, ResponseMetadata, ResponseSignature,
};
use tracing::{error, info, warn};

/// Create a TLS-enabled ureq agent with bundled Mozilla CA certificates.
/// Returns None if TLS initialization fails (graceful degradation).
fn create_tls_agent(timeout: Duration) -> Option<ureq::Agent> {
    let result = std::panic::catch_unwind(|| {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(timeout)
            .timeout_write(Duration::from_secs(5))
            .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(Arc::new(tls_config))
            .build()
    });

    match result {
        Ok(agent) => {
            info!("iOS sync: TLS agent created successfully");
            Some(agent)
        },
        Err(e) => {
            error!("iOS sync: TLS initialization panicked: {:?}", e);
            None
        },
    }
}

/// Create a basic ureq agent without custom TLS config (uses defaults).
fn create_basic_agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(timeout)
        .timeout_write(Duration::from_secs(5))
        .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Perform license verification using blocking I/O (no tokio).
///
/// This is the iOS-specific code path that bypasses tokio entirely.
/// Uses rustls with bundled Mozilla CA certificates.
/// Each trust-root host is queried on its own thread.
pub fn get_license_status_blocking(
    _request: &LicenseStatusRequest,
    timeout: Duration,
) -> LicenseStatusResponse {
    info!("iOS sync: Starting blocking license verification (parallel)");
    let start = std::time::Instant::now();

    // Try to create TLS-enabled agent, fall back to basic agent if it fails
    let (_agent, tls_mode) = match create_tls_agent(timeout) {
        Some(agent) => (agent, "webpki-roots"),
        None => {
            warn!("iOS sync: TLS agent creation failed, using default TLS");
            (create_basic_agent(timeout), "default")
        },
    };

    info!("iOS sync: Using TLS mode: {}", tls_mode);

    let now = chrono::Utc::now().timestamp();

    // Trust root (CC 5.3.4): every configured host's GenesisBundle, verified
    // against the baked accord holders, selected by the core's rule.
    let validation = crate::mobile_trust_root::validate_trust_root_blocking(
        timeout,
        |t| create_tls_agent(t).unwrap_or_else(|| create_basic_agent(t)),
        "iOS sync",
    );
    info!(
        "iOS sync: Validation complete in {:?} - status: {:?}",
        start.elapsed(),
        validation.status
    );

    // Build response
    LicenseStatusResponse {
        // Community until the licensure-row gate exists (same as desktop).
        status: LicenseStatus::UnlicensedCommunity,
        license: None,
        mandatory_disclosure: MandatoryDisclosure {
            text: "COMMUNITY MODE: This is an unlicensed community agent.".to_string(),
            severity: DisclosureSeverity::Warning,
            locale: "en".to_string(),
        },
        attestation: ResponseAttestation {
            platform: PlatformAttestation::Ios(ciris_keyring::IosAttestation {
                secure_enclave: true,
                app_attest: None,
                device_check_token: None,
            }),
            signature: ResponseSignature {
                classical: Vec::new(),
                classical_algorithm: "Ed25519".to_string(),
                pqc: Vec::new(),
                pqc_algorithm: "ML-DSA-65".to_string(),
                pqc_public_key: Vec::new(),
                signature_mode: "Available".to_string(),
            },
            integrity_valid: true,
            timestamp: now,
        },
        validation: validation.to_validation_results(now),
        metadata: ResponseMetadata {
            protocol_version: "2.0.0".to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: now,
            cache_ttl: 300,
            request_id: format!("ios-sync-{}", now),
        },
        runtime_validation: None,
        shutdown_directive: None,
        function_integrity: None,
        binary_integrity: None,
        federation_provenance: None,
    }
}
