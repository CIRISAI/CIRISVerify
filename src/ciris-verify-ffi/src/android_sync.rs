//! Android-specific synchronous validation using blocking I/O.
//!
//! Tokio's async I/O doesn't work on Android JNI threads because:
//! 1. The event loop/epoll doesn't poll correctly
//! 2. Worker threads aren't JNI-attached
//!
//! This module provides a completely synchronous code path using ureq
//! with rustls for HTTP requests, bypassing tokio entirely.
//!
//! The trust-root check is shared with iOS (`mobile_trust_root`, CC 5.3.4).
//!
//! TLS uses rustls with bundled Mozilla CA certificates (webpki-roots)
//! since native-certs can't access Android's system cert store.

#![cfg(target_os = "android")]

use std::sync::Arc;
use std::time::Duration;

use ciris_keyring::{PlatformAttestation, SoftwareAttestation};
use ciris_verify_core::license::LicenseStatus;
use ciris_verify_core::types::{
    DisclosureSeverity, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    ResponseAttestation, ResponseMetadata, ResponseSignature,
};
use tracing::{error, info, warn};

/// Create a TLS-enabled ureq agent with bundled Mozilla CA certificates.
/// Returns None if TLS initialization fails (graceful degradation).
fn create_tls_agent(timeout: Duration) -> Option<ureq::Agent> {
    // Wrap in catch_unwind to prevent crashes from propagating
    let result = std::panic::catch_unwind(|| {
        // Build root certificate store from bundled Mozilla certs
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(timeout)
            .timeout_write(Duration::from_secs(5))
            .user_agent(&format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(Arc::new(tls_config))
            .build();

        agent
    });

    match result {
        Ok(agent) => {
            info!("Android sync: TLS agent created successfully");
            Some(agent)
        },
        Err(e) => {
            error!("Android sync: TLS initialization panicked: {:?}", e);
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
/// This is the Android-specific code path that bypasses tokio entirely.
/// Uses rustls with bundled Mozilla CA certificates.
/// Each trust-root host is queried on its own thread.
pub fn get_license_status_blocking(
    _request: &LicenseStatusRequest,
    timeout: Duration,
) -> LicenseStatusResponse {
    info!("Android sync: Starting blocking license verification (parallel)");
    let start = std::time::Instant::now();

    // Try to create TLS-enabled agent, fall back to basic agent if it fails
    let (_agent, tls_mode) = match create_tls_agent(timeout) {
        Some(agent) => (agent, "webpki-roots"),
        None => {
            warn!("Android sync: TLS agent creation failed, using default TLS");
            (create_basic_agent(timeout), "default")
        },
    };

    info!("Android sync: Using TLS mode: {}", tls_mode);

    let now = chrono::Utc::now().timestamp();

    // Trust root (CC 5.3.4): every configured host's GenesisBundle, verified
    // against the baked accord holders, selected by the core's rule.
    let validation = crate::mobile_trust_root::validate_trust_root_blocking(
        timeout,
        |t| create_tls_agent(t).unwrap_or_else(|| create_basic_agent(t)),
        "Android sync",
    );
    info!(
        "Android sync: Validation complete in {:?} - status: {:?}",
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
            platform: PlatformAttestation::Software(SoftwareAttestation {
                key_derivation: "none".to_string(),
                storage: "android-sync".to_string(),
                security_warning: format!("Android sync path - {} + DoH", tls_mode),
            }),
            signature: ResponseSignature {
                classical: Vec::new(),
                classical_algorithm: "none".to_string(),
                pqc: Vec::new(),
                pqc_algorithm: "none".to_string(),
                pqc_public_key: Vec::new(),
                signature_mode: "Unavailable".to_string(),
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
            request_id: format!("android-sync-{}", now),
        },
        runtime_validation: None,
        shutdown_directive: None,
        function_integrity: None,
        binary_integrity: None, // Android sync path - no self-verification
        federation_provenance: None,
    }
}
