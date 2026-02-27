//! CIRISRegistry client for manifest and build verification.
//!
//! Fetches file integrity manifests from the registry to enable
//! Tripwire-style verification of agent binaries.
//!
//! ## Platform-Aware HTTP
//!
//! On Android/iOS, tokio's async I/O is broken (JNI threads, iOS getaddrinfo hangs).
//! This module uses blocking `ureq` on mobile platforms and async `reqwest` on desktop.
//! The async function signatures are preserved for API compatibility.

use std::collections::HashMap;
use std::time::Duration;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use reqwest::Client;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::error::VerifyError;

// Use shared mobile_http module for Android/iOS
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::mobile_http;

/// Build record from CIRISRegistry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    /// Build UUID.
    pub build_id: String,
    /// Semantic version (e.g., "2.0.0").
    pub version: String,
    /// SHA-256 of all source files concatenated.
    pub build_hash: String,
    /// SHA-256 of the manifest JSON itself.
    pub file_manifest_hash: String,
    /// Number of files in manifest.
    pub file_manifest_count: i32,
    /// Full manifest: {"version":"...","files":{"path":"sha256",...}}.
    pub file_manifest_json: FileManifest,
    /// Modules included (e.g., ["core"], ["core","medical"]).
    #[serde(default)]
    pub includes_modules: Vec<String>,
    /// Git repository URL.
    #[serde(default)]
    pub source_repo: Option<String>,
    /// Git commit hash.
    #[serde(default)]
    pub source_commit: Option<String>,
    /// Registration timestamp (Unix).
    #[serde(default)]
    pub registered_at: i64,
    /// Status: active, deprecated, revoked.
    #[serde(default)]
    pub status: String,
}

/// File integrity manifest.
///
/// Supports two formats:
/// 1. Structured: `{"version": "...", "files": {"path": "hash", ...}}`
/// 2. Flat (from registry): `{"path": "hash", ...}`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FileManifest {
    /// Structured format with version and files fields.
    Structured {
        /// Manifest version.
        #[serde(default)]
        version: String,
        /// Map of file path to SHA-256 hash.
        #[serde(default)]
        files: HashMap<String, String>,
    },
    /// Flat format - just the file map directly.
    Flat(HashMap<String, String>),
}

impl FileManifest {
    /// Get the version string (empty if flat format).
    pub fn version(&self) -> &str {
        match self {
            FileManifest::Structured { version, .. } => version,
            FileManifest::Flat(_) => "",
        }
    }

    /// Get the files map.
    pub fn files(&self) -> &HashMap<String, String> {
        match self {
            FileManifest::Structured { files, .. } => files,
            FileManifest::Flat(files) => files,
        }
    }

    /// Get the number of files.
    pub fn len(&self) -> usize {
        self.files().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.files().is_empty()
    }
}

/// Registry client for fetching manifests.
///
/// Uses platform-appropriate HTTP:
/// - Android/iOS: Blocking `ureq` (tokio async I/O is broken on mobile)
/// - Desktop: Async `reqwest`
pub struct RegistryClient {
    /// HTTP client (reqwest on desktop, ureq on mobile).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    client: Client,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    agent: ureq::Agent,
    /// Base URL for the registry API.
    base_url: String,
}

impl RegistryClient {
    /// Create a new registry client.
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL for the registry API (e.g., `https://api.registry.ciris-services-1.ai`)
    /// * `timeout` - Request timeout
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn new(base_url: &str, timeout: Duration) -> Result<Self, VerifyError> {
        // Use aggressive timeouts to fail fast on unreachable hosts
        // This is critical for emulators where TCP connections can hang indefinitely
        let connect_timeout = Duration::from_secs(3);
        let read_timeout = timeout.min(Duration::from_secs(8));

        let client = Client::builder()
            .timeout(read_timeout)                    // Total request timeout
            .connect_timeout(connect_timeout)         // TCP connect timeout
            .read_timeout(read_timeout)               // Read timeout
            .pool_idle_timeout(Duration::from_secs(5)) // Don't keep idle connections
            .pool_max_idle_per_host(1)                // Minimal connection pooling
            .tcp_nodelay(true)                        // Disable Nagle for faster failure detection
            .user_agent(format!("CIRISVerify/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to create registry client: {}", e),
            })?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Create a new registry client (mobile - blocking ureq).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn new(base_url: &str, timeout: Duration) -> Result<Self, VerifyError> {
        info!("RegistryClient: using mobile blocking HTTP (ureq)");
        let agent = mobile_http::create_tls_agent(timeout)?;
        Ok(Self {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    // =========================================================================
    // Desktop implementations (async reqwest)
    // =========================================================================

    /// Fetch a build record by version.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self), fields(version = %version))]
    pub async fn get_build_by_version(&self, version: &str) -> Result<BuildRecord, VerifyError> {
        let url = format!("{}/v1/builds/{}", self.base_url, version);
        debug!("Fetching build from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Registry request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("Registry HTTP error: {}", response.status()),
            });
        }

        let build = response
            .json::<BuildRecord>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse build record: {}", e),
            })?;

        info!(
            build_id = %build.build_id,
            file_count = build.file_manifest_count,
            "Fetched build manifest from registry"
        );

        Ok(build)
    }

    /// Fetch a build record by build hash.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self), fields(build_hash = %build_hash))]
    pub async fn get_build_by_hash(&self, build_hash: &str) -> Result<BuildRecord, VerifyError> {
        let url = format!("{}/v1/builds/hash/{}", self.base_url, build_hash);
        debug!("Fetching build by hash from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Registry request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("Registry HTTP error: {}", response.status()),
            });
        }

        response
            .json::<BuildRecord>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse build record: {}", e),
            })
    }

    /// Check if the registry is reachable.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub async fn health_check(&self) -> Result<bool, VerifyError> {
        let url = format!("{}/health", self.base_url);

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(e) => {
                warn!("Registry health check failed: {}", e);
                Ok(false)
            },
        }
    }

    // =========================================================================
    // Mobile implementations (blocking ureq)
    // =========================================================================

    /// Fetch a build record by version (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self), fields(version = %version))]
    pub async fn get_build_by_version(&self, version: &str) -> Result<BuildRecord, VerifyError> {
        let url = format!("{}/v1/builds/{}", self.base_url, version);
        debug!("Fetching build from {} (mobile blocking)", url);

        let build: BuildRecord = mobile_http::get_json(&self.agent, &url)?;

        info!(
            build_id = %build.build_id,
            file_count = build.file_manifest_count,
            "Fetched build manifest from registry (mobile)"
        );

        Ok(build)
    }

    /// Fetch a build record by build hash (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self), fields(build_hash = %build_hash))]
    pub async fn get_build_by_hash(&self, build_hash: &str) -> Result<BuildRecord, VerifyError> {
        let url = format!("{}/v1/builds/hash/{}", self.base_url, build_hash);
        debug!("Fetching build by hash from {} (mobile blocking)", url);
        mobile_http::get_json(&self.agent, &url)
    }

    /// Check if the registry is reachable (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub async fn health_check(&self) -> Result<bool, VerifyError> {
        let url = format!("{}/health", self.base_url);
        mobile_http::check_status(&self.agent, &url)
    }
}

/// Binary manifest from CIRISRegistry.
///
/// Contains SHA-256 hashes of CIRISVerify binaries for each platform.
/// Used for Level 2 binary self-verification ("who watches the watchmen").
///
/// ## Recursive Trust Dependency
///
/// Binary self-verification is inherently recursive:
/// - To verify the binary, we fetch the manifest from the registry
/// - To trust the manifest, we need Level 3 multi-source validation
/// - But Level 3 validation is performed BY this binary
///
/// This circular dependency is resolved by the initial provisioning:
/// - The FIRST installation must come from a trusted source (app stores, PyPI)
/// - Once installed, the binary can verify future updates against the registry
/// - Level 3 cross-validation (2/3 geo-distributed sources) prevents registry MITM
///
/// ## Trust Boundaries
///
/// Self-verification does NOT protect against:
/// - A fully compromised registry (attacker updates both binary and manifest)
/// - Compromised initial provisioning (malicious app store listing)
///
/// Mitigations:
/// - Level 3 multi-source consensus (US DNS + EU DNS + HTTPS must agree)
/// - Initial install via trusted channels (Google Play, App Store, PyPI)
/// - Manifest signing key pinning (future enhancement)
///
/// ## Registry Route Required
///
/// The registry needs to implement:
/// ```text
/// GET /v1/verify/binary-manifest/{version}
/// ```
///
/// Response:
/// ```json
/// {
///   "version": "0.5.2",
///   "binaries": {
///     "x86_64-unknown-linux-gnu": "sha256:abc123...",
///     "aarch64-apple-darwin": "sha256:def456...",
///     "x86_64-pc-windows-msvc": "sha256:ghi789..."
///   },
///   "generated_at": "2026-02-20T00:00:00Z"
/// }
/// ```
///
/// ## GitHub Release Integration
///
/// The release workflow computes hashes for each binary:
/// 1. Build binaries for all targets
/// 2. Compute SHA-256 for each binary
/// 3. Upload CHECKSUMS.txt as release asset
/// 4. POST hashes to registry API (or registry fetches from GitHub)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryManifest {
    /// CIRISVerify version.
    pub version: String,
    /// Map of target triple → SHA-256 hash.
    /// Keys: x86_64-unknown-linux-gnu, aarch64-apple-darwin, etc.
    pub binaries: HashMap<String, String>,
    /// ISO 8601 timestamp when manifest was generated.
    #[serde(default)]
    pub generated_at: String,
}

impl RegistryClient {
    // =========================================================================
    // Binary & Function Manifests - Desktop (async reqwest)
    // =========================================================================

    /// Fetch the binary manifest for self-verification.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self), fields(version = %version))]
    pub async fn get_binary_manifest(&self, version: &str) -> Result<BinaryManifest, VerifyError> {
        let url = format!("{}/v1/verify/binary-manifest/{}", self.base_url, version);
        info!("Fetching binary manifest from URL: {}", url);

        let response = self.client.get(&url).send().await.map_err(|e| {
            warn!("Binary manifest request FAILED: url={}, error={}", url, e);
            VerifyError::HttpsError {
                message: format!("Binary manifest request failed (url={}): {}", url, e),
            }
        })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!(
                    "Binary manifest HTTP error: {} (route may not be implemented)",
                    response.status()
                ),
            });
        }

        let manifest =
            response
                .json::<BinaryManifest>()
                .await
                .map_err(|e| VerifyError::HttpsError {
                    message: format!("Failed to parse binary manifest: {}", e),
                })?;

        info!(
            version = %manifest.version,
            binary_count = manifest.binaries.len(),
            "Fetched binary manifest from registry"
        );

        Ok(manifest)
    }

    /// Fetch the function-level integrity manifest for a specific target.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self), fields(version = %version, target = %target))]
    pub async fn get_function_manifest(
        &self,
        version: &str,
        target: &str,
    ) -> Result<crate::security::function_integrity::FunctionManifest, VerifyError> {
        let url = format!(
            "{}/v1/verify/function-manifest/{}/{}",
            self.base_url, version, target
        );
        debug!("Fetching function manifest from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Function manifest request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!(
                    "Function manifest HTTP error: {} (version={}, target={})",
                    response.status(),
                    version,
                    target
                ),
            });
        }

        let manifest = response
            .json::<crate::security::function_integrity::FunctionManifest>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse function manifest: {}", e),
            })?;

        info!(
            version = %manifest.binary_version,
            target = %manifest.target,
            function_count = manifest.functions.len(),
            "Fetched function manifest from registry"
        );

        Ok(manifest)
    }

    /// List available target triples for function manifests.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self), fields(version = %version))]
    pub async fn list_function_manifest_targets(
        &self,
        version: &str,
    ) -> Result<FunctionManifestTargets, VerifyError> {
        let url = format!("{}/v1/verify/function-manifests/{}", self.base_url, version);
        debug!("Listing function manifest targets from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Function manifest targets request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!(
                    "Function manifest targets HTTP error: {} (version={})",
                    response.status(),
                    version
                ),
            });
        }

        let targets = response
            .json::<FunctionManifestTargets>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse function manifest targets: {}", e),
            })?;

        info!(
            version = %targets.version,
            target_count = targets.targets.len(),
            "Listed function manifest targets from registry"
        );

        Ok(targets)
    }

    // =========================================================================
    // Binary & Function Manifests - Mobile (blocking ureq)
    // =========================================================================

    /// Fetch the binary manifest for self-verification (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self), fields(version = %version))]
    pub async fn get_binary_manifest(&self, version: &str) -> Result<BinaryManifest, VerifyError> {
        let url = format!("{}/v1/verify/binary-manifest/{}", self.base_url, version);
        info!("Fetching binary manifest from URL: {} (mobile)", url);
        mobile_http::get_json(&self.agent, &url)
    }

    /// Fetch the function-level integrity manifest (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self), fields(version = %version, target = %target))]
    pub async fn get_function_manifest(
        &self,
        version: &str,
        target: &str,
    ) -> Result<crate::security::function_integrity::FunctionManifest, VerifyError> {
        let url = format!(
            "{}/v1/verify/function-manifest/{}/{}",
            self.base_url, version, target
        );
        debug!("Fetching function manifest from {} (mobile)", url);
        mobile_http::get_json(&self.agent, &url)
    }

    /// List available target triples for function manifests (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self), fields(version = %version))]
    pub async fn list_function_manifest_targets(
        &self,
        version: &str,
    ) -> Result<FunctionManifestTargets, VerifyError> {
        let url = format!("{}/v1/verify/function-manifests/{}", self.base_url, version);
        debug!("Listing function manifest targets from {} (mobile)", url);
        mobile_http::get_json(&self.agent, &url)
    }

    // =========================================================================
    // Play Integrity (Google Android HW Attestation) - Desktop
    // =========================================================================

    /// Get a nonce for Play Integrity verification.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self))]
    pub async fn get_integrity_nonce(
        &self,
    ) -> Result<crate::play_integrity::IntegrityNonce, VerifyError> {
        let url = format!("{}/v1/integrity/nonce", self.base_url);
        debug!("Fetching Play Integrity nonce from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Play Integrity nonce request failed: {}", e),
            })?;

        if response.status().as_u16() == 409 {
            return Err(VerifyError::HttpsError {
                message: "Play Integrity nonce conflict: a nonce was already issued for this session. Wait for it to expire or use the existing one.".to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("Play Integrity nonce HTTP error: {}", response.status()),
            });
        }

        response
            .json::<crate::play_integrity::IntegrityNonce>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse integrity nonce: {}", e),
            })
    }

    /// Verify a Play Integrity token from Android.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self, integrity_token))]
    pub async fn verify_integrity_token(
        &self,
        integrity_token: &str,
        nonce: &str,
    ) -> Result<crate::play_integrity::IntegrityVerifyResponse, VerifyError> {
        let url = format!("{}/v1/integrity/verify", self.base_url);
        debug!("Verifying Play Integrity token at {}", url);

        let request = crate::play_integrity::IntegrityVerifyRequest {
            integrity_token: integrity_token.to_string(),
            nonce: nonce.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Play Integrity verify request failed: {}", e),
            })?;

        if response.status().as_u16() == 503 {
            return Err(VerifyError::HttpsError {
                message: "Play Integrity not configured on registry".to_string(),
            });
        }

        if response.status().as_u16() == 409 {
            return Err(VerifyError::HttpsError {
                message: "Play Integrity nonce already consumed or expired. Request a new nonce."
                    .to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("Play Integrity verify HTTP error: {}", response.status()),
            });
        }

        let result = response
            .json::<crate::play_integrity::IntegrityVerifyResponse>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse integrity response: {}", e),
            })?;

        info!(
            verified = result.verified,
            summary = %result.summary(),
            "Play Integrity verification complete"
        );

        Ok(result)
    }

    // =========================================================================
    // Play Integrity - Mobile (blocking ureq)
    // =========================================================================

    /// Get a nonce for Play Integrity verification (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self))]
    pub async fn get_integrity_nonce(
        &self,
    ) -> Result<crate::play_integrity::IntegrityNonce, VerifyError> {
        let url = format!("{}/v1/integrity/nonce", self.base_url);
        debug!("Fetching Play Integrity nonce from {} (mobile)", url);
        mobile_http::get_json(&self.agent, &url)
    }

    /// Verify a Play Integrity token (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self, integrity_token))]
    pub async fn verify_integrity_token(
        &self,
        integrity_token: &str,
        nonce: &str,
    ) -> Result<crate::play_integrity::IntegrityVerifyResponse, VerifyError> {
        let url = format!("{}/v1/integrity/verify", self.base_url);
        debug!("Verifying Play Integrity token at {} (mobile)", url);

        let request = crate::play_integrity::IntegrityVerifyRequest {
            integrity_token: integrity_token.to_string(),
            nonce: nonce.to_string(),
        };

        let (_, result): (u16, crate::play_integrity::IntegrityVerifyResponse) =
            mobile_http::post_json(&self.agent, &url, &request)?;

        info!(
            verified = result.verified,
            summary = %result.summary(),
            "Play Integrity verification complete (mobile)"
        );

        Ok(result)
    }

    // =========================================================================
    // App Attest (Apple iOS HW Attestation) - Desktop
    // =========================================================================

    /// Get a nonce for App Attest verification.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self))]
    pub async fn get_app_attest_nonce(
        &self,
    ) -> Result<crate::app_attest::AppAttestNonce, VerifyError> {
        let url = format!("{}/v1/integrity/ios/nonce", self.base_url);
        debug!("Fetching App Attest nonce from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("App Attest nonce request failed: {}", e),
            })?;

        if response.status().as_u16() == 409 {
            return Err(VerifyError::HttpsError {
                message: "App Attest nonce conflict: a nonce was already issued for this session. Wait for it to expire or use the existing one.".to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("App Attest nonce HTTP error: {}", response.status()),
            });
        }

        response
            .json::<crate::app_attest::AppAttestNonce>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse App Attest nonce: {}", e),
            })
    }

    /// Verify an App Attest attestation object from iOS.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self, attestation))]
    pub async fn verify_app_attest(
        &self,
        attestation: &str,
        key_id: &str,
        nonce: &str,
    ) -> Result<crate::app_attest::AppAttestVerifyResponse, VerifyError> {
        let url = format!("{}/v1/integrity/ios/verify", self.base_url);
        debug!("Verifying App Attest attestation at {}", url);

        let request = crate::app_attest::AppAttestVerifyRequest {
            attestation: attestation.to_string(),
            key_id: key_id.to_string(),
            nonce: nonce.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("App Attest verify request failed: {}", e),
            })?;

        if response.status().as_u16() == 503 {
            return Err(VerifyError::HttpsError {
                message: "App Attest not configured on registry".to_string(),
            });
        }

        if response.status().as_u16() == 409 {
            return Err(VerifyError::HttpsError {
                message: "App Attest nonce already consumed or expired. Request a new nonce."
                    .to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("App Attest verify HTTP error: {}", response.status()),
            });
        }

        let result = response
            .json::<crate::app_attest::AppAttestVerifyResponse>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse App Attest response: {}", e),
            })?;

        info!(
            verified = result.verified,
            summary = %result.summary(),
            "App Attest verification complete"
        );

        Ok(result)
    }

    /// Verify an App Attest assertion (post-attestation ongoing verification).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self, assertion, client_data))]
    pub async fn verify_app_attest_assertion(
        &self,
        assertion: &str,
        key_id: &str,
        client_data: &str,
        nonce: &str,
    ) -> Result<crate::app_attest::AppAttestAssertionResponse, VerifyError> {
        let url = format!("{}/v1/integrity/ios/assert", self.base_url);
        debug!("Verifying App Attest assertion at {}", url);

        let request = crate::app_attest::AppAttestAssertionRequest {
            assertion: assertion.to_string(),
            key_id: key_id.to_string(),
            client_data: client_data.to_string(),
            nonce: nonce.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("App Attest assertion request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("App Attest assertion HTTP error: {}", response.status()),
            });
        }

        response
            .json::<crate::app_attest::AppAttestAssertionResponse>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse App Attest assertion response: {}", e),
            })
    }

    // =========================================================================
    // App Attest - Mobile (blocking ureq)
    // =========================================================================

    /// Get a nonce for App Attest verification (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self))]
    pub async fn get_app_attest_nonce(
        &self,
    ) -> Result<crate::app_attest::AppAttestNonce, VerifyError> {
        let url = format!("{}/v1/integrity/ios/nonce", self.base_url);
        debug!("Fetching App Attest nonce from {} (mobile)", url);
        mobile_http::get_json(&self.agent, &url)
    }

    /// Verify an App Attest attestation object (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self, attestation))]
    pub async fn verify_app_attest(
        &self,
        attestation: &str,
        key_id: &str,
        nonce: &str,
    ) -> Result<crate::app_attest::AppAttestVerifyResponse, VerifyError> {
        let url = format!("{}/v1/integrity/ios/verify", self.base_url);
        debug!("Verifying App Attest attestation at {} (mobile)", url);

        let request = crate::app_attest::AppAttestVerifyRequest {
            attestation: attestation.to_string(),
            key_id: key_id.to_string(),
            nonce: nonce.to_string(),
        };

        let (_, result): (u16, crate::app_attest::AppAttestVerifyResponse) =
            mobile_http::post_json(&self.agent, &url, &request)?;

        info!(
            verified = result.verified,
            summary = %result.summary(),
            "App Attest verification complete (mobile)"
        );

        Ok(result)
    }

    /// Verify an App Attest assertion (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self, assertion, client_data))]
    pub async fn verify_app_attest_assertion(
        &self,
        assertion: &str,
        key_id: &str,
        client_data: &str,
        nonce: &str,
    ) -> Result<crate::app_attest::AppAttestAssertionResponse, VerifyError> {
        let url = format!("{}/v1/integrity/ios/assert", self.base_url);
        debug!("Verifying App Attest assertion at {} (mobile)", url);

        let request = crate::app_attest::AppAttestAssertionRequest {
            assertion: assertion.to_string(),
            key_id: key_id.to_string(),
            client_data: client_data.to_string(),
            nonce: nonce.to_string(),
        };

        let (_, result): (u16, crate::app_attest::AppAttestAssertionResponse) =
            mobile_http::post_json(&self.agent, &url, &request)?;

        Ok(result)
    }

    // =========================================================================
    // Key Verification - Desktop
    // =========================================================================

    /// Verify an agent signing key by its Ed25519 fingerprint.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[instrument(skip(self), fields(fingerprint = %fingerprint))]
    pub async fn verify_key_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<KeyVerificationResponse, VerifyError> {
        let url = format!("{}/v1/verify/key/{}", self.base_url, fingerprint);
        debug!("Verifying key by fingerprint at {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Key verification request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(VerifyError::HttpsError {
                message: format!("Key verification HTTP error: {}", response.status()),
            });
        }

        let result = response
            .json::<KeyVerificationResponse>()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Failed to parse key verification response: {}", e),
            })?;

        info!(
            found = result.found,
            status = ?result.status,
            key_id = ?result.key_id,
            "Key verification complete"
        );

        Ok(result)
    }

    // =========================================================================
    // Key Verification - Mobile (blocking ureq)
    // =========================================================================

    /// Verify an agent signing key by its Ed25519 fingerprint (mobile - blocking).
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[instrument(skip(self), fields(fingerprint = %fingerprint))]
    pub async fn verify_key_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<KeyVerificationResponse, VerifyError> {
        let url = format!("{}/v1/verify/key/{}", self.base_url, fingerprint);
        debug!("Verifying key by fingerprint at {} (mobile)", url);

        let result: KeyVerificationResponse = mobile_http::get_json(&self.agent, &url)?;

        info!(
            found = result.found,
            status = ?result.status,
            key_id = ?result.key_id,
            "Key verification complete (mobile)"
        );

        Ok(result)
    }
}

/// Response from key verification endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVerificationResponse {
    /// Whether the key was found in the registry.
    pub found: bool,
    /// Key ID (UUID) if found.
    pub key_id: Option<String>,
    /// Organization ID that owns this key.
    pub org_id: Option<String>,
    /// Key status as string (KEY_ACTIVE, KEY_ROTATED, KEY_REVOKED, KEY_PENDING, NOT_FOUND).
    pub status: String,
    /// Key status as numeric code.
    pub status_code: i32,
    /// Ed25519 fingerprint.
    #[serde(default)]
    pub ed25519_fingerprint: Option<String>,
    /// ML-DSA-65 fingerprint.
    #[serde(default)]
    pub ml_dsa_65_fingerprint: Option<String>,
    /// Ed25519 public key (base64).
    #[serde(default)]
    pub ed25519_public_key: Option<String>,
    /// ML-DSA-65 public key (base64).
    #[serde(default)]
    pub ml_dsa_65_public_key: Option<String>,
    /// Activation timestamp (Unix).
    #[serde(default)]
    pub activated_at: Option<i64>,
    /// Revocation timestamp (Unix).
    #[serde(default)]
    pub revoked_at: Option<i64>,
    /// Revocation reason.
    #[serde(default)]
    pub revocation_reason: Option<String>,
}

impl KeyVerificationResponse {
    /// Check if the key is valid for signing (found and active).
    pub fn is_valid_for_signing(&self) -> bool {
        self.found && (self.status == "KEY_ACTIVE" || self.status_code == 1)
    }

    /// Check if the key is still valid during grace period (rotated).
    pub fn is_valid_rotated(&self) -> bool {
        self.found && (self.status == "KEY_ROTATED" || self.status_code == 2)
    }

    /// Check if the key has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.found && (self.status == "KEY_REVOKED" || self.status_code == 3)
    }
}

/// Compute Ed25519 fingerprint (SHA-256 hex) from a public key.
pub fn compute_ed25519_fingerprint(public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(public_key);
    hex::encode(hash)
}

/// Response from listing function manifest targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionManifestTargets {
    /// Version queried.
    pub version: String,
    /// Available target triples.
    pub targets: Vec<String>,
}

/// Compute SHA-256 hash of the currently running binary.
///
/// Used for Level 4 self-verification: proves CIRISVerify hasn't been tampered with.
///
/// # Returns
///
/// Lowercase hex-encoded SHA-256 hash, or error if binary cannot be read.
///
/// # Platform Notes
///
/// - Android: Discovers `libciris_verify_ffi.so` via `/proc/self/maps`
/// - Linux: Reads from `/proc/self/exe`
/// - macOS/Windows: Uses `std::env::current_exe()`
pub fn compute_self_hash() -> Result<String, VerifyError> {
    use sha2::{Digest, Sha256};

    // On Android, current_exe() returns /system/bin/app_process64 which is the
    // Android runtime, not our library. We need to find libciris_verify_ffi.so.
    #[cfg(target_os = "android")]
    let exe_path = {
        match find_library_path("libciris_verify_ffi.so") {
            Some(path) => {
                tracing::info!("compute_self_hash (Android): found .so at {:?}", path);
                path
            },
            None => {
                tracing::warn!(
                    "compute_self_hash (Android): could not find libciris_verify_ffi.so, falling back to current_exe()"
                );
                std::env::current_exe().map_err(|e| VerifyError::IntegrityError {
                    message: format!("Cannot determine executable path: {}", e),
                })?
            },
        }
    };

    // On iOS, current_exe() returns the app binary, not our dylib.
    // Use dyld image iteration to find CIRISVerify.framework/CIRISVerify.
    #[cfg(target_os = "ios")]
    let exe_path = {
        match find_library_path_dyld() {
            Some(path) => {
                tracing::info!("compute_self_hash (iOS): found dylib at {:?}", path);
                path
            },
            None => {
                tracing::warn!(
                    "compute_self_hash (iOS): dylib not found in dyld images, falling back to current_exe()"
                );
                std::env::current_exe().map_err(|e| VerifyError::IntegrityError {
                    message: format!("Cannot determine executable path: {}", e),
                })?
            },
        }
    };

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let exe_path = std::env::current_exe().map_err(|e| VerifyError::IntegrityError {
        message: format!("Cannot determine executable path: {}", e),
    })?;

    tracing::info!(
        "compute_self_hash: exe_path={:?}, exists={}",
        exe_path,
        exe_path.exists()
    );

    let file_bytes = std::fs::read(&exe_path).map_err(|e| VerifyError::IntegrityError {
        message: format!("Cannot read executable for hashing: {}", e),
    })?;

    // On iOS/macOS, hash only the code portion of __TEXT (after header + load commands).
    // Code signing modifies load command fields (e.g. LC_CODE_SIGNATURE offset at 0x709)
    // but never touches actual code sections (__text, __stubs, __stub_helper).
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    let hash_bytes = {
        match extract_text_code_region(&file_bytes) {
            Some((offset, size)) => {
                tracing::info!(
                    "compute_self_hash: hashing __TEXT code region (offset=0x{:x}, size=0x{:x}, file_size=0x{:x})",
                    offset, size, file_bytes.len()
                );
                &file_bytes[offset..offset + size]
            },
            None => {
                tracing::warn!(
                    "compute_self_hash: could not extract __TEXT code region, hashing full file (size=0x{:x})",
                    file_bytes.len()
                );
                &file_bytes[..]
            },
        }
    };

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    let hash_bytes = &file_bytes[..];

    let mut hasher = Sha256::new();
    hasher.update(hash_bytes);
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Extract the hashable code region from a Mach-O __TEXT segment.
///
/// Returns `(file_offset, size)` of the code-only portion of __TEXT,
/// skipping the Mach-O header and load commands. Code signing modifies
/// fields in the load commands (e.g. LC_CODE_SIGNATURE) but never
/// touches the actual code sections (__text, __stubs, __stub_helper).
/// By starting after header + sizeofcmds we get a hash stable across signing.
#[cfg(any(target_os = "ios", target_os = "macos"))]
fn extract_text_code_region(data: &[u8]) -> Option<(usize, usize)> {
    use goblin::mach::Mach;

    match Mach::parse(data) {
        Ok(Mach::Binary(macho)) => extract_text_code_from_macho(&macho),
        Ok(Mach::Fat(fat)) => {
            tracing::info!(
                "extract_text_code_region: fat binary with {} arches",
                fat.narches
            );
            if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(0) {
                extract_text_code_from_macho(&macho)
            } else {
                tracing::warn!("extract_text_code_region: fat arch[0] is not MachO");
                None
            }
        },
        Err(e) => {
            tracing::warn!("extract_text_code_region: Mach-O parse error: {}", e);
            None
        },
    }
}

/// Helper: extract code region from a parsed MachO.
#[cfg(any(target_os = "ios", target_os = "macos"))]
fn extract_text_code_from_macho(macho: &goblin::mach::MachO) -> Option<(usize, usize)> {
    // Header + load commands = mutable area modified by code signing.
    // Code signing adds LC_CODE_SIGNATURE (16 bytes), changing sizeofcmds.
    // Page-align to 4096 so the hash start is identical regardless of
    // whether LC_CODE_SIGNATURE is present (padding is always zeros).
    let header_size: usize = if macho.is_64 { 32 } else { 28 };
    let cmds_end = header_size + macho.header.sizeofcmds as usize;
    let page_aligned = (cmds_end + 0xFFF) & !0xFFF; // round up to 4096

    for seg in &macho.segments {
        let name = seg.name().unwrap_or("");
        if name == "__TEXT" {
            let seg_start = seg.fileoff as usize;
            let seg_end = seg_start + seg.filesize as usize;
            // Hash from page-aligned boundary to end of __TEXT segment
            let hash_start = page_aligned.max(seg_start);
            let hash_size = seg_end.saturating_sub(hash_start);
            tracing::info!(
                "extract_text_code_region: __TEXT=0x{:x}..0x{:x}, cmds_end=0x{:x}, page_aligned=0x{:x}, hashing 0x{:x}..0x{:x} ({} bytes)",
                seg_start, seg_end, cmds_end, page_aligned, hash_start, hash_start + hash_size, hash_size
            );
            return Some((hash_start, hash_size));
        }
    }
    tracing::warn!("extract_text_code_region: no __TEXT segment found");
    None
}

/// Find a loaded library's path by parsing /proc/self/maps.
///
/// On Android, shared libraries are loaded into the process address space
/// and their paths are listed in /proc/self/maps. This function finds the
/// first mapping for a library with the given name.
#[cfg(target_os = "android")]
fn find_library_path(lib_name: &str) -> Option<std::path::PathBuf> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let maps_file = match File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("find_library_path: cannot open /proc/self/maps: {}", e);
            return None;
        },
    };

    let reader = BufReader::new(maps_file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // /proc/self/maps format:
        // address          perms offset  dev   inode   pathname
        // 7f1234567000-... r-xp  00000000 fd:01 1234567 /path/to/lib.so
        if line.contains(lib_name) {
            // Find the path - it's the last whitespace-separated field
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let full_path = parts[5..].join(" ");
                if full_path.contains(lib_name) {
                    tracing::info!("find_library_path: found {} at {}", lib_name, full_path);
                    return Some(std::path::PathBuf::from(full_path));
                }
            }
        }
    }

    tracing::warn!(
        "find_library_path: {} not found in /proc/self/maps",
        lib_name
    );
    None
}

/// Find the path to our loaded library using dyld image iteration.
///
/// Iterates all loaded dyld images to find one whose name contains
/// `libciris_verify_ffi` or `CIRISVerify`. This matches the same approach
/// used by `get_code_base_macos()` in function_integrity.rs.
#[cfg(target_os = "ios")]
fn find_library_path_dyld() -> Option<std::path::PathBuf> {
    extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(image_index: u32) -> *const std::ffi::c_char;
    }

    const LIB_NAME: &str = "libciris_verify_ffi";
    const FRAMEWORK_NAME: &str = "CIRISVerify";

    unsafe {
        let count = _dyld_image_count();
        tracing::info!("find_library_path_dyld: searching {} loaded images", count);

        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(name_ptr);
            let name_str = name.to_string_lossy();

            if i < 5 || name_str.contains(LIB_NAME) || name_str.contains(FRAMEWORK_NAME) {
                tracing::info!("find_library_path_dyld: image[{}] = {}", i, name_str);
            }

            if name_str.contains(LIB_NAME) || name_str.contains(FRAMEWORK_NAME) {
                let path = std::path::PathBuf::from(name_str.into_owned());
                tracing::info!("find_library_path_dyld: FOUND at image[{}]: {:?}", i, path);
                return Some(path);
            }
        }

        tracing::warn!(
            "find_library_path_dyld: {} / {} not found in {} images",
            LIB_NAME,
            FRAMEWORK_NAME,
            count
        );
        None
    }
}

/// Get the current target platform name at compile time.
///
/// Returns the Rust target triple directly - the registry uses these
/// as keys (e.g., `aarch64-linux-android`, `x86_64-unknown-linux-gnu`).
pub fn current_target() -> &'static str {
    env!("TARGET")
}

/// Verify the running binary against a registry manifest.
///
/// # Arguments
///
/// * `manifest` - Binary manifest from registry
///
/// # Returns
///
/// `true` if the running binary's hash matches the manifest entry
/// for the current target triple.
pub fn verify_self_against_manifest(manifest: &BinaryManifest) -> Result<bool, VerifyError> {
    let target = current_target();
    let actual_hash = compute_self_hash()?;

    match manifest.binaries.get(target) {
        Some(expected_hash) => {
            // Strip "sha256:" prefix if present
            let expected = expected_hash
                .strip_prefix("sha256:")
                .unwrap_or(expected_hash);

            // Constant-time comparison
            use subtle::ConstantTimeEq;
            let actual_bytes = hex::decode(&actual_hash).unwrap_or_default();
            let expected_bytes = hex::decode(expected).unwrap_or_default();

            Ok(actual_bytes.ct_eq(&expected_bytes).into())
        },
        None => Err(VerifyError::IntegrityError {
            message: format!("No binary hash for target '{}' in manifest", target),
        }),
    }
}

/// Default registry URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://api.registry.ciris-services-1.ai";

/// Fallback registry URLs for resilience.
/// These are independent domains to survive single-domain outages or MITM attacks.
pub const FALLBACK_REGISTRY_URLS: &[&str] = &[
    "https://registry-us.ciris-services-1.ai",
    "https://registry-eu.ciris-services-1.ai",
];

/// Multi-endpoint registry client with automatic failover.
///
/// Tries the primary endpoint first, then falls back to secondary endpoints
/// on network errors (similar to DoH fallback pattern).
pub struct ResilientRegistryClient {
    /// Primary registry client.
    primary: RegistryClient,
    /// Fallback registry clients.
    fallbacks: Vec<RegistryClient>,
}

impl ResilientRegistryClient {
    /// Create a new resilient client with primary and fallback endpoints.
    pub fn new(
        primary_url: &str,
        fallback_urls: &[&str],
        timeout: Duration,
    ) -> Result<Self, VerifyError> {
        let primary = RegistryClient::new(primary_url, timeout)?;
        let fallbacks = fallback_urls
            .iter()
            .filter_map(|url| RegistryClient::new(url, timeout).ok())
            .collect();

        Ok(Self { primary, fallbacks })
    }

    /// Create with default endpoints.
    pub fn with_defaults(timeout: Duration) -> Result<Self, VerifyError> {
        Self::new(DEFAULT_REGISTRY_URL, FALLBACK_REGISTRY_URLS, timeout)
    }

    /// Get the underlying primary client (for compatibility).
    pub fn primary(&self) -> &RegistryClient {
        &self.primary
    }

    /// Fetch a build record by version with failover.
    pub async fn get_build_by_version(&self, version: &str) -> Result<BuildRecord, VerifyError> {
        // Try primary first
        match self.primary.get_build_by_version(version).await {
            Ok(build) => return Ok(build),
            Err(e) => {
                warn!("Primary registry failed for build/{}: {}", version, e);
            },
        }

        // Try fallbacks
        for (i, fallback) in self.fallbacks.iter().enumerate() {
            match fallback.get_build_by_version(version).await {
                Ok(build) => {
                    info!("Fallback[{}] succeeded for build/{}", i, version);
                    return Ok(build);
                },
                Err(e) => {
                    warn!("Fallback[{}] failed for build/{}: {}", i, version, e);
                },
            }
        }

        Err(VerifyError::HttpsError {
            message: format!("All registry endpoints failed for build/{}", version),
        })
    }

    /// Fetch binary manifest with failover.
    pub async fn get_binary_manifest(&self, version: &str) -> Result<BinaryManifest, VerifyError> {
        match self.primary.get_binary_manifest(version).await {
            Ok(m) => return Ok(m),
            Err(e) => warn!(
                "Primary registry failed for binary-manifest/{}: {}",
                version, e
            ),
        }

        for (i, fallback) in self.fallbacks.iter().enumerate() {
            match fallback.get_binary_manifest(version).await {
                Ok(m) => {
                    info!("Fallback[{}] succeeded for binary-manifest/{}", i, version);
                    return Ok(m);
                },
                Err(e) => warn!(
                    "Fallback[{}] failed for binary-manifest/{}: {}",
                    i, version, e
                ),
            }
        }

        Err(VerifyError::HttpsError {
            message: format!(
                "All registry endpoints failed for binary-manifest/{}",
                version
            ),
        })
    }

    /// Fetch function manifest with failover.
    pub async fn get_function_manifest(
        &self,
        version: &str,
        target: &str,
    ) -> Result<crate::security::function_integrity::FunctionManifest, VerifyError> {
        match self.primary.get_function_manifest(version, target).await {
            Ok(m) => return Ok(m),
            Err(e) => warn!(
                "Primary registry failed for function-manifest/{}/{}: {}",
                version, target, e
            ),
        }

        for (i, fallback) in self.fallbacks.iter().enumerate() {
            match fallback.get_function_manifest(version, target).await {
                Ok(m) => {
                    info!(
                        "Fallback[{}] succeeded for function-manifest/{}/{}",
                        i, version, target
                    );
                    return Ok(m);
                },
                Err(e) => warn!(
                    "Fallback[{}] failed for function-manifest/{}/{}: {}",
                    i, version, target, e
                ),
            }
        }

        Err(VerifyError::HttpsError {
            message: format!(
                "All registry endpoints failed for function-manifest/{}/{}",
                version, target
            ),
        })
    }

    /// Verify key by fingerprint with failover.
    pub async fn verify_key_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<KeyVerificationResponse, VerifyError> {
        match self.primary.verify_key_by_fingerprint(fingerprint).await {
            Ok(r) => return Ok(r),
            Err(e) => warn!(
                "Primary registry failed for verify/key/{}: {}",
                fingerprint, e
            ),
        }

        for (i, fallback) in self.fallbacks.iter().enumerate() {
            match fallback.verify_key_by_fingerprint(fingerprint).await {
                Ok(r) => {
                    info!("Fallback[{}] succeeded for verify/key/{}", i, fingerprint);
                    return Ok(r);
                },
                Err(e) => warn!(
                    "Fallback[{}] failed for verify/key/{}: {}",
                    i, fingerprint, e
                ),
            }
        }

        Err(VerifyError::HttpsError {
            message: format!(
                "All registry endpoints failed for verify/key/{}",
                fingerprint
            ),
        })
    }

    /// Health check on primary endpoint.
    pub async fn health_check(&self) -> Result<bool, VerifyError> {
        self.primary.health_check().await
    }
}

// Tests only run on desktop (need reqwest)
#[cfg(test)]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = RegistryClient::new(DEFAULT_REGISTRY_URL, Duration::from_secs(30));
        assert!(client.is_ok());
    }

    #[test]
    fn test_url_normalization() {
        let client = RegistryClient::new(
            "https://api.registry.ciris-services-1.ai/",
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://api.registry.ciris-services-1.ai");
    }
}
