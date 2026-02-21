//! CIRISRegistry client for manifest and build verification.
//!
//! Fetches file integrity manifests from the registry to enable
//! Tripwire-style verification of agent binaries.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::error::VerifyError;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// Manifest version.
    #[serde(default)]
    pub version: String,
    /// Map of file path to SHA-256 hash.
    #[serde(default)]
    pub files: HashMap<String, String>,
}

/// Registry client for fetching manifests.
pub struct RegistryClient {
    /// HTTP client.
    client: Client,
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
    pub fn new(base_url: &str, timeout: Duration) -> Result<Self, VerifyError> {
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))  // Quick fail on unreachable hosts
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

    /// Fetch a build record by version.
    ///
    /// # Arguments
    ///
    /// * `version` - Semantic version to look up (e.g., "2.0.0")
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
    ///
    /// # Arguments
    ///
    /// * `build_hash` - SHA-256 hash of the build
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
    /// Fetch the binary manifest for self-verification.
    ///
    /// This enables Level 4 attestation: the running CIRISVerify binary
    /// can verify its own integrity against the registry-hosted manifest.
    ///
    /// # Arguments
    ///
    /// * `version` - CIRISVerify version to fetch (e.g., "0.5.1")
    #[instrument(skip(self), fields(version = %version))]
    pub async fn get_binary_manifest(&self, version: &str) -> Result<BinaryManifest, VerifyError> {
        let url = format!("{}/v1/verify/binary-manifest/{}", self.base_url, version);
        debug!("Fetching binary manifest from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::HttpsError {
                message: format!("Binary manifest request failed: {}", e),
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
    ///
    /// Used for runtime function integrity verification. The manifest contains
    /// SHA-256 hashes of all FFI export functions, allowing verification that
    /// the code hasn't been tampered with since build time.
    ///
    /// # Arguments
    ///
    /// * `version` - CIRISVerify version (e.g., "0.5.5")
    /// * `target` - Target triple (e.g., "x86_64-unknown-linux-gnu")
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
/// - Linux: Reads from `/proc/self/exe`
/// - macOS/Windows: Uses `std::env::current_exe()`
pub fn compute_self_hash() -> Result<String, VerifyError> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;

    let exe_path = std::env::current_exe().map_err(|e| VerifyError::IntegrityError {
        message: format!("Cannot determine executable path: {}", e),
    })?;

    let mut file = File::open(&exe_path).map_err(|e| VerifyError::IntegrityError {
        message: format!("Cannot open executable for hashing: {}", e),
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| VerifyError::IntegrityError {
                message: format!("Error reading executable: {}", e),
            })?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Get the current target triple at compile time.
///
/// Returns the Rust target triple (e.g., "x86_64-unknown-linux-gnu").
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

#[cfg(test)]
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
