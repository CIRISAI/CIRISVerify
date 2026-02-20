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
            .connect_timeout(Duration::from_secs(10))
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
