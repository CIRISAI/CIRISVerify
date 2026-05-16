//! Bootstrap-trusted steward keyset loader (v2.2.0+, issue #22).
//!
//! Loads the packaged `data/bootstrap_stewards.json` keyset embedded at
//! compile time via `include_bytes!`. Decoded entries are exposed to the
//! constructor which iterates them when verifying the function manifest
//! signature.
//!
//! ## Trust model
//!
//! The keyset shares the exact trust boundary of the v2.1.x hardcoded
//! constants — both are baked into the wheel and propagated by the same
//! signed release artifact. The structural difference is that keys are
//! now *addressable* (by `key_id`) instead of source-code-embedded,
//! which unblocks:
//!
//! - **Multi-steward bootstrap**: a single wheel can list multiple
//!   trusted stewards. Needed for CIRISAgent 2.9.1 decentralization,
//!   where every agent bundles its own CIRISRegistry and acts as a
//!   steward for its scope.
//! - **Hot rotation in v2.3.0+**: the keyset becomes a versioned,
//!   independently-signable artifact distinct from the binary, so
//!   rotation no longer requires a wheel respin propagated to every
//!   agent.
//!
//! ## Back-compat (v2.2.0)
//!
//! The v2.1.x hardcoded constants stay in `constructor.rs` as a
//! belt-and-suspenders fallback. If keyset parse fails for any reason,
//! the constructor falls through to the single hardcoded steward. v2.3.0
//! will drop the fallback once downstream confirms keyset propagation.

use base64::Engine;
use serde::Deserialize;

/// Packaged keyset bytes, embedded at compile time so the trust boundary
/// is unchanged from v2.1.x. v2.3.0+ may switch to runtime loading.
const KEYSET_BYTES: &[u8] = include_bytes!("../data/bootstrap_stewards.json");

/// Expected `format_version` field. Bumped only on incompatible schema
/// changes; additive fields don't bump this.
const SUPPORTED_FORMAT_VERSION: u32 = 1;

/// Ed25519 public key length in bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// ML-DSA-65 public key length in bytes (FIPS 204 final).
const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;

#[derive(Debug, Deserialize)]
struct BootstrapKeyset {
    format_version: u32,
    stewards: Vec<StewardEntryJson>,
}

#[derive(Debug, Deserialize)]
struct StewardEntryJson {
    key_id: String,
    #[allow(dead_code)]
    algorithm: String,
    ed25519_public_key_b64: String,
    mldsa65_public_key_b64: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
}

/// Decoded steward entry suitable for manifest verification.
///
/// Owns the key material (allocated `Vec<u8>` for ML-DSA-65, fixed
/// array for Ed25519). The keyset is loaded once and cached for the
/// process lifetime, so allocation cost is paid at most once per run.
#[derive(Debug)]
pub struct LoadedSteward {
    /// Stable identifier for logging and registry cross-reference.
    pub key_id: String,
    /// Ed25519 public key (32 bytes).
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    /// ML-DSA-65 public key (1952 bytes).
    pub mldsa65: Vec<u8>,
}

/// Errors from loading or decoding the embedded keyset.
#[derive(Debug)]
pub enum KeysetError {
    /// JSON parse error.
    ParseError(String),
    /// Unsupported `format_version` (this binary doesn't understand it).
    InvalidFormatVersion(u32),
    /// Decoded key has wrong byte length.
    InvalidKeyLength {
        /// Which field: `"ed25519"` or `"mldsa65"`.
        field: &'static str,
        /// Decoded length.
        got: usize,
        /// Expected length.
        want: usize,
    },
    /// Base64 decode error on one of the key fields.
    Base64Decode(String),
    /// The keyset parsed cleanly but contains zero stewards.
    EmptyKeyset,
}

impl std::fmt::Display for KeysetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(e) => write!(f, "keyset parse error: {}", e),
            Self::InvalidFormatVersion(v) => write!(
                f,
                "keyset format_version {} not supported by this binary",
                v
            ),
            Self::InvalidKeyLength { field, got, want } => write!(
                f,
                "keyset key {} length wrong: got {} bytes, expected {}",
                field, got, want
            ),
            Self::Base64Decode(e) => write!(f, "keyset base64 decode error: {}", e),
            Self::EmptyKeyset => write!(f, "keyset has zero stewards"),
        }
    }
}

impl std::error::Error for KeysetError {}

/// Parse and decode the embedded bootstrap keyset.
///
/// Returns `Err` if the embedded JSON is malformed, format_version is
/// unsupported, base64 decoding fails on any key, or any key has the
/// wrong length. The caller is expected to fall back to the hardcoded
/// v2.1.x constants on `Err`.
pub fn load_keyset() -> Result<Vec<LoadedSteward>, KeysetError> {
    let parsed: BootstrapKeyset =
        serde_json::from_slice(KEYSET_BYTES).map_err(|e| KeysetError::ParseError(e.to_string()))?;

    if parsed.format_version != SUPPORTED_FORMAT_VERSION {
        return Err(KeysetError::InvalidFormatVersion(parsed.format_version));
    }
    if parsed.stewards.is_empty() {
        return Err(KeysetError::EmptyKeyset);
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut out = Vec::with_capacity(parsed.stewards.len());
    for entry in parsed.stewards {
        let ed_decoded = b64
            .decode(&entry.ed25519_public_key_b64)
            .map_err(|e| KeysetError::Base64Decode(format!("ed25519: {}", e)))?;
        if ed_decoded.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(KeysetError::InvalidKeyLength {
                field: "ed25519",
                got: ed_decoded.len(),
                want: ED25519_PUBLIC_KEY_LEN,
            });
        }
        let mldsa_decoded = b64
            .decode(&entry.mldsa65_public_key_b64)
            .map_err(|e| KeysetError::Base64Decode(format!("mldsa65: {}", e)))?;
        if mldsa_decoded.len() != MLDSA65_PUBLIC_KEY_LEN {
            return Err(KeysetError::InvalidKeyLength {
                field: "mldsa65",
                got: mldsa_decoded.len(),
                want: MLDSA65_PUBLIC_KEY_LEN,
            });
        }

        let mut ed_arr = [0u8; ED25519_PUBLIC_KEY_LEN];
        ed_arr.copy_from_slice(&ed_decoded);
        out.push(LoadedSteward {
            key_id: entry.key_id,
            ed25519: ed_arr,
            mldsa65: mldsa_decoded,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock: the packaged keyset parses cleanly under this binary's
    /// `format_version`. If this fails, every downstream wheel ships
    /// broken — make sure CI catches it.
    #[test]
    fn embedded_keyset_parses() {
        let stewards = load_keyset().expect("embedded keyset must parse");
        assert!(
            !stewards.is_empty(),
            "embedded keyset must contain ≥1 steward"
        );
    }

    /// Lock: the first entry's bytes equal the v2.1.x hardcoded steward
    /// pubkey. This guarantees zero behavior change for existing
    /// deployments at v2.2.0 — same trusted key, just addressable.
    /// The byte comparison is done against the constructor module's
    /// constants to avoid drift.
    #[test]
    fn first_entry_matches_v21_hardcoded_steward() {
        let stewards = load_keyset().expect("keyset must parse");
        let first = &stewards[0];
        assert_eq!(
            first.key_id, "ciris-registry-main-v1",
            "first entry key_id is the v2.1.x steward"
        );
        assert_eq!(first.ed25519.len(), 32);
        assert_eq!(first.mldsa65.len(), 1952);
        // The actual byte-equality assertion lives in
        // constructor::tests::test_keyset_first_entry_equals_hardcoded so it
        // can see the static arrays.
    }

    #[test]
    fn keyset_error_display_is_readable() {
        let e = KeysetError::InvalidFormatVersion(99);
        assert!(format!("{e}").contains("format_version 99"));
        let e = KeysetError::EmptyKeyset;
        assert!(format!("{e}").contains("zero stewards"));
    }
}
