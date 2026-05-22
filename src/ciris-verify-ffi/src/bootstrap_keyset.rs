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
//!
//! ## Deliberately NOT here: steward transport identities (CIRISVerify#27)
//!
//! The AV-42 transport-identity binding (`FederationEnvelope`, v2.9.0)
//! could in principle pin each bootstrap steward's Reticulum transport
//! identity here, giving zero-TOFU cold contact with the trust anchors.
//! It does **not**, and must not. This keyset is `include_bytes!`-baked
//! into the wheel; a steward's *transport* key is cheap plumbing that
//! rotates often, and baking it in would make every transport-key
//! rotation require a wheel respin — re-imposing exactly the rigidity
//! issue #22 removed for the long-lived federation pubkeys. A steward's
//! transport identity is *learned* from its first authenticated
//! `FederationEnvelope` (or, later, carried by the v2.3.0+
//! runtime-loadable signed keyset artifact). This file holds only the
//! long-lived Ed25519 / ML-DSA federation pubkeys.

use base64::Engine;
use ciris_crypto::{Ed25519Verifier, HybridSignature, HybridVerifier, MlDsa65Verifier};
use serde::Deserialize;

/// Packaged keyset bytes, embedded at compile time so the trust boundary
/// is unchanged from v2.1.x. The embedded keyset needs no signature of
/// its own — it *is* the binary, propagated by the same signed release
/// artifact. A **runtime-loaded** keyset (CIRISVerify#29 WS-2) does not
/// share that trust boundary and therefore must be signed; see
/// [`load_signed_keyset`].
const KEYSET_BYTES: &[u8] = include_bytes!("../data/bootstrap_stewards.json");

/// Domain-separation prefix for the keyset's own canonical signing
/// bytes. A runtime keyset is signed over `KEYSET_DOMAIN_SEP || …`; the
/// prefix keeps a keyset signature from ever being confused with any
/// other CIRIS signed primitive. Stable wire constant.
// WS-2: production wiring of the runtime-keyset path is gated on the
// root-key ceremony (THREAT_MODEL.md §10 Gap 5). The loader is shipped
// and test-exercised; until an embedded root pubkey is provisioned it
// has no non-test caller.
#[allow(dead_code)]
const KEYSET_DOMAIN_SEP: &[u8] = b"CIRIS-BOOTSTRAP-KEYSET-V1";

/// Expected `format_version` field. Bumped only on incompatible schema
/// changes; additive fields don't bump this.
const SUPPORTED_FORMAT_VERSION: u32 = 1;

/// Ed25519 public key length in bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// ML-DSA-65 public key length in bytes (FIPS 204 final).
const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;

#[derive(Debug, Deserialize, serde::Serialize)]
struct BootstrapKeyset {
    format_version: u32,
    stewards: Vec<StewardEntryJson>,
    /// Hybrid signature over the keyset's canonical bytes
    /// ([`keyset_signing_bytes`]). Absent in the embedded keyset (which
    /// is trusted by being the binary); **required** for a
    /// runtime-loaded keyset. CIRISVerify#29 WS-2.
    #[serde(default)]
    signature: Option<HybridSignature>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
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

/// Errors from loading or decoding a keyset (embedded or runtime).
#[allow(dead_code)] // SignatureRequired/RootKeyMismatch/SignatureInvalid: see load_signed_keyset (WS-2)
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
    /// A runtime-loaded keyset carried no `signature`. The embedded
    /// keyset may be unsigned (it is the binary); a runtime keyset must
    /// not be. CIRISVerify#29 WS-2.
    SignatureRequired,
    /// The keyset signature's embedded public keys do not match the
    /// pinned root public keys — trust is the pinned root key, never a
    /// self-asserted one.
    RootKeyMismatch,
    /// The keyset signature did not verify over the keyset's canonical
    /// bytes (tampered keyset, or signed by a non-root key).
    SignatureInvalid,
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
            Self::SignatureRequired => {
                write!(f, "runtime-loaded keyset has no signature (required)")
            },
            Self::RootKeyMismatch => write!(
                f,
                "keyset signature public keys do not match the pinned root key"
            ),
            Self::SignatureInvalid => {
                write!(f, "keyset signature did not verify over the keyset bytes")
            },
        }
    }
}

impl std::error::Error for KeysetError {}

/// The pinned root public keys a runtime keyset's signature is checked
/// against (CIRISVerify#29 WS-2).
///
/// A runtime-loaded keyset does not share the binary's trust boundary;
/// it is trusted only if signed by the federation **root key**, whose
/// public halves are pinned here. The root *private* key is held under
/// a key-ceremony procedure — out of scope for this code; production
/// wiring of an embedded root pubkey is gated on that ceremony (see
/// `THREAT_MODEL.md` §10 Gap 5). Until then `load_signed_keyset` is
/// callable with any caller-supplied `RootPublicKeys` (tests, or an
/// operator-configured root).
// WS-2: production wiring of the runtime-keyset path is gated on the
// root-key ceremony (THREAT_MODEL.md §10 Gap 5). The loader is shipped
// and test-exercised; until an embedded root pubkey is provisioned it
// has no non-test caller.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RootPublicKeys {
    /// Root Ed25519 public key (32 bytes).
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    /// Root ML-DSA-65 public key (1952 bytes).
    pub mldsa65: Vec<u8>,
}

/// Canonical bytes a runtime keyset's `signature` covers.
///
/// `KEYSET_DOMAIN_SEP || format_version(u32 LE) || count(u32 LE) ||
/// for each steward: LP(key_id) LP(ed25519_b64) LP(mldsa65_b64)` — `LP`
/// is a `u32`-length-prefixed byte string, stewards in file order.
/// Deterministic; the base64 strings are hashed as-is.
// WS-2: production wiring of the runtime-keyset path is gated on the
// root-key ceremony (THREAT_MODEL.md §10 Gap 5). The loader is shipped
// and test-exercised; until an embedded root pubkey is provisioned it
// has no non-test caller.
#[allow(dead_code)]
fn keyset_signing_bytes(keyset: &BootstrapKeyset) -> Vec<u8> {
    fn lp(buf: &mut Vec<u8>, b: &[u8]) {
        buf.extend_from_slice(&(u32::try_from(b.len()).unwrap_or(u32::MAX)).to_le_bytes());
        buf.extend_from_slice(b);
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(KEYSET_DOMAIN_SEP);
    buf.extend_from_slice(&keyset.format_version.to_le_bytes());
    buf.extend_from_slice(
        &(u32::try_from(keyset.stewards.len()).unwrap_or(u32::MAX)).to_le_bytes(),
    );
    for s in &keyset.stewards {
        lp(&mut buf, s.key_id.as_bytes());
        lp(&mut buf, s.ed25519_public_key_b64.as_bytes());
        lp(&mut buf, s.mldsa65_public_key_b64.as_bytes());
    }
    buf
}

/// Validate `format_version`, non-emptiness, then base64-decode and
/// length-check every steward's keys.
fn decode_stewards(parsed: BootstrapKeyset) -> Result<Vec<LoadedSteward>, KeysetError> {
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

/// Parse and decode the **embedded** bootstrap keyset.
///
/// The embedded keyset is trusted by being the binary — it carries no
/// signature of its own. Returns `Err` if the embedded JSON is
/// malformed, `format_version` is unsupported, base64 decoding fails, or
/// any key has the wrong length; the caller falls back to the hardcoded
/// v2.1.x constants on `Err`.
pub fn load_keyset() -> Result<Vec<LoadedSteward>, KeysetError> {
    let parsed: BootstrapKeyset =
        serde_json::from_slice(KEYSET_BYTES).map_err(|e| KeysetError::ParseError(e.to_string()))?;
    decode_stewards(parsed)
}

/// Parse, signature-verify, and decode a **runtime-loaded** keyset
/// (CIRISVerify#29 WS-2).
///
/// Unlike [`load_keyset`] (the compile-time-embedded keyset, trusted by
/// being the binary), a runtime keyset is trusted only if it carries a
/// `signature` that hybrid-verifies over [`keyset_signing_bytes`]
/// against the pinned `root` keys. This lets steward keys — and their
/// transport identities — rotate by shipping a new signed keyset file,
/// with no wheel respin (the rigidity issue #22 removed).
///
/// Checks, in order, all fail-secure (any failure rejects the whole
/// keyset — no partial trust):
/// 1. a `signature` is present;
/// 2. the signature's embedded public keys equal the pinned root keys
///    — trust is the pinned root key, never a self-asserted one;
/// 3. the hybrid signature verifies over the canonical bytes.
///
/// # Errors
///
/// [`KeysetError::SignatureRequired`], [`KeysetError::RootKeyMismatch`],
/// [`KeysetError::SignatureInvalid`], plus the parse/decode errors of
/// [`load_keyset`].
// WS-2: production wiring of the runtime-keyset path is gated on the
// root-key ceremony (THREAT_MODEL.md §10 Gap 5). The loader is shipped
// and test-exercised; until an embedded root pubkey is provisioned it
// has no non-test caller.
#[allow(dead_code)]
pub fn load_signed_keyset(
    bytes: &[u8],
    root: &RootPublicKeys,
) -> Result<Vec<LoadedSteward>, KeysetError> {
    let parsed: BootstrapKeyset =
        serde_json::from_slice(bytes).map_err(|e| KeysetError::ParseError(e.to_string()))?;
    let signature = parsed
        .signature
        .as_ref()
        .ok_or(KeysetError::SignatureRequired)?;

    // Trust is the pinned root key — the signature must carry exactly it.
    if signature.classical.public_key != root.ed25519 || signature.pqc.public_key != root.mldsa65 {
        return Err(KeysetError::RootKeyMismatch);
    }

    let signing_bytes = keyset_signing_bytes(&parsed);
    let verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());
    // HybridVerifier::verify returns Err on mismatch, never Ok(false) —
    // unwrap_or(false) folds both into "rejected".
    if !verifier.verify(&signing_bytes, signature).unwrap_or(false) {
        return Err(KeysetError::SignatureInvalid);
    }

    decode_stewards(parsed)
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

    // ---- #29 WS-2: runtime-loadable signed keyset -----------------------

    use ciris_crypto::{Ed25519Signer, HybridSigner, MlDsa65Signer};

    type RootSigner = HybridSigner<Ed25519Signer, MlDsa65Signer>;

    fn root_signer() -> RootSigner {
        HybridSigner::new(Ed25519Signer::random(), MlDsa65Signer::new().unwrap()).unwrap()
    }

    /// Build a one-steward keyset; if `signer` is `Some`, sign it. The
    /// steward keys are dummy bytes of the correct length (decode checks
    /// length, not curve validity). Returns the JSON bytes.
    fn build_keyset(signer: Option<&RootSigner>) -> Vec<u8> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut ks = BootstrapKeyset {
            format_version: 1,
            stewards: vec![StewardEntryJson {
                key_id: "runtime-steward-1".to_string(),
                algorithm: "hybrid-ed25519-mldsa65".to_string(),
                ed25519_public_key_b64: b64.encode([0x11u8; ED25519_PUBLIC_KEY_LEN]),
                mldsa65_public_key_b64: b64.encode(vec![0x22u8; MLDSA65_PUBLIC_KEY_LEN]),
                description: "test".to_string(),
            }],
            signature: None,
        };
        if let Some(s) = signer {
            ks.signature = Some(s.sign(&keyset_signing_bytes(&ks)).unwrap());
        }
        serde_json::to_vec(&ks).unwrap()
    }

    fn root_keys_of(json: &[u8]) -> RootPublicKeys {
        let ks: BootstrapKeyset = serde_json::from_slice(json).unwrap();
        let sig = ks.signature.unwrap();
        let mut ed = [0u8; ED25519_PUBLIC_KEY_LEN];
        ed.copy_from_slice(&sig.classical.public_key);
        RootPublicKeys {
            ed25519: ed,
            mldsa65: sig.pqc.public_key,
        }
    }

    #[test]
    fn signed_keyset_loads_under_correct_root() {
        let signer = root_signer();
        let json = build_keyset(Some(&signer));
        let root = root_keys_of(&json);
        let stewards = load_signed_keyset(&json, &root).expect("valid signed keyset must load");
        assert_eq!(stewards.len(), 1);
        assert_eq!(stewards[0].key_id, "runtime-steward-1");
    }

    #[test]
    fn unsigned_runtime_keyset_is_rejected() {
        let json = build_keyset(None);
        let root = RootPublicKeys {
            ed25519: [0u8; ED25519_PUBLIC_KEY_LEN],
            mldsa65: vec![0u8; MLDSA65_PUBLIC_KEY_LEN],
        };
        assert!(matches!(
            load_signed_keyset(&json, &root),
            Err(KeysetError::SignatureRequired)
        ));
    }

    #[test]
    fn signed_keyset_rejected_under_wrong_root() {
        let json = build_keyset(Some(&root_signer()));
        // A different root key than the one that signed the keyset.
        let other = build_keyset(Some(&root_signer()));
        let wrong_root = root_keys_of(&other);
        assert!(matches!(
            load_signed_keyset(&json, &wrong_root),
            Err(KeysetError::RootKeyMismatch)
        ));
    }

    #[test]
    fn tampered_signed_keyset_is_rejected() {
        let signer = root_signer();
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut ks = BootstrapKeyset {
            format_version: 1,
            stewards: vec![StewardEntryJson {
                key_id: "s1".to_string(),
                algorithm: "hybrid".to_string(),
                ed25519_public_key_b64: b64.encode([0x11u8; ED25519_PUBLIC_KEY_LEN]),
                mldsa65_public_key_b64: b64.encode(vec![0x22u8; MLDSA65_PUBLIC_KEY_LEN]),
                description: String::new(),
            }],
            signature: None,
        };
        ks.signature = Some(signer.sign(&keyset_signing_bytes(&ks)).unwrap());
        // Adversary swaps in their own steward key *after* signing.
        ks.stewards[0].ed25519_public_key_b64 = b64.encode([0x99u8; ED25519_PUBLIC_KEY_LEN]);
        let json = serde_json::to_vec(&ks).unwrap();
        let sig = ks.signature.unwrap();
        let mut ed = [0u8; ED25519_PUBLIC_KEY_LEN];
        ed.copy_from_slice(&sig.classical.public_key);
        let root = RootPublicKeys {
            ed25519: ed,
            mldsa65: sig.pqc.public_key,
        };
        assert!(
            matches!(
                load_signed_keyset(&json, &root),
                Err(KeysetError::SignatureInvalid)
            ),
            "a steward swapped in after signing must fail signature verification"
        );
    }

    #[test]
    fn embedded_keyset_still_loads_unsigned() {
        // WS-2 must not regress the embedded path: the embedded keyset is
        // trusted by being the binary and carries no signature.
        assert!(load_keyset().is_ok());
    }
}
