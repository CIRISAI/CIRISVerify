//! Universal CEG-object outbox — the one standard filesystem location every
//! producer drops *signed CEG objects* to, and **CIRISServer** drains + relays
//! over CEG (CIRISServer 6.0).
//!
//! ## The path rule (universal across verify CLI + KMP client + server)
//!
//! Mirrors the CIRISAgent KMP client `ciris/` root convention:
//!
//! | Platform | `ciris/` root |
//! |----------|---------------|
//! | Desktop (Linux / Windows / macOS) | `~/ciris` |
//! | iOS / Android | `<Documents>/ciris` |
//!
//! `$CIRIS_HOME` overrides the root. Under it:
//! - `ceg/outbox/<kind>/<id>.json` — producers WRITE here.
//! - `ceg/sent/<kind>/<id>.json` — CIRISServer moves an object here after a
//!   successful relay.
//!
//! ## Why an outbox (not a direct call)
//!
//! verify is offline crypto: it *signs*, it never broadcasts. CIRISServer is
//! the only component holding both the verify wheel (to authenticate) and the
//! embedded CIRISPersist `Engine` (to apply the bring-in rules) and the network
//! presence (to announce over CEG). So a signed object lands in the outbox;
//! CIRISServer drains it, verifies, calls the substrate, and announces. The
//! storage substrate (Persist) never picks the file up directly — by design it
//! is signature-blind (the #65 two-quorums split).
//!
//! ## The relay envelope
//!
//! Each file is a [`SignedCegObject`]: `{schema, kind, key_id, created_at,
//! body, signatures?}`. `body` is the CEG object. When the object is delivered
//! as a *signed request* (e.g. a self-login), `signatures` carries the request
//! envelope's hybrid signature, mapping 1:1 onto CIRISServer's `x-ciris-*`
//! headers. A **self-signed** object (a `KeyRecord`, whose `scrub_*` signature
//! is inside `body`) leaves `signatures` `None`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::VerifyError;

/// Env var that overrides the `ciris/` root.
pub const CIRIS_HOME_ENV: &str = "CIRIS_HOME";

/// Relay-envelope schema tag.
pub const SCHEMA: &str = "ciris.ceg.signed-object.v1";

/// Serializes every test that mutates the process-global `CIRIS_HOME` env var
/// (here and in `crate::federation_identity`), since `cargo test` runs them in
/// parallel in one process. Poison-tolerant (a panicking test must not wedge
/// the rest).
#[cfg(test)]
pub(crate) static CIRIS_HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The platform `ciris/` root: `$CIRIS_HOME` if set, else desktop `~/ciris`,
/// mobile `<Documents>/ciris`.
#[must_use]
pub fn ciris_root() -> PathBuf {
    if let Some(dir) = std::env::var_os(CIRIS_HOME_ENV) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let home = home_dir();
    if cfg!(any(target_os = "android", target_os = "ios")) {
        home.join("Documents").join("ciris")
    } else {
        home.join("ciris")
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `<root>/ceg/outbox` — producers WRITE signed CEG objects here.
#[must_use]
pub fn ceg_outbox() -> PathBuf {
    ciris_root().join("ceg").join("outbox")
}

/// `<root>/ceg/sent` — CIRISServer moves objects here after a successful relay.
#[must_use]
pub fn ceg_sent() -> PathBuf {
    ciris_root().join("ceg").join("sent")
}

/// `<root>/keys` — local key material (e.g. the software ML-DSA-65 seed half).
#[must_use]
pub fn keys_dir() -> PathBuf {
    ciris_root().join("keys")
}

/// The outbox path for one object: `<outbox>/<kind>/<id>.json`.
#[must_use]
pub fn object_path(kind: &str, id: &str) -> PathBuf {
    object_path_under(&ceg_outbox(), kind, id)
}

fn object_path_under(outbox: &std::path::Path, kind: &str, id: &str) -> PathBuf {
    outbox
        .join(sanitize(kind))
        .join(format!("{}.json", sanitize(id)))
}

/// Keep a `kind` / `id` (or any externally-supplied filename component) safe as
/// a single path segment — anything outside `[A-Za-z0-9._-]` becomes `_`, so no
/// `..` or path separator survives. Shared so the CLI's seed-file path uses the
/// exact same form as the outbox `id` (they must stay correlated).
#[must_use]
pub fn sanitize_segment(s: &str) -> String {
    sanitize(s)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The hybrid request-envelope signature halves — map 1:1 onto CIRISServer's
/// `x-ciris-signature-ed25519` / `x-ciris-signature-ml-dsa-65` headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CegSignatures {
    /// Base64 Ed25519 over `JCS(body)` → `x-ciris-signature-ed25519`.
    pub ed25519: String,
    /// Base64 ML-DSA-65 over `JCS(body) ‖ ed25519_sig` →
    /// `x-ciris-signature-ml-dsa-65`.
    pub ml_dsa_65: String,
}

/// A signed CEG object as written to the outbox for CIRISServer to relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCegObject {
    /// Relay-envelope schema tag ([`SCHEMA`]).
    pub schema: String,
    /// The CEG object kind (e.g. `"federation_key_record"`, `"self_login"`).
    pub kind: String,
    /// The signing identity's federation `key_id` → `x-ciris-signing-key-id`.
    pub key_id: String,
    /// RFC-3339 creation timestamp (caller-supplied).
    pub created_at: String,
    /// The CEG object itself.
    pub body: Value,
    /// Request-envelope signature (for signed-request objects). `None` for a
    /// self-signed object whose signature lives inside `body`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<CegSignatures>,
}

impl SignedCegObject {
    /// A self-signed object (signature is inside `body`).
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        key_id: impl Into<String>,
        created_at: impl Into<String>,
        body: Value,
    ) -> Self {
        Self {
            schema: SCHEMA.to_string(),
            kind: kind.into(),
            key_id: key_id.into(),
            created_at: created_at.into(),
            body,
            signatures: None,
        }
    }

    /// Attach a request-envelope hybrid signature (the `x-ciris-*` mapping).
    #[must_use]
    pub fn with_signatures(mut self, ed25519: String, ml_dsa_65: String) -> Self {
        self.signatures = Some(CegSignatures { ed25519, ml_dsa_65 });
        self
    }

    /// Write this object to the outbox at `<outbox>/<kind>/<id>.json`,
    /// creating parent dirs. Returns the written path.
    ///
    /// # Errors
    ///
    /// [`VerifyError::IntegrityError`] on a serialization or filesystem fault.
    pub fn write_to_outbox(&self, id: &str) -> Result<PathBuf, VerifyError> {
        let path = object_path(&self.kind, id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(|e| VerifyError::IntegrityError {
            message: format!("serialize CEG object: {e}"),
        })?;
        std::fs::write(&path, json).map_err(io_err)?;
        Ok(path)
    }
}

fn io_err(e: std::io::Error) -> VerifyError {
    VerifyError::IntegrityError {
        message: format!("CEG outbox io: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_path_layout_is_kind_then_id() {
        let outbox = PathBuf::from("/tmp/ciris/ceg/outbox");
        let p = object_path_under(&outbox, "federation_key_record", "abc123");
        assert_eq!(
            p,
            PathBuf::from("/tmp/ciris/ceg/outbox/federation_key_record/abc123.json")
        );
    }

    #[test]
    fn sanitize_blocks_path_traversal_and_separators() {
        let outbox = PathBuf::from("/root/outbox");
        let p = object_path_under(&outbox, "../../etc", "a/b/../c");
        // Separators become `_`, so each is a single literal segment — no `/`
        // survives, so neither `kind` nor `id` can escape the outbox.
        assert_eq!(p, PathBuf::from("/root/outbox/.._.._etc/a_b_.._c.json"));
        let segments: Vec<_> = p.components().collect();
        assert!(
            segments.iter().all(|c| c.as_os_str() != ".."),
            "no `..` traversal segment survives sanitization"
        );
    }

    #[test]
    fn ciris_home_env_overrides_root() {
        let _g = CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Single self-contained env test (no parallel env-readers in this mod).
        std::env::set_var(CIRIS_HOME_ENV, "/custom/ciris");
        assert_eq!(ciris_root(), PathBuf::from("/custom/ciris"));
        assert_eq!(ceg_outbox(), PathBuf::from("/custom/ciris/ceg/outbox"));
        std::env::remove_var(CIRIS_HOME_ENV);
    }

    #[test]
    fn round_trips_through_outbox() {
        let _g = CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("ciris-outbox-test-{}", std::process::id()));
        std::env::set_var(CIRIS_HOME_ENV, &dir);

        let obj = SignedCegObject::new(
            "federation_key_record",
            "key-xyz",
            "2026-06-18T00:00:00Z",
            json!({"hello": "world"}),
        );
        let path = obj.write_to_outbox("key-xyz").unwrap();
        assert!(path.exists());

        let read: SignedCegObject = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(read, obj);
        assert_eq!(read.schema, SCHEMA);
        assert!(
            read.signatures.is_none(),
            "self-signed object: no top-level sig"
        );

        std::env::remove_var(CIRIS_HOME_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signatures_round_trip_with_xciris_field_names() {
        // The `signatures` map 1:1 onto CIRISServer's x-ciris-* headers — pin
        // the JSON key names (`ed25519` / `ml_dsa_65`) so the server mapping
        // can't silently drift.
        let obj = SignedCegObject::new("self_login", "k", "2026-06-18T00:00:00Z", json!({"a": 1}))
            .with_signatures("ED25519SIG".into(), "MLDSASIG".into());
        let v = serde_json::to_value(&obj).unwrap();
        assert_eq!(v["signatures"]["ed25519"], "ED25519SIG");
        assert_eq!(v["signatures"]["ml_dsa_65"], "MLDSASIG");
        let back: SignedCegObject = serde_json::from_value(v).unwrap();
        assert_eq!(
            back.signatures,
            Some(CegSignatures {
                ed25519: "ED25519SIG".into(),
                ml_dsa_65: "MLDSASIG".into()
            })
        );
    }

    #[test]
    fn write_to_outbox_overwrites_same_id() {
        let _g = CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("ciris-outbox-ow-{}", std::process::id()));
        std::env::set_var(CIRIS_HOME_ENV, &dir);

        SignedCegObject::new("k", "id1", "t", json!({"v": 1}))
            .write_to_outbox("id1")
            .unwrap();
        let path = SignedCegObject::new("k", "id1", "t", json!({"v": 2}))
            .write_to_outbox("id1")
            .unwrap();
        let read: SignedCegObject = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            read.body,
            json!({"v": 2}),
            "second write must replace the first"
        );

        std::env::remove_var(CIRIS_HOME_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_collapses_unicode_and_empty_home_falls_back() {
        let _g = CIRIS_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let out = PathBuf::from("/o");
        let p = object_path_under(&out, "föo→bar", "naïve");
        // Every component is a single safe segment — only [A-Za-z0-9._-] and no
        // separators survive (composition-agnostic: assert the char class, not
        // an exact unicode→`_` count).
        let tail: Vec<String> = p
            .components()
            .skip(2) // skip "/" and "o"
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(tail.len(), 2, "kind + id are exactly two segments");
        for seg in &tail {
            assert!(
                seg.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
                "segment {seg:?} contains an unsafe char"
            );
        }

        // Empty CIRIS_HOME is treated as unset (must not root the tree at "").
        std::env::set_var(CIRIS_HOME_ENV, "");
        assert_ne!(ciris_root(), PathBuf::from(""));
        assert!(ciris_root().ends_with("ciris"));
        std::env::remove_var(CIRIS_HOME_ENV);
    }
}
