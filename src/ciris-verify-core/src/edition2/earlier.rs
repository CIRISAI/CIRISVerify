//! Earlier-form names (CC 2.6.1, `row-ref` edition 1; CC 8.11).
//!
//! An edition-2 row names a JSON-era object by `[1, [-16, name]]`, where
//! `name` is SHA-256 of the message the object's Ed25519 half signed (the
//! canonical bytes both halves bind, never those bytes followed by the
//! Ed25519 signature), by a rule for each family. For a genesis bundle the
//! name is SHA-256 of its 32-byte `authorization_digest`. Never an
//! `attestation_id`.
//!
//! The four families this edition names (CC, rc20):
//! - the accord invocation: its canonical bytes, domain prefix included
//!   ([`accord_invocation`]);
//! - the key record: JCS of its `registration_envelope` ([`key_record`]);
//! - the build-manifest contribution: JCS of its envelope ([`manifest_contribution`]);
//! - the genesis bundle: SHA-256 of `authorization_digest` ([`genesis_bundle`]).

use super::{Digest32, Value};
use crate::humanity_accord::Invocation;
use sha2::{Digest, Sha256};

/// The name of an object whose Ed25519 half signed `message`.
#[must_use]
pub fn name(message: &[u8]) -> Digest32 {
    Sha256::digest(message).into()
}

/// An accord invocation's earlier-form name.
#[must_use]
pub fn accord_invocation(inv: &Invocation) -> Digest32 {
    inv.canonical_digest()
}

/// A key record's earlier-form name: SHA-256 of JCS(`registration_envelope`).
///
/// # Errors
/// [`crate::error::VerifyError`] if the envelope does not canonicalize.
pub fn key_record(
    registration_envelope: &serde_json::Value,
) -> Result<Digest32, crate::error::VerifyError> {
    Ok(name(&crate::jcs::canonicalize(registration_envelope)?))
}

/// A build-manifest contribution's earlier-form name: SHA-256 of JCS(envelope).
///
/// # Errors
/// [`crate::error::VerifyError`] if the envelope does not canonicalize.
pub fn manifest_contribution(
    envelope: &serde_json::Value,
) -> Result<Digest32, crate::error::VerifyError> {
    Ok(name(&crate::jcs::canonicalize(envelope)?))
}

/// A genesis bundle's earlier-form name: SHA-256 of its `authorization_digest`.
#[must_use]
pub fn genesis_bundle(authorization_digest: &[u8; 32]) -> Digest32 {
    name(authorization_digest)
}

/// The edition-1 `row-ref` `[1, [-16, name]]`.
#[must_use]
pub fn row_ref(name: &Digest32) -> Value {
    Value::Array(vec![Value::Uint(1), super::hash_digest_value(name)])
}
