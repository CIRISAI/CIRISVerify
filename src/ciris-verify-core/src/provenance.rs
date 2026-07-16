//! Federation-key directory provenance verification (CIRISVerify#29 WS-4).
//!
//! CIRISPersist's `federation_keys` directory is the federation's
//! identity substrate: every key the federation trusts is a row, and
//! every row is *scrub-signed* by another row — the chain terminating
//! at a self-signed steward bootstrap. This recursive-provenance
//! property lets a verifier reduce "do I trust key K?" to "does K's
//! chain root at a steward I pinned?" — the AV-8 long-term mitigation
//! (`THREAT_MODEL.md` §3.2).
//!
//! Persist *assembles* the chain (`federation::rooting::provenance_chain`,
//! CIRISPersist#94); CIRISVerify *verifies* it — here. The split is
//! deliberate: persist stores, consumers compute their own trust
//! verdict (`MISSION.md` §7). This module never queries persist; it
//! takes a [`ProvenanceChain`] (persist's wire contract) and checks it.
//!
//! ## What is verified
//!
//! For a chain `[leaf, …, steward_bootstrap]`:
//! 1. non-empty, within depth, `chain[0]` is the queried key;
//! 2. each non-terminal link names the next as its `scrub_key_id`;
//! 3. each link's scrub-signature verifies — Ed25519 over
//!    `jcs::canonicalize(registration_envelope)`, against the **parent**
//!    link's public key (the self-signed terminus against its own), with
//!    `original_content_hash` cross-checked to equal
//!    `hex(sha256(canonical))`. A link that carries a PQC scrub-signature
//!    must also verify it, ML-DSA-65 over `canonical ‖ classical_sig` (the
//!    bound-signature rule). **These are the exact bytes
//!    `federation_self_record`'s producers sign** — verifying over the
//!    hash digest instead (pre-fix) rejected every real record, which is
//!    why CIRISPersist had to fork this walk (crypto-DRY assessment);
//! 4. the terminus is self-signed and carries one of the caller's accepted
//!    terminus roles (default `{"steward"}`; CIRISPersist roots at
//!    `accord_holder`/`canonical` — CIRISVerify#208);
//! 5. the terminus's public key is one the caller pinned as a trusted
//!    bootstrap anchor — trust is the pinned key, never a self-asserted
//!    one (the steward-pubkey-pinning discipline).
//!
//! Any failure rejects the whole chain — fail-secure, no partial trust
//! (`MISSION.md` §1.6). Verifying a chain authenticates an *identity's
//! provenance*; per the federation-wide invariant it confers no
//! *trust* — that remains an operator decision (`MISSION.md` §1.4).
//!
//! ## Cross-repo wire contract
//!
//! [`ProvenanceLink`] / [`ProvenanceChain`] mirror CIRISPersist's
//! `federation::rooting` types field-for-field (Persist#94). Field
//! names and JSON shape are the contract — a change is a cross-repo
//! coordination event.

use base64::Engine;
use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, MlDsa65Verifier, PqcVerifier};
use sha2::{Digest, Sha256};

use crate::threshold::HybridPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `identity_type` a terminating bootstrap link must carry.
pub const STEWARD_IDENTITY_TYPE: &str = "steward";

/// Maximum provenance-chain length — a runaway / cycle guard. Mirrors
/// CIRISPersist's `MAX_PROVENANCE_DEPTH`.
pub const MAX_PROVENANCE_DEPTH: usize = 64;

/// One `federation_keys` directory row, as a provenance-chain link.
/// Mirrors CIRISPersist's `rooting::ProvenanceLink` (Persist#94).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceLink {
    /// `key_id` of the row this link describes.
    pub key_id: String,
    /// Row's Ed25519 public key, base64 standard.
    pub pubkey_ed25519_base64: String,
    /// Row's ML-DSA-65 public key, base64 standard. `None` while the
    /// row is hybrid-pending (cold-path PQC sign not yet complete).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// `identity_type` (`agent` / `primitive` / `steward` / `partner`).
    pub identity_type: String,
    /// `identity_ref` of the row.
    pub identity_ref: String,
    /// The registration envelope whose JCS canonicalization is the exact
    /// preimage the scrub-signature covers (CIRISVerify#204-followup / the
    /// crypto-DRY provenance fix). This is the object
    /// [`federation_self_record::produce_self_key_record`] /
    /// `produce_scrubbed_key_record` build and sign; the verifier
    /// recanonicalizes it and cross-checks it against [`Self::original_content_hash`].
    ///
    /// [`federation_self_record::produce_self_key_record`]: crate::federation_self_record::produce_self_key_record
    pub registration_envelope: Value,
    /// `hex(sha256(jcs::canonicalize(registration_envelope)))` — an integrity
    /// binding on the envelope, NOT the signed preimage. The scrub-signatures
    /// cover the canonical envelope *bytes* (see [`Self::registration_envelope`]);
    /// this field is cross-checked to equal the recomputed digest so a tampered
    /// hash can't decouple the row's `original_content_hash` column from what
    /// was actually signed.
    pub original_content_hash: String,
    /// Ed25519 scrub-signature over `jcs::canonicalize(registration_envelope)`,
    /// base64 standard. Always present.
    pub scrub_signature_classical: String,
    /// ML-DSA-65 scrub-signature over `jcs::canonicalize(registration_envelope)
    /// ‖ classical_sig` (bound), base64 standard. `None` while hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` of the parent row that signed this row. Equal to
    /// [`Self::key_id`] iff this is the self-signed bootstrap.
    pub scrub_key_id: String,
    /// RFC 3339 timestamp the scrub-signature was issued.
    pub scrub_timestamp: String,
    /// `true` iff this link is the self-signed bootstrap.
    pub is_self_signed: bool,
}

/// A `federation_keys` row plus its full recursive-provenance chain.
/// Mirrors CIRISPersist's `rooting::ProvenanceChain` (Persist#94).
///
/// `chain` is ordered leaf → root: `chain[0].key_id == key_id`,
/// `chain[i].scrub_key_id == chain[i+1].key_id`, and the final element
/// is the self-signed steward bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceChain {
    /// The queried `key_id` — must equal `chain[0].key_id`.
    pub key_id: String,
    /// The links, leaf → root.
    pub chain: Vec<ProvenanceLink>,
    /// Persist's own assessment that the chain terminates at a steward
    /// bootstrap. Advisory — CIRISVerify recomputes it; never trusted
    /// in place of verification.
    #[serde(default)]
    pub terminates_at_steward_bootstrap: bool,
}

/// Why a provenance chain was rejected. Verifying produces `Ok(())` or
/// exactly one of these — no third state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The chain has no links.
    EmptyChain,
    /// The chain is longer than [`MAX_PROVENANCE_DEPTH`].
    OverDepth {
        /// The offending length.
        depth: usize,
    },
    /// `chain[0].key_id` does not equal the chain's queried `key_id`.
    QueriedKeyMismatch,
    /// A non-terminal link does not name the next link as its parent.
    BrokenLink {
        /// The link with the bad parent reference.
        key_id: String,
        /// The parent the chain order implies.
        expected_parent: String,
        /// The parent the link actually names.
        named_parent: String,
    },
    /// A self-signed link appeared before the terminus.
    SelfSignedMidChain {
        /// The offending link.
        key_id: String,
    },
    /// The terminal link is not self-signed.
    TerminusNotSelfSigned,
    /// The terminal link is self-signed but not a steward.
    TerminusNotSteward {
        /// The terminus's actual `identity_type`.
        identity_type: String,
    },
    /// A link's `registration_envelope` could not be JCS-canonicalized (the
    /// signed preimage is unrecoverable).
    BadContentHash {
        /// The offending link.
        key_id: String,
    },
    /// A link's `original_content_hash` does not equal
    /// `hex(sha256(jcs::canonicalize(registration_envelope)))` — the persisted
    /// hash column has been decoupled from the envelope the signature covers
    /// (tamper / drift). Rejected before any signature check.
    ContentHashMismatch {
        /// The offending link.
        key_id: String,
    },
    /// A base64 signature field did not decode.
    BadSignatureEncoding {
        /// The offending link.
        key_id: String,
    },
    /// A base64 public-key field did not decode.
    BadKeyEncoding {
        /// The link whose key field is malformed.
        key_id: String,
    },
    /// A link carries a PQC scrub-signature but its parent has no
    /// ML-DSA-65 public key to verify it against.
    ParentMissingPqcKey {
        /// The parent link.
        key_id: String,
    },
    /// A scrub-signature did not verify.
    ScrubSignatureInvalid {
        /// The link whose scrub-signature failed.
        key_id: String,
        /// `"classical"` or `"pqc"`.
        half: &'static str,
    },
    /// The chain is internally valid but its steward bootstrap is not a
    /// pinned trusted anchor.
    UntrustedAnchor {
        /// The terminus `key_id`.
        key_id: String,
    },
    /// A link carries no ML-DSA-65 scrub-signature (classical-only /
    /// hybrid-pending) but the chain was verified under the federation-tier
    /// [`HybridPolicy::RequireHybrid`] (CEG 1.0-RC7 §10.1.5.1.1). Such a link
    /// is local-tier only.
    LinkNotHybrid {
        /// The classical-only link.
        key_id: String,
    },
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "provenance chain is empty"),
            Self::OverDepth { depth } => {
                write!(
                    f,
                    "provenance chain too deep: {depth} > {MAX_PROVENANCE_DEPTH}"
                )
            },
            Self::QueriedKeyMismatch => {
                write!(f, "chain[0].key_id does not match the queried key_id")
            },
            Self::BrokenLink {
                key_id,
                expected_parent,
                named_parent,
            } => write!(
                f,
                "broken provenance link at {key_id}: chain order implies parent \
                 {expected_parent} but the link names {named_parent}"
            ),
            Self::SelfSignedMidChain { key_id } => {
                write!(f, "self-signed link {key_id} appears before the terminus")
            },
            Self::TerminusNotSelfSigned => {
                write!(f, "the terminal link is not a self-signed bootstrap")
            },
            Self::TerminusNotSteward { identity_type } => write!(
                f,
                "the terminal bootstrap's identity_type '{identity_type}' carries no accepted \
                 terminus role (default: 'steward')"
            ),
            Self::BadContentHash { key_id } => {
                write!(
                    f,
                    "link {key_id}: registration_envelope could not be JCS-canonicalized"
                )
            },
            Self::ContentHashMismatch { key_id } => write!(
                f,
                "link {key_id}: original_content_hash != sha256(jcs(registration_envelope)) \
                 — hash column decoupled from the signed envelope"
            ),
            Self::BadSignatureEncoding { key_id } => {
                write!(f, "link {key_id}: scrub-signature base64 decode failed")
            },
            Self::BadKeyEncoding { key_id } => {
                write!(f, "link {key_id}: public-key base64 decode failed")
            },
            Self::ParentMissingPqcKey { key_id } => write!(
                f,
                "parent link {key_id} has no ML-DSA-65 key to verify a child's PQC scrub-signature"
            ),
            Self::ScrubSignatureInvalid { key_id, half } => {
                write!(f, "link {key_id}: {half} scrub-signature did not verify")
            },
            Self::UntrustedAnchor { key_id } => write!(
                f,
                "provenance chain roots at {key_id}, which is not a pinned trusted steward"
            ),
            Self::LinkNotHybrid { key_id } => write!(
                f,
                "provenance link {key_id} is classical-only (hybrid-pending); \
                 not admissible at federation-tier (RC7 §10.1.5.1.1)"
            ),
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// Verify a federation-key provenance chain (CIRISVerify#29 WS-4).
///
/// `Ok(())` means: the chain is structurally sound, every link's
/// scrub-signature(s) verify against the parent, and it roots at a
/// self-signed steward bootstrap whose public key is in
/// `trusted_bootstrap_ed25519` (each entry a raw 32-byte Ed25519 key).
///
/// # Errors
///
/// Exactly one [`ProvenanceError`] on any failure — fail-secure, no
/// partial trust.
pub fn verify_provenance_chain(
    chain: &ProvenanceChain,
    trusted_bootstrap_ed25519: &[Vec<u8>],
) -> Result<(), ProvenanceError> {
    verify_provenance_chain_with_policy(
        chain,
        trusted_bootstrap_ed25519,
        HybridPolicy::RequireHybrid,
    )
}

/// Verify a [`ProvenanceChain`] under an explicit [`HybridPolicy`].
///
/// [`verify_provenance_chain`] is the federation-tier default
/// ([`HybridPolicy::RequireHybrid`]): every link MUST carry a valid ML-DSA-65
/// scrub-signature (CEG 1.0-RC7 §10.1.5.1.1) — a classical-only
/// ("hybrid-pending") link is rejected, because a federation-key directory
/// rooted on a classical-only scrub chain could be forged whole by a future
/// Ed25519 break (`FEDERATION_THREAT_MODEL.md` F-AV-14 / AV-8).
/// [`HybridPolicy::AllowClassicalPending`] tolerates a classical-only link and
/// is for **local-tier** (§10.1.5.2) self-read ONLY — never a federation trust
/// decision.
///
/// The accepted terminus role set defaults to `{"steward"}`. Callers whose real
/// trust roots terminate at a different role (CIRISPersist's genesis roots are
/// `accord_holder` / `canonical`, never `steward`) use
/// [`verify_provenance_chain_with_policy_and_terminus`].
pub fn verify_provenance_chain_with_policy(
    chain: &ProvenanceChain,
    trusted_bootstrap_ed25519: &[Vec<u8>],
    policy: HybridPolicy,
) -> Result<(), ProvenanceError> {
    verify_provenance_chain_with_policy_and_terminus(
        chain,
        trusted_bootstrap_ed25519,
        policy,
        &[STEWARD_IDENTITY_TYPE],
    )
}

/// Verify a [`ProvenanceChain`] under an explicit [`HybridPolicy`] AND a
/// caller-supplied set of `identity_type` roles that may **terminate** a chain
/// (CIRISVerify#208).
///
/// The terminus is self-signed and anchor-pinned as before; this parameterizes
/// only *which self-attested role* it may carry, so verify stays policy-neutral
/// on the trust-root taxonomy. The terminus `identity_type` is a comma-joined
/// SET (CEG 1.0-RC5 §7.0.1) and passes iff **any** of its roles is in
/// `accepted_terminus_types`.
///
/// - [`verify_provenance_chain`] / [`verify_provenance_chain_with_policy`] pass
///   `&["steward"]` — unchanged behaviour.
/// - CIRISPersist passes e.g. `&["accord_holder", "canonical", "steward"]` so its
///   baked genesis roots (`accord_holder` A1/B1/C1, `canonical,node`) root
///   without re-labeling — the last blocker to deleting its forked chain-walk
///   (crypto-DRY assessment; the v10.4.0 preimage fix removed the other one).
///
/// `accepted_terminus_types` is a caller-pinned allowlist; an empty set rejects
/// every terminus (fail-closed).
///
/// # Errors
/// [`ProvenanceError`] naming the first failing step (see the module docs).
pub fn verify_provenance_chain_with_policy_and_terminus(
    chain: &ProvenanceChain,
    trusted_bootstrap_ed25519: &[Vec<u8>],
    policy: HybridPolicy,
    accepted_terminus_types: &[&str],
) -> Result<(), ProvenanceError> {
    let links = &chain.chain;
    if links.is_empty() {
        return Err(ProvenanceError::EmptyChain);
    }
    if links.len() > MAX_PROVENANCE_DEPTH {
        return Err(ProvenanceError::OverDepth { depth: links.len() });
    }
    if links[0].key_id != chain.key_id {
        return Err(ProvenanceError::QueriedKeyMismatch);
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let ed = Ed25519Verifier::new();
    let mldsa = MlDsa65Verifier::new();
    let last = links.len() - 1;

    for (i, link) in links.iter().enumerate() {
        // ---- structural: linkage + terminus shape -----------------------
        let parent: &ProvenanceLink = if i == last {
            if !link.is_self_signed || link.scrub_key_id != link.key_id {
                return Err(ProvenanceError::TerminusNotSelfSigned);
            }
            // CEG 1.0-RC5 §7.0.1: `identity_type` is a comma-joined SET, read
            // by set-membership — NOT scalar equality. A terminus legitimately
            // carries multiple roles (e.g. "steward,witness" or
            // "accord_holder,steward"), so a scalar comparison would wrongly
            // reject a valid one. The accepted role set is caller-supplied
            // (CIRISVerify#208) — `{"steward"}` by default.
            if !link
                .identity_type
                .split(',')
                .any(|role| accepted_terminus_types.contains(&role))
            {
                return Err(ProvenanceError::TerminusNotSteward {
                    identity_type: link.identity_type.clone(),
                });
            }
            link // self-signed: verified against its own key
        } else {
            if link.is_self_signed {
                return Err(ProvenanceError::SelfSignedMidChain {
                    key_id: link.key_id.clone(),
                });
            }
            if link.scrub_key_id != links[i + 1].key_id {
                return Err(ProvenanceError::BrokenLink {
                    key_id: link.key_id.clone(),
                    expected_parent: links[i + 1].key_id.clone(),
                    named_parent: link.scrub_key_id.clone(),
                });
            }
            &links[i + 1]
        };

        // ---- crypto: scrub-signature(s) ---------------------------------
        // The signed preimage is the JCS canonicalization of the registration
        // envelope — the exact bytes `federation_self_record`'s producers sign
        // via `signer.sign_bound(&canonical)`. `original_content_hash` is an
        // integrity binding on that envelope, NOT the preimage; verifying over
        // the digest (pre-fix) could never match a real signature.
        let canonical = crate::jcs::canonicalize(&link.registration_envelope).map_err(|_| {
            ProvenanceError::BadContentHash {
                key_id: link.key_id.clone(),
            }
        })?;
        // Cross-check: the row's advertised hash MUST equal the digest of the
        // envelope we are about to verify against, so a tampered hash column
        // can't decouple the persisted `original_content_hash` from the signed
        // bytes. Constant-time-insensitive is fine — this is a public digest.
        let computed_hash = hex::encode(Sha256::digest(&canonical));
        if !computed_hash.eq_ignore_ascii_case(link.original_content_hash.trim()) {
            return Err(ProvenanceError::ContentHashMismatch {
                key_id: link.key_id.clone(),
            });
        }
        let classical_sig = b64.decode(&link.scrub_signature_classical).map_err(|_| {
            ProvenanceError::BadSignatureEncoding {
                key_id: link.key_id.clone(),
            }
        })?;
        let parent_ed = b64.decode(&parent.pubkey_ed25519_base64).map_err(|_| {
            ProvenanceError::BadKeyEncoding {
                key_id: parent.key_id.clone(),
            }
        })?;

        if !matches!(ed.verify(&parent_ed, &canonical, &classical_sig), Ok(true)) {
            return Err(ProvenanceError::ScrubSignatureInvalid {
                key_id: link.key_id.clone(),
                half: "classical",
            });
        }

        // PQC scrub-signature. Under RequireHybrid (federation-tier, RC7
        // §10.1.5.1.1) every link MUST carry one and it MUST verify — a
        // classical-only ("hybrid-pending") link is rejected. Under
        // AllowClassicalPending (local-tier self-read) a missing PQC half is
        // tolerated, but a *present* one must still verify.
        let Some(pqc_sig_b64) = &link.scrub_signature_pqc else {
            if policy == HybridPolicy::RequireHybrid {
                return Err(ProvenanceError::LinkNotHybrid {
                    key_id: link.key_id.clone(),
                });
            }
            continue; // local-tier: classical-only link tolerated
        };
        let pqc_sig =
            b64.decode(pqc_sig_b64)
                .map_err(|_| ProvenanceError::BadSignatureEncoding {
                    key_id: link.key_id.clone(),
                })?;
        let parent_mldsa_b64 = parent.pubkey_ml_dsa_65_base64.as_ref().ok_or(
            ProvenanceError::ParentMissingPqcKey {
                key_id: parent.key_id.clone(),
            },
        )?;
        let parent_mldsa =
            b64.decode(parent_mldsa_b64)
                .map_err(|_| ProvenanceError::BadKeyEncoding {
                    key_id: parent.key_id.clone(),
                })?;
        // Bound signature: PQC covers canonical ‖ classical_sig.
        let mut bound = canonical.clone();
        bound.extend_from_slice(&classical_sig);
        if !matches!(mldsa.verify(&parent_mldsa, &bound, &pqc_sig), Ok(true)) {
            return Err(ProvenanceError::ScrubSignatureInvalid {
                key_id: link.key_id.clone(),
                half: "pqc",
            });
        }
    }

    // ---- anchor: terminus must be a pinned trusted steward --------------
    let terminus_ed = b64
        .decode(&links[last].pubkey_ed25519_base64)
        .map_err(|_| ProvenanceError::BadKeyEncoding {
            key_id: links[last].key_id.clone(),
        })?;
    if !trusted_bootstrap_ed25519
        .iter()
        .any(|k| k.as_slice() == terminus_ed.as_slice())
    {
        return Err(ProvenanceError::UntrustedAnchor {
            key_id: links[last].key_id.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    /// A keypair for a federation row.
    struct Keypair {
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Keypair {
        fn new() -> Self {
            Self {
                ed: Ed25519Signer::random().unwrap(),
                mldsa: MlDsa65Signer::new().unwrap(),
            }
        }
        fn ed_pub(&self) -> Vec<u8> {
            self.ed.public_key().unwrap()
        }
        fn ed_pub_b64(&self) -> String {
            base64::engine::general_purpose::STANDARD.encode(self.ed_pub())
        }
        fn mldsa_pub_b64(&self) -> String {
            base64::engine::general_purpose::STANDARD.encode(self.mldsa.public_key().unwrap())
        }
    }

    /// Build a link for `key_id`, scrub-signed by `scrub_by` (which is
    /// `own` itself for a self-signed bootstrap). `with_pqc=false`
    /// produces a hybrid-pending link (classical only).
    #[allow(clippy::too_many_arguments)]
    /// Build a link the way the REAL producers do: sign over
    /// `jcs::canonicalize(registration_envelope)`, not the hash. `salt`
    /// distinguishes envelopes so each link has distinct signed bytes.
    /// (Pre-fix this signed `content_hash` directly, which masked the
    /// producer/verifier preimage mismatch — the crypto-DRY assessment bug.)
    fn make_link(
        key_id: &str,
        identity_type: &str,
        own: &Keypair,
        scrub_by: &Keypair,
        scrub_key_id: &str,
        salt: u8,
        with_pqc: bool,
    ) -> ProvenanceLink {
        let b64 = base64::engine::general_purpose::STANDARD;
        // A representative registration envelope (shape is opaque to the
        // verifier — it canonicalizes whatever object is here).
        let registration_envelope = serde_json::json!({
            "key_id": key_id,
            "identity_type": identity_type,
            "pubkey_ed25519": own.ed_pub_b64(),
            "salt": salt,
        });
        let canonical = crate::jcs::canonicalize(&registration_envelope).unwrap();
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let classical_sig = scrub_by.ed.sign(&canonical).unwrap();
        let scrub_signature_pqc = if with_pqc {
            let mut bound = canonical.clone();
            bound.extend_from_slice(&classical_sig);
            Some(b64.encode(scrub_by.mldsa.sign(&bound).unwrap()))
        } else {
            None
        };
        ProvenanceLink {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: own.ed_pub_b64(),
            pubkey_ml_dsa_65_base64: Some(own.mldsa_pub_b64()),
            identity_type: identity_type.to_string(),
            identity_ref: format!("ref-{key_id}"),
            registration_envelope,
            original_content_hash,
            scrub_signature_classical: b64.encode(&classical_sig),
            scrub_signature_pqc,
            scrub_key_id: scrub_key_id.to_string(),
            scrub_timestamp: "2026-05-22T00:00:00Z".to_string(),
            is_self_signed: scrub_key_id == key_id,
        }
    }

    /// A valid 2-link chain: child ← steward(self-signed). Returns the
    /// chain and the steward's pinned Ed25519 anchor key.
    fn valid_chain() -> (ProvenanceChain, Vec<u8>, Keypair, Keypair) {
        let steward = Keypair::new();
        let child = Keypair::new();
        let steward_link = make_link(
            "steward-1",
            STEWARD_IDENTITY_TYPE,
            &steward,
            &steward,
            "steward-1",
            0xAA,
            true,
        );
        let child_link = make_link(
            "agent-1",
            "agent",
            &child,
            &steward,
            "steward-1",
            0xBB,
            true,
        );
        let chain = ProvenanceChain {
            key_id: "agent-1".to_string(),
            chain: vec![child_link, steward_link],
            terminates_at_steward_bootstrap: true,
        };
        let anchor = steward.ed_pub();
        (chain, anchor, steward, child)
    }

    #[test]
    fn valid_chain_verifies() {
        let (chain, anchor, ..) = valid_chain();
        assert!(verify_provenance_chain(&chain, &[anchor]).is_ok());
    }

    /// THE regression test for the crypto-DRY provenance fix: a record emitted
    /// by the REAL producer (`federation_self_record::produce_self_key_record`,
    /// which signs `jcs::canonicalize(registration_envelope)` via `sign_bound`)
    /// must verify through `verify_provenance_chain`. Before the fix the verifier
    /// checked the signature against the 32-byte hash digest, so it rejected
    /// every real record — and this coherence went untested (the `make_link`
    /// fixture signed the hash too), which is why CIRISPersist had to fork the
    /// walk. This test locks producer↔verifier coherence.
    #[tokio::test]
    async fn real_producer_record_roundtrips_through_verifier() {
        use crate::federation_self_record::produce_self_key_record;
        use crate::self_at_login::HybridSigningIdentity;

        let steward = HybridSigningIdentity::generate("steward-root").unwrap();
        let signed =
            produce_self_key_record(&steward, STEWARD_IDENTITY_TYPE, "2026-07-15T00:00:00Z", &[])
                .await
                .unwrap();
        let r = &signed.record;

        // Map the producer's self-signed KeyRecord onto a provenance terminus.
        let link = ProvenanceLink {
            key_id: r.key_id.clone(),
            pubkey_ed25519_base64: r.pubkey_ed25519_base64.clone(),
            pubkey_ml_dsa_65_base64: r.pubkey_ml_dsa_65_base64.clone(),
            identity_type: r.identity_type.clone(),
            identity_ref: r.identity_ref.clone(),
            registration_envelope: r.registration_envelope.clone(),
            original_content_hash: r.original_content_hash.clone(),
            scrub_signature_classical: r.scrub_signature_classical.clone(),
            scrub_signature_pqc: r.scrub_signature_pqc.clone(),
            scrub_key_id: r.scrub_key_id.clone(),
            scrub_timestamp: r.scrub_timestamp.clone(),
            is_self_signed: true,
        };
        let anchor = base64::engine::general_purpose::STANDARD
            .decode(&r.pubkey_ed25519_base64)
            .unwrap();
        let chain = ProvenanceChain {
            key_id: r.key_id.clone(),
            chain: vec![link],
            terminates_at_steward_bootstrap: true,
        };

        // Federation-tier (RequireHybrid) — the producer emits a hybrid record.
        verify_provenance_chain(&chain, &[anchor])
            .expect("a record from the real producer MUST verify through the verifier");
    }

    /// The integrity cross-check bites: a record whose `original_content_hash`
    /// column has been decoupled from its signed envelope is rejected before any
    /// signature check.
    #[test]
    fn tampered_content_hash_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        chain.chain[0].original_content_hash = "00".repeat(32);
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn single_self_signed_steward_verifies() {
        let steward = Keypair::new();
        let link = make_link(
            "steward-1",
            STEWARD_IDENTITY_TYPE,
            &steward,
            &steward,
            "steward-1",
            0x11,
            true,
        );
        let chain = ProvenanceChain {
            key_id: "steward-1".to_string(),
            chain: vec![link],
            terminates_at_steward_bootstrap: true,
        };
        assert!(verify_provenance_chain(&chain, &[steward.ed_pub()]).is_ok());
    }

    /// Build a chain whose child link is classical-only (PQC-pending).
    fn hybrid_pending_chain() -> (ProvenanceChain, Vec<u8>) {
        let steward = Keypair::new();
        let child = Keypair::new();
        let steward_link = make_link(
            "steward-1",
            STEWARD_IDENTITY_TYPE,
            &steward,
            &steward,
            "steward-1",
            0x22,
            true,
        );
        let child_link = make_link(
            "agent-1",
            "agent",
            &child,
            &steward,
            "steward-1",
            0x33,
            false, // no PQC scrub-signature
        );
        let chain = ProvenanceChain {
            key_id: "agent-1".to_string(),
            chain: vec![child_link, steward_link],
            terminates_at_steward_bootstrap: true,
        };
        (chain, steward.ed_pub())
    }

    #[test]
    fn hybrid_pending_link_rejected_at_federation_tier() {
        // RC7 §10.1.5.1.1 / F-AV-14 / AV-8: a classical-only scrub link cannot
        // root federation-tier trust — a future Ed25519 break could forge the
        // whole chain. The default policy rejects it.
        let (chain, anchor) = hybrid_pending_chain();
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::LinkNotHybrid { .. })
        ));
    }

    #[test]
    fn hybrid_pending_link_accepted_only_at_local_tier() {
        // The classical-only chain is admissible ONLY under the explicit
        // local-tier policy (§10.1.5.2 self-read).
        let (chain, anchor) = hybrid_pending_chain();
        assert!(verify_provenance_chain_with_policy(
            &chain,
            &[anchor],
            HybridPolicy::AllowClassicalPending,
        )
        .is_ok());
    }

    #[test]
    fn untrusted_anchor_is_rejected() {
        let (chain, ..) = valid_chain();
        let stranger = Keypair::new().ed_pub();
        assert!(matches!(
            verify_provenance_chain(&chain, &[stranger]),
            Err(ProvenanceError::UntrustedAnchor { .. })
        ));
    }

    /// #160 centipede-head rooting semantics (locked): a genesis chain whose
    /// terminus is a HUMANITY_ACCORD holder seeded as `steward,accord_holder`
    /// roots under a **1-of-N** anchor that contains only that one holder key.
    /// The `identity_type` is a comma-joined SET, so `steward,accord_holder`
    /// satisfies the terminus-is-steward check; and the anchor is set-MEMBERSHIP,
    /// so A1 alone roots the mesh even though the kill-switch needs 2-of-3. A
    /// different single key does NOT root it (membership, not blanket-accept).
    #[test]
    fn accord_holder_terminus_roots_under_one_of_n_anchor() {
        let holder = Keypair::new(); // an accord holder, e.g. A1
        let node = Keypair::new(); // the canonical mesh node
        let holder_link = make_link(
            "A1",
            "steward,accord_holder", // seeded role set (persist's genesis row)
            &holder,
            &holder,
            "A1",
            0x11,
            true,
        );
        let node_link = make_link(
            "canonical-node-1",
            "node",
            &node,
            &holder, // scrubbed by A1 (1/3 during bootstrap)
            "A1",
            0x22,
            true,
        );
        let chain = ProvenanceChain {
            key_id: "canonical-node-1".to_string(),
            chain: vec![node_link, holder_link],
            terminates_at_steward_bootstrap: true,
        };

        // 1-of-N: roots with ONLY A1 in the anchor.
        assert!(
            verify_provenance_chain(&chain, &[holder.ed_pub()]).is_ok(),
            "chain scrubbed by A1 must root under an anchor containing A1"
        );
        // Set membership, not blanket-accept: a different single key rejects.
        assert!(matches!(
            verify_provenance_chain(&chain, &[Keypair::new().ed_pub()]),
            Err(ProvenanceError::UntrustedAnchor { .. })
        ));
        // N>1 anchor that includes A1 still roots (1 of the N matches).
        assert!(
            verify_provenance_chain(&chain, &[Keypair::new().ed_pub(), holder.ed_pub()]).is_ok()
        );
    }

    /// #208: persist's baked genesis roots carry ONLY `accord_holder` (A1/B1/C1)
    /// or `canonical,node` — never `steward`. The steward-only default rejects
    /// them (`TerminusNotSteward`), but the parameterized entry point roots them
    /// when the caller supplies the accepted role set — the last blocker to
    /// deleting persist's forked chain-walk.
    #[test]
    fn accord_holder_only_terminus_needs_parameterized_terminus_set() {
        let holder = Keypair::new();
        let node = Keypair::new();
        let holder_link = make_link(
            "A1",
            "accord_holder", // persist's REAL genesis row — no steward role
            &holder,
            &holder,
            "A1",
            0x11,
            true,
        );
        let node_link = make_link(
            "canonical-node-1",
            "canonical,node",
            &node,
            &holder,
            "A1",
            0x22,
            true,
        );
        let chain = ProvenanceChain {
            key_id: "canonical-node-1".to_string(),
            chain: vec![node_link, holder_link],
            terminates_at_steward_bootstrap: true,
        };
        let anchor = vec![holder.ed_pub()];

        // Steward-only default: rejected (this is the #465 fork's raison d'être).
        assert!(matches!(
            verify_provenance_chain(&chain, &anchor),
            Err(ProvenanceError::TerminusNotSteward { .. })
        ));

        // Parameterized with persist's accepted set: roots.
        verify_provenance_chain_with_policy_and_terminus(
            &chain,
            &anchor,
            HybridPolicy::RequireHybrid,
            &["accord_holder", "canonical", "steward"],
        )
        .expect("an accord_holder terminus roots when the caller accepts that role");

        // A set that does NOT include accord_holder still rejects it.
        assert!(matches!(
            verify_provenance_chain_with_policy_and_terminus(
                &chain,
                &anchor,
                HybridPolicy::RequireHybrid,
                &["steward", "canonical"],
            ),
            Err(ProvenanceError::TerminusNotSteward { .. })
        ));

        // Empty accepted set is fail-closed.
        assert!(matches!(
            verify_provenance_chain_with_policy_and_terminus(
                &chain,
                &anchor,
                HybridPolicy::RequireHybrid,
                &[],
            ),
            Err(ProvenanceError::TerminusNotSteward { .. })
        ));
    }

    #[test]
    fn empty_chain_is_rejected() {
        let chain = ProvenanceChain {
            key_id: "x".to_string(),
            chain: vec![],
            terminates_at_steward_bootstrap: false,
        };
        assert_eq!(
            verify_provenance_chain(&chain, &[]),
            Err(ProvenanceError::EmptyChain)
        );
    }

    #[test]
    fn queried_key_mismatch_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        chain.key_id = "wrong-key".to_string();
        assert_eq!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::QueriedKeyMismatch)
        );
    }

    #[test]
    fn broken_linkage_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        chain.chain[0].scrub_key_id = "some-other-steward".to_string();
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::BrokenLink { .. })
        ));
    }

    #[test]
    fn terminus_not_self_signed_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        chain.chain[1].is_self_signed = false;
        assert_eq!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::TerminusNotSelfSigned)
        );
    }

    #[test]
    fn terminus_not_steward_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        chain.chain[1].identity_type = "agent".to_string();
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::TerminusNotSteward { .. })
        ));
    }

    /// CEG 1.0-RC5 §7.0.1: `identity_type` is a comma-joined SET, read by
    /// membership. A fabric-node steward carrying multiple roles
    /// ("steward,witness") MUST still resolve as a valid steward terminus —
    /// the pre-RC5 scalar `!= "steward"` check would have wrongly rejected it.
    #[test]
    fn multi_role_fabric_node_steward_terminus_verifies() {
        let (mut chain, anchor, ..) = valid_chain();
        chain.chain[1].identity_type = "steward,witness".to_string();
        assert!(verify_provenance_chain(&chain, std::slice::from_ref(&anchor)).is_ok());

        // …and a set that does NOT contain "steward" is still rejected
        // (membership, not substring — "stewardship" must not match).
        chain.chain[1].identity_type = "witness,stewardship".to_string();
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::TerminusNotSteward { .. })
        ));
    }

    #[test]
    fn tampered_classical_signature_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        // Corrupt the child's classical scrub-signature.
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut sig = b64
            .decode(&chain.chain[0].scrub_signature_classical)
            .unwrap();
        sig[0] ^= 1;
        chain.chain[0].scrub_signature_classical = b64.encode(&sig);
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::ScrubSignatureInvalid {
                half: "classical",
                ..
            })
        ));
    }

    #[test]
    fn tampered_pqc_signature_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut sig = b64
            .decode(chain.chain[0].scrub_signature_pqc.as_ref().unwrap())
            .unwrap();
        sig[0] ^= 1;
        chain.chain[0].scrub_signature_pqc = Some(b64.encode(&sig));
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::ScrubSignatureInvalid { half: "pqc", .. })
        ));
    }

    #[test]
    fn wrong_parent_key_breaks_signature() {
        // The steward's pubkey is swapped for a stranger's: the child's
        // scrub-signature (made by the real steward) no longer verifies.
        let (mut chain, _anchor, ..) = valid_chain();
        let stranger = Keypair::new();
        chain.chain[1].pubkey_ed25519_base64 = stranger.ed_pub_b64();
        assert!(matches!(
            verify_provenance_chain(&chain, &[stranger.ed_pub()]),
            Err(ProvenanceError::ScrubSignatureInvalid {
                half: "classical",
                ..
            })
        ));
    }

    #[test]
    fn self_signed_mid_chain_is_rejected() {
        let (mut chain, anchor, ..) = valid_chain();
        chain.chain[0].is_self_signed = true;
        chain.chain[0].scrub_key_id = chain.chain[0].key_id.clone();
        assert!(matches!(
            verify_provenance_chain(&chain, &[anchor]),
            Err(ProvenanceError::SelfSignedMidChain { .. })
        ));
    }
}
