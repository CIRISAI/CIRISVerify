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
//! 3. each link's scrub-signature verifies — Ed25519 over the
//!    hex-decoded `original_content_hash`, against the **parent** link's
//!    public key (the self-signed terminus against its own). A link
//!    that carries a PQC scrub-signature must also verify it, ML-DSA-65
//!    over `hash ‖ classical_sig` (the bound-signature rule);
//! 4. the terminus is self-signed with `identity_type == "steward"`;
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
use serde::{Deserialize, Serialize};

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
    /// `sha256(canonical(registration_envelope))`, hex-encoded — the
    /// bytes the scrub-signature covers.
    pub original_content_hash: String,
    /// Ed25519 scrub-signature over the (hex-decoded)
    /// `original_content_hash`, base64 standard. Always present.
    pub scrub_signature_classical: String,
    /// ML-DSA-65 scrub-signature over `original_content_hash ‖
    /// classical_sig` (bound), base64 standard. `None` while
    /// hybrid-pending.
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
    /// A link's `original_content_hash` is not 32 hex-encoded bytes.
    BadContentHash {
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
                "the terminal bootstrap is identity_type '{identity_type}', not 'steward'"
            ),
            Self::BadContentHash { key_id } => {
                write!(
                    f,
                    "link {key_id}: original_content_hash is not 32 hex bytes"
                )
            },
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
            // by set-membership — NOT scalar equality. A fabric-node steward
            // legitimately carries multiple roles (e.g. "steward,witness"), so
            // a scalar `!= "steward"` would wrongly reject a valid terminus.
            if !link
                .identity_type
                .split(',')
                .any(|role| role == STEWARD_IDENTITY_TYPE)
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
        let hash = hex::decode(&link.original_content_hash).map_err(|_| {
            ProvenanceError::BadContentHash {
                key_id: link.key_id.clone(),
            }
        })?;
        if hash.len() != 32 {
            return Err(ProvenanceError::BadContentHash {
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

        if !matches!(ed.verify(&parent_ed, &hash, &classical_sig), Ok(true)) {
            return Err(ProvenanceError::ScrubSignatureInvalid {
                key_id: link.key_id.clone(),
                half: "classical",
            });
        }

        // PQC scrub-signature is verified when present. A row may be
        // hybrid-pending (Ed25519-only) until the cold-path PQC sign
        // fills in — persist allows that — so a *missing* PQC half is
        // not a rejection, but a *present* one must verify.
        if let Some(pqc_sig_b64) = &link.scrub_signature_pqc {
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
            // Bound signature: PQC covers hash ‖ classical_sig.
            let mut bound = hash.clone();
            bound.extend_from_slice(&classical_sig);
            if !matches!(mldsa.verify(&parent_mldsa, &bound, &pqc_sig), Ok(true)) {
                return Err(ProvenanceError::ScrubSignatureInvalid {
                    key_id: link.key_id.clone(),
                    half: "pqc",
                });
            }
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
    fn make_link(
        key_id: &str,
        identity_type: &str,
        own: &Keypair,
        scrub_by: &Keypair,
        scrub_key_id: &str,
        content_hash: [u8; 32],
        with_pqc: bool,
    ) -> ProvenanceLink {
        let b64 = base64::engine::general_purpose::STANDARD;
        let classical_sig = scrub_by.ed.sign(&content_hash).unwrap();
        let scrub_signature_pqc = if with_pqc {
            let mut bound = content_hash.to_vec();
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
            original_content_hash: hex::encode(content_hash),
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
            [0xAAu8; 32],
            true,
        );
        let child_link = make_link(
            "agent-1",
            "agent",
            &child,
            &steward,
            "steward-1",
            [0xBBu8; 32],
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

    #[test]
    fn single_self_signed_steward_verifies() {
        let steward = Keypair::new();
        let link = make_link(
            "steward-1",
            STEWARD_IDENTITY_TYPE,
            &steward,
            &steward,
            "steward-1",
            [0x11u8; 32],
            true,
        );
        let chain = ProvenanceChain {
            key_id: "steward-1".to_string(),
            chain: vec![link],
            terminates_at_steward_bootstrap: true,
        };
        assert!(verify_provenance_chain(&chain, &[steward.ed_pub()]).is_ok());
    }

    #[test]
    fn hybrid_pending_link_still_verifies() {
        // A classical-only (PQC-pending) child is accepted; its classical
        // scrub-signature still chains.
        let steward = Keypair::new();
        let child = Keypair::new();
        let steward_link = make_link(
            "steward-1",
            STEWARD_IDENTITY_TYPE,
            &steward,
            &steward,
            "steward-1",
            [0x22u8; 32],
            true,
        );
        let child_link = make_link(
            "agent-1",
            "agent",
            &child,
            &steward,
            "steward-1",
            [0x33u8; 32],
            false,
        );
        let chain = ProvenanceChain {
            key_id: "agent-1".to_string(),
            chain: vec![child_link, steward_link],
            terminates_at_steward_bootstrap: true,
        };
        assert!(verify_provenance_chain(&chain, &[steward.ed_pub()]).is_ok());
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
