//! # ciris-verify-core
//!
//! Core verification logic for CIRISVerify - the hardware-rooted license
//! verification module for the CIRIS ecosystem.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    LicenseEngine                             │
//! │                                                              │
//! │  ┌──────────────────────────────────────────────────┐      │
//! │  │   TrustRootValidator  (CC 5.3.4)                  │      │
//! │  │   each HTTPS host's GenesisBundle → verified      │      │
//! │  │   against the baked accord holders → one root     │      │
//! │  │   (highest version; equal-version split = fail)   │      │
//! │  └──────────────────────────────────────────────────┘      │
//! │                           │                                  │
//! │                           ▼                                  │
//! │  ┌──────────────────────────────────────────────────┐      │
//! │  │   Licence gate — community until the licensure    │      │
//! │  │   row path lands (`licensure:{authority}:v1`)     │      │
//! │  └──────────────────────────────────────────────────┘      │
//! │                           │                                  │
//! │                           ▼                                  │
//! │  ┌──────────────────────────────────────────────────┐      │
//! │  │              ResponseBuilder                      │      │
//! │  │    (attestation, mandatory disclosure)           │      │
//! │  └──────────────────────────────────────────────────┘      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Properties
//!
//! - **Fail-secure**: All errors degrade to MORE restrictive modes
//! - **Multi-source**: Requires 2-of-3 source agreement
//! - **Hardware-bound**: Responses signed by hardware-protected keys
//! - **Mandatory disclosure**: Cannot be suppressed or modified

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::pedantic)] // Too strict for production code
#![allow(clippy::doc_markdown)] // Allow product names without backticks
#![allow(clippy::missing_errors_doc)] // Error documentation not required
#![allow(clippy::missing_panics_doc)] // Panic documentation not required
#![allow(clippy::module_name_repetitions)] // Allow Type in module::Type
#![allow(clippy::must_use_candidate)] // Not all functions need must_use

#[macro_use]
extern crate alloc;

/// The `alloc` names every module uses, so a module reads the same with and
/// without `std` (CIRISVerify#325).
#[allow(unused_imports)]
pub(crate) mod prelude {
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::collections::{BTreeMap, BTreeSet};
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec::Vec;
}

/// Accord-holder custody attestation — the hardware-unforgeable YubiKey PIV
/// attestation the CIRISServer admission gate verifies (the safe-mesh floor,
/// CIRISVerify#91 / CIRISServer#41) before admitting an accord kill-switch key.
#[cfg(feature = "host")]
pub mod accord_custody_attestation;
/// HUMANITY_ACCORD genesis producer (CEG §9.1, CIRISVerify#82-followup) — holder
/// `accord_holder` records + the entrenched-`family` 2-of-3 genesis, round-tripped
/// through `threshold::verify_founder_quorum`.
pub mod accord_genesis;
/// The constitutional halt latch: pause, fuse, confirm, resume
/// (CIRISVerify#305, CIRISConstitution#146).
pub mod accord_halt_latch;
/// HUMANITY_ACCORD live-quorum decimation-recovery objects (FSD-004 / CC §4.2.6)
/// — Phase 1, step 1: the `AccordProposal` / `AccordParticipation` preimages with
/// the adversarial-review CRITICAL bindings (vote + proposal digest + member +
/// family + window in the signed bytes). The tally / fire / membership-change
/// surfaces are step 2.
pub mod accord_live_quorum;
pub mod announce_policy;
pub mod app_attest;
#[cfg(feature = "host")]
pub mod attest_bundle;
#[cfg(feature = "host")]
pub mod attest_heartbeat;
#[cfg(feature = "host")]
pub mod audit;
#[cfg(feature = "host")]
pub mod binary_format;
/// Peer-presentable build-attestation bundle (#181) — binds the presenting
/// node's federation key to the pipeline-signed manifest it claims to run.
#[cfg(feature = "std")]
pub mod build_attestation_bundle;
#[cfg(feature = "host")]
pub mod cache;
/// CC 2.3.2.1 canonical-hash subject codec (#201) — tagged subjects, bare hex rejected.
pub mod canonical_subject;
pub mod ceg_error;
pub mod ceg_outbox;
/// Does a shipped classification carry policy force? (#238 follow-up) —
/// every classification states, in the type, whether a consumer may gate on it.
pub mod classification;
#[cfg(feature = "host")]
pub mod config;
/// Device-attestation chain validation (#199) — Android Key Attestation to a
/// pinned vendor root. Hardware is a trust signal, never a requirement.
#[cfg(feature = "host")]
pub mod device_attestation;
pub mod doc_integrity;
#[cfg(feature = "host")]
pub mod engine;
pub mod error;
pub mod fedcode;
pub mod federation_envelope;
#[cfg(feature = "host")]
pub mod federation_identity;
pub mod federation_keyset;
pub mod federation_provenance;
pub mod federation_self_record;
pub mod genesis_bundle;
#[cfg(feature = "host")]
pub mod hardware_info;
pub mod holds_bytes;
#[cfg(feature = "host")]
pub mod http_client;
#[cfg(feature = "host")]
pub mod https;
pub mod humanity_accord;
pub mod infrastructure_community;
pub mod jcs;
#[cfg(feature = "host")]
pub mod keys;
pub mod license;
pub mod locale_merkle;
#[cfg(feature = "host")]
pub mod manifest_cache;
#[cfg(feature = "std")]
pub mod manifest_contribution;
#[cfg(all(feature = "host", any(target_os = "android", target_os = "ios")))]
pub mod mobile_http;
pub mod operational_admit;
#[cfg(feature = "host")]
pub mod parallel_race;
/// CIRISPersist's row identity `persist_row_hash` (CC 3.2 T6, annex 8.11).
pub mod persist_canonical;
pub mod play_integrity;
/// Presentation-surface identifier scope (CIRISConstitution#80) — keeps the
/// reserved unlinkable-presentation slot reachable.
pub mod presentation;
pub mod provenance;
pub mod reconsider_dos;
/// Redactable commitments (#241) — distinguishing 'redacted by authority'
/// from 'tampered', cryptographically rather than by assertion.
pub mod redactable;
#[cfg(feature = "host")]
pub mod registry;
#[cfg(feature = "std")]
pub mod safety_evidence;
#[cfg(feature = "std")]
pub mod security;
pub mod self_at_login;
#[cfg(feature = "std")]
pub mod skill_import;
pub mod subject_binding;
/// §19 Holonomic substrate verifiers (CEG 1.0-RC11, CIRISVerify#78) — ALM
/// capacity authenticity, durable-storage holding claims, WholenessWitness
/// divergence detection + equivocation, recursive trust bootstrap, A/V chunk
/// nonces. All
/// ride the §19.0 binary signed-preimage framing + the PQC-mandatory gate.
pub mod substrate;
/// CIRISVerify#202 — compile-time-fenced test-only trust-root / custody
/// relaxation for the local mesh harness (never in a prod artifact).
#[cfg(feature = "std")]
pub mod test_anchor;
pub mod threshold;
pub mod tpm_attest;
pub mod transparency;
pub mod transport_binding;
#[cfg(feature = "host")]
pub mod tree_verify;
/// CoTS-shaped constrained trust-anchor store (#227) — anchors resolved by
/// (purpose, environment) instead of hand-pinned per call site.
#[cfg(feature = "std")]
pub mod trust_anchor_store;
pub mod types;
#[cfg(feature = "host")]
pub mod unified;
#[cfg(feature = "host")]
pub mod validation;
#[cfg(feature = "host")]
pub mod watchdog;
/// WebAuthn / FIDO2 passkey assertion verification — the presence/unlock factor
/// for a user identity (authenticator apps: Google, Microsoft, Apple/Android).
/// CIRISVerify#80.
pub mod webauthn;
pub mod witness_relation;

#[cfg(feature = "host")]
pub use attest_bundle::{
    AttestBundle, AttestationFact, HardwareCustody, ProvenanceBlock, TransparencyLogBlock,
};
#[cfg(feature = "host")]
pub use cache::{CachedLicense, LicenseCache};
pub use canonical_subject::{
    canonical_subject, canonical_subject_from_triple, classify_subject, parse_canonical_subject,
    require_canonical_subject, SubjectError, SubjectKind, CANONICAL_SUBJECT_ALG,
    CANONICAL_SUBJECT_PREFIX,
};
pub use ceg_error::{CegError, CegErrorCode};
pub use ciris_crypto::constant_time_eq;
#[cfg(feature = "host")]
pub use config::VerifyConfig;
#[cfg(feature = "host")]
pub use engine::LicenseEngine;
pub use error::VerifyError;
#[cfg(feature = "std")]
pub use federation_envelope::TransportEpochGuard;
pub use federation_envelope::{
    EnvelopePurpose, EnvelopeVerifyPolicy, FederationEnvelope, TransportIdentity,
    ENVELOPE_DOMAIN_SEP, ENVELOPE_SCHEMA_VERSION,
};
pub use federation_keyset::{
    federation_keyset_signing_bytes, FederationKeyset, FEDERATION_KEYSET_DOMAIN_SEP,
    FEDERATION_KEYSET_SCHEMA_VERSION,
};
pub use federation_provenance::{
    AttestationEntry, FederationProvenance, FederationProvenanceBuilder, Score,
};
pub use holds_bytes::{verify_holds_bytes, HoldsBytesError};
pub use humanity_accord::{
    verify_invocation, Invocation, InvocationDedup, InvocationError, InvocationKind,
    INVOCATION_DOMAIN_PREFIX, LIFECYCLE_DOMAIN_PREFIX,
};
#[cfg(feature = "host")]
pub use keys::{
    derive_symmetric_key, derive_transport_identity, DERIVED_KEY_LEN, TRANSPORT_SEED_LEN,
};
pub use license::{LicenseDetails, LicenseStatus, LicenseType};
pub use locale_merkle::{
    locale_leaf_to_attestation_entries, merkle_root, parent_hash, verify_locale_inclusion,
    LocaleInclusionProof, LocaleLeaf, LOCALE_LEAF_DOMAIN_V2, RFC6962_LEAF_PREFIX,
    RFC6962_PARENT_PREFIX,
};
pub use provenance::{
    verify_provenance_chain, verify_provenance_chain_with_policy,
    verify_provenance_chain_with_policy_and_terminus, ProvenanceChain, ProvenanceError,
    ProvenanceLink, MAX_PROVENANCE_DEPTH, STEWARD_IDENTITY_TYPE,
};
pub use reconsider_dos::{
    ActorBudget, ActorBudgetExhausted, EventRateLimit, EventRateLimited, FilingOutcome,
    HarassmentClusterDetected, HarassmentClusterSignal, ReconsiderDosGuard, ReconsiderRejection,
    DEFAULT_ACTOR_BUDGET, DEFAULT_BUDGET_WINDOW_MS, DEFAULT_EVENT_RATE_LIMIT,
    DEFAULT_HARASSMENT_CLUSTER_THRESHOLD,
};
#[cfg(feature = "host")]
pub use security::file_integrity::{
    check_available as check_available_agent_integrity, check_full as check_agent_integrity,
    check_spot as spot_check_agent_integrity, generate_manifest, load_manifest,
    FileIntegrityResult, FileManifest,
};
#[cfg(feature = "host")]
pub use security::{IntegrityChecker, IntegrityStatus};
#[cfg(feature = "std")]
pub use skill_import::{
    verify_skill_import_manifest, SkillImportManifest, SourceType, SKILL_IMPORT_DOMAIN_V2,
};
pub use threshold::{
    verify_threshold_signatures, verify_threshold_signatures_with_policy, HybridPolicy,
    ThresholdError, ThresholdMember, ThresholdSignature,
};
pub use transparency::{
    hash_leaf, hash_node, verify_consistency, verify_inclusion, ConsistencyProof, MerkleProof,
    ProofChain, SignedTreeHead, TransparencyEntry, TransparencyError, TransparencyLeaf,
    TransparencyStore, TrustedWitness, WitnessConsistencyProof, WitnessSignature,
};
#[cfg(feature = "std")]
pub use transparency::{InMemoryTransparencyStore, TransparencyLog};
#[cfg(feature = "host")]
pub use types::{AttestationProof, LicenseStatusResponse};
pub use types::{
    BinaryIntegrityStatus, CapabilityCheckRequest, CapabilityCheckResponse, EnforcementAction,
    LicenseStatusRequest, MandatoryDisclosure, RuntimeValidation, RuntimeViolation,
    ShutdownDirective, ShutdownType, ViolationSeverity,
};
#[cfg(feature = "host")]
pub use watchdog::ShutdownWatchdog;
pub use witness_relation::{
    admit_attestation, admit_with_declared_relation, AdmissionDecision, EnvelopeMetadata,
    OversightMode, WitnessRelation,
};

// Audit trail verification
#[cfg(feature = "host")]
pub use audit::{
    read_audit_from_jsonl, read_audit_from_sqlite, verify_audit_database, verify_audit_full,
    verify_audit_json, verify_audit_jsonl, AuditEntry, AuditVerificationResult, AuditVerifier,
    ChainSummary,
};
#[cfg(feature = "host")]
pub use registry::{
    compute_ed25519_fingerprint, compute_self_hash, current_target, verify_self_against_manifest,
    BinaryManifest, BuildRecord, FileManifest as RegistryManifest, KeyVerificationResponse,
    RegistryClient,
};
#[cfg(feature = "host")]
pub use tree_verify::{
    verify_tree, FailedFile, FailedFileKind, TreeVerifyRequest, TreeVerifyResult,
};
#[cfg(feature = "host")]
pub use unified::{
    FullAttestationRequest, FullAttestationResult, IntegrityCheckResult, PythonIntegrityResult,
    PythonModuleHashes, SourceCheckResult, UnifiedAttestationEngine,
};

// Manifest cache for offline L1 verification
#[cfg(feature = "host")]
pub use manifest_cache::{
    load_and_verify as load_manifest_cache, BuildRecordCache, CacheLoadResult, SignedManifestCache,
};

// Hardware information and limitations
#[cfg(feature = "host")]
pub use hardware_info::{HardwareInfo, HardwareLimitation, SecurityAdvisory};
