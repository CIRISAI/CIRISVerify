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
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
//! │  │ DnsValidator │  │ HttpsClient  │  │ LicenseCache │      │
//! │  │ (multi-src)  │  │ (cert pin)   │  │ (encrypted)  │      │
//! │  └──────────────┘  └──────────────┘  └──────────────┘      │
//! │                           │                                  │
//! │                           ▼                                  │
//! │  ┌──────────────────────────────────────────────────┐      │
//! │  │              ConsensusValidator                   │      │
//! │  │         (2-of-3 source agreement)                │      │
//! │  └──────────────────────────────────────────────────┘      │
//! │                           │                                  │
//! │                           ▼                                  │
//! │  ┌──────────────────────────────────────────────────┐      │
//! │  │              LicenseVerifier                      │      │
//! │  │    (JWT parsing, dual signature verification)    │      │
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

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::pedantic)] // Too strict for production code
#![allow(clippy::doc_markdown)] // Allow product names without backticks
#![allow(clippy::missing_errors_doc)] // Error documentation not required
#![allow(clippy::missing_panics_doc)] // Panic documentation not required
#![allow(clippy::module_name_repetitions)] // Allow Type in module::Type
#![allow(clippy::must_use_candidate)] // Not all functions need must_use

pub mod app_attest;
pub mod attest_bundle;
pub mod attest_heartbeat;
pub mod audit;
pub mod binary_format;
pub mod cache;
pub mod ceg_error;
pub mod ceg_outbox;
pub mod config;
pub mod dns;
pub mod doc_integrity;
pub mod engine;
pub mod error;
pub mod fedcode;
pub mod federation_envelope;
pub mod federation_identity;
pub mod federation_keyset;
pub mod federation_provenance;
pub mod federation_self_record;
pub mod hardware_info;
pub mod holds_bytes;
/// §19 Holonomic substrate verifiers (CEG 1.0-RC11, CIRISVerify#78) — ALM
/// capacity authenticity, fountain holding claims, WholenessWitness divergence
/// detection + equivocation, recursive trust bootstrap, A/V chunk nonces. All
/// ride the §19.0 binary signed-preimage framing + the PQC-mandatory gate.
pub mod holonomic;
pub mod http_client;
pub mod https;
pub mod humanity_accord;
pub mod infrastructure_community;
pub mod jcs;
pub mod jwt;
pub mod keys;
pub mod license;
pub mod locale_merkle;
pub mod manifest_cache;
#[cfg(any(target_os = "android", target_os = "ios"))]
pub mod mobile_http;
pub mod operational_admit;
pub mod parallel_race;
pub mod play_integrity;
pub mod provenance;
pub mod reconsider_dos;
pub mod registry;
pub mod revocation;
pub mod security;
pub mod self_at_login;
pub mod skill_import;
pub mod steward_key;
pub mod threshold;
pub mod tpm_attest;
pub mod transparency;
pub mod transport_binding;
pub mod tree_verify;
pub mod types;
pub mod unified;
pub mod validation;
pub mod watchdog;
/// WebAuthn / FIDO2 passkey assertion verification — the presence/unlock factor
/// for a user identity (authenticator apps: Google, Microsoft, Apple/Android).
/// CIRISVerify#80.
pub mod webauthn;
pub mod witness_relation;

pub use attest_bundle::{
    AttestBundle, AttestationFact, HardwareCustody, ProvenanceBlock, TransparencyLogBlock,
};
pub use cache::{CachedLicense, LicenseCache};
pub use ceg_error::{CegError, CegErrorCode};
pub use config::{TrustModel, VerifyConfig};
pub use engine::LicenseEngine;
pub use error::VerifyError;
pub use federation_envelope::{
    EnvelopePurpose, EnvelopeVerifyPolicy, FederationEnvelope, TransportEpochGuard,
    TransportIdentity, ENVELOPE_DOMAIN_SEP, ENVELOPE_SCHEMA_VERSION,
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
    INVOCATION_DOMAIN_PREFIX,
};
pub use jwt::{HybridJwt, HybridJwtParser, JwtError};
pub use keys::{
    derive_symmetric_key, derive_transport_identity, DERIVED_KEY_LEN, TRANSPORT_SEED_LEN,
};
pub use license::{LicenseDetails, LicenseStatus, LicenseType};
pub use locale_merkle::{
    locale_leaf_to_attestation_entries, merkle_root, parent_hash, verify_locale_inclusion,
    LocaleInclusionProof, LocaleLeaf, LOCALE_LEAF_DOMAIN_PREFIX, RFC6962_LEAF_PREFIX,
    RFC6962_PARENT_PREFIX,
};
pub use provenance::{
    verify_provenance_chain, verify_provenance_chain_with_policy, ProvenanceChain, ProvenanceError,
    ProvenanceLink, MAX_PROVENANCE_DEPTH, STEWARD_IDENTITY_TYPE,
};
pub use reconsider_dos::{
    ActorBudget, ActorBudgetExhausted, EventRateLimit, EventRateLimited, FilingOutcome,
    HarassmentClusterDetected, HarassmentClusterSignal, ReconsiderDosGuard, ReconsiderRejection,
    DEFAULT_ACTOR_BUDGET, DEFAULT_BUDGET_WINDOW_MS, DEFAULT_EVENT_RATE_LIMIT,
    DEFAULT_HARASSMENT_CLUSTER_THRESHOLD,
};
pub use revocation::{RevocationChecker, RevocationStatus};
pub use security::file_integrity::{
    check_available as check_available_agent_integrity, check_full as check_agent_integrity,
    check_spot as spot_check_agent_integrity, generate_manifest, load_manifest,
    FileIntegrityResult, FileManifest,
};
pub use security::{constant_time_eq, IntegrityChecker, IntegrityStatus};
pub use skill_import::{
    verify_skill_import_manifest, SkillImportManifest, SourceType, SKILL_IMPORT_DOMAIN_PREFIX,
};
pub use steward_key::{
    verify_steward_key_response, CertValiditySelfAttest, ResponseSignature, Steward,
    StewardKeyResponse, ThresholdPolicy, STEWARD_KEY_RESPONSE_DOMAIN_PREFIX,
};
pub use threshold::{
    verify_threshold_signatures, verify_threshold_signatures_with_policy, HybridPolicy,
    ThresholdError, ThresholdMember, ThresholdSignature,
};
pub use transparency::{
    verify_consistency, verify_inclusion, ConsistencyProof, InMemoryTransparencyStore, MerkleProof,
    ProofChain, SignedTreeHead, TransparencyEntry, TransparencyError, TransparencyLeaf,
    TransparencyLog, TransparencyStore, TrustedWitness, WitnessConsistencyProof, WitnessSignature,
};
pub use types::{
    AttestationProof, BinaryIntegrityStatus, CapabilityCheckRequest, CapabilityCheckResponse,
    EnforcementAction, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    RuntimeValidation, RuntimeViolation, ShutdownDirective, ShutdownType, ViolationSeverity,
};
pub use watchdog::ShutdownWatchdog;
pub use witness_relation::{
    admit_attestation, admit_with_declared_relation, AdmissionDecision, EnvelopeMetadata,
    OversightMode, WitnessRelation,
};

// Audit trail verification
pub use audit::{
    read_audit_from_jsonl, read_audit_from_sqlite, verify_audit_database, verify_audit_full,
    verify_audit_json, verify_audit_jsonl, AuditEntry, AuditVerificationResult, AuditVerifier,
    ChainSummary,
};
pub use registry::{
    compute_ed25519_fingerprint, compute_self_hash, current_target, verify_self_against_manifest,
    BinaryManifest, BuildRecord, FileManifest as RegistryManifest, KeyVerificationResponse,
    RegistryClient,
};
pub use tree_verify::{
    verify_tree, FailedFile, FailedFileKind, TreeVerifyRequest, TreeVerifyResult,
};
pub use unified::{
    FullAttestationRequest, FullAttestationResult, IntegrityCheckResult, PythonIntegrityResult,
    PythonModuleHashes, SourceCheckResult, UnifiedAttestationEngine,
};

// Manifest cache for offline L1 verification
pub use manifest_cache::{
    load_and_verify as load_manifest_cache, BuildRecordCache, CacheLoadResult, SignedManifestCache,
};

// Hardware information and limitations
pub use hardware_info::{HardwareInfo, HardwareLimitation, SecurityAdvisory};
