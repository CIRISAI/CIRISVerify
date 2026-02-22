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

pub mod audit;
pub mod cache;
pub mod config;
pub mod dns;
pub mod engine;
pub mod error;
pub mod https;
pub mod jwt;
pub mod license;
pub mod registry;
pub mod revocation;
pub mod security;
pub mod transparency;
pub mod types;
pub mod unified;
pub mod validation;
pub mod watchdog;

pub use cache::{CachedLicense, LicenseCache};
pub use config::{TrustModel, VerifyConfig};
pub use engine::LicenseEngine;
pub use error::VerifyError;
pub use jwt::{HybridJwt, HybridJwtParser, JwtError};
pub use license::{LicenseDetails, LicenseStatus, LicenseType};
pub use revocation::{RevocationChecker, RevocationStatus};
pub use security::file_integrity::{
    check_full as check_agent_integrity, check_spot as spot_check_agent_integrity,
    generate_manifest, load_manifest, FileIntegrityResult, FileManifest,
};
pub use security::{constant_time_eq, IntegrityChecker, IntegrityStatus};
pub use transparency::{MerkleProof, ProofChain, TransparencyEntry, TransparencyLog};
pub use types::{
    AttestationProof, BinaryIntegrityStatus, CapabilityCheckRequest, CapabilityCheckResponse,
    EnforcementAction, LicenseStatusRequest, LicenseStatusResponse, MandatoryDisclosure,
    RuntimeValidation, RuntimeViolation, ShutdownDirective, ShutdownType, ViolationSeverity,
};
pub use watchdog::ShutdownWatchdog;

// Audit trail verification
pub use audit::{
    AuditEntry, AuditVerificationResult, AuditVerifier, ChainSummary,
    read_audit_from_sqlite, read_audit_from_jsonl,
    verify_audit_database, verify_audit_jsonl, verify_audit_full, verify_audit_json,
};
pub use registry::{
    compute_self_hash, current_target, verify_self_against_manifest, BinaryManifest, BuildRecord,
    FileManifest as RegistryManifest, RegistryClient,
};
pub use unified::{
    FullAttestationRequest, FullAttestationResult, IntegrityCheckResult, SourceCheckResult,
    UnifiedAttestationEngine,
};
