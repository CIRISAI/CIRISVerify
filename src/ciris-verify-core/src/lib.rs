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

pub mod cache;
pub mod config;
pub mod dns;
pub mod engine;
pub mod error;
pub mod https;
pub mod jwt;
pub mod license;
pub mod revocation;
pub mod security;
pub mod types;
pub mod validation;
pub mod watchdog;

pub use cache::{CachedLicense, LicenseCache};
pub use config::VerifyConfig;
pub use engine::LicenseEngine;
pub use error::VerifyError;
pub use jwt::{HybridJwt, HybridJwtParser, JwtError};
pub use license::{LicenseDetails, LicenseStatus, LicenseType};
pub use revocation::{RevocationChecker, RevocationStatus};
pub use security::{constant_time_eq, IntegrityChecker, IntegrityStatus};
pub use types::{
    CapabilityCheckRequest, CapabilityCheckResponse, EnforcementAction, LicenseStatusRequest,
    LicenseStatusResponse, MandatoryDisclosure, RuntimeValidation, RuntimeViolation,
    ShutdownDirective, ShutdownType, ViolationSeverity,
};
pub use watchdog::ShutdownWatchdog;
