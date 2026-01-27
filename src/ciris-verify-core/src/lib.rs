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
#![warn(clippy::pedantic)]

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

pub use cache::{CachedLicense, LicenseCache};
pub use config::VerifyConfig;
pub use engine::LicenseEngine;
pub use error::VerifyError;
pub use jwt::{HybridJwt, HybridJwtParser, JwtError};
pub use license::{LicenseDetails, LicenseStatus, LicenseType};
pub use revocation::{RevocationChecker, RevocationStatus};
pub use security::{IntegrityChecker, IntegrityStatus, constant_time_eq};
pub use types::{
    LicenseStatusRequest, LicenseStatusResponse,
    CapabilityCheckRequest, CapabilityCheckResponse,
    MandatoryDisclosure,
};
