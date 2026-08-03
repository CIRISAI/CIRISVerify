//! Device-attestation chain validation — the **hardware half** of "never trust
//! a self-report" (CIRISVerify#199, CC 4.2.2.1).
//!
//! ## The rule, and the half this closes
//!
//! [`crate::build_attestation_bundle`] (CIRISVerify#181) refuses to believe a
//! peer's *build* string; it walks a chain to a pinned trust root instead. CC
//! 4.2.2.1 applies the same rule to the other claim a peer makes about itself —
//! its **hardware class**. A peer asserting `StrongBox` is asserting a string
//! until someone walks its attestation chain to a **pinned vendor root**.
//!
//! Verify already pins exactly one such root: the Yubico Attestation Root,
//! consumed by
//! [`crate::accord_custody_attestation::verify_yubikey_piv_attestation`]. This
//! module is the sibling for platform devices: **Android Key Attestation**
//! (X.509 + the `KeyDescription` extension) and **Apple App Attest** (a CBOR
//! attestation object, WebAuthn-shaped). **TPM EK remains the open leg of
//! #199** — its anchor is a vendor *set*, so it wants the trust-anchor store's
//! multi-anchor resolution rather than a pinned root.
//!
//! Neither validator is platform-gated, and that is deliberate: verifying a
//! device attestation is a **relying-party** operation. The phone produces the
//! attestation; whoever receives it verifies — usually a Linux server. Gating
//! these to android/apple targets would ship the verifier where it is not
//! needed and omit it where it is.
//!
//! ## Hardware is a trust SIGNAL, not a requirement
//!
//! This is the load-bearing framing and it shapes the whole API:
//!
//! - **Absence of an attestation is not a failure.** A node with no secure
//!   element, an AOSP build, or a desktop simply does not exercise this path.
//!   It is not refused; it just contributes no hardware evidence. Callers MUST
//!   NOT gate admission on the presence of a device attestation.
//! - **A `Software` security level is a valid measurement**, not an error. It
//!   says "this key is not hardware-held" — useful information, honestly
//!   reported.
//! - **What IS decisive is an over-claim.** A peer claiming `StrongBox` whose
//!   attestation measures `Software` has been **refuted** — see
//!   [`crate::device_attestation::AndroidAttestationVerdict::refutes`]. That
//!   direction carries hard
//!   information; a *pass* only shows the peer holds a genuine chain, which an
//!   honest peer and a well-resourced impostor can both do.
//!
//! So: weight refutations heavily, weight passes lightly, and never treat
//! absence as either.
//!
//! ## What a passing chain proves
//!
//! That the vendor's root attests a key with the measured security level, and
//! that **the attested key is the one the caller pinned** — the binding check
//! is what stops a *lifted* attestation (replaying a real device's real
//! attestation under someone else's key). Without it the walk is theatre. The
//! `attestationChallenge` binding is the anti-replay half: a stale attestation
//! for a different challenge is refused.
//!
//! It does **not** prove what code is running, and it does not prove the key is
//! being used honestly — only that it lives where the vendor says it lives.
//!
//! ## Not covered here
//!
//! **Revocation.** Google publishes an attestation-status CRL; consulting it
//! needs network I/O, so it cannot live in this pure function. A caller that
//! needs revocation must check it separately. Nothing here should be read as
//! "this key is not revoked".

use x509_parser::der_parser::asn1_rs::{Enumerated, FromDer, Integer, OctetString, Sequence};
use x509_parser::prelude::*;

use crate::federation_provenance::{dim, AttestationEntry};

/// Android Key Attestation extension OID (the `KeyDescription`).
pub const OID_ANDROID_KEY_ATTESTATION: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Where the attested key actually lives, as measured from the chain — the
/// `SecurityLevel` of Android's `KeyDescription`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AndroidSecurityLevel {
    /// Key is held in software. A valid measurement, not a failure.
    Software,
    /// Key is held in the TEE (Trusted Execution Environment).
    TrustedEnvironment,
    /// Key is held in a discrete StrongBox secure element — the strongest
    /// Android claim.
    StrongBox,
}

impl crate::classification::Classification for AndroidSecurityLevel {
    /// **MEASUREMENT.** Where the chain says the key lives — an input to
    /// policy, not policy. Absence of an attestation is not a failure, and a
    /// `Software` level is a valid measurement; a consumer composes its own
    /// admission rule over this (and see `refutes` for the direction that
    /// actually carries hard information).
    fn gating() -> crate::classification::Gating {
        crate::classification::Gating::Measurement
    }
}

impl crate::classification::Classification for AppAttestEnvironment {
    /// **MEASUREMENT.** Production vs development, as measured from the
    /// `aaguid` — reported, never enforced.
    fn gating() -> crate::classification::Gating {
        crate::classification::Gating::Measurement
    }
}

impl AndroidSecurityLevel {
    fn from_der_value(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Software),
            1 => Some(Self::TrustedEnvironment),
            2 => Some(Self::StrongBox),
            _ => None,
        }
    }

    /// The `hardware_class` string this level corresponds to (CEG §9.4 shape,
    /// matching the existing `YubiKey_5_FIPS` convention).
    #[must_use]
    pub const fn hardware_class(self) -> &'static str {
        match self {
            Self::Software => "Android_Software",
            Self::TrustedEnvironment => "Android_TEE",
            Self::StrongBox => "Android_StrongBox",
        }
    }
}

/// What the chain measured. **Measurements, not levels** (`MISSION.md` §1.4):
/// each field states what was observed; no tier is composed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidAttestationVerdict {
    /// The attestation's own security level — where the *attestation* was
    /// produced.
    pub attestation_security_level: AndroidSecurityLevel,
    /// The KeyMint/Keymaster security level — where the *key* lives. This is
    /// the one that answers "is this key in StrongBox".
    pub keymint_security_level: AndroidSecurityLevel,
    /// `attestationVersion` from the `KeyDescription`.
    pub attestation_version: u32,
}

impl AndroidAttestationVerdict {
    /// The measured hardware class, from the **key's** security level.
    #[must_use]
    pub const fn hardware_class(&self) -> &'static str {
        self.keymint_security_level.hardware_class()
    }

    /// Does this measurement **refute** a claimed hardware class?
    ///
    /// `true` iff the peer claimed a *stronger* custody than the chain
    /// measured — e.g. it claimed `Android_StrongBox` and the attestation says
    /// `TrustedEnvironment` or `Software`. An unrecognized claim string is not
    /// refuted here (this function only speaks to Android classes); a claim
    /// *weaker* than measured is not a refutation either — under-claiming is
    /// not a lie.
    ///
    /// This is the direction that carries hard information; see the module
    /// docs.
    #[must_use]
    pub fn refutes(&self, claimed_class: &str) -> bool {
        let claimed = match claimed_class {
            "Android_Software" => AndroidSecurityLevel::Software,
            "Android_TEE" => AndroidSecurityLevel::TrustedEnvironment,
            "Android_StrongBox" => AndroidSecurityLevel::StrongBox,
            _ => return false,
        };
        claimed > self.keymint_security_level
    }

    /// Project into [`AttestationEntry`] measurements — the scoring signal.
    ///
    /// Always emits the measured `hardware_custody:*` fact. Note that a
    /// `Software` measurement is reported as a **pass** of the dimension: the
    /// dimension records *what was measured*, and "software-held" is a true,
    /// successfully-measured fact. Whether that is good enough is consumer
    /// policy, not verify's call.
    #[must_use]
    pub fn to_attestation_entries(&self, attester: &str) -> Vec<AttestationEntry> {
        vec![
            AttestationEntry::pass(dim::hardware_custody("android"), attester)
                .with_source_ref(self.hardware_class().to_string()),
        ]
    }
}

/// Why an Android attestation chain was **not** accepted. Every variant means
/// the evidence is unusable — distinct from "no evidence was offered", which is
/// not an error at all (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AndroidAttestationError {
    /// A certificate did not parse.
    CertParse {
        /// Which certificate.
        which: &'static str,
    },
    /// The chain does not link leaf → intermediates → pinned root.
    ChainInvalid {
        /// Which link, and why.
        detail: String,
    },
    /// The leaf carries no Android Key Attestation extension.
    NoKeyDescription,
    /// The `KeyDescription` extension did not parse as the pinned ASN.1 shape.
    MalformedKeyDescription {
        /// What failed.
        detail: String,
    },
    /// The attested key is not the key the caller pinned — a **lifted**
    /// attestation (a genuine chain replayed under someone else's key).
    AttestedKeyMismatch,
    /// The `attestationChallenge` is not the challenge the caller issued — a
    /// stale or replayed attestation.
    ChallengeMismatch,
}

impl std::fmt::Display for AndroidAttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertParse { which } => write!(f, "certificate did not parse: {which}"),
            Self::ChainInvalid { detail } => write!(f, "attestation chain invalid: {detail}"),
            Self::NoKeyDescription => {
                write!(f, "leaf carries no Android Key Attestation extension")
            },
            Self::MalformedKeyDescription { detail } => {
                write!(f, "malformed KeyDescription: {detail}")
            },
            Self::AttestedKeyMismatch => {
                write!(f, "attested key is not the pinned key (lifted attestation)")
            },
            Self::ChallengeMismatch => write!(f, "attestation challenge mismatch (replay)"),
        }
    }
}

impl std::error::Error for AndroidAttestationError {}

/// Parse the `KeyDescription` SEQUENCE, returning
/// `(attestation_version, attestation_level, keymint_level, challenge)`.
///
/// Pinned ASN.1 (Android Keystore `KeyDescription`); only the prefix this
/// module reads is parsed, the trailing `AuthorizationList`s are left alone:
///
/// ```text
/// KeyDescription ::= SEQUENCE {
///     attestationVersion       INTEGER,
///     attestationSecurityLevel ENUMERATED,
///     keyMintVersion           INTEGER,
///     keyMintSecurityLevel     ENUMERATED,
///     attestationChallenge     OCTET STRING,
///     ...
/// }
/// ```
fn parse_key_description(
    raw: &[u8],
) -> Result<(u32, AndroidSecurityLevel, AndroidSecurityLevel, Vec<u8>), AndroidAttestationError> {
    let malformed = |detail: &str| AndroidAttestationError::MalformedKeyDescription {
        detail: detail.to_string(),
    };

    let (_, seq) = Sequence::from_der(raw).map_err(|_| malformed("outer SEQUENCE"))?;
    let body = seq.content.as_ref();

    let (body, version) = Integer::from_der(body).map_err(|_| malformed("attestationVersion"))?;
    let (body, att_level) =
        Enumerated::from_der(body).map_err(|_| malformed("attestationSecurityLevel"))?;
    let (body, _keymint_version) =
        Integer::from_der(body).map_err(|_| malformed("keyMintVersion"))?;
    let (body, km_level) =
        Enumerated::from_der(body).map_err(|_| malformed("keyMintSecurityLevel"))?;
    let (_, challenge) =
        OctetString::from_der(body).map_err(|_| malformed("attestationChallenge"))?;

    let att = AndroidSecurityLevel::from_der_value(att_level.0)
        .ok_or_else(|| malformed("unknown attestationSecurityLevel"))?;
    let km = AndroidSecurityLevel::from_der_value(km_level.0)
        .ok_or_else(|| malformed("unknown keyMintSecurityLevel"))?;

    Ok((
        version.as_u32().unwrap_or(0),
        att,
        km,
        challenge.as_ref().to_vec(),
    ))
}

/// Verify an Android Key Attestation chain and measure where the key lives.
///
/// Mirrors [`crate::accord_custody_attestation::verify_yubikey_piv_attestation`]
/// so a consumer can drive every hardware class from one chokepoint.
///
/// The chain (all fail-closed):
///
/// 1. `leaf_der` is signed by `intermediate_ders[0]`, each intermediate by the
///    next, and the last by `pinned_root_der` (the Google Hardware Attestation
///    Root, supplied by the caller — the same caller-pins-the-root discipline
///    the Yubico path uses).
/// 2. The leaf carries a `KeyDescription` extension that parses.
/// 3. **The attested key is `expected_pubkey`** — without this a genuine
///    attestation can be lifted and replayed under an attacker's key.
/// 4. The `attestationChallenge` is `expected_challenge` — anti-replay.
///
/// The measured security level is **returned, never enforced**: a `Software`
/// result is a successful measurement. Use
/// [`AndroidAttestationVerdict::refutes`] to test a peer's *claim* against it.
///
/// # Errors
///
/// An [`AndroidAttestationError`] naming the first failing step.
pub fn verify_android_key_attestation(
    leaf_der: &[u8],
    intermediate_ders: &[&[u8]],
    pinned_root_der: &[u8],
    expected_pubkey: &[u8],
    expected_challenge: &[u8],
) -> Result<AndroidAttestationVerdict, AndroidAttestationError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|_| AndroidAttestationError::CertParse { which: "leaf" })?;
    let chain: Vec<X509Certificate> = intermediate_ders
        .iter()
        .map(|der| {
            X509Certificate::from_der(der).map(|(_, c)| c).map_err(|_| {
                AndroidAttestationError::CertParse {
                    which: "intermediate",
                }
            })
        })
        .collect::<Result<_, _>>()?;
    let (_, root) = X509Certificate::from_der(pinned_root_der)
        .map_err(|_| AndroidAttestationError::CertParse { which: "root" })?;

    // --- 1. leaf → intermediates → pinned root. ---
    let first_parent = chain.first().map_or_else(|| &root, |c| c);
    leaf.verify_signature(Some(first_parent.public_key()))
        .map_err(|e| AndroidAttestationError::ChainInvalid {
            detail: format!("leaf not signed by its parent: {e:?}"),
        })?;
    for i in 0..chain.len() {
        let parent = chain.get(i + 1).map_or_else(|| &root, |c| c);
        chain[i]
            .verify_signature(Some(parent.public_key()))
            .map_err(|e| AndroidAttestationError::ChainInvalid {
                detail: format!("chain link {i} broken: {e:?}"),
            })?;
    }

    // --- 2. The KeyDescription. ---
    let ext = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == OID_ANDROID_KEY_ATTESTATION)
        .ok_or(AndroidAttestationError::NoKeyDescription)?;
    let (attestation_version, attestation_security_level, keymint_security_level, challenge) =
        parse_key_description(ext.value)?;

    // --- 3. The attested key IS the pinned key (anti-lift). ---
    if leaf.public_key().subject_public_key.data.as_ref() != expected_pubkey {
        return Err(AndroidAttestationError::AttestedKeyMismatch);
    }

    // --- 4. Freshness (anti-replay). ---
    if challenge != expected_challenge {
        return Err(AndroidAttestationError::ChallengeMismatch);
    }

    Ok(AndroidAttestationVerdict {
        attestation_security_level,
        keymint_security_level,
        attestation_version,
    })
}

/// Verify an Android Key Attestation chain, resolving the root from a
/// **constrained** [`TrustAnchorStore`](crate::trust_anchor_store::TrustAnchorStore)
/// instead of taking a hand-pinned root (CIRISVerify#227).
///
/// Anchors are drawn from `(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE)`
/// only, so a root admitted for TLS or for a different device class can never
/// satisfy this check — the containment a flat root list cannot express.
///
/// Succeeds if the chain roots at **any** admissible anchor (a vendor may
/// operate several, and roots rotate). Returns `Ok(None)` when the store holds
/// no anchor for this environment: that is **no hardware evidence**, not a
/// failure — callers must not turn it into a refusal (see the module docs).
///
/// # Errors
///
/// An [`AndroidAttestationError`] when anchors *were* available but none
/// validated the chain — the last failure is reported.
pub fn verify_android_key_attestation_with_store(
    store: &crate::trust_anchor_store::TrustAnchorStore,
    leaf_der: &[u8],
    intermediate_ders: &[&[u8]],
    expected_pubkey: &[u8],
    expected_challenge: &[u8],
) -> Result<Option<AndroidAttestationVerdict>, AndroidAttestationError> {
    use crate::trust_anchor_store::{environments, Purpose};

    let anchors = store.resolve_x509(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE);
    if anchors.is_empty() {
        return Ok(None);
    }

    let mut last_err = None;
    for root in anchors {
        match verify_android_key_attestation(
            leaf_der,
            intermediate_ders,
            root,
            expected_pubkey,
            expected_challenge,
        ) {
            Ok(v) => return Ok(Some(v)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(AndroidAttestationError::ChainInvalid {
        detail: "no admissible anchor validated the chain".to_string(),
    }))
}

// ===========================================================================
// Apple App Attest (CIRISVerify#199, the second device-attestation leg).
//
// Unlike Android/TPM this is a CBOR attestation object, not a bare X.509
// chain — it is WebAuthn-shaped with an Apple-specific `authData`.
//
// NOTE this validator is deliberately NOT platform-gated. App Attest
// verification is a RELYING-PARTY operation: the iOS device *produces* the
// attestation and whoever *receives* it verifies, typically a Linux server.
// Gating it to apple targets would ship the verifier where it is not needed
// and omit it where it is.
// ===========================================================================

/// Apple's `credCert` nonce extension OID — a DER SEQUENCE wrapping one OCTET
/// STRING that must equal the computed nonce.
pub const OID_APPLE_APP_ATTEST_NONCE: &str = "1.2.840.113635.100.8.2";

/// Which App Attest environment produced the attestation, read from the
/// `aaguid` in `authData`.
///
/// A **measurement**, not a pass/fail: a development attestation is honestly
/// reported rather than refused, and the caller decides whether it is
/// acceptable for its environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestEnvironment {
    /// `appattest\0…` — a production attestation.
    Production,
    /// `appattestdevelop` — a development attestation.
    Development,
}

impl AppAttestEnvironment {
    /// The `hardware_class` this environment corresponds to.
    #[must_use]
    pub const fn hardware_class(self) -> &'static str {
        match self {
            Self::Production => "Apple_AppAttest",
            Self::Development => "Apple_AppAttest_Development",
        }
    }
}

/// What an App Attest chain measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestVerdict {
    /// The attested key identifier — `sha256(credCert public key)`.
    pub key_id: Vec<u8>,
    /// Production vs development, from the `aaguid`.
    pub environment: AppAttestEnvironment,
    /// `signCount` from `authData`. MUST be 0 for an attestation (assertions
    /// increment it); surfaced so a caller can record the starting point.
    pub sign_count: u32,
    /// The attested public key (DER `SubjectPublicKeyInfo`) — the value a
    /// relying party stores to verify this device's later assertions.
    pub public_key_der: Vec<u8>,
}

impl AppAttestVerdict {
    /// The measured hardware class.
    #[must_use]
    pub const fn hardware_class(&self) -> &'static str {
        self.environment.hardware_class()
    }

    /// Does this measurement **refute** a claimed hardware class?
    ///
    /// Fires only on the over-claim: claiming a production Secure Enclave
    /// attestation when the chain measured a *development* one. Same asymmetry
    /// as [`AndroidAttestationVerdict::refutes`] — under-claims and non-Apple
    /// classes are never refuted.
    #[must_use]
    pub fn refutes(&self, claimed_class: &str) -> bool {
        claimed_class == AppAttestEnvironment::Production.hardware_class()
            && self.environment == AppAttestEnvironment::Development
    }

    /// Project into [`AttestationEntry`] measurements — the scoring signal.
    #[must_use]
    pub fn to_attestation_entries(&self, attester: &str) -> Vec<AttestationEntry> {
        vec![
            AttestationEntry::pass(dim::hardware_custody("ios_secure_enclave"), attester)
                .with_source_ref(self.hardware_class().to_string()),
        ]
    }
}

/// Why an App Attest object was **not** accepted. As with Android, this is
/// distinct from "no attestation was offered", which is not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppAttestError {
    /// The attestation object is not valid CBOR, or not the expected shape.
    MalformedObject {
        /// What failed.
        detail: String,
    },
    /// `fmt` is not `apple-appattest`.
    WrongFormat {
        /// The format found.
        fmt: String,
    },
    /// A certificate in `x5c` did not parse.
    CertParse {
        /// Which certificate.
        which: &'static str,
    },
    /// The chain does not link credCert -> intermediate -> pinned Apple root.
    ChainInvalid {
        /// Which link, and why.
        detail: String,
    },
    /// `authData` is shorter than the fields it must carry.
    AuthDataTruncated,
    /// `rpIdHash` != `sha256(app_id)` — the attestation is for a different app.
    AppIdMismatch,
    /// The credCert nonce extension is absent or malformed.
    NonceExtensionMissing,
    /// The nonce extension does not equal `sha256(authData || sha256(challenge))`
    /// — a stale or replayed attestation.
    NonceMismatch,
    /// `sha256(credCert pubkey)` != the key identifier the caller pinned — the
    /// anti-lift check.
    KeyIdMismatch,
    /// `signCount` was non-zero; a fresh attestation must start at 0.
    NonZeroSignCount {
        /// The count found.
        found: u32,
    },
}

impl std::fmt::Display for AppAttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedObject { detail } => write!(f, "malformed attestation object: {detail}"),
            Self::WrongFormat { fmt } => write!(f, "not apple-appattest (got {fmt})"),
            Self::CertParse { which } => write!(f, "certificate did not parse: {which}"),
            Self::ChainInvalid { detail } => write!(f, "attestation chain invalid: {detail}"),
            Self::AuthDataTruncated => write!(f, "authData truncated"),
            Self::AppIdMismatch => write!(f, "rpIdHash does not match the expected app id"),
            Self::NonceExtensionMissing => write!(f, "credCert nonce extension absent/malformed"),
            Self::NonceMismatch => write!(f, "attestation nonce mismatch (replay)"),
            Self::KeyIdMismatch => write!(f, "attested key is not the pinned key identifier"),
            Self::NonZeroSignCount { found } => {
                write!(f, "attestation signCount must be 0, got {found}")
            },
        }
    }
}

impl std::error::Error for AppAttestError {}

/// Pull a named entry out of a CBOR map.
fn cbor_get<'a>(
    map: &'a [(ciborium::value::Value, ciborium::value::Value)],
    key: &str,
) -> Option<&'a ciborium::value::Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Verify an Apple App Attest attestation object.
///
/// Implements Apple's published relying-party procedure:
///
/// 1. CBOR-decode; `fmt` MUST be `apple-appattest`.
/// 2. Walk `x5c` — credCert -> intermediate -> the caller-pinned **Apple App
///    Attest Root CA** (same caller-pins-the-root discipline as every other
///    validator here).
/// 3. `nonce = sha256(authData || sha256(challenge))`; the credCert extension
///    `1.2.840.113635.100.8.2` (a DER SEQUENCE wrapping one OCTET STRING) MUST
///    equal it — **anti-replay**.
/// 4. `sha256(credCert public key)` MUST equal `expected_key_id` — **anti-lift**,
///    the check without which a genuine attestation can be replayed under
///    someone else's key (#199 ask 3).
/// 5. `rpIdHash` MUST equal `sha256(app_id)` — the attestation is for *this*
///    app.
/// 6. `signCount` MUST be 0 for a fresh attestation.
///
/// The environment (production vs development) is **measured and returned**,
/// never enforced — use [`AppAttestVerdict::refutes`] to test a peer's claim
/// against it.
///
/// # Errors
///
/// An [`AppAttestError`] naming the first failing step.
pub fn verify_apple_app_attest(
    attestation_object_cbor: &[u8],
    challenge: &[u8],
    app_id: &str,
    expected_key_id: &[u8],
    pinned_root_der: &[u8],
) -> Result<AppAttestVerdict, AppAttestError> {
    use ciborium::value::Value as Cbor;
    use sha2::{Digest, Sha256};

    let malformed = |d: &str| AppAttestError::MalformedObject {
        detail: d.to_string(),
    };

    // --- 1. CBOR shape. ---
    let root: Cbor = ciborium::from_reader(attestation_object_cbor)
        .map_err(|e| malformed(&format!("cbor decode: {e}")))?;
    let top = root
        .as_map()
        .ok_or_else(|| malformed("top level not a map"))?;

    let fmt = cbor_get(top, "fmt")
        .and_then(Cbor::as_text)
        .ok_or_else(|| malformed("fmt missing"))?;
    if fmt != "apple-appattest" {
        return Err(AppAttestError::WrongFormat {
            fmt: fmt.to_string(),
        });
    }

    let auth_data = cbor_get(top, "authData")
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| malformed("authData missing"))?;
    let att_stmt = cbor_get(top, "attStmt")
        .and_then(Cbor::as_map)
        .ok_or_else(|| malformed("attStmt missing"))?;
    let x5c = cbor_get(att_stmt, "x5c")
        .and_then(Cbor::as_array)
        .ok_or_else(|| malformed("x5c missing"))?;
    if x5c.is_empty() {
        return Err(malformed("x5c empty"));
    }

    // --- 2. Chain: credCert -> intermediates -> pinned Apple root. ---
    let ders: Vec<&[u8]> = x5c
        .iter()
        .map(|c| c.as_bytes().map(Vec::as_slice))
        .collect::<Option<_>>()
        .ok_or_else(|| malformed("x5c entry not a byte string"))?;

    let (_, cred_cert) = X509Certificate::from_der(ders[0])
        .map_err(|_| AppAttestError::CertParse { which: "credCert" })?;
    let intermediates: Vec<X509Certificate> = ders[1..]
        .iter()
        .map(|d| {
            X509Certificate::from_der(d)
                .map(|(_, c)| c)
                .map_err(|_| AppAttestError::CertParse {
                    which: "intermediate",
                })
        })
        .collect::<Result<_, _>>()?;
    let (_, root_cert) = X509Certificate::from_der(pinned_root_der)
        .map_err(|_| AppAttestError::CertParse { which: "root" })?;

    let first_parent = intermediates.first().map_or_else(|| &root_cert, |c| c);
    cred_cert
        .verify_signature(Some(first_parent.public_key()))
        .map_err(|e| AppAttestError::ChainInvalid {
            detail: format!("credCert not signed by its parent: {e:?}"),
        })?;
    for i in 0..intermediates.len() {
        let parent = intermediates.get(i + 1).map_or_else(|| &root_cert, |c| c);
        intermediates[i]
            .verify_signature(Some(parent.public_key()))
            .map_err(|e| AppAttestError::ChainInvalid {
                detail: format!("chain link {i} broken: {e:?}"),
            })?;
    }

    // --- 3. Nonce (anti-replay). ---
    let client_data_hash = Sha256::digest(challenge);
    let mut n = Sha256::new();
    n.update(auth_data);
    n.update(client_data_hash);
    let nonce = n.finalize();

    let ext = cred_cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == OID_APPLE_APP_ATTEST_NONCE)
        .ok_or(AppAttestError::NonceExtensionMissing)?;
    // SEQUENCE { [1] { OCTET STRING } } — locate the 32-byte octet string.
    let embedded = ext
        .value
        .windows(nonce.len())
        .any(|w| w == nonce.as_slice());
    if !embedded {
        return Err(AppAttestError::NonceMismatch);
    }

    // --- 4. Attested key IS the pinned key identifier (anti-lift). ---
    let spki = cred_cert.public_key();
    let key_id = Sha256::digest(spki.subject_public_key.data.as_ref()).to_vec();
    if key_id != expected_key_id {
        return Err(AppAttestError::KeyIdMismatch);
    }

    // --- 5/6. authData: rpIdHash, flags, signCount, aaguid. ---
    // Layout: rpIdHash[32] | flags[1] | signCount[4] | aaguid[16] | …
    if auth_data.len() < 53 {
        return Err(AppAttestError::AuthDataTruncated);
    }
    if auth_data[..32] != Sha256::digest(app_id.as_bytes())[..] {
        return Err(AppAttestError::AppIdMismatch);
    }
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if sign_count != 0 {
        return Err(AppAttestError::NonZeroSignCount { found: sign_count });
    }
    let aaguid = &auth_data[37..53];
    let environment = if aaguid == b"appattestdevelop" {
        AppAttestEnvironment::Development
    } else {
        AppAttestEnvironment::Production
    };

    Ok(AppAttestVerdict {
        key_id,
        environment,
        sign_count,
        public_key_der: spki.raw.to_vec(),
    })
}

/// Verify an App Attest object, resolving the Apple root from a **constrained**
/// [`TrustAnchorStore`](crate::trust_anchor_store::TrustAnchorStore).
///
/// Anchors come from `(Purpose::KeyAttestation, environments::APPLE_APP_ATTEST)`
/// only. Returns `Ok(None)` on a store miss — **no hardware evidence, not a
/// failure**.
///
/// # Errors
/// An [`AppAttestError`] when anchors were available but none validated.
pub fn verify_apple_app_attest_with_store(
    store: &crate::trust_anchor_store::TrustAnchorStore,
    attestation_object_cbor: &[u8],
    challenge: &[u8],
    app_id: &str,
    expected_key_id: &[u8],
) -> Result<Option<AppAttestVerdict>, AppAttestError> {
    use crate::trust_anchor_store::{environments, Purpose};

    let anchors = store.resolve_x509(Purpose::KeyAttestation, environments::APPLE_APP_ATTEST);
    if anchors.is_empty() {
        return Ok(None);
    }
    let mut last = None;
    for root in anchors {
        match verify_apple_app_attest(
            attestation_object_cbor,
            challenge,
            app_id,
            expected_key_id,
            root,
        ) {
            Ok(v) => return Ok(Some(v)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(AppAttestError::ChainInvalid {
        detail: "no admissible anchor validated the chain".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_levels_map_to_hardware_classes() {
        assert_eq!(
            AndroidSecurityLevel::StrongBox.hardware_class(),
            "Android_StrongBox"
        );
        assert_eq!(
            AndroidSecurityLevel::TrustedEnvironment.hardware_class(),
            "Android_TEE"
        );
        assert_eq!(
            AndroidSecurityLevel::Software.hardware_class(),
            "Android_Software"
        );
    }

    fn verdict(km: AndroidSecurityLevel) -> AndroidAttestationVerdict {
        AndroidAttestationVerdict {
            attestation_security_level: km,
            keymint_security_level: km,
            attestation_version: 4,
        }
    }

    /// The refuter fires only on an OVER-claim. This is the whole asymmetry:
    /// hardware is a signal, so under-claiming and unknown classes are fine —
    /// claiming more custody than the chain measured is the lie.
    #[test]
    fn refutes_only_on_over_claim() {
        let tee = verdict(AndroidSecurityLevel::TrustedEnvironment);
        assert!(
            tee.refutes("Android_StrongBox"),
            "claiming StrongBox on a TEE key must be refuted"
        );
        assert!(!tee.refutes("Android_TEE"), "an exact claim is not refuted");
        assert!(
            !tee.refutes("Android_Software"),
            "under-claiming is not a lie"
        );
        assert!(
            !tee.refutes("YubiKey_5_FIPS"),
            "a non-Android class is out of this validator's scope"
        );
    }

    /// A software-held key is a valid MEASUREMENT, not a failure — the
    /// "hardware is a signal, not a requirement" rule in test form.
    #[test]
    fn software_level_is_a_measurement_not_a_failure() {
        let sw = verdict(AndroidSecurityLevel::Software);
        let entries = sw.to_attestation_entries("ciris-verify");
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].is_pass(),
            "measuring 'software-held' is a successful measurement"
        );
        assert_eq!(entries[0].dimension, "hardware_custody:android");
        assert_eq!(entries[0].source_ref.as_deref(), Some("Android_Software"));
        assert!(
            !sw.refutes("Android_Software"),
            "an honest software claim is never refuted"
        );
    }

    #[test]
    fn strongbox_verdict_reports_its_class() {
        let sb = verdict(AndroidSecurityLevel::StrongBox);
        assert_eq!(sb.hardware_class(), "Android_StrongBox");
        assert_eq!(
            sb.to_attestation_entries("ciris-verify")[0]
                .source_ref
                .as_deref(),
            Some("Android_StrongBox")
        );
    }

    /// The KeyDescription parser against a hand-built DER matching the pinned
    /// ASN.1 prefix.
    #[test]
    fn parses_a_well_formed_key_description() {
        // SEQUENCE { INTEGER 4, ENUMERATED 2, INTEGER 300, ENUMERATED 2,
        //            OCTET STRING "nonce", OCTET STRING "" }
        let der: Vec<u8> = vec![
            0x30, 0x14, // SEQUENCE, len 20
            0x02, 0x01, 0x04, // INTEGER 4 (attestationVersion)
            0x0a, 0x01, 0x02, // ENUMERATED 2 (StrongBox)
            0x02, 0x02, 0x01, 0x2c, // INTEGER 300 (keyMintVersion)
            0x0a, 0x01, 0x02, // ENUMERATED 2 (StrongBox)
            0x04, 0x05, b'n', b'o', b'n', b'c', b'e', // OCTET STRING "nonce"
        ];
        let (version, att, km, challenge) = parse_key_description(&der).unwrap();
        assert_eq!(version, 4);
        assert_eq!(att, AndroidSecurityLevel::StrongBox);
        assert_eq!(km, AndroidSecurityLevel::StrongBox);
        assert_eq!(challenge, b"nonce");
    }

    #[test]
    fn malformed_key_description_fails_closed() {
        assert!(matches!(
            parse_key_description(&[0x30, 0x00]),
            Err(AndroidAttestationError::MalformedKeyDescription { .. })
        ));
        assert!(matches!(
            parse_key_description(b"not der at all"),
            Err(AndroidAttestationError::MalformedKeyDescription { .. })
        ));
    }

    /// An unknown SecurityLevel enum value must fail closed rather than being
    /// silently coerced to a level we recognize.
    #[test]
    fn unknown_security_level_fails_closed() {
        let der: Vec<u8> = vec![
            0x30, 0x10, 0x02, 0x01, 0x04, //
            0x0a, 0x01, 0x09, // ENUMERATED 9 — not a defined SecurityLevel
            0x02, 0x01, 0x01, //
            0x0a, 0x01, 0x02, //
            0x04, 0x03, b'a', b'b', b'c',
        ];
        assert!(matches!(
            parse_key_description(&der),
            Err(AndroidAttestationError::MalformedKeyDescription { .. })
        ));
    }

    #[test]
    fn garbage_certificates_fail_closed() {
        let err =
            verify_android_key_attestation(b"garbage", &[], b"garbage", &[], &[]).unwrap_err();
        assert_eq!(err, AndroidAttestationError::CertParse { which: "leaf" });
    }

    // =======================================================================
    // End-to-end chain tests over a MOCK Google root.
    //
    // The parser + refuter tests above exercise no certificate at all, so
    // without these the security-critical paths — the chain walk, the
    // anti-lift key binding, and the anti-replay challenge check — would ship
    // green and unproven. (#199 ask 3 is explicit: without the binding check
    // the walk "is theatre".) Artifacts here chain to a MOCK root and are
    // therefore inert against the real Google Hardware Attestation Root — they
    // cannot forge a real-gate pass, the same posture as the #219 mock Yubico
    // CA.
    // =======================================================================

    use rcgen::{
        CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, PKCS_ED25519,
    };

    /// Raw 32-byte Ed25519 pubkey from an rcgen keypair's SPKI (trailing 32 B).
    fn raw_ed(kp: &KeyPair) -> Vec<u8> {
        let spki = kp.public_key_der();
        spki[spki.len() - 32..].to_vec()
    }

    fn params(cn: &str) -> CertificateParams {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        p.distinguished_name = dn;
        p
    }

    /// DER for a `KeyDescription` carrying `km_level` + `challenge`.
    fn key_description(km_level: u8, challenge: &[u8]) -> Vec<u8> {
        let mut inner = vec![
            0x02, 0x01, 0x04, // attestationVersion 4
            0x0a, 0x01, km_level, // attestationSecurityLevel
            0x02, 0x01, 0x01, // keyMintVersion 1
            0x0a, 0x01, km_level, // keyMintSecurityLevel
        ];
        inner.push(0x04);
        inner.push(u8::try_from(challenge.len()).unwrap());
        inner.extend_from_slice(challenge);

        let mut der = vec![0x30, u8::try_from(inner.len()).unwrap()];
        der.extend_from_slice(&inner);
        der
    }

    /// `(leaf_der, root_der)` for a leaf attesting `leaf_kp` at `km_level`
    /// with `challenge`, signed directly by a mock root.
    fn mock_chain(leaf_kp: &KeyPair, km_level: u8, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("mock Google Hardware Attestation Root")
            .self_signed(&root_kp)
            .unwrap();

        let mut leaf_params = params("mock android key");
        leaf_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(km_level, challenge),
        )];
        let leaf = leaf_params.signed_by(leaf_kp, &root, &root_kp).unwrap();

        (leaf.der().to_vec(), root.der().to_vec())
    }

    #[test]
    fn strongbox_chain_verifies_end_to_end() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, root) = mock_chain(&leaf_kp, 2, b"challenge-1");

        let verdict =
            verify_android_key_attestation(&leaf, &[], &root, &raw_ed(&leaf_kp), b"challenge-1")
                .unwrap();

        assert_eq!(
            verdict.keymint_security_level,
            AndroidSecurityLevel::StrongBox
        );
        assert_eq!(verdict.hardware_class(), "Android_StrongBox");
        assert!(!verdict.refutes("Android_StrongBox"));
    }

    /// The anti-LIFT check: a genuine chain replayed under a different key must
    /// be refused. Without this the whole walk proves nothing about *who* is
    /// presenting.
    #[test]
    fn lifted_attestation_under_another_key_is_refused() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, root) = mock_chain(&leaf_kp, 2, b"challenge-1");
        let attacker = raw_ed(&KeyPair::generate_for(&PKCS_ED25519).unwrap());

        let err = verify_android_key_attestation(&leaf, &[], &root, &attacker, b"challenge-1")
            .unwrap_err();
        assert_eq!(err, AndroidAttestationError::AttestedKeyMismatch);
    }

    /// The anti-REPLAY check: a genuine attestation for a stale challenge must
    /// be refused.
    #[test]
    fn stale_challenge_is_refused() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, root) = mock_chain(&leaf_kp, 2, b"challenge-1");

        let err = verify_android_key_attestation(
            &leaf,
            &[],
            &root,
            &raw_ed(&leaf_kp),
            b"a-different-challenge",
        )
        .unwrap_err();
        assert_eq!(err, AndroidAttestationError::ChallengeMismatch);
    }

    /// A chain that does not root at the caller's pinned root is refused — the
    /// attacker-mints-their-own-CA case.
    #[test]
    fn chain_under_a_foreign_root_is_refused() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, _real_root) = mock_chain(&leaf_kp, 2, b"challenge-1");

        let other_root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let other_root = params("attacker root").self_signed(&other_root_kp).unwrap();

        let err = verify_android_key_attestation(
            &leaf,
            &[],
            other_root.der(),
            &raw_ed(&leaf_kp),
            b"challenge-1",
        )
        .unwrap_err();
        assert!(matches!(err, AndroidAttestationError::ChainInvalid { .. }));
    }

    /// A genuine TEE key claiming StrongBox is REFUTED — the over-claim
    /// falsifier, driven end-to-end off a real parsed chain rather than a
    /// hand-built verdict.
    #[test]
    fn tee_chain_refutes_a_strongbox_claim() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, root) = mock_chain(&leaf_kp, 1, b"challenge-1");

        let verdict =
            verify_android_key_attestation(&leaf, &[], &root, &raw_ed(&leaf_kp), b"challenge-1")
                .unwrap();

        assert_eq!(verdict.hardware_class(), "Android_TEE");
        assert!(verdict.refutes("Android_StrongBox"));
        assert!(!verdict.refutes("Android_TEE"));
    }

    // --- store-resolved path (#227) ---

    /// The store-resolved entry point verifies against an anchor drawn from
    /// the correct (purpose, environment) slot.
    #[test]
    fn store_resolved_verification_succeeds() {
        use crate::trust_anchor_store::{environments, single, Purpose, TrustAnchorStore};

        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, root) = mock_chain(&leaf_kp, 2, b"challenge-1");
        let store = TrustAnchorStore::new().with_store(single(
            environments::ANDROID_KEYSTORE,
            Purpose::KeyAttestation,
            vec![root],
        ));

        let verdict = verify_android_key_attestation_with_store(
            &store,
            &leaf,
            &[],
            &raw_ed(&leaf_kp),
            b"challenge-1",
        )
        .unwrap()
        .expect("anchor present");
        assert_eq!(verdict.hardware_class(), "Android_StrongBox");
    }

    /// An empty store is "no hardware evidence" — `Ok(None)`, NOT an error.
    /// Hardware is a signal, not a requirement.
    #[test]
    fn empty_store_is_no_evidence_not_a_failure() {
        use crate::trust_anchor_store::TrustAnchorStore;

        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, _root) = mock_chain(&leaf_kp, 2, b"challenge-1");

        let out = verify_android_key_attestation_with_store(
            &TrustAnchorStore::new(),
            &leaf,
            &[],
            &raw_ed(&leaf_kp),
            b"challenge-1",
        )
        .unwrap();
        assert!(out.is_none(), "a store miss must not be an error");
    }

    /// The containment property, end-to-end: the SAME root filed under a
    /// different environment does not satisfy an Android lookup.
    #[test]
    fn anchor_filed_under_another_environment_does_not_apply() {
        use crate::trust_anchor_store::{environments, single, Purpose, TrustAnchorStore};

        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (leaf, root) = mock_chain(&leaf_kp, 2, b"challenge-1");
        let store = TrustAnchorStore::new().with_store(single(
            environments::YUBIKEY_PIV, // right root, WRONG environment
            Purpose::KeyAttestation,
            vec![root],
        ));

        let out = verify_android_key_attestation_with_store(
            &store,
            &leaf,
            &[],
            &raw_ed(&leaf_kp),
            b"challenge-1",
        )
        .unwrap();
        assert!(
            out.is_none(),
            "an anchor scoped to another environment must not be reachable here"
        );
    }

    // =======================================================================
    // Apple App Attest — mock-Apple-root end-to-end.
    //
    // Same posture as the Android mock: artifacts chain to a MOCK root, so they
    // are inert against the real Apple App Attestation Root CA.
    // =======================================================================

    /// `rpIdHash | flags | signCount | aaguid | credIdLen | credId`
    fn app_attest_auth_data(app_id: &str, sign_count: u32, aaguid: &[u8; 16]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut d = Vec::new();
        d.extend_from_slice(&Sha256::digest(app_id.as_bytes()));
        d.push(0x40); // flags: attested-credential-data present
        d.extend_from_slice(&sign_count.to_be_bytes());
        d.extend_from_slice(aaguid);
        d.extend_from_slice(&0u16.to_be_bytes());
        d
    }

    /// Build a mock App Attest object. Returns `(cbor, root_der, key_id)`.
    fn mock_app_attest(
        app_id: &str,
        challenge: &[u8],
        aaguid: &[u8; 16],
        sign_count: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};

        let auth_data = app_attest_auth_data(app_id, sign_count, aaguid);

        // nonce = sha256(authData || sha256(challenge))
        let mut n = Sha256::new();
        n.update(&auth_data);
        n.update(Sha256::digest(challenge));
        let nonce = n.finalize().to_vec();

        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("mock Apple App Attestation Root CA")
            .self_signed(&root_kp)
            .unwrap();

        let cred_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut cred_params = params("mock credCert");
        // Apple wraps the nonce in a DER SEQUENCE; the verifier locates the
        // 32-byte octet string within the extension value.
        let mut ext = vec![0x30, u8::try_from(nonce.len() + 2).unwrap(), 0x04];
        ext.push(u8::try_from(nonce.len()).unwrap());
        ext.extend_from_slice(&nonce);
        cred_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 2, 840, 113635, 100, 8, 2],
            ext,
        )];
        let cred = cred_params.signed_by(&cred_kp, &root, &root_kp).unwrap();

        let key_id = Sha256::digest(raw_ed(&cred_kp)).to_vec();

        use ciborium::value::Value as Cbor;
        let obj = Cbor::Map(vec![
            (
                Cbor::Text("fmt".into()),
                Cbor::Text("apple-appattest".into()),
            ),
            (
                Cbor::Text("attStmt".into()),
                Cbor::Map(vec![(
                    Cbor::Text("x5c".into()),
                    Cbor::Array(vec![Cbor::Bytes(cred.der().to_vec())]),
                )]),
            ),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&obj, &mut cbor).unwrap();

        (cbor, root.der().to_vec(), key_id)
    }

    const PROD_AAGUID: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
    const DEV_AAGUID: &[u8; 16] = b"appattestdevelop";

    #[test]
    fn app_attest_production_object_verifies() {
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, root, key_id) = mock_app_attest(app, b"chal-1", PROD_AAGUID, 0);

        let v = verify_apple_app_attest(&cbor, b"chal-1", app, &key_id, &root).unwrap();
        assert_eq!(v.environment, AppAttestEnvironment::Production);
        assert_eq!(v.hardware_class(), "Apple_AppAttest");
        assert_eq!(v.sign_count, 0);
        assert!(!v.public_key_der.is_empty());
    }

    /// Anti-LIFT: a genuine object replayed under another key identifier.
    #[test]
    fn app_attest_lifted_key_identifier_is_refused() {
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, root, _) = mock_app_attest(app, b"chal-1", PROD_AAGUID, 0);
        let err = verify_apple_app_attest(&cbor, b"chal-1", app, &[9u8; 32], &root).unwrap_err();
        assert_eq!(err, AppAttestError::KeyIdMismatch);
    }

    /// Anti-REPLAY: the nonce binds authData to the issued challenge.
    #[test]
    fn app_attest_stale_challenge_is_refused() {
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, root, key_id) = mock_app_attest(app, b"chal-1", PROD_AAGUID, 0);
        let err = verify_apple_app_attest(&cbor, b"other-chal", app, &key_id, &root).unwrap_err();
        assert_eq!(err, AppAttestError::NonceMismatch);
    }

    /// The attestation must be for THIS app.
    #[test]
    fn app_attest_wrong_app_id_is_refused() {
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, root, key_id) = mock_app_attest(app, b"chal-1", PROD_AAGUID, 0);
        let err =
            verify_apple_app_attest(&cbor, b"chal-1", "OTHER.app.id", &key_id, &root).unwrap_err();
        assert_eq!(err, AppAttestError::AppIdMismatch);
    }

    #[test]
    fn app_attest_foreign_root_is_refused() {
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, _root, key_id) = mock_app_attest(app, b"chal-1", PROD_AAGUID, 0);
        let other_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let other = params("attacker root").self_signed(&other_kp).unwrap();
        let err = verify_apple_app_attest(&cbor, b"chal-1", app, &key_id, other.der()).unwrap_err();
        assert!(matches!(err, AppAttestError::ChainInvalid { .. }));
    }

    /// A development attestation is a valid MEASUREMENT — reported, not refused
    /// — but it REFUTES a production claim.
    #[test]
    fn app_attest_development_measures_and_refutes_a_production_claim() {
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, root, key_id) = mock_app_attest(app, b"chal-1", DEV_AAGUID, 0);

        let v = verify_apple_app_attest(&cbor, b"chal-1", app, &key_id, &root)
            .expect("a development attestation is not an error");
        assert_eq!(v.environment, AppAttestEnvironment::Development);
        assert!(v.refutes("Apple_AppAttest"), "over-claim must be refuted");
        assert!(!v.refutes("Apple_AppAttest_Development"));
    }

    #[test]
    fn app_attest_nonzero_sign_count_is_refused() {
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, root, key_id) = mock_app_attest(app, b"chal-1", PROD_AAGUID, 7);
        let err = verify_apple_app_attest(&cbor, b"chal-1", app, &key_id, &root).unwrap_err();
        assert_eq!(err, AppAttestError::NonZeroSignCount { found: 7 });
    }

    #[test]
    fn app_attest_wrong_format_is_refused() {
        use ciborium::value::Value as Cbor;
        let obj = Cbor::Map(vec![(
            Cbor::Text("fmt".into()),
            Cbor::Text("packed".into()),
        )]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&obj, &mut cbor).unwrap();
        let err = verify_apple_app_attest(&cbor, b"c", "a", &[], b"r").unwrap_err();
        assert!(matches!(err, AppAttestError::WrongFormat { .. }));
    }

    /// Store-resolved: an empty store is "no hardware evidence", not an error.
    #[test]
    fn app_attest_empty_store_is_no_evidence() {
        use crate::trust_anchor_store::TrustAnchorStore;
        let app = "TEAMID1234.ai.ciris.agent";
        let (cbor, _root, key_id) = mock_app_attest(app, b"chal-1", PROD_AAGUID, 0);
        let out = verify_apple_app_attest_with_store(
            &TrustAnchorStore::new(),
            &cbor,
            b"chal-1",
            app,
            &key_id,
        )
        .unwrap();
        assert!(out.is_none());
    }

    /// A leaf with no KeyDescription is refused rather than silently treated as
    /// software-held.
    #[test]
    fn leaf_without_key_description_is_refused() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("mock root").self_signed(&root_kp).unwrap();
        let leaf = params("no ext")
            .signed_by(&leaf_kp, &root, &root_kp)
            .unwrap();

        let err = verify_android_key_attestation(
            leaf.der(),
            &[],
            root.der(),
            &raw_ed(&leaf_kp),
            b"challenge-1",
        )
        .unwrap_err();
        assert_eq!(err, AndroidAttestationError::NoKeyDescription);
    }
}
