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
//! module is the sibling for platform devices, starting with **Android Key
//! Attestation**. Apple App Attest and TPM EK remain open legs of #199.
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
