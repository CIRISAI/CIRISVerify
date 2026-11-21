//! Accord-holder **custody verification** — the YubiKey PIV attestation chain
//! that proves an accord holder's signing key lives on a genuine FIPS YubiKey
//! with touch required (CIRISVerify#91, CC 4.2.2, CC 4.2.3).
//!
//! The accord kill-switch is only as trustworthy as the custody of its keys, so
//! a holder is seated **only** with proof its signing key lives on a genuine
//! FIPS YubiKey — never a self-claim a patched verify could forge. The proof is
//! the YubiKey PIV slot-9c attestation certificate, signed *inside* the YubiKey
//! by its slot-f9 attestation key and chaining to **Yubico's pinned PIV
//! attestation root**. Only a real YubiKey produces a valid 9c attestation, and
//! the cert's Yubico extensions (`1.3.6.1.4.1.41482.3.*`) carry firmware, FIPS
//! status, touch policy and serial.
//!
//! [`crate::accord_custody_attestation::verify_yubikey_piv_attestation`] is what the edition-2 genesis reader's
//! custody gate ([`crate::edition2::genesis`]) runs over a holder's
//! `key:record` chain, and what CIRISPersist calls. The earlier, pair-signed
//! custody bundle (`accord_holder_custody_attestation`, its producers and
//! verifier) was removed in 23.3.3.
//!
//! ## What the verifier proves
//!
//! 1. The 9c cert chains `9c → f9 → [intermediate(s)…] → ` the **pinned Yubico
//!    root** — a variable-length path (3 certs for the pre-fw-5.7 PKI, 4 for the
//!    2024-12 PKI), every link a real signature verification.
//! 2. The key the 9c cert *attests* equals the holder's Ed25519 key (the
//!    attestation is for *this* holder's signing key, not a borrowed one).
//! 3. The Yubico extensions show **FIPS-certified** (slot-f9 `.10`) **+
//!    touch=always** (slot-9c `.8`) → `hardware_class: YubiKey_5_FIPS`. Firmware
//!    (`.3`) is recorded, not floored; a present serial (`.7`) must be a DER
//!    INTEGER fitting `u32`.
//!
//! ## Confirmed against a real key
//!
//! Validated end-to-end against a physical **YubiKey 5 FIPS fw 5.7.4** (Ed25519
//! slot-9c key, touch=always) via `examples/validate_yubikey_attestation`:
//! `verify_yubikey_piv_attestation` ADMITTED with `fips_certified:true`,
//! `touch_always:true`, `firmware:5.7.4`. So the documented Yubico encodings hold
//! on real hardware: `.3` firmware and `.8` pin/touch are inner DER OCTET STRINGs
//! (`inner_octet_string` unwraps; the touch byte is read from the unwrapped
//! `[pin, touch]` — reading the wrapper length byte would false-accept a no-touch
//! key), `.10` FIPS rides the **f9** device cert, the attested key is a bare
//! 32-byte id-Ed25519 SPKI, and the **SHA256-RSA** chain verifies through
//! `x509_parser::verify_signature`.
//!
//! **PKI note (load-bearing for the pin):** Yubico's 2024-12 overhaul made the
//! chain 5 levels — `9c → f9 (CN=Yubico PIV Attestation) → CN=Yubico PIV
//! Attestation B 1 → CN=Yubico Attestation Intermediate B 1 → CN=Yubico
//! Attestation Root 1` (as the accord holders' real chains carry it). Pin the
//! durable **root** (`Yubico Attestation Root 1`,
//! `developers.yubico.com/PKI/yubico-ca-1.pem`), not the rotating `B 1`
//! intermediates; the bundle carries `[f9, PIV Attestation B 1, Attestation
//! Intermediate B 1]`. Pre-5.7
//! keys still verify with `[f9]` under the old `Yubico PIV Root CA Serial 263751`.
//!
//! ## Tiers (CIRISVerify#325)
//!
//! `verify_yubikey_piv_attestation` and its verdict and error types are in
//! the `std` tier: they parse X.509 and read no clock, keyring or network, so a
//! browser or UEFI node built with `default-features = false, features =
//! ["std", "pqc"]` verifies custody. `test_support` needs only `std` (plus its
//! own `test-support` feature).

use x509_parser::der_parser::asn1_rs::FromDer;
use x509_parser::prelude::*;

// Yubico PIV attestation extension OIDs (arc 1.3.6.1.4.1.41482.3.*).
const OID_YUBICO_FIRMWARE: &str = "1.3.6.1.4.1.41482.3.3";
const OID_YUBICO_SERIAL: &str = "1.3.6.1.4.1.41482.3.7";
const OID_YUBICO_PIN_TOUCH_POLICY: &str = "1.3.6.1.4.1.41482.3.8";
const OID_YUBICO_FIPS_CERTIFIED: &str = "1.3.6.1.4.1.41482.3.10";

/// Ed25519 SubjectPublicKeyInfo algorithm OID (id-Ed25519, RFC 8410).
const OID_ED25519: &str = "1.3.101.112";

/// Touch-policy byte (`…3.8` second byte) meaning "touch required for every use".
/// **Cross-confirm** against a real attestation (see module note).
const TOUCH_POLICY_ALWAYS: u8 = 0x02;

/// The verified custody facts of an accord holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyVerdict {
    /// The §9.4 hardware_class established by the attestation.
    pub hardware_class: String,
    /// YubiKey firmware `major.minor.patch` from the `…3.3` extension.
    pub firmware: String,
    /// YubiKey serial from the `…3.7` extension, if present.
    pub serial: Option<u32>,
    /// Whether the FIPS-certified extension (`…3.10`) is present.
    pub fips_certified: bool,
    /// Whether the touch policy (`…3.8`) is "always".
    pub touch_always: bool,
}

/// Why a custody attestation was rejected (fail-closed — admit only on `Ok`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CustodyError {
    /// A certificate (9c / f9 / root) could not be parsed.
    CertParse {
        /// Which cert.
        which: &'static str,
    },
    /// The attestation chain did not verify (9c → f9 → pinned Yubico root).
    ChainInvalid {
        /// Link that failed.
        detail: String,
    },
    /// The key the 9c cert attests is not the holder's Ed25519 key.
    AttestedKeyMismatch,
    /// The floor was not met (not FIPS, or touch not always, or firmware too old).
    FloorNotMet {
        /// Why.
        detail: String,
    },
    /// The 9c leaf carries the serial extension (`1.3.6.1.4.1.41482.3.7`) but
    /// its value is not one DER INTEGER fitting `u32`. A present member that
    /// fails its type is refused, never read as absent (CC 4.2.3).
    SerialMalformed,
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertParse { which } => write!(f, "could not parse {which} certificate"),
            Self::ChainInvalid { detail } => write!(f, "attestation chain invalid: {detail}"),
            Self::AttestedKeyMismatch => {
                write!(
                    f,
                    "the attested key is not the holder's federation Ed25519 key"
                )
            },
            Self::FloorNotMet { detail } => write!(f, "custody floor not met: {detail}"),
            Self::SerialMalformed => write!(
                f,
                "the 9c serial extension is not a DER INTEGER fitting u32"
            ),
        }
    }
}

impl std::error::Error for CustodyError {}

/// Unwrap a short-form DER OCTET STRING (`0x04 len content`), returning its
/// content when the bytes are exactly one OCTET STRING covering the whole
/// slice; otherwise returns the input unchanged. Yubico wraps the `.3` / `.8`
/// extension payloads this way on post-fix firmware (yubico-piv-tool#181) but
/// stored them bare on older firmware — tolerating both is fail-safe here
/// because the extension bytes are authenticated by the pinned attestation
/// chain (a forger can't alter them without breaking the signature).
fn inner_octet_string(raw: &[u8]) -> &[u8] {
    if raw.len() >= 2 && raw[0] == 0x04 {
        let len = raw[1] as usize;
        // Short-form length only (Yubico values are < 128 bytes, high bit clear).
        if raw[1] & 0x80 == 0 && raw.len() == 2 + len {
            return &raw[2..];
        }
    }
    raw
}

/// Verify a YubiKey PIV slot-9c attestation chain `9c → f9 → [intermediates…] →
/// pinned root`, confirm the attested key equals `expected_ed`, and extract +
/// enforce the FIPS + touch floor. The security-critical core, factored out so
/// it is directly testable against a generated chain (without the
/// bundle-signature layer).
///
/// `attestation_chain_ders` is the path **above** the 9c leaf, leaf-first:
/// `[f9, …intermediates…]` — `chain[0]` (f9) is the device attestation cert that
/// signs the 9c leaf and carries the FIPS `.10` extension; the last entry is
/// verified against `pinned_root_der`. For the pre-fw-5.7 PKI this is a single
/// `[f9]` and `pinned_root_der` is `Yubico PIV Root CA Serial 263751`; for the
/// 2024-12 PKI it is `[f9, "Yubico PIV Attestation B 1", "Yubico Attestation
/// Intermediate B 1"]` and `pinned_root_der`
/// is the durable `Yubico Attestation Root 1`. Every link is a real signature
/// verification; no name/CA-flag trust is inferred.
///
/// # Errors
///
/// [`CustodyError`] naming the first failing check (incl. an empty chain).
pub fn verify_yubikey_piv_attestation(
    attest_9c_der: &[u8],
    attestation_chain_ders: &[&[u8]],
    pinned_root_der: &[u8],
    expected_ed: &[u8],
) -> Result<CustodyVerdict, CustodyError> {
    if attestation_chain_ders.is_empty() {
        return Err(CustodyError::ChainInvalid {
            detail: "empty attestation chain (need at least the f9 device cert)".to_string(),
        });
    }
    let (_, cert_9c) = X509Certificate::from_der(attest_9c_der)
        .map_err(|_| CustodyError::CertParse { which: "9c" })?;
    let chain: Vec<X509Certificate> = attestation_chain_ders
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .map(|(_, c)| c)
                .map_err(|_| CustodyError::CertParse { which: "chain" })
        })
        .collect::<Result<_, _>>()?;
    let (_, cert_root) = X509Certificate::from_der(pinned_root_der)
        .map_err(|_| CustodyError::CertParse { which: "root" })?;

    // 9c signed by chain[0] (f9); chain[i] signed by chain[i+1]; chain.last by root.
    cert_9c
        .verify_signature(Some(chain[0].public_key()))
        .map_err(|e| CustodyError::ChainInvalid {
            detail: format!("9c not signed by f9: {e:?}"),
        })?;
    for i in 0..chain.len() - 1 {
        chain[i]
            .verify_signature(Some(chain[i + 1].public_key()))
            .map_err(|e| CustodyError::ChainInvalid {
                detail: format!("attestation chain link {i}→{} broken: {e:?}", i + 1),
            })?;
    }
    chain[chain.len() - 1]
        .verify_signature(Some(cert_root.public_key()))
        .map_err(|e| CustodyError::ChainInvalid {
            detail: format!("top of chain not signed by the pinned Yubico root: {e:?}"),
        })?;

    // The attested key == the holder's federation Ed25519 key.
    let spki = cert_9c.public_key();
    if spki.algorithm.algorithm.to_id_string() != OID_ED25519 {
        return Err(CustodyError::FloorNotMet {
            detail: "attested key is not Ed25519".to_string(),
        });
    }
    if spki.subject_public_key.data.as_ref() != expected_ed {
        return Err(CustodyError::AttestedKeyMismatch);
    }

    // Yubico extensions → firmware + touch=always (slot-9c) and FIPS (slot-f9).
    //
    // Encoding note (cross-confirmed vs Yubico's PIV attestation docs +
    // yubico-piv-tool#181): the `.3` firmware and `.8` pin/touch values are an
    // **inner DER OCTET STRING** wrapping the raw payload (post-fix firmware;
    // older firmware stored them bare). `inner_octet_string` unwraps when
    // present and falls back to the raw bytes otherwise, so both encodings
    // parse — and the touch byte is read from the *unwrapped* `[pin, touch]`
    // content (reading the wrapper length byte instead would silently accept a
    // no-touch key, the one false-accept that matters for a kill-switch gate).
    let mut firmware = None;
    let mut serial = None;
    let mut touch_always = false;
    for ext in cert_9c.extensions() {
        match ext.oid.to_id_string().as_str() {
            OID_YUBICO_FIRMWARE => {
                let v = inner_octet_string(ext.value);
                if v.len() >= 3 {
                    firmware = Some(format!("{}.{}.{}", v[0], v[1], v[2]));
                }
            },
            OID_YUBICO_SERIAL => {
                // Present means it names the device: one DER INTEGER, nothing
                // after it, fitting u32. Anything else is refused, so a bad
                // extension cannot skip the one-device check (CC 4.2.3).
                serial = match x509_parser::der_parser::asn1_rs::Integer::from_der(ext.value) {
                    Ok(([], n)) => Some(n.as_u32().map_err(|_| CustodyError::SerialMalformed)?),
                    _ => return Err(CustodyError::SerialMalformed),
                };
            },
            OID_YUBICO_PIN_TOUCH_POLICY => {
                let v = inner_octet_string(ext.value);
                if v.len() >= 2 {
                    touch_always = v[1] == TOUCH_POLICY_ALWAYS;
                }
            },
            _ => {},
        }
    }

    // The FIPS-certified extension (`.10`) is carried on the factory-loaded
    // slot-**f9** device attestation cert (`chain[0]`), NOT the per-slot 9c leaf
    // — scanning the 9c cert (which never carries it) would fail-reject every
    // genuine FIPS key. Confirmed against a real YubiKey 5 FIPS fw 5.7.4 (#91).
    let fips_certified = chain[0]
        .extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == OID_YUBICO_FIPS_CERTIFIED);
    if !fips_certified {
        return Err(CustodyError::FloorNotMet {
            detail: "YubiKey is not FIPS-certified (no 1.3.6.1.4.1.41482.3.10 on the f9 cert)"
                .to_string(),
        });
    }
    if !touch_always {
        return Err(CustodyError::FloorNotMet {
            detail: "touch policy is not 'always' — every accord signature must require a touch"
                .to_string(),
        });
    }

    Ok(CustodyVerdict {
        hardware_class: "YubiKey_5_FIPS".to_string(),
        firmware: firmware.unwrap_or_default(),
        serial,
        fips_certified,
        touch_always,
    })
}

/// TEST-ONLY fabricated YubiKey PIV custody artifacts (CIRISVerify#219).
///
/// Behind the non-default `test-support` feature (also compiled for this crate's
/// own `#[cfg(test)]` tests). Lets a downstream FIPS-floor gate — CIRISPersist's
/// canonical-admission anti-Sybil floor (#513), CIRISServer's `accord.rs` — build
/// a *synthetic* hardware-attested member and drive the full positive
/// path through [`verify_yubikey_piv_attestation`], instead of only refusal
/// paths.
///
/// ## Security posture — why exporting this is safe
///
/// Every artifact chains to a **mock** Yubico root that this module mints. A
/// production gate pins the **real** Yubico Attestation Root, against which these
/// artifacts are **inert** — [`verify_yubikey_piv_attestation`] rejects them
/// unless the caller *also* injects [`test_support::MockYubicoCa::root_der`] as
/// the pinned root, which is a test-only affordance. So you cannot forge a
/// real-gate pass with this. It is still fenced behind an opt-in feature (never
/// in `default`, never in the release lane) so the `rcgen` dependency and the
/// fabrication code are physically absent from production artifacts.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::TOUCH_POLICY_ALWAYS;
    use crate::self_at_login::HybridSigningIdentity;
    use crate::threshold::ThresholdMember;
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
    use rcgen::{
        Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair,
        PKCS_ED25519,
    };

    /// A mock Yubico PIV attestation CA. Mint several FIPS-attested members under
    /// ONE root, then inject [`Self::root_der`] as the pinned root when driving a
    /// strict custody gate — so a whole quorum verifies against one root, exactly
    /// as the real ceremony's A1/B1/C1 do against the real Yubico root.
    pub struct MockYubicoCa {
        root_kp: KeyPair,
        root: Certificate,
        root_der: Vec<u8>,
    }

    /// A fabricated FIPS-attested member: the directory entry a gate resolves the
    /// holder against, the attestation chain
    /// [`verify_yubikey_piv_attestation`](super::verify_yubikey_piv_attestation)
    /// admits (when the CA's root is the pinned one), and the **full hybrid
    /// signer** so a downstream can actually sign as the member (CIRISVerify#221).
    pub struct MockAttestedMember {
        /// The holder's pinned pubkeys.
        pub member: ThresholdMember,
        /// The slot-9c attestation cert DER (attests `member`'s Ed25519 key).
        pub attest_9c_der: Vec<u8>,
        /// The chain above the 9c leaf, leaf-first (`[f9]`).
        pub chain_ders: Vec<Vec<u8>>,
        /// The member's hybrid signer (Ed25519 + ML-DSA-65), both halves
        /// deterministically derived from `seed`. `holder.directory_member()`
        /// equals [`Self::member`]. Use it to produce the hybrid-Strict
        /// signatures a full mock quorum needs.
        pub holder: HybridSigningIdentity,
        /// The 32-byte Ed25519 seed backing the member (deterministic; the same
        /// seed reproduces the same member — pubkeys AND signer — for rotation
        /// tests).
        pub seed: [u8; 32],
    }

    /// Deterministic ML-DSA-65 seed for a member, domain-separated from its
    /// Ed25519 seed so the two halves are independent but both reproducible.
    fn mldsa_seed_from(ed_seed: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ciris-mock-mldsa-seed-v1");
        h.update(ed_seed);
        h.finalize().into()
    }

    fn params(cn: &str) -> CertificateParams {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        p.distinguished_name = dn;
        p
    }

    /// An rcgen `KeyPair` from a raw 32-byte Ed25519 seed (PKCS#8 v1 wrapper), so
    /// the mock 9c leaf key equals the holder's `Ed25519Signer::from_seed(seed)`
    /// key — the binding [`verify_yubikey_piv_attestation`](super::verify_yubikey_piv_attestation)
    /// checks (attested key == holder Ed25519).
    fn keypair_from_seed(seed: &[u8; 32]) -> KeyPair {
        use base64::Engine as _;
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(seed);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
        KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_ED25519).expect("valid Ed25519 PKCS#8")
    }

    impl Default for MockYubicoCa {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockYubicoCa {
        /// Mint a fresh mock Yubico attestation root.
        #[must_use]
        pub fn new() -> Self {
            let root_kp = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
            let root = params("Yubico PIV Attestation (MOCK root)")
                .self_signed(&root_kp)
                .expect("self-sign root");
            let root_der = root.der().to_vec();
            Self {
                root_kp,
                root,
                root_der,
            }
        }

        /// The mock root DER — inject this as the pinned `yubico_root_der` when
        /// verifying members minted by this CA.
        #[must_use]
        pub fn root_der(&self) -> &[u8] {
            &self.root_der
        }

        /// Mint an **admissible** member: FIPS-certified + touch-always, firmware
        /// 5.7.4 — the shape the strict floor accepts. `seed` makes it
        /// deterministic; distinct `seed`/`key_id` give distinct members for a
        /// quorum.
        #[must_use]
        pub fn attest_member(&self, seed: [u8; 32], key_id: &str) -> MockAttestedMember {
            self.attest_member_with(seed, key_id, true, TOUCH_POLICY_ALWAYS)
        }

        /// Full control for refusal-path coverage: set `fips=false` or a `touch`
        /// other than `TOUCH_POLICY_ALWAYS` to build a member the floor
        /// MUST reject even though the chain is otherwise valid.
        #[must_use]
        pub fn attest_member_with(
            &self,
            seed: [u8; 32],
            key_id: &str,
            fips: bool,
            touch: u8,
        ) -> MockAttestedMember {
            let leaf_kp = keypair_from_seed(&seed);

            // f9 device cert (carries the FIPS `.10` extension when `fips`).
            let f9_kp = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
            let mut f9_params = params("YubiKey PIV Attestation (MOCK f9)");
            if fips {
                f9_params.custom_extensions = vec![CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 41482, 3, 10],
                    vec![],
                )];
            }
            let f9 = f9_params
                .signed_by(&f9_kp, &self.root, &self.root_kp)
                .expect("sign f9");

            // 9c leaf: firmware 5.7.4 (`.3`) + pin/touch (`.8`), both inner-OCTET.
            let mut leaf = params("YubiKey PIV Attestation 9c (MOCK)");
            leaf.custom_extensions = vec![
                CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 41482, 3, 3],
                    vec![0x04, 0x03, 5, 7, 4],
                ),
                CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 41482, 3, 8],
                    vec![0x04, 0x02, 0x01, touch],
                ),
            ];
            let cert_9c = leaf.signed_by(&leaf_kp, &f9, &f9_kp).expect("sign 9c");

            // The holder whose Ed25519 == the 9c leaf key (same seed), with a
            // deterministic ML-DSA-65 half (#221) so the returned signer is fully
            // usable AND the member reproduces exactly from `seed`.
            let ed = Ed25519Signer::from_seed(&seed).expect("ed from seed");
            let mldsa = MlDsa65Signer::from_seed(&mldsa_seed_from(&seed)).expect("mldsa from seed");
            let holder = HybridSigningIdentity::new(key_id, ed, mldsa);
            let member = holder.directory_member().expect("directory member");

            MockAttestedMember {
                member,
                attest_9c_der: cert_9c.der().to_vec(),
                chain_ders: vec![f9.der().to_vec()],
                holder,
                seed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Build a mock attestation chain root → f9 → 9c that mirrors the *documented*
    /// real YubiKey encoding: the 9c leaf carries the firmware (`.3`) + pin/touch
    /// (`.8`) extensions as **inner DER OCTET STRINGs**, and the FIPS (`.10`)
    /// extension rides the **f9** cert (not the leaf). Returns (9c, f9, root) DER.
    fn mock_chain(leaf_kp: &KeyPair, fips: bool, touch: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("Yubico PIV Attestation (test root)")
            .self_signed(&root_kp)
            .unwrap();
        let f9_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut f9_params = params("YubiKey PIV Attestation (test f9)");
        if fips {
            // FIPS `.10` lives on the factory f9 cert (presence = FIPS-certified).
            f9_params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 10],
                vec![],
            )];
        }
        let f9 = f9_params.signed_by(&f9_kp, &root, &root_kp).unwrap();

        let mut leaf = params("YubiKey PIV Attestation 9c");
        leaf.custom_extensions = vec![
            // firmware 5.7.4, DER OCTET STRING-wrapped: 04 03 05 07 04
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 3],
                vec![0x04, 0x03, 5, 7, 4],
            ),
            // [pin_policy=once(0x01), touch_policy], OCTET STRING-wrapped: 04 02 01 <touch>
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 8],
                vec![0x04, 0x02, 0x01, touch],
            ),
        ];
        let cert_9c = leaf.signed_by(leaf_kp, &f9, &f9_kp).unwrap();
        (
            cert_9c.der().to_vec(),
            f9.der().to_vec(),
            root.der().to_vec(),
        )
    }

    #[test]
    fn fips_touch_chain_verifies_and_extracts() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let v = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &raw_ed(&leaf_kp))
            .expect("a FIPS, touch-always, root-chained attestation must verify");
        assert_eq!(v.hardware_class, "YubiKey_5_FIPS");
        assert!(v.fips_certified && v.touch_always);
        assert_eq!(v.firmware, "5.7.4");
    }

    #[test]
    fn wrong_root_breaks_the_chain() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, _root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        // A different (attacker) root the f9 does not chain to.
        let other_root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let other_root = params("attacker root").self_signed(&other_root_kp).unwrap();
        let err = verify_yubikey_piv_attestation(
            &c9,
            &[f9.as_slice()],
            other_root.der(),
            &raw_ed(&leaf_kp),
        )
        .unwrap_err();
        assert!(matches!(err, CustodyError::ChainInvalid { .. }));
    }

    #[test]
    fn non_fips_yubikey_rejected() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, false, TOUCH_POLICY_ALWAYS);
        let err = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &raw_ed(&leaf_kp))
            .unwrap_err();
        assert!(matches!(err, CustodyError::FloorNotMet { .. }));
    }

    #[test]
    fn touch_not_always_rejected() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, true, 0x01 /* not always */);
        let err = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &raw_ed(&leaf_kp))
            .unwrap_err();
        assert!(matches!(err, CustodyError::FloorNotMet { .. }));
    }

    #[test]
    fn attested_key_must_be_the_holder_key() {
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let (c9, f9, root) = mock_chain(&leaf_kp, true, TOUCH_POLICY_ALWAYS);
        let someone_else = raw_ed(&KeyPair::generate_for(&PKCS_ED25519).unwrap());
        let err = verify_yubikey_piv_attestation(&c9, &[f9.as_slice()], &root, &someone_else)
            .unwrap_err();
        assert_eq!(err, CustodyError::AttestedKeyMismatch);
    }

    #[test]
    fn four_level_chain_with_intermediate_verifies() {
        // The 2024-12 Yubico PKI: 9c → f9 → intermediate → root. The verifier
        // must walk the intermediate up to the pinned *root* (not a fixed
        // 3-cert chain), with FIPS .10 still read off the f9 device cert.
        let leaf_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let root = params("Yubico Attestation Root 1 (test)")
            .self_signed(&root_kp)
            .unwrap();
        let mid_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mid = params("Yubico PIV Attestation B 1 (test)")
            .signed_by(&mid_kp, &root, &root_kp)
            .unwrap();
        let mut f9p = params("Yubico PIV Attestation (test f9)");
        f9p.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 41482, 3, 10],
            vec![],
        )];
        let f9_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let f9 = f9p.signed_by(&f9_kp, &mid, &mid_kp).unwrap();
        let mut leaf = params("YubiKey 9c (test)");
        leaf.custom_extensions = vec![
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 3],
                vec![0x04, 0x03, 5, 7, 4],
            ),
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 3, 8],
                vec![0x04, 0x02, 0x01, TOUCH_POLICY_ALWAYS],
            ),
        ];
        let c9 = leaf.signed_by(&leaf_kp, &f9, &f9_kp).unwrap();

        let c9d = c9.der().to_vec();
        let f9d = f9.der().to_vec();
        let midd = mid.der().to_vec();
        let rootd = root.der().to_vec();
        let expected = raw_ed(&leaf_kp);

        // Full 4-level chain to the pinned root verifies.
        let v = verify_yubikey_piv_attestation(
            &c9d,
            &[f9d.as_slice(), midd.as_slice()],
            &rootd,
            &expected,
        )
        .expect("a 9c → f9 → intermediate → root chain must verify");
        assert_eq!(v.hardware_class, "YubiKey_5_FIPS");
        assert!(v.fips_certified && v.touch_always);
        assert_eq!(v.firmware, "5.7.4");

        // Pinning a *stranger* root (the intermediate doesn't chain to it) fails.
        let stranger_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let stranger = params("stranger root").self_signed(&stranger_kp).unwrap();
        assert!(matches!(
            verify_yubikey_piv_attestation(
                &c9d,
                &[f9d.as_slice(), midd.as_slice()],
                stranger.der(),
                &expected
            )
            .unwrap_err(),
            CustodyError::ChainInvalid { .. }
        ));

        // A missing intermediate (chain=[f9], root pinned) cannot bridge to root.
        assert!(matches!(
            verify_yubikey_piv_attestation(&c9d, &[f9d.as_slice()], &rootd, &expected).unwrap_err(),
            CustodyError::ChainInvalid { .. }
        ));

        // An empty chain is fail-closed.
        assert!(matches!(
            verify_yubikey_piv_attestation(&c9d, &[], &rootd, &expected).unwrap_err(),
            CustodyError::ChainInvalid { .. }
        ));
    }

    fn member_ed(m: &crate::threshold::ThresholdMember) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&m.ed25519_public_key_base64)
            .unwrap()
    }

    /// The CIRISPersist shape (`default-features = false, features = ["std",
    /// "pqc"]`): a mock-CA member, valid under its own root, is refused under
    /// every baked Yubico root (#325).
    #[test]
    fn mock_member_is_refused_under_the_baked_yubico_roots() {
        use super::test_support::MockYubicoCa;
        use crate::trust_anchor_store::{baked, environments, Purpose};

        let ca = MockYubicoCa::new();
        let m = ca.attest_member([7; 32], "A1");
        let chain: Vec<&[u8]> = m.chain_ders.iter().map(Vec::as_slice).collect();
        let ed = member_ed(&m.member);
        assert!(
            verify_yubikey_piv_attestation(&m.attest_9c_der, &chain, ca.root_der(), &ed).is_ok()
        );

        let store = baked::default_store();
        let roots = store.resolve_x509(Purpose::KeyAttestation, environments::YUBIKEY_PIV);
        assert!(!roots.is_empty(), "the baked store pins a Yubico PIV root");
        for root in roots {
            assert!(matches!(
                verify_yubikey_piv_attestation(&m.attest_9c_der, &chain, root, &ed),
                Err(CustodyError::ChainInvalid { .. })
            ));
        }
    }

    /// #219: the exported `test_support` machinery must produce members the REAL
    /// verifier admits under the CA's injected root — the affordance
    /// CIRISPersist's FIPS floor drives — and the refusal knob works.
    #[test]
    fn test_support_mints_members_the_real_verifier_admits() {
        use super::test_support::MockYubicoCa;

        let ca = MockYubicoCa::new();
        let verify = |m: &super::test_support::MockAttestedMember, root: &[u8]| {
            let chain: Vec<&[u8]> = m.chain_ders.iter().map(Vec::as_slice).collect();
            verify_yubikey_piv_attestation(&m.attest_9c_der, &chain, root, &member_ed(&m.member))
        };
        // Three distinct FIPS-attested members under one root (the A1/B1/C1 shape).
        for (i, kid) in [(1u8, "A1"), (2, "B1"), (3, "C1")] {
            let m = ca.attest_member([i; 32], kid);
            let v = verify(&m, ca.root_der())
                .expect("mock FIPS member must verify against the CA's injected root");
            assert_eq!(v.hardware_class, "YubiKey_5_FIPS");
            assert!(v.fips_certified && v.touch_always);
        }

        // Refusal knob: a non-FIPS member is rejected by the floor even though
        // its chain is otherwise valid.
        let bad = ca.attest_member_with([9; 32], "X", false, TOUCH_POLICY_ALWAYS);
        assert!(matches!(
            verify(&bad, ca.root_der()),
            Err(CustodyError::FloorNotMet { .. })
        ));

        // Inertness: a member minted by one CA does NOT verify against a
        // DIFFERENT root — you can't forge a real-gate pass.
        let m = ca.attest_member([1; 32], "A1");
        assert!(verify(&m, MockYubicoCa::new().root_der()).is_err());

        // Determinism: the same seed reproduces the SAME member.
        assert_eq!(m.member, ca.attest_member([1; 32], "A1").member);
    }
}
