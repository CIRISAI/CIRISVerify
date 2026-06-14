//! Generic, interface-keyed external hardware-security-token abstraction.
//!
//! This module is the *brand-agnostic* substrate for external removable
//! security tokens (USB/NFC smartcards) — the device class that backs the
//! HUMANITY_ACCORD holder keys. It is keyed on the **interface standard**
//! the token speaks ([`TokenInterface`] — PIV, OpenPGP-card, PKCS#11),
//! **not** on any vendor. "YubiKey" is the canonical *reference device*: it
//! is one row in [`hardware_class_table`], not a code path. A Nitrokey, a
//! SoloKey, a smartcard, or an unknown PIV applet all flow through the same
//! probe and the same resolver.
//!
//! ## What this module is (and is not)
//!
//! - **Real and unit-tested:** the [`TokenInterface`] taxonomy, the
//!   [`ProbedToken`] descriptor, and the pure, data-driven
//!   [`resolve_hardware_class`] resolver that maps a probed device to a
//!   CEG §9.4 `hardware_class` string via an explicit open data table with a
//!   conservative unknown-device default. This is the piece that makes the
//!   abstraction generic; it is exercised in the test module below.
//! - **Honestly stubbed, pending hardware:** the actual PC/SC + PIV/PKCS#11
//!   I/O ([`get_token_signer`]). There is no token on the build/test box, so
//!   the hardware path returns [`KeyringError::NotSupported`]. The intended
//!   implementation crates are [`pcsc`](https://crates.io/crates/pcsc) (PC/SC
//!   reader transport) and [`cryptoki`](https://crates.io/crates/cryptoki)
//!   (PKCS#11). See the TODO on [`get_token_signer`].
//!
//! ## Signing-only Ed25519 framing (CIRISVerify#62)
//!
//! These tokens carry the **classical half only** — a non-extractable
//! Ed25519 signing key (OpenPGP applet / PIV slot). As of 2026 no shipping
//! token has an ML-DSA-65 (FIPS 204) applet, so the post-quantum half always
//! lives in software alongside (see `ACCORD_KEY_GENESIS_RUNBOOK.md` §4.2).
//! This module therefore never claims to produce a hybrid signature: it is a
//! classical [`HardwareSigner`] producing Ed25519 signatures, and the PQC
//! half is a separate software `PqcSigner` (feature `pqc-ml-dsa`) bound at a higher
//! layer.
//!
//! The token is **signing-only**. In FIPS Approved Mode the X25519/key-exchange
//! applet is expected to be blocked; accord keys sign over published bytes and
//! never do key agreement.

use crate::error::KeyringError;
use crate::signer::HardwareSigner;

/// The interface standard an external security token speaks.
///
/// This is the abstraction's key. We dispatch on *how to talk to the token*,
/// not on who made it. Every supported transport/applet standard gets a
/// variant; vendor identity is captured separately in [`ProbedToken`] and is
/// used only to refine the `hardware_class` label, never to choose a code
/// path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenInterface {
    /// NIST SP 800-73 PIV (Personal Identity Verification) applet, accessed
    /// over PC/SC. Common on smartcards and YubiKey PIV slots.
    Piv,
    /// OpenPGP card application (ISO 7816 / OpenPGP-card spec). The applet the
    /// accord runbook uses for the on-device Ed25519 signing key.
    OpenPgpCard,
    /// PKCS#11 (Cryptoki) module — a vendor-supplied `.so`/`.dll` exposing the
    /// token. The most generic path; covers tokens with no native PIV/OpenPGP
    /// applet but a Cryptoki driver.
    Pkcs11,
}

impl TokenInterface {
    /// Stable lowercase wire/log label for this interface.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Piv => "piv",
            Self::OpenPgpCard => "openpgp-card",
            Self::Pkcs11 => "pkcs11",
        }
    }
}

/// A device descriptor produced by probing an attached token.
///
/// This is the *input* to [`resolve_hardware_class`]. In a real deployment a
/// PC/SC probe fills these fields from the answer-to-reset / applet AID / a
/// model string read from the card. Here it is a plain, constructible struct
/// so the resolver is unit-testable with no hardware present.
///
/// All fields besides `interface` are optional: an unknown card may answer
/// only "I speak PIV" and nothing else, and the resolver must still produce a
/// safe, non-mislabeling answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbedToken {
    /// The interface standard the probe could speak to the token over.
    pub interface: TokenInterface,
    /// Vendor / application identifier read from the card, if any (e.g. an
    /// OpenPGP-card AID prefix `d2:76:00:01:24` for Yubico, or a PKCS#11
    /// manufacturer string). Used only to refine the class label.
    pub vendor_aid: Option<String>,
    /// Free-form model string read from the token, if any (e.g.
    /// `"YubiKey 5 FIPS"`, `"Nitrokey 3"`). Used only to refine the class
    /// label.
    pub model: Option<String>,
}

impl ProbedToken {
    /// Construct a probe descriptor for a bare interface with no vendor/model
    /// detail. Resolves to the conservative generic class.
    #[must_use]
    pub fn bare(interface: TokenInterface) -> Self {
        Self {
            interface,
            vendor_aid: None,
            model: None,
        }
    }

    /// Builder: attach a model string.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Builder: attach a vendor/application identifier.
    #[must_use]
    pub fn with_vendor_aid(mut self, aid: impl Into<String>) -> Self {
        self.vendor_aid = Some(aid.into());
        self
    }
}

/// The conservative `hardware_class` assigned to any external token we cannot
/// positively identify.
///
/// This is the load-bearing safety property of the resolver: an unrecognized
/// device is labeled as a generic external secure element at the **lowest**
/// external-token trust, and is **never** rejected and **never** mislabeled as
/// a recognized branded device. Consumers apply their own policy (a strict
/// consumer may decline to honor a generic class for a professional tier); the
/// resolver never makes that policy call, it only refuses to overclaim.
pub const GENERIC_EXTERNAL_TOKEN_CLASS: &str = "ExternalToken_Generic";

/// One entry in the open `hardware_class` mapping table.
///
/// A probed token matches an entry when its [`ProbedToken::interface`] is in
/// `interfaces` AND at least one of `model_substrings` / `vendor_aid_prefixes`
/// matches (case-insensitive for model substrings). Entries are evaluated in
/// table order; the first match wins, so put more specific rows first.
#[derive(Debug, Clone, Copy)]
pub struct HardwareClassRule {
    /// Interfaces this rule applies to.
    pub interfaces: &'static [TokenInterface],
    /// Case-insensitive substrings to look for in [`ProbedToken::model`].
    pub model_substrings: &'static [&'static str],
    /// Prefixes to match against [`ProbedToken::vendor_aid`] (case-sensitive;
    /// AIDs are canonically lowercase hex here).
    pub vendor_aid_prefixes: &'static [&'static str],
    /// The CEG §9.4 `hardware_class` string this rule resolves to.
    pub hardware_class: &'static str,
}

/// The open, data-driven device → `hardware_class` table (CEG §9.4).
///
/// This is deliberately a flat, readable data table rather than branching
/// code. Adding support for a new device is a one-row edit, not a new code
/// path. **YubiKey 5 FIPS is the canonical reference device — it is exactly
/// one row here** (`YubiKey_5_FIPS`, trust-multiplier 0.95 per the accord
/// runbook §9.4), with no special casing anywhere else in the module.
///
/// Rows are matched top-down, first match wins. Anything that matches no row
/// falls through to [`GENERIC_EXTERNAL_TOKEN_CLASS`].
#[must_use]
pub fn hardware_class_table() -> &'static [HardwareClassRule] {
    // Yubico OpenPGP-card AID prefix (RID d2:76:00:01:24 = FSFE/Yubico OpenPGP
    // application). Lowercase, colon-free for prefix matching.
    const YUBICO_OPENPGP_AID: &str = "d2760001240103";

    &[
        // YubiKey 5 FIPS — the canonical reference device. One row.
        HardwareClassRule {
            interfaces: &[
                TokenInterface::Piv,
                TokenInterface::OpenPgpCard,
                TokenInterface::Pkcs11,
            ],
            model_substrings: &["yubikey 5 fips", "yubikey 5c fips", "yubikey 5 nfc fips"],
            vendor_aid_prefixes: &[YUBICO_OPENPGP_AID],
            hardware_class: "YubiKey_5_FIPS",
        },
        // Non-FIPS YubiKey 5 — distinct class (no FIPS Approved Mode boundary).
        HardwareClassRule {
            interfaces: &[
                TokenInterface::Piv,
                TokenInterface::OpenPgpCard,
                TokenInterface::Pkcs11,
            ],
            model_substrings: &["yubikey 5"],
            vendor_aid_prefixes: &[],
            hardware_class: "YubiKey_5",
        },
        // Nitrokey — a different vendor, proving the table is not YubiKey-only.
        HardwareClassRule {
            interfaces: &[
                TokenInterface::Piv,
                TokenInterface::OpenPgpCard,
                TokenInterface::Pkcs11,
            ],
            model_substrings: &["nitrokey"],
            vendor_aid_prefixes: &[],
            hardware_class: "Nitrokey",
        },
    ]
}

/// Resolve a probed token to a CEG §9.4 `hardware_class` string.
///
/// Pure, total, data-driven, and free of I/O — this is the unit-testable core
/// of the abstraction. It walks [`hardware_class_table`] top-down; the first
/// rule whose interface set contains the probe's interface and whose model
/// substring (case-insensitive) **or** vendor-AID prefix matches wins. If
/// nothing matches it returns [`GENERIC_EXTERNAL_TOKEN_CLASS`] — never an
/// error, never a branded label.
#[must_use]
pub fn resolve_hardware_class(probe: &ProbedToken) -> &'static str {
    let model_lc = probe.model.as_ref().map(|m| m.to_lowercase());
    let vendor_aid = probe.vendor_aid.as_deref();

    for rule in hardware_class_table() {
        if !rule.interfaces.contains(&probe.interface) {
            continue;
        }

        let model_hit = model_lc.as_deref().is_some_and(|m| {
            rule.model_substrings
                .iter()
                .any(|needle| m.contains(needle))
        });

        let aid_hit = vendor_aid.is_some_and(|aid| {
            rule.vendor_aid_prefixes
                .iter()
                .any(|prefix| aid.starts_with(prefix))
        });

        if model_hit || aid_hit {
            return rule.hardware_class;
        }
    }

    // Conservative default: a real external token, but one we cannot
    // positively brand. Lowest external-token trust; never rejected.
    GENERIC_EXTERNAL_TOKEN_CLASS
}

/// `HardwareSigner`-shaped entry point for an external token.
///
/// Returns a [`HardwareSigner`] bound to the Ed25519 signing key on the token
/// reached over `interface`, selected by `alias` (PIV slot id / OpenPGP key
/// reference / PKCS#11 key label, depending on the interface).
///
/// # Status: honestly stubbed, pending hardware
///
/// There is no PC/SC token on the build/test machine, so this **always**
/// returns [`KeyringError::NotSupported`]. The abstraction around it — the
/// interface taxonomy and the probe → `hardware_class` resolver — is real and
/// tested; only the hardware I/O is stubbed.
///
/// TODO(CIRISVerify#62): implement the real token signer against:
///   - [`pcsc`](https://crates.io/crates/pcsc) for the PC/SC reader transport
///     (enumerate readers, connect, transmit APDUs) for the [`TokenInterface::Piv`]
///     and [`TokenInterface::OpenPgpCard`] paths, and
///   - [`cryptoki`](https://crates.io/crates/cryptoki) for the
///     [`TokenInterface::Pkcs11`] path (load module, open session, sign).
///
/// The signer must be Ed25519 signing-only (classical half), gate signing
/// behind the token's touch/PIN policy, and report a `hardware_type` derived
/// from a probe + [`resolve_hardware_class`]. It must be put behind a
/// `hw-token` Cargo feature (mirroring `tpm`/`android`) so the default build
/// does not link `pcsc`/`cryptoki`.
pub fn get_token_signer(
    interface: TokenInterface,
    alias: &str,
) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    tracing::warn!(
        interface = interface.as_str(),
        alias,
        "get_token_signer: external-token hardware path is not yet implemented \
         (no PC/SC backend compiled in). Returning NotSupported. \
         Intended impl: pcsc + cryptoki behind a `hw-token` feature."
    );

    Err(KeyringError::NotSupported {
        operation: format!(
            "external token signing over {} (alias={alias}); \
             PC/SC PIV/PKCS#11 backend not yet implemented (CIRISVerify#62)",
            interface.as_str()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_labels_are_stable() {
        assert_eq!(TokenInterface::Piv.as_str(), "piv");
        assert_eq!(TokenInterface::OpenPgpCard.as_str(), "openpgp-card");
        assert_eq!(TokenInterface::Pkcs11.as_str(), "pkcs11");
    }

    #[test]
    fn yubikey_5_fips_is_the_reference_row_by_model() {
        // The canonical reference device, identified by model string.
        let probe = ProbedToken::bare(TokenInterface::OpenPgpCard).with_model("YubiKey 5 FIPS");
        assert_eq!(resolve_hardware_class(&probe), "YubiKey_5_FIPS");

        // Case-insensitivity on the model match.
        let probe_lc = ProbedToken::bare(TokenInterface::Piv).with_model("yubikey 5c fips");
        assert_eq!(resolve_hardware_class(&probe_lc), "YubiKey_5_FIPS");
    }

    #[test]
    fn yubikey_fips_resolves_by_vendor_aid_when_no_model() {
        // A bare OpenPGP card that only surfaces the Yubico AID, no model.
        // AID prefix match lands on the first (FIPS) row in the table and
        // never on the generic default.
        let probe = ProbedToken {
            interface: TokenInterface::OpenPgpCard,
            vendor_aid: Some("d2760001240103040006".to_string()),
            model: None,
        };
        assert_eq!(resolve_hardware_class(&probe), "YubiKey_5_FIPS");
    }

    #[test]
    fn non_yubikey_device_maps_to_its_own_class_not_yubikey() {
        // Nitrokey proves the table is genuinely vendor-generic: a different
        // brand must NOT be mislabeled as a YubiKey.
        let probe = ProbedToken::bare(TokenInterface::OpenPgpCard).with_model("Nitrokey 3");
        let class = resolve_hardware_class(&probe);
        assert_eq!(class, "Nitrokey");
        assert_ne!(class, "YubiKey_5_FIPS");
        assert!(!class.contains("YubiKey"));
    }

    #[test]
    fn unknown_device_falls_back_to_generic_never_rejected() {
        // An unrecognized smartcard speaking PIV with no identifying detail.
        let probe = ProbedToken::bare(TokenInterface::Piv);
        assert_eq!(resolve_hardware_class(&probe), GENERIC_EXTERNAL_TOKEN_CLASS);

        // An unknown vendor/model over PKCS#11 also defaults conservatively,
        // and crucially is NEVER labeled as any branded device.
        let weird = ProbedToken::bare(TokenInterface::Pkcs11)
            .with_model("Acme SmartToken 9000")
            .with_vendor_aid("ff:ff:ff");
        let class = resolve_hardware_class(&weird);
        assert_eq!(class, GENERIC_EXTERNAL_TOKEN_CLASS);
        assert!(!class.contains("YubiKey"));
        assert!(!class.contains("Nitrokey"));
    }

    #[test]
    fn non_fips_yubikey_5_is_distinct_from_fips() {
        // "YubiKey 5 NFC" (no FIPS) must NOT silently inherit the FIPS class.
        let probe = ProbedToken::bare(TokenInterface::Piv).with_model("YubiKey 5 NFC");
        assert_eq!(resolve_hardware_class(&probe), "YubiKey_5");
        assert_ne!(resolve_hardware_class(&probe), "YubiKey_5_FIPS");
    }

    #[test]
    fn resolver_is_pure_and_total_over_all_interfaces() {
        // Every interface, with an empty probe, yields the safe default and
        // never panics — the resolver is total.
        for iface in [
            TokenInterface::Piv,
            TokenInterface::OpenPgpCard,
            TokenInterface::Pkcs11,
        ] {
            let probe = ProbedToken::bare(iface);
            assert_eq!(resolve_hardware_class(&probe), GENERIC_EXTERNAL_TOKEN_CLASS);
        }
    }

    #[test]
    fn get_token_signer_is_honestly_stubbed() {
        // The hardware path compiles and returns a clear NotSupported with the
        // issue reference — it does not panic and does not pretend to work.
        // (`Box<dyn HardwareSigner>` isn't Debug, so match the Result directly
        // rather than using `unwrap_err`.)
        match get_token_signer(TokenInterface::Piv, "9a") {
            Err(KeyringError::NotSupported { operation }) => {
                assert!(operation.contains("piv"));
                assert!(operation.contains("CIRISVerify#62"));
            },
            Err(other) => panic!("expected NotSupported, got {other:?}"),
            Ok(_) => panic!("expected NotSupported, got Ok(signer)"),
        }
    }

    #[test]
    fn probed_token_builders_compose() {
        let probe = ProbedToken::bare(TokenInterface::Pkcs11)
            .with_model("Nitrokey 3A")
            .with_vendor_aid("20:a0:00:00:05:27");
        assert_eq!(probe.interface, TokenInterface::Pkcs11);
        assert_eq!(probe.model.as_deref(), Some("Nitrokey 3A"));
        assert_eq!(probe.vendor_aid.as_deref(), Some("20:a0:00:00:05:27"));
    }
}
