//! **Constrained** trust-anchor store, modelled on IETF RATS **CoTS** —
//! Concise TA Stores (CIRISVerify#227).
//!
//! ## Why this exists
//!
//! Verify was accumulating hand-pinned attestation roots: Yubico (#91), Google
//! (#199), with Apple and **six** TPM vendor roots queued behind them. Pinning
//! each one at its call site doesn't scale, and — worse — it gives every anchor
//! **unlimited scope**: a flat `&[root]` list cannot express *"this root is
//! valid for Android key attestation and nothing else."*
//!
//! CoTS ([`draft-ietf-rats-concise-ta-stores`]) is the standard that models
//! exactly that: *"optionally **constrained** trust anchor stores containing
//! optionally **constrained** trust anchors."* This module is a faithful
//! in-memory realization of that data model.
//!
//! [`draft-ietf-rats-concise-ta-stores`]: https://datatracker.ietf.org/doc/draft-ietf-rats-concise-ta-stores/
//!
//! ## The security property
//!
//! Resolution is **doubly constrained**: an anchor is returned only when the
//! caller's `purpose` **and** `environment` both match the store that carries
//! it. So the Yubico PIV root cannot satisfy an Android key-attestation lookup,
//! and a root admitted for `KeyAttestation` cannot be used to validate a TLS
//! certificate. That containment is the entire point — a flat root list has no
//! way to say it, and this module refuses to let a caller opt out of it.
//!
//! ## Ecosystem position — verify is the first Rust CoTS
//!
//! Surveyed 2026-08-01:
//!
//! - [`Azure/corim`](https://github.com/Azure/corim) (`corim` on crates.io,
//!   MIT, `draft-ietf-rats-corim-10`) implements CoRIM / CoMID / CoSWID / CoTL
//!   and signed CoRIM — and states plainly that **CoTS is *"a separate draft,
//!   not modeled."***
//! - None of Veraison's seven Rust repos (`corim-rs`, `coserv-rs`, `rust-ear`,
//!   `rust-ccatoken`, `rust-cmw`, `rust-regl`, `rust-apiclient`) implement CoTS
//!   either.
//!
//! So there is no Rust CoTS to adopt. This module is deliberately written to be
//! **upstreamable**: the type names, field semantics and enum values track the
//! draft's CDDL (indices recorded in the doc comments) so it can either grow a
//! CBOR codec later or be contributed to `Azure/corim` as its CoTS module. What
//! is intentionally **not** here yet is the CBOR/COSE wire encoding — the value
//! today is the model plus constrained resolution; wire interop can follow
//! without disturbing this API.
//!
//! ## Hardware remains a trust SIGNAL, not a requirement
//!
//! A store **miss returns an empty slice, never an error**. A caller that finds
//! no anchor for a purpose/environment has *no hardware evidence* — which is
//! not the same as a failed verification, and must never be turned into a
//! refusal to admit a peer. Same rule as
//! [`crate::device_attestation`].

use std::collections::BTreeMap;

/// `$pkix-ta-type` — how a trust anchor's bytes are encoded (CoTS §
/// `trust-anchor`). Values are the draft's, and are wire-significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaFormat {
    /// `0` — DER-encoded X.509 certificate. What every root we pin today is.
    X509Cert,
    /// `1` — RFC 5914 `TrustAnchorInfo`.
    TrustAnchorInfo,
    /// `2` — DER-encoded `SubjectPublicKeyInfo` (a bare key, no certificate).
    SubjectPublicKeyInfo,
}

impl TaFormat {
    /// The draft's wire value for this format.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::X509Cert => 0,
            Self::TrustAnchorInfo => 1,
            Self::SubjectPublicKeyInfo => 2,
        }
    }
}

/// `$$tas-list-purpose` — what a store's anchors may be used **for**.
///
/// The draft enumerates `cots`, `corim`, `coswid`, `eat`, `key-attestation`,
/// `certificate`, `dloa`. `KeyAttestation` is the one that carries our device
/// roots (Yubico / Google / Apple / TPM vendors); `Certificate` is the PKIX
/// path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    /// Verifying further CoTS instances.
    Cots,
    /// Verifying CoRIM endorsements / reference values.
    Corim,
    /// Verifying CoSWID tags.
    Coswid,
    /// Verifying EAT attestation tokens.
    Eat,
    /// Verifying **key attestations** — device attestation chains.
    KeyAttestation,
    /// Verifying PKIX certificates.
    Certificate,
    /// Verifying Digital Letters of Approval.
    Dloa,
}

impl Purpose {
    /// The draft's string label for this purpose.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cots => "cots",
            Self::Corim => "corim",
            Self::Coswid => "coswid",
            Self::Eat => "eat",
            Self::KeyAttestation => "key-attestation",
            Self::Certificate => "certificate",
            Self::Dloa => "dloa",
        }
    }
}

/// A trust anchor — `trust-anchor = [ format => $pkix-ta-type, data => bstr ]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// How `data` is encoded.
    pub format: TaFormat,
    /// The anchor bytes.
    pub data: Vec<u8>,
}

impl TrustAnchor {
    /// A DER X.509 certificate anchor — the common case.
    #[must_use]
    pub fn x509(der: impl Into<Vec<u8>>) -> Self {
        Self {
            format: TaFormat::X509Cert,
            data: der.into(),
        }
    }
}

/// `cas-and-tas-map` — the anchors a store carries, plus optional intermediate
/// CAs to help path building.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CasAndTas {
    /// `tastore.tas` \[0\] — the trust anchors. Required, non-empty.
    pub tas: Vec<TrustAnchor>,
    /// `tastore.cas` \[1\] — optional intermediate certificates (DER).
    pub cas: Vec<Vec<u8>>,
}

/// `environment-group-list-map` — which environment a store's anchors apply to.
///
/// The draft allows an `environment-map` (CoMID), an `abbreviated-swid-tag`, or
/// a `named-ta-store` \[2\]. We use the **named** form: a stable label such as
/// `"yubikey-piv"` or `"android-keystore"`. Modelling the CoMID
/// `environment-map` is left for when a consumer actually needs vendor/model
/// granularity — the named form is the draft's own escape hatch and keeps this
/// honest rather than half-implementing a richer shape.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EnvironmentGroup {
    /// `named-ta-store` — the environment label.
    pub named_ta_store: String,
}

impl EnvironmentGroup {
    /// A named environment group.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            named_ta_store: name.into(),
        }
    }
}

/// `concise-ta-store-map` — one constrained trust-anchor store.
///
/// Field indices from the draft's CDDL, recorded so a future CBOR codec has an
/// unambiguous target: `language` \[0\], `store-identity` \[1\],
/// `environments` \[2\] (**required**), `purposes` \[3\], `perm_claims` \[4\],
/// `excl_claims` \[5\], `keys` \[6\] (**required**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConciseTaStore {
    /// \[1\] Optional store identity (human/audit label).
    pub store_identity: Option<String>,
    /// \[2\] **Required.** Environments these anchors apply to.
    pub environments: Vec<EnvironmentGroup>,
    /// \[3\] Purposes these anchors may be used for. **Empty means the store is
    /// unusable**, not universal — see [`ConciseTaStore::applies_to`].
    pub purposes: Vec<Purpose>,
    /// \[6\] **Required.** The anchors.
    pub keys: CasAndTas,
}

impl ConciseTaStore {
    /// Does this store apply to `purpose` in `environment`?
    ///
    /// **Fail-closed on both axes.** An empty `purposes` or `environments` list
    /// matches *nothing* — the draft treats these as constraints, so an absent
    /// constraint list is an unusable store, never a wildcard. Reading omission
    /// as "applies to everything" would silently hand every anchor unlimited
    /// scope, which is the exact failure this module exists to prevent.
    #[must_use]
    pub fn applies_to(&self, purpose: Purpose, environment: &str) -> bool {
        self.purposes.contains(&purpose)
            && self
                .environments
                .iter()
                .any(|e| e.named_ta_store == environment)
    }
}

/// A set of constrained trust-anchor stores, resolved by (purpose,
/// environment).
///
/// This is what replaces the scattered `pinned_root_der` arguments: one place
/// that answers "which anchors may I use for *this* check?".
#[derive(Debug, Clone, Default)]
pub struct TrustAnchorStore {
    stores: Vec<ConciseTaStore>,
}

impl TrustAnchorStore {
    /// An empty store. Resolving anything against it yields no anchors — a
    /// node with no pinned roots simply has no hardware evidence.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a store.
    #[must_use]
    pub fn with_store(mut self, store: ConciseTaStore) -> Self {
        self.stores.push(store);
        self
    }

    /// Every anchor admissible for `purpose` in `environment`.
    ///
    /// Returns an **empty vec on a miss — never an error**. A caller with no
    /// anchors has no hardware evidence; that is a measurement, not a failure
    /// (see the module docs).
    #[must_use]
    pub fn resolve(&self, purpose: Purpose, environment: &str) -> Vec<&TrustAnchor> {
        self.stores
            .iter()
            .filter(|s| s.applies_to(purpose, environment))
            .flat_map(|s| s.keys.tas.iter())
            .collect()
    }

    /// The DER bytes of every X.509 anchor admissible for `purpose` in
    /// `environment` — the shape the chain validators consume.
    ///
    /// Non-X.509 anchor formats are skipped rather than mis-fed to an X.509
    /// path builder.
    #[must_use]
    pub fn resolve_x509(&self, purpose: Purpose, environment: &str) -> Vec<&[u8]> {
        self.resolve(purpose, environment)
            .into_iter()
            .filter(|ta| ta.format == TaFormat::X509Cert)
            .map(|ta| ta.data.as_slice())
            .collect()
    }

    /// Intermediate CAs offered for `purpose` in `environment` (path-building
    /// help, never themselves trusted as anchors).
    #[must_use]
    pub fn resolve_cas(&self, purpose: Purpose, environment: &str) -> Vec<&[u8]> {
        self.stores
            .iter()
            .filter(|s| s.applies_to(purpose, environment))
            .flat_map(|s| s.keys.cas.iter())
            .map(Vec::as_slice)
            .collect()
    }

    /// How many stores are held (diagnostics).
    #[must_use]
    pub fn len(&self) -> usize {
        self.stores.len()
    }

    /// Is the store set empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }

    /// A census of `environment -> anchor count` for a purpose — an operator
    /// diagnostic ("which device classes can this node actually prove?").
    #[must_use]
    pub fn census(&self, purpose: Purpose) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for s in self.stores.iter().filter(|s| s.purposes.contains(&purpose)) {
            for env in &s.environments {
                *out.entry(env.named_ta_store.clone()).or_insert(0) += s.keys.tas.len();
            }
        }
        out
    }
}

/// **Baked** trust anchors — validated at load, not pasted.
///
/// Anchors ship as auditable PEM (`src/roots/*.pem`, `include_str!`'d) rather
/// than opaque byte arrays, so a reviewer can read what is trusted. Every bake
/// carries a **pinned SHA-256 of its DER**, checked on every load: swapping the
/// PEM for a different certificate fails loudly instead of silently changing
/// what the fleet trusts. Same discipline as the #107 accord genesis bake — the
/// bake is *validated*, not pasted.
pub mod baked {
    use super::{environments, single, ConciseTaStore, Purpose, TrustAnchorStore};

    /// **Yubico Attestation Root 1.**
    ///
    /// Provenance: `developers.yubico.com/PKI/yubico-ca-1.pem`, the durable
    /// root of Yubico's 2024-12 PKI (the 4-level chain
    /// `9c → f9 → Yubico PIV Attestation B 1 → Yubico Attestation Root 1`).
    /// This exact certificate was exercised end-to-end against a physical
    /// **YubiKey 5 FIPS fw 5.7.4** during the #91 validation and the #118
    /// six-key HUMANITY_ACCORD ceremony — so it is hardware-confirmed, not
    /// merely downloaded.
    ///
    /// Pin the **root**, never the rotating `B 1` intermediate.
    const YUBICO_ROOT_PEM: &str = include_str!("roots/yubico-attestation-root-1.pem");

    /// Pinned `sha256(DER)` of [`yubico_attestation_root`], lowercase hex.
    pub const YUBICO_ROOT_SHA256: &str =
        "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8";

    /// **Google Hardware Attestation Root** (`serialNumber = f92009e853b6b045`,
    /// valid 2022-03-20 → 2042-03-15).
    ///
    /// Provenance (fetched + verified 2026-08-01): served by Google's official
    /// endpoint `https://android.googleapis.com/attestation/root`, and
    /// **independently confirmed byte-identical** on the published
    /// `developer.android.com/privacy-and-security/security-key-attestation`
    /// page. Self-signature verified. Two independent Google sources agree.
    const GOOGLE_HW_ROOT_PEM: &str = include_str!("roots/google-hardware-attestation-root.pem");

    /// Pinned `sha256(DER)` of [`google_hardware_attestation_root`].
    pub const GOOGLE_HW_ROOT_SHA256: &str =
        "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc";

    /// **Google `Key Attestation CA1`** (`CN = Key Attestation CA1, O = Google
    /// LLC`, valid 2025-07-17 → 2035-07-15).
    ///
    /// Google operates **more than one** attestation root, and this newer one
    /// is served alongside the 2022 root by the same official endpoint — which
    /// is precisely why anchors belong in a store that can hold a *set* and why
    /// [`crate::device_attestation::verify_android_key_attestation_with_store`]
    /// tries **every** admissible anchor rather than a single pinned root.
    ///
    /// Same provenance + independent confirmation as
    /// [`GOOGLE_HW_ROOT_SHA256`].
    const GOOGLE_KEY_ATTEST_CA1_PEM: &str = include_str!("roots/google-key-attestation-ca1.pem");

    /// Pinned `sha256(DER)` of [`google_key_attestation_ca1`].
    pub const GOOGLE_KEY_ATTEST_CA1_SHA256: &str =
        "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0";

    /// **Apple App Attestation Root CA** (`CN = Apple App Attestation Root CA,
    /// O = Apple Inc.`, valid 2020-03-18 → 2045-03-15).
    ///
    /// Provenance (fetched + verified 2026-08-01): Apple's official certificate
    /// authority page,
    /// `https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem`.
    /// Self-signature verified.
    ///
    /// **Baked ahead of its validator.** The Apple App Attest *verifier* is
    /// still an open leg of #199 (attestation objects are CBOR, not X.509), so
    /// nothing consumes this anchor yet. It is pinned now so the trust decision
    /// is reviewed independently of the parsing work — an anchor with no
    /// validator is inert, never a weakening.
    const APPLE_APP_ATTEST_ROOT_PEM: &str = include_str!("roots/apple-app-attestation-root-ca.pem");

    /// Pinned `sha256(DER)` of [`apple_app_attestation_root`].
    pub const APPLE_APP_ATTEST_ROOT_SHA256: &str =
        "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932";

    /// A baked anchor failed its integrity check. Fail-closed: callers get no
    /// anchor rather than an unverified one.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum BakedRootError {
        /// The embedded PEM did not contain a parseable CERTIFICATE block.
        MalformedPem {
            /// Which root.
            which: &'static str,
        },
        /// The DER digest did not match the pinned fingerprint — the embedded
        /// certificate is not the one this build was reviewed against.
        FingerprintMismatch {
            /// Which root.
            which: &'static str,
            /// The pinned digest.
            expected: &'static str,
            /// What the embedded bytes actually hash to.
            found: String,
        },
    }

    impl std::fmt::Display for BakedRootError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::MalformedPem { which } => write!(f, "baked root {which}: malformed PEM"),
                Self::FingerprintMismatch {
                    which,
                    expected,
                    found,
                } => write!(
                    f,
                    "baked root {which}: fingerprint mismatch (expected {expected}, found {found})"
                ),
            }
        }
    }

    impl std::error::Error for BakedRootError {}

    /// Decode the first `CERTIFICATE` block of a PEM document to DER.
    ///
    /// Deliberately strict and dependency-free: it takes only the base64
    /// between the exact BEGIN/END markers.
    fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        let body = pem
            .split("-----BEGIN CERTIFICATE-----")
            .nth(1)?
            .split("-----END CERTIFICATE-----")
            .next()?;
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(b64).ok()
    }

    /// Load a baked PEM and enforce its pinned digest.
    fn load(
        which: &'static str,
        pem: &str,
        pinned: &'static str,
    ) -> Result<Vec<u8>, BakedRootError> {
        use sha2::{Digest, Sha256};
        let der = pem_to_der(pem).ok_or(BakedRootError::MalformedPem { which })?;
        let found = hex::encode(Sha256::digest(&der));
        if found != pinned {
            return Err(BakedRootError::FingerprintMismatch {
                which,
                expected: pinned,
                found,
            });
        }
        Ok(der)
    }

    /// The Yubico Attestation Root 1, DER — digest-checked on every call.
    ///
    /// # Errors
    /// [`BakedRootError`] if the embedded PEM is malformed or does not match
    /// [`YUBICO_ROOT_SHA256`].
    pub fn yubico_attestation_root() -> Result<Vec<u8>, BakedRootError> {
        load(
            "yubico-attestation-root-1",
            YUBICO_ROOT_PEM,
            YUBICO_ROOT_SHA256,
        )
    }

    /// The Google Hardware Attestation Root (2022), DER — digest-checked.
    ///
    /// # Errors
    /// [`BakedRootError`] on malformed PEM or fingerprint mismatch.
    pub fn google_hardware_attestation_root() -> Result<Vec<u8>, BakedRootError> {
        load(
            "google-hardware-attestation-root",
            GOOGLE_HW_ROOT_PEM,
            GOOGLE_HW_ROOT_SHA256,
        )
    }

    /// Google `Key Attestation CA1` (2025), DER — digest-checked.
    ///
    /// # Errors
    /// [`BakedRootError`] on malformed PEM or fingerprint mismatch.
    pub fn google_key_attestation_ca1() -> Result<Vec<u8>, BakedRootError> {
        load(
            "google-key-attestation-ca1",
            GOOGLE_KEY_ATTEST_CA1_PEM,
            GOOGLE_KEY_ATTEST_CA1_SHA256,
        )
    }

    /// The Apple App Attestation Root CA, DER — digest-checked.
    ///
    /// # Errors
    /// [`BakedRootError`] on malformed PEM or fingerprint mismatch.
    pub fn apple_app_attestation_root() -> Result<Vec<u8>, BakedRootError> {
        load(
            "apple-app-attestation-root-ca",
            APPLE_APP_ATTEST_ROOT_PEM,
            APPLE_APP_ATTEST_ROOT_SHA256,
        )
    }

    /// The store verify ships with.
    ///
    /// Contains every anchor that is **baked and hardware-validated** today —
    /// currently the Yubico PIV root. Google / Apple / TPM-vendor anchors are
    /// deliberately absent until their certificates are sourced and reviewed:
    /// an absent anchor means *no hardware evidence for that class*, which is a
    /// measurement, **not** a refusal (see the module docs). Callers add their
    /// own anchors with [`TrustAnchorStore::with_store`].
    #[must_use]
    pub fn default_store() -> TrustAnchorStore {
        let mut store = TrustAnchorStore::new();

        if let Ok(der) = yubico_attestation_root() {
            store = store.with_store(single(
                environments::YUBIKEY_PIV,
                Purpose::KeyAttestation,
                vec![der],
            ));
        }

        // Google runs MORE THAN ONE attestation root; both ride in one store
        // for the Android environment and the validator tries each.
        let google: Vec<Vec<u8>> = [
            google_hardware_attestation_root(),
            google_key_attestation_ca1(),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !google.is_empty() {
            store = store.with_store(single(
                environments::ANDROID_KEYSTORE,
                Purpose::KeyAttestation,
                google,
            ));
        }

        // Baked ahead of its validator (the Apple leg of #199 is still open):
        // an anchor with no consumer is inert, never a weakening.
        if let Ok(der) = apple_app_attestation_root() {
            store = store.with_store(single(
                environments::APPLE_APP_ATTEST,
                Purpose::KeyAttestation,
                vec![der],
            ));
        }

        store
    }

    /// A single-anchor store for `environment`, for callers supplying their own
    /// reviewed root (e.g. the Google Hardware Attestation Root).
    #[must_use]
    pub fn anchor_for(environment: &str, der: Vec<u8>) -> ConciseTaStore {
        single(environment, Purpose::KeyAttestation, vec![der])
    }
}

/// The environment labels verify's own trust shapes use.
///
/// These are the **superset** of what we need today, named once so a store
/// producer and a validator cannot drift on spelling. Adding a device class is
/// a new constant here plus anchors in the store — not a new pinned-root
/// parameter threaded through another call site.
pub mod environments {
    /// YubiKey PIV attestation (CIRISVerify#91) — the Yubico Attestation Root.
    pub const YUBIKEY_PIV: &str = "yubikey-piv";
    /// Android Keystore key attestation (CIRISVerify#199) — the Google
    /// Hardware Attestation Root.
    pub const ANDROID_KEYSTORE: &str = "android-keystore";
    /// Apple App Attest / DeviceCheck (open leg of #199).
    pub const APPLE_APP_ATTEST: &str = "apple-app-attest";
    /// TPM 2.0 endorsement-key roots — a vendor **set** (Infineon, ST,
    /// Nuvoton, AMD, Intel, Qualcomm), which is precisely why it needs a store
    /// rather than a single pinned root (open leg of #199).
    pub const TPM_EK: &str = "tpm-ek";
    /// FIDO authenticator attestation roots, as distributed by the FIDO
    /// Metadata Service.
    pub const FIDO_MDS: &str = "fido-mds";
    /// PKIX / TLS server certificates.
    pub const TLS_PKIX: &str = "tls-pkix";
}

/// Build a single-purpose, single-environment store — the common case.
///
/// ```
/// use ciris_verify_core::trust_anchor_store::{
///     environments, single, Purpose, TrustAnchorStore,
/// };
///
/// let store = TrustAnchorStore::new().with_store(single(
///     environments::ANDROID_KEYSTORE,
///     Purpose::KeyAttestation,
///     vec![b"<google root der>".to_vec()],
/// ));
///
/// assert_eq!(
///     store
///         .resolve_x509(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE)
///         .len(),
///     1
/// );
/// // The same root is NOT admissible for a different environment.
/// assert!(store
///     .resolve_x509(Purpose::KeyAttestation, environments::YUBIKEY_PIV)
///     .is_empty());
/// ```
#[must_use]
pub fn single(environment: &str, purpose: Purpose, x509_ders: Vec<Vec<u8>>) -> ConciseTaStore {
    ConciseTaStore {
        store_identity: Some(format!("{environment}/{}", purpose.label())),
        environments: vec![EnvironmentGroup::named(environment)],
        purposes: vec![purpose],
        keys: CasAndTas {
            tas: x509_ders.into_iter().map(TrustAnchor::x509).collect(),
            cas: Vec::new(),
        },
    }
}

/// Cache for the **expensive, stable** half of attestation verification.
///
/// ## What may and may not be cached
///
/// Caching a *verification decision* is caching a security decision, and it is
/// how stale-accept bugs happen. This cache therefore holds only the part that
/// is expensive **and** a pure function of its inputs — the X.509 chain path
/// validation — and never the volatile policy checks:
///
/// | Check | Cached | Why |
/// |---|---|---|
/// | Chain path validation (signatures) | **yes** | expensive; deterministic in `(leaf, intermediates, root)` |
/// | `attestationChallenge` match | **never** | it *is* the anti-replay check — caching defeats its only purpose |
/// | Attested-key binding | never | cheap; no reason to risk it |
/// | Purpose/environment resolution | never | cheap, and a policy change must take effect immediately |
/// | Revocation status | never | the classic stale-accept hole |
///
/// So a rotated policy or an expired challenge takes effect instantly, while
/// repeated validation of the same chain still can't burn CPU — the DoS
/// property we actually wanted.
///
/// ## Keying and bounds
///
/// The key is `sha256` over the **exact bytes** that determine the outcome
/// (`leaf ‖ each intermediate ‖ root`) — never a weaker handle like a key_id,
/// which an attacker could reuse across different chains. Capacity is bounded
/// (an unbounded map is a memory-DoS), evicting oldest-first.
///
/// **Negative results are not cached.** Caching failures would let a transient
/// fault persist and would let an attacker poison entries for a legitimate
/// peer; the CPU-DoS argument is already answered by caching the positive path.
#[derive(Debug)]
pub struct ChainValidationCache {
    entries: std::sync::Mutex<Vec<([u8; 32], u64)>>,
    capacity: usize,
}

impl ChainValidationCache {
    /// A cache holding at most `capacity` validated chains.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
            capacity: capacity.max(1),
        }
    }

    /// The cache key for a chain — `sha256(leaf ‖ intermediates… ‖ root)`.
    #[must_use]
    pub fn key(leaf: &[u8], intermediates: &[&[u8]], root: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(leaf);
        for i in intermediates {
            h.update(i);
        }
        h.update(root);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Has this exact chain already validated, and not yet expired?
    ///
    /// `now_epoch_secs` is caller-supplied — this crate is clock-free so
    /// behaviour stays reproducible in tests (the same discipline as
    /// [`crate::reconsider_dos`]).
    #[must_use]
    pub fn is_valid(&self, key: &[u8; 32], now_epoch_secs: u64) -> bool {
        self.entries
            .lock()
            .is_ok_and(|e| e.iter().any(|(k, exp)| k == key && *exp > now_epoch_secs))
    }

    /// Record that this chain validated, expiring at `expires_at_epoch_secs`.
    ///
    /// The caller MUST bound the expiry by the evidence's own validity —
    /// `min(policy_ttl, leaf notAfter)` — so a cache entry can never outlive
    /// the certificate that justified it.
    pub fn record_valid(&self, key: [u8; 32], expires_at_epoch_secs: u64) {
        if let Ok(mut e) = self.entries.lock() {
            e.retain(|(k, _)| k != &key);
            if e.len() >= self.capacity {
                e.remove(0);
            }
            e.push((key, expires_at_epoch_secs));
        }
    }

    /// Drop entries that expired at or before `now_epoch_secs`.
    pub fn evict_expired(&self, now_epoch_secs: u64) {
        if let Ok(mut e) = self.entries.lock() {
            e.retain(|(_, exp)| *exp > now_epoch_secs);
        }
    }

    /// Number of entries currently held (diagnostics).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |e| e.len())
    }

    /// Is the cache empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anchors are seeded from the environment name so two stores never carry
    /// byte-identical anchors — otherwise a cross-environment leak test would
    /// pass vacuously.
    fn store_with(env: &str, purpose: Purpose, n: usize) -> ConciseTaStore {
        single(
            env,
            purpose,
            (0..n)
                .map(|i| format!("{env}#{i}").into_bytes())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn resolves_anchors_for_the_matching_purpose_and_environment() {
        let s = TrustAnchorStore::new().with_store(store_with(
            environments::ANDROID_KEYSTORE,
            Purpose::KeyAttestation,
            2,
        ));
        assert_eq!(
            s.resolve(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE)
                .len(),
            2
        );
    }

    /// THE security property: an anchor admitted for one environment must not
    /// satisfy a lookup for another. A flat root list cannot express this.
    #[test]
    fn anchors_do_not_leak_across_environments() {
        let s = TrustAnchorStore::new()
            .with_store(store_with(
                environments::YUBIKEY_PIV,
                Purpose::KeyAttestation,
                1,
            ))
            .with_store(store_with(
                environments::ANDROID_KEYSTORE,
                Purpose::KeyAttestation,
                1,
            ));

        let yubi = s.resolve(Purpose::KeyAttestation, environments::YUBIKEY_PIV);
        let android = s.resolve(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE);
        assert_eq!(yubi.len(), 1);
        assert_eq!(android.len(), 1);
        assert_ne!(
            yubi[0], android[0],
            "each environment must resolve to its OWN anchor"
        );
    }

    /// The other half: a key-attestation root must not become a TLS root.
    #[test]
    fn anchors_do_not_leak_across_purposes() {
        let s = TrustAnchorStore::new().with_store(store_with(
            environments::ANDROID_KEYSTORE,
            Purpose::KeyAttestation,
            1,
        ));
        assert!(
            s.resolve(Purpose::Certificate, environments::ANDROID_KEYSTORE)
                .is_empty(),
            "a key-attestation anchor must not satisfy a certificate lookup"
        );
    }

    /// An absent constraint list is NOT a wildcard — reading omission as
    /// "applies to everything" would hand every anchor unlimited scope.
    #[test]
    fn empty_constraint_lists_match_nothing() {
        let no_purpose = ConciseTaStore {
            store_identity: None,
            environments: vec![EnvironmentGroup::named(environments::TPM_EK)],
            purposes: vec![],
            keys: CasAndTas {
                tas: vec![TrustAnchor::x509(vec![1, 2, 3])],
                cas: vec![],
            },
        };
        assert!(!no_purpose.applies_to(Purpose::KeyAttestation, environments::TPM_EK));

        let no_env = ConciseTaStore {
            store_identity: None,
            environments: vec![],
            purposes: vec![Purpose::KeyAttestation],
            keys: CasAndTas {
                tas: vec![TrustAnchor::x509(vec![1, 2, 3])],
                cas: vec![],
            },
        };
        assert!(!no_env.applies_to(Purpose::KeyAttestation, environments::TPM_EK));
    }

    /// A miss is an empty result, never an error — hardware is a signal, not a
    /// requirement.
    #[test]
    fn a_miss_is_empty_not_an_error() {
        let s = TrustAnchorStore::new();
        assert!(s
            .resolve(Purpose::KeyAttestation, environments::APPLE_APP_ATTEST)
            .is_empty());
        assert!(s.is_empty());
    }

    /// The TPM case is exactly why a store beats a pinned root: one
    /// environment, many vendor anchors.
    #[test]
    fn one_environment_can_carry_a_vendor_set() {
        let s = TrustAnchorStore::new().with_store(single(
            environments::TPM_EK,
            Purpose::KeyAttestation,
            vec![
                b"infineon".to_vec(),
                b"st".to_vec(),
                b"nuvoton".to_vec(),
                b"amd".to_vec(),
                b"intel".to_vec(),
                b"qualcomm".to_vec(),
            ],
        ));
        assert_eq!(
            s.resolve_x509(Purpose::KeyAttestation, environments::TPM_EK)
                .len(),
            6
        );
    }

    #[test]
    fn resolve_x509_skips_non_x509_formats() {
        let mut st = store_with(environments::FIDO_MDS, Purpose::KeyAttestation, 0);
        st.keys.tas = vec![
            TrustAnchor::x509(vec![9, 9]),
            TrustAnchor {
                format: TaFormat::SubjectPublicKeyInfo,
                data: vec![7, 7],
            },
        ];
        let s = TrustAnchorStore::new().with_store(st);
        let ders = s.resolve_x509(Purpose::KeyAttestation, environments::FIDO_MDS);
        assert_eq!(
            ders.len(),
            1,
            "the bare SPKI must not be fed to an X.509 path"
        );
        assert_eq!(ders[0], &[9, 9]);
    }

    #[test]
    fn census_reports_provable_device_classes() {
        let s = TrustAnchorStore::new()
            .with_store(store_with(
                environments::YUBIKEY_PIV,
                Purpose::KeyAttestation,
                1,
            ))
            .with_store(store_with(environments::TPM_EK, Purpose::KeyAttestation, 3));
        let c = s.census(Purpose::KeyAttestation);
        assert_eq!(c.get(environments::YUBIKEY_PIV), Some(&1));
        assert_eq!(c.get(environments::TPM_EK), Some(&3));
        assert_eq!(c.get(environments::APPLE_APP_ATTEST), None);
    }

    // --- baked roots ---

    /// The bake is VALIDATED, not pasted: the embedded PEM must hash to the
    /// pinned digest, so swapping the file fails loudly.
    #[test]
    fn baked_yubico_root_matches_its_pinned_fingerprint() {
        let der = baked::yubico_attestation_root().expect("baked root must load");
        assert!(!der.is_empty());

        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(&der)),
            baked::YUBICO_ROOT_SHA256,
            "embedded certificate is not the reviewed one"
        );
    }

    /// The baked root is reachable through the store at its own environment —
    /// and only there.
    #[test]
    fn default_store_carries_the_yubico_root_scoped_to_piv() {
        let s = baked::default_store();
        assert_eq!(
            s.resolve_x509(Purpose::KeyAttestation, environments::YUBIKEY_PIV)
                .len(),
            1
        );
        // Containment asserted by IDENTITY, not by emptiness: the Android slot
        // legitimately holds Google's roots now, so the property under test is
        // that the *Yubico* anchor specifically is not among them.
        use sha2::{Digest, Sha256};
        let android: Vec<String> = s
            .resolve_x509(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE)
            .iter()
            .map(|d| hex::encode(Sha256::digest(d)))
            .collect();
        assert!(
            !android.contains(&baked::YUBICO_ROOT_SHA256.to_string()),
            "the Yubico root must not be reachable as an Android anchor"
        );
        assert!(
            s.resolve_x509(Purpose::Certificate, environments::YUBIKEY_PIV)
                .is_empty(),
            "a key-attestation anchor must not serve certificate validation"
        );
    }

    /// Every baked anchor must match its pinned digest — the bake is validated,
    /// not pasted, for all of them.
    #[test]
    fn every_baked_anchor_matches_its_pinned_fingerprint() {
        use sha2::{Digest, Sha256};
        for (name, loaded, pinned) in [
            (
                "yubico",
                baked::yubico_attestation_root(),
                baked::YUBICO_ROOT_SHA256,
            ),
            (
                "google-hw-root",
                baked::google_hardware_attestation_root(),
                baked::GOOGLE_HW_ROOT_SHA256,
            ),
            (
                "google-key-attestation-ca1",
                baked::google_key_attestation_ca1(),
                baked::GOOGLE_KEY_ATTEST_CA1_SHA256,
            ),
            (
                "apple-app-attest",
                baked::apple_app_attestation_root(),
                baked::APPLE_APP_ATTEST_ROOT_SHA256,
            ),
        ] {
            let der = loaded.unwrap_or_else(|e| panic!("{name} must load: {e}"));
            assert!(!der.is_empty(), "{name} empty");
            assert_eq!(
                hex::encode(Sha256::digest(&der)),
                pinned,
                "{name}: embedded certificate is not the reviewed one"
            );
        }
    }

    /// Google operates MORE THAN ONE attestation root — both must be reachable
    /// under the Android environment. This is the concrete case that a single
    /// pinned root could not have expressed.
    #[test]
    fn android_environment_carries_both_google_roots() {
        let s = baked::default_store();
        let anchors = s.resolve_x509(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE);
        assert_eq!(anchors.len(), 2, "both Google roots must be admissible");

        use sha2::{Digest, Sha256};
        let digests: Vec<String> = anchors
            .iter()
            .map(|d| hex::encode(Sha256::digest(d)))
            .collect();
        assert!(digests.contains(&baked::GOOGLE_HW_ROOT_SHA256.to_string()));
        assert!(digests.contains(&baked::GOOGLE_KEY_ATTEST_CA1_SHA256.to_string()));
    }

    /// Containment holds across the populated store: no baked anchor leaks into
    /// another environment.
    #[test]
    fn baked_anchors_stay_in_their_own_environments() {
        let s = baked::default_store();
        assert_eq!(
            s.resolve(Purpose::KeyAttestation, environments::YUBIKEY_PIV)
                .len(),
            1
        );
        assert_eq!(
            s.resolve(Purpose::KeyAttestation, environments::ANDROID_KEYSTORE)
                .len(),
            2
        );
        assert_eq!(
            s.resolve(Purpose::KeyAttestation, environments::APPLE_APP_ATTEST)
                .len(),
            1
        );
        // Nothing is reachable for a purpose it was not admitted for.
        for env in [
            environments::YUBIKEY_PIV,
            environments::ANDROID_KEYSTORE,
            environments::APPLE_APP_ATTEST,
        ] {
            assert!(
                s.resolve(Purpose::Certificate, env).is_empty(),
                "{env}: key-attestation anchors must not serve certificate validation"
            );
        }
    }

    /// Classes with no baked anchor yield no evidence — not an error. TPM is
    /// still unsourced (a vendor SET, tracked on #199).
    #[test]
    fn unbaked_classes_are_absent_not_failing() {
        let s = baked::default_store();
        for env in [environments::TPM_EK, environments::FIDO_MDS] {
            assert!(s.resolve(Purpose::KeyAttestation, env).is_empty());
        }
    }

    // --- chain validation cache ---

    #[test]
    fn cache_hits_only_the_exact_chain_and_respects_expiry() {
        let c = ChainValidationCache::with_capacity(8);
        let k = ChainValidationCache::key(b"leaf", &[b"mid"], b"root");
        let other = ChainValidationCache::key(b"leaf", &[b"mid"], b"OTHER-root");

        assert!(!c.is_valid(&k, 100), "cold cache must miss");
        c.record_valid(k, 200);
        assert!(c.is_valid(&k, 100), "within TTL");
        assert!(
            !c.is_valid(&k, 200),
            "expiry is exclusive — no stale accept"
        );
        assert!(!c.is_valid(&k, 300), "past TTL");
        assert!(
            !c.is_valid(&other, 100),
            "a different root must not hit the same entry"
        );
    }

    /// Unbounded growth is a memory-DoS; capacity is enforced.
    #[test]
    fn cache_is_bounded() {
        let c = ChainValidationCache::with_capacity(4);
        for i in 0..32u8 {
            c.record_valid(ChainValidationCache::key(&[i], &[], b"root"), 999);
        }
        assert!(c.len() <= 4, "cache must not grow without bound");
    }

    #[test]
    fn cache_evicts_expired_entries() {
        let c = ChainValidationCache::with_capacity(8);
        c.record_valid(ChainValidationCache::key(b"a", &[], b"r"), 50);
        c.record_valid(ChainValidationCache::key(b"b", &[], b"r"), 500);
        c.evict_expired(100);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn wire_values_and_labels_track_the_draft() {
        assert_eq!(TaFormat::X509Cert.wire_value(), 0);
        assert_eq!(TaFormat::TrustAnchorInfo.wire_value(), 1);
        assert_eq!(TaFormat::SubjectPublicKeyInfo.wire_value(), 2);
        assert_eq!(Purpose::KeyAttestation.label(), "key-attestation");
        assert_eq!(Purpose::Certificate.label(), "certificate");
        assert_eq!(Purpose::Dloa.label(), "dloa");
    }
}
