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

impl crate::classification::Classification for Purpose {
    /// **STRUCTURAL**, not merely normative (CIRISOntology#3 disposition
    /// split). The `$$tas-list-purpose` values are **wire values** with pinned
    /// CDDL indices: deviating does not defy the draft's authors, it breaks
    /// CBOR dispatch against every other CoTS implementation. No body can
    /// waive that, which is exactly what distinguishes this from a ruling —
    /// a consumer who disagrees files a bug, it does not petition the IETF.
    ///
    /// Constrained resolution gates on this by design; that containment is the
    /// module's entire security property.
    fn gating() -> crate::classification::Gating {
        crate::classification::Gating::Structural {
            breaks:
                "CBOR wire interop with other draft-ietf-rats-concise-ta-stores implementations",
        }
    }
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

/// **How an anchor was sourced** — machine-readable provenance (CIRISPersist,
/// on CIRISVerify#241).
///
/// Baking an aggregation at the same tier as a vendor-official root makes the
/// *declared* depth stronger than the *actual* provenance. That is the defect
/// the CIRISPersist#545/#554 arc cost a live ceremony to learn: **never let
/// evidence be synthesized to satisfy your own gate.** Recording the tier makes
/// weaker provenance a value a consumer can read and gate on, rather than a
/// footnote in a commit message.
///
/// This is **[`Gating::Measurement`](crate::classification::Gating::Measurement)**:
/// it states how an anchor reached us. Whether a given tier is acceptable is
/// the consumer's policy — a mesh may reasonably accept `CommunityAggregated`
/// TPM roots while a high-assurance deployment refuses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// **Variant order is weakest-to-strongest, and that is load-bearing:** the
/// derived `Ord` is what makes `provenance >= min` mean *"at least this well
/// sourced"* in
/// [`resolve_x509_min_provenance`](TrustAnchorStore::resolve_x509_min_provenance).
/// Reordering these variants silently changes which anchors a strict consumer
/// admits, so the ordering is asserted by test.
pub enum AnchorProvenance {
    /// Supplied by the caller at runtime — provenance is whatever the caller
    /// knows, and this store makes no claim about it. **Weakest.**
    CallerSupplied,
    /// From a **community-curated aggregation** (e.g. `1id-com/tpm-manufacturer-cas`)
    /// or a vendor-adjacent bundle (Microsoft `TrustedTPM.cab`) rather than the
    /// vendor's own endpoint. Weaker provenance; a consumer may refuse it.
    CommunityAggregated,
    /// Fetched from the **vendor's own endpoint**, self-signature verified, and
    /// (where a second official source exists) cross-checked byte-identical.
    /// The Google / Apple bakes.
    VendorOfficial,
    /// Additionally **exercised end-to-end against physical hardware** — the
    /// **strongest** tier. Currently only the Yubico root (#91 validation + the
    /// #118 six-key ceremony).
    HardwareValidated,
}

impl AnchorProvenance {
    /// Was this anchor obtained from the vendor itself (either official tier)?
    #[must_use]
    pub const fn is_vendor_sourced(self) -> bool {
        matches!(self, Self::VendorOfficial | Self::HardwareValidated)
    }
}

impl crate::classification::Classification for AnchorProvenance {
    /// **MEASUREMENT.** States how an anchor was sourced; whether a tier is
    /// acceptable is consumer policy.
    fn gating() -> crate::classification::Gating {
        crate::classification::Gating::Measurement
    }
}

/// A trust anchor — `trust-anchor = [ format => $pkix-ta-type, data => bstr ]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// How `data` is encoded.
    pub format: TaFormat,
    /// The anchor bytes.
    pub data: Vec<u8>,
    /// How this anchor was sourced. Defaults to
    /// [`AnchorProvenance::CallerSupplied`] via [`TrustAnchor::x509`] — a store
    /// never silently upgrades a caller's anchor to a vendor tier.
    pub provenance: AnchorProvenance,
}

impl TrustAnchor {
    /// A DER X.509 certificate anchor — the common case.
    #[must_use]
    pub fn x509(der: impl Into<Vec<u8>>) -> Self {
        Self {
            format: TaFormat::X509Cert,
            data: der.into(),
            provenance: AnchorProvenance::CallerSupplied,
        }
    }

    /// A DER X.509 anchor with a stated provenance tier.
    #[must_use]
    pub fn x509_with_provenance(der: impl Into<Vec<u8>>, provenance: AnchorProvenance) -> Self {
        Self {
            format: TaFormat::X509Cert,
            data: der.into(),
            provenance,
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

    /// Anchors admissible for `purpose` in `environment` whose provenance is at
    /// least `min` — the consumer-policy half of the tier
    /// (CIRISPersist, on CIRISVerify#241).
    ///
    /// A deployment that refuses community-aggregated roots calls this with
    /// [`AnchorProvenance::VendorOfficial`]; one that accepts them calls
    /// [`resolve_x509`](Self::resolve_x509). Weaker provenance is thereby a
    /// value a consumer gates on, not a footnote it has to know about.
    ///
    /// Ordering: [`AnchorProvenance`] is ordered weakest-to-strongest
    /// (`CallerSupplied < CommunityAggregated < VendorOfficial <
    /// HardwareValidated`), so `min = VendorOfficial` admits both vendor tiers
    /// and excludes aggregation- and caller-sourced anchors.
    #[must_use]
    pub fn resolve_x509_min_provenance(
        &self,
        purpose: Purpose,
        environment: &str,
        min: AnchorProvenance,
    ) -> Vec<&[u8]> {
        self.resolve(purpose, environment)
            .into_iter()
            .filter(|ta| ta.format == TaFormat::X509Cert && ta.provenance >= min)
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

    /// One baked TPM vendor root CA.
    #[derive(Debug, Clone, Copy)]
    pub struct BakedTpmRoot {
        /// The vendor directory this root was filed under upstream.
        pub vendor: &'static str,
        /// Stable identifier, also the PEM filename stem.
        pub name: &'static str,
        /// The auditable PEM.
        pub pem: &'static str,
        /// Pinned `sha256(DER)`.
        pub sha256: &'static str,
    }

    /// **The baked TPM EK vendor roots.**
    ///
    /// # Provenance — read this before trusting the tier
    ///
    /// These are [`AnchorProvenance::CommunityAggregated`](super::AnchorProvenance::CommunityAggregated), **not**
    /// [`AnchorProvenance::VendorOfficial`](super::AnchorProvenance::VendorOfficial), and the distinction is real:
    /// they were obtained from Microsoft's `TrustedTPM.cab` distribution, so
    /// Microsoft — a third party to Infineon, Nuvoton, ST, and the rest — is
    /// the party attesting that these are those vendors' roots. A caller who
    /// requires first-party sourcing excludes them with
    /// [`TrustAnchorStore::resolve_x509_min_provenance`](super::TrustAnchorStore::resolve_x509_min_provenance).
    ///
    /// Four sourcing routes were attempted before settling here; the full
    /// record, including what failed and why, is in
    /// `docs/TPM_ANCHOR_PROVENANCE.md`. In short: no TPM vendor publishes its
    /// root CAs at a stable, machine-fetchable endpoint the way Google and
    /// Apple do, and the one community aggregation that claims to
    /// (`1id-com/tpm-manufacturer-cas`) contains **zero certificates** — it is
    /// a scaffold, not a trust store.
    ///
    /// # What was and was not baked
    ///
    /// From 2,567 certificates across nine vendor directories, only
    /// **self-signed roots** are here — 40 of them. Excluded: every
    /// intermediate (pinning an intermediate as an anchor is the mistake the
    /// Yubico bake explicitly avoided — pin the durable root, never the
    /// rotating issuer), the 2,184 Microsoft-issued certificates, and one
    /// Infineon root that **expired in 2018**. Every remaining root had its
    /// self-signature cryptographically verified, not merely name-matched.
    ///
    /// Note that a few entries are third-party CAs filed under a vendor
    /// (VeriSign under Infineon, GlobalSign under ST, a Microsoft TPM root
    /// under Qualcomm). That is not an error: those vendors genuinely chain
    /// their EK certificates under those CAs.
    ///
    /// # Why a table and not one constant per root
    ///
    /// **Nuvoton alone ships 17 roots.** A `pinned_root` parameter could not
    /// have expressed this vendor at all — which is the same lesson the two
    /// Google roots taught, only louder, and the reason the store resolves a
    /// *set* per environment and the validator tries every admissible anchor.
    pub const TPM_VENDOR_ROOTS: &[BakedTpmRoot] = &[
        BakedTpmRoot {
            vendor: "AMD",
            name: "amd-amd-root-ca-r4",
            pem: include_str!("roots/tpm/amd-amd-root-ca-r4.pem"),
            sha256: "853d5c5abe1fe97bddb62db0aecb4888a52c83353645cf70b12289d62257e78d",
        },
        BakedTpmRoot {
            vendor: "AMD",
            name: "amd-microsoft-pluton-root-ca-2021",
            pem: include_str!("roots/tpm/amd-microsoft-pluton-root-ca-2021.pem"),
            sha256: "32ab5fe7cb4396659fcb621ca14c6fb8fc2420f64050637d77e45a86c5d3916e",
        },
        BakedTpmRoot {
            vendor: "Atmel",
            name: "atmel-atmel-tpm-root-signing-module",
            pem: include_str!("roots/tpm/atmel-atmel-tpm-root-signing-module.pem"),
            sha256: "3784884ec83a8d7edbfb928ac878dc75c11451381c6a0cb27aaffb3171e0d33f",
        },
        BakedTpmRoot {
            vendor: "Infineon",
            name: "infineon-infineon-optiga-tm-ecc-root-ca",
            pem: include_str!("roots/tpm/infineon-infineon-optiga-tm-ecc-root-ca.pem"),
            sha256: "cfeb02fecd55ad7a73c6e1d11985d4c47dee248ab63dcb66091a2489660443c3",
        },
        BakedTpmRoot {
            vendor: "Infineon",
            name: "infineon-infineon-optiga-tm-ecc-root-ca-2",
            pem: include_str!("roots/tpm/infineon-infineon-optiga-tm-ecc-root-ca-2.pem"),
            sha256: "ee0c827555c4e9012037df4257bb8aaa26084a17b13ede41cd7895c8d6c11190",
        },
        BakedTpmRoot {
            vendor: "Infineon",
            name: "infineon-infineon-optiga-tm-ecc-root-ca-3",
            pem: include_str!("roots/tpm/infineon-infineon-optiga-tm-ecc-root-ca-3.pem"),
            sha256: "5a84cc3476221cce5be81af8d755d175fea03d208b3412a231710c56774542fd",
        },
        BakedTpmRoot {
            vendor: "Infineon",
            name: "infineon-infineon-optiga-tm-rsa-root-ca",
            pem: include_str!("roots/tpm/infineon-infineon-optiga-tm-rsa-root-ca.pem"),
            sha256: "899e35474c9807eb4c7f2f7a12da0028fb250cd02154d0009fca7d9c66574f3b",
        },
        BakedTpmRoot {
            vendor: "Infineon",
            name: "infineon-infineon-optiga-tm-rsa-root-ca-2",
            pem: include_str!("roots/tpm/infineon-infineon-optiga-tm-rsa-root-ca-2.pem"),
            sha256: "b413c71580af3ec5efe83fad31db2d4af4612355e3b01e50903b10763d738894",
        },
        BakedTpmRoot {
            vendor: "Infineon",
            name: "infineon-infineon-optiga-tm-rsa-root-ca-3",
            pem: include_str!("roots/tpm/infineon-infineon-optiga-tm-rsa-root-ca-3.pem"),
            sha256: "976b0579c016741b0003bf8055e920ab08f72abc819547b3480b0c141e956b70",
        },
        BakedTpmRoot {
            vendor: "Infineon",
            name: "infineon-verisign-trusted-platform-module-root-ca",
            pem: include_str!("roots/tpm/infineon-verisign-trusted-platform-module-root-ca.pem"),
            sha256: "967bb3d4544ea2740fce338077e1f5a9ea3085667246e6b968294aa045a57549",
        },
        BakedTpmRoot {
            vendor: "Intel",
            name: "intel-www-intel-com-2e1b3ba7",
            pem: include_str!("roots/tpm/intel-www-intel-com-2e1b3ba7.pem"),
            sha256: "2e1b3ba79af56d758be51697621bc4b9e8cee0983db3e749c55eb9b37c6d2ae0",
        },
        BakedTpmRoot {
            vendor: "Intel",
            name: "intel-www-intel-com-beb40bb7",
            pem: include_str!("roots/tpm/intel-www-intel-com-beb40bb7.pem"),
            sha256: "beb40bb7507b33967226aa80e084749fbb6593893c642e818d682e9a8d07fc24",
        },
        BakedTpmRoot {
            vendor: "NationZ",
            name: "nationz-nations-tpm-ecc-root-ca-001",
            pem: include_str!("roots/tpm/nationz-nations-tpm-ecc-root-ca-001.pem"),
            sha256: "31e7a6de95991cfcca3e7c1680be3ba96de8b2c4bca72da1072ee699da23b2d2",
        },
        BakedTpmRoot {
            vendor: "NationZ",
            name: "nationz-nations-tpm-rsa-root-ca-001",
            pem: include_str!("roots/tpm/nationz-nations-tpm-rsa-root-ca-001.pem"),
            sha256: "00608b414f9c522c5d30366c4b751681c3fd10b7ea0027e0f3877742c477c5a7",
        },
        BakedTpmRoot {
            vendor: "NationZ",
            name: "nationz-nationz-tpm-root-ca",
            pem: include_str!("roots/tpm/nationz-nationz-tpm-root-ca.pem"),
            sha256: "1293d71d6f61c86b98102fd3d4085ff12538f108e925489c0d545059e5f89c36",
        },
        BakedTpmRoot {
            vendor: "NationZ",
            name: "nationz-nsing-tpm-ecc-root-ca-001",
            pem: include_str!("roots/tpm/nationz-nsing-tpm-ecc-root-ca-001.pem"),
            sha256: "6ccf8a8a803d07a002a15d4889ffa0b125e4a82a1fe4211db3c6e8592919f9dc",
        },
        BakedTpmRoot {
            vendor: "NationZ",
            name: "nationz-nsing-tpm-rsa-root-ca-001",
            pem: include_str!("roots/tpm/nationz-nsing-tpm-rsa-root-ca-001.pem"),
            sha256: "72ca00612395af027cd84c5514219f110e964dfa0bfc1efbb3ac147e3b173971",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-npctxxx-ecc521-rootca",
            pem: include_str!("roots/tpm/nuvoton-npctxxx-ecc521-rootca.pem"),
            sha256: "083e7bd13e8fe0bb9b0c64db9e0c8356681df65714d2d5c4925eb98ae1369d40",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-ntc-tpm-ek-root-ca-01",
            pem: include_str!("roots/tpm/nuvoton-ntc-tpm-ek-root-ca-01.pem"),
            sha256: "56b67007f448bd5c5746299fcdea9323971bbdaaefd8e3b9b84773abc888c90e",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-ntc-tpm-ek-root-ca-02",
            pem: include_str!("roots/tpm/nuvoton-ntc-tpm-ek-root-ca-02.pem"),
            sha256: "8fac94b462b37acb84431bdc71395585caf518c17f656051ff9c4347a4726ed9",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-ntc-tpm-ek-root-ca-arsuf-01",
            pem: include_str!("roots/tpm/nuvoton-ntc-tpm-ek-root-ca-arsuf-01.pem"),
            sha256: "9e0434093fd0d4f8b927af1f4f6cffbd75f0584af4ade939bbd6851227fa4263",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-1013",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-1013.pem"),
            sha256: "38f8c5012d1b1321e833376611612b5b1cde466574cabc67fd2262e3b8da2f6d",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-1014",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-1014.pem"),
            sha256: "ad392726a92f62e5b7b112460c4e89f9fcbd523d08f39dcb928210ce8d4f676f",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-1110",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-1110.pem"),
            sha256: "2782e51a95e86d9557fe4204316cf805bd6f5898f81f9732e944d742bcdc5f54",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-1111",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-1111.pem"),
            sha256: "e38c280f7c0e0b49f31efc7531032bb6a86c3fba4eb89beb1d510eaa4510ae4a",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-2010",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-2010.pem"),
            sha256: "970b1cb098896f0d31be45dd299ed31f1640689f7c1618d7370cd71b6eb97560",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-2011",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-2011.pem"),
            sha256: "ab6005053c48534c46f54d2afbbd300a99f7b0e3ab1786034cb0785ca081a7ba",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-2012",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-2012.pem"),
            sha256: "dc79aaba3d09f42a9da4ecd91db0289214e56c16e4201be6ae67433ad273c6dc",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-2110",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-2110.pem"),
            sha256: "4aebe77a51ed29959a7f9f5e07a24a558dee8167f3985d724995a541c258dfda",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-2111",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-2111.pem"),
            sha256: "cd8185ff8995ed09811970090a8c36fafab34ef87f47fa51fdb9ecf95c9c2e04",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvoton-tpm-root-ca-2112",
            pem: include_str!("roots/tpm/nuvoton-nuvoton-tpm-root-ca-2112.pem"),
            sha256: "66e3a1013d4f697700f731e7d68c69b58351f90ec9580d85862d020ab4abf1af",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvotontpmrootca1210",
            pem: include_str!("roots/tpm/nuvoton-nuvotontpmrootca1210.pem"),
            sha256: "ba70a6ea7b77c7fee8947a07b1e70e0b26d39ce5e6307f63d5e4b9507f19a157",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvotontpmrootca2210",
            pem: include_str!("roots/tpm/nuvoton-nuvotontpmrootca2210.pem"),
            sha256: "fc61abbc18100f460205ebe09d8c3e6995ac2be2234344a7facb62e15f9a7584",
        },
        BakedTpmRoot {
            vendor: "Nuvoton",
            name: "nuvoton-nuvotontpmrootca2211",
            pem: include_str!("roots/tpm/nuvoton-nuvotontpmrootca2211.pem"),
            sha256: "2bbc5db224b8f28a6d2cf336d4da7ab21c8c490e3d60ef497801dc0b6ac00227",
        },
        BakedTpmRoot {
            vendor: "QC",
            name: "qc-microsoft-tpm-root-certificate-authority-2014",
            pem: include_str!("roots/tpm/qc-microsoft-tpm-root-certificate-authority-2014.pem"),
            sha256: "870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da",
        },
        BakedTpmRoot {
            vendor: "QC",
            name: "qc-qualcomm-wes-secure-provisioning-root-v2",
            pem: include_str!("roots/tpm/qc-qualcomm-wes-secure-provisioning-root-v2.pem"),
            sha256: "87c849b6ca87a58a0af4031531e49216d149e62a52ebea5df1805819cf44250e",
        },
        BakedTpmRoot {
            vendor: "STMicro",
            name: "stmicro-globalsign-trusted-platform-module-ecc-root-ca",
            pem: include_str!(
                "roots/tpm/stmicro-globalsign-trusted-platform-module-ecc-root-ca.pem"
            ),
            sha256: "5a8c7b5eb888cfce9322068e80e82b28b554ffeb7fdc9638dcb3763077401d26",
        },
        BakedTpmRoot {
            vendor: "STMicro",
            name: "stmicro-globalsign-trusted-platform-module-root-ca",
            pem: include_str!("roots/tpm/stmicro-globalsign-trusted-platform-module-root-ca.pem"),
            sha256: "f27bf02c6e00c73d915eeb6a6a2f5fbf0c31ae0393149e6b5c31e41b113841c3",
        },
        BakedTpmRoot {
            vendor: "STMicro",
            name: "stmicro-stsafe-ecc-root-ca-02",
            pem: include_str!("roots/tpm/stmicro-stsafe-ecc-root-ca-02.pem"),
            sha256: "fd1e7b68accd825636b27b3177c67402d463a7f04c97b6c47ab705fcdc1a04f6",
        },
        BakedTpmRoot {
            vendor: "STMicro",
            name: "stmicro-stsafe-rsa-root-ca-02",
            pem: include_str!("roots/tpm/stmicro-stsafe-rsa-root-ca-02.pem"),
            sha256: "c8f179943356e13d9d84b100201cefabbf408880241e5329e60d950ce1dea623",
        },
    ];

    /// Every baked TPM vendor root as DER, each digest-checked on load.
    ///
    /// A root whose embedded PEM does not match its pinned digest is **omitted**
    /// rather than returned unverified — the fail-closed direction, since a
    /// missing anchor means *no hardware evidence*, never a refusal. A test
    /// asserts all [`TPM_VENDOR_ROOTS`] load, so a mismatch fails the build
    /// rather than silently shrinking the fleet's trust set.
    #[must_use]
    pub fn tpm_vendor_roots() -> Vec<Vec<u8>> {
        TPM_VENDOR_ROOTS
            .iter()
            .filter_map(|r| load(r.name, r.pem, r.sha256).ok())
            .collect()
    }

    /// The store verify ships with.
    ///
    /// Carries the Yubico PIV root ([`AnchorProvenance::HardwareValidated`](super::AnchorProvenance::HardwareValidated)),
    /// both Google Android roots and the Apple App Attest root
    /// ([`AnchorProvenance::VendorOfficial`](super::AnchorProvenance::VendorOfficial)), and the 40 TPM vendor roots
    /// ([`AnchorProvenance::CommunityAggregated`](super::AnchorProvenance::CommunityAggregated) — see [`TPM_VENDOR_ROOTS`]
    /// for why that tier and not a higher one).
    ///
    /// Anchors sit at **different provenance tiers on purpose**. A caller that
    /// will not accept third-party-aggregated sourcing filters with
    /// [`TrustAnchorStore::resolve_x509_min_provenance`](super::TrustAnchorStore::resolve_x509_min_provenance) rather than being
    /// silently handed a weaker anchor than it asked for.
    ///
    /// `FIDO_MDS` remains unbaked. An absent anchor means *no hardware evidence
    /// for that class*, which is a measurement, **not** a refusal (see the
    /// module docs). Callers add their own anchors with
    /// [`TrustAnchorStore::with_store`](super::TrustAnchorStore::with_store).
    #[must_use]
    pub fn default_store() -> TrustAnchorStore {
        use super::{AnchorProvenance, CasAndTas, EnvironmentGroup, TrustAnchor};

        /// One store carrying anchors at a stated provenance tier.
        fn tiered(
            environment: &str,
            ders: Vec<Vec<u8>>,
            provenance: AnchorProvenance,
        ) -> ConciseTaStore {
            ConciseTaStore {
                store_identity: Some(format!("{environment}/key-attestation")),
                environments: vec![EnvironmentGroup::named(environment)],
                purposes: vec![Purpose::KeyAttestation],
                keys: CasAndTas {
                    tas: ders
                        .into_iter()
                        .map(|d| TrustAnchor::x509_with_provenance(d, provenance))
                        .collect(),
                    cas: Vec::new(),
                },
            }
        }

        let mut store = TrustAnchorStore::new();

        if let Ok(der) = yubico_attestation_root() {
            // The only anchor exercised end-to-end against physical hardware
            // (#91 validation + the #118 six-key ceremony).
            store = store.with_store(tiered(
                environments::YUBIKEY_PIV,
                vec![der],
                AnchorProvenance::HardwareValidated,
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
            store = store.with_store(tiered(
                environments::ANDROID_KEYSTORE,
                google,
                AnchorProvenance::VendorOfficial,
            ));
        }

        // Baked ahead of its validator (the Apple leg of #199 is still open):
        // an anchor with no consumer is inert, never a weakening.
        if let Ok(der) = apple_app_attestation_root() {
            store = store.with_store(tiered(
                environments::APPLE_APP_ATTEST,
                vec![der],
                AnchorProvenance::VendorOfficial,
            ));
        }

        // TPM is a vendor *set*, not a vendor root — 40 roots across 8 vendors,
        // 17 from Nuvoton alone. Aggregated by Microsoft rather than published
        // first-party, hence the lower tier; `docs/TPM_ANCHOR_PROVENANCE.md`
        // records what was tried to do better.
        let tpm = tpm_vendor_roots();
        if !tpm.is_empty() {
            store = store.with_store(tiered(
                environments::TPM_EK,
                tpm,
                AnchorProvenance::CommunityAggregated,
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
                provenance: AnchorProvenance::CallerSupplied,
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

    /// Classes with no baked anchor yield no evidence — not an error.
    #[test]
    fn unbaked_classes_are_absent_not_failing() {
        let s = baked::default_store();
        assert!(s
            .resolve(Purpose::KeyAttestation, environments::FIDO_MDS)
            .is_empty());
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

#[cfg(test)]
mod provenance_tier {
    use super::*;

    /// Each baked anchor carries the tier its sourcing actually earned — the
    /// Yubico root is the only one exercised against physical hardware.
    #[test]
    fn baked_anchors_carry_their_real_tier() {
        let s = baked::default_store();
        for (env, expected) in [
            (
                environments::YUBIKEY_PIV,
                AnchorProvenance::HardwareValidated,
            ),
            (
                environments::ANDROID_KEYSTORE,
                AnchorProvenance::VendorOfficial,
            ),
            (
                environments::APPLE_APP_ATTEST,
                AnchorProvenance::VendorOfficial,
            ),
        ] {
            let anchors = s.resolve(Purpose::KeyAttestation, env);
            assert!(!anchors.is_empty(), "{env} should be baked");
            for a in anchors {
                assert_eq!(a.provenance, expected, "{env} tier");
                assert!(a.provenance.is_vendor_sourced(), "{env} is vendor-sourced");
            }
        }
    }

    /// A caller's own anchor is NEVER silently promoted to a vendor tier.
    #[test]
    fn caller_supplied_anchors_are_not_promoted() {
        let a = TrustAnchor::x509(vec![1, 2, 3]);
        assert_eq!(a.provenance, AnchorProvenance::CallerSupplied);
        assert!(!a.provenance.is_vendor_sourced());
    }

    /// The consumer-policy half: a high-assurance deployment can require a
    /// vendor tier and thereby exclude aggregation-sourced roots.
    #[test]
    fn min_provenance_excludes_weaker_tiers() {
        let store = TrustAnchorStore::new().with_store(ConciseTaStore {
            store_identity: None,
            environments: vec![EnvironmentGroup::named(environments::TPM_EK)],
            purposes: vec![Purpose::KeyAttestation],
            keys: CasAndTas {
                tas: vec![
                    TrustAnchor::x509_with_provenance(
                        b"vendor".to_vec(),
                        AnchorProvenance::VendorOfficial,
                    ),
                    TrustAnchor::x509_with_provenance(
                        b"aggregated".to_vec(),
                        AnchorProvenance::CommunityAggregated,
                    ),
                ],
                cas: vec![],
            },
        });

        // Default resolution admits both — a mesh may accept aggregations.
        assert_eq!(
            store
                .resolve_x509(Purpose::KeyAttestation, environments::TPM_EK)
                .len(),
            2
        );
        // Requiring a vendor tier excludes the aggregation.
        let strict = store.resolve_x509_min_provenance(
            Purpose::KeyAttestation,
            environments::TPM_EK,
            AnchorProvenance::VendorOfficial,
        );
        assert_eq!(strict.len(), 1);
        assert_eq!(strict[0], b"vendor");
    }

    /// Every baked TPM root loads and matches its pinned digest. A silent
    /// omission would shrink the fleet's trust set without telling anyone, so
    /// the count is asserted rather than the mere non-emptiness.
    #[test]
    fn every_baked_tpm_root_loads_and_matches_its_pin() {
        assert_eq!(
            baked::tpm_vendor_roots().len(),
            baked::TPM_VENDOR_ROOTS.len(),
            "a baked TPM root failed its digest check"
        );
        assert_eq!(baked::TPM_VENDOR_ROOTS.len(), 40);
    }

    /// **A TPM vendor is a SET, not a root.** Nuvoton ships 17 — a single
    /// `pinned_root` parameter could not express this vendor at all, which is
    /// the whole reason the store resolves a set per environment.
    #[test]
    fn tpm_vendors_ship_multiple_roots_each() {
        let nuvoton = baked::TPM_VENDOR_ROOTS
            .iter()
            .filter(|r| r.vendor == "Nuvoton")
            .count();
        assert!(
            nuvoton > 1,
            "a vendor with one root would not exercise the set design"
        );
        assert_eq!(nuvoton, 17);

        let vendors: std::collections::BTreeSet<_> =
            baked::TPM_VENDOR_ROOTS.iter().map(|r| r.vendor).collect();
        assert_eq!(vendors.len(), 8, "8 vendors represented");
    }

    /// The TPM anchors resolve, and resolve at the tier they were actually
    /// sourced at. Baking them at `VendorOfficial` would overstate what
    /// Microsoft's aggregation proves.
    #[test]
    fn tpm_anchors_resolve_as_community_aggregated_not_vendor_official() {
        let s = baked::default_store();
        assert_eq!(
            s.resolve(Purpose::KeyAttestation, environments::TPM_EK)
                .len(),
            40
        );

        // A caller demanding first-party sourcing must NOT be handed these.
        assert!(
            s.resolve_x509_min_provenance(
                Purpose::KeyAttestation,
                environments::TPM_EK,
                AnchorProvenance::VendorOfficial,
            )
            .is_empty(),
            "aggregated anchors must not satisfy a vendor-official requirement"
        );
        assert_eq!(
            s.resolve_x509_min_provenance(
                Purpose::KeyAttestation,
                environments::TPM_EK,
                AnchorProvenance::CommunityAggregated,
            )
            .len(),
            40
        );
    }

    /// Containment, by fingerprint identity rather than by emptiness: the TPM
    /// roots must be unreachable as Android or PIV anchors. Asserting "the
    /// other slot is empty" would stop testing anything the moment that slot
    /// is populated — which is exactly what happened to the old Android test.
    #[test]
    fn tpm_roots_are_unreachable_from_other_environments() {
        use sha2::{Digest, Sha256};
        let s = baked::default_store();
        let tpm: std::collections::BTreeSet<String> = baked::tpm_vendor_roots()
            .iter()
            .map(|d| hex::encode(Sha256::digest(d)))
            .collect();
        assert_eq!(tpm.len(), 40, "no duplicate roots baked");

        for env in [
            environments::ANDROID_KEYSTORE,
            environments::YUBIKEY_PIV,
            environments::APPLE_APP_ATTEST,
        ] {
            for der in s.resolve_x509(Purpose::KeyAttestation, env) {
                assert!(
                    !tpm.contains(&hex::encode(Sha256::digest(der))),
                    "a TPM vendor root is reachable as a {env} anchor"
                );
            }
        }

        // ...and a TPM anchor cannot validate a TLS certificate.
        assert!(s
            .resolve(Purpose::Certificate, environments::TPM_EK)
            .is_empty());
    }
}

#[cfg(test)]
mod provenance_ordering {
    use super::AnchorProvenance::{
        CallerSupplied, CommunityAggregated, HardwareValidated, VendorOfficial,
    };

    /// The derived `Ord` IS the semantics of `resolve_x509_min_provenance`.
    /// An earlier revision declared these strongest-first, which made
    /// `>= VendorOfficial` admit every tier including caller-supplied — a
    /// strict consumer would have silently got the permissive set.
    #[test]
    fn ordering_is_weakest_to_strongest() {
        assert!(CallerSupplied < CommunityAggregated);
        assert!(CommunityAggregated < VendorOfficial);
        assert!(VendorOfficial < HardwareValidated);
        // The property the resolver relies on.
        assert!(HardwareValidated >= VendorOfficial);
        assert!(!(CommunityAggregated >= VendorOfficial));
        assert!(!(CallerSupplied >= VendorOfficial));
    }
}
