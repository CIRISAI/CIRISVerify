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
