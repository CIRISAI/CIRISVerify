# CIRISVerify: Standards Comparison and Peer Analysis

**Version**: 3.0
**Date**: 2026-08-06
**Author**: CIRIS L3C
**Baseline release**: v13.0.0
**Scope**: attestation verification, trust-anchor management, artifact integrity, hybrid PQC signing
**Out of scope**: federated mesh transport — that is
[CIRISEdge/docs/STANDARDS_COMPARISON.md](https://github.com/CIRISAI/CIRISEdge/blob/main/docs/STANDARDS_COMPARISON.md)'s
domain. Edge consumes verify's primitives; it does not re-implement them.

> **Revision note.** v2.0 (2026-01-25) framed this project primarily as a
> post-quantum *license-verification* module, because that is what it was.
> Forty releases later the centre of gravity has moved to **attestation
> verification and trust-anchor management**, and this rewrite reflects that.
> The PQC material is retained but demoted from headline to Part IV.

---

## What CIRISVerify is, without reference to CIRIS

**A Rust library that decides whether a piece of evidence about a machine, a
build, or a key is worth believing — and says exactly how much.**

Strip away the ecosystem and four capabilities remain, each usable standalone:

| # | Capability | Concretely |
|---|---|---|
| 1 | **Device attestation verification** | Walk an Android Key Attestation, Apple App Attest, TPM 2.0 EK, or YubiKey PIV chain to a pinned vendor root; bind the attested key to the key you actually hold; bind the challenge you actually issued |
| 2 | **Constrained trust-anchor storage** | An in-memory realization of IETF `draft-ietf-rats-concise-ta-stores-02`, resolving anchors on **(purpose, environment)** together, with 44 vendor roots baked and provenance-tiered |
| 3 | **Artifact integrity + transparency** | RFC 6962 Merkle log, RFC 8785 JCS canonicalization, per-file build manifests, runtime binary self-verification, SD-JWT-style redactable commitments |
| 4 | **Hybrid post-quantum signing** | Ed25519 + ML-DSA-65 (FIPS 204) with *bound* signatures, X25519 + ML-KEM-768 hybrid KEX, HPKE over X-Wing, fail-secure RNG health checking |

The organizing stance, and the part most worth borrowing: **verify emits
measurements, never verdicts.** It reports what a chain proved and what it did
not. Composing that into an admission decision is the consumer's job — and the
type system says so, because every classification verify ships declares whether
a consumer may gate on it, and on whose authority
([`classification.rs`](../src/ciris-verify-core/src/classification.rs)).

**Who this is for outside CIRIS:** anyone verifying hardware attestations from
mixed fleets (Android + iOS + TPM + FIDO tokens) who wants one anchor store
rather than four bespoke pinning paths; anyone who needs an attestation
verifier that is a *library* rather than a service; anyone starting a
greenfield signing scheme who wants post-quantum coverage without waiting.

**Who it is not for:** anyone needing attestation-as-a-service with an
operational SLA (use Veraison), a public-good keyless signing ecosystem (use
Sigstore), or a horizontally-sharded transparency log (use Trillian).

---

## Executive summary — the honest read

| Area | Where verify sits |
|---|---|
| **CoTS (concise trust-anchor stores)** | **First Rust implementation.** A 2026-08-01 survey found none to adopt |
| **Hybrid PQC signing** | **Ahead.** Day-one hybrid with bound signatures, where most peers are classical or mid-migration |
| **Cross-platform device attestation** | **Parity, unusually unified.** Peers do one platform well; verify does four behind one store |
| **Transparency log** | **Parity on algorithm, behind on scale.** RFC 6962-correct, hybrid-signed heads; not sharded |
| **Selective disclosure** | **Parity.** SD-JWT salted-digest construction, correctly salted |
| **Supply-chain provenance** | **Behind on ecosystem.** No keyless/OIDC identity, no public instance, no SLSA self-assessment |
| **Revocation** | **Absent everywhere.** Stated plainly rather than implied |
| **TPM boot state (PCR quotes)** | **Absent.** Verify does device *identity*, not boot *state* |

Two claims are made and defended below — first Rust CoTS, and a hybrid posture
ahead of the field. Everything else is parity or a deficit, and the deficits
are enumerated in Part VI.

---

## Part I — Attestation verification peers

### 1. Veraison (Linux Foundation / Arm) — the closest peer

Attestation verification services implementing the RATS stack: CoRIM, CoMID,
CoSWID, CoTL, EAT.

| | Veraison | CIRISVerify |
|---|---|---|
| Shape | Services + Go/Rust libraries | Embeddable Rust library (+ C FFI, Python wheel) |
| RATS coverage | CoRIM, CoMID, CoSWID, CoTL, EAT | **CoTS**, plus device-chain validators |
| CoTS | **Not modeled** — `Azure/corim` states it is a separate draft; none of Veraison's seven Rust repos implement it | **Implemented** — the gap this fills |
| Wire encoding | CBOR/COSE throughout | **Model only — no CBOR/COSE yet.** Verify's clearest deficit |
| PQC | Classical | Hybrid day-one |

**Verdict: complementary, not competitive.** Verify's `trust_anchor_store` was
written to be upstreamable to `Azure/corim` as its CoTS module, with the
`draft-ietf-rats-concise-ta-stores-02` CDDL indices recorded in doc comments so
a CBOR codec has an unambiguous target.

**Where verify loses:** no wire encoding, no verifier service, no EAT/CoRIM. If
you need to *interoperate* over CBOR today, use Veraison.

### 2. IETF RFC 9683 / RFC 9684 (TPM-based network device attestation)

RFC 9683 (RIV) and RFC 9684 (YANG module) standardize TPM remote attestation
for network equipment.

| | RFC 9683/9684 | CIRISVerify |
|---|---|---|
| Scope | Network device firmware integrity | Device identity + artifact integrity |
| Hardware | TPM 1.2/2.0 only | TPM + Secure Enclave + Keystore + PIV token |
| Interface | YANG/NETCONF | Rust API, C FFI, Python |
| Quote mechanism | TPM Quote (with PCRs) | **EK certificate chain only — no quote** |

Verify uses challenge-response nonce binding on the platforms where the
attestation format carries one (Android `attestationChallenge`, Apple App
Attest nonce), and deliberately does **not** on TPM EK certificates, which are
long-lived vendor credentials with no nonce. **Gap:** no YANG interface, and no
quote verification — see Keylime below.

### 3. Keylime (CNCF) — TPM remote attestation

Continuous TPM attestation for cloud fleets: registrar, verifier, agent, IMA
measured boot, PCR quote validation.

**Where Keylime wins decisively:** it verifies **boot state** via PCR quotes
with nonce freshness. Verify has **no PCR-quote verifier**. It validates EK
certificates — device *identity* — and refuses to conflate that with boot
state. That is a documented boundary rather than an oversight, but it means
verify cannot answer *"did this machine boot clean."*

**Where verify differs:** library not service; four platforms not TPM-only;
hybrid PQC.

### 4. `go-attestation` / `go-tpm` (Google)

The reference Go TPM stack — EK/AK credential activation, quotes, event-log
parsing.

Verify's TPM leg covers EK-certificate chain validation with the **anti-lift
binding** (the certified key must be the key the caller pinned), but not
credential activation or event-log replay. `go-attestation` is more complete
for TPM specifically; verify is broader across platforms and is the only one of
the two with a constrained anchor store.

### 5. Platform-native: Play Integrity, App Attest, Android Key Attestation, FIDO MDS

Each vendor publishes a spec and expects you to write the verifier. Verify
implements three against one store:

- **Android Key Attestation** — `KeyDescription` (OID
  `1.3.6.1.4.1.11129.2.1.17`), chain to a pinned Google root,
  `attestationChallenge` binding, security-level extraction
- **Apple App Attest** — CBOR attestation object, `nonce = sha256(authData ‖
  sha256(challenge))` matched against the credCert extension, `rpIdHash`,
  `signCount == 0`
- **YubiKey PIV** — 9c → f9 → pinned Yubico root, FIPS + touch-policy floor
- **FIDO MDS** — *not implemented.* A different distribution model; named as
  unadopted rather than quietly missing

**Play Integrity** is used as an *advisory* signal only, never a trust anchor —
it has [known bypasses](https://www.guardsquare.com/blog/google-play-integrity-api-app-attestation),
depends on Google servers, and excludes de-Googled Android (GrapheneOS et al.).
Key Attestation, which is a chain to a pinned root, is the load-bearing path.

**The structural differentiator.** These normally exist as four unrelated code
paths with four hardcoded roots. Verify resolves all of them from one CoTS
store keyed on `(purpose, environment)`, so a Yubico root **cannot** satisfy an
Android lookup and a key-attestation root cannot validate a TLS certificate —
containment a flat `&[root]` list cannot express at all.

**The framing differentiator.** An over-claim is decisive; a pass is weak
evidence; absence is not failure. `refutes(claimed_class)` fires only when a
peer claimed *stronger* custody than the chain measured. Most implementations
treat attestation as a boolean gate, which silently converts hardware into a
*requirement* and excludes every device without a secure element.

### 6. Confidential computing: Intel TDX, AMD SEV-SNP, Arm CCA

Not a competitor — a different layer. These attest a *runtime environment*;
verify attests *identity and artifacts*. Verify can run inside a confidential
VM and attest from within it. The one overlap worth noting is trust-root shape:
TDX/SEV root in the CPU vendor, which is a single-vendor anchor, where verify's
store is explicitly multi-vendor and provenance-tiered.

---

## Part II — Supply chain and transparency peers

### 7. Sigstore (cosign / Rekor / Fulcio)

The dominant open-source artifact-signing ecosystem: keyless signing via OIDC,
short-lived certificates, a public Rekor transparency log.

| | Sigstore | CIRISVerify |
|---|---|---|
| Identity | Keyless, OIDC-federated | Hardware-rooted, long-lived |
| Transparency | Public-good instance, huge adoption | Embeddable log, no public instance |
| Crypto | Classical (ECDSA/Ed25519) | Hybrid + ML-DSA-65 |
| Ecosystem | Enormous | Small |

**Where verify loses badly: ecosystem.** Sigstore has a public-good instance,
CI integrations everywhere, and a community. Verify has none of that and should
not pretend otherwise. If you are signing OSS release artifacts, use Sigstore.

**Where the two genuinely differ:** Sigstore's trust model is *ephemeral
identity anchored in OIDC* — excellent for CI, and structurally unable to
answer "is this the same physical device as last week." Verify's is *durable
identity anchored in hardware*. Different questions, not competing answers.

### 8. in-toto + SLSA

in-toto ITE-6/DSSE attestations; SLSA provenance levels.

Verify's `manifest_contribution` and `build_attestation_bundle` occupy the same
conceptual space — signed build provenance — with one addition worth naming:
the **presenter binding**. in-toto proves a build happened as described; it does
not bind *the entity presenting the evidence* to it. Verify's bundle requires
the presenter's `attesting_key_id` to equal a pinned member resolved from the
caller's directory and never from the object, which refuses a relayed bundle.

**Honest boundary, carried in verify's own module docs:** this does **not**
prove remote execution, which is unprovable. It proves an *attributable,
falsifiable* assertion over independently-rooted evidence.

**Where verify loses:** no SLSA level self-assessment, no DSSE compatibility, no
predicate ecosystem. in-toto and SLSA are standards with real adoption; verify's
shapes are internal.

### 9. Trillian / Certificate Transparency

Google's RFC 6962 log, and the reference implementation of the idea.

Verify's `transparency` is RFC 6962-correct (`0x00` leaf / `0x01` node domain
separation, inclusion and consistency proofs) with **hybrid-signed tree heads**,
which is ahead of Trillian's classical STH signing. `hash_leaf` / `hash_node`
are public precisely so downstream stores do not reimplement them.

**Where verify loses:** Trillian is a sharded, database-backed production
service. Verify is a library with a pluggable store. A deployment-architecture
gap rather than an algorithmic one — and a real gap at scale.

### 10. The Update Framework (TUF) / Notary

Verify has **anti-rollback** (monotonically non-decreasing revocation
revisions), which is TUF-flavoured, but no delegation hierarchy, no
threshold-signed role metadata in TUF's sense, and no repository model. If your
problem is *software update security specifically*, TUF is the mature answer.

---

## Part III — Selective disclosure and credentials

### 11. SD-JWT, ISO mdoc/mDL (18013-5), W3C VC 2.0, BBS+/AnonCreds

Verify's `redactable` implements the **SD-JWT/mDoc salted-digest**
construction: each member commits as `sha256(domain ‖ u32(index) ‖
u32(salt_len) ‖ salt ‖ bytes)` under a fresh 128-bit salt.

**Why salted rather than a plain Merkle-over-fields:** unsalted digests are
broken for erasure. A digest of a boolean, a small enum, or a date is
recoverable by dictionary search — and erased content is exactly what an
adversary targets. This is the standard construction, and verify follows it
rather than inventing one.

Two properties beyond the baseline: the root binds **member count** (foreclosing
redact-by-omission) and **index** (members cannot be reordered or swapped
between slots). Redaction *withholds a disclosure and never alters one*, so the
producer's original signature still verifies and a redacted slot stays
cryptographically distinguishable from a tampered one.

**Where verify is behind: unlinkability.** Presenting twice is correlatable via
stable key identifiers. BBS+ and AnonCreds deliver unlinkable presentation
today; verify does not. Its position is explicit rather than aspirational —
unlinkability is a **property commitment with a staged adoption path**,
ZK-wrapped *unmodified* ML-DSA is the designated candidate, and one interim
constraint is enforced in code: identity must stay separable from presentation
format, so the upgrade is a format addition rather than a re-issuance event
([`presentation.rs`](../src/ciris-verify-core/src/presentation.rs)).

### 12. WebAuthn / passkeys

Verify implements assertion verification (cross-checked against `webauthn-rs`,
origin exact-match, `signCount` surfaced) and uses it strictly as an **unlock**
factor — never as the owner-binding signature. The split matters: a passkey
proves presence, not custody of the federation key.

---

## Part IV — Cryptography

### 13. PQC: liboqs, AWS-LC, BoringSSL, RustCrypto, libcrux

Verify uses RustCrypto `ml-dsa` (FIPS 204) and `ml-kem`, byte-verified against
`dilithium-py` (the FIPS 204 reference implementation), so signatures verify
across Rust and Python.

**The differentiator is posture, not primitive.** Most of the field is
classical-with-a-migration-plan. Verify is hybrid on day one, specifically:

- **Bound signatures.** `pqc_sig = Sign_PQC(data ‖ classical_sig)` — the PQC
  signature covers the classical one, so an adversary who breaks Ed25519 cannot
  strip or swap the classical half.
- **Hybrid *required* at federation-tier gates.** A classical-only signature
  does not count at the admission boundary. Many hybrid deployments accept
  either half, which means a classical break silently suffices.
- **Fail-secure RNG.** NIST SP 800-90B startup health check with a
  process-global latch; keygen returns an error rather than drawing from a
  failed CSPRNG. Most libraries assume the OS RNG is fine and never check.

**Standards alignment:** NIST FIPS 203/204, NSA CNSA 2.0 (which requires PQ
signing for software and firmware *now* — software/firmware signing is the
earliest CNSA 2.0 deadline, not the latest), RFC 9180 (HPKE), RFC 8785 (JCS),
RFC 6962.

| CNSA 2.0 capability | Support by | Verify |
|---|---|---|
| Software/firmware signing | Immediately | **Compliant, day one** |
| Web/cloud services | 2025 | Tracking |
| Traditional networking | 2026 | N/A |

### 14. Hybrid key exchange

X25519 + ML-KEM-768, plus HPKE mode_base over the X-Wing hybrid KEM — the same
construction direction as TLS hybrid key exchange (`X25519MLKEM768`), applied
at the application layer for key grants.

---

## Part V — What is genuinely novel

Deliberately narrow. Most of verify is a competent implementation of other
people's standards, which is the correct default for security software.

1. **First Rust CoTS implementation.** Survey of 2026-08-01: `Azure/corim`
   explicitly does not model CoTS; none of Veraison's seven Rust repos do.
2. **Doubly-constrained anchor resolution, fail-closed on omission.** An empty
   `purposes` or `environments` list matches **nothing**, never a wildcard.
   Reading omission as "applies to everything" is the failure a flat root list
   makes almost inevitable.
3. **Machine-readable anchor provenance.** `CallerSupplied < CommunityAggregated
   < VendorOfficial < HardwareValidated`, with a minimum-tier resolver. Baking a
   community aggregation beside a vendor-official root otherwise makes the
   *declared* depth stronger than the *actual* provenance. Verify ships all four
   tiers with the sourcing for each written down — including the dead ends
   ([`TPM_ANCHOR_PROVENANCE.md`](TPM_ANCHOR_PROVENANCE.md)).
4. **Gating declared in the type.** Every shipped classification states whether
   a consumer may gate on it — `Normative { authority }` (a ruling, amendable by
   a named body), `Structural { breaks }` (a mechanism, amendable by nobody),
   `Measurement`, or `Proposal { tracking }` — and propagates weakest-wins
   through derivation, so a measurement cannot be laundered into policy by
   aggregation. We know of no peer that does this. It exists because a
   downstream repo once read a proposal as a ruling and built an admission gate
   on it.
5. **Refuter asymmetry as an explicit stance.** Weight refutations heavily,
   passes lightly, absence not at all.

---

## Part VI — Deficits, stated plainly

| Gap | Status | Use instead |
|---|---|---|
| CBOR/COSE wire encoding for CoTS | Model only | Veraison, for interop today |
| PCR quote / boot-state verification | **Absent** | Keylime, `go-attestation` |
| Revocation checking, any kind | **Absent everywhere.** Nothing here means "not revoked" | Vendor CRL/OCSP directly |
| Unlinkable presentation | Committed as a property, staged | BBS+, AnonCreds |
| Horizontal transparency-log scale | Library, not sharded service | Trillian |
| Keyless / OIDC signing identity | Not the model | Sigstore |
| SLSA level, DSSE predicates | Not assessed | in-toto / SLSA |
| YANG/NETCONF interface | Not implemented | RFC 9684 implementations |
| FIDO MDS | Named as unadopted | FIDO MDS directly |
| Formal verification | None | libcrux, HACL* |
| Third-party security audit | **None to date** | — |

The last row is the honest headline. Verify has had internal adversarial audits
— one found 1 CRITICAL and 3 HIGH, all in *wiring* rather than primitives — but
**no external audit**. Treat the cryptographic posture as carefully constructed
and unreviewed by outsiders.

---

## Sources

- IETF RATS: `draft-ietf-rats-concise-ta-stores-02`, RFC 9334 (Architecture),
  RFC 9711 (EAT), `draft-ietf-rats-corim`
- IETF RFC 9683 (RIV), RFC 9684 (YANG); `draft-ietf-lamps-csr-attestation`
- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA); SP 800-90B
- NSA CNSA 2.0 requirements
- RFC 6962 (Certificate Transparency), RFC 8785 (JCS), RFC 9180 (HPKE)
- ISO/IEC 18013-5 (mDL), IETF SD-JWT, W3C VC 2.0, W3C WebAuthn L3
- TCG TPM 2.0 Library Specification; TCG EK Credential Profile
- Veraison (`veraison/services`, `Azure/corim`); Keylime; Sigstore; in-toto;
  SLSA; Trillian; TUF
- Android Key Attestation; Google Play Integrity; Apple App Attest; Yubico PIV
  Attestation
