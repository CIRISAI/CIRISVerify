# TPM EK trust-anchor provenance record

**Status:** current as of v12.6.0 (2026-08-03) · CIRISVerify#199, #227

This document records **how the baked TPM EK vendor roots were obtained**, what
was tried first and failed, and precisely what the resulting anchors do and do
not prove. It exists because the anchors ship at
`AnchorProvenance::CommunityAggregated` rather than `VendorOfficial`, and that
tier is a claim about sourcing that a reader should be able to audit rather than
take on faith.

The short version: **no TPM vendor publishes its root CAs at a stable,
machine-fetchable endpoint the way Google and Apple do.** Four routes were
attempted. Three are dead ends. The fourth works but routes through Microsoft,
which is a third party to every vendor whose roots it distributes — hence the
lower tier.

## Why this record exists at all

The Yubico, Google, and Apple bakes each carry a one-line provenance note in
code because each had a clean answer: fetched from the vendor's own endpoint,
self-signature verified, and (for Google) cross-confirmed byte-identical against
a second independent vendor-published page. TPM has no such answer, and the
honest response to that is a written record, not a silently weaker pin wearing
the same clothes as the strong ones.

## Attempt 1 — vendor official endpoints

Targeted the published CA/PKI pages for Infineon, Nuvoton, and STMicroelectronics.

| Vendor | Result |
|---|---|
| Infineon | HTTP 200, but the page is JavaScript-driven. **Zero PEM blocks** in the served HTML; zero certificate-shaped links recoverable. |
| Nuvoton | Same — no machine-fetchable certificate material. |
| STMicroelectronics | HTTP 000 (host unreachable from the build environment). |

**Outcome: dead end.** This is not a transient failure; these vendors do not
operate a certificate-distribution endpoint analogous to
`android.googleapis.com/attestation/root` or
`apple.com/certificateauthority/…`. TPM EK roots are distributed to platform
vendors through channels that assume an OS integrator, not a public fetch.

## Attempt 2 — the community aggregation

[`1id-com/tpm-manufacturer-cas`](https://github.com/1id-com/tpm-manufacturer-cas)
presents itself as an aggregated TPM manufacturer CA bundle and is the result
most obviously reachable by search.

**It contains zero certificates.** The bundle file is a placeholder comment
reading *"Add manufacturer root CA certificates to the certs/ subdirectories"*;
every `certs/*/` directory holds only a `README.md`. Its `update-intel.sh`
contains a base URL and no fetch that ever ran. The repository has 1 star and a
NOASSERTION license.

**Outcome: dead end — and a correction to the record.** This repository has been
referred to in prior CIRIS discussion as though it were a usable trust bundle.
It is a scaffold. Anyone reasoning about TPM anchor availability on the basis of
its existence should stop doing so.

## Attempt 3 — Intel direct

`trustedservices.intel.com` and `pki.trustedservices.intel.com`, the endpoints
named by the aggregation's own unrun script.

**Outcome: dead end.** HTTP 403 and connection failure respectively.

## Attempt 4 — Microsoft `TrustedTPM.cab` (successful)

Microsoft distributes a curated TPM vendor CA set for Windows platform
attestation.

- **Source:** `https://go.microsoft.com/fwlink/?linkid=2097925`
- **Retrieved:** 2026-08-03
- **Size:** 2,988,320 bytes · **Last modified upstream:** 2026-07-21
- **Format:** MSZIP-compressed cabinet, 1 folder, 2,571 files

No CAB extractor was available in the environment (`cabextract`, `7z`, and
`bsdtar` all absent), so the CFHEADER/CFFILE/CFDATA structures were parsed
directly and the single MSZIP folder decompressed block-by-block
(183 blocks → 5,967,580 bytes) before the per-file byte ranges were carved out.

### Vendor coverage in the cabinet

```
Microsoft 2184 · Infineon 161 · Intel 60 · AMD 58 · NationZ 31
STMicro     28 · Nuvoton  21 · Atmel 13 · QC   11
```

## What was baked, and what was deliberately not

From 2,567 certificate-shaped entries, **40 anchors** were baked. The filters,
in order:

1. **Microsoft-issued certificates excluded** (2,184 of them). They are
   Microsoft's own attestation CAs, not vendor EK roots.
2. **Intermediates excluded.** Only certificates where `subject == issuer` were
   considered. Pinning an intermediate as a trust anchor is the specific mistake
   the Yubico bake called out — *pin the durable root, never the rotating
   issuer* — and Yubico's 2024-12 PKI overhaul is the standing proof of why.
3. **Self-signatures cryptographically verified**, not name-matched. Of 41
   candidate self-signed roots, 40 verified.
4. **One expired root excluded:** Infineon `CN=Infineon TPM CA 008`
   (`sha256 2f93344342ab…`), valid 2003-11-20 → **2018-11-20**. Its signature is
   cryptographically sound — the failure is expiry alone — but an expired
   certificate has no business being an anchor.
5. **Duplicates removed by DER digest.**

### Resulting set

| Vendor | Roots |
|---|---|
| Nuvoton | 17 |
| Infineon | 7 |
| NationZ / NSING | 5 |
| STMicroelectronics | 4 |
| AMD | 2 |
| Intel | 2 |
| Qualcomm | 2 |
| Atmel | 1 |
| **Total** | **40** |

Signature algorithms present: `ecdsa-with-SHA256/384/512`,
`sha256/384WithRSAEncryption`, and `sha1WithRSAEncryption` (10 older roots). The
SHA-1 self-signatures are **not** security-load-bearing here: these certificates
are trusted because their DER digest is pinned in this build, not because their
self-signature validates. A SHA-1 self-signature on a digest-pinned root is a
provenance curiosity, not a downgrade — but it is recorded so nobody discovers
it later and mistakes it for one.

### A note on third-party CAs filed under vendors

A few baked roots are not vendor-named: VeriSign Trusted Computing CA (filed
under Infineon), GlobalSign Trusted Computing CA ×2 (under ST), and a Microsoft
TPM root (under Qualcomm). **This is not an error.** Those vendors genuinely
chain their EK certificates under those CAs, and omitting them would silently
fail to validate real hardware.

## Why `CommunityAggregated` and not `VendorOfficial`

Microsoft curates this set, but Microsoft is a **third party** to Infineon,
Nuvoton, ST, Atmel, NationZ, and Qualcomm. Nothing here was fetched from, or
independently cross-confirmed against, the vendors themselves — which is exactly
what `VendorOfficial` asserts and what the Google bake actually did (two
independent Google-published sources agreeing byte-for-byte before anything was
pinned).

The tier is therefore load-bearing, not decorative. A caller that will not
accept third-party-aggregated sourcing excludes these anchors:

```rust
store.resolve_x509_min_provenance(
    Purpose::KeyAttestation,
    environments::TPM_EK,
    AnchorProvenance::VendorOfficial,   // yields nothing — by design
)
```

A test asserts this exclusion holds, so the tier cannot quietly stop meaning
something.

## What these anchors do and do not prove

They let a TPM EK certificate chain be **walked** to a pinned root, which is the
hardware half of *never trust a self-report*. They do not change the standing
framing:

- **Absence is not failure.** A platform with no TPM, or one whose vendor is not
  in this set, resolves to no anchor — *no hardware evidence*, never a refusal.
- **Hardware is a signal, not a requirement.** A pass shows the presenter holds
  correctly-rooted evidence, which an impostor with real hardware also holds.
  An **over-claim is decisive**. Weight refutations heavily, passes lightly,
  absence not at all.
- **No revocation.** Nothing here consults a vendor CRL. Nothing here means
  "not revoked".
- **No discrete-vs-firmware TPM distinction.** The EK certificate does not
  reliably carry one, and inventing it would be a fabricated measurement.

## What would improve this

Any of the following would justify promoting these anchors to `VendorOfficial`,
and each is a tractable ask rather than a research problem:

1. A vendor-published, machine-fetchable root endpoint — the single highest-value
   ask, and one worth raising with the TCG rather than eight vendors separately.
2. Independent cross-confirmation of a given root against vendor-supplied
   material (a datasheet fingerprint, a signed vendor advisory), which can be
   done per-root and incrementally.
3. Direct receipt from a vendor under an auditable channel.

Until then the honest tier is the one shipped, and the anchors are challengeable
on the record above — which was the point of writing it down before shipping
rather than after being asked.
