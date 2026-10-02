# FSD-006 — The build-manifest lifecycle, end to end

**Status:** DRAFT for cross-repo sign-off · **Author:** CIRISVerify · **Opened:** 2026-10-01
**Tracks:** CIRISVerify#299 (and the class it belongs to) · CIRISRegistry `fold/builds-ceg-native` · CC 1.0-rc6

| Sign-off | Owns | Status |
|---|---|---|
| CIRISConstitution | the wire grammar: dimension, envelope members, blob rules, authority planes | **ACCEPT** §2–§7; rulings Q1, Q2, Q3, Q4a/b, Q8; prose landed on rc6 at 9f31720 (registry_sha256 unchanged). Q4c and Q6 referred to the steward |
| CIRISPersist | admission, row mirror, blob store, `holds_bytes`, capability walk | **ACCEPT WITH CHANGES**, read from code at v52.0.2 (`review_fsd006.md`): would admit §3 as written; corrections to stages 5, 6, 10 and §5; Q2, Q5, Q8 confirmed; Q3 reach and Q4 put to the steward |
| CIRISServer / CIRISRegistry fold | the `/v1/builds` submit and read doors | **ACCEPT** with corrections to stages 6, 8, 11; Q2 + Q7 implemented (CIRISRegistry#143 @ 28de8c7, CIRISServer#442 @ b92547fe). Session sign-off; its human has not reviewed |
| CIRISEdge | blob fetch, presenter-bundle gate | **ACCEPT** (2026-10-01, CIRISEdge#786): 19.0.0 break, stages 8/10, Q6 (then ruled onto the ladder; the citation shape is CC's); stage 11 marked ⚠️ pending audit |
| CIRISVerify | producer, signature + shape verifier, presenter bundle, agent-side consumer | author |

---

## 1. Why the manifest is the microcosm

A build manifest is the smallest object that goes through **every** stage a public blob does in the
federation. An `encyclopedia_article` (CC 3.3.11, worked through in CC 8.1.5) and a NodeCore
`external_content` row follow the same steps:

> bytes exist → they get a content address → **a claim references them** → the claim is signed
> → a node admits the claim → the bytes are stored and a holder is announced → claim and holder
> replicate → **someone decides whether the claimant had standing to say it** → a reader finds a
> holder, fetches, checks size and full SHA, and only then consumes → the claim is presented
> onward → it is superseded, withdrawn, or its standing is revoked.

The manifest has every one of those steps and real stakes in each: an agent loads code on the
strength of it. It is also the object where four repos currently **disagree**, with every suite
green. That makes it the right place to pin the lifecycle once, as the template the encyclopedia /
NodeCore blob path inherits rather than re-derives.

The rule this document enforces everywhere: **meaning comes from a signed claim that references the
bytes; possession of bytes means nothing; authority comes from the reader's own walk, never from
the serving node.**

## 2. The lifecycle, stage by stage

| # | Stage | Manifest instance | General public-blob form | Owner | CC | Today |
|---|---|---|---|---|---|---|
| 1 | Bytes | the canonical file manifest (JSON) | article body, media, package | producer | 3.1.2.1 | ✅ |
| 2 | Address | `manifest_hash` = sha256(bytes), bare lowercase hex | `content_sha256` | producer | 5.3.2.5 | ✅ |
| 3 | Claim | `scores` on `provenance:build_manifest:{target}:v1`, `evidence_refs: [manifest_hash]` | `scores` on `encyclopedia:article:{…}:v1`, `evidence_refs: [sha]` | producer | 2.1, 3.1.7 R3 | ❌ **v18: no `:v1`** → fixed 19.0.0 |
| 4 | Sign | bound-hybrid over JCS(envelope); **row mirror + `asserted_at` inside the bytes** | same | Verify (`sign_build_manifest_contribution`) | 2.6.1, 5.3.2.4.2 | ❌ **v18: no `row`** → fixed 19.0.0 |
| 5 | Admit | `put_attestation`: R3, row↔column binding, instant binding, hybrid | same door | Persist | 5.3.2.4.3.1 | ✅ |
| 6 | Store bytes | `put_blob_signing(sha, bytes, …, author_key_id)`: `author` is whose content it is; the holder claim is the **serving node's**, signed by it | same | Persist (via submit door) | 3.1.9.1 | ✅ (Q5 answered by registry, observed `Stored { announced: true }`; persist to confirm) |
| 7 | Announce holder | `holds_bytes:sha256:{prefix}` auto-emitted | same | Persist | 3.1.9.1, 5.3.2.1 | ✅ |
| 8 | Replicate | claim + holder rows via anti-entropy | same | Persist / Edge | 5.3.2.3 | ⚠️ **conditional**, measured on a 3-node mesh: crosses only if (a) the consent grant covers `provenance:` (persist projects a non-root author's row as Cohort), (b) both owners accept a common root, else edge withholds it as "Attributed but not Rooted" (CIRISEdge#659, CIRISServer#710), (c) the pipeline's key record and grant replicate too |
| 9 | **Standing** | accord role on the pipeline's key record (production), or a `trust:confers:v1` grant the reader's walk finds | the author's standing for the family (editor-consensus for `encyclopedia:*`) | Persist (`is_infra_attest_effective` / `capability_roots_to_trusted_root`) | 3.2 T2 | ✅ 19.0.0 — §5 (verify's two private models deleted; registry door asks both) |
| 9a | Grant producer | `ciris-verify delegate` mints the blessing | the root's conferral for any content family | Verify (`sign_delegation_grant`) | 3.2 T2 | ❌ **cannot be counted by the walk** — Q8 |
| 10 | Discover | `holds_bytes` directory → `resolve_holders` | same | Persist / Edge | 5.3.2 | ✅ |
| 11 | Fetch | `ContentFetch`, ≤2 holders in parallel, `ContentMiss` → `withdraws` | same | Edge | 5.3.2.1 | ⚠️ `ContentMiss`→`withdraws` shipped; the ≤2-holder cap is not found in edge's fetch paths, and the chunked path is an adaptive multi-peer scheduler (audit: CIRISEdge#786; a carve-out would go to CC). Also: edge declines commons blobs unless the operator consents and the holder is allow-listed, so only registry-conferred nodes hold manifest bytes and **an agent reads them over HTTP from a registry node, not over the swarm** (roster fixed at puller spawn, CIRISEdge#785) |
| 12 | Check | **size first**, then full SHA, before any consumer sees a byte | same | consumer | 5.3.2.5 | ✅ 19.0.0: `build.manifest_size` (Q2 ruled); registry submit door refuses `manifest_size_mismatch` before hashing |
| 13 | Consume | agent loader / L4 file integrity; render tier from sniffed bytes | renderer, render tier | consumer | 5.3.2.6 | ⚠️ read door now returns the claim + `standing` (Q7 done, registry 28de8c7); Verify's agent-side consumer of it is the next change |
| 14 | Present | presenter bundle: node K says "I run build M", carrying M's claim | citing an article in a downstream claim | Verify (`build_attestation_bundle`) | — | ⚠️ Q6 |
| 15 | Retire | `supersedes` (rebuild) · `withdraws` (bad build) · grant tombstone (pipeline loses standing) | `supersedes` revision chain, takedown | producer / root | 2.3, 4.5.3 | ❓ Q4 |

## 3. The wire object (normative once signed off)

```json
{
  "asserted_at": "2026-10-01T14:50:29.308Z",
  "build": {
    "target": "python-source-tree",
    "build_id": "…",
    "binary_hash": "<64 hex>",
    "binary_version": "…",
    "manifest_hash": "<64 hex>",
    "manifest_size": 41237
  },
  "delegation_scope": "infra:attest",
  "dimension": "provenance:build_manifest:python-source-tree:v1",
  "evidence_refs": ["<manifest_hash>"],
  "row": {
    "attestation_id": "<uuid v4, minted before signing>",
    "attestation_type": "scores",
    "attested_key_id": "<pipeline key_id>",
    "attesting_key_id": "<pipeline key_id>",
    "cohort_scope": "federation",
    "subject_key_ids": []
  },
  "score": 1
}
```

Carried as `{signed_envelope, ed25519_signature_base64, mldsa65_signature_base64}`: the same three
members as Verify's `SignedEnvelope` and Registry's `SignedContribution`.

- **Identity is stated once, in `row`.** There are no top-level `attesting_key_id` /
  `subject_key_ids` / `signed_at` that could disagree with the mirror (v18 had both a top-level
  `subject_key_ids: [build_id]` and no mirror).
- **`subject_key_ids` is empty.** CC 2.3.2.1 admits only canonical key_ids, and a build id is not
  one. The build is named by `build` and the blob by `evidence_refs`.
- **`asserted_at` is the one signed instant**, millisecond `Z` (CC 2.6.2), truncated before
  rendering so the signed string and the derived column are the same instant.
- **`on_behalf_of` / `delegation_ref` are gone.** Standing is not a claim the producer makes about
  itself (§5).

The encyclopedia form differs only in `dimension`, the descriptor member (`build` ↔ the article /
media Source struct, CC 3.3.13), and `cohort_scope`.

## 4. The R3 class — why #299 is not one bug

CC 3.1.7 R3's version grammar is **global**: every non-exempt family ends in exactly one `:vN`,
whatever that family's own `segments` array says. Reading the registry JSON family by family
suggests otherwise. Verify read it that way and was wrong twice: 18.0.0 fixed `hardware_custody`
alone, and #299 then found `build_manifest`. Replaying **every** family Verify emits through CC's
own matcher (`tools/cc_namespace_match.py`) found eight that persist refuses as
`missing_version_segment`:

`provenance:build_manifest` (+ `:locale:`), `provenance:slsa`, `provenance:skill_import`,
`transparency_log:inclusion`, `transparency_log:consistency`, `transparency_log:cosigned`,
`rollback_detected`, `cert_validity`.

Only the four bare `attestation:*` constants are exempt. 19.0.0 puts every family on one
`dim::DIMENSION_VERSION`, and the CI guard replays all of them through the matcher, with negative
controls. **Ask to every repo that emits dimensions:** do the same replay. The JSON reading has now
misled the author of the dimension module twice.

## 5. Standing: the substrate decides, by one of two authorities

Whether a pipeline may attest builds is answered by persist over the **reader's own directory**,
by one of two authorities. Verify re-derives neither.

| Standing | Persist authority | Shape | Reader-relative | Retirement | Reach (federation scope) |
|---|---|---|---|---|---|
| **Accord role** (production) | `admission::is_infra_attest_effective(dir, pipeline)` (CIRISPersist#422/#424) | `infra:attest` inside the pipeline's accord-co-scrubbed key record, at quorum. Written by CIRISServer `/v1/accord/ci-key/{propose,cosign}` | no | quorum role withdrawal; `supersedes` naming a successor key is the rotate-in | Global |
| **Conferred**: Delegation | `trust_root::capability_roots_to_trusted_root(dir, reader, pipeline, "infra:attest")` | `delegates_to(root → pipeline)`, `dimension: trust:confers:v1`, `scope ∋ infra:attest` | yes | `supersedes` on the grant = rotation, earlier claims keep standing; `withdraws` = compromise, everything ends (CC 3.2 T2, steward ruling) | Cohort |
| **Conferred**: FamilyQuorum | same walk | the same grant, whose scrub set reaches a constitutional family's quorum; root = the **family id** | yes | as above | Cohort |

The walk's third arm, **AccordCoScrub**, cannot bless a pipeline. It makes the subject itself the
candidate root and requires `trust_root_valid` on it (self-charter, recovery commitment, fresh
heartbeat), which a pipeline never has. This is what CIRISRegistry measured on its mesh (322ce7e),
and persist confirmed it from code. The accord co-scrub reaches a pipeline through the *role*
authority instead.

**Verify 19.0.0:** `verify_build_manifest_contribution(obj, pipeline_member, &PipelineBlessing)`,
where `PipelineBlessing { pipeline_key_id, standing: Conferred { root_key_id,
grant_attestation_id, plane: Delegation | FamilyQuorum } | AccordRole }`. The walk's
co-scrub arm is unrepresentable. Verify checks the signature and shape and that the blessing
names the signing pipeline; the caller asks persist. The FFI/wheel take and return
`standing: "delegation" | "family_quorum" | "accord_role"`, with root and grant present only for the
walk standings. Registry's door asks the walk first, then the role, and refuses only if both say no
(CIRISRegistry 18a138c); its read response carries the same discriminator.

Verify's own two authority models are deleted. The co-scrub verifier (9.0.0–18.0.0) asked the
right question for the accord-role standing, but verify's copy could not see a quorum role
withdrawal, so a withdrawn pipeline still verified. The one-hop grant check could not see
tombstones or expiry.

**Generalisation for public blobs:** each content family names its standing authority once (builds
→ accord role or `infra:attest` conferral; encyclopedia → editor-consensus per CC 3.3.11). The
reader asks the substrate, never a field the producer wrote about itself.

## 6. The read door must return the claim, not a summary of it

`GET /v1/builds/{version}` (fold branch) returns `build_id`, hashes, the parsed manifest, and a
`federation_provenance` *summary*. It does **not** return the signed Contribution, so an agent's
Verify cannot re-check anything and ends up trusting the serving node. CC 5.3.4 forbids exactly
that ("nothing a serving install signs on its own account is a root").

**Ask (Server/Registry):** include the stored `SignedContribution` (and the grant id the walk
returned) in the read response. Verify's agent-side consumer then re-verifies the signature and
shape locally, and checks size + full SHA of the manifest bytes (CC 5.3.2.5) before L4 file
integrity consumes them. Standing still comes from the serving node's walk, and the response says
whose walk it was (`served_by`, as the GenesisBundle does). The same rule applies to every public
blob read: **return the claim with the bytes.**

## 7. Trust root for the walk: the GenesisBundle

`/v1/steward-key` now serves the CC 5.3.4 GenesisBundle (live: `version: 2`, holders A1/B1/C1 with
custody attestations, 2 holder authorizations, the canonical serve node co-scrubbed A1+B1, the
`genesis-charter` grant). This is what Verify's registry-consensus path (#176, #69, the third strand
of #223) has been unable to parse since rc4. Verify will consume it **only** against an
out-of-band anchor: the baked accord-holder keys from the #107 genesis, per CC 5.3.4's "names,
not anchors" rule. That is a separate change, tracked on those issues; it is noted here because
`R` in §5 ultimately roots there.

## 8. Open questions — each needs an owner's answer before 19.0.0 freezes the wire

**Q1 (Constitution) — family.** `provenance:build_manifest:{target}` (CC 3.1.2) and
`agent_files:build:{target}` (CC 3.1.9.1, a joint Registry/NodeCore claim on "files an agent may
load") both describe this object. Is the manifest Contribution one of them, or both? Verify
proposes **`provenance:build_manifest` only**: `agent_files:*` names a file to load, the manifest
names a build's file set, and emitting both would be two claims about one fact.

**Q2 (Constitution + Persist) — declared size.** CC 5.3.2.5: "every blob carries its size", and it
names the build manifest's descriptor. `build` carries no size, so a fetcher can only enforce the
CC 2.6.1.3 cap. Verify proposes **`build.manifest_size` (u64 bytes)** in this same break, since
adding it later is another wire break. Registry's `BuildFacts` would gain the member.

**Q3 (Constitution + Persist) — cohort.** `federation` (as fold_builds requires) vs `global` (as
the CC 8.1.5 encyclopedia example promotes to). Verify proposes **`federation`** for builds;
please confirm the encyclopedia template's scope separately.

**Q4 (Constitution + Persist) — retirement semantics.**
(a) A rebuild of the same `build_id`: `supersedes` chain, or an independent row?
(b) A bad build: `withdraws` signed by the pipeline, by the root, or either?
(c) The pipeline's grant is tombstoned. fold_builds re-checks standing **now** at every read, so
every past build disappears with it. Is that intended (compromise response), or should standing be
evaluated as of `asserted_at` (key rotation)? These are different events and probably need two
mechanisms. Verify has no proposal and needs a ruling.

**Q5 (Persist) — holder announcement for the submit door.** `put_blob_signing` signs as the
pipeline key. Confirm the `holds_bytes` row names the **serving node** as holder, not the pipeline,
which holds nothing once CI exits.

**Q6 (Constitution + Edge) — the presenter's claim.** The presenter bundle (#181) signs a `scores`
on the *same* `provenance:build_manifest:{target}` dimension with the presenter as attester. That
puts two different claims under one dimension: "pipeline built M" and "node K runs M". The bundle
envelope also has no row mirror, so it is not storable either. Verify proposes a distinct
`provenance:runs_build:{target}:v1` (a new CC row) with a row mirror, plus a reference to the
manifest's `attestation_id`. Until it is ratified, the bundle stays gossip-only and is never
submitted to a store.

**Q7 (Server/Registry) — §6's read-response change.** Accept, or say why not.

**Q8 (Persist + Constitution) — the grant producer is the other half of stage 9, and it is broken
the same way.** `ciris-verify delegate` → `self_at_login::sign_delegation_grant` emits
`attestation_type: "scores"`, `dimension: "delegates_to"` (refused by R3 as
`missing_version_segment`), `delegated_scope: […]`, top-level `subject_key_ids`, and **no row
mirror**. Persist's walk counts a conferral only if it is `row.attestation_type: delegates_to`,
`row.attested_key_id` = the subject, `scope` contains the token (`delegated_scope` is never read),
and the job dimension is `trust:confers:v1` or absent. So no grant Verify has ever minted can bless
a pipeline. Registry's tests mint theirs through persist's emit path, which is why nothing noticed.
The same producer also feeds the #63 self-at-login delegation and `operational_admit`'s role
chain, both of which read `delegated_scope`. Proposal: Verify emits persist's conferral shape
(`dimension: trust:confers:v1`, `scope`, row mirror with `attestation_type: delegates_to`) for the
`infra:*` capability grant, and `operational_admit` reads `scope`. That needs persist to confirm
the shape and CC to confirm `trust:confers:v1` is the job label for a capability conferral (it
matches `trust:{job}:{version}` in the rc6 registry).

## 9. What Verify ships in 19.0.0

- `dim::DIMENSION_VERSION`; all eight families carry the tail; `attest_bundle` splits the tail once
  and projects only the emitted rule version. CI replays every family through CC's matcher at a
  pinned rc6 commit and runs CC's emitted-dimension audit; an always-on Rust test covers runs
  without CC.
- `sign_build_manifest_contribution(pipeline, build, asserted_at)` emits §3 exactly, including
  `manifest_size`.
- `verify_build_manifest_contribution(obj, pipeline_member, &PipelineBlessing)` with the two-authority
  `PipelineStanding` (§5). The co-scrub verifier and the one-hop grant verifier are deleted.
- `verify_build_attestation_bundle` takes the blessing instead of `(pipeline_record, accord_anchors)`.
  CIRISEdge `bundle_gate` must call persist's authorities (edge accepted, CIRISEdge#786). The bundle's
  claim rides the trust ladder (Q6): `BundleInputs.presents`, the row mirror, `references_attestation_id`,
  `evidence_refs`, `asserted_at`; `BundleRejection::to_attestation_entry` takes the `PresentedBuild`.
- FFI / wheel (`verified`, `standing`, `manifest_size`), CLI `manifest sign --manifest-size`,
  `ciris-build-sign sign --emit-contribution`, and `release.yml`'s opt-in
  `CIRIS_EMIT_BUILD_CONTRIBUTION`.

**Not in 19.0.0, tracked as CIRISVerify#300:** Q8. Verify's grant producer (`sign_delegation_grant`) still emits the
pre-rc5 shape (`dimension: delegates_to`, `delegated_scope`, no row mirror) that the walk never
counts. Production standing does not depend on it (accord role), but the #63 self-at-login delegation
and `operational_admit`'s role chain both read `delegated_scope`, so moving it to `trust:confers:v1` +
`scope` + row mirror is its own change with its own consumers.

## 9a. Rulings received (2026-10-01)

- **Q1 (CC):** `provenance:build_manifest:{target}:v1` only. `agent_files:build:{target}` is the
  canonical attester's separate "an agent may load this" claim (CC 4.4.3.7) over the same bytes; a
  pipeline never emits it. Now stated in CC 3.1.2.1.
- **Q2 (CC, registry implemented):** `build.manifest_size` (u64 bytes), required. It follows from
  existing CC 5.3.2.5 text. **Frozen.**
- **Q3 (CC):** `federation`. `global` is not in the closed cohort set; the CC 8.1.5 example and
  4.4.3.3.1 are corrected. The encyclopedia template is `federation` too.
- **Q4a (CC):** a rebuild of the same `build_id` is a `supersedes` on the prior Contribution.
- **Q4b (CC):** a bad build is withdrawn by the **pipeline** (CC 2.4.1.1 path 1). The root cannot
  reach the row, since `subject_key_ids` is empty; the root's levers are the grant and the key.
- **Q4c — RULED by the steward (CC 3.2 T2, rc6 b384beb):** "We have supersede for exactly this
  purpose." Rotation is a `supersedes` on the grant: the root issues the successor grant, the
  lineage is kept, and a claim made under the superseded grant with `asserted_at` before the
  successor's keeps its standing (the reader walks the chain). A `withdraws` has no successor:
  standing ends at once for everything under it, the compromise response. Key-plane
  `revoked_after` composes as before; no second mechanism. Persist has not yet confirmed its walk
  honours a superseded grant for past builds (tracked for persist v53). For the accord-role
  standing, retirement is the quorum role withdrawal on the key record.
- **Q5 (registry observed, persist confirmed):** the holder is the serving node. `put_blob_signing`
  signs with the serving node's signer and records `author_key_id` as whose content it is; it
  refuses a body over 1 MiB and refuses proxy writes under Stop disk pressure. The holder row
  carries a required `size`.
- **Q6 — RULED by the steward (rc6 b384beb): no new row.** "Build attestation is already a claim
  we make as part of trust claims." A node's "I run build M" is the trust-ladder attestation it
  already carries: `attestation:self_verify` for the verifier's own binary, `attestation:agent_integrity`
  for an agent's tree, signed by the running node about itself and citing the manifest's
  Contribution (CC 3.1.2.1). The presenter bundle moves off `provenance:build_manifest:{target}`;
  a target no ladder row fits is reported to CC as a ladder gap (CIRISConstitution#137). **Citation
  wire (CC rc6 812170f):** `references_attestation_id` = the manifest Contribution's row id;
  `evidence_refs` = the manifest blob's digest (served bytes, so a pull can fire). Implemented in
  19.0.0: `PresentedBuild { SelfVerify, AgentIntegrity }` (closed), the bundle carries its own row
  mirror, and both scoring projections use the ladder dimension, never the pipeline's.
- **Q7 (registry, implemented):** reads return `contribution` + `standing {scope, root_key_id,
  grant_attestation_id, walked_by}` + `manifest_size`. Offered if wanted: `pipeline_record` and the
  signed grant, so an agent can run its own check against the baked anchor.
- **Q8 (CC confirmed):** a capability conferral is `delegates_to(root → subject)` carrying
  `dimension: trust:confers:v1`, with the scopes in the CC 2.1 `scope` member (`delegated_scope`
  was renamed in rc5). Persist to confirm the row shape.

### Persist's corrections (read from code)

- **Stage 5** has three more requirements: the pipeline key must be **registered on the admitting
  node**; `attestation_id` must be a **UUID** (postgres column; Verify mints v4); `asserted_at` must
  not be **future-dated**. No admission gate checks standing; standing is a read-time question.
  `delegation_scope` is read by nothing in persist. Registry's door reads it.
- **Stage 10:** persist's read is `list_holders`; `resolve_holders` is edge's.
- **§5:** the walk is **reader-relative** and has three arms (Delegation, FamilyQuorum,
  AccordCoScrub), **any of which can bless a pipeline**. Under FamilyQuorum the root is a *family
  id*. So `PipelineBlessing` and `VerifiedManifest` carry `conferral_plane` (19.0.0). This refines
  §5's account of registry's measurement: on that mesh the co-scrub arm failed `trust_root_valid`
  for the pipeline as its own root. That is a property of the trust state there, not a rule that
  the arm can never bless.
- **Q2:** persist does not gate `build.manifest_size`; its descriptor gate fires only on a `media`
  member (`{digest, size, format}`). CC ruled `build.manifest_size`, and registry's door gates it,
  so 19.0.0 keeps the CC shape. Persist's gate would apply only if the descriptor moved to `media`.
- **Q3 — reach is a product decision, referred to the steward.** `federation` is confirmed, but a
  pipeline blessed **only by delegation** has its manifests *projected to Cohort*, not Global.
  Global reach needs the accord-co-scrubbed `infra:attest` role on the pipeline's key record. That
  ties to stage 8(a): how far should a build manifest travel?
- **Q4 — persist dissents from CC's recommendation.** Read-time "now" is intended as the
  compromise response. Evaluating standing as-of `asserted_at` is **unsafe because the signer
  chooses that instant**, so a compromised pipeline backdates. Rotation = a new grant plus
  re-attestation of the builds that should survive.
- **Q8:** the counted shape is `attestation_type: delegates_to`, attesting = root, attested =
  subject, federation tier, `scope` (string or array) containing the token, `dimension`
  `trust:confers:v1` or absent. Reference JSON: persist's fixture
  `confer_scope_from_trusted_root` (admission.rs).

### Resolved during review: the production bless

Registry first reported that Server's `/v1/accord/ci-key` ceremony (co-scrub of the role, no
grant) gave production pipelines no standing. Persist then identified `is_infra_attest_effective`
as the authority for exactly that shape, and registry withdrew the report and adopted
walk-or-role. A holder-co-signed `delegates_to` grant from the same ceremony (FamilyQuorum plane)
remains **optional**: it would add the reader-relative un-trust lever, not standing. Server offered
to add it.

### Open constitutional question: is the accord-role bless an accord power? (steward's)

CC rc6 812170f corrects 3.1.2.1: standing is evaluated on whichever CC 3.2 T2 plane conferred it (a
key root's delegation, or a family root's quorum-scrubbed grant). It records the shipped accord-role
path (`/v1/accord/ci-key` co-scrub → `is_infra_attest_effective`) as **"recorded, not settled"**,
because CC 4.2.1 enumerates accord powers and names only the canonical-conferral co-scrub, and CC 4.2
is entrenched. That decision is on CIRISConstitution#137. Verify models it because it is what ships;
if it is ruled out, `PipelineStanding::AccordRole` is removed and Server's ceremony adds the
holder-co-signed grant (FamilyQuorum), which it has already offered.

### CI (19.0.0)

The matcher replay was a local-only gate: CI never checked out CIRISConstitution, so the step
skipped. CI now checks out CC at the pinned rc6 commit, makes an absent matcher a failure
(`CIRIS_CC_REQUIRED`), and also runs CC's `tools/audit_emitted_dimensions.py` over `src/` and
`bindings/` (20 registered, 0 not).

### Also from CC (affects §7)

The founders of `ciris-canonical` are A1/B1/C1 directly, and shipped roots are minted with
witnessed mode off (`witness_quorum: 0`). Verify's GenesisBundle consumer must not expect a witness
directory.

### Cross-repo witness (2026-10-01)

A Contribution minted by the release `ciris-build-sign sign --emit-contribution` binary was submitted
by CIRISRegistry, in-process, to `fold_builds`' submit door (SQLite Engine, persist v52.0.1,
registry 18a138c), with the pipeline registered from its public keys only and **no** blessing. The
door passed size, manifest hash, the facts (dimension `:v1`, `delegation_scope`, `evidence_refs`,
bare-hex hash), the row mirror, key lookup, and **the bound-hybrid signature over persist's canonical
bytes**, then refused `pipeline_not_blessed`, which is correct with no standing given. Control: the
same body with `build.build_id` altered after signing → `signature_invalid`. Admission into persist
(`assemble` + `put_attestation`) and a 201 under `accord_role` with replication are pending the
Server mesh ladder run. The witness also caught a second digest form (`binary_hash: sha256:…` beside a
bare `manifest_hash`): the producer now requires bare hex for both (CC 2.6.3).

## 10. Sign-off

Each owning session: reply with **ACCEPT**, or with the numbered questions you rule on and any
stage in §2 you mark wrong. Verify will not tag 19.0.0 until Q2 and Q6 have an answer, because
those are the two that would force a second wire break. Q4 can follow in a later minor.
