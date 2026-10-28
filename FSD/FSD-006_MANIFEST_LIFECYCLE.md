# FSD-006 — The build-manifest lifecycle, end to end

**Status:** Accepted by CIRISConstitution, CIRISPersist, CIRISServer/CIRISRegistry and CIRISEdge · **Author:** CIRISVerify · **CC:** 1.0

| Owner | Owns |
|---|---|
| CIRISConstitution | the wire grammar: dimension, envelope members, blob rules, authority planes |
| CIRISPersist | admission, row mirror, blob store, `holds_bytes`, capability walk |
| CIRISServer / CIRISRegistry | the `/v1/builds` submit and read doors |
| CIRISEdge | blob fetch, presenter-bundle gate |
| CIRISVerify | producer, signature + shape verifier, presenter bundle |

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
strength of it. That makes it the right place to pin the lifecycle once, as the template the
encyclopedia / NodeCore blob path inherits rather than re-derives.

The rule this document enforces everywhere: **meaning comes from a signed claim that references the
bytes; possession of bytes means nothing; authority comes from the reader's own walk, never from
the serving node.**

## 2. The lifecycle, stage by stage

| # | Stage | Manifest instance | General public-blob form | Owner | CC | State |
|---|---|---|---|---|---|---|
| 1 | Bytes | the canonical file manifest (JSON) | article body, media, package | producer | 3.1.2.1 | ✅ |
| 2 | Address | `manifest_hash` = sha256(bytes), bare lowercase hex | `content_sha256` | producer | 5.3.2.5 | ✅ |
| 3 | Claim | `scores` on `provenance:build_manifest:{target}:v1`, `evidence_refs: [manifest_hash]` | `scores` on `encyclopedia:article:{…}:v1`, `evidence_refs: [sha]` | producer | 2.1, 3.1.7 R3 | ✅ |
| 4 | Sign | bound-hybrid over JCS(envelope); **row mirror + `asserted_at` inside the bytes** | same | Verify (`sign_build_manifest_contribution`) | 2.6.1, 5.3.2.4.2 | ✅ |
| 5 | Admit | `put_attestation`: R3, row↔column binding, instant binding, hybrid; pipeline key registered on the admitting node; `attestation_id` a UUID; `asserted_at` not future-dated. No admission gate checks standing | same door | Persist | 5.3.2.4.3.1 | ✅ |
| 6 | Store bytes | `put_blob_signing(sha, bytes, …, author_key_id)`: `author` is whose content it is; the holder claim is the **serving node's**, signed by it | same | Persist (via submit door) | 3.1.9.1 | ✅ holder is the serving node; body ≤ 1 MiB; holder row carries `size` |
| 7 | Announce holder | `holds_bytes:sha256:{prefix}` auto-emitted | same | Persist | 3.1.9.1, 5.3.2.1 | ✅ |
| 8 | Replicate | claim + holder rows via anti-entropy | same | Persist / Edge | 5.3.2.3 | ⚠️ **conditional**: crosses only if (a) the consent grant covers `provenance:` (persist projects a non-root author's row as Cohort), (b) both owners accept a common root, else edge withholds it as "Attributed but not Rooted", (c) the pipeline's key record and grant replicate too |
| 9 | **Standing** | accord role on the pipeline's key record (production), or a `trust:confers:v1` grant the reader's walk finds | the author's standing for the family (editor-consensus for `encyclopedia:*`) | Persist (`is_infra_attest_effective` / `capability_roots_to_trusted_root`) | 3.2 T2, 4.2.1 | ✅ §5 |
| 9a | Grant producer | `ciris-verify delegate` mints the blessing | the root's conferral for any content family | Verify (`sign_delegation_grant`) | 3.2 T2 | ❌ **not counted by the walk** — §8 |
| 10 | Discover | `holds_bytes` directory → `list_holders` (persist) / `resolve_holders` (edge) | same | Persist / Edge | 5.3.2 | ✅ |
| 11 | Fetch | `ContentFetch`, ≤2 holders in parallel, `ContentMiss` → `withdraws` | same | Edge | 5.3.2.1 | ⚠️ `ContentMiss`→`withdraws` is implemented; edge does not enforce the ≤2-holder cap, and its chunked path is an adaptive multi-peer scheduler. Edge declines commons blobs unless the operator consents and the holder is allow-listed, so only registry-conferred nodes hold manifest bytes and **an agent reads them over HTTP from a registry node, not over the swarm** |
| 12 | Check | **size first**, then full SHA, before any consumer sees a byte | same | consumer | 5.3.2.5 | ✅ `build.manifest_size`; registry submit door refuses `manifest_size_mismatch` before hashing |
| 13 | Consume | agent loader / L4 file integrity; render tier from sniffed bytes | renderer, render tier | consumer | 5.3.2.6 | ⚠️ the read door returns the claim + `standing` (§6); Verify has no agent-side consumer of it |
| 14 | Present | presenter bundle: node K's trust-ladder attestation citing M's claim | citing an article in a downstream claim | Verify (`build_attestation_bundle`) | 3.1.2.1 | ✅ §7 |
| 15 | Retire | `supersedes` (rebuild, rotation) · `withdraws` (bad build, compromise) · quorum role withdrawal | `supersedes` revision chain, takedown | producer / root | 2.3, 2.4.1.1, 3.2 T2, 4.5.3 | ✅ §5 |

## 3. The wire object (normative)

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
  `subject_key_ids` / `signed_at` that could disagree with the mirror.
- **`subject_key_ids` is empty.** CC 2.3.2.1 admits only canonical key_ids, and a build id is not
  one. The build is named by `build` and the blob by `evidence_refs`.
- **`asserted_at` is the one signed instant**, millisecond `Z` (CC 2.6.2), truncated before
  rendering so the signed string and the derived column are the same instant.
- **No `on_behalf_of` / `delegation_ref`.** Standing is not a claim the producer makes about
  itself (§5).
- **Family:** `provenance:build_manifest:{target}:v1` only (CC 3.1.2.1). `agent_files:build:{target}`
  is the canonical attester's separate "an agent may load this" claim (CC 4.4.3.7) over the same
  bytes; a pipeline never emits it.
- **Size:** `build.manifest_size` (u64 bytes) is required (CC 5.3.2.5).
- **Cohort:** `federation`; `global` is not in the closed cohort set.
- **Digests:** `binary_hash` and `manifest_hash` are both bare lowercase hex (CC 2.6.3).

The encyclopedia form differs only in `dimension`, the descriptor member (`build` ↔ the article /
media Source struct, CC 3.3.13), and `cohort_scope`.

## 4. Version tails: R3 is global

CC 3.1.7 R3's version grammar is **global**: every non-exempt family ends in exactly one `:vN`,
whatever that family's own `segments` array says; only the four bare `attestation:*` constants are
exempt. Every family Verify emits carries `dim::DIMENSION_VERSION`: `provenance:build_manifest`
(+ `:locale:`), `provenance:slsa`, `provenance:skill_import`, `transparency_log:inclusion`,
`transparency_log:consistency`, `transparency_log:cosigned`, `rollback_detected`, `cert_validity`,
`hardware_custody`. CI checks out CIRISConstitution at a pinned commit, replays every emitted
family through CC's matcher (`tools/cc_namespace_match.py`) with negative controls, fails if the
matcher is absent (`CIRIS_CC_REQUIRED`), and runs CC's `tools/audit_emitted_dimensions.py` over
`src/` and `bindings/`. Any repo that emits dimensions should run the same replay rather than
reading the registry JSON family by family.

## 5. Standing: the substrate decides, by one of two authorities

Whether a pipeline may attest builds is answered by persist over the **reader's own directory**,
by one of two authorities. Verify re-derives neither.

| Standing | Persist authority | Shape | Reader-relative | Retirement | Reach (federation scope) |
|---|---|---|---|---|---|
| **Accord role** (production) | `admission::is_infra_attest_effective(dir, pipeline)` | `infra:attest` inside the pipeline's accord-co-scrubbed key record, at quorum. Written by CIRISServer `/v1/accord/ci-key/{propose,cosign}` | no | quorum role withdrawal; `supersedes` naming a successor key is the rotate-in | Global |
| **Conferred**: Delegation | `trust_root::capability_roots_to_trusted_root(dir, reader, pipeline, "infra:attest")` | `delegates_to(root → pipeline)`, `dimension: trust:confers:v1`, `scope ∋ infra:attest` | yes | `supersedes` on the grant = rotation, earlier claims keep standing; `withdraws` = compromise, everything ends (CC 3.2 T2) | Cohort |
| **Conferred**: FamilyQuorum | same walk | the same grant, whose scrub set reaches a constitutional family's quorum; root = the **family id** | yes | as above | Cohort |

The walk's third arm, **AccordCoScrub**, makes the subject itself the candidate root and requires
`trust_root_valid` on it (self-charter, recovery commitment, fresh heartbeat), which a pipeline
does not have. The accord co-scrub reaches a pipeline through the *role* authority instead.

The accord-role bless is an enumerated power of a root's conferring roster (CC 4.2.1, "Blessing a
build pipeline is in scope"), bounded to `infra:attest`: a co-scrub bearing any other role on a
pipeline record is out of role. The pipeline key holds no seat. The bless ends by revocation of the
record or un-trust of the root. **A reader MUST evaluate both planes before finding a pipeline
without standing** (CC 3.1.2.1).

**Retirement (CC 2.4.1.1, 3.2 T2).** A rebuild of the same `build_id` is a `supersedes` on the
prior Contribution. A bad build is withdrawn by the **pipeline**; the root cannot reach the row
(`subject_key_ids` is empty), and its levers are the grant and the key. Rotation is a `supersedes`
on the grant: the root issues the successor grant, the lineage is kept, and a claim made under the
superseded grant with `asserted_at` before the successor's keeps its standing. A `withdraws` has no
successor: standing ends at once for everything under it. Key-plane `revoked_after` composes with
both. For the accord-role standing, retirement is the quorum role withdrawal on the key record.

**Reach.** A pipeline blessed only by delegation has its manifests projected to Cohort; Global reach
needs the accord-co-scrubbed `infra:attest` role on the pipeline's key record.

**Verify:** `verify_build_manifest_contribution(obj, pipeline_member, &PipelineBlessing)`,
where `PipelineBlessing { pipeline_key_id, standing: Conferred { root_key_id,
grant_attestation_id, plane: Delegation | FamilyQuorum } | AccordRole }`. The walk's
co-scrub arm is unrepresentable. Verify checks the signature and shape and that the blessing
names the signing pipeline; the caller asks persist. The FFI/wheel take and return
`standing: "delegation" | "family_quorum" | "accord_role"`, with root and grant present only for the
walk standings. Registry's door asks the walk first, then the role, and refuses only if both say no;
its read response carries the same discriminator. Verify holds no authority model of its own: a
local copy could not see a quorum role withdrawal, a tombstone or an expiry.

**Generalisation for public blobs:** each content family names its standing authority once (builds
→ accord role or `infra:attest` conferral; encyclopedia → editor-consensus per CC 3.3.11). The
reader asks the substrate, never a field the producer wrote about itself.

## 6. The read door returns the claim, not a summary of it

`GET /v1/builds/{version}` returns `contribution` (the stored `SignedContribution`), `standing
{scope, root_key_id, grant_attestation_id, walked_by}` and `manifest_size`. A reader re-verifies the
signature and shape locally and checks size + full SHA of the manifest bytes (CC 5.3.2.5) before
file integrity consumes them; standing comes from the serving node's walk, and the response says
whose walk it was. CC 5.3.4: nothing a serving install signs on its own account is a root. The same
rule applies to every public blob read: **return the claim with the bytes.**

## 7. Presenting a build

A node's "I run build M" is the trust-ladder attestation it already carries (CC 3.1.2.1):
`attestation:self_verify` for the verifier's own binary, `attestation:agent_integrity` for an
agent's tree, signed by the running node about itself and citing the manifest's Contribution. It
does not reuse `provenance:build_manifest:{target}`, which is the pipeline's claim. The citation
is `references_attestation_id` = the manifest Contribution's row id and `evidence_refs` = the
manifest blob's digest. `build_attestation_bundle` implements it with `PresentedBuild { SelfVerify,
AgentIntegrity }` (closed); the bundle carries its own row mirror, and both scoring projections use
the ladder dimension. A target no ladder row fits is a ladder gap for CC, not a presenter's choice.

The walk roots in the trust root (FSD-001 §5): the GenesisBundle verified against the accord
holders baked into the binary. The founders of `ciris-canonical` are A1/B1/C1 directly and shipped
roots are minted with `witness_quorum: 0`, so a consumer does not expect a witness directory.

## 8. Known gap: the grant producer

`ciris-verify delegate` → `self_at_login::sign_delegation_grant` emits `dimension: "delegates_to"`
(refused by R3 as `missing_version_segment`), `delegated_scope: […]`, top-level `subject_key_ids`,
and no row mirror. Persist's walk counts a conferral only as `row.attestation_type: delegates_to`,
attesting = root, `row.attested_key_id` = the subject, federation tier, `scope` (string or array)
containing the token, and `dimension` `trust:confers:v1` or absent (reference: persist's fixture
`confer_scope_from_trusted_root`, admission.rs). So no grant this producer mints can bless a
pipeline. Production standing does not depend on it (accord role). The self-at-login delegation
and `operational_admit`'s role chain read `delegated_scope`, so moving the producer to
`trust:confers:v1` + `scope` + row mirror changes those consumers too. Tracked as CIRISVerify#300.

## 9. Verify's surface

- `dim::DIMENSION_VERSION` on every emitted family; `attest_bundle` splits the tail once and
  projects only the emitted rule version.
- `sign_build_manifest_contribution(pipeline, build, asserted_at)` emits §3 exactly.
- `verify_build_manifest_contribution(obj, pipeline_member, &PipelineBlessing)` with
  `PipelineStanding` (§5).
- `verify_build_attestation_bundle` takes the blessing; the bundle's claim rides the trust ladder
  (§7): `BundleInputs.presents`, the row mirror, `references_attestation_id`, `evidence_refs`,
  `asserted_at`; `BundleRejection::to_attestation_entry` takes the `PresentedBuild`.
- FFI / wheel (`verified`, `standing`, `manifest_size`), CLI `manifest sign --manifest-size`,
  `ciris-build-sign sign --emit-contribution`, and `release.yml`'s opt-in
  `CIRIS_EMIT_BUILD_CONTRIBUTION`.
- A holder-co-signed `delegates_to` grant from the accord ceremony (FamilyQuorum plane) is optional:
  it adds the reader-relative un-trust lever, not standing.

## 10. Reproducing the mesh path

CIRISServer `harness/mesh-repro`, `MAN_EXTERNAL_PIPELINE=<dir> ./run_scenario.sh manifest`: a test
root scrub-signs a key record for the pipeline's public keys with `roles: [infra:attest]`;
`POST /v1/builds` with the producer's `.body` returns 201 with `standing: accord_role`, and a second
registry serves `GET /v1/builds/manifest/{sha}` with matching bytes after replication. The same
scenario covers delegation standing and an unblessed pipeline (refused, served nowhere).
