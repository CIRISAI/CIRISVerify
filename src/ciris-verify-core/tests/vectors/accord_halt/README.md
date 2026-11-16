# Edition-2 accord halt known answers

`accord_halt_v1.json` holds the accord's rows of edition 2 (CC 4.2.1.1, CC 4.2.1.3,
CC 4.2.6; CIRISConstitution rc20 64c5918): the invocation rows (`constitutional`,
`notify`, `drill`), the counted lifecycle rows (`confirmed`, `active`), their
refusals, and latch sequences. `tests/accord_halt_vectors.rs` replays it through
`edition2::accord_halt` and `accord_halt_latch::HaltLatch::apply_forward`.

`gen_accord_halt.py` wrote it without verify's code. It has its own CBOR
deterministic encoder and composite signer (copied from
`../edition2/gen_row_statements_v2.py`: dilithium-py, FIPS 204 deterministic,
the label as the ML-DSA context; pyca/cryptography for Ed25519). Its
expectations are written from the text, not computed by a model of the reader.

    pip install dilithium-py cryptography
    python3 -I gen_accord_halt.py > accord_halt_v1.json

## The roster

A placement-equivalent holder set, the holders of the bundle in force:

| Holder | Key seed | ML-DSA-65 seed | Ed25519 seed |
|---|---|---|---|
| A1 | 1 | `[1]*32` | `[101]*32` |
| B1 | 2 | `[2]*32` | `[102]*32` |
| C1 | 3 | `[3]*32` | `[103]*32` |
| outsider (not listed) | 9 | `[9]*32` | `[109]*32` |

Each `kid` is the RFC 9679 thumbprint of `{1: 7, 3: -70100, -1: pub}` and each
`iss` the identity reference of that thumbprint. The roster states the accord's
`family_key_id` (`humanity-accord`), the bundle's object id (a stated digest,
SHA-256 of `accord_halt_v1: the bundle in force`; no bundle is minted here, the
reader takes the holders' composite keys), and the charter's `halt_fuse_secs`
(3600; absent would mean 86400). A strict majority of three is two. In Rust,
`HaltRoster::new` takes these, and `HaltRoster::from_placement` (`std`) takes
them from a `GenesisPlacement`.

## The rows as implemented

Every accord row is a `scores` row, one statement per voice, `sub` = the
accord's `family_key_id` here (see [Open](#what-the-text-leaves-open)).

**Invocation** (one holder's statement). The kind is the family (header -70002):

| Kind | Family id |
|---|---|
| `constitutional` | `accord:invoke:constitutional:.halt_id` |
| `notify` | `accord:invoke:notify:.notify_id` |
| `drill` | `accord:invoke:drill:.drill_id` |

The payload is a closed map:

| Member | Type | Rule |
|---|---|---|
| `author` | identity-ref | the statement's `iss`, a holder of the bundle in force, signing with the key the bundle names |
| `accord_root` | tstr | the roster's `family_key_id` |
| `invocation_id` | tstr | the id of the halt, notify or drill |
| `nonce` | bstr .size 32 | |
| `asserted_at` | ms-time | |
| `valid_until` | ms-time | |
| `payload_digest` | `[-16, digest]` | on a notify, and on nothing else |

**Lifecycle** (counted: one statement per holder over one payload, no `author`),
family `accord:lifecycle:.kind`, the kind the leaf of `dimension`
(`accord:lifecycle:confirmed:v1` or `accord:lifecycle:active:v1`):

| Member | Type | Rule |
|---|---|---|
| `refs.head` | row-ref | the bundle in force's object id |
| `refs.target` | row-ref | the halt's row id; the named row is a `constitutional` halt |
| `dimension` | tstr | `accord:lifecycle:{confirmed,active}:vN` |
| `accord_root` | tstr | the roster's `family_key_id` |
| `invocation_id` | tstr | the lifecycle row's own id |
| `nonce` | bstr .size 32 | |
| `asserted_at` | ms-time | |
| `valid_until` | ms-time | |

`refs` holds exactly `head` and `target`. The row counts at a strict majority of
the roster, one voice per `iss`; a statement's own fault refuses that statement
only.

## Sections

- `roster`, `outsider`: the keys, as above.
- `invocations`: four valid invocations, each with every member, the row id,
  the statement id, and the statement re-minted byte for byte by
  `sign_row_statement`: `halt_constitutional_a1`, `notify_b1` (with
  `payload_digest`), `drill_c1`, `halt_constitutional_b1`.
- `lifecycles`: `confirmed_a1_b1` and `active_b1_c1` (valid: kind, row id,
  target, head, voices, statement ids), and refusals: a lone voice and a
  repeated voice (`count_unmet:1:2`), two rows of one voice each, an outsider's
  voice, another halt (`other_halt`), the drill as target (`target_not_a_halt`),
  no target (`member:target`), another bundle (`other_bundle`), an author
  (`family:author_column`), an unversioned dimension, and the halt's own
  statement presented as a lifecycle row (`wrong_family`).
- `invocation_refusals`: an outsider's halt (`not_a_holder`), a holder's key
  under another holder's `iss` (`iss_not_holder`), `author` not the `iss`, a
  member tampered after signing (`statement_invalid:bad_signature`), a carried
  `invocation_kind` (`member:closed_map`), `payload_digest` on a halt and none
  on a notify, a 31-byte nonce, another accord root, the parent family
  `accord:.`, a `delegates_to` row type, and a lifecycle statement presented as
  an invocation (`wrong_family`).
- `latch`: sequences of `apply` (a case, the receipt instant in ms, the outcome:
  `paused`, `confirmed`, `resumed`, `unchanged`) and `check` (an instant, paused
  or not), the fuse the roster's `halt_fuse_secs` counted from receipt: halt →
  fuse lapses; halt → confirmed → no lapse; halt → active → cleared; confirmed
  then active; a late confirmation; notify and drill never latch; a second halt
  does not reset the fuse.

A drill verifies as a halt does (one holder, CC 4.2.1.1: "a drill rehearses the
fire path") and never touches the latch; a lifecycle row naming it is refused,
since the lifecycle guard requires a `constitutional` halt as its target (CC
8, `accord:lifecycle:{kind}` guard).

## What the text leaves open

- **`sub`.** No member table fixes the CWT `sub` of an accord row; CC 2.6.1.1
  says only "what the row is about". The row id reads it. The reader does not
  constrain it; these vectors use the accord's `family_key_id`.
- **Row type.** The text does not say `scores` in so many words; the families
  are attestations (`+1.0 only`, transition `attest`), and none of the four
  structural composers fits. The reader requires `scores`.
- **`valid_until` against `asserted_at`.** No order is stated; none is checked.
- **The resumption held before its halt.** "A halt that arrives after its
  `valid_until` still fires, unless the node already holds a resumption that
  names it" (CC 4.2.1.1). The latch keeps no resumption without a halt in
  force, so this stays the caller's (the store holds rows).
- **Dedup.** Per-kind dedup of `invocation_id` and single use of `nonce` within
  `valid_until` stay the caller's.
- **The first drill's rehearsal.** CEREMONY.md step 11 has "confirmation and
  resumption rehearsed at a strict majority" after the first drill, while the
  lifecycle guard admits only a `constitutional` halt as target: a drill cannot
  be confirmed or resumed by a lifecycle row as the text stands.
- CC's own schema sample (`tools/build_cc_signed_object_v2.py`) writes
  `dimension: "accord:lifecycle:active"` without the version tail, which the
  namespace matcher refuses (`missing_version_segment`); the sample is a CDDL
  shape check, and these vectors carry `:v1`.
