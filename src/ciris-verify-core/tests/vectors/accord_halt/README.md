# Edition-2 accord halt known answers

`accord_halt_v2.json` holds the accord's rows of edition 2 (CC 4.2.1.1, CC 4.2.1.3,
CC 4.2.6, CC 2.6.1.8; CIRISConstitution rc20 436b5bc): the invocation rows
(`constitutional`, `notify`, `drill`), the counted lifecycle rows (`confirmed`,
`active`), and latch sequences. Every case names the roster it is read under and
answers `valid`, `waiting:<what>` (`kid`, `bundle` or `kid+bundle`, with
`waiting.kids_hex` / `waiting.bundles_hex`, sorted) or `refused:<token>`
(`count_unmet` with `count.have` / `count.need`).
`tests/accord_halt_vectors_v2.rs` replays it through `edition2::accord_halt`
(`HaltReading::{Valid, Waiting, Refused}`) and
`accord_halt_latch::HaltLatch::apply_forward`.

`gen_accord_halt_v2.py` wrote it without verify's code. It has its own CBOR
deterministic encoder and composite signer (copied from
`../edition2/gen_row_statements_v2.py`: dilithium-py, FIPS 204 deterministic,
the label as the ML-DSA context; pyca/cryptography for Ed25519). Its
expectations are written from the text, not computed by a model of the reader.

    pip install dilithium-py cryptography
    python3 -I gen_accord_halt_v2.py > accord_halt_v2.json

`accord_halt_v1.json` (`gen_accord_halt.py`), published at v23.2.0, stays
byte-identical and is no longer replayed. v1 refused what v2 answers Waiting;
see [Waiting](#waiting).

## Waiting

A missed halt is the one unrecoverable failure (CC 4.2.1.1), so a reader never
refuses a halt for what it does not yet hold:

- **A statement under a key the roster does not hold waits on the key.** CC
  2.6.1.8 step 6: "Read kid; resolve the key record, or answer Waiting on it",
  and "Step 6 alone answers Waiting"; CC 2.4: "a row signed by a key not yet
  held is retryable, since a row waits for what it names". The reader cannot
  tell a stranger's key from a holder's key that a bundle it lacks seats (a
  rotation, a recovery: the holder's identity reference stays, its key
  changes). v1's `outsider_halt` (`not_a_holder`) is `waiting:kid` here, and
  `not_a_holder` is gone: nothing refuses with it.
- **A lifecycle row whose `refs.head` is not the roster's bundle waits on that
  bundle.** CC 4.2.1.1: "The reader verifies the row against the bundle in
  force that ... `refs.head` names on a lifecycle row"; CC 2.7.3: "A row waits
  for what it names." The reader holds one roster; whether the named bundle is
  unheld or held but not this roster's, the answer is to read the row again
  under the roster `refs.head` names (`named_head`, `HaltRoster::find_by_head`).
  CC draws no line between an unheld and a superseded bundle here, and neither
  does the reader. v1's `lifecycle_other_bundle` (`other_bundle`) is
  `waiting:bundle`, and `other_bundle` is gone. Every refusal that reads the
  row alone (members, `refs.target`, the halt's kind) is decided first.
- **A lifecycle row is counted on held voices.** Met by held voices: valid,
  whatever else was presented. Short of it: Waiting where a statement waits on a
  bundle, or where the held voices and the distinct unheld keys could together
  meet it, naming them; `refused:count_unmet` otherwise. A refused statement
  never makes a row wait. v1's `lifecycle_outsider_voice` (`count_unmet`) is
  `waiting:kid`.

Still refused: `iss_not_holder` (a held key under another holder's `iss`),
`other_accord`, and every member, family and window fault.

## The rosters

Two placement-equivalent holder sets, each the holders of one bundle:

| Holder | Key seed | ML-DSA-65 seed | Ed25519 seed | `genesis` | `rotated` |
|---|---|---|---|---|---|
| A1 | 1 | `[1]*32` | `[101]*32` | seated | |
| A1, rotated | 11 | `[11]*32` | `[111]*32` | | seated, `iss` A1's |
| B1 | 2 | `[2]*32` | `[102]*32` | seated | seated |
| C1 | 3 | `[3]*32` | `[103]*32` | seated | seated |
| outsider (not listed) | 9 | `[9]*32` | `[109]*32` | | |

Each `kid` is the RFC 9679 thumbprint of `{1: 7, 3: -70100, -1: pub}` and each
`iss` the identity reference of the holder's first key's thumbprint (a bundle
seats a key for an identity, so A1's rotated key signs as A1). Each roster
states the accord's `family_key_id` (`humanity-accord`), the bundle's object id
(a stated digest: SHA-256 of `accord_halt_v1: the bundle in force` for
`genesis`, of `accord_halt_v2: the bundle seating A1's rotated key` for
`rotated`; no bundle is minted here, the reader takes the holders' composite
keys), and the charter's `halt_fuse_secs` (3600; absent would mean 86400). A strict majority of three is two. In Rust,
`HaltRoster::new` takes these, and `HaltRoster::from_placement` (`std`) takes
them from a `GenesisPlacement`.

## The rows as implemented

Every accord row is a `scores` row, one statement per voice. Its CWT `sub` is
the accord's `family_key_id`, equal to `accord_root` (`member:sub` otherwise),
and its `valid_until` is after its `asserted_at`
(`valid_until_not_after_asserted_at` otherwise). These follow CC's rulings on
the points rc20 64c5918 left open.

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
only, and an unheld statement waits (above).

## Sections

- `rosters` (`genesis`, `rotated`), `outsider`: the keys, as above.
- `invocations`:
  - valid: `halt_constitutional_a1`, `notify_b1` (with `payload_digest`),
    `drill_c1`, `halt_constitutional_b1`, and `halt_rotated_a1_seated` (A1's
    halt under its rotated key, read under `rotated`), each with every member,
    the row id, the statement id, and the statement re-minted byte for byte by
    `sign_row_statement`;
  - `waiting:kid`: `halt_rotated_a1_unseated` (the same statement under
    `genesis`), `outsider_halt`, `halt_a1_first_key_under_rotated` (A1's first
    key, which `rotated` no longer seats: held inert, it never fires there);
  - refused: a holder's key under another holder's `iss` (`iss_not_holder`),
    `author` not the `iss`, a member tampered after signing
    (`statement_invalid:bad_signature`), a carried `invocation_kind`
    (`member:closed_map`), `payload_digest` on a halt and none on a notify, a
    31-byte nonce, another accord root (`other_accord`), the parent family
    `accord:.`, a `delegates_to` row type, a `sub` that is not the accord's,
    `valid_until` equal to `asserted_at`, and a lifecycle statement presented
    as an invocation (`wrong_family`).
- `lifecycles` (each naming its halt; a valid one names its counted statements
  by index):
  - valid: `confirmed_a1_b1`, `active_b1_c1`; `confirmed_b1_c1_plus_rotated_a1`
    (met by held voices plus an unheld key, not counted);
    `confirmed_a1_b1_plus_outsider` (an outsider's voice in a count still met);
    `rotated_confirmation_seated` (A1 rotated and B1 over the rotated bundle,
    read under `rotated`);
  - `waiting:kid`: `confirmed_b1_rotated_a1_unmet_waits` and
    `lifecycle_outsider_voice` (one held voice, and an unheld key could be the
    second);
  - `waiting:bundle`: `lifecycle_names_unheld_bundle` (A1 and B1 over the
    rotated bundle, read under `genesis`), `lifecycle_other_bundle` (a bundle
    no roster here is of);
  - `waiting:kid+bundle`: `rotated_confirmation_unseated` (A1 rotated and B1
    over the rotated bundle, read under `genesis`);
  - refused: `confirmed_unmet_refused_voices` (A1 held, B1 tampered, C1's key
    under A1's `iss`: `count_unmet` 1 of 2, a refused statement never waits),
    a lone voice and a repeated voice (`count_unmet`), two rows of one voice
    each, another halt (`other_halt`), the drill as target
    (`target_not_a_halt`), no target (`member:target`), an author
    (`family:author_column`), an unversioned dimension, a `sub` that is not the
    accord's (`member:sub`), `valid_until` before `asserted_at`, and the halt's
    own statement presented as a lifecycle row (`wrong_family`).
- `latch`: sequences of `apply` (a case, the receipt instant in ms, the outcome:
  `paused`, `confirmed`, `resumed`, `unchanged`) and `check` (an instant, paused
  or not), the fuse the roster's `halt_fuse_secs` counted from receipt: halt →
  fuse lapses; halt → confirmed → no lapse; halt → active → cleared; confirmed
  then active; a late confirmation; notify and drill never latch; a second halt
  does not reset the fuse; the held-resumption sequences below; and a rotated
  holder's halt, read under the roster that seats its key, fires
  (`rotated_holder_halt_fires`).

A drill verifies as a halt does (one holder, CC 4.2.1.1: "a drill rehearses the
fire path") and never touches the latch; a lifecycle row naming it is refused,
since the lifecycle guard requires a `constitutional` halt as its target (CC
8, `accord:lifecycle:{kind}` guard).

## CC's rulings, and what stays open

CC ruled on the points rc20 64c5918 left open:

- **`sub`** is the accord's `family_key_id` (= `accord_root`), on invocation and
  lifecycle rows alike: `halt_sub_not_accord`, `lifecycle_sub_not_accord`
  (`member:sub`).
- **The row type** is `scores`.
- **A drill** rehearses the fire path only: a lifecycle row naming it is
  `target_not_a_halt`.
- **`valid_until <= asserted_at`** makes the row Invalid:
  `halt_valid_until_equals_asserted_at`,
  `lifecycle_valid_until_before_asserted_at`
  (`valid_until_not_after_asserted_at`).
- **A resumption held before its halt** is the latch's. The latch keeps the
  row id each applied `lifecycle:active` names (whether or not that halt was
  in force), and a halt received after its `valid_until` that one of them names
  does not fire (CC 4.2.1.1). A halt received within its `valid_until` (or at
  exactly it, which is not after it) fires: the text's exception is only for a
  halt past its `valid_until`. The held resumption, applied again, ends it.
  Sequences: `resumption_held_then_late_halt` (does not fire),
  `resumption_held_then_halt_at_valid_until` and
  `resumption_held_then_halt_within_valid_until` (fire),
  `late_halt_without_resumption_fires`, `other_resumption_held_then_late_halt`.
- **The roster** is the reader's: the bundle in force is the one the row names,
  by `accord_root` for an invocation and `refs.head` for a lifecycle row
  (`named_accord_root`, `named_head`, `HaltRoster::find_by_head`,
  `HaltRoster::from_placements_by_head`); an invocation naming another accord
  is `other_accord`, and a lifecycle row read under another bundle's roster
  waits on the bundle it names.
- **Dedup** of `invocation_id` (per kind) and the single use of `nonce` within
  `valid_until` are the store's duty, and nothing here checks them: a replayed
  row verifies again.

Still as the text stands:

- **The first drill's rehearsal.** CEREMONY.md step 11 has "confirmation and
  resumption rehearsed at a strict majority" after the first drill, while the
  lifecycle guard admits only a `constitutional` halt as target: a drill cannot
  be confirmed or resumed by a lifecycle row.
- CC's own schema sample (`tools/build_cc_signed_object_v2.py`) writes
  `dimension: "accord:lifecycle:active"` without the version tail, which the
  namespace matcher refuses (`missing_version_segment`); the sample is a CDDL
  shape check, and these vectors carry `:v1`.
