# Edition-2 row statement known answers

`row_statements_v4.json` holds CC 2.6.1 row statements (CIRISConstitution rc20
0c9e17c, the clean mesh; `manifests/signed_object_v2.cddl`), with its family
cases read under CC's family model at the released tag v1.0-rc20 (d4bd2a6), for
CIRISVerify#326, and two rc21 rulings (see [What changed from v3](#what-changed-from-v3)).
`tests/edition2_row_vectors_v4.rs` replays it. It supersedes
`row_statements_v3.json`, `row_statements_v2.json` (see [What changed from v2](#what-changed-from-v2)) and
`row_statements_v1.json` (see [What changed from v1](#what-changed-from-v1)),
which stay beside it byte for byte, with their generators, for the readers that
pinned them; none is replayed.

`gen_row_statements_v4.py` wrote v4 (`gen_row_statements_v3.py` v3,
`gen_row_statements_v2.py` v2 and `gen_row_statements.py` v1) without
verify's code. It has its own CBOR deterministic encoder (RFC 8949 §4.2.1,
bytewise key order) and signs with the composite ML-DSA-65-Ed25519 through
dilithium-py (FIPS 204, deterministic variant, the label as the ML-DSA context)
and pyca/cryptography (Ed25519):

    pip install dilithium-py cryptography
    python3 -I gen_row_statements_v4.py > row_statements_v4.json
    python3 -I gen_row_statements_v3.py > row_statements_v3.json   # unchanged
    python3 -I gen_row_statements_v2.py > row_statements_v2.json   # unchanged
    python3 -I gen_row_statements.py > row_statements_v1.json      # unchanged

Key `n` is ML-DSA-65 seed `[n]*32` and Ed25519 seed `[n+100]*32`; its `kid` is the
RFC 9679 thumbprint of `{1: 7, 3: -70100, -1: pub}` and its `iss` the identity
reference of that thumbprint.

## Levels

Every v4 case states the `level` it is read at:

- `statement`: `edition2::verify_row_statement`, no family model (`valid`,
  `refusals`; `key_directory` through a `KeyRecordDirectory`);
- `family`: `edition2::family::verify_row_in_family` under the model the case
  names in `model`: `test` (the stated `family_model`) or `vendored`
  (`VendoredFamilyModel`, CC's `family_authorship.json`); a case with `ctx`
  through `verify_row_in_family_with`, one with `read: as_given` through
  `verify_row_in_family_as_given`, and `family_vendored_groups` through
  `verify_group_row_in_family`;
- `object`: `verify_object_statement` (non-row object headers);
- `payload`: `keys::check_key_record` over a key-record payload;
- `value`: `classify_reference` over a CBOR value.

Every `valid` case is valid at both levels: its `family_vendored_expect` is
`valid`, and the test replays each through `verify_row_in_family(..,
&VendoredFamilyModel)` with no caller-supplied selector keys.

## Sections

Rc20 (the namespace registry vendored at `data/cc/namespace_registry.json`):

- `valid`: four statements, each with its `kid`, `iss`, row id and statement id,
  re-minted byte for byte by `edition2::sign_row_statement`:
  - `authored_score`: an authored scores row (`evidence:*`, authored in CC's
    model) signed by its author;
  - `counted_with_refs`: a counted row with `refs`, a salt, `nbf`/`exp` and both
    redaction forms, on `group:roster` (counted in CC's model: authorship
    `* => counted`), so it carries no `author`;
  - `second_voice`: the same counted row signed by a second key, a second voice
    of it: the same row id, another statement id (CC 2.6.1.9);
  - `disclosed`: a row with disclosures (digests stated).
- `refusals`: statements with the verdict each must get (`waiting:kid:<kid>`, or
  `invalid:<reason>[:<member>]`). They cover the composite, deterministic
  encoding, headers and CWT claims, time claims, `refs` sets and tuples,
  edition-1 row-refs, values and fixed6 ranges, disclosures, and dimension →
  family through CC's one matcher (CC 3.1.7).
- `key_records`: the CC 2.4.1.1 end rule over key-record payloads, with
  refusal tokens.
- `key_directory`: key resolution through key-record rows: a held chain, Waiting
  on the deepest missing key, a record that breaks the end rule (Invalid), and a
  statement after the held record's `valid_until`
  (`waiting:covering_record:<kid>:<at_ms>`).
- `family_model` + `family`: the author column and second-consent roles under a
  stated test model (`model: test`, a caller-supplied model).
- `objects`: non-row object headers (no `cty`, never -70001/-70002, closed
  `typ`), with the object id. Payload rules come with the ceremony set.
- `references`: values typed by form (`[-16, digest]` a row, an identity
  reference a key), for CIRISKernel's `Obj::from_reference`.
- `family_vendored` (`model: vendored`): the author column and second-consent
  roles under CC's own cells (`manifests/family_authorship.json`, v1.0-rc20
  d4bd2a6), read by CC's one selector evaluator (`tools/cc_family_select.py`):
  the leaf is the row's dimension bound under its family, and `verb` /
  `identity` / `group` / `seats` come from the case's optional `ctx` (absent:
  unknown). `act` is never a payload member: the reader derives it when the
  `ctx` leaves it out (CC 2.6.1.9), `own` for one statement of a row with an
  `author`, and each `key:record` / `licensure` case states the derived `act`
  (`own`; `none` for one voice of a counted row read alone; `withheld` where
  `read: as_given` derives nothing, as a harness withholding it). The expectations are stated from that evaluator's
  answers: a leaf or a caller key that decides, an unknown arm before the
  decider (`authorship_undetermined`), a false test beside an unsupplied one,
  `when`-conditioned roles that hold, do not hold or are unknown, a role
  member that names the signer or does not, and `owner_of_sub` and
  `key:record`'s `target` (the issuer of the row `refs.target` names) never
  read from the payload. A row's dimension
  must resolve to its own header family, so `accord:*` (a closed family no
  dimension resolves to cleanly) is reached only without a dimension, where its
  first arm is unknown.
- `family_vendored_groups` (`model: vendored`, `act: group`): the statements of
  one counted row read together by `verify_group_row_in_family`, which derives
  `act` = `group` (CC 2.6.1.9); `expect` is each voice's verdict (with the row
  id they share) or `several_rows`. Counting the voices over the roster they
  name is the caller's.

## What changed from v3

- **Each key's own holder signs its record** (CC 2.4.1.1, rc21: "no third
  party ends a key and no third party revives one"). Every `key_directory`
  record is signed by the key it records. A record only another key signed
  makes the key live nowhere: the statement waits on the key's own voice,
  `waiting:voice:<kid>`. v3's `held_through_chain` (B's record signed by A
  alone: Valid) is `record_not_own_voice`, and `deep_waiting` (signed by an
  unheld G alone: waiting on G) is `record_by_stranger`, both waiting on B.
- **Body decimals** (CC 2.6.1.4): `body_decimal` carries `4([-2, 12345])` and
  `4([-1, -5])` and is valid; a tag 4 not normalised (`[-1, 10]`, `[0, 7]`,
  `[-1, 0]`) is a second encoding, `not_deterministic:payload`; a bignum, alone
  or as a decimal's mantissa, is `body_number_unrepresentable`.
- `node_at_asserted` (a `valid_until` equal to `asserted_at`) is
  `key_record_out_of_window`: a record covers `[asserted_at, valid_until)`.

## What changed from v2

CC's family model at the released tag v1.0-rc20 (d4bd2a6) makes `key:record`
and `licensure:{authority_id}` `act=group => counted ; authored` (v2 read them
as plain authored and as a `gap`), and its rulings make `act` something the
reader derives, never a payload member (CC 2.6.1.9). Every section other than
`family_vendored` is byte-identical to v2; `family_vendored_groups` is new.
In `family_vendored`:

- `v_author_signs` (`key:record`): valid, now as act `own` derived from its one
  statement.
- `v_gap_role_not_admitted` → `v_key_record_second_signer_no_target`: the same
  statement and verdict (`iss_not_in_role`); the role is now `predecessor_key`
  by `target`, not two `gap` roles.
- new `v_key_record_predecessor_not_from_payload`: `predecessor_key` is the
  issuer of the row `refs.target` names (CC 3.1.3), which the row does not
  carry, so a payload member `target` naming the signer does not admit it.
- new `v_key_record_voice_alone`: one voice of a counted `key:record` read
  alone derives no act (`authorship_undetermined`).
- new `v_key_record_act_withheld`, `v_licensure_act_withheld`, `v_act_withheld`:
  read as given with `act` withheld, `authorship_undetermined` (v2's
  `v_act_unsupplied` verdict).
- `v_gap_undetermined` → `v_licensure_own`: `licensure` is no longer a gap;
  act `own`, valid (was `authorship_undetermined`).
- `v_act_unsupplied` → `v_act_derived_own`: `collection:{kind}` with no `ctx`
  now derives `own`, valid (was `authorship_undetermined`).
- `v_when_gap_member` → `v_when_role_member_absent`: the same statement and
  verdict; `retirement`'s `custodian` role is now by the member `custodian`,
  which the payload does not carry. New `v_when_role_member_named`: the payload
  names the signer as `custodian`, `valid:role:custodian`.

## What changed from v1

Eric's ruling on the clean mesh (CIRISConstitution rc20 0c9e17c): "Nothing
carries, clean mesh … a wire break … nodes will need to upgrade". No row of
edition 2 names an object of the earlier form, and a node refuses an object of
the earlier form (CC 2.6.1.3, 2.6.1.12); the CDDL's `row-ref` is
`[edition: 2, id: hash-digest]`. CIRISPersist replayed v1 (verify 23.1.3) and
found three disagreements with CC, each confirmed against the rc20 text:

1. **`names_earlier_form`** was valid in v1. It names five earlier-form objects
   by edition-1 row-refs `[1, [-16, name]]`. v2 carries the same statement byte
   for byte under `refusals`, expecting `invalid:malformed:also` (the first
   `refs` member the reader meets in deterministic order); the new
   `row_ref_edition_1` refuses a lone edition-1 `target` as
   `invalid:malformed:target`. The `earlier_form` section (the earlier-form
   names of four families) is gone with `edition2::earlier`.
2. **`after_valid_until`** was `invalid:key_not_valid`. CC 2.4.1.1: "a row whose
   signed instant no held record of its key covers is retryable". v2 expects
   `waiting:covering_record:<kid>:<at_ms>` (`MissingKey::CoveringRecord`): a
   newer record of the key is what is missing. A record that breaks the end rule
   stays Invalid (`record_breaks_end_rule`).
3. **`held_in_part`** (a key whose ML-DSA half is known only by commitment,
   `waiting:mldsa_half:…`) is removed with `MissingKey::MlDsaHalf` and
   `KeyRecordDirectory::insert_partial`: under the clean mesh a key held in
   part is simply Waiting on its edition-2 record.

Also, so that every valid statement is valid under CC's vendored model:
`counted_with_refs` moves from `key:record` (authored in CC's model) to
`group:roster` (counted), and `second_voice` becomes the second voice of that
counted row instead of a second signer of `authored_score`'s authored payload
(on `evidence:*` CC names no second-signer role, so that voice was
`iss_not_in_role` at the family level). Every case now states its `level`, and
family cases their `model`. Every other case is regenerated with the same
statement bytes and verdict.

v1 history: the 23.0.0 release shipped it with the first eight
`family_vendored` cases; 23.1.0 added cases and reworded one description.

## The key of `iss`

`key_of_iss_v1.json` holds 23 cases of the key check in CC 2.6.1's
verification order (rc20, CC 2.6.1.8 steps 6 to 8): a row statement's signing
key must be a key of its CWT `iss`, the key `iss` names or one reached from it
by rotation records (CC 2.6.1.7, CC 2.4.1.1, CC 3.1.3); otherwise
`kid_not_of_iss`. Each case states its directory (`raw` keys, or `records`
inserted in order into a key-record directory), its level and its outcome.
`tests/edition2_key_of_iss_vectors.rs` replays it. `gen_key_of_iss.py` wrote it
with the same independent encoder and signers:

    python3 -I gen_key_of_iss.py > key_of_iss_v1.json

`key_of_iss_v3.json` is v2 with an occurrence key's proof of possession signed as itself (CIRISConstitution
rc21 90d537b: way (a), `iss` the occurrence key, since it is not yet an occurrence; CC 3.3.6, 3.3.6.4),
plus `possession_signed_as_identity` (v2's form, which waits on the key's own voice). 32 cases.
`tests/edition2_key_of_iss_vectors_v3.rs` replays it; `gen_key_of_iss_v3.py` wrote it:

    python3 -I gen_key_of_iss_v3.py > key_of_iss_v3.json

`key_of_iss_v2.json` (no longer replayed) holds 31 cases of step 8 as CIRISConstitution v1.0-rc21-wire states it, and
of step 4's end rule: the four ways a key is a key of `iss` ((a) the thumbprint inside `iss`,
(b) a rotation chain, (c) a key the bundle in force seats, (d) an admitted `identity:occurrence`),
Waiting on what is not held (a named record, a voice a rotation or an occurrence lacks, the bundle
in force), half-open coverage `[asserted_at, valid_until)`, `valid_until_not_after_asserted_at`,
the guard that never binds a machine's key under a person's identity, eviction, and
`location_proof` authored by its subject alone. Each case states its directory: key records,
admitted occurrences, evictions, the bundle in force's seats (`[issuer seed, seated key seed]`) and
a pending bundle. `gen_key_of_iss_v2.py`
(the v1 generator's helpers, copied; independent of verify) wrote it:

    python3 -I gen_key_of_iss_v2.py > key_of_iss_v2.json

`key_of_iss_model.tsv` is the expected output of CIRISConstitution's KeyOfIss model
(`formal/key_of_iss`, TLA+ and its Python twin); `tests/edition2_key_of_iss_model.rs` signs each
of its chain world's statement groups and compares `KeyRecordDirectory::key_of` with every row,
in two arrival orders.
