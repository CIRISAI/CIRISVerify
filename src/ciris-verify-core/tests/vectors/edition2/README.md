# Edition-2 row statement known answers

`row_statements_v2.json` holds CC 2.6.1 row statements (CIRISConstitution rc20
0c9e17c, the clean mesh; `manifests/signed_object_v2.cddl`) for
CIRISVerify#326. `tests/edition2_row_vectors_v2.rs` replays it. It supersedes
`row_statements_v1.json`, which stays beside it byte for byte for the readers
that pinned it (see [What changed from v1](#what-changed-from-v1)); v1 is no
longer replayed.

`gen_row_statements_v2.py` wrote v2 (and `gen_row_statements.py` v1) without
verify's code. It has its own CBOR deterministic encoder (RFC 8949 §4.2.1,
bytewise key order) and signs with the composite ML-DSA-65-Ed25519 through
dilithium-py (FIPS 204, deterministic variant, the label as the ML-DSA context)
and pyca/cryptography (Ed25519):

    pip install dilithium-py cryptography
    python3 -I gen_row_statements_v2.py > row_statements_v2.json
    python3 -I gen_row_statements.py > row_statements_v1.json   # unchanged

Key `n` is ML-DSA-65 seed `[n]*32` and Ed25519 seed `[n+100]*32`; its `kid` is the
RFC 9679 thumbprint of `{1: 7, 3: -70100, -1: pub}` and its `iss` the identity
reference of that thumbprint.

## Levels

Every v2 case states the `level` it is read at:

- `statement`: `edition2::verify_row_statement`, no family model (`valid`,
  `refusals`; `key_directory` through a `KeyRecordDirectory`);
- `family`: `edition2::family::verify_row_in_family` under the model the case
  names in `model`: `test` (the stated `family_model`) or `vendored`
  (`VendoredFamilyModel`, CC's `family_authorship.json`);
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
  roles under CC's own cells (`manifests/family_authorship.json`, rc20
  e08bf05), read by CC's one selector evaluator (`tools/cc_family_select.py`):
  the leaf is the row's dimension bound under its family, and `verb` /
  `identity` / `group` / `seats` / `act` come from the case's optional `ctx`
  (absent: unknown). The expectations are stated from that evaluator's
  answers: a leaf or a caller key that decides, an unknown arm before the
  decider (`authorship_undetermined`), a false test beside an unsupplied one,
  `when`-conditioned roles that hold, do not hold or are unknown, a `gap`
  member, and `owner_of_sub` never read from the payload. A row's dimension
  must resolve to its own header family, so `accord:*` (a closed family no
  dimension resolves to cleanly) is reached only without a dimension, where its
  first arm is unknown.

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
