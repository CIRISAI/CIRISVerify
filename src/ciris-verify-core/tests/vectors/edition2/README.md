# Edition-2 row statement known answers

`row_statements_v1.json` holds CC 2.6.1 row statements (CIRISConstitution rc20
09907aa, `manifests/signed_object_v2.cddl`) for CIRISVerify#326.

`gen_row_statements.py` wrote it without verify's code. It has its own CBOR
deterministic encoder (RFC 8949 §4.2.1, bytewise key order) and signs with the
composite ML-DSA-65-Ed25519 through dilithium-py (FIPS 204, deterministic
variant, the label as the ML-DSA context) and pyca/cryptography (Ed25519):

    pip install dilithium-py cryptography
    python3 -I gen_row_statements.py > row_statements_v1.json

Key `n` is ML-DSA-65 seed `[n]*32` and Ed25519 seed `[n+100]*32`; its `kid` is the
RFC 9679 thumbprint of `{1: 7, 3: -70100, -1: pub}` and its `iss` the identity
reference of that thumbprint.

Sections (rc20, CIRISConstitution 09907aa; the namespace registry vendored at
`data/cc/namespace_registry.json`):

- `valid`: five statements, each with its `kid`, `iss`, row id and statement id,
  re-minted byte for byte by `edition2::sign_row_statement`. They are an authored
  scores row, the same payload under a second voice, a counted row with `refs`, a
  salt, `nbf`/`exp` and both redaction forms, a row with disclosures (digests
  stated), and a row naming earlier-form objects.
- `refusals`: statements with the verdict each must get (`waiting:kid:<kid>`, or
  `invalid:<reason>[:<member>]`). They cover the composite, deterministic
  encoding, headers and CWT claims, time claims, `refs` sets and tuples, values
  and fixed6 ranges, disclosures, and dimension → family through CC's one
  matcher (CC 3.1.7).
- `earlier_form`: the earlier-form name of each of the four families (accord
  invocation, key record, build-manifest contribution, genesis bundle), with the
  JSON input, the signed message and the name.
- `key_records`: the CC 2.4.1.1 end rule over key-record payloads, with
  refusal tokens.
- `key_directory`: key resolution through key-record rows: a held chain, Waiting
  on the deepest missing key, a key held in part (ML-DSA half by commitment),
  a record that breaks the end rule, and a statement after `valid_until`.
- `family_model` + `family`: the author column and second-consent roles under a
  stated test model. CC's typed `authorship` / `second_signers` columns are
  pending in rc20; until they land, the model is caller-supplied.
- `objects`: non-row object headers (no `cty`, never -70001/-70002, closed
  `typ`), with the object id. Payload rules come with the ceremony set.
- `references`: values typed by form (`[-16, digest]` a row, an identity
  reference a key), for CIRISKernel's `Obj::from_reference`.
