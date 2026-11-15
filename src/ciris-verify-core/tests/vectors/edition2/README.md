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

- `valid`: three statements (an authored scores row, the same payload under a
  second voice, a counted row with `refs`, a salt, `nbf`/`exp` and both SD-CWT
  redaction forms), each with its `kid`, `iss`, row id and statement id.
  `tests/edition2_row_vectors.rs` verifies them and re-mints each with
  `edition2::sign_row_statement`, which must give the same bytes.
- `refusals`: 23 statements with the verdict each must get (`waiting`, or
  `invalid:<reason>[:<member>]`), including an ML-DSA half signed under the
  empty FIPS 204 context, non-deterministic encodings, header and claim faults,
  time disagreements, `refs` set and role faults, and value faults.
