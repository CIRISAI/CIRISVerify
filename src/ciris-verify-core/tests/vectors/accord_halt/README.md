# The accord holder's composite signature on an invocation

`accord_halt_composite_v1.json` holds the holder signature of CC 4.2.1.1 (rc20): the
composite ML-DSA-65-Ed25519 of CC 2.6.1.7 (COSE alg -70100) over the invocation's
canonical text preimage, domain prefix included and no trailing newline. That is the
byte string `Invocation::canonical_bytes()` lays out. Each holder seals a halt of this
form before the genesis is published (CIRISConstitution `formal/ceremony/CEREMONY.md`,
step 3), so these bytes are on the genesis's critical path.

## Keys

| Label | ML-DSA-65 seed (xi) | Ed25519 seed | Thumbprint (kid) |
|---|---|---|---|
| A1 | `a1` x 32 | `1a` x 32 | `b7ff500b…e328d5` |
| B1 | `b1` x 32 | `1b` x 32 | `1da5ba6f…7a34c2` |
| C1 | `c1` x 32 | `1c` x 32 | `04f9d53b…7ea8c0` |
| outsider | `d1` x 32 | `1d` x 32 | `3af5d825…9bb79a` |

A1, B1 and C1 are the seed roster of three. The outsider is not on it. The same keys are
used by `../recovery_commitment`.

## Cases

| id | Kind | Signers | SHA-256 of the canonical bytes |
|---|---|---|---|
| `constitutional_halt` | `constitutional`, `halt-2026-11-16` | A1 | `682388ac…62ab23` |
| `lifecycle_confirmed` | `lifecycle:confirmed`, confirms the halt | A1, B1 | `96d042da…4999fd` |
| `lifecycle_active` | `lifecycle:active`, resumes the halt | B1, C1 | `39296fde…b00dff` |

Each case states every invocation field, the payload text that `payload_sha256` hashes,
the canonical text and bytes, and each signature with its SHA-256. ML-DSA-65 signs
deterministically, so verify's own signature is byte-identical to the file's.

## Refusals

- `domain_prefix_removed`: A1 signs the halt's bytes without `ciris.accord_invoke.v2\n`.
- `wrong_holder`: the outsider signs the halt's exact bytes; refused under A1, B1 and C1.
- `mutated_invocation_id`, `mutated_kind_drill`, `mutated_payload_sha256`: A1's genuine
  halt signature, presented with one field changed.
- `signed_sha256_not_text`: A1 signs the 32-byte SHA-256 of the canonical bytes rather
  than the bytes. CC 4.2.1.1 writes `canonical = sha256(...)` and says the composite is
  over `canonical`. Verify signs and verifies the text preimage, as the earlier form
  did, because the composite hashes its message with SHA-512 itself. This case pins
  that reading until CC states which is meant.

Every refused signature verifies over the message it signed (`signed_message_hex`), so
each refusal is caused by the change it names and not by a bad signature.

## Regenerate

`gen_accord_halt_composite.py` lays out the preimage from the CC text and signs with
dilithium-py and pyca/cryptography, sharing no code with verify:

    pip install dilithium-py cryptography
    python3 -I gen_accord_halt_composite.py > accord_halt_composite_v1.json

`tests/accord_halt_composite_vectors.rs` rebuilds each `Invocation` from its fields,
checks the canonical bytes, verifies every signature with
`humanity_accord::verify_invocation_composite`, re-signs it byte-identically, and checks
that each refusal is refused.

## What this does not fix

This file fixes the holder signature only. CC 2.6.1.11 makes an accord invocation a row,
and CC 4.2.1.1 puts the holder signature inside that row. The row's payload members are
not specified in rc20: the member that carries the signature, and how the invocation
fields are typed in CBOR.
