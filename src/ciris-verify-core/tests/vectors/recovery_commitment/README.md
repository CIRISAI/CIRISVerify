# The recovery commitment

`recovery_commitment_v1.json` holds known answers for the recovery commitment of CC 3.2
T3 and CC 4.2.6 (rc20; `recovery-commitment-input` in `manifests/signed_object_v2.cddl`):

    commitment = [-16, SHA-256( CDE( ["CEG-recovery/2", keys] ) )]

`keys` is a set of `ceg-key` (`{1: 7, 3: -70100, -1: <1984-byte composite pub>}`), sorted
by the bytewise order of each key's deterministic encoding, with no duplicate (CC
2.6.1.2). A per-holder commitment has one key. The keys are the composite keys of the
accord-halt KAT roster in `../accord_halt`. Their seeds (ML-DSA-65 xi / Ed25519) are
`a1`/`1a` for A1, `b1`/`1b` for B1 and `c1`/`1c` for C1, each repeated 32 times.

| id | Input | Digest |
|---|---|---|
| `one_key` | A1 | `8cd895ee…4d9397` |
| `one_key_b1` | B1 | `a6d600fc…f9eddb` |
| `one_key_c1` | C1 | `85b5db86…ba129d` |
| `three_keys_unsorted` | C1, B1, A1 | `a833cec3…c9559b` |
| `three_keys_other_order` | B1, C1, A1 | `a833cec3…c9559b` |
| `duplicate_key` | A1, A1 | `8cd895ee…4d9397` (the same as `one_key`) |

Each case gives the input keys in order, the set order, the CDE preimage (`cde_hex`),
the digest, and the carried `[-16, digest]` (`commitment_cde_hex`).

`edition2::recovery::recovery_commitment` takes its keys as a set: it sorts them by
encoding and drops duplicates. A received commitment's preimage is not re-encoded by a
reader, so the duplicate case pins the producer's answer only.

## Regenerate

`gen_recovery_commitment.py` uses its own CBOR encoder over dilithium-py and
pyca/cryptography, sharing no code with verify:

    pip install dilithium-py cryptography
    python3 -I gen_recovery_commitment.py > recovery_commitment_v1.json

The test `edition2::recovery::tests::replays_known_answers` replays every case.
