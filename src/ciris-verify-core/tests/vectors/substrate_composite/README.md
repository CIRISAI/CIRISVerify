# Composite signatures over the CC Part 6 preimages

`composite_signatures_v1.json` holds, for each §19 / §19.7 golden preimage (the
`expected_canonical_bytes_hex` of the vectors in `../substrate_v19` and
`../substrate_v19_7`, unchanged by 23.0.0), a composite ML-DSA-65-Ed25519
signature (CC 2.6.1.7) by one stated key, plus four refusals:
- a flipped byte in the ML-DSA region;
- a flipped byte in the Ed25519 region;
- a signature by another key;
- a truncated signature.

`gen.py` wrote it without verify's code (dilithium-py deterministic, pyca/cryptography):

    pip install dilithium-py cryptography
    python3 -I gen.py ../substrate_v19 ../substrate_v19_7 > composite_signatures_v1.json

`tests/substrate_composite_vectors.rs` checks every case against `substrate::verify_composite`.
