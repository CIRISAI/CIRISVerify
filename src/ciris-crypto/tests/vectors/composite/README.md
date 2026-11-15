# Composite ML-DSA-65 with Ed25519 known answers

`mldsa65_ed25519_draft_kats.json` holds the drafts' own vectors for the
CC 2.6.1.7 composite (CIRISVerify#326). Nothing in it was produced by verify.

- `lamps_19`: draft-ietf-lamps-pq-composite-sigs-19 Appendix E, tcId
  `id-MLDSA65-Ed25519-SHA512`: `pk`, `sk` (`mldsaSeed || ed25519Seed`), `s` over
  `m` with an empty context, `sWithContext` over `m` with the draft's context.
- `jose_06`: draft-ietf-jose-pq-composite-sigs-06 Figure 12: the two zero seeds,
  the AKP public key, the COSE_Sign1 payload, the message representative `M'`
  and the signature. The figure's `alg` is `-59`, a requested value (the draft's
  IANA table says TBD); CIRIS carries `-70100` until a value is assigned.

`extract.py` reads the two draft texts (from ietf.org/archive/id) and writes the
file:

    python3 -I extract.py draft-ietf-lamps-pq-composite-sigs-19.txt \
        draft-ietf-jose-pq-composite-sigs-06.txt > mldsa65_ed25519_draft_kats.json

`check.py` verifies every vector without verify's code, using dilithium-py
(FIPS 204) and pyca/cryptography (Ed25519). It rebuilds both public keys from
the seeds, rebuilds JOSE's `M'` from a hand-encoded Sig_structure, and confirms
that the ML-DSA half verifies only under the label as its FIPS 204 context,
never under the empty one:

    pip install dilithium-py cryptography
    python3 check.py mldsa65_ed25519_draft_kats.json

`tests/composite_vectors.rs` runs the same checks against `ciris_crypto::composite`.
In COSE the application context is always empty (JOSE -06 §2), so the LAMPS
`sWithContext` signature is expected to be refused.
