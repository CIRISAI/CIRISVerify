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

## StreamKeyBinding v2

`stream_key_binding_v2_composite_v2.json` (SHA-256
`4668ef04c3a2c718334c4a6f2ffc5d7f581608a20cf42cf23971f4b7140263eb`) comes from
`gen_stream_key_binding_v2_composite_v2.py` and follows CC 1.0-rc21 5.3.3.5
(815050d, 544755a). The binding layout and its signing label `av-stream-key:v2`
are unchanged. Two things change from the first set:

- `stream_id` is `SHA-256("ciris-edge:call-stream:v3" ‖ u16be len ‖ room ‖ u16be len ‖ publisher ‖ join_nonce[32])`.
- The publisher is a member key (`member-kat-a`), never a node key.

`stream_ids` adds known answers for the derivation alone. Among them,
`split_ab_c` and `split_a_bc` show the case that motivated the change: under
v2's bare concatenation those two inputs gave the same id. The file is replayed
by `stream_key_binding_v2_composite` against `stream_seal::call_stream_id`.

`stream_key_binding_v2_composite_v1.json` and `gen_stream_key_binding_v2.py`
are the first set (v2 stream id, node publisher). They are kept byte-identical
and are no longer replayed. Regenerate either file with dilithium-py and
pyca/cryptography:

    python3 -I gen_stream_key_binding_v2_composite_v2.py > stream_key_binding_v2_composite_v2.json
