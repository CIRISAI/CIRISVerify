# Accord lineage vector

`accord_lineage_v1.json` is CIRISPersist's cross-implementation vector for the
accord roster lineage (CC 3.2 T6, annex 8.11). It is vendored byte for byte from
CIRISPersist, branch `vec-accord-lineage`, commit `e943482e`
(`tests/vectors/accord_lineage/accord_lineage_v1.json`, produced by
`src/federation/accord_lineage_vector.rs`). Do not edit it here; regenerate it
in persist and copy it over.

**The vector is synthetic.** Every key is a deterministic test signer (seed =
the key id's bytes over a `[0x11; 32]` overlay) and every instant is fixed.
Nothing in it comes from the baked HUMANITY_ACCORD genesis.

## What it holds

Three versions of one family record, each admitted by persist's real doors
(v1 genesis, v2 a roster change, v3 a holder recovery). Each version carries
the offered and stored family record, the `canonical_bytes` (`utf8` and `hex`)
its `persist_row_hash` hashes, the hash and its `prev_head_digest`.
`canonicalizer_rules` holds the canonicalizer probes (non-ASCII, non-BMP,
escapes, key order, floats, integer extremes) and the instant truncations.

## What pins it

`tests/persist_canonical_vectors.rs` reproduces every `canonical_bytes` byte
for byte through `ciris_verify_core::persist_canonical` from the raw stored and
offered records, every `persist_row_hash` and `prev_head_digest` link, every
probe and every instant truncation.

Verify no longer rebuilds or verifies the roster change and recovery the file
carries: the earlier-form live-quorum module (`accord_live_quorum`), its v2
vector and its recovery refusal vectors were removed in 23.3.3. The file is
kept, unchanged, as the cross-implementation pin of `persist_row_hash`.
