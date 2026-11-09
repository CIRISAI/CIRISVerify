# FedCode golden vectors

`fedcode_vectors.json` is the reference set for the CIRIS federation identity
code: CC 2.6.8 (`key_id` — FedCode) as implemented by
`ciris_verify_core::fedcode`, the reference codec FSD-003 names. CIRISClient
(the Kotlin port in common code), CIRISAgent and CIRISServer each carry their
own decoder and pin this file in their decoder tests; nothing in Verify is
called by them, they read the JSON.

## What the file holds

Every pubkey is ed25519-dalek's verifying key for a 32-byte seed of one
repeated byte (owner `alice` is seed `0x01`, the agent `0x02`, the node `0x03`,
the family `0x04`, the community `0x05`; node `i` has federation seed
`0x40 + i` and transport seed `0x80 + i`). The ML-DSA-65 public key is a
1952-byte stand-in (byte `i` = `i mod 251`); the PQC commitment carried by every
vector is its sha256, so a port that cannot mint ML-DSA keys still reproduces
it.

| Section | Contents |
|---|---|
| `wire` | The constants a port needs: CRC, base32, prefixes, kind bytes, hint encoding, v3 tail, limits, `key_id` shape. |
| `valid` | Twenty-four codes. Each carries the encoder input (or `construction` for the hand-built v1 and pre-commitment v3 codes), the payload bytes before base32 (hex), the CRC-16-CCITT, the dashed display code, the undashed QR code and the decoded value. Covers v1; v2 for the five kinds with and without hints; v3 with nodes, commitment only (`node_count = 0`) for every kind, both; the 16-node bound; the 1,024-byte payload edge; the empty tail encoding as v2 byte for byte (`identical_to`). |
| `refusals` | Forty-one inputs that must be refused, each with `stage` (`encode` or `decode`), the input, the CC constraint and the expected error kind (`Malformed`, `InvalidVersion`, or `ChecksumMismatch` with the declared and computed CRC). Covers bad commitment hex (upper-case, short, long, non-hex, empty), 17 nodes, 1,025 bytes (at the encoder and the decoder), a transport key equal to the owner's pubkey, nodes on a non-user kind, over-long fields, CRC mismatch, unknown prefix, garbage and truncated bodies, unknown version and kind bytes, a bad commitment tag, a truncated commitment, non-UTF-8 and over-declared fields, a `sha256(key_id)` that does not match the display `key_id` (zeroed, or the id swapped), and a v2 payload missing its `group_key_id` hint byte. |
| `normalisation` | Eighteen renderings (dashed, undashed, lower-case, undashed prefix, whitespace in and around the code) that decode to the same value as a named `valid` vector. |
| `consumer_cases` | The v2-only decoder's refusal of `CIRIS-V3-` before any payload byte (CC 2.6.8 constraint 5). The crate exposes no v2-only path, so the inputs are given for the consumer's own test. |
| `admission` | `AdmittedHybridKey::admit` against the stand-in: a matching pull admitted, a one-bit substitution refused, a code without a commitment refused. |
| `known_disagreements` | Where the shipped codec departs from CC 2.6.8. Empty (see below). |

## Known disagreements

The section is kept, with an empty `cases` array, so a consumer's loader
does not change shape. Version 22.1.0 recorded four departures there; all four
were fixed in CIRISVerify#331 and their inputs moved:

- `sha256(key_id)` is verified on decode (constant time): `dec_key_id_hash_zeroed`
  and `dec_key_id_swapped` in `refusals`.
- The 1,024-byte payload bound binds the decoder: `dec_payload_1025`.
- A non-user code carrying only the PQC commitment reads back: the
  `v3_{agent,node,family,community}_commitment_only` codes in `valid`. A
  non-user v3 code is refused only when `node_count > 0`.
- A v2 payload missing its `group_key_id` hint byte is refused:
  `dec_v2_missing_group_hint`.

## Regenerating

The test `tests/fedcode_vectors.rs` rebuilds the file in memory on every run
and fails if the committed file differs. To regenerate after a deliberate
codec change:

```sh
CIRIS_FEDCODE_VECTORS_REGENERATE=1 cargo test -p ciris-verify-core --test fedcode_vectors
```

Keys are sorted, indentation is two spaces, one trailing newline. The CRC and
base32 in the test are reimplemented rather than borrowed from the crate, so
the payload bytes the file carries are an independent reading of the codec's
output.

Issues: CIRISVerify#329, CIRISVerify#331.
