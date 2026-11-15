# Stream DEK known answers

`stream_dek_vectors.json` is the CC 5.1 (rc19) known-answer set for the
per-stream call DEK under the MLS group exporter (CIRISVerify#308):

```
DEK(stream_id, epoch) = HKDF-SHA256(ikm  = MLS-Exporter("ciris-stream-dek/v1", "", 32),
                                    salt = "",
                                    info = b"ciris-stream-dek/v1" ‖ stream_id_utf8 ‖ epoch_be8,
                                    len  = 32)
```

## The stream id

The **normative** `stream_id` is the lowercase hex of the 32-byte stream-id
digest: 64 lowercase hex characters, one rule for every stream kind, A/V and
data streams (CC 5.3.3.2) alike (CC 5.3.3.1). CIRISEdge currently spells A/V
stream ids `av-{64 lowercase hex}`. That is a recorded divergence, but the
string is a KDF input both ends must agree on, so verify accepts it for
compatibility. The two spellings of one digest derive different DEKs.

## Cases

Each `valid` case gives the exporter secret (the MLS exporter output; the MLS
step is the caller's), the `stream_id`, the epoch, the HKDF `info` in hex and
the DEK in hex.

- Edge's `av-` form: epoch 0, a rolled epoch, two streams in one epoch, the
  CC 5.3.3.5 known-answer stream id, a second exporter secret and epoch
  `u64::MAX`.
- The normative bare form: the CC 5.3.3.5 known-answer stream id, the bare
  spelling of `epoch_zero`'s digest (a different DEK from the `av-` spelling),
  and a data stream at two epochs.

Each `refusals` case is a `stream_id` that must be refused: upper-case hex,
63 and 65 digits and a non-hex digit (each with and without `av-`), `AV-`,
another prefix, the empty string and the prefix alone.

## How the file was made

The values were computed without the Rust code, by a short Python script run
with `python3 -I`: a from-scratch RFC 5869 HKDF (extract and expand written out
over the standard library's `hmac` and `hashlib`), self-checked against RFC 5869
test cases A.1 and A.3 before any vector was emitted. The script's output was
written here with sorted keys. `tests/stream_dek_vectors.rs` recomputes every
case with `ciris_crypto::stream_dek` and fails on any difference.
