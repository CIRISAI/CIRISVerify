# Stream DEK known answers

`stream_dek_vectors.json` is the CC 5.1 (rc19) known-answer set for the
per-stream call DEK under the MLS group exporter (CIRISVerify#308):

```
DEK(stream_id, epoch) = HKDF-SHA256(ikm  = MLS-Exporter("ciris-stream-dek/v1", "", 32),
                                    salt = "",
                                    info = b"ciris-stream-dek/v1" ‖ stream_id_utf8 ‖ epoch_be8,
                                    len  = 32)
```

Each `valid` case gives the exporter secret (the MLS exporter output; the MLS
step is the caller's), the `stream_id` (`av-` + 64 lowercase hex), the epoch,
the HKDF `info` in hex and the DEK in hex. The cases cover epoch 0, a rolled
epoch, two streams in one epoch, the CC 5.3.3.7 known-answer stream id, a
second exporter secret and epoch `u64::MAX`. Each `refusals` case is a
`stream_id` that must be refused: a bare 64-hex id (persist's inline-blob log
id, CIRISPersist#953), upper-case hex, 63 and 65 digits, a non-hex digit, a
wrong prefix, the empty string and the prefix alone.

## How the file was made

The values were computed without the Rust code, by a short Python script run
with `python3 -I`: a from-scratch RFC 5869 HKDF (extract and expand written out
over the standard library's `hmac` and `hashlib`), self-checked against RFC 5869
test cases A.1 and A.3 before any vector was emitted. The script's output was
written here with sorted keys. `tests/stream_dek_vectors.rs` recomputes every
case with `ciris_crypto::stream_dek` and fails on any difference.
