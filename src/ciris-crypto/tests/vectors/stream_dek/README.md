# Stream DEK known answers

`stream_dek_vectors.json` is the CC 5.1 known-answer set for the
per-stream call DEK under the MLS group exporter (CIRISVerify#308):

```
DEK(stream_id, epoch) = HKDF-SHA256(ikm  = MLS-Exporter("ciris-stream-dek/v1", "", 32),
                                    salt = "",
                                    info = b"ciris-stream-dek/v1" ‖ stream_id_utf8 ‖ epoch_be8,
                                    len  = 32)
```

## The stream id

`stream_id` is `av-` followed by the lowercase hex of the 32-byte stream id,
67 characters (rc20 CC 5.3.3.1): the spelling CIRISEdge and the store use.
Bare 64-hex is the store's inline-blob log id (CIRISPersist#953), not a stream
id. From 23.0.0 that is the only spelling accepted (a hard cut).

## Cases

Each `valid` case gives the exporter secret (the MLS exporter output; the MLS
step is the caller's), the `stream_id`, the epoch, the HKDF `info` in hex and
the DEK in hex: epoch 0, a rolled epoch, two streams in one epoch, the
CC 5.3.3.5 known-answer stream id, a second exporter secret, epoch `u64::MAX`,
and a third stream at two epochs. The cases kept from before 23.0.0 have
unchanged bytes.

Each `refusals` case is a `stream_id` that must be refused: bare hex (two
digests), bare upper-case hex, `av` with no hyphen, `AV-`, another prefix,
upper-case hex, 63 and 65 digits and a non-hex digit after `av-`, the empty
string and the prefix alone.

## How the file was made

The values were computed without the Rust code, by a short Python script run
with `python3 -I`: a from-scratch RFC 5869 HKDF (extract and expand written out
over the standard library's `hmac` and `hashlib`), self-checked against RFC 5869
test cases A.1 and A.3 before any vector was emitted. The script's output was
written here with sorted keys. `tests/stream_dek_vectors.rs` recomputes every
case with `ciris_crypto::stream_dek` and fails on any difference.
