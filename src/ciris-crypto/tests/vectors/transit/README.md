# CTKX v2 link-handshake known answers

`transit_ctkx_v2_v1.json` is the known-answer set for the CC 5.3.3.10 mutual
X-Wing link handshake, `CTKX` v2, suite `transit_xwing_hkdf_sha256`
(CIRISEdge#1007). The wire is `docs/TRANSIT_HANDSHAKE_V2.md`;
`tests/transit_vectors.rs` re-runs every case through `ciris_crypto::transit`.

## How the file was made

`gen.py` writes it. The script was written from the doc, not from the Rust,
and assembles every primitive itself:

- **X-Wing, draft-connolly-cfrg-xwing-kem-11.** Key generation from the 32-byte
  seed by `SHAKE256(seed, 96)`, ML-KEM-768 `KeyGen_internal(d, z)` on the first
  64 bytes and X25519 on the last 32. Encapsulation from the 64-byte `eseed`:
  ML-KEM `Encaps_internal(m = eseed[0:32])` and the X25519 ephemeral
  `eseed[32:64]`. The combiner `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")`.
  ML-KEM is kyber-py's FIPS 203 internal (deterministic) functions; X25519 is
  pyca/cryptography; SHA3 and SHAKE are `hashlib`.
- **HKDF-SHA256** (RFC 5869) written out over the standard library's `hmac`.
- **HMAC-SHA256** from the standard library; **AES-256-GCM** from
  pyca/cryptography.

**Self-check, before anything is generated.** The script asserts its X-Wing
against every case of `../xwing/draft-connolly-cfrg-xwing-kem-11.json` (seed →
pk, eseed → ct and ss, decapsulation; 3 of 3), and its HKDF against RFC 5869
A.1 and A.3. A failure aborts the run. Each refusal below is also raised by the
Python implementation with the recorded code before it is written.

Run it from the repository root, in a venv with `kyber-py` (1.2.0) and
`cryptography`:

```
python3 -I src/ciris-crypto/tests/vectors/transit/gen.py
```

## Inputs

Every input is fixed and recorded: the 16-byte `link_id`, the two key ids, each
X-Wing static seed (`SHA-256("ctkx-v2-kat/" ‖ label)`), the ephemeral seed, and
each 64-byte encapsulation randomness (`SHAKE256("ctkx-v2-kat/" ‖ label, 64)`).
Static secrets enter the Rust only through the decapsulation closures, as the
vault's `seal.xwing-decap` would.

## Cases

- **`handshakes`** (3): `mutual`; `first_contact_no_static` (`has_static = 0`,
  a client-only initiator); `first_contact_unbound_static` (`has_static = 1`, the
  responder lacks the binding). Each records `msg1`, `msg2`, `CTKC`, `k_i2r`,
  `k_r2i`, `k_conf`, and the intermediates `h0`, `h1`, `k_id`, `id_block`, `h2`,
  `h3` and `bound`.
- **`promotions`** (1): the first-contact link with a static promoted: `msg3`,
  `h3'`, `CTKC'` and the new keys.
- **`framing`** (2): the mutual `msg1` and `msg2` in `CTKX` v2 parts at a
  400-byte part limit (headers included).
- **`refusals`** (38), each with the error code `TransitError::code` returns:
  a wrong suite, the v1 suite string, a wrong message type, truncated `msg1`
  and `msg2`, trailing bytes on both, a tampered `id_ct` (body and tag) and
  `ct1`, a wrong and an empty `responder_key_id`, a tampered `confirm_r` and
  `ct2`, unknown `flags`, a mutual `msg2` to an initiator with no static, a
  non-`CTKC` frame, a bad, truncated, over-long and foreign `CTKC`, a promotion
  with a different static, a promotion of a mutual link, the old `CTKC` offered
  as `CTKC'`, truncated and over-long `msg3`, and the framing refusals (`CTKX`
  0x01 and 0x03, bad magic, unknown part kind, `total_len` over 8 KiB, a
  continuation first, a missing part, an overrun).

The refusal codes are verify's names for the doc's refusals; the order in which
a message is checked (parse, then key ids, then the decapsulation and `id_ct`)
is the one both implementations share.

## Note on sizes

`msg2` is 1,154 bytes at first contact and 2,274 bytes mutual
(`1 + 1 + 1120 [+ 1120] + 32`). The doc's prose figures (1,155 and 2,275) are
one byte over its own layout; the layout governs.

## The per-frame seal, v0x02 with key phases

`transit_seal_frame_v2_v1.json` is the known-answer set for the CC 5.3.3.10 E1
per-frame link seal, frame version 0x02 with key phases (the doc's "The
per-frame seal is seal frame version 0x02, with key phases" and "Key phases"):

```
frame = 0x02 ‖ phase u8 ‖ counter u64_be ‖ AES-256-GCM(k, nonce, aad, pt) ‖ tag[16]
k     = HKDF-SHA256(ikm = k_dir(phase), salt = link_id[16], info = "CIRIS-E1-LINK-SEAL-V2")
nonce = lane u8 ‖ 0x000000 ‖ counter u64_be
aad   = 0x02 ‖ lane u8 ‖ phase u8 ‖ link_id[16]
```

`gen.py` writes it in the same run, with pyca/cryptography's AES-GCM and its
own HKDF, and runs every sequence through its own receiver model before
writing it. `tests/transit_seal_frame_vectors.rs` replays each sequence
through `ciris_crypto::transit::{seal_frame, FrameOpener}`.

**Inputs chain to `transit_ctkx_v2_v1.json`.** The `link_id` and phase 0's
`k_i2r` / `k_r2i` are the `first_contact_unbound_static` handshake's, and phase
1's are its `promotion`'s `k_i2r'` / `k_r2i'`; the Rust test checks both
files agree. Phase 0's first Channel frame carries that handshake's `CTKC`,
and phase 1's carries `CTKC'`. `seal_keys` records the four derived `k`.

**A sequence** names its receiver (`responder` opens `k_i2r` frames,
`initiator` opens `k_r2i` frames) and lists operations in order: `open` (a
lane and a frame), `promote` and `retire_phase0` (the handshake budget after
a promotion has run out). Each `open` records the frame's seal inputs
(`phase`, `counter`, `plaintext`, and `key_phase` when the key is not the
named phase's) and any `tamper` applied after sealing (`xor`, `set`,
`truncate_to`), so every frame but the v1 one is rebuilt and compared byte for
byte. Outcomes are `plaintext`, `dropped_stale`, `dropped_replay`, `ok`, or
`close` with the `FrameError::code`; a `close` ends its sequence. Each
sequence also records its final `seal_stale_phase` and `seal_dropped_replay`
counts.

**Receiver rules the vectors fix:**

- classification by the clear header, in order: an empty frame or one
  shorter than header plus tag is `seal_truncated` (after the version check,
  so v1 is refused by name: `seal_v1_refused`; other versions
  `seal_version_unsupported`); phase 2 or more is `seal_unknown_phase`;
  phase 1 before promotion is `seal_phase_before_promotion`; phase 0 on a lane
  whose phase-0 keys are retired is `dropped_stale`, unopened;
- a held phase that fails AEAD is `seal_open_failed`;
- phase 0 is retired on a lane once a phase-1 frame on it opens (even one the
  window then drops), and on every lane by `retire_phase0`, which does nothing
  before a promotion; a second promotion is `seal_already_promoted`;
- **the replay window is v1's** (edge's `link_seal.rs`): the AEAD opens first,
  then a counter repeated inside the lane's 128-frame window, or 128 or more
  behind its highest, is `dropped_replay` and the link stays open. The window
  moves only for frames that opened and is shared by both phases.

**Sequences** (25): phase 0 in each direction; promotion in each direction;
stale phase 0 after phase 1 is seen, before it is seen, and after retirement;
`retire_phase0` before promotion; phases 2 and 255; phase 1 before promotion;
tampered ciphertext, tag and counter; the phase byte flipped 0→1 and 1→0;
a frame on the wrong lane; a v1 frame, version 0x03, a truncated and an empty
frame; a repeated counter, a too-old counter, a counter reused across the
phase change; a second promotion.
