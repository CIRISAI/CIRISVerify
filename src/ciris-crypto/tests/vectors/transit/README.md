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
