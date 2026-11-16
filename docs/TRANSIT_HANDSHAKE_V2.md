# CC 5.3.3.10 link handshake: proposed wire (`CTKX` v2)

**Status: AGREED and IMPLEMENTED** (`ciris_crypto::transit`, verify 23.1.0), revised after edge's review (`handshake_v2_review.md`). This is verify's half of the joint submission with edge (CIRISEdge#1007). Eric ruled that it lands in the refactor cut. Edge accepted it, and the constitution confirmed its reading of CC 5.3.3.10. It is implemented as `ciris_crypto::transit` (feature `transit`, `no_std`), with known answers at `src/ciris-crypto/tests/vectors/transit/transit_ctkx_v2_v1.json`. It replaces `ciris_crypto::transit_kex` (`CTKX` v1: one message, responder-only, X25519 + ML-KEM under HKDF) as a hard cut.

## What CC 5.3.3.10 requires

- **A KEM-authenticated handshake.** Nobody signs to open a link.
- **The hybrid KEM is X-Wing.** Each node's static is the transit pair its signed binding publishes, minted fresh for this edition.
- **Two messages, one flight:**
  - the initiator sends an ephemeral public key, an encapsulation to the responder's static, and its own identity sealed under the keys so derived;
  - the responder answers with an encapsulation to the initiator's ephemeral, an encapsulation to the initiator's static where it holds the initiator's binding, and a key confirmation.
- **Session keys** derive from every shared secret present.
- **Known initiator:** the handshake is mutual. **Unknown initiator, at first contact:** the encapsulation to its static is omitted. The link is still sealed and forward-secret, and a later encapsulation on the same link promotes it to mutual.
- **Thirteen frames:** it fits one flight of thirteen frames at the Reticulum base size.

## Primitives

- **`XW`:** X-Wing, draft-connolly-cfrg-xwing-kem (draft-11 is identical to draft-06 for decapsulation, checked against edge's `kat_outfox_xwing_v1`), via `ciris_crypto::xwing`. Sizes:
  - public key 1216 bytes (`pk_M ‖ pk_X`);
  - ciphertext 1120 bytes;
  - shared secret 32 bytes.
- **`H`:** SHA-256.
- **`HKDF`:** HKDF-SHA256 (RFC 5869).
- **`MAC`:** HMAC-SHA256.
- **`AEAD`:** AES-256-GCM.
- **Suite identifier:** `transit_xwing_hkdf_sha256` (snake_case under CC 3.3.2's rule).

## Keys

| Key | Holder | Where it lives (FSD/WASM_NODE §8.5, as Eric ruled) |
|---|---|---|
| `S_r`, the responder's static (X-Wing) | responder | vault: `seal.generate(id, transit)`; decapsulation with `seal.xwing-decap` |
| `S_i`, the initiator's static (X-Wing), optional | initiator | vault, likewise; a node publishing no transit pair (a client-only phone) has none |
| `E_i`, the initiator's ephemeral (X-Wing) | initiator | node memory, one per handshake, zeroized when done (the ephemeral session-key class) |

Every encapsulation uses only a public key and runs in the node, drawing its randomness from `random.fill`. The vault does two decapsulations: the responder's of `ct1`, and the initiator's of `ct3`.

## Transcript

The transcript is a running hash, Noise-style, bound to the Reticulum link:

```
h0 = H("ciris-transit/v2" ‖ link_id[16] ‖ pk(S_r))
h1 = H(h0 ‖ pk(E_i) ‖ ct1)
h2 = H(h1 ‖ id_ct)
h3 = H(h2 ‖ flags ‖ ct2 ‖ [ct3])
```

## Message 1, initiator to responder

```
(ct1, ss1) = XW.Encaps(pk(S_r))
k_id       = HKDF(salt = h1, ikm = ss1, info = "ciris-transit/v2/identity", 32)
id_block   = u16 len ‖ initiator_key_id ‖ u8 has_static ‖ [H(pk(S_i))]
id_ct      = AEAD(k_id, nonce = 0^12, aad = h1, id_block)

msg1 = 0x01 ‖ u8 len ‖ "transit_xwing_hkdf_sha256" ‖ u16 len ‖ responder_key_id
            ‖ pk(E_i)[1216] ‖ ct1[1120] ‖ u16 len ‖ id_ct
```

- **`responder_key_id` is in the clear** so the responder can pick which static is meant, for example during a rotation. It names the node being dialled, which the dialler already knows.
- **The initiator's identity is hidden from a passive observer.** It is sealed under `ss1`, which only the holder of `S_r` derives. The responder learns it. Someone who later compromises `S_r` also learns it (the same property as Noise IK), and that is stated.
- **`H(pk(S_i))` commits the initiator to one static.** The responder looks up the initiator's signed binding by `initiator_key_id`, and proceeds as mutual only when the binding's transit pair hashes to this commitment. Otherwise it treats the initiator as unknown.

## Message 2, responder to initiator

```
ss1        = XW.Decaps(S_r, ct1)                      # vault: seal.xwing-decap
id_block   = AEAD-open(k_id, …)                        # refused, the link closes, if it fails
(ct2, ss2) = XW.Encaps(pk(E_i))                        # forward secrecy
(ct3, ss3) = XW.Encaps(pk(S_i))  iff the binding is held and matches  # mutual
flags      = u8, bit 0 = mutual (ct3 present)
prk        = HKDF-Extract(salt = h3, ikm = ss1 ‖ ss2 ‖ [ss3])
k_i2r      = HKDF-Expand(prk, "ciris-transit/v2/initiator-to-responder" ‖ bound, 32)
k_r2i      = HKDF-Expand(prk, "ciris-transit/v2/responder-to-initiator" ‖ bound, 32)
k_conf     = HKDF-Expand(prk, "ciris-transit/v2/confirm" ‖ bound, 32)
confirm_r  = MAC(k_conf, "responder" ‖ h3)

msg2 = 0x02 ‖ flags ‖ ct2[1120] ‖ [ct3[1120]] ‖ confirm_r[32]
```

Here `bound = u8 len ‖ suite ‖ u16 len ‖ initiator_key_id ‖ u16 len ‖ responder_key_id`, as in v1.

**The initiator** decapsulates `ct2` with `E_i` in node memory, and `ct3` with `S_i` in the vault (`seal.xwing-decap`). It derives the same keys, checks `confirm_r` in constant time (closing the link on a mismatch), and then zeroizes `E_i` and the shared secrets.

## Confirmation and authentication

- **The responder is authenticated to the initiator** by `confirm_r`. Only a holder of `S_r` derives `ss1`, and therefore `k_conf`.
- **The initiator is authenticated to the responder,** when mutual, by its first sealed frame. That frame MUST be `"CTKC" ‖ MAC(k_conf, "initiator" ‖ h3)`, sent under `k_i2r`; `CTKC` is mandatory. Only a holder of `S_i` derives `ss3`, so authentication is already implicit in the keys. `CTKC` adds no flight and gives the responder one defined point at which it flips the link's plane.
- **CC's reading (constitution session; a sentence is going into CC 5.3.3.10):** "The responder holds the initiator authenticated from the first sealed frame that opens under the session keys; that frame is the initiator's key confirmation, and it adds no flight."
- **The responder closes the link if the initiator's first sealed frame is anything other than a valid `CTKC`.** That includes a frame that fails to open, a frame of another kind, and a `CTKC` whose MAC does not verify. In first-contact mode the same first frame still carries `CTKC`, computed under keys without `ss3`. It confirms only that the initiator holds `E_i`, not who it is.
- **Even in mutual mode, the responder serves only the first-contact plane until `CTKC` verifies.** Sending `msg2` attributes nothing. This is what defeats a replayed `msg1`: the responder answers it with a fresh `ct2` to `pk(E_i)`, and the replayer, holding no `E_i`, derives neither `ss2` nor the keys. It can produce no frame that opens, and no `CTKC`. Binding `link_id` into `h0` makes a `msg1` from one Reticulum link worthless on any other.
- **The link is attributed when either of these holds:**
  - `CTKC` verifies (mutual), or
  - the link's signed identification verifies under the existing identify-plus-binding path.

  The second path is the only one for an initiator with `has_static = 0`, such as a client-only phone, which can never be promoted.
- **Until the link is attributed it carries the first-contact plane only** (CC 5.4.6):
  - **(a) The self-introduction is admitted.** That is the initiator's own Key, IdentityOccurrence and transport_destination rows, signed by the key `id_ct` committed to. Without this a brand-new node, whose binding no seat yet holds, could never become attributed (CIRISEdge#1004).
  - **(b) A sealed link is never closed merely for lacking attribution.** Frames of other planes are refused by name, and the link stays open, subject to the first-contact limits below.
- **Forward secrecy:** `ss2` comes from an ephemeral the initiator erases, so compromising either static after the fact does not reveal the session keys.
- **Key-compromise impersonation:** an adversary holding `S_r` cannot pose as a mutual initiator to the responder, because it lacks `ss3`. An adversary holding `S_i` cannot pose as the responder, because it lacks `ss1`.
- **Replay:** replaying `msg1` makes the responder draw a fresh `ct2` and `ct3`. The replayer holds no `E_i`, so it derives nothing. `link_id` in `h0` binds the exchange to one Reticulum link.
- **Not given:** full deniability while the link's identification frame remains a signature, as CC states.

## Promotion: an unknown initiator becomes mutual

- **The responder** sends this on the sealed link once it holds the initiator's binding:
  ```
  (ct3', ss3') = XW.Encaps(pk(S_i))
  msg3 = 0x03 ‖ ct3'[1120]
  ```
- **The binding must match msg1's commitment.** The responder promotes only when the binding it now holds has a transit pair whose hash equals msg1's `H(pk(S_i))`. A binding naming any other static is refused for promotion. The link stays at first contact.
- **The rekey:** both ends compute `h3' = H(h3 ‖ "promote" ‖ ct3')` and `prk' = HKDF-Extract(salt = h3', ikm = k_i2r ‖ k_r2i ‖ ss3')`. From `prk'` they derive new `k_i2r'`, `k_r2i'` and `k_conf'` under the same labels as `msg2`, each followed by `bound` (`label ‖ bound`).
- **The confirmation:** the initiator answers with `"CTKC" ‖ MAC(k_conf', "initiator" ‖ h3')` under the new `k_i2r'`. The responder sends no further confirmation: it is already authenticated on this sealed link, and `msg3` travels under its keys. The responder holds the initiator mutually attributed once `CTKC'` verifies. Anything else as the initiator's first frame under the new phase closes the link.
- **Key phases (edge's proposal; the exact frame is under "Framing, sizes, limits" below):** lanes are not ordered relative to one another, so a frame under the old key may arrive after the switch.
  - **Counters continue** across the rekey, so each lane's 128-frame replay window carries over. They do not restart.
  - **Seal frames gain a key-phase byte:** seal frame version 0x02, with the phase also in the AAD.
  - **The receiver keeps the previous phase's open keys** until it has seen the new phase on that lane, or for one handshake budget, whichever comes first. Then it zeroizes them.
  - A frame of an unknown phase fails to open.

## Encoding details

- **Byte order:** every length (`u16 len` in `msg1` and in `id_block`; `u32 total_len` in the part framing) and every integer is big-endian, as in v1's `bound`.
- **Unknown bits refused:** `flags` bits other than bit 0 are refused (closed format).
- **v1 refused by name:** the v1 suite string `transit_x25519_mlkem768_hkdf_sha256` is refused with its own error, separate from an unknown suite.

## Framing, sizes, limits

- **Parts:** each message travels in the v1 part framing at version 0x02.
  - start: `"CTKX" ‖ 0x02 ‖ 0x00 ‖ u32 total_len ‖ bytes`;
  - continuation: `"CTKX" ‖ 0x02 ‖ 0x01 ‖ bytes`;
  - a message is at most 8 KiB.
  - **The budget covers both messages, `msg2`'s reassembly included,** and scales with the interface bitrate. For example, about 10 s on TCP or WebSocket, and about 7 s at SF7 or 23 s at SF9 on RNode/LoRa for about 13 parts. The handshake is not charged to shaping, because it runs before shaping begins (CC 5.3.3.10).
- **Sizes:**
  - `msg1` is about 2,400 bytes (6 + suite + key id + 1216 + 1120 + about 70);
  - `msg2` is 1,154 bytes (first contact) or 2,274 bytes (mutual): 1 + 1 + 1120 [+ 1120] + 32;
  - in total about 4.7 KB, roughly thirteen frames at the base link MDU, as CC states.
- **Resource limits:** each stranger's `msg1` costs the responder one X-Wing decapsulation (in the vault) and one AEAD open, and costs the attacker almost nothing. So:
  - decapsulation runs behind the receiver rates of E1 rule 9 (per link, per sender, node-wide) and outside any node-wide lock, as CC requires;
  - a node-wide decapsulation token bucket caps vault work;
  - no store read happens until `id_ct` opens;
  - binding lookups that miss are cached briefly;
  - first-contact sealed links, which now stay open per (b), have a count cap and an idle timeout.
- **The per-frame seal is seal frame version 0x02, with key phases.** This supersedes v1's frame `0x01 ‖ counter ‖ …`, which is refused after the cut. The layout is edge's `link_seal.rs` with the phase byte added. Edge implements it and must confirm these bytes.

  ```
  frame = 0x02 ‖ phase u8 ‖ counter u64_be ‖ AES-256-GCM(k, nonce, aad, pt) ‖ tag[16]
  k     = HKDF-SHA256(ikm = k_dir(phase), salt = link_id[16], info = "CIRIS-E1-LINK-SEAL-V2")
  nonce = lane u8 ‖ 0x000000 ‖ counter u64_be          (12 bytes)
  aad   = 0x02 ‖ lane u8 ‖ phase u8 ‖ link_id[16]
  ```

  - **`k_dir(phase)`** is `k_i2r` or `k_r2i` for the frame's direction.
  - **Phases:** phase 0 holds the keys from `msg2`. Phase 1 holds `k_i2r'` / `k_r2i'` from a promotion. A link is promoted at most once, so `phase` is 0 or 1, and any other value fails to open.
  - **Lanes and counters:** lanes are Channel 1, Resource 2, Request 3, Response 4 and Datagram 5. Each lane has its own counter, and the counter **continues** across the phase change, so the 128-frame replay window carries over. A (key, nonce) pair never repeats: the phase changes the key, and within a phase the lane and counter make each nonce unique.
  - **The receiver** opens a frame with the keys of the phase it names. After a promotion it keeps phase 0's open keys until it has seen phase 1 on that lane, or for one handshake budget, whichever is first, then zeroizes them.
  - **A sender** switches to phase 1 for every lane once it has sent or received `CTKC'`.
  - **The label** is `CIRIS-E1-LINK-SEAL-V2`, not v1's: the frame format changed, so the derived key changes with it.
  - **Known answers:** verify's vectors fix the handshake and the promotion rekey (`k_i2r'`, `k_r2i'`). Seal-frame known answers are not yet published: a phase-0 frame and a phase-1 frame on each direction, a stale phase-0 frame after the switch, and an unknown phase. Verify will publish them independently, as for the handshake, once edge confirms the layout.

## Downgrade

`CTKX` 0x01 is refused by name, because v1 is deleted under the hard cut. There is no fallback to the responder-only exchange.

## Seal interface (WIT `ciris:node@0.1.0`)

- `generate(id, transit)`: a fresh X-Wing static, 1216-byte public key. It replaces the old `transit-kex` kind.
- `xwing-decap(id, ct)`: the responder's decapsulation of `ct1`, and the initiator's of `ct3`.
- `kem-decap` is removed.
- Ephemeral `E_i` and all encapsulations run in the node.

## Known answers

These are in `src/ciris-crypto/tests/vectors/transit/transit_ctkx_v2_v1.json`. They were generated by `gen.py` beside the file, without verify's code: its own X-Wing draft-11 (checked against `draft-connolly-cfrg-xwing-kem-11.json` before anything is generated), kyber-py's ML-KEM-768, pyca/cryptography X25519 and AES-GCM, and hashlib SHA-2/SHA-3. The file contains:

- three handshakes: mutual; first contact with `has_static = 0`; first contact where the responder lacks the binding;
- one promotion;
- two framing cases;
- 38 refusals.

`tests/transit_vectors.rs` reproduces every message, key and refusal code byte for byte.

**Choices the vectors fix**, beyond this document:

- key ids are non-empty UTF-8 of at most 1024 bytes;
- `has_static` is 0 or 1;
- messages are checked in a fixed order: parse, then key ids, then decapsulation and `id_ct`;
- `max_part_len` includes the part header.

**Encapsulation randomness:** the core takes caller-supplied encapsulation randomness, so that the node can feed it from `random.fill` and the vectors can be deterministic. It MUST be fresh per encapsulation and never reused.

## Open for review

1. **Settled (CC):** a mandatory `CTKC` on the first sealed frame (no extra flight; authentication already implicit through `ss3`) satisfies "two messages, one flight… authenticated by the handshake itself". CC confirmed this reading and is adding the sentence quoted above to CC 5.3.3.10.
2. `responder_key_id` in the clear (kept, for rotation).
3. **Settled:** key phases with continuing counters (above).
4. **Settled:** no 0-RTT data under `k_id`.
5. **Decided (Eric): seat keys move by a re-bind ceremony.** The holders sign `canonical_rebind` for each seat's new X-Wing transit key before the cut, under CC 3.3.6.2's existing rule. A seat therefore holds both keys during the window:
   - it generates the new key with `seal.generate("transit:v2:<…>", transit)` under a fresh id, while the old pair stays pinned and in use;
   - it publishes the new public key for the rebind;
   - it switches to `CTKX` v2 at the cut.

   There is no dual-protocol window: v1 is refused after the cut. Only the new key exists early, unused until then. Seal ids are free strings, so holding both needs no interface change. A node MUST NOT regenerate the v2 key once it has been published for the rebind (the first-run rule of `seal.generate`).
