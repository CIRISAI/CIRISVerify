# CC 5.3.3.10 link handshake: proposed wire (`CTKX` v2)

**Status: PROPOSED.** This is verify's half of the joint submission with edge (CIRISEdge#1007). Eric ruled that it lands in the refactor cut. It is for edge's review and the constitution's text, and nothing here is implemented yet. It replaces `ciris_crypto::transit_kex` (`CTKX` v1: one message, responder-only, X25519 + ML-KEM under HKDF) as a hard cut.

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
- **The initiator is authenticated to the responder,** when mutual, by its first sealed frame. That frame MUST be `"CTKC" ‖ MAC(k_conf, "initiator" ‖ h3)`, sent under `k_i2r`. Only a holder of `S_i` derives `ss3`. Until that frame verifies, the responder treats the link as first contact (CC 5.4.6): nothing beyond the first-contact plane is admitted. This keeps the exchange at two handshake messages while making the initiator's authentication explicit.
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
- **The rekey:** both ends compute `prk' = HKDF-Extract(salt = H(h3 ‖ "promote" ‖ ct3'), ikm = k_i2r ‖ k_r2i ‖ ss3')`, then new `k_i2r`, `k_r2i` and `k_conf` under the same labels.
- **The confirmation:** the initiator answers with `"CTKC" ‖ MAC(k_conf', "initiator" ‖ …)` under the new `k_i2r`.
- **Lane counters:** edge's link seal restarts its counters for the new keys. Edge decides the mechanics.

## Framing, sizes, limits

- **Parts:** each message travels in the v1 part framing at version 0x02.
  - start: `"CTKX" ‖ 0x02 ‖ 0x00 ‖ u32 total_len ‖ bytes`;
  - continuation: `"CTKX" ‖ 0x02 ‖ 0x01 ‖ bytes`;
  - a message is at most 8 KiB, with a 10 s budget.
- **Sizes:**
  - `msg1` is about 2,400 bytes (6 + suite + key id + 1216 + 1120 + about 70);
  - `msg2` is 1,155 bytes (first contact) or 2,275 bytes (mutual);
  - in total about 4.7 KB, roughly thirteen frames at the base link MDU, as CC states.
- **Resource limits:** the responder decapsulates `ct1` (an X-Wing decapsulation in the vault) for any stranger's `msg1`. That runs behind the receiver rates of E1 rule 9 (per link, per sender, node-wide) and outside any node-wide lock, as CC requires.
- **The per-frame seal is unchanged** (`link_seal.rs`): `k = HKDF(ikm = k_dir, salt = link_id, info = "CIRIS-E1-LINK-SEAL-V1")`, with lanes and a replay window as today.

## Seal interface (WIT `ciris:node@0.1.0`)

- `generate(id, transit)`: a fresh X-Wing static, 1216-byte public key. It replaces the old `transit-kex` kind.
- `xwing-decap(id, ct)`: the responder's decapsulation of `ct1`, and the initiator's of `ct3`.
- `kem-decap` is removed.
- Ephemeral `E_i` and all encapsulations run in the node.

## Known answers

Verify will publish them once edge agrees on this wire, generated independently in the way of the binding and substrate vectors. They will cover:

- a mutual handshake;
- a first-contact handshake;
- a promotion;
- refusals: a wrong `confirm_r`, a tampered `id_ct`, a commitment mismatch, and a wrong suite.

## Open for review

1. Is the initiator's explicit confirmation as its first sealed frame (`CTKC`) acceptable as "two messages", or should the confirmation ride inside `msg1`'s successor on the same flight?
2. Should `responder_key_id` be in the clear, or should the dialler always use the newest pair from the binding? The clear id helps during a rotation.
3. Edge's lane-counter restart on promotion.
4. Whether `msg1` may carry 0-RTT application data under `k_id`. **Proposed: no**, because such data has no forward secrecy.
