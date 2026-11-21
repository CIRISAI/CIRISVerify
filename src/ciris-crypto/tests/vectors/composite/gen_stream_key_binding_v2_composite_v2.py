# Independent StreamKeyBinding v2 known answers, second set (CC 1.0-rc21 5.3.3.5, 815050d / 544755a):
# the binding layout is unchanged (version 0x02, signing label av-stream-key:v2), but stream_id is now
# SHA-256("ciris-edge:call-stream:v3" || u16be len || room || u16be len || publisher || join_nonce[32]),
# and the publisher is a member's federation key id on the producing device, never a node key.
# Also emits stream-id known answers, among them ("ab","c") vs ("a","bc"), which v2's concatenation merged.
import hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65
raw = lambda k: k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
PREFIX, LABEL = b"CompositeAlgorithmSignatures2025", b"COMPSIG-MLDSA65-Ed25519-SHA512"
u16 = lambda n: n.to_bytes(2, "big")
room, pub, nonce, epoch = b"room-kat", b"member-kat-a", bytes([7]) * 32, 5
def stream_id(r, p, n):
    assert 1 <= len(r) <= 1024 and 1 <= len(p) <= 1024 and len(n) == 32
    return hashlib.sha256(b"ciris-edge:call-stream:v3" + u16(len(r)) + r + u16(len(p)) + p + n).digest()
sid = lambda n: stream_id(room, pub, n)
chunk = raw(Ed25519PrivateKey.from_private_bytes(bytes([0x0c]) * 32))
ml_pk, ml_sk = ML_DSA_65.key_derive(bytes([0x54]) * 32)
ed = Ed25519PrivateKey.from_private_bytes(bytes([0x01]) * 32)
cpk = ml_pk + raw(ed)
def sign(msg):
    mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(msg).digest()
    s = ML_DSA_65.sign(ml_sk, mp, ctx=LABEL, deterministic=True) + ed.sign(mp)
    assert len(s) == 3373 and ML_DSA_65.verify(ml_pk, mp, s[:3309], ctx=LABEL)
    return s
def body(codecs, replaces, end, final_seq, kind, framing, profile):
    b = b"\x02" + u16(len(room)) + room + u16(len(pub)) + pub + nonce + sid(nonce) + epoch.to_bytes(8, "big") + chunk
    assert codecs == sorted(codecs) and len({c for c, _ in codecs}) == len(codecs) and len(codecs) <= 8
    b += bytes([len(codecs)]) + b"".join(bytes([c]) + u16(len(t)) + t for c, t in codecs)
    b += (b"\x01" + replaces) if replaces else b"\x00"
    b += bytes([end]) + (final_seq.to_bytes(8, "big") if end else b"")
    return b + bytes([kind, framing, profile])
cases = []
for cid, desc, args in [
    ("v2_full", "Codec map av1 (class 0x01) and opus (0xFF); replaces the stream of join nonce 08x32; end Backgrounded (2) with final_seq 41; kind media; framing fragments; profile accountable.",
     dict(codecs=[(0x01, b"av1"), (0xFF, b"opus")], replaces=sid(bytes([8]) * 32), end=2, final_seq=41, kind=0, framing=1, profile=1)),
    ("v2_minimal", "Codec map opus (0xFF) only; no replaces; no end (so no final_seq); kind media; framing none; profile best-effort.",
     dict(codecs=[(0xFF, b"opus")], replaces=None, end=0, final_seq=None, kind=0, framing=0, profile=0)),
]:
    bd = body(**args)
    msg = b"ciris-edge:av-stream-key:v2" + bd
    sig = sign(msg)
    enc = bd + u16(3373) + sig
    cases.append({"id": cid, "description": desc, "body_hex": bd.hex(), "signing_bytes_hex": msg.hex(),
                  "signature_hex": sig.hex(), "signature_sha256": hashlib.sha256(sig).hexdigest(),
                  "encoding_hex": enc.hex(), "encoding_len": len(enc),
                  "encoding_sha256": hashlib.sha256(enc).hexdigest(), "part_id_hex": hashlib.sha256(enc).hexdigest()[:16]})
sids = []
for cid, r, p, n in [("binding_inputs", room, pub, nonce), ("split_ab_c", b"ab", b"c", bytes(32)),
                     ("split_a_bc", b"a", b"bc", bytes(32)), ("utf8_multibyte", "r\u00f6om".encode(), "m\u00e9mber".encode(), bytes(range(32))),
                     ("max_fields", b"r" * 1024, b"p" * 1024, bytes([0xff]) * 32)]:
    sids.append({"id": cid, "room_hex": r.hex(), "publisher_hex": p.hex(), "join_nonce_hex": n.hex(),
                 "preimage_sha256": hashlib.sha256(b"ciris-edge:call-stream:v3" + u16(len(r)) + r + u16(len(p)) + p + n).hexdigest(),
                 "stream_id_hex": stream_id(r, p, n).hex()})
assert sids[1]["stream_id_hex"] != sids[2]["stream_id_hex"]
assert hashlib.sha256(b"ciris-edge:call-stream:v2" + b"ab" + b"c" + bytes(32)).digest() == hashlib.sha256(b"ciris-edge:call-stream:v2" + b"a" + b"bc" + bytes(32)).digest()
json.dump({"$note": ("StreamKeyBinding v2 (version 0x02) with one composite signature: v1's six members, then codec_map "
                     "(u8 count, then class u8 || u16 len || ASCII token, sorted by class), replaces (u8 0|1 [|| stream_id]), end u8 "
                     "(0 none, 1 Left, 2 Backgrounded, 3 Ended), final_seq u64 BE iff end != 0, kind u8, framing u8, profile u8 "
                     "(0 best-effort, 1 accountable); then u16 3373 || composite. Signing bytes 'ciris-edge:av-stream-key:v2' || body. "
                     "stream_id is CC rc21's v3 derivation (length-prefixed room and publisher). "
                     "Inputs: publisher member-kat-a (a member key, never a node key) Ed25519 01x32 / ML-DSA-65 54x32, room-kat, join nonce 07x32, epoch 5, chunk key 0cx32. "
                     "Generated with dilithium-py (deterministic) and pyca/cryptography."),
           "publisher_composite_public_key_hex": cpk.hex(),
           "publisher_composite_public_key_sha256": hashlib.sha256(cpk).hexdigest(),
           "chunk_public_key_hex": chunk.hex(), "stream_id_hex": sid(nonce).hex(), "cases": cases,
           "stream_ids": sids, "stream_id_rule": "SHA-256('ciris-edge:call-stream:v3' || u16be len || room || u16be len || publisher || join_nonce[32]); room and publisher 1..=1024 bytes UTF-8"},
          sys.stdout, indent=1, sort_keys=True); print()
