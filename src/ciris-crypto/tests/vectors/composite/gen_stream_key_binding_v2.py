# Independent StreamKeyBinding v2 known answers (Eric's ruling on CIRISEdge#1007: v2 is THE binding,
# version 0x02, v1's six members, the v2 members plus `profile`, then one composite `signature`).
# Inputs as v1 (CC 5.3.3.5). Layout from edge v45.1.3 av_chunk_auth.rs unsigned_body + the new profile byte.
import hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65
raw = lambda k: k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
PREFIX, LABEL = b"CompositeAlgorithmSignatures2025", b"COMPSIG-MLDSA65-Ed25519-SHA512"
u16 = lambda n: n.to_bytes(2, "big")
room, pub, nonce, epoch = b"room-kat", b"node-kat-a", bytes([7]) * 32, 5
sid = lambda n: hashlib.sha256(b"ciris-edge:call-stream:v2" + room + pub + n).digest()
chunk = raw(Ed25519PrivateKey.from_private_bytes(bytes([0x0c]) * 32))
assert sid(nonce).hex() == "c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8"
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
json.dump({"$note": ("StreamKeyBinding v2 (version 0x02) with one composite signature: v1's six members, then codec_map "
                     "(u8 count, then class u8 || u16 len || ASCII token, sorted by class), replaces (u8 0|1 [|| stream_id]), end u8 "
                     "(0 none, 1 Left, 2 Backgrounded, 3 Ended), final_seq u64 BE iff end != 0, kind u8, framing u8, profile u8 "
                     "(0 best-effort, 1 accountable); then u16 3373 || composite. Signing bytes 'ciris-edge:av-stream-key:v2' || body. "
                     "Inputs as v1: node-kat-a Ed25519 01x32 / ML-DSA-65 54x32, room-kat, join nonce 07x32, epoch 5, chunk key 0cx32. "
                     "Generated with dilithium-py (deterministic) and pyca/cryptography."),
           "publisher_composite_public_key_hex": cpk.hex(),
           "publisher_composite_public_key_sha256": hashlib.sha256(cpk).hexdigest(),
           "chunk_public_key_hex": chunk.hex(), "stream_id_hex": sid(nonce).hex(), "cases": cases},
          sys.stdout, indent=1, sort_keys=True); print()
