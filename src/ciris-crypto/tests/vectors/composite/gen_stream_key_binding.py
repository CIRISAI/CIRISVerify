# Independent StreamKeyBinding composite known answer (rc20 CC 5.3.3.1 inputs; composite per CC 2.6.1.7).
import hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65
raw = lambda k: k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
PREFIX, LABEL = b"CompositeAlgorithmSignatures2025", b"COMPSIG-MLDSA65-Ed25519-SHA512"
room, pub = b"room-kat", b"node-kat-a"
nonce, epoch = bytes([7]) * 32, 5
sid = hashlib.sha256(b"ciris-edge:call-stream:v2" + room + pub + nonce).digest()
assert sid.hex() == "c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8", sid.hex()
chunk = raw(Ed25519PrivateKey.from_private_bytes(bytes([0x0c]) * 32))
assert chunk.hex() == "0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d", chunk.hex()
u16 = lambda n: n.to_bytes(2, "big")
body = b"\x01" + u16(len(room)) + room + u16(len(pub)) + pub + nonce + sid + epoch.to_bytes(8, "big") + chunk
msg = b"ciris-edge:av-stream-key:v1" + body
ml_pk, ml_sk = ML_DSA_65.key_derive(bytes([0x54]) * 32)
ed = Ed25519PrivateKey.from_private_bytes(bytes([0x01]) * 32)
cpk = ml_pk + raw(ed)
mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(msg).digest()
sig = ML_DSA_65.sign(ml_sk, mp, ctx=LABEL, deterministic=True) + ed.sign(mp)
assert len(sig) == 3373 and ML_DSA_65.verify(ml_pk, mp, sig[:3309], ctx=LABEL)
enc = body + u16(len(sig)) + sig
json.dump({"$note": ("StreamKeyBinding with one composite signature (rc20 CC 5.3.3.1 as revised; composite CC 2.6.1.7). "
                     "Inputs from the section's known answers: publisher node-kat-a with Ed25519 seed 01x32 and ML-DSA-65 seed 54x32, "
                     "room room-kat, join nonce 07x32, epoch 5, chunk key seed 0cx32. Signing bytes = 'ciris-edge:av-stream-key:v1' || body. "
                     "ML-DSA-65 signs deterministically. Generated with dilithium-py and pyca/cryptography."),
           "stream_id_hex": sid.hex(), "chunk_public_key_hex": chunk.hex(), "body_hex": body.hex(),
           "signing_bytes_hex": msg.hex(), "publisher_composite_public_key_hex": cpk.hex(),
           "signature_hex": sig.hex(), "encoding_hex": enc.hex(),
           "encoding_sha256": hashlib.sha256(enc).hexdigest(), "encoding_len": len(enc),
           "part_id_hex": hashlib.sha256(enc).hexdigest()[:16]}, sys.stdout, indent=1, sort_keys=True); print()
