import json, hashlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from dilithium_py.ml_dsa import ML_DSA_65
P = b"CompositeAlgorithmSignatures2025"; LBL = b"COMPSIG-MLDSA65-Ed25519-SHA512"
d = json.load(open(sys.argv[1])); x = bytes.fromhex
def mprime(m, ctx=b""): return P + LBL + bytes([len(ctx)]) + ctx + hashlib.sha512(m).digest()
def verify(pk, m, s, ctx=b""):
    mp = mprime(m, ctx)
    assert ML_DSA_65.verify(pk[:1952], mp, s[:3309], ctx=LBL), "mldsa"
    Ed25519PublicKey.from_public_bytes(pk[1952:]).verify(s[3309:], mp)
    # neither half under an empty ML-DSA ctx
    assert not ML_DSA_65.verify(pk[:1952], mp, s[:3309], ctx=b"")
l = d["lamps_19"]; pk = x(l["pk_hex"])
verify(pk, x(l["m_hex"]), x(l["s_hex"])); verify(pk, x(l["m_hex"]), x(l["s_with_context_hex"]), x(l["ctx_hex"]))
# keygen from sk = mldsa_seed || ed25519_sk
sk = x(l["sk_hex"]); mpk, _ = ML_DSA_65.key_derive(sk[:32])
from cryptography.hazmat.primitives import serialization as s
epk = Ed25519PrivateKey.from_private_bytes(sk[32:]).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
assert mpk + epk == pk, "lamps keygen"
j = d["jose_06"]; pub = x(j["pub_hex"])
mpk, _ = ML_DSA_65.key_derive(x(j["mldsa_seed_hex"]))
epk = Ed25519PrivateKey.from_private_bytes(x(j["ed25519_seed_hex"])).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
assert mpk + epk == pub, "jose keygen"
# Sig_structure: ["Signature1", bstr(protected {1:-59, 4:kid}), h'', payload]
kid = x(j["kid_hex"]); prot = bytes([0xa2, 0x01, 0x38, 0x3a, 0x04, 0x48]) + kid
def bstr(b): return (bytes([0x40 + len(b)]) if len(b) < 24 else bytes([0x58, len(b)])) + b
pl = x(j["payload_hex"])
M = bytes([0x84, 0x6a]) + b"Signature1" + bstr(prot) + b"\x40" + bstr(pl)
assert mprime(M).hex() == j["m_prime_hex"], "jose M'"
verify(pub, M, x(j["signature_hex"]))
print("all draft known answers verify independently (dilithium-py + cryptography)")
