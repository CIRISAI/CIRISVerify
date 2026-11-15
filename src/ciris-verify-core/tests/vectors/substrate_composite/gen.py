# Composite ML-DSA-65-Ed25519 (CC 2.6.1.7) signatures over the CC Part 6 golden
# preimages, generated without verify's code (dilithium-py, pyca/cryptography).
# The preimages are the existing §19 / §19.7 vectors' expected_canonical_bytes_hex,
# unchanged by the composite cut.
#   python3 -I gen.py ../substrate_v19 ../substrate_v19_7 > composite_signatures_v1.json
import glob, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65

PREFIX, LABEL = b"CompositeAlgorithmSignatures2025", b"COMPSIG-MLDSA65-Ed25519-SHA512"

class Key:
    def __init__(self, n):
        self.n = n
        self.ml_pk, self.ml_sk = ML_DSA_65.key_derive(bytes([n]) * 32)
        self.ed = Ed25519PrivateKey.from_private_bytes(bytes([(n + 100) % 256]) * 32)
        self.pub = self.ml_pk + self.ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    def sign(self, m):
        mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(m).digest()
        return ML_DSA_65.sign(self.ml_sk, mp, ctx=LABEL, deterministic=True) + self.ed.sign(mp)

K, OTHER = Key(21), Key(22)
cases = []
for root in sys.argv[1:]:
    for f in sorted(glob.glob(os.path.join(root, "**", "*.json"), recursive=True)):
        d = json.load(open(f))
        if not isinstance(d, dict) or "expected_canonical_bytes_hex" not in d:
            continue
        pre = bytes.fromhex(d["expected_canonical_bytes_hex"])
        sig = K.sign(pre)
        rel = os.path.relpath(f, os.path.dirname(os.path.abspath(root))).replace(os.sep, "/")
        cases.append({"source": rel, "vector_id": d.get("vector_id", rel), "preimage_hex": pre.hex(),
                      "signature_hex": sig.hex(),
                      "refusals": {
                          "ml_dsa_region_flipped": (sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]).hex(),
                          "ed25519_region_flipped": (sig[:-1] + bytes([sig[-1] ^ 1])).hex(),
                          "other_key": OTHER.sign(pre).hex(),
                          "truncated": sig[:-1].hex()}})
out = {"$schema_note": ("Composite ML-DSA-65-Ed25519 (CC 2.6.1.7; LAMPS -19 as JOSE -06 profiles it) over each CC Part 6 "
                        "golden preimage, generated independently of the Rust code (dilithium-py deterministic, pyca/cryptography). "
                        "Signer: ML-DSA-65 seed [21]*32, Ed25519 seed [121]*32. A refusal must not verify; 'truncated' is a "
                        "malformed signature, the others are SignatureInvalid."),
       "composite_public_key_hex": K.pub.hex(), "cases": cases}
json.dump(out, sys.stdout, indent=1, sort_keys=True); print()
