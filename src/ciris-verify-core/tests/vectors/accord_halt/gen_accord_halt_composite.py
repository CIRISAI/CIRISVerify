# Independent known answers for the accord holder's composite signature on an invocation
# (CC 4.2.1.1 / 4.2.1.3, rc20): the composite ML-DSA-65-Ed25519 of CC 2.6.1.7 over the invocation's
# canonical text preimage, domain prefix included. Shares no code with verify: the preimage is laid out
# here from the CC text, ML-DSA-65 is dilithium-py (deterministic), Ed25519 is pyca/cryptography, and the
# thumbprint uses the small CBOR encoder below.
#
#   python3 -I gen_accord_halt_composite.py > accord_halt_composite_v1.json
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65

PREFIX, LABEL = b"CompositeAlgorithmSignatures2025", b"COMPSIG-MLDSA65-Ed25519-SHA512"
INVOKE, LIFECYCLE = "ciris.accord_invoke.v2\n", "ciris.accord_lifecycle.v1\n"


# ---- CBOR deterministic encoding (RFC 8949 §4.2.1), only what a COSE key needs
def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * w): return bytes([major << 5 | ai]) + n.to_bytes(w, "big")
def enc(v):
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list): return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted((enc(k), enc(x)) for k, x in v.items())
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)


class Holder:
    def __init__(self, label, ml_seed, ed_seed):
        self.label, self.ml_seed, self.ed_seed = label, ml_seed, ed_seed
        self.ml_pk, self.ml_sk = ML_DSA_65.key_derive(ml_seed)
        self.ed = Ed25519PrivateKey.from_private_bytes(ed_seed)
        self.pub = self.ml_pk + self.ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        assert len(self.pub) == 1984
        self.thumbprint = hashlib.sha256(enc({1: 7, 3: -70100, -1: self.pub})).digest()

    def sign(self, msg):
        mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(msg).digest()
        s = ML_DSA_65.sign(self.ml_sk, mp, ctx=LABEL, deterministic=True) + self.ed.sign(mp)
        assert len(s) == 3373 and ML_DSA_65.verify(self.ml_pk, mp, s[:3309], ctx=LABEL)
        return s

    def verifies(self, msg, s):
        mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(msg).digest()
        if not ML_DSA_65.verify(self.ml_pk, mp, s[:3309], ctx=LABEL): return False
        try:
            self.ed.public_key().verify(s[3309:], mp)
            return True
        except Exception:
            return False

    def json(self):
        return {"label": self.label, "mldsa65_seed_hex": self.ml_seed.hex(), "ed25519_seed_hex": self.ed_seed.hex(),
                "composite_public_key_hex": self.pub.hex(),
                "composite_public_key_sha256": hashlib.sha256(self.pub).hexdigest(),
                "thumbprint_hex": self.thumbprint.hex()}


# The seated roster A1/B1/C1 and one key outside it. Seeds: ML-DSA-65 xi = 0xa1 x 32 and Ed25519 = 0x1a x 32
# for A1, and likewise b1/1b, c1/1c, d1/1d.
A, B, C = (Holder(l, bytes([m]) * 32, bytes([e]) * 32) for l, m, e in (("A1", 0xa1, 0x1a), ("B1", 0xb1, 0x1b), ("C1", 0xc1, 0x1c)))
D = Holder("outsider", bytes([0xd1]) * 32, bytes([0x1d]) * 32)


def canonical(inv):
    """CC 4.2.1.1 / 4.2.1.3: the text inside sha256(...), domain prefix included, no trailing newline."""
    kind = inv["invocation_kind"]
    lines = [("invocation_kind", kind), ("invocation_id", inv["invocation_id"])]
    if kind == "lifecycle:active": lines.append(("resumes_halt_id", inv["resumes_halt_id"]))
    if kind == "lifecycle:confirmed": lines.append(("confirms_halt_id", inv["confirms_halt_id"]))
    lines += [(k, inv[k]) for k in ("nonce", "asserted_at", "valid_until", "payload_sha256")]
    prefix = LIFECYCLE if kind.startswith("lifecycle:") else INVOKE
    return (prefix + "\n".join(f"{k}={v}" for k, v in lines)).encode()


def nonce(start):
    return base64.urlsafe_b64encode(bytes(range(start, start + 32))).rstrip(b"=").decode()


def invocation(kind, iid, nonce_start, asserted_at, valid_until, payload, **binding):
    inv = {"invocation_kind": kind, "invocation_id": iid, **binding, "nonce": nonce(nonce_start),
           "asserted_at": asserted_at, "valid_until": valid_until,
           "payload_sha256": hashlib.sha256(payload.encode()).hexdigest()}
    return inv


def sig_json(holder, s):
    return {"holder": holder.label, "signature_hex": s.hex(), "signature_sha256": hashlib.sha256(s).hexdigest()}


HALT_PAYLOAD = "EmergencyShutdown CONSTITUTIONAL: known-answer halt, sealed before the genesis"
halt = invocation("constitutional", "halt-2026-11-16", 0x00, "2026-11-16T12:00:00.000Z", "2026-11-17T12:00:00.000Z",
                  HALT_PAYLOAD)
CONFIRM_PAYLOAD = "lifecycle:confirmed halt-2026-11-16"
confirm = invocation("lifecycle:confirmed", "confirm-2026-11-16", 0x20, "2026-11-16T13:00:00.000Z",
                     "2026-11-17T13:00:00.000Z", CONFIRM_PAYLOAD, confirms_halt_id="halt-2026-11-16")
RESUME_PAYLOAD = "lifecycle:active resumes halt-2026-11-16"
resume = invocation("lifecycle:active", "resume-2026-11-17", 0x40, "2026-11-17T09:00:00.000Z",
                    "2026-11-18T09:00:00.000Z", RESUME_PAYLOAD, resumes_halt_id="halt-2026-11-16")

cases = []
for cid, desc, inv, payload, signers in [
    ("constitutional_halt", "A constitutional halt, one holder's signature (A1), as each holder seals it before the "
     "genesis (CC 4.2.1.1).", halt, HALT_PAYLOAD, [A]),
    ("lifecycle_confirmed", "The strict-majority confirmation of that halt (CC 4.2.1.3): A1, the firer, and B1 cosign "
     "the same bytes; 2 of 3.", confirm, CONFIRM_PAYLOAD, [A, B]),
    ("lifecycle_active", "The resumption of that halt (CC 4.2.1.3): B1 and C1 cosign; 2 of 3.", resume,
     RESUME_PAYLOAD, [B, C]),
]:
    msg = canonical(inv)
    cases.append({"id": cid, "description": desc, "invocation": inv, "payload_text": payload,
                  "canonical_text": msg.decode(), "canonical_bytes_hex": msg.hex(),
                  "canonical_sha256_hex": hashlib.sha256(msg).hexdigest(),
                  "signatures": [sig_json(h, h.sign(msg)) for h in signers]})

refusals = []
halt_msg = canonical(halt)
# 1. The domain prefix removed: a genuine signature over the bytes without "ciris.accord_invoke.v2\n".
stripped = halt_msg[len(INVOKE):]
s = A.sign(stripped)
assert A.verifies(stripped, s) and not A.verifies(halt_msg, s)
refusals.append({"id": "domain_prefix_removed", "description": "A1's signature over the halt's canonical bytes with "
                 "the domain prefix removed; it verifies over what it signed and is refused over the canonical bytes.",
                 "invocation": halt, "checked_against": ["A1"], "signed_message_hex": stripped.hex(), **sig_json(A, s)})
# 2. A wrong holder: a key outside the roster signs the halt's exact canonical bytes.
s = D.sign(halt_msg)
assert D.verifies(halt_msg, s) and not any(h.verifies(halt_msg, s) for h in (A, B, C))
refusals.append({"id": "wrong_holder", "description": "The halt's exact canonical bytes signed by a key outside the "
                 "roster (seeds d1/1d); refused under each of A1, B1 and C1.", "invocation": halt,
                 "checked_against": ["A1", "B1", "C1"], "signed_message_hex": halt_msg.hex(), **sig_json(D, s),
                 "signer_composite_public_key_hex": D.pub.hex()})
# 3. A mutated field: A1's genuine halt signature presented with one field changed.
s = A.sign(halt_msg)
for mid, field, value in [("mutated_invocation_id", "invocation_id", "halt-2026-11-17"),
                          ("mutated_kind_drill", "invocation_kind", "drill"),
                          ("mutated_payload_sha256", "payload_sha256", hashlib.sha256(b"another payload").hexdigest())]:
    m = dict(halt, **{field: value})
    assert not A.verifies(canonical(m), s)
    refusals.append({"id": mid, "description": f"A1's genuine signature over the halt, presented with {field} changed "
                     f"to {value!r}.", "invocation": m, "checked_against": ["A1"],
                     "signed_message_hex": halt_msg.hex(), **sig_json(A, s)})
# 4. The digest signed instead of the preimage: under verify's reading the composite signs the canonical
#    text itself (it hashes with SHA-512 inside); a signature over the 32-byte SHA-256 of that text is refused.
dig = hashlib.sha256(halt_msg).digest()
s = A.sign(dig)
assert not A.verifies(halt_msg, s)
refusals.append({"id": "signed_sha256_not_text", "description": "A1's signature over the 32-byte SHA-256 of the "
                 "canonical bytes rather than over the canonical bytes; refused under verify's reading of CC 4.2.1.1 "
                 "(see the README: the text writes `canonical = sha256(...)`).", "invocation": halt,
                 "checked_against": ["A1"], "signed_message_hex": dig.hex(), **sig_json(A, s)})

json.dump({"$note": ("Accord invocation holder signatures (CC 4.2.1.1 / 4.2.1.3, rc20): the composite ML-DSA-65-Ed25519 "
                     "of CC 2.6.1.7 (COSE alg -70100, deterministic ML-DSA-65) over the invocation's canonical text "
                     "preimage, domain prefix included, no trailing newline: the bytes verify's "
                     "Invocation::canonical_bytes() lays out. canonical_sha256_hex is the sha256(...) the CC text "
                     "wraps the preimage in; it is not what is signed. Generated by gen_accord_halt_composite.py with "
                     "dilithium-py and pyca/cryptography, independent of verify."),
           "roster": [h.json() for h in (A, B, C)], "outsider": D.json(),
           "cases": cases, "refusals": refusals}, sys.stdout, indent=1, sort_keys=True)
print()
