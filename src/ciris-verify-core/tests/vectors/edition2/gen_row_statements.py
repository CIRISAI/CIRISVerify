# Independent generator of CC 2.6.1 (rc20) edition-2 row statement known answers.
# Its own CBOR deterministic encoder (RFC 8949 4.2.1 bytewise key order), dilithium-py
# (FIPS 204, deterministic) and pyca/cryptography (Ed25519). Shares no code with verify.
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65

PREFIX = b"CompositeAlgorithmSignatures2025"
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"


class Tag:
    def __init__(self, n, v): self.n, self.v = n, v


class Simple:
    def __init__(self, n): self.n = n


def head(major, n):
    m = major << 5
    if n < 24: return bytes([m | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size): return bytes([m | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def enc(v):
    if v is None: return b"\xf6"
    if v is True: return b"\xf5"
    if v is False: return b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted((enc(k), enc(x)) for k, x in v.items())
        assert len({k for k, _ in items}) == len(items)
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag): return head(6, v.n) + enc(v.v)
    if isinstance(v, Simple): return head(7, v.n)
    raise TypeError(v)


class Key:
    def __init__(self, n):
        self.ml_seed, self.ed_seed = bytes([n]) * 32, bytes([(n + 100) % 256]) * 32
        self.ml_pk, self.ml_sk = ML_DSA_65.key_derive(self.ml_seed)
        ed = Ed25519PrivateKey.from_private_bytes(self.ed_seed)
        self.ed = ed
        self.pub = self.ml_pk + ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        assert len(self.pub) == 1984
        self.kid = hashlib.sha256(enc({1: 7, 3: -70100, -1: self.pub})).digest()
        self.iss = "urn:ietf:params:oauth:ckt:sha-256:" + base64.urlsafe_b64encode(self.kid).rstrip(b"=").decode()

    def sign(self, m):
        mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(m).digest()
        s = ML_DSA_65.sign(self.ml_sk, mp, ctx=LABEL, deterministic=True) + self.ed.sign(mp)
        assert len(s) == 3373
        return s


def statement(k, sub, rtype, family, payload, claims_edit=None, prot_edit=None, unprot=None, sig_edit=None):
    claims = {1: k.iss, 2: sub, 6: payload["asserted_at"] // 1000, -70003: 2}
    if "valid_from" in payload: claims[5] = payload["valid_from"] // 1000
    if "valid_until" in payload: claims[4] = payload["valid_until"] // 1000
    if claims_edit: claims_edit(claims)
    prot = {1: -70100, 3: "application/vnd.ciris.row+cbor", 4: k.kid, 15: claims, 16: "ceg-row/2",
            -70001: rtype, -70002: family}
    if prot_edit: prot_edit(prot)
    pb, plb = enc(prot), enc(payload)
    m = enc(["Signature1", pb, b"", plb])
    sig = k.sign(m)
    if sig_edit: sig = sig_edit(sig, m)
    return enc(Tag(18, [pb, unprot or {}, plb, sig])), pb, plb


def hd(d): return [-16, d]
def rref(n): return [2, hd(bytes([n]) * 32)]


A, B, C = Key(1), Key(2), Key(3)
P1 = {"author": A.iss, "asserted_at": 1763200000123, "dimension": "evidence:safety_battery:k:c:p:v1",
      "score": 750000, "confidence": 900000, "evidence_refs": [hd(bytes([9]) * 32)]}
P2 = {"asserted_at": 1763200000999, "valid_from": 1763200000000, "valid_until": 1794736000500,
      "refs": {"head": rref(1), "further_heads": [rref(2), rref(3)], "also": {"ack": [rref(4)]}},
      "salt": bytes(range(16)), "body": {"note": "a note", Simple(59): [bytes([5]) * 32]},
      "list": [1, Tag(60, bytes([6]) * 32)]}

valid, refusals = [], []


def add_valid(cid, desc, k, sub, rt, fam, p):
    st, pb, plb = statement(k, sub, rt, fam, p)
    author = p.get("author")
    rid = hashlib.sha256(enc(["CEG-row/2", rt, fam, sub, author, plb])).digest()
    sid = hashlib.sha256(enc(["CEG-statement-id/2", pb, plb])).digest()
    valid.append({"id": cid, "description": desc, "key_seed": k.ml_seed[0], "statement_hex": st.hex(),
                  "kid_hex": k.kid.hex(), "iss": k.iss, "row_id_hex": rid.hex(), "statement_id_hex": sid.hex()})
    return st


s1 = add_valid("authored_score", "An authored scores row signed by its author.", A, "subject-1", "scores",
               "evidence:.suite:.kind:.cell:.prefix", P1)
add_valid("second_voice", "The same payload signed by a second key: same row id, another statement id.", B,
          "subject-1", "scores", "evidence:.suite:.kind:.cell:.prefix", P1)
add_valid("counted_with_refs", "A counted row (no author) with refs, a salt, nbf/exp and both redaction forms.",
          C, "urn:ietf:params:oauth:ckt:sha-256:" + "A" * 43, "supersedes", "key:record", P2)


def refuse(cid, desc, verdict, st, keys=(A,)):
    refusals.append({"id": cid, "description": desc, "expect": verdict, "statement_hex": st.hex(),
                     "held_key_seeds": [k.ml_seed[0] for k in keys]})


def edit(d, k, v):
    d = dict(d); d[k] = v; return d


def drop(d, k):
    d = dict(d); del d[k]; return d


refuse("waiting_on_key", "A valid statement whose key is not held.", "waiting", s1, keys=())
refuse("bad_signature", "One signature byte flipped.", "invalid:bad_signature",
       statement(A, "s", "scores", "a", P1, sig_edit=lambda s, m: s[:-1] + bytes([s[-1] ^ 1]))[0])
refuse("ml_dsa_empty_ctx", "The ML-DSA half signed with the empty FIPS 204 context.", "invalid:bad_signature",
       statement(A, "s", "scores", "a", P1, sig_edit=lambda s, m: ML_DSA_65.sign(
           A.ml_sk, PREFIX + LABEL + b"\x00" + hashlib.sha512(m).digest(), deterministic=True) + s[3309:])[0])
refuse("iat_disagrees", "iat is not floor(asserted_at / 1000).", "invalid:time:iat",
       statement(A, "s", "scores", "a", P1, claims_edit=lambda c: c.__setitem__(6, c[6] + 1))[0])
refuse("exp_missing", "valid_until present, exp absent.", "invalid:time:exp",
       statement(A, "s", "scores", "a", P2, claims_edit=lambda c: c.__delitem__(4))[0])
refuse("cty_with_parameters", "cty carries parameters.", "invalid:malformed:cty",
       statement(A, "s", "scores", "a", P1, prot_edit=lambda p: p.__setitem__(3, "application/vnd.ciris.row+cbor;type=scores"))[0])
refuse("extra_protected_member", "The protected header carries crit.", "invalid:unexpected:protected",
       statement(A, "s", "scores", "a", P1, prot_edit=lambda p: p.__setitem__(2, [1]))[0])
refuse("no_family", "-70002 absent.", "invalid:unexpected:protected",
       statement(A, "s", "scores", "a", P1, prot_edit=lambda p: p.__delitem__(-70002))[0])
refuse("unknown_row_type", "A row type outside the five.", "invalid:malformed:row-type",
       statement(A, "s", "endorses", "a", P1)[0], keys=())
refuse("family_leaf_uppercase", "A family id with an upper-case letter.", "invalid:malformed:family-id",
       statement(A, "s", "scores", "Evidence", P1)[0])
refuse("edition_1", "edition claim 1.", "invalid:malformed:edition",
       statement(A, "s", "scores", "a", P1, claims_edit=lambda c: c.__setitem__(-70003, 1))[0])
refuse("iss_bad_last_char", "iss whose 43rd character carries trailing bits.", "invalid:malformed:iss",
       statement(A, "s", "scores", "a", P1, claims_edit=lambda c: c.__setitem__(1, c[1][:-1] + "B"))[0])
refuse("refs_unsorted_set", "further_heads out of order.", "invalid:set_order:further_heads",
       statement(A, "s", "scores", "a", edit(P2, "refs", {"further_heads": [rref(3), rref(2)]}))[0])
refuse("refs_empty", "An empty refs map.", "invalid:malformed:refs",
       statement(A, "s", "scores", "a", edit(P1, "refs", {}))[0])
refuse("also_unknown_role", "An also role outside {ack, cites}.", "invalid:unexpected:also",
       statement(A, "s", "scores", "a", edit(P1, "refs", {"also": {"quotes": [rref(1)]}}))[0])
refuse("null_member", "A null member.", "invalid:malformed:ceg-value",
       statement(A, "s", "scores", "a", edit(P1, "x", None))[0])
refuse("score_out_of_range", "score above 10^6.", "invalid:malformed:score",
       statement(A, "s", "scores", "a", edit(P1, "score", 1000001))[0])
_c = {1: A.iss, 2: "s", 6: 0, -70003: 2}
_p = enc({1: -70100, 3: "application/vnd.ciris.row+cbor", 4: A.kid, 15: _c, 16: "ceg-row/2", -70001: "scores", -70002: "a"})
_pl = enc(drop(P1, "asserted_at"))
refuse("no_asserted_at", "asserted_at absent.", "invalid:malformed:asserted_at",
       enc(Tag(18, [_p, {}, _pl, A.sign(enc(["Signature1", _p, b"", _pl]))])))
# Non-deterministic encodings.
_good = bytes.fromhex(valid[0]["statement_hex"])
refuse("long_array_head", "The COSE_Sign1 array head in a two-byte form.", "invalid:not_deterministic:statement",
       _good[:1] + b"\x98\x04" + _good[2:])
refuse("untagged", "A COSE_Sign1 without tag 18.", "invalid:not_cose_sign1", _good[1:])
# Bytewise order puts the shorter "score" (0x65...) before "asserted_at" (0x6b...); here reversed.
_unsorted = b"\xa2" + enc("asserted_at") + enc(500) + enc("score") + enc(1)
refuse("payload_keys_unsorted", "The payload map's keys out of bytewise order.", "invalid:not_deterministic:payload",
       enc(Tag(18, [_p, {}, _unsorted, A.sign(enc(["Signature1", _p, b"", _unsorted]))])))
refuse("unprotected_text_label", "A text label in the unprotected header.", "invalid:unexpected:unprotected",
       statement(A, "s", "scores", "a", P1, unprot={"note": 1})[0])
refuse("disclosure_short_salt", "An sd_claims disclosure with a 15-byte salt.", "invalid:malformed:sd-disclosure",
       statement(A, "s", "scores", "a", P1, unprot={17: [enc([bytes(15), 1, "k"])]})[0])

assert len({r["id"] for r in refusals}) == len(refusals)
out = {
    "$schema_note": (
        "CC 2.6.1 (CIRISConstitution rc20 09907aa, manifests/signed_object_v2.cddl) edition-2 row statement "
        "known answers (CIRISVerify#326). Keys: ML-DSA-65 seed = [n]*32, Ed25519 seed = [n+100]*32 for "
        "key_seed n. Signatures are deterministic (FIPS 204 deterministic variant; Ed25519). Generated "
        "independently of the Rust code by its own CBOR encoder over dilithium-py and pyca/cryptography; "
        "see README.md beside this file. expect: valid, waiting, or invalid:<reason>[:<member>]."),
    "valid": valid,
    "refusals": refusals,
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
print()
