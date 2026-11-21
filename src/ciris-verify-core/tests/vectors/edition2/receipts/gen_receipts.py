# Independent known answers for SCITT receipts (RFC 9942 COSE Receipts over the RFC 9162 SHA-256 tree, as
# RFC 9943 carries them in header 394; CC 2.7.11) and the head-receipt count of the rc22 model (a lineage
# head's receipts: any statement OF the head, composite-signed by a charter service, iat required, a service
# counted once).
#
# It reuses gen_genesis_bundles_v5.py's CBOR encoder, composite signer and genesis statements (loaded from
# ../genesis and run into a scratch directory whose output is discarded), adds its own RFC 9162 tree, and
# signs the other algorithms with pyca/cryptography and dilithium-py. It shares no code with verify:
#
#   python3 -I gen_receipts.py > receipts_v1.json
import hashlib, importlib.util, json, os, sys, tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65

here = os.path.dirname(os.path.abspath(__file__))
gdir = os.path.join(here, "..", "genesis")
argv = sys.argv
with tempfile.TemporaryDirectory() as scratch:
    sys.argv = ["gen_genesis_bundles_v5.py", "--out", scratch]
    spec = importlib.util.spec_from_file_location("g5", os.path.join(gdir, "gen_genesis_bundles_v5.py"))
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
sys.argv = argv
enc, Tag, sha = g.enc, g.Tag, g.sha


def dec_sign1(b):
    """Parse a tag-18 COSE_Sign1 this file produced: return (protected bytes, payload bytes, signature)."""
    # A small reader for the four-element array: the items are bstr, map, bstr|null, bstr.
    assert b[0] == 0xd2 and b[1] == 0x84
    i = 2
    def item(i):
        major, ai = b[i] >> 5, b[i] & 31
        if ai < 24: n, i2 = ai, i + 1
        else:
            size = {24: 1, 25: 2, 26: 4, 27: 8}[ai]; n = int.from_bytes(b[i + 1:i + 1 + size], "big"); i2 = i + 1 + size
        return major, n, i2
    major, n, i = item(i); prot = b[i:i + n]; i += n
    major, n, j = item(i); assert major == 5 and n == 0; i = j
    if b[i] == 0xf6: pl = None; i += 1
    else: major, n, i = item(i); pl = b[i:i + n]; i += n
    major, n, i = item(i); sig = b[i:i + n]
    return prot, pl, sig


def leaf_of(st):
    p, pl, s = dec_sign1(st)
    return enc(Tag(18, [p, {}, pl, s]))


def lh(leaf): return sha(b"\x00" + leaf)
def nh(a, b): return sha(b"\x01" + a + b)


def mth(hs):
    if len(hs) == 0: return sha(b"")
    if len(hs) == 1: return hs[0]
    k = 1
    while k * 2 < len(hs): k *= 2
    return nh(mth(hs[:k]), mth(hs[k:]))


def path(m, hs):
    if len(hs) <= 1: return []
    k = 1
    while k * 2 < len(hs): k *= 2
    return path(m, hs[:k]) + [mth(hs[k:])] if m < k else path(m - k, hs[k:]) + [mth(hs[:k])]


class Ed:
    def __init__(self, n, alg=-8):
        self.alg = alg
        self.k = Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)
        self.x = self.k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        self.cose = enc({1: 1, 3: alg, -1: 6, -2: self.x})
        self.thumb = sha(enc({1: 1, -1: 6, -2: self.x}))
    def sign(self, m): return self.k.sign(m)


class P256:
    alg = -7
    def __init__(self, n):
        self.k = ec.derive_private_key(int.from_bytes(sha(bytes([n])), "big") % (2 ** 255), ec.SECP256R1())
        nums = self.k.public_key().public_numbers()
        self.cose = enc({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        self.thumb = sha(enc({1: 2, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}))
    def sign(self, m):
        r, s = decode_dss_signature(self.k.sign(m, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class MlDsa:
    alg = -49
    def __init__(self, n):
        self.pk, self.sk = ML_DSA_65.key_derive(bytes([n]) * 32)
        self.cose = enc({1: 7, 3: -49, -1: self.pk})
        self.thumb = sha(self.cose)
    def sign(self, m): return ML_DSA_65.sign(self.sk, m, ctx=b"", deterministic=True)


class Comp:
    alg = -70100
    def __init__(self, n):
        self.key = g.Key(n)
        self.cose = enc(self.key.cose)
        self.kid = self.key.kid
        self.thumb = self.key.kid
    def sign(self, m): return self.key.sign(m)


def receipt(statements, index, signer, iat=1767312000, iss=None, kid=True, vds=1, alg=None, attach=False,
            edit_path=None, edit_index=None, edit_size=None, drop_iat=False, sub="humanity-accord", no_iss=False):
    hs = [lh(leaf_of(s)) for s in statements]
    root, p = mth(hs), path(index, hs)
    if edit_path: p = edit_path(p)
    prot = {1: alg or signer.alg, 395: vds}
    if kid and hasattr(signer, "kid"): prot[4] = signer.kid
    cwt = {}
    if iss is None and not no_iss and isinstance(signer, Comp): iss = signer.key.iss
    if iss: cwt[1] = iss
    if sub: cwt[2] = sub
    if iat is not None and not drop_iat: cwt[6] = iat
    if cwt: prot[15] = cwt
    pb = enc(prot)
    sig = signer.sign(enc(["Signature1", pb, b"", root]))
    proof = enc([edit_size if edit_size is not None else len(statements),
                 edit_index if edit_index is not None else index, p])
    return enc(Tag(18, [pb, {396: {-1: [proof]}}, root if attach else None, sig]))


def with_receipts(st, rs):
    p, pl, s = dec_sign1(st)
    return enc(Tag(18, [p, {394: sorted(rs)} if rs else {}, pl, s]))


# ---------------------------------------------------------------- statements
A, B, C = g.A, g.B, g.C
P = g.payload()
HEAD = [g.voice(k, P) for k in (A, B, C)]                       # the head's three holder statements
P2 = g.payload(at=g.T1 + 1000)                                   # another head at the same place (no prev)
OTHER = [g.voice(k, P2) for k in (A, B, C)]
FILLER = [g.voice(g.Key(70 + i), g.payload(at=g.T1 + 10 * i)) for i in range(4)]
LOG = FILLER[:2] + [HEAD[0]] + FILLER[2:] + [HEAD[1], HEAD[2]]   # one service's log, 7 leaves
S1, S2, S3, S4 = Comp(91), Comp(92), Comp(93), Comp(94)
ED, EC, ML = Ed(95), P256(96), MlDsa(97)
ED19 = Ed(98, alg=-19)
keys = {"S1": S1, "S2": S2, "S3": S3, "S4": S4, "ED": ED, "EC": EC, "ML": ML, "ED19": ED19}

verify, head_cases = [], []


def vcase(cid, desc, st, rc, key, expect, size=None, index=None, iat=None, leaf=None):
    c = {"id": cid, "description": desc, "statement_hex": st.hex(), "receipt_hex": rc.hex(), "key": key, "expect": expect}
    if expect == "ok": c.update(tree_size=size, leaf_index=index, iat=iat)
    if leaf is not None: c["leaf_hex"] = leaf.hex()
    verify.append(c)


ix = LOG.index(HEAD[0])
for name, k in (("composite", S1), ("ed25519", ED), ("p256", EC), ("mldsa65", ML)):
    vcase("%s_ok" % name, "A %s service's receipt over head statement A in a 7-leaf log, leaf 2." % name,
          HEAD[0], receipt(LOG, ix, k), name == "composite" and "S1" or {"ed25519": "ED", "p256": "EC", "mldsa65": "ML"}[name],
          "ok", 7, ix, 1767312000)
vcase("single_leaf", "A one-leaf log: the path is empty and the root is the leaf hash.", HEAD[0],
      receipt([HEAD[0]], 0, S1), "S1", "ok", 1, 0, 1767312000)
vcase("last_leaf", "The last leaf of the 7-leaf log.", HEAD[2], receipt(LOG, 6, S1), "S1", "ok", 7, 6, 1767312000)
vcase("attached_root", "The receipt carries the root as an attached payload: it must equal the root.", HEAD[0],
      receipt(LOG, ix, S1, attach=True), "S1", "ok", 7, ix, 1767312000)
vcase("statement_carries_receipts", "The statement carries receipts in its own header: the leaf empties the "
      "unprotected header, so the receipt still verifies.", with_receipts(HEAD[0], [receipt(LOG, ix, S2)]),
      receipt(LOG, ix, S1), "S1", "ok", 7, ix, 1767312000)
vcase("alg_mismatch", "A composite receipt read under an Ed25519 key.", HEAD[0], receipt(LOG, ix, S1), "ED",
      "receipt_alg_mismatch")
vcase("kid_mismatch", "S1's receipt (kid S1) read under S2's key.", HEAD[0], receipt(LOG, ix, S1), "S2",
      "receipt_key_mismatch")
vcase("no_kid_wrong_key", "S1's receipt naming no kid, read under S2's key: the signature fails.", HEAD[0],
      receipt(LOG, ix, S1, kid=False), "S2", "receipt_bad_signature")
vcase("vds_2", "vds 2, not RFC9162_SHA256.", HEAD[0], receipt(LOG, ix, S1, vds=2), "S1", "receipt_unsupported_vds")
vcase("index_out_of_range", "The proof's leaf index is the tree size.", HEAD[0], receipt(LOG, ix, S1, edit_index=7),
      "S1", "receipt_bad_inclusion_path")
vcase("path_too_short", "The path lacks its last hash: it ends before the root.", HEAD[0],
      receipt(LOG, ix, S1, edit_path=lambda p: p[:-1]), "S1", "receipt_bad_inclusion_path")
vcase("path_flipped", "A path hash with one bit flipped: another root, so the signature fails.", HEAD[0],
      receipt(LOG, ix, S1, edit_path=lambda p: [bytes([p[0][0] ^ 1]) + p[0][1:]] + p[1:]), "S1", "receipt_bad_signature")
vcase("other_statement", "A receipt for head statement B read over statement A: another leaf, another root.",
      HEAD[0], receipt(LOG, LOG.index(HEAD[1]), S1), "S1", "receipt_bad_signature")
vcase("ed25519_alg_19_ok", "An Ed25519 key whose COSE_Key names alg -19, and a receipt under -19.", HEAD[0],
      receipt(LOG, ix, ED19), "ED19", "ok", 7, ix, 1767312000)
vcase("ed25519_alg_8_vs_19", "A receipt under -8 read with a key that names -19: the algs are not interchangeable.",
      HEAD[0], receipt(LOG, ix, Ed(98)), "ED19", "receipt_alg_mismatch")
vcase("subject_mismatch", "A receipt naming a sub other than the statement's.", HEAD[0],
      receipt(LOG, ix, S1, sub="another-accord"), "S1", "receipt_subject_mismatch")
vcase("subject_absent", "A receipt naming no sub, for a statement that names one.", HEAD[0],
      receipt(LOG, ix, S1, sub=None), "S1", "receipt_subject_mismatch")
vcase("not_sign1", "The receipt is a bare CBOR array, not tag 18.", HEAD[0], enc([1, 2, 3]), "S1", "receipt_malformed")
leaf = b"an audit entry, canonical, hash and signature emptied"
hs = [lh(leaf)] + [lh(leaf_of(s)) for s in FILLER[:2]]
root = mth(hs)
prot = enc({1: -70100, 4: S1.kid, 15: {1: S1.key.iss, 6: 1767312000}, 395: 1})
rawr = enc(Tag(18, [prot, {396: {-1: [enc([3, 0, path(0, hs)])]}}, None, S1.sign(enc(["Signature1", prot, b"", root]))]))
vcase("raw_leaf", "A receipt over a leaf that is not a row statement, read with verify_receipt_for_leaf.", b"", rawr,
      "S1", "ok", 3, 0, 1767312000, leaf=leaf)

# ---------------------------------------------------------------- receipts_of: the unsigned header is read, never refused
good = receipt(LOG, ix, S1)
junk = [b"\x01", enc([1]), enc(Tag(18, [b"", {}, None, b""])), enc(Tag(18, [enc({1: -70100}), {}, None, b"x"]))]
many = [receipt(LOG, ix, S1, iat=1767312000 + i) for i in range(18)]
receipts_of_cap = {"id": "cap_16_in_byte_order", "description": "Eighteen distinct receipts and one repeated: the held "
                   "set is the first 16 in byte order, unique.", "statement_hex": with_receipts(HEAD[0], many + [many[0]]).hex(),
                   "held_hex": [r.hex() for r in sorted(set(many))[:16]]}
receipts_of = [receipts_of_cap, {"id": "junk_ignored", "description": "Header 394 carries one receipt and four items that are not "
                "receipts (a non-CBOR byte, an array, a tag 18 without vdp, another without vdp): the receipt is held, "
                "the rest ignored.", "statement_hex": with_receipts(HEAD[0], [good] + junk).hex(),
                "held_hex": [good.hex()]}]

# ---------------------------------------------------------------- the header reader
hdr = receipt(LOG, ix, S1, iss="https://ts.example/log", sub="log-2026", iat=1767312345)
header = [{"id": "named", "receipt_hex": hdr.hex(),
           "expect": {"alg": -70100, "vds": 1, "kid_hex": S1.kid.hex(), "iss": "https://ts.example/log", "sub": "log-2026",
                      "iat": 1767312345}},
          {"id": "unnamed_vds_2", "receipt_hex": receipt(LOG, ix, ED, vds=2, drop_iat=True, kid=False, sub=None).hex(),
           "expect": {"alg": -8, "vds": 2, "kid_hex": None, "iss": None, "sub": None, "iat": None}}]

# ---------------------------------------------------------------- merges
rA0, rB0 = receipt(LOG, ix, S1), receipt(LOG, ix, S2)
merge = [{"id": "union", "held_hex": with_receipts(HEAD[0], [rA0]).hex(), "offered_hex": with_receipts(HEAD[0], [rB0, rA0]).hex(),
          "expect": "ok", "held_after_hex": [r.hex() for r in sorted({rA0, rB0})]},
         {"id": "different_statement", "held_hex": with_receipts(HEAD[0], [rA0]).hex(),
          "offered_hex": with_receipts(HEAD[1], [rB0]).hex(), "expect": "different_statement"},
         {"id": "too_many", "held_hex": with_receipts(HEAD[0], many[:10]).hex(),
          "offered_hex": with_receipts(HEAD[0], many[10:]).hex(), "expect": "too_many"}]

# ---------------------------------------------------------------- the head count
def hcase(cid, desc, statements, services, expect):
    head_cases.append({"id": cid, "description": desc, "head_payload_hex": enc(P).hex(),
                       "statements_hex": [s.hex() for s in statements], "services": services, "expect": sorted(expect)})


rA, rB, rC = (receipt(LOG, LOG.index(h), S) for h, S in ((HEAD[0], S1), (HEAD[1], S2), (HEAD[2], S3)))
three = [with_receipts(HEAD[0], [rA]), with_receipts(HEAD[1], [rB]), with_receipts(HEAD[2], [rC])]
hcase("three_services", "Three services, each one receipt, each over a different holder statement of the head.",
      three, ["S1", "S2", "S3", "S4"], ["S1", "S2", "S3"])
hcase("one_service_twice", "S1 has receipts over two statements of the head, S2 over one: S1 counts once.",
      [with_receipts(HEAD[0], [rA]), with_receipts(HEAD[1], [receipt(LOG, LOG.index(HEAD[1]), S1),
                                                              receipt(LOG, LOG.index(HEAD[1]), S2)])],
      ["S1", "S2", "S3"], ["S1", "S2"])
hcase("duplicate_entry", "The services list names S1 twice under two ids: one key, counted once (the first id).",
      three, ["S1", "S1_again"], ["S1"])
hcase("no_instant", "S2's receipt carries no iat: nothing dates it, so it does not count.",
      [with_receipts(HEAD[0], [rA]), with_receipts(HEAD[1], [receipt(LOG, LOG.index(HEAD[1]), S2, drop_iat=True)])],
      ["S1", "S2"], ["S1"])
OLOG = FILLER[:2] + [OTHER[0]]
hcase("other_head_statement", "S2's receipt is for a statement of ANOTHER head at the same place (same prev, a "
      "different payload), passed beside the head's own statements: it is not a statement of the head, so it counts "
      "for nothing (evidence of equivocation, surfaced by the caller).",
      [with_receipts(HEAD[0], [rA]), with_receipts(OTHER[0], [receipt(OLOG, 2, S2)])], ["S1", "S2"], ["S1"])
hcase("receipt_for_other_leaf_on_head", "S2's receipt over the other head's statement, carried in a head "
      "statement's header: its leaf is not this statement's, so it does not verify.",
      [with_receipts(HEAD[0], [rA, receipt(OLOG, 2, S2)])], ["S1", "S2"], ["S1"])
hcase("none", "No statement carries a receipt.", HEAD, ["S1", "S2"], [])
hcase("issuer_mismatch", "S2's receipt names S3 as its iss: it is not counted for S2.",
      [with_receipts(HEAD[0], [rA]), with_receipts(HEAD[1], [receipt(LOG, LOG.index(HEAD[1]), S2, iss=S3.key.iss)])],
      ["S1", "S2"], ["S1"])
hcase("subject_mismatch", "S2's receipt names another subject: not the statement's own sub, not counted.",
      [with_receipts(HEAD[0], [rA]), with_receipts(HEAD[1], [receipt(LOG, LOG.index(HEAD[1]), S2, sub="another-accord")])],
      ["S1", "S2"], ["S1"])
hcase("subject_absent", "S2's receipt names no sub: refused on the head path.",
      [with_receipts(HEAD[0], [rA]), with_receipts(HEAD[1], [receipt(LOG, LOG.index(HEAD[1]), S2, sub=None)])],
      ["S1", "S2"], ["S1"])

# ---------------------------------------------------------------- RFC 9162 consistency (2.1.4)
def subproof(m, d, b):
    n = len(d)
    if m == n: return [] if b else [mth(d)]
    k = 1
    while k * 2 < n: k *= 2
    return subproof(m, d[:k], b) + [mth(d[k:])] if m <= k else subproof(m - k, d[k:], False) + [mth(d[:k])]


cons = []
for n in range(1, 9):
    for m in range(1, n + 1):
        cons.append({"old_size": m, "new_size": n, "old_root_hex": None, "new_root_hex": None,
                     "proof_hex": [h.hex() for h in subproof(m, [lh(bytes([i])) for i in range(n)], True)], "expect": True})
Lc = [lh(bytes([i])) for i in range(8)]
for c in cons:
    c["old_root_hex"], c["new_root_hex"] = mth(Lc[:c["old_size"]]).hex(), mth(Lc[:c["new_size"]]).hex()
bad = dict(cons[-5]); bad = {**bad, "old_root_hex": mth(Lc[:2] + [lh(b"x")] + Lc[3:bad["old_size"]]).hex(), "expect": False}
cons.append(bad)
# ---------------------------------------------------------------- RFC 9162 inclusion known answers
incl = []
L = [lh(bytes([i])) for i in range(8)]
for n in range(1, 9):
    for m in range(n):
        incl.append({"tree_size": n, "leaf_index": m, "leaf_hash_hex": L[m].hex(),
                     "path_hex": [h.hex() for h in path(m, L[:n])], "root_hex": mth(L[:n]).hex()})

json.dump({
    "_meta": {"spec": "RFC 9942 / RFC 9162 / RFC 9943; CC 2.7.11; the rc22 head-receipt model (CC 3.2 T6)",
              "generator": "gen_receipts.py over gen_genesis_bundles_v5.py (independent of verify)",
              "keys": "composite services S1..S4 = Key 91..94 (ML-DSA-65 seed [n]*32, Ed25519 [n+100]*32); ED Ed25519 seed "
                      "[95]*32; EC P-256 scalar sha256([96]) mod 2^255; ML ML-DSA-65 seed [97]*32",
              "iat": "1767312000 unless stated"},
    "keys": {n: {"cose_key_hex": k.cose.hex(), "composite_hex": k.key.pub.hex() if isinstance(k, Comp) else None,
                 "thumbprint_hex": k.thumb.hex(), "alg": k.alg,
                 "identity_ref": k.key.iss if isinstance(k, Comp) else None}
             for n, k in keys.items()} | {"S1_again": {"cose_key_hex": S1.cose.hex(), "composite_hex": S1.key.pub.hex(),
                                                       "thumbprint_hex": S1.thumb.hex(), "alg": -70100,
                                                       "identity_ref": S1.key.iss + "-again"}},
    "mint": {"description": "S1's receipt for LOG leaf 2 with iss S1, the statement's sub and iat 1767312000: a "
                            "minter must produce these bytes.", "iss": S1.key.iss,
             "log_hex": [st.hex() for st in LOG], "index": ix, "iat": 1767312000, "receipt_hex": receipt(LOG, ix, S1).hex(),
             "ml_seed_hex": (bytes([91]) * 32).hex(), "ed_seed_hex": (bytes([191]) * 32).hex()},
    "verify": verify, "receipts_of": receipts_of, "header": header, "merge": merge, "head": head_cases,
    "inclusion": incl, "consistency": cons,
}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
