# Independent generator of `ceg-genesis-bundle/2` known answers (CC 2.6.1.11, CIRISConstitution rc20 ae09856).
#
# Its own CBOR deterministic encoder, dilithium-py (FIPS 204, deterministic), pyca/cryptography (Ed25519,
# X25519, X.509) and kyber-py (ML-KEM-768, for real X-Wing public keys). It shares no code with verify.
# The CBOR encoder and the composite signer are copied from ../gen_row_statements.py.
#
#   python3 -I gen_genesis_bundles.py --cc /path/to/build_cc_signed_object_v2.py --out .
#
# It writes genesis_bundles_v1.json (the cases) and pool_0.json .. pool_3.json (the statements, split by the
# first hex character of their key, so each file stays under the repository's 1000 KB limit).
#
# With --cc it also loads CC's reference bundle reader and its broken samples (the tool at CIRISConstitution
# ae09856), embeds the samples' bytes, and runs the reference reader over every first-bundle case,
# recording its answer beside ours.
import base64, datetime, hashlib, importlib.util, json, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

PREFIX = b"CompositeAlgorithmSignatures2025"
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"
GTYP = "ceg-genesis-bundle/2"
IREF = "urn:ietf:params:oauth:ckt:sha-256:"


class Tag:
    def __init__(self, n, v): self.n, self.v = n, v


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
    raise TypeError(v)


def sha(b): return hashlib.sha256(b).digest()
def iref_of(d): return IREF + base64.urlsafe_b64encode(d).rstrip(b"=").decode()
def cset(xs): return sorted(xs, key=enc)          # a CBOR set: sorted by encoding
def hd(d): return [-16, d]
def rref(d): return [2, hd(d)]


class Key:
    def __init__(self, n, ed_seed=None):
        self.n = n
        self.ml_seed = bytes([n]) * 32
        self.ed_seed = ed_seed or bytes([(n + 100) % 256]) * 32
        self.ml_pk, self.ml_sk = ML_DSA_65.key_derive(self.ml_seed)
        self.ed = Ed25519PrivateKey.from_private_bytes(self.ed_seed)
        self.ed_pk = self.ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        self.pub = self.ml_pk + self.ed_pk
        assert len(self.pub) == 1984
        self.cose = {1: 7, 3: -70100, -1: self.pub}
        self.kid = sha(enc(self.cose))
        self.iss = iref_of(self.kid)

    def sign(self, m):
        mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(m).digest()
        s = ML_DSA_65.sign(self.ml_sk, mp, ctx=LABEL, deterministic=True) + self.ed.sign(mp)
        assert len(s) == 3373
        return s


def row(k, family, payload, sub=None, iss=None, sig_edit=None):
    """A row statement (CC 2.6.1.1) signed by k; returns (bytes, row id)."""
    claims = {1: iss or k.iss, 2: sub or k.iss, 6: payload["asserted_at"] // 1000, -70003: 2}
    if "valid_until" in payload: claims[4] = payload["valid_until"] // 1000
    prot = {1: -70100, 3: "application/vnd.ciris.row+cbor", 4: k.kid, 15: claims, 16: "ceg-row/2",
            -70001: "scores", -70002: family}
    pb, plb = enc(prot), enc(payload)
    sig = k.sign(enc(["Signature1", pb, b"", plb]))
    if sig_edit: sig = sig_edit(sig)
    rid = sha(enc(["CEG-row/2", "scores", family, sub or k.iss, payload.get("author"), plb]))
    return enc(Tag(18, [pb, {}, plb, sig])), rid


def object_id(plb, author=None): return sha(enc(["CEG-object/2", GTYP, author, plb]))


def voice(k, payload, iat=None, iss=None, typ=GTYP, drop_iat=False, sig_edit=None, signer=None):
    """One holder's statement over a bundle payload: protected exactly {1, 4, 15, 16}."""
    plb = enc(payload)
    claims = {1: iss or k.iss, -70003: 2}
    if not drop_iat: claims[6] = payload["asserted_at"] // 1000 if iat is None else iat
    s = signer or k
    prot = {1: -70100, 4: s.kid, 15: claims, 16: typ}
    pb = enc(prot)
    sig = s.sign(enc(["Signature1", pb, b"", plb]))
    if sig_edit: sig = sig_edit(sig)
    return enc(Tag(18, [pb, {}, plb, sig]))


def flip(sig): return sig[:-1] + bytes([sig[-1] ^ 1])


# ---------------------------------------------------------------- X-Wing (draft-connolly-cfrg-xwing-kem-11 §5.2)
def xwing_pk(seed):
    x = hashlib.shake_256(seed).digest(96)
    ek, _ = ML_KEM_768._keygen_internal(x[:32], x[32:64])
    pkx = X25519PrivateKey.from_private_bytes(x[64:]).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    assert len(ek) == 1184 and len(pkx) == 32
    return ek + pkx


def x25519_pub(seed):
    return X25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def ed25519_pub(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def rns_destination_hash(x, e, app, aspects):          # CC 3.3.6.3
    name = app + "".join("." + a for a in aspects)
    nh = sha(name.encode())[:10]
    ih = sha(x + e)[:16]
    return sha(nh + ih)[:16]


# ---------------------------------------------------------------- the mock YubiKey PIV PKI (CC 4.2.2.1)
NB = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NA = datetime.datetime(2099, 12, 31, tzinfo=datetime.timezone.utc)
OID_FW, OID_TOUCH, OID_FIPS = "1.3.6.1.4.1.41482.3.3", "1.3.6.1.4.1.41482.3.8", "1.3.6.1.4.1.41482.3.10"


def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, issuer, pub, signer, serial, exts=()):
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(pub)
         .serial_number(serial).not_valid_before(NB).not_valid_after(NA))
    for oid, val in exts:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), val), critical=False)
    return b.sign(signer, None).public_bytes(ser.Encoding.DER)


class CA:
    def __init__(self, label):
        self.key = Ed25519PrivateKey.from_private_bytes(sha(label.encode()))
        self.cn = label
        self.der = cert(label, label, self.key.public_key(), self.key, 1)


ROOT = CA("Yubico PIV Attestation (MOCK root, test only)")
UNTRUSTED = CA("Untrusted attestation root (test only)")


def yubikey_chain(ed_pub, n, ca=ROOT, fips=True, touch=2):
    """[9c leaf, f9]: the leaf attests ed_pub; f9 carries FIPS (.10); the leaf firmware 5.7.4 and touch."""
    f9k = Ed25519PrivateKey.from_private_bytes(sha(b"f9" + bytes([n]) + ca.cn.encode()))
    f9cn = "YubiKey PIV Attestation f9 (MOCK %d)" % n
    f9 = cert(f9cn, ca.cn, f9k.public_key(), ca.key, 100 + n, [(OID_FIPS, b"")] if fips else [])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    leaf = cert("YubiKey PIV Attestation 9c (MOCK %d)" % n, f9cn, Ed25519PublicKey.from_public_bytes(ed_pub), f9k,
                200 + n, [(OID_FW, b"\x04\x03\x05\x07\x04"), (OID_TOUCH, b"\x04\x02\x01" + bytes([touch]))])
    return [leaf, f9]


# ---------------------------------------------------------------- parties and rows
T0 = 1767225600000                      # the records' instant
T1 = T0 + 86_400_000 + 123              # the first bundle's
T2 = T1 + 30 * 86_400_000               # a later bundle's
YEAR = 31_536_000_000

A, B, C, D = Key(1), Key(2), Key(3), Key(4)          # holders; D joins later
S1, S2 = Key(11), Key(12)                            # seats
W1, W2, W3 = Key(21), Key(22), Key(23)               # witnesses
X = Key(9)                                           # a stranger
A2 = Key(31)                                         # another key under A's name
C2 = Key(33)                                         # a key C rotated to, never held
REC = {k.n: Key(k.n + 50) for k in (A, B, C, D)}     # each holder's recovery key


def commitment(keys): return sha(enc(["CEG-recovery/2", cset([k.cose for k in keys])]))


def holder_record(k, ev=None, key=None, roles=("accord_holder",), signer=None):
    if ev is None:
        ev = {"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
              "chain": yubikey_chain((key or k).ed_pk, k.n)}
    p = {"key": (key or k).cose, "author": k.iss, "asserted_at": T0, "identity_type": cset(list(roles))}
    if ev != "none": p["attestation_evidence"] = ev
    return row(signer or key or k, "key:record", p, sub=k.iss, iss=k.iss)


def seat_record(k, roles=("node",), until=T0 + YEAR, sig_edit=None):
    p = {"key": k.cose, "author": k.iss, "asserted_at": T0, "identity_type": cset(list(roles)), "valid_until": until}
    return row(k, "key:record", p, sig_edit=sig_edit)


def witness_record(k):
    return row(k, "key:record", {"key": k.cose, "author": k.iss, "asserted_at": T0, "identity_type": ["witness"]})


def seat_keys(k):
    return xwing_pk(sha(b"transit" + bytes([k.n]))), xwing_pk(sha(b"onion" + bytes([k.n])))


def binding(k, signer=None, edit=None, author=None):
    t, o = seat_keys(k)
    rx, re_ = x25519_pub(sha(b"rns-x" + bytes([k.n]))), ed25519_pub(sha(b"rns-ed" + bytes([k.n])))
    td = {"reticulum_x25519_pubkey": rx, "reticulum_ed25519_pubkey": re_, "app_name": "ciris.federation",
          "aspects": ["serve"], "destination_hash": rns_destination_hash(rx, re_, "ciris.federation", ["serve"])}
    p = {"author": author or k.iss, "asserted_at": T0, "transport_destination": td,
         "transit_xwing_pubkey": t, "onion_hop_xwing_pubkey": o}
    if edit: edit(p)
    s = signer or k
    return row(s, "identity:occurrence", p, sub=(author or k.iss), iss=(author or k.iss) if signer is None else s.iss)


POOL = {}                                  # sha256 prefix -> hex
def put(b):
    k = sha(b).hex()[:16]
    POOL[k] = b.hex()
    return k


R = {}                                     # name -> (bytes, row id)
for k in (A, B, C, D): R["rec_" + str(k.n)] = holder_record(k)
for k in (S1, S2): R["rec_" + str(k.n)] = seat_record(k); R["bind_" + str(k.n)] = binding(k)
for k in (W1, W2, W3): R["rec_" + str(k.n)] = witness_record(k)
R["rec_9"] = row(X, "key:record", {"key": X.cose, "author": X.iss, "asserted_at": T0, "identity_type": ["user"]})


def payload(holders=(A, B, C), seats=(S1, S2), witnesses=(), rows=None, version=1, prev=None, at=T1,
            commits=None, scope=("infra:attest", "infra:serve"), charter_edit=None, edit=None, fam="humanity-accord"):
    if rows is None:
        rows = [R["rec_%d" % k.n][1] for k in (*holders, *seats, *witnesses)] + [R["bind_%d" % k.n][1] for k in seats]
    refs = {"also": {"cites": cset([rref(r) for r in rows])}}
    if prev is not None: refs["prev"] = rref(prev)
    ch = {"recovery_commitments": commits or {h.iss: hd(commitment([REC[h.n]])) for h in holders},
          "scope": cset(list(scope)), "halt_fuse_secs": 86400}
    if witnesses:
        ch.update(witnesses=cset([w.iss for w in witnesses]), witness_quorum=len(witnesses) // 2 + 1,
                  witness_cadence_secs=86400, attach_window_secs=604800)
    if charter_edit: charter_edit(ch)
    p = {"refs": refs, "version": version, "asserted_at": at, "family_key_id": fam,
         "holders": cset([h.iss for h in holders]), "serve_nodes": cset([s.iss for s in seats]), "charter": ch}
    if edit: edit(p)
    return p


def held(*names, extra=()):
    return [{"id": R[n][1].hex(), "statement": put(R[n][0])} for n in names] + list(extra)


ALL = ["rec_1", "rec_2", "rec_3", "rec_11", "rec_12", "bind_11", "bind_12"]
WIT = ALL + ["rec_21", "rec_22", "rec_23"]
LATER = ["rec_1", "rec_2", "rec_4", "rec_11", "rec_12", "bind_11", "bind_12"]
TPS = lambda ks: {"thumbprints": sorted(k.kid.hex() for k in ks)}

cases, cc_projections = [], {}


def case(cid, desc, statements, rows, anchor, expect, predecessors=(), top_refused=(), cc=None, forks=None):
    """expect: one entry per object id the statements carry."""
    c = {"id": cid, "description": desc, "statements": [put(s) for s in statements], "rows": rows,
         "anchor": anchor, "predecessors": list(predecessors), "expect": expect,
         "top_refused": list(top_refused)}
    if forks is not None: c["forks"] = forks
    cases.append(c)
    if cc: cc_projections[cid] = cc


def bundle(oid, verdict, token=None, detail=None, refused=(), placement=None, waiting=None):
    e = {"object_id": oid.hex(), "verdict": verdict, "refused": [{"index": i, "fault": f} for i, f in refused]}
    if token: e["token"] = token
    if detail: e["detail"] = detail
    if placement: e["placement"] = placement
    if waiting: e["waiting"] = waiting
    return e


def placement_of(p, holders, seats, witnesses, counted):
    out = {"version": p["version"], "asserted_at": p["asserted_at"], "family_key_id": p["family_key_id"],
           "prev": p["refs"]["prev"][1][1].hex() if "prev" in p["refs"] else None,
           "holders": [], "seats": [], "witnesses": [], "counted": sorted(k.iss for k in counted),
           "halt_fuse": p["charter"].get("halt_fuse_secs", 86400), "scope": p["charter"]["scope"]}
    for h in sorted(holders, key=lambda k: enc(k.iss)):
        out["holders"].append({"identity_ref": h.iss, "kid": h.kid.hex(), "record": R["rec_%d" % h.n][1].hex(),
                               "recovery_commitment": p["charter"]["recovery_commitments"][h.iss][1].hex(),
                               "hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline"})
    for s in sorted(seats, key=lambda k: enc(k.iss)):
        t, o = seat_keys(s)
        out["seats"].append({"identity_ref": s.iss, "kid": s.kid.hex(), "record": R["rec_%d" % s.n][1].hex(),
                             "binding": R["bind_%d" % s.n][1].hex(), "valid_until": T0 + YEAR,
                             "transit_xwing_pubkey_sha256": sha(t).hex(), "onion_hop_xwing_pubkey_sha256": sha(o).hex(),
                             "transit_seed": sha(b"transit" + bytes([s.n])).hex(),
                             "onion_seed": sha(b"onion" + bytes([s.n])).hex()})
    for w in sorted(witnesses, key=lambda k: enc(k.iss)):
        out["witnesses"].append({"identity_ref": w.iss, "kid": w.kid.hex(), "record": R["rec_%d" % w.n][1].hex()})
    return out


# Party of each named row, for the projection.
PARTY = {}
for k in (A, B, C, D, S1, S2, W1, W2, W3, X):
    PARTY[R["rec_%d" % k.n][1]] = ("key:record", k.iss)
    if "bind_%d" % k.n in R: PARTY[R["bind_%d" % k.n][1]] = ("identity:occurrence", k.iss)


def ccp(p, voices_keys, row_ids, anchor, custody=None, iat=None, extra_rows=None):
    """A CC projection: voices (iss, iat), held rows (family, author, extra)."""
    rows = {}
    for rid in row_ids:
        fam, author = PARTY[rid]
        extra = {}
        if fam == "key:record" and author in p["holders"]:
            extra = {"chain_verifies": True, "pq_custody": "removable_offline"}
        if fam == "identity:occurrence":
            extra = {"xwing": ["transit", "onion"]}
        rows[rid] = (fam, author, extra)
    for rid, v in (extra_rows or {}).items(): rows[rid] = v
    for author, ext in (custody or {}).items():
        rid = [r for r, (f, a, _) in rows.items() if f == "key:record" and a == author][0]
        rows[rid] = ("key:record", author, ext)
    vs = [(k.iss, (iat or {}).get(k.iss, p["asserted_at"] // 1000)) for k in voices_keys]
    return {"p": p, "voices": vs, "rows": rows, "anchor": anchor}


def ids(names): return [R[n][1] for n in names]


def anchor_cc(a, p):
    if a is None: return None
    if "thumbprints" in a: return ("thumbprints", [iref_of(bytes.fromhex(t)) for t in a["thumbprints"]])
    return ("object_id", [-16, bytes.fromhex(a["object_id"])])


# ================================================================ first bundles
P = payload()
PB = enc(P)
OID = object_id(PB)
V3 = [voice(k, P) for k in (A, B, C)]
GOOD_PLACEMENT = placement_of(P, (A, B, C), (S1, S2), (), (A, B, C))
an = TPS((A, B, C))
case("first_valid", "The first bundle: three holders, two seats, every holder signed, thumbprint anchor.",
     V3, held(*ALL), an, [bundle(OID, "valid", placement=GOOD_PLACEMENT)],
     cc=ccp(P, (A, B, C), ids(ALL), an))
an_oid = {"object_id": OID.hex()}
case("first_valid_object_id_anchor", "The same bundle under its object id as the anchor.",
     V3, held(*ALL), an_oid, [bundle(OID, "valid", placement=GOOD_PLACEMENT)],
     cc=ccp(P, (A, B, C), ids(ALL), an_oid))
case("first_valid_with_stranger", "The valid bundle and a fourth statement by a key in no role: refused, the rest stand.",
     V3 + [voice(X, P)], held(*ALL, "rec_9"), an,
     [bundle(OID, "valid", refused=[(3, "statement_no_role")], placement=GOOD_PLACEMENT)])

PW = payload(witnesses=(W1, W2, W3))
OW = object_id(enc(PW))
case("first_valid_witnessed", "Witnessed mode on: three witnesses, quorum 2, each witness's record cited.",
     [voice(k, PW) for k in (A, B, C)], held(*WIT), an,
     [bundle(OW, "valid", placement=placement_of(PW, (A, B, C), (S1, S2), (W1, W2, W3), (A, B, C)))],
     cc=ccp(PW, (A, B, C), ids(WIT), an))

# --- count and voices
case("missing_holder_signature", "Two of three holders signed a first bundle: the count is unmet.",
     V3[:2], held(*ALL), an, [bundle(OID, "nothing", "genesis_bundle_count_unmet")],
     cc=ccp(P, (A, B), ids(ALL), an))
case("iat_off_by_one", "C's statement carries iat one second late: that statement is refused (iat_mismatch); "
     "the count is unmet. CC's reference reader answers Invalid iat_mismatch for the bundle.",
     V3[:2] + [voice(C, P, iat=P["asserted_at"] // 1000 + 1)], held(*ALL), an,
     [bundle(OID, "nothing", "genesis_bundle_count_unmet", refused=[(2, "iat_mismatch")])],
     cc=ccp(P, (A, B, C), ids(ALL), an, iat={C.iss: P["asserted_at"] // 1000 + 1}))
case("statement_without_iat", "C's statement carries no iat: refused before grouping; the count is unmet.",
     V3[:2] + [voice(C, P, drop_iat=True)], held(*ALL), an,
     [bundle(OID, "nothing", "genesis_bundle_count_unmet")], top_refused=[{"index": 2, "fault": "iat_missing"}])
case("bad_signature_voice", "C's signature has one byte flipped: refused; the count is unmet.",
     V3[:2] + [voice(C, P, sig_edit=flip)], held(*ALL), an,
     [bundle(OID, "nothing", "genesis_bundle_count_unmet", refused=[(2, "statement_invalid")])])
case("kid_not_iss", "A's statement names A's iss but is signed under another key: refused in a first bundle.",
     [voice(A, P, signer=A2)] + V3[1:], held(*ALL), an,
     [bundle(OID, "nothing", "genesis_bundle_count_unmet", refused=[(0, "statement_kid_not_iss")])])
RS, _rsid = R["rec_11"]
case("row_offered_as_voice", "A row statement offered as a bundle voice: refused; the count is unmet.",
     V3[:2] + [RS], held(*ALL), an, [bundle(OID, "nothing", "genesis_bundle_count_unmet")],
     top_refused=[{"index": 2, "fault": "statement_invalid"}])
case("wrong_typ", "A statement of typ ceg-revocation-snapshot/2 over the same payload: refused.",
     V3[:2] + [voice(C, P, typ="ceg-revocation-snapshot/2")], held(*ALL), an,
     [bundle(OID, "nothing", "genesis_bundle_count_unmet")],
     top_refused=[{"index": 2, "fault": "statement_not_genesis_bundle"}])

# --- anchor
an_bad = TPS((A, B, X))
case("anchor_thumbprints_mismatch", "A holder set unlike the thumbprint anchor: not anchored.",
     V3, held(*ALL), an_bad, [bundle(OID, "nothing", "genesis_bundle_not_anchored")],
     cc=ccp(P, (A, B, C), ids(ALL), an_bad))
an_zero = {"object_id": "00" * 32}
case("anchor_object_id_mismatch", "An object id unlike the anchor: not anchored.",
     V3, held(*ALL), an_zero, [bundle(OID, "nothing", "genesis_bundle_not_anchored")],
     cc=ccp(P, (A, B, C), ids(ALL), an_zero))
case("no_anchor", "A reader with no anchor promotes nothing to a root.",
     V3, held(*ALL), None, [bundle(OID, "nothing", "genesis_bundle_not_anchored")])

# --- named rows
case("cited_row_not_held", "Seat 1's key record is named but not held: Waiting on it.",
     V3, [r for r in held(*ALL) if r["id"] != R["rec_11"][1].hex()], an,
     [bundle(OID, "waiting", waiting={"rows": [R["rec_11"][1].hex()], "prev": None, "kids": []})],
     cc=ccp(P, (A, B, C), [r for r in ids(ALL) if r != R["rec_11"][1]], an))
case("cited_row_misfiled", "A row held under another id than the one named: the named row is not held.",
     V3, [r for r in held(*ALL) if r["id"] != R["rec_11"][1].hex()] + [{"id": R["rec_11"][1].hex(), "statement": put(R["rec_12"][0])}],
     an, [bundle(OID, "waiting", waiting={"rows": [R["rec_11"][1].hex()], "prev": None, "kids": []})])
P_nob = payload(rows=ids(ALL[:-1]))
case("seat_binding_not_cited", "Seat 2's binding is not in cites: a seat with no binding, unplaced.",
     [voice(k, P_nob) for k in (A, B, C)], held(*ALL[:-1]), an,
     [bundle(object_id(enc(P_nob)), "nothing", "genesis_bundle_row_unplaced")],
     cc=ccp(P_nob, (A, B, C), ids(ALL[:-1]), an))
P_extra = payload(rows=ids(ALL) + [R["rec_9"][1]])
case("cited_row_unplaced", "A stranger's key record named in cites: a row with no place.",
     [voice(k, P_extra) for k in (A, B, C)], held(*ALL, "rec_9"), an,
     [bundle(object_id(enc(P_extra)), "nothing", "genesis_bundle_row_unplaced")],
     cc=ccp(P_extra, (A, B, C), ids(ALL) + [R["rec_9"][1]], an))
A_dup = holder_record(A, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
                             "chain": yubikey_chain(A.ed_pk, 1)}, roles=("accord_holder", "steward"))
PARTY[A_dup[1]] = ("key:record", A.iss)
P_dup = payload(rows=ids(ALL) + [A_dup[1]])
case("two_records_for_one_holder", "Two key records by holder A: two rows for one place.",
     [voice(k, P_dup) for k in (A, B, C)], held(*ALL, extra=[{"id": A_dup[1].hex(), "statement": put(A_dup[0])}]), an,
     [bundle(object_id(enc(P_dup)), "nothing", "genesis_bundle_row_unplaced")],
     cc=ccp(P_dup, (A, B, C), ids(ALL) + [A_dup[1]], an))


def swap_row(name, new):
    """The bundle naming `new` in place of R[name]; returns (payload, rows held, oid)."""
    PARTY[new[1]] = PARTY[R[name][1]]
    names = [n for n in ALL if n != name]
    p = payload(rows=ids(names) + [new[1]])
    return p, held(*names, extra=[{"id": new[1].hex(), "statement": put(new[0])}]), object_id(enc(p)), ids(names) + [new[1]]


def row_case(cid, desc, name, new, token, detail, cc_custody=None):
    p, rows, oid, rids = swap_row(name, new)
    party = PARTY[new[1]][1]
    case(cid, desc, [voice(k, p) for k in (A, B, C)], rows, an, [bundle(oid, "nothing", token, detail)],
         cc=ccp(p, (A, B, C), rids, an, custody=cc_custody) if cc_custody is not None else None)


row_case("named_row_bad_signature", "Seat 1's key record with a flipped signature byte (same row id): Invalid as a row.",
         "rec_11", seat_record(S1, sig_edit=flip), "genesis_bundle_row_invalid", "row_invalid")
row_case("seat_record_not_node", "Seat 1's record is node + pseudonym, not exactly node.",
         "rec_11", seat_record(S1, roles=("node", "pseudonym")), "genesis_bundle_row_invalid", "seat_not_node")
row_case("seat_record_without_end", "Seat 1's node record has no valid_until: key_record_out_of_window.",
         "rec_11", row(S1, "key:record", {"key": S1.cose, "author": S1.iss, "asserted_at": T0, "identity_type": ["node"]}),
         "genesis_bundle_row_invalid", "key_record_out_of_window")
row_case("holder_record_not_accord_holder", "Holder B's record carries user, not accord_holder.",
         "rec_2", holder_record(B, roles=("user",)), "genesis_bundle_row_invalid", "holder_not_accord_holder")
row_case("holder_record_not_genesis_key", "Holder A's record (author A) records another key: not A's genesis key.",
         "rec_1", holder_record(A, key=A2), "genesis_bundle_row_invalid", "holder_not_genesis_key")
row_case("holder_record_signed_by_other", "Holder A's record signed by B's key: not signed by the key it records.",
         "rec_1", holder_record(A, signer=B), "genesis_bundle_row_invalid", "row_signer")

# --- CC's key-record samples, as a holder's named record (CC 4.2.2.1)
row_case("holder_pq_custody_unknown", "CC sample: a pq_custody outside the three (token): the record is refused.",
         "rec_1", holder_record(A, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "token",
                                       "chain": yubikey_chain(A.ed_pk, 1)}),
         "genesis_bundle_row_invalid", "key_record_bad_pq_custody")
row_case("holder_chain_in_hex", "CC sample: a chain in hex (text, not bytes): the record is refused.",
         "rec_1", holder_record(A, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
                                       "chain": ["3082"]}),
         "genesis_bundle_row_invalid", "key_record_bad_attestation_evidence")
row_case("holder_chain_empty", "CC sample: an empty chain: the record is refused.",
         "rec_1", holder_record(A, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
                                       "chain": []}),
         "genesis_bundle_row_invalid", "key_record_bad_attestation_evidence")

# --- the custody gate (CC 4.2.2.1)
row_case("holder_not_removable_offline", "Holder A's ML-DSA half software_wrapped: fails the gate.",
         "rec_1", holder_record(A, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "software_wrapped",
                                       "chain": yubikey_chain(A.ed_pk, 1)}),
         "genesis_holder_custody", "custody_pq_not_removable_offline",
         cc_custody={A.iss: {"chain_verifies": True, "pq_custody": "software_wrapped"}})
row_case("holder_chain_untrusted_root", "Holder B's chain verifies only to a root the reader does not trust.",
         "rec_2", holder_record(B, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
                                       "chain": yubikey_chain(B.ed_pk, 2, ca=UNTRUSTED)}),
         "genesis_holder_custody", "custody_chain_invalid",
         cc_custody={B.iss: {"chain_verifies": False, "pq_custody": "removable_offline"}})
row_case("holder_attested_key_mismatch", "Holder C's chain attests an Ed25519 key that is not its record's half.",
         "rec_3", holder_record(C, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
                                       "chain": yubikey_chain(X.ed_pk, 3)}),
         "genesis_holder_custody", "custody_attested_key_mismatch",
         cc_custody={C.iss: {"chain_verifies": False, "pq_custody": "removable_offline"}})
row_case("holder_not_fips", "Holder A's f9 certificate carries no FIPS extension: the floor is not met.",
         "rec_1", holder_record(A, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
                                       "chain": yubikey_chain(A.ed_pk, 1, fips=False)}),
         "genesis_holder_custody", "custody_floor_not_met")
row_case("holder_no_chain", "Holder A asserts YubiKey_5_FIPS with no chain: unattested, not seated.",
         "rec_1", holder_record(A, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline"}),
         "genesis_holder_custody", "custody_unattested",
         cc_custody={A.iss: {"chain_verifies": False, "pq_custody": "removable_offline"}})
row_case("holder_no_evidence", "Holder A's record carries no attestation_evidence: no class, not seated.",
         "rec_1", holder_record(A, ev="none"), "genesis_holder_custody", "custody_no_class")

# --- seat bindings (CC 3.3.6.2)
def bind_case(cid, desc, b, detail):
    row_case(cid, desc, "bind_11", b, "genesis_bundle_row_invalid", detail)


def setk(k, v): return lambda p: p.__setitem__(k, v)


T11, O11 = seat_keys(S1)
bind_case("binding_other_signer", "Seat 1's binding (author S1) signed by seat 2's key.",
          binding(S1, signer=S2), "row_signer")
bind_case("binding_transit_short", "transit_xwing_pubkey of 1215 bytes.",
          binding(S1, edit=setk("transit_xwing_pubkey", T11[:1215])), "binding_xwing_member")
bind_case("binding_onion_missing", "No onion_hop_xwing_pubkey.",
          binding(S1, edit=lambda p: p.pop("onion_hop_xwing_pubkey")), "binding_xwing_member")
bind_case("binding_shared_x25519_half", "The onion key's X25519 half equals the transit key's.",
          binding(S1, edit=setk("onion_hop_xwing_pubkey", O11[:1184] + T11[1184:])), "onion_hop_x25519_reuse")
bind_case("binding_transit_reuses_transport_x25519", "The transit key's X25519 half is the RNS link x25519.",
          binding(S1, edit=lambda p: p["transport_destination"].__setitem__("reticulum_x25519_pubkey", T11[1184:])),
          "transit_x25519_reuse")
bind_case("binding_onion_reuses_signer", "The onion key's X25519 half is the seat's own Ed25519 half.",
          binding(S1, edit=setk("onion_hop_xwing_pubkey", O11[:1184] + S1.ed_pk)), "onion_hop_x25519_reuse")
bind_case("binding_earlier_pair", "The binding also carries the earlier transit_kex_pubkeys pair.",
          binding(S1, edit=setk("transit_kex_pubkeys", {"x25519": bytes(32), "ml_kem_768": bytes(1184)})),
          "binding_earlier_transit_pair")
bind_case("binding_opted_out", "The seat carries onion_relay.opt_out: seat_opted_out.",
          binding(S1, edit=setk("onion_relay", {"opt_out": True})), "seat_opted_out")
bind_case("binding_no_transport_destination", "An identity:occurrence by the seat with no transport_destination.",
          binding(S1, edit=lambda p: p.pop("transport_destination")), "binding_no_transport_destination")

# --- the payload rule (genesis_bundle_malformed)
def bad_payload(cid, desc, p, reason, cc=True):
    oid = object_id(enc(p))
    case(cid, desc, [voice(k, p) for k in (A, B, C)], held(*ALL), an,
         [bundle(oid, "invalid", "genesis_bundle_malformed", reason)],
         cc=ccp(p, (A, B, C), ids(ALL), an) if cc else None)


bad_payload("version_2_no_prev", "version 2 with no prev.", payload(version=2), "version_prev_mismatch")
bad_payload("version_1_with_prev", "version 1 with a prev.", payload(prev=OID), "version_prev_mismatch")
bad_payload("holders_seats_overlap", "A holder also listed in serve_nodes.",
            payload(edit=lambda p: p.__setitem__("serve_nodes", cset([A.iss, S1.iss]))), "holders_seats_overlap")
bad_payload("witness_is_a_seat", "A seat also listed as a witness.",
            payload(witnesses=(W1, W2, W3), rows=ids(WIT),
                    charter_edit=lambda c: c.__setitem__("witnesses", cset([W1.iss, W2.iss, S1.iss]))),
            "holders_seats_overlap", cc=False)
bad_payload("recovery_commitments_not_holders", "Commitments keyed by two of the three holders.",
            payload(commits={h.iss: hd(commitment([REC[h.n]])) for h in (A, B)}), "recovery_commitments_not_holders")
bad_payload("scope_missing_infra", "scope without infra:attest.", payload(scope=("infra:serve", "infra:store")),
            "scope_missing_infra")
bad_payload("witness_members_partial", "witnesses and witness_quorum without witness_cadence_secs.",
            payload(witnesses=(W1, W2, W3), rows=ids(WIT), charter_edit=lambda c: c.pop("witness_cadence_secs")),
            "witness_members_partial", cc=False)
bad_payload("witness_quorum_mismatch", "Three witnesses with quorum 3 (floor(3/2)+1 is 2).",
            payload(witnesses=(W1, W2, W3), rows=ids(WIT), charter_edit=lambda c: c.__setitem__("witness_quorum", 3)),
            "witness_quorum_mismatch", cc=False)
bad_payload("holders_unsorted", "holders not in CDE order.",
            payload(edit=lambda p: p.__setitem__("holders", list(reversed(p["holders"])))),
            "federation_set_semantics_unsorted", cc=False)
bad_payload("cites_edition_1", "A cites row-ref of edition 1.",
            payload(edit=lambda p: p["refs"]["also"].__setitem__("cites", cset([[1, hd(r)] for r in ids(ALL)]))),
            "genesis_bundle_schema", cc=False)
bad_payload("halt_fuse_zero", "halt_fuse_secs 0.", payload(charter_edit=lambda c: c.__setitem__("halt_fuse_secs", 0)),
            "genesis_bundle_schema", cc=False)

# ================================================================ later bundles
PL = payload(holders=(A, B, D), rows=ids(LATER), version=2, prev=OID, at=T2)
OL = object_id(enc(PL))
PRE = [{"case": "first_valid"}]
LP = placement_of(PL, (A, B, D), (S1, S2), (), (A, B, D))
case("later_valid", "Version 2: C swapped for D; a strict majority of the predecessor's holders (A, B) and D sign.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None, [bundle(OL, "valid", placement=LP)], predecessors=PRE)
case("later_removed_holder_counts", "A and the removed holder C (under its key from the predecessor) are the "
     "majority; D, the added holder, signs.",
     [voice(k, PL) for k in (A, C, D)], held(*LATER), None,
     [bundle(OL, "valid", placement=placement_of(PL, (A, B, D), (S1, S2), (), (A, C, D)))], predecessors=PRE)
case("later_added_holder_unsigned", "A and B sign but D, the added holder, does not: the count is unmet.",
     [voice(k, PL) for k in (A, B)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_count_unmet")], predecessors=PRE)
case("later_minority", "A and D only: one of three predecessor holders is no majority.",
     [voice(k, PL) for k in (A, D)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_count_unmet")], predecessors=PRE)
case("later_voice_key_not_held", "C signs under a key C rotated to (not held, not in the predecessor): Waiting on it.",
     [voice(A, PL), voice(C, PL, iss=C.iss, signer=C2), voice(D, PL)], held(*LATER), None,
     [bundle(OL, "waiting", waiting={"rows": [], "prev": None, "kids": [C2.kid.hex()]})], predecessors=PRE)
case("later_prev_not_held", "The predecessor is not held: Waiting on it.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None,
     [bundle(OL, "waiting", waiting={"rows": [], "prev": OID.hex(), "kids": []})])
case("later_prev_not_valid", "The predecessor is held and not Valid: the bundle concludes nothing.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_prev_not_valid")], predecessors=[{"not_valid": OID.hex()}])
PL3 = payload(holders=(A, B, D), rows=ids(LATER), version=3, prev=OID, at=T2)
case("later_version_skip", "Version 3 naming a version-1 predecessor.",
     [voice(k, PL3) for k in (A, B, D)], held(*LATER), None,
     [bundle(object_id(enc(PL3)), "invalid", "genesis_bundle_malformed", "version_prev_mismatch")], predecessors=PRE)
PLF = payload(holders=(A, B, D), rows=ids(LATER), version=2, prev=OID, at=T2, fam="another-accord")
case("later_family_key_id_changed", "A later bundle with another family_key_id.",
     [voice(k, PLF) for k in (A, B, D)], held(*LATER), None,
     [bundle(object_id(enc(PLF)), "invalid", "genesis_bundle_malformed", "family_key_id_changed")], predecessors=PRE)
PLC = payload(rows=ids(ALL), version=2, prev=OID, at=T2,
              commits={A.iss: hd(commitment([REC[1]])), B.iss: hd(commitment([REC[4]])), C.iss: hd(commitment([REC[3]]))})
case("later_changed_commitment_unsigned", "B's recovery commitment changes but B does not sign (A and C do).",
     [voice(k, PLC) for k in (A, C)], held(*ALL), None,
     [bundle(object_id(enc(PLC)), "nothing", "genesis_bundle_count_unmet")], predecessors=PRE)
case("later_changed_commitment_signed", "B's recovery commitment changes and B signs, with A.",
     [voice(k, PLC) for k in (A, B)], held(*ALL), None,
     [bundle(object_id(enc(PLC)), "valid", placement=placement_of(PLC, (A, B, C), (S1, S2), (), (A, B)))],
     predecessors=PRE)
case("later_stranger_voice", "A and the stranger X sign: X has no role, A alone is no majority.",
     [voice(A, PL), voice(X, PL), voice(D, PL)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_count_unmet", refused=[(1, "statement_no_role")])], predecessors=PRE)

# ================================================================ forks
P_alt = payload(at=T1 + 1000)
O_alt = object_id(enc(P_alt))
case("fork_of_the_genesis", "Two first bundles every anchored holder signed: both Valid, a fork of the genesis.",
     V3 + [voice(k, P_alt) for k in (A, B, C)], held(*ALL), an,
     sorted([bundle(OID, "valid", placement=GOOD_PLACEMENT),
             bundle(O_alt, "valid", placement=placement_of(P_alt, (A, B, C), (S1, S2), (), (A, B, C)))],
            key=lambda e: e["object_id"]),
     forks={"forks": [{"kind": "genesis", "prev": None, "bundles": sorted([OID.hex(), O_alt.hex()])}], "head": None})
case("object_id_anchor_voids_the_other", "The same two first bundles under an object-id anchor: the other is void.",
     V3 + [voice(k, P_alt) for k in (A, B, C)], held(*ALL), an_oid,
     sorted([bundle(OID, "valid", placement=GOOD_PLACEMENT),
             bundle(O_alt, "nothing", "genesis_bundle_not_anchored")], key=lambda e: e["object_id"]),
     forks={"forks": [], "head": OID.hex()})
PL_alt = payload(holders=(A, B, D), rows=ids(LATER), version=2, prev=OID, at=T2 + 1000)
OL_alt = object_id(enc(PL_alt))
case("fork_of_successors", "Two Valid version-2 bundles naming one prev: a fork.",
     [voice(k, PL) for k in (A, B, D)] + [voice(k, PL_alt) for k in (A, B, D)], held(*LATER), None,
     sorted([bundle(OL, "valid", placement=LP),
             bundle(OL_alt, "valid", placement=placement_of(PL_alt, (A, B, D), (S1, S2), (), (A, B, D)))],
            key=lambda e: e["object_id"]),
     predecessors=PRE,
     forks={"forks": [{"kind": "successors", "prev": OID.hex(), "bundles": sorted([OL.hex(), OL_alt.hex()])}],
            "head": None})
case("chain_to_head", "The valid version-2 bundle over its predecessor: the head is version 2.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None, [bundle(OL, "valid", placement=LP)], predecessors=PRE,
     forks={"forks": [], "head": OL.hex()})

# ================================================================ recovery commitment known answers
recovery = []
for label, keys in (("one_key", [REC[1]]), ("two_keys", [REC[2], REC[1]])):
    inp = enc(["CEG-recovery/2", cset([k.cose for k in keys])])
    recovery.append({"id": label, "key_seeds": [k.n for k in keys], "input_hex": inp.hex(),
                     "commitment": sha(inp).hex()})

# ================================================================ CC's samples and its reference reader
cc_out = None
if "--cc" in sys.argv:
    path = sys.argv[sys.argv.index("--cc") + 1]
    spec = importlib.util.spec_from_file_location("build_cc_signed_object_v2", path)
    ccm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ccm)
    good, broken = ccm.genesis_samples()
    kgood, kbroken = ccm.key_record_samples()
    rgood, rbroken = ccm.recovery_samples()
    cc_out = {"tool": "tools/build_cc_signed_object_v2.py @ CIRISConstitution ae09856",
              "payload_samples": [{"name": "the valid sample", "payload_hex": good.hex(), "expect": "not_invalid"}]
              + [{"name": n, "payload_hex": b.hex(), "expect": "invalid"} for n, b in broken],
              "key_record_samples": [{"name": "the valid sample", "payload_hex": kgood.hex(), "expect": "ok"}]
              + [{"name": n, "payload_hex": b.hex(), "expect": "refused"} for n, b in kbroken],
              "recovery_samples": [{"name": "the valid sample", "input_hex": rgood.hex(), "expect": "ok"}]
              + [{"name": n, "input_hex": b.hex(), "expect": "refused"} for n, b in rbroken],
              "statement_samples": [{"name": n, "statement_hex": b.hex(), "expect": "invalid"}
                                    for n, b in ccm.broken_samples()],
              "reader": []}

    def ours(e):
        if e["verdict"] == "valid": return ["Valid", None]
        if e["verdict"] == "invalid": return ["Invalid", e["detail"]]
        if e["verdict"] == "waiting": return ["Waiting", None]
        return ["nothing", e["token"]]

    for c in cases:
        pj = cc_projections.get(c["id"])
        if pj is None: continue
        anc = anchor_cc(c["anchor"], pj["p"])
        try:
            ans, out = ccm.read_bundle(pj["p"], pj["voices"], pj["rows"], anc)
        except Exception as ex:                       # the reference reader reads the CDDL-valid shape only
            ans, out = "error", repr(ex)
        theirs = [ans, out if isinstance(out, str) else None]
        mine = ours(c["expect"][0])
        cc_out["reader"].append({"case": c["id"], "reference": theirs, "ours": mine,
                                 "agree": theirs[0] == mine[0] and (theirs[1] == mine[1] or mine[0] in ("Valid", "Waiting"))})
    # The reference reader's own ten breaks, by name, against the case that reproduces each.
    case_of = {"a missing holder signature": "missing_holder_signature",
               "an iat not floor(asserted_at / 1000)": "iat_off_by_one",
               "a seat whose binding is not in cites": "seat_binding_not_cited",
               "holders and serve_nodes overlapping": "holders_seats_overlap",
               "a holder not removable_offline": "holder_not_removable_offline",
               "a holder whose chain does not verify": "holder_chain_untrusted_root",
               "a holder set unlike the anchor": "anchor_thumbprints_mismatch",
               "an object id unlike the anchor": "anchor_object_id_mismatch",
               "a cited row not held": "cited_row_not_held",
               "a version 2 with no prev": "version_2_no_prev"}
    cc_out["reader_breaks"] = [{"name": why, "expect": list(want), "case": case_of[why]}
                               for why, _, want in ccm.reader_samples()[2]]

out = {
    "_meta": {
        "spec": "CC 2.6.1.11 / 4.2.2.1 / 3.2 T3 / 5.3.4, CIRISConstitution rc20 ae09856",
        "generator": "gen_genesis_bundles.py (independent of verify)",
        "keys": "Key n: ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32. Holders A,B,C,D = 1,2,3,4; seats 11,12; "
                "witnesses 21,22,23; stranger 9; A's other key 31; C's rotated key 33; recovery key of holder n = n+50.",
        "verdicts": "valid | invalid (token genesis_bundle_malformed, detail = reason) | waiting {rows, prev, kids} | "
                    "nothing (token; detail = the row or custody fault)",
    },
    "attestation_root_der": ROOT.der.hex(),
    "untrusted_root_der": UNTRUSTED.der.hex(),
    "parties": {name_: {"n": k.n, "kid": k.kid.hex(), "iss": k.iss} for name_, k in
                (("A", A), ("B", B), ("C", C), ("D", D), ("S1", S1), ("S2", S2), ("W1", W1), ("W2", W2), ("W3", W3),
                 ("X", X), ("A2", A2), ("C2", C2))},
    "seat_xwing": {name_: {"transit_xwing_pubkey": seat_keys(k)[0].hex(), "onion_hop_xwing_pubkey": seat_keys(k)[1].hex()}
                   for name_, k in (("S1", S1), ("S2", S2))},
    "cases": cases,
    "recovery_commitments": recovery,
}
if cc_out: out["cc"] = cc_out
import os
OUT = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "."


def write(name_, obj):
    with open(os.path.join(OUT, name_), "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")


write("genesis_bundles_v1.json", out)
for i, chars in enumerate(("0123", "4567", "89ab", "cdef")):
    write("pool_%d.json" % i, {k: v for k, v in POOL.items() if k[0] in chars})
