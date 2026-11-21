# Independent generator of `ceg-genesis-bundle/2` known answers, version 4: version 3 (below, kept as it was in
# gen_genesis_bundles_v3.py) with every seat's binding carrying `dial_hints` (CC 3.3.6.1, as verify proposes it
# for rc22): [ 1*4 [type, body] ], ordered, the body the CC 2.6.8 CIRIS-V4 hint body. A genesis serve seat's
# binding MUST carry a tcp hint (seat_dial_hints_missing); a known type with a bad body is dial_hint_malformed;
# an unknown type is carried and skipped. Seat 1 carries a DNS-name tcp hint then a udp hint; seat 2 an
# IP-literal tcp hint, an unknown type (6) and an auto hint. New cases break each rule.
#
# Version 3's header follows.
# Independent generator of `ceg-genesis-bundle/2` known answers, version 3 (CC 2.6.1.11, CC 4.2.6,
# CC 3.3.6.2, CIRISConstitution rc21-wire e6fd7c6): recoveries, roster changes, the seat-record and binding rules,
# spent commitments and forks with what their tips share.
#
# v3 is v2 (gen_genesis_bundles_v2.py, rc20 64c5918, which stays as it was) with one rule added: rc21 rules
# that a seat's binding is the seat's own identity:occurrence, checked by that family's payload rule as it is
# alone. Its identity_key_id and occurrence_key_id are the seat's identity reference (its author and the CWT
# sub) and its device_class is "server". Every seat binding here carries the three members; new cases break
# each of them.
#
# Its own CBOR deterministic encoder, dilithium-py (FIPS 204, deterministic), pyca/cryptography (Ed25519,
# X25519, X.509) and kyber-py (ML-KEM-768, for real X-Wing public keys). It shares no code with verify.
# The CBOR encoder and the composite signer are copied from ../gen_row_statements.py; the rest grows from
# gen_genesis_bundles.py (v1, CC rc20 ae09856) and gen_genesis_bundles_v2.py, which stay as they were.
#
#   python3 -I gen_genesis_bundles_v3.py --cc /path/to/build_cc_signed_object_v2.py --out .
#
# It writes genesis_bundles_v3.json (the cases) and pool_v3_0.json .. pool_v3_7.json (the statements, split
# by the first hex character of their key, so each file stays under the repository's 1000 KB limit).
#
# With --cc it also loads CC's reference bundle reader and its broken samples (the tool at CIRISConstitution
# rc21-wire e6fd7c6), embeds the samples' bytes, and runs the reference reader over every case it can model (first
# bundles and later ones, each over the reference reader's own placement of its predecessor), recording its
# answer beside ours.
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
    ROWINFO[rid] = (family, payload.get("author"), payload)
    return enc(Tag(18, [pb, {}, plb, sig])), rid


ROWINFO = {}                               # row id -> (family, author, payload), for CC's projection


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
A_NEW, A_NEW2 = Key(41), Key(42)                     # A's signing keys after its first and second recovery
A_REC2, A_REC3 = Key(61), Key(62)                    # A's next recovery keys (after the first, the second)
WRONG = Key(71)                                      # a key no commitment names


def commitment(keys): return sha(enc(["CEG-recovery/2", cset([k.cose for k in keys])]))


def holder_record(k, ev=None, key=None, roles=("accord_holder",), signer=None, at=T0):
    if ev is None:
        ev = {"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
              "chain": yubikey_chain((key or k).ed_pk, k.n)}
    p = {"key": (key or k).cose, "author": k.iss, "asserted_at": at, "identity_type": cset(list(roles))}
    if ev != "none": p["attestation_evidence"] = ev
    return row(signer or key or k, "key:record", p, sub=k.iss, iss=k.iss)


def recovery_key_record(holder, rk, at=T0):
    """The recovery key's own record: authored under the holder's name, signed by the recovery key."""
    p = {"key": rk.cose, "author": holder.iss, "asserted_at": at, "identity_type": ["accord_holder"]}
    return row(rk, "key:record", p, sub=holder.iss, iss=holder.iss)


def seat_record(k, roles=("node",), until=T0 + YEAR, sig_edit=None):
    p = {"key": k.cose, "author": k.iss, "asserted_at": T0, "identity_type": cset(list(roles)), "valid_until": until}
    return row(k, "key:record", p, sig_edit=sig_edit)


def witness_record(k):
    return row(k, "key:record", {"key": k.cose, "author": k.iss, "asserted_at": T0, "identity_type": ["witness"]})


def seat_keys(k):
    return xwing_pk(sha(b"transit" + bytes([k.n]))), xwing_pk(sha(b"onion" + bytes([k.n])))


def dh(t, body): return [t, body]
def dh_hostport(t, host, port): return dh(t, port.to_bytes(2, "big") + host.encode())


SEAT_HINTS = {11: [dh_hostport(1, "seat1.genesis.example.net", 4242), dh_hostport(2, "seat1.genesis.example.net", 4243)],
              12: [dh_hostport(1, "203.0.113.12", 4242), dh(6, b"\x01\x02\x03"),
                   dh(3, b"\x00" + b"reticulum")]}


def seat_hints(n): return SEAT_HINTS.get(n, [dh_hostport(1, "seat%d.genesis.example.net" % n, 4242)])
def hints_json(hs): return [{"type": t, "body_hex": b.hex()} for t, b in hs]


def binding(k, signer=None, edit=None, author=None, record="own", sub=None):
    """A seat's binding; `record` is the key record it names in refs (CC 3.3.6.2): its own by default. It is
    the seat's own identity:occurrence (CC 2.6.1.11, rc21): identity_key_id = occurrence_key_id = author =
    sub, device_class "server"."""
    t, o = seat_keys(k)
    rx, re_ = x25519_pub(sha(b"rns-x" + bytes([k.n]))), ed25519_pub(sha(b"rns-ed" + bytes([k.n])))
    td = {"reticulum_x25519_pubkey": rx, "reticulum_ed25519_pubkey": re_, "app_name": "ciris.federation",
          "aspects": ["serve"], "destination_hash": rns_destination_hash(rx, re_, "ciris.federation", ["serve"])}
    p = {"author": author or k.iss, "asserted_at": T0, "transport_destination": td,
         "transit_xwing_pubkey": t, "onion_hop_xwing_pubkey": o,
         "identity_key_id": author or k.iss, "occurrence_key_id": author or k.iss, "device_class": "server",
         "dial_hints": seat_hints(k.n)}
    if record == "own": record = R["rec_%d" % k.n][1]
    # Every occurrence names in refs.head the self-roster row its signer stood on (CC 3.3.6.4, rc21-wire);
    # a seat's first bind names its genesis key's own record.
    p["refs"] = {"head": rref(R["rec_%d" % k.n][1])}
    if record is not None: p["refs"]["also"] = {"cites": [rref(record)]}
    if edit: edit(p)
    s = signer or k
    return row(s, "identity:occurrence", p, sub=sub or (author or k.iss),
               iss=(author or k.iss) if signer is None else s.iss)


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


def placement_of(p, holders, seats, witnesses, counted, recs=None, prev=None, recovered=None, rk=None):
    """The placement a Valid bundle yields. `recs` maps a holder to (its record's row id, the key it records)
    where that is not its genesis record; `prev` is the predecessor's placement, whose spent and named
    commitments this one carries on; `recovered` the holder a recovery recovers."""
    recs = recs or {}
    coms = {h: c[1].hex() for h, c in p["charter"]["recovery_commitments"].items()}
    spent = set(prev["spent_commitments"]) if prev else set()
    if recovered is not None: spent.add(next(x["recovery_commitment"] for x in prev["holders"]
                                             if x["identity_ref"] == recovered.iss))
    lineage = (set(prev["lineage_commitments"]) if prev else set()) | set(coms.values())
    out = {"version": p["version"], "asserted_at": p["asserted_at"], "family_key_id": p["family_key_id"],
           "prev": p["refs"]["prev"][1][1].hex() if "prev" in p["refs"] else None,
           "holders": [], "seats": [], "witnesses": [], "counted": sorted(k.iss for k in counted),
           "halt_fuse": p["charter"].get("halt_fuse_secs", 86400), "scope": p["charter"]["scope"],
           "object_id": object_id(enc(p)).hex(), "recovered": recovered.iss if recovered else None,
           "spent_commitments": sorted(spent), "lineage_commitments": sorted(lineage)}
    # The keys the lineage retired per holder: each seated key a holder left, and each spent recovery key.
    retired = {k: set(v) for k, v in prev["retired_holder_keys"].items()} if prev else {}
    for h in holders:
        new = recs.get(h, (None, h))[1].kid.hex()
        for x in (prev["holders"] if prev else []):
            if x["identity_ref"] == h.iss and x["kid"] != new:
                retired.setdefault(h.iss, set()).add(x["kid"])
    if recovered is not None: retired.setdefault(recovered.iss, set()).add(rk.kid.hex())
    out["retired_holder_keys"] = {k: sorted(v) for k, v in retired.items()}
    for h in sorted(holders, key=lambda k: enc(k.iss)):
        rid, key = recs.get(h, (R["rec_%d" % h.n][1], h))
        out["holders"].append({"identity_ref": h.iss, "kid": key.kid.hex(), "record": rid.hex(),
                               "recovery_commitment": p["charter"]["recovery_commitments"][h.iss][1].hex(),
                               "hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline"})
    for s in sorted(seats, key=lambda k: enc(k.iss)):
        t, o = seat_keys(s)
        out["seats"].append({"identity_ref": s.iss, "kid": s.kid.hex(), "record": R["rec_%d" % s.n][1].hex(),
                             "binding": R["bind_%d" % s.n][1].hex(), "valid_until": T0 + YEAR,
                             "transit_xwing_pubkey_sha256": sha(t).hex(), "onion_hop_xwing_pubkey_sha256": sha(o).hex(),
                             "transit_seed": sha(b"transit" + bytes([s.n])).hex(),
                             "onion_seed": sha(b"onion" + bytes([s.n])).hex(),
                             "dial_hints": hints_json(seat_hints(s.n))})
    for w in sorted(witnesses, key=lambda k: enc(k.iss)):
        out["witnesses"].append({"identity_ref": w.iss, "kid": w.kid.hex(), "record": R["rec_%d" % w.n][1].hex()})
    return out


def ccp(p, voices_keys, row_ids, anchor, custody=None, iat=None, extra_rows=None):
    """A CC projection: voices (iss, iat), held rows (family, author, extra), read from the rows themselves.
    A voice is a holder's key, or ("recovery", holder, recovery key) for a recovery key's statement."""
    rows = {}
    for rid in row_ids:
        fam, author, pl = ROWINFO[rid]
        extra = {}
        if fam == "key:record":
            extra = {"key": pl["key"]}
            if "valid_until" in pl: extra["valid_until"] = pl["valid_until"]
            ev = pl.get("attestation_evidence")
            if ev is not None:
                extra.update(chain_verifies=bool(ev.get("chain")), pq_custody=ev.get("pq_custody"))
        if fam == "identity:occurrence":
            extra = {"xwing": ["transit", "onion"]}
            if "also" in pl.get("refs", {}): extra["cites"] = pl["refs"]["also"]["cites"][0]
            if "head" in pl.get("refs", {}): extra["head"] = pl["refs"]["head"]
            for m in ("identity_key_id", "occurrence_key_id", "device_class"):
                if m in pl: extra[m] = pl[m]
        rows[rid] = (fam, author, extra)
    for rid, v in (extra_rows or {}).items(): rows[rid] = v
    for author, ext in (custody or {}).items():
        rid = [r for r, (f, a, x) in rows.items() if f == "key:record" and a == author and "chain_verifies" in x][0]
        rows[rid] = ("key:record", author, dict(rows[rid][2], **ext))
    vs = []
    for k in voices_keys:
        if isinstance(k, tuple):
            vs.append((("recovery", k[1].iss, k[2].cose), (iat or {}).get(k[1].iss, p["asserted_at"] // 1000)))
        else:
            vs.append((k.iss, (iat or {}).get(k.iss, p["asserted_at"] // 1000)))
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
P_dup = payload(rows=ids(ALL) + [A_dup[1]])
case("two_records_for_one_holder", "Two key records by holder A: two rows for one place.",
     [voice(k, P_dup) for k in (A, B, C)], held(*ALL, extra=[{"id": A_dup[1].hex(), "statement": put(A_dup[0])}]), an,
     [bundle(object_id(enc(P_dup)), "nothing", "genesis_bundle_row_unplaced")],
     cc=ccp(P_dup, (A, B, C), ids(ALL) + [A_dup[1]], an))


def swap_row(name, new):
    """The bundle naming `new` in place of R[name]; returns (payload, rows held, oid). A seat's record is
    swapped with its binding, which names the new record, so the record's fault is the only one."""
    swaps = {name: new}
    if name == "rec_11": swaps["bind_11"] = binding(S1, record=new[1])
    names = [n for n in ALL if n not in swaps]
    news = list(swaps.values())
    p = payload(rows=ids(names) + [x[1] for x in news])
    return (p, held(*names, extra=[{"id": x[1].hex(), "statement": put(x[0])} for x in news]), object_id(enc(p)),
            ids(names) + [x[1] for x in news])


def row_case(cid, desc, name, new, token, detail, cc_custody=None):
    p, rows, oid, rids = swap_row(name, new)
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
row_case("seat_record_ended", "Seat 1's record ends at the bundle's own asserted_at: it does not cover the bundle's "
         "instant (valid_until must be later).",
         "rec_11", seat_record(S1, until=T1), "genesis_bundle_row_invalid", "seat_record_ended", cc_custody={})
row_case("seat_record_ended_before", "Seat 1's record ended a day before the bundle.",
         "rec_11", seat_record(S1, until=T1 - 86_400_000), "genesis_bundle_row_invalid", "seat_record_ended",
         cc_custody={})

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
def bind_case(cid, desc, b, detail, cc=False):
    row_case(cid, desc, "bind_11", b, "genesis_bundle_row_invalid", detail, cc_custody={} if cc else None)


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
bind_case("binding_names_no_record", "Seat 1's binding carries no refs: it names no key record (CC 3.3.6.2).",
          binding(S1, record=None), "binding_names_no_record", cc=True)
bind_case("binding_names_other_record", "Seat 1's binding names seat 2's key record, not its own.",
          binding(S1, record=R["rec_12"][1]), "binding_names_no_record", cc=True)
bind_case("binding_xwing_inside_transport_destination", "CC sample: an X-Wing key inside transport_destination, "
          "a closed map of the five RNS members: the binding is Invalid as a row.",
          binding(S1, edit=lambda p: p["transport_destination"].__setitem__("transit_xwing_pubkey", bytes(1216))),
          "row_invalid")
bind_case("binding_destination_hash_text", "CC sample: destination_hash as hex text, not 16 bytes.",
          binding(S1, edit=lambda p: p["transport_destination"].__setitem__("destination_hash", "00" * 16)),
          "row_invalid")
bind_case("binding_opt_out_false", "CC sample: onion_relay {opt_out: false}; the member is only ever {opt_out: true}.",
          binding(S1, edit=setk("onion_relay", {"opt_out": False})), "row_invalid")

# --- the binding is the seat's own identity:occurrence (CC 2.6.1.11, rc21-wire e6fd7c6): the family's payload rule
# as the row is alone, then identity_key_id = occurrence_key_id = the seat's identity reference, device_class
# "server". Each break is Invalid as a row: genesis_bundle_row_invalid, row_invalid.
bind_case("binding_no_identity_key_id", "Seat 1's binding with no identity_key_id: off the identity:occurrence rule.",
          binding(S1, edit=lambda p: p.pop("identity_key_id")), "row_invalid", cc=True)
bind_case("binding_no_head", "Seat 1's binding whose refs name no self-roster head (CC 3.3.6.4): off the "
          "identity:occurrence rule.", binding(S1, edit=lambda p: p["refs"].pop("head")), "row_invalid", cc=True)
bind_case("binding_no_occurrence_key_id", "Seat 1's binding with no occurrence_key_id: off the identity:occurrence rule.",
          binding(S1, edit=lambda p: p.pop("occurrence_key_id")), "row_invalid", cc=True)
bind_case("binding_device_class_laptop", "Seat 1's binding of device_class laptop (in the closed set, not server).",
          binding(S1, edit=setk("device_class", "laptop")), "row_invalid", cc=True)
bind_case("binding_device_class_phone", "CC's reader sample: seat 1's binding of device_class phone.",
          binding(S1, edit=setk("device_class", "phone")), "row_invalid", cc=True)
bind_case("binding_device_class_unlisted", "Seat 1's binding of device_class tablet, outside the closed set.",
          binding(S1, edit=setk("device_class", "tablet")), "row_invalid", cc=True)
bind_case("binding_no_device_class", "Seat 1's binding with no device_class.",
          binding(S1, edit=lambda p: p.pop("device_class")), "row_invalid", cc=True)
bind_case("binding_identity_key_id_other", "Seat 1's binding whose identity_key_id names seat 2: not the seat's "
          "identity reference.",
          binding(S1, edit=setk("identity_key_id", S2.iss)), "row_invalid", cc=True)
bind_case("binding_occurrence_key_id_other", "Seat 1's binding whose occurrence_key_id names seat 2.",
          binding(S1, edit=setk("occurrence_key_id", S2.iss)), "row_invalid", cc=True)
bind_case("binding_identity_key_id_not_iref", "Seat 1's binding whose identity_key_id is a bare key label, not an "
          "identity reference.",
          binding(S1, edit=setk("identity_key_id", "S1")), "row_invalid", cc=True)
bind_case("binding_sub_not_seat", "Seat 1's binding (author, identity_key_id and occurrence_key_id S1) under CWT sub "
          "S2: occurrence_key_id is not the sub. CC's reader projection carries no sub, so it is not modelled.",
          binding(S1, sub=S2.iss), "row_invalid")

# --- dial_hints (CC 3.3.6.1, v4): a genesis serve seat is dialled cold from the bundle alone.
bind_case("binding_dial_hints_missing", "Seat 1's binding carries no dial_hints: a fresh node cannot dial it.",
          binding(S1, edit=lambda p: p.pop("dial_hints")), "seat_dial_hints_missing")
bind_case("binding_dial_hints_no_tcp", "Seat 1's binding carries udp and http hints but no tcp hint.",
          binding(S1, edit=setk("dial_hints", [dh_hostport(2, "seat1.genesis.example.net", 4243),
                                               dh(5, b"https://seat1.genesis.example.net/rns")])), "seat_dial_hints_missing")
bind_case("binding_dial_hints_unknown_only", "Seat 1's binding carries only an unknown hint type: skipped, so no tcp.",
          binding(S1, edit=setk("dial_hints", [dh(6, b"\x01")])), "seat_dial_hints_missing")
bind_case("binding_dial_hint_port_zero", "Seat 1's tcp hint has port 0: a known type with a bad body.",
          binding(S1, edit=setk("dial_hints", [dh_hostport(1, "seat1.genesis.example.net", 0)])), "dial_hint_malformed")
bind_case("binding_dial_hint_host_space", "Seat 1's tcp hint host carries a space.",
          binding(S1, edit=setk("dial_hints", [dh_hostport(1, "seat1 genesis.example.net", 4242)])), "dial_hint_malformed")
bind_case("binding_dial_hint_http_not_https", "Seat 1's http hint is not https (beside a good tcp hint).",
          binding(S1, edit=setk("dial_hints", [dh_hostport(1, "seat1.genesis.example.net", 4242),
                                               dh(5, b"http://seat1.genesis.example.net/")])), "dial_hint_malformed")
bind_case("binding_dial_hint_rnode_short", "Seat 1's rnode hint body is 9 bytes, not 10.",
          binding(S1, edit=setk("dial_hints", [dh_hostport(1, "seat1.genesis.example.net", 4242), dh(4, bytes(9))])),
          "dial_hint_malformed")
bind_case("binding_dial_hints_empty", "Seat 1's dial_hints is an empty array (absence is the one encoding of none).",
          binding(S1, edit=setk("dial_hints", [])), "row_invalid")
bind_case("binding_dial_hints_five", "Seat 1's dial_hints carries five entries (the bound is 4).",
          binding(S1, edit=setk("dial_hints", [dh_hostport(1, "seat1.genesis.example.net", 4242 + i) for i in range(5)])),
          "row_invalid")
bind_case("binding_dial_hint_not_pair", "Seat 1's dial_hints entry is [1], not [type, body].",
          binding(S1, edit=setk("dial_hints", [[1]])), "row_invalid")
bind_case("binding_dial_hint_body_text", "Seat 1's dial_hints entry body is text, not bytes.",
          binding(S1, edit=setk("dial_hints", [[1, "seat1.genesis.example.net"]])), "row_invalid")
bind_case("binding_dial_hint_type_256", "Seat 1's dial_hints entry type is 256.",
          binding(S1, edit=setk("dial_hints", [[256, b"\x10\x92seat1"]])), "row_invalid")

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
bad_payload("scope_unsorted", "scope as [infra:attest, infra:serve], not in CDE set order (the shorter text first).",
            payload(charter_edit=lambda c: c.__setitem__("scope", ["infra:attest", "infra:serve"])),
            "federation_set_semantics_unsorted")
bad_payload("cites_edition_1", "A cites row-ref of edition 1.",
            payload(edit=lambda p: p["refs"]["also"].__setitem__("cites", cset([[1, hd(r)] for r in ids(ALL)]))),
            "genesis_bundle_schema", cc=False)
bad_payload("halt_fuse_zero", "halt_fuse_secs 0.", payload(charter_edit=lambda c: c.__setitem__("halt_fuse_secs", 0)),
            "genesis_bundle_schema", cc=False)

# ================================================================ later bundles
PL = payload(holders=(A, B, D), rows=ids(LATER), version=2, prev=OID, at=T2)
OL = object_id(enc(PL))
PRE = [{"case": "first_valid"}]
LP = placement_of(PL, (A, B, D), (S1, S2), (), (A, B, D), prev=GOOD_PLACEMENT)
LIDS = ids(LATER)
case("later_valid", "Version 2: C swapped for D; a strict majority of the predecessor's holders (A, B) and D sign.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None, [bundle(OL, "valid", placement=LP)], predecessors=PRE,
     cc=ccp(PL, (A, B, D), LIDS, None))
case("later_removed_holder_counts", "A and the removed holder C (under its key from the predecessor) are the "
     "majority; D, the added holder, signs.",
     [voice(k, PL) for k in (A, C, D)], held(*LATER), None,
     [bundle(OL, "valid", placement=placement_of(PL, (A, B, D), (S1, S2), (), (A, C, D), prev=GOOD_PLACEMENT))],
     predecessors=PRE, cc=ccp(PL, (A, C, D), LIDS, None))
case("later_added_holder_unsigned", "A and B sign but D, the added holder, does not: the count is unmet.",
     [voice(k, PL) for k in (A, B)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_count_unmet")], predecessors=PRE, cc=ccp(PL, (A, B), LIDS, None))
case("later_minority", "A and D only: one of three predecessor holders is no majority.",
     [voice(k, PL) for k in (A, D)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_count_unmet")], predecessors=PRE, cc=ccp(PL, (A, D), LIDS, None))
case("later_voice_key_not_held", "C signs under a key C rotated to, not the key the predecessor seats for C: that "
     "statement is refused (each later statement is under the key the predecessor names), and A alone of the "
     "predecessor's holders is no majority. v1 answered Waiting on the key.",
     [voice(A, PL), voice(C, PL, iss=C.iss, signer=C2), voice(D, PL)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_count_unmet", refused=[(1, "statement_kid_not_iss")])], predecessors=PRE)
case("later_prev_not_held", "The predecessor is not held: Waiting on it.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None,
     [bundle(OL, "waiting", waiting={"rows": [], "prev": OID.hex(), "kids": []})],
     cc=ccp(PL, (A, B, D), LIDS, None))
case("later_prev_not_valid", "The predecessor is held and not Valid: the bundle concludes nothing.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_prev_not_valid")], predecessors=[{"not_valid": OID.hex()}],
     cc=ccp(PL, (A, B, D), LIDS, None))
PL3 = payload(holders=(A, B, D), rows=ids(LATER), version=3, prev=OID, at=T2)
case("later_version_skip", "Version 3 naming a version-1 predecessor.",
     [voice(k, PL3) for k in (A, B, D)], held(*LATER), None,
     [bundle(object_id(enc(PL3)), "invalid", "genesis_bundle_malformed", "version_prev_mismatch")], predecessors=PRE,
     cc=ccp(PL3, (A, B, D), LIDS, None))
PLF = payload(holders=(A, B, D), rows=ids(LATER), version=2, prev=OID, at=T2, fam="another-accord")
case("later_family_key_id_changed", "A later bundle with another family_key_id.",
     [voice(k, PLF) for k in (A, B, D)], held(*LATER), None,
     [bundle(object_id(enc(PLF)), "invalid", "genesis_bundle_malformed", "family_key_id_changed")], predecessors=PRE,
     cc=ccp(PLF, (A, B, D), LIDS, None))
PLC = payload(rows=ids(ALL), version=2, prev=OID, at=T2,
              commits={A.iss: hd(commitment([REC[1]])), B.iss: hd(commitment([REC[4]])), C.iss: hd(commitment([REC[3]]))})
case("later_changed_commitment_unsigned", "B's recovery commitment changes but B does not sign (A and C do).",
     [voice(k, PLC) for k in (A, C)], held(*ALL), None,
     [bundle(object_id(enc(PLC)), "nothing", "genesis_bundle_count_unmet")], predecessors=PRE,
     cc=ccp(PLC, (A, C), ids(ALL), None))
case("later_changed_commitment_signed", "B's recovery commitment changes and B signs, with A.",
     [voice(k, PLC) for k in (A, B)], held(*ALL), None,
     [bundle(object_id(enc(PLC)), "valid",
             placement=placement_of(PLC, (A, B, C), (S1, S2), (), (A, B), prev=GOOD_PLACEMENT))],
     predecessors=PRE, cc=ccp(PLC, (A, B), ids(ALL), None))
case("later_stranger_voice", "A and the stranger X sign: X has no role, A alone is no majority.",
     [voice(A, PL), voice(X, PL), voice(D, PL)], held(*LATER), None,
     [bundle(OL, "nothing", "genesis_bundle_count_unmet", refused=[(1, "statement_no_role")])], predecessors=PRE)

# ================================================================ recoveries (CC 2.6.1.11, CC 4.2.6)
# A recovery is a later bundle with ONE statement: iss A, kid A's recovery key, resolved through the recovery
# key's own key:record named in cites beside A's new signing-key record; A's commitment becomes the next one.
R["rk_1"] = recovery_key_record(A, REC[1], at=T2 - 1000)          # A's recovery key's record
R["rk_wrong"] = recovery_key_record(A, WRONG, at=T2 - 1000)        # a key under A's name no commitment names
R["recA"] = holder_record(A, key=A_NEW, at=T2 - 1000)              # A's new signing-key record
R["recA_rk"] = holder_record(A, key=REC[1], at=T2 - 1000)          # a "signing" record of A's own recovery key
R["recA_b"] = holder_record(A, key=REC[2], at=T2 - 1000)           # one of B's recovery key, which a commitment names
SEATS = ["rec_11", "rec_12", "bind_11", "bind_12"]
REST = ["rec_2", "rec_3"] + SEATS
REC_ROWS = ["recA", "rk_1"] + REST
NEXT = {A.iss: hd(commitment([A_REC2])), B.iss: hd(commitment([REC[2]])), C.iss: hd(commitment([REC[3]]))}


def later_payload(names, commits=NEXT, version=2, prev=OID, at=T2, holders=(A, B, C), **kw):
    return payload(holders=holders, rows=ids(names), version=version, prev=prev, at=at, commits=dict(commits), **kw)


def rvoice(rk, p, **kw): return voice(rk, p, iss=A.iss, **kw)


PR = later_payload(REC_ROWS)
OR = object_id(enc(PR))
RECP = placement_of(PR, (A, B, C), (S1, S2), (), (A,), recs={A: (R["recA"][1], A_NEW)}, prev=GOOD_PLACEMENT,
                    recovered=A, rk=REC[1])
case("recovery_valid", "A recovers: one statement by A's recovery key (iss A, kid the recovery key, its record "
     "named), A's new signing-key record named, A's commitment the next one. It counts on that statement alone; "
     "A's first commitment is spent.",
     [rvoice(REC[1], PR)], held(*REC_ROWS), None, [bundle(OR, "valid", placement=RECP)], predecessors=PRE,
     cc=ccp(PR, [("recovery", A, REC[1])], ids(REC_ROWS), None))


def rcase(cid, desc, p, names, rk, expect, pre=PRE, cc=True, sig_edit=None):
    oid = object_id(enc(p))
    case(cid, desc, [rvoice(rk, p, sig_edit=sig_edit)], held(*names), None,
         [dict(expect, object_id=oid.hex())], predecessors=pre,
         cc=ccp(p, [("recovery", A, rk)], ids(names), None) if cc else None)


def nothing(token, detail=None, refused=()): return bundle(bytes(32), "nothing", token, detail, refused=refused)
def invalid(reason): return bundle(bytes(32), "invalid", "genesis_bundle_malformed", reason)


P_wrong = later_payload(["recA", "rk_wrong"] + REST)
rcase("recovery_commitment_mismatch", "A recovery under a key whose record is named but which A's commitment in force "
      "does not commit to: the statement does not count.", P_wrong, ["recA", "rk_wrong"] + REST, WRONG,
      nothing("genesis_bundle_count_unmet", "recovery_commitment_mismatch"))
P_sk = later_payload(["recA", "rec_1"] + REST)
rcase("recovery_under_signing_key", "A's lone statement under A's current signing key, with its record and A's new "
      "record named: that key is not the one A's commitment commits to.", P_sk, ["recA", "rec_1"] + REST, A,
      nothing("genesis_bundle_count_unmet", "recovery_commitment_mismatch"))
P_nn = later_payload(["recA"] + REST)
rcase("recovery_key_record_not_named", "A recovery whose recovery key's record is not named: the key does not "
      "resolve, and the statement does not count.", P_nn, ["recA"] + REST, REC[1],
      nothing("genesis_bundle_count_unmet", "recovery_commitment_mismatch"))
P_keep = later_payload(REC_ROWS, commits={**NEXT, A.iss: hd(commitment([REC[1]]))})
rcase("recovery_keeps_commitment", "A recovery whose next commitment is the one it spends.", P_keep, REC_ROWS, REC[1],
      nothing("genesis_bundle_count_unmet", "recovery_commitment_spent"))
P_kis = later_payload(["recA_rk", "rk_1"] + REST)
rcase("recovery_key_is_signing_key", "A recovery whose new signing-key record holds the recovery key itself.",
      P_kis, ["recA_rk", "rk_1"] + REST, REC[1], invalid("recovery_key_is_signing_key"))
P_kb = later_payload(["recA_b", "rk_1"] + REST)
rcase("recovery_seats_committed_key", "A recovery seating as A's signing key B's recovery key, a key a commitment "
      "of the lineage commits to.", P_kb, ["recA_b", "rk_1"] + REST, REC[1], invalid("recovery_key_is_signing_key"))
P_reuse = later_payload(["rec_1", "rk_1"] + REST)
rcase("recovery_reuses_signing_key", "A recovery naming A's current record as the new one: the new key is A's "
      "current key.", P_reuse, ["rec_1", "rk_1"] + REST, REC[1], invalid("recovery_reuses_signing_key"))
P_other = later_payload(REC_ROWS, commits={**NEXT, B.iss: hd(commitment([REC[4]]))})
rcase("recovery_changes_other_seat", "A recovery that also re-commits B.", P_other, REC_ROWS, REC[1],
      invalid("recovery_changes_other_seat"))
P_fuse = later_payload(REC_ROWS, charter_edit=lambda c: c.__setitem__("halt_fuse_secs", 3600))
rcase("recovery_changes_charter", "A recovery that also changes halt_fuse_secs.", P_fuse, REC_ROWS, REC[1],
      invalid("recovery_changes_other_seat"))
P_seat = later_payload(["recA", "rk_1", "rec_2", "rec_3", "rec_11", "bind_11"],
                       edit=lambda p: p.__setitem__("serve_nodes", [S1.iss]))
rcase("recovery_drops_a_seat", "A recovery that also drops seat 2.", P_seat,
      ["recA", "rk_1", "rec_2", "rec_3", "rec_11", "bind_11"], REC[1], invalid("recovery_changes_other_seat"))
rcase("recovery_bad_signature", "The recovery statement's signature has a byte flipped: refused; nothing counts.",
      PR, REC_ROWS, REC[1], nothing("genesis_bundle_count_unmet", refused=[(0, "statement_invalid")]), cc=False,
      sig_edit=flip)

# --- after a recovery: spent never returns; the recovered holder's record is the one in force
PRE_R = [{"case": "recovery_valid"}]
R["recA2"] = holder_record(A, key=A_NEW2, at=T2 + 86_400_000)
R["rk_2"] = recovery_key_record(A, A_REC2, at=T2 + 86_400_000)
T3 = T2 + 2 * 86_400_000
NEXT2 = {**NEXT, A.iss: hd(commitment([A_REC3]))}
P2 = later_payload(["recA2", "rk_2"] + REST, commits=NEXT2, version=3, prev=OR, at=T3)
case("second_recovery_valid", "A recovers again, under the recovery key its first recovery committed; both "
     "commitments it used are spent.",
     [rvoice(A_REC2, P2)], held("recA2", "rk_2", *REST), None,
     [bundle(object_id(enc(P2)), "valid",
             placement=placement_of(P2, (A, B, C), (S1, S2), (), (A,), recs={A: (R["recA2"][1], A_NEW2)},
                                    prev=RECP, recovered=A, rk=A_REC2))],
     predecessors=PRE_R, cc=ccp(P2, [("recovery", A, A_REC2)], ids(["recA2", "rk_2"] + REST), None))
P2s = later_payload(["recA2", "rk_1"] + REST, commits=NEXT2, version=3, prev=OR, at=T3)
rcase("recovery_spent_key", "A second recovery under A's first recovery key, already spent.",
      P2s, ["recA2", "rk_1"] + REST, REC[1], nothing("genesis_bundle_count_unmet", "recovery_commitment_spent"),
      pre=PRE_R)
P2r = later_payload(["recA2", "rk_2"] + REST, commits={**NEXT, A.iss: hd(commitment([REC[1]]))}, version=3, prev=OR,
                    at=T3)
rcase("second_recovery_relists_spent", "A second recovery whose next commitment is the one the first spent.",
      P2r, ["recA2", "rk_2"] + REST, A_REC2, nothing("genesis_bundle_count_unmet", "recovery_commitment_spent"),
      pre=PRE_R)
REC_HELD = ["recA"] + REST
P_rel = later_payload(REC_HELD, commits={**NEXT, A.iss: hd(commitment([REC[1]]))}, version=3, prev=OR, at=T3)
case("relisted_spent_commitment", "A roster bundle (A under its new key, and B) setting A's commitment back to the "
     "one A's recovery spent: a spent commitment never returns.",
     [voice(A_NEW, P_rel, iss=A.iss), voice(B, P_rel)], held(*REC_HELD), None,
     [bundle(object_id(enc(P_rel)), "nothing", "genesis_bundle_count_unmet", "recovery_commitment_spent")],
     predecessors=PRE_R, cc=ccp(P_rel, (A, B), ids(REC_HELD), None))
P_after = later_payload(REC_HELD, commits={**NEXT, B.iss: hd(commitment([REC[4]]))}, version=3, prev=OR, at=T3)
case("recovered_holder_seated_key", "After A's recovery, a roster bundle re-committing B, signed by A under its new "
     "key and B: A's record is the new one, which the bundle in force seats (not A's genesis key), and passes.",
     [voice(A_NEW, P_after, iss=A.iss), voice(B, P_after)], held(*REC_HELD), None,
     [bundle(object_id(enc(P_after)), "valid",
             placement=placement_of(P_after, (A, B, C), (S1, S2), (), (A, B), recs={A: (R["recA"][1], A_NEW)},
                                    prev=RECP))],
     predecessors=PRE_R, cc=ccp(P_after, (A, B), ids(REC_HELD), None))
P_stale = later_payload(["rec_1"] + REST, commits={**NEXT, B.iss: hd(commitment([REC[4]]))}, version=3, prev=OR, at=T3)
case("recovered_holder_genesis_record", "After A's recovery, a roster bundle B and C sign naming A's genesis record, "
     "a key the recovery retired: holder_key_retired (Invalid, read from the payload and the predecessor; it answers "
     "before holder_not_genesis_key, which turns on the statements held).",
     [voice(B, P_stale), voice(C, P_stale)], held("rec_1", *REST), None,
     [bundle(object_id(enc(P_stale)), "invalid", "genesis_bundle_malformed", "holder_key_retired")],
     predecessors=PRE_R, cc=ccp(P_stale, (B, C), ids(["rec_1"] + REST), None))

# --- a roster bundle re-seats a holder under a new key only with that holder's counted statement under its current key
ROT = ["recA"] + REST
P_rot = later_payload(ROT, commits={**NEXT, A.iss: hd(commitment([REC[1]]))})
O_rot = object_id(enc(P_rot))
ROTP = placement_of(P_rot, (A, B, C), (S1, S2), (), (A, B, C), recs={A: (R["recA"][1], A_NEW)}, prev=GOOD_PLACEMENT)
case("roster_bundle_rotates_holder_key", "Without a recovery, a roster bundle every holder signs, A under its current "
     "(genesis) key, naming a new record for A: A's own counted statement re-seats A at the new key.",
     [voice(k, P_rot) for k in (A, B, C)], held(*ROT), None, [bundle(O_rot, "valid", placement=ROTP)],
     predecessors=PRE, cc=ccp(P_rot, (A, B, C), ids(ROT), None))
case("roster_bundle_rotates_without_holder_voice", "The same bundle counted on B and C alone: A's statement is not "
     "among the counted, so A's new record is not the key the bundle in force seats for A.",
     [voice(k, P_rot) for k in (B, C)], held(*ROT), None,
     [bundle(O_rot, "nothing", "genesis_bundle_row_invalid", "holder_not_genesis_key")],
     predecessors=PRE, cc=ccp(P_rot, (B, C), ids(ROT), None))
case("roster_bundle_rotates_holder_voice_under_new_key", "The same bundle with A's statement under the new key: refused "
     "(statement_kid_not_iss, not the key the predecessor seats); B and C meet the count, but A's statement under its "
     "current key is not among the counted, so A's new record is holder_not_genesis_key.",
     [voice(A_NEW, P_rot, iss=A.iss), voice(B, P_rot), voice(C, P_rot)], held(*ROT), None,
     [bundle(O_rot, "nothing", "genesis_bundle_row_invalid", "holder_not_genesis_key",
             refused=[(0, "statement_kid_not_iss")])],
     # A's statement is refused, so it is no voice: CC's projection carries the counted voices only.
     predecessors=PRE, cc=ccp(P_rot, (B, C), ids(ROT), None))
P_rot2 = later_payload(ROT, commits={**NEXT, A.iss: hd(commitment([REC[1]])), B.iss: hd(commitment([REC[4]]))},
                       version=3, prev=O_rot, at=T3)
case("roster_after_rotation_counts_new_key", "The next bundle after A's rotation re-commits B, signed by A under its new "
     "key (the one the predecessor now seats) and B: Valid.",
     [voice(A_NEW, P_rot2, iss=A.iss), voice(B, P_rot2)], held(*ROT), None,
     [bundle(object_id(enc(P_rot2)), "valid",
             placement=placement_of(P_rot2, (A, B, C), (S1, S2), (), (A, B), recs={A: (R["recA"][1], A_NEW)},
                                    prev=ROTP))],
     predecessors=[{"case": "roster_bundle_rotates_holder_key"}], cc=ccp(P_rot2, (A, B), ids(ROT), None))

# --- no later bundle seats a holder at a key its lineage retired, or at its in-force recovery commitment's key
PRE_ROT = [{"case": "roster_bundle_rotates_holder_key"}]
GEN_A = ["rec_1"] + REST
P_back = later_payload(GEN_A, commits={**NEXT, A.iss: hd(commitment([REC[1]]))}, version=3, prev=O_rot, at=T3)
case("roster_reseats_retired_key_after_rotation", "After A rotated to a new key, a roster bundle A (under its new key) "
     "and B sign re-seating A at its genesis key, which the lineage retired: holder_key_retired.",
     [voice(A_NEW, P_back, iss=A.iss), voice(B, P_back)], held(*GEN_A), None,
     [bundle(object_id(enc(P_back)), "invalid", "genesis_bundle_malformed", "holder_key_retired")],
     predecessors=PRE_ROT, cc=ccp(P_back, (A, B), ids(GEN_A), None))
P_back_r = later_payload(GEN_A, commits={**NEXT, B.iss: hd(commitment([REC[4]]))}, version=3, prev=OR, at=T3)
case("roster_reseats_retired_key_after_recovery", "After A's recovery, a roster bundle A (under its recovered key), B "
     "and C sign re-seating A at its genesis key, which the recovery retired: holder_key_retired.",
     [voice(A_NEW, P_back_r, iss=A.iss), voice(B, P_back_r), voice(C, P_back_r)], held(*GEN_A), None,
     [bundle(object_id(enc(P_back_r)), "invalid", "genesis_bundle_malformed", "holder_key_retired")],
     predecessors=PRE_R, cc=ccp(P_back_r, (A, B, C), ids(GEN_A), None))
RK_A = ["recA_rk"] + REST
P_inforce = later_payload(RK_A, commits={**NEXT, A.iss: hd(commitment([REC[1]]))})
case("roster_seats_in_force_recovery_key", "A roster bundle every holder signs (A under its current key) seating A at "
     "the key A's recovery commitment in force commits to: holder_key_retired.",
     [voice(k, P_inforce) for k in (A, B, C)], held(*RK_A), None,
     [bundle(object_id(enc(P_inforce)), "invalid", "genesis_bundle_malformed", "holder_key_retired")],
     predecessors=PRE, cc=ccp(P_inforce, (A, B, C), ids(RK_A), None))
P_spentk = later_payload(RK_A, version=3, prev=OR, at=T3)
case("roster_seats_spent_recovery_key", "After A's recovery, a roster bundle A (under its recovered key), B and C sign "
     "seating A at the recovery key that recovery spent: holder_key_retired.",
     [voice(A_NEW, P_spentk, iss=A.iss), voice(B, P_spentk), voice(C, P_spentk)], held(*RK_A), None,
     [bundle(object_id(enc(P_spentk)), "invalid", "genesis_bundle_malformed", "holder_key_retired")],
     predecessors=PRE_R, cc=ccp(P_spentk, (A, B, C), ids(RK_A), None))

# ================================================================ forks
def common(tips):
    """What every tip names (CC 2.6.1.11): the tips by object id, the holders every tip seats under one key and
    the seats every tip lists with one key and one pair of X-Wing keys, in the first tip's order."""
    tips = sorted(tips, key=lambda t: t["object_id"])
    first, rest = tips[0], tips[1:]
    hs = [h["identity_ref"] for h in first["holders"]
          if all(any(x["identity_ref"] == h["identity_ref"] and x["kid"] == h["kid"] for x in t["holders"]) for t in rest)]
    key = lambda s: (s["identity_ref"], s["kid"], s["transit_xwing_pubkey_sha256"], s["onion_hop_xwing_pubkey_sha256"])
    ss = [s["identity_ref"] for s in first["seats"] if all(any(key(x) == key(s) for x in t["seats"]) for t in rest)]
    return {"tips": [t["object_id"] for t in tips], "holders": hs, "seats": ss}


P_alt = payload(at=T1 + 1000)
O_alt = object_id(enc(P_alt))
case("fork_of_the_genesis", "Two first bundles every anchored holder signed: both Valid, a fork of the genesis.",
     V3 + [voice(k, P_alt) for k in (A, B, C)], held(*ALL), an,
     sorted([bundle(OID, "valid", placement=GOOD_PLACEMENT),
             bundle(O_alt, "valid", placement=placement_of(P_alt, (A, B, C), (S1, S2), (), (A, B, C)))],
            key=lambda e: e["object_id"]),
     forks={"forks": [{"kind": "genesis", "prev": None, "bundles": sorted([OID.hex(), O_alt.hex()])}], "head": None,
            "common": None})
case("object_id_anchor_voids_the_other", "The same two first bundles under an object-id anchor: the other is void.",
     V3 + [voice(k, P_alt) for k in (A, B, C)], held(*ALL), an_oid,
     sorted([bundle(OID, "valid", placement=GOOD_PLACEMENT),
             bundle(O_alt, "nothing", "genesis_bundle_not_anchored")], key=lambda e: e["object_id"]),
     forks={"forks": [], "head": OID.hex(), "common": common([GOOD_PLACEMENT])})
PL_alt = payload(holders=(A, B, D), rows=ids(LATER), version=2, prev=OID, at=T2 + 1000)
OL_alt = object_id(enc(PL_alt))
case("fork_of_successors", "Two Valid version-2 bundles naming one prev: a fork.",
     [voice(k, PL) for k in (A, B, D)] + [voice(k, PL_alt) for k in (A, B, D)], held(*LATER), None,
     sorted([bundle(OL, "valid", placement=LP),
             bundle(OL_alt, "valid", placement=placement_of(PL_alt, (A, B, D), (S1, S2), (), (A, B, D),
                                                            prev=GOOD_PLACEMENT))],
            key=lambda e: e["object_id"]),
     predecessors=PRE,
     forks={"forks": [{"kind": "successors", "prev": OID.hex(), "bundles": sorted([OL.hex(), OL_alt.hex()])}],
            "head": None, "common": common([LP, placement_of(PL_alt, (A, B, D), (S1, S2), (), (A, B, D),
                                                             prev=GOOD_PLACEMENT)])})
case("chain_to_head", "The valid version-2 bundle over its predecessor: the head is version 2.",
     [voice(k, PL) for k in (A, B, D)], held(*LATER), None, [bundle(OL, "valid", placement=LP)], predecessors=PRE,
     forks={"forks": [], "head": OL.hex(), "common": common([LP])})
case("fork_roster_and_recovery", "Two later bundles count on one predecessor: C swapped for D (A, B, D sign), and "
     "A's recovery. A fork: the reader holds both as tips and acts on what both name, B and the two seats (A's key "
     "differs between the tips; C and D stand in one each).",
     [voice(k, PL) for k in (A, B, D)] + [rvoice(REC[1], PR)], held(*LATER, "rec_3", "rk_1", "recA"), None,
     sorted([bundle(OL, "valid", placement=LP), bundle(OR, "valid", placement=RECP)], key=lambda e: e["object_id"]),
     predecessors=PRE,
     forks={"forks": [{"kind": "successors", "prev": OID.hex(), "bundles": sorted([OL.hex(), OR.hex()])}],
            "head": None, "common": common([LP, RECP])})

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
    bgood, bbroken = ccm.binding_samples()
    fgood = fbroken = None
    for root_, _what, vb, br in ccm.family_payload_samples():
        if root_ == "identity-occurrence": fgood, fbroken = vb, br
    cc_out = {"tool": "tools/build_cc_signed_object_v2.py @ CIRISConstitution v1.0-rc21 b016df4",
              "occurrence_samples": [{"name": "the valid sample", "payload_hex": fgood.hex(), "expect": "ok"}]
              + [{"name": n, "payload_hex": b.hex(), "expect": "refused"} for n, b in fbroken],
              "payload_samples": [{"name": "the valid sample", "payload_hex": good.hex(), "expect": "not_invalid"}]
              + [{"name": n, "payload_hex": b.hex(), "expect": "invalid"} for n, b in broken],
              "key_record_samples": [{"name": "the valid sample", "payload_hex": kgood.hex(), "expect": "ok"}]
              + [{"name": n, "payload_hex": b.hex(), "expect": "refused"} for n, b in kbroken],
              "recovery_samples": [{"name": "the valid sample", "input_hex": rgood.hex(), "expect": "ok"}]
              + [{"name": n, "input_hex": b.hex(), "expect": "refused"} for n, b in rbroken],
              "binding_samples": [{"name": "the valid sample", "payload_hex": bgood.hex(), "expect": "ok"}]
              + [{"name": n, "payload_hex": b.hex(), "expect": "refused"} for n, b in bbroken],
              "statement_samples": [{"name": n, "statement_hex": b.hex(), "expect": "invalid"}
                                    for n, b in ccm.broken_samples()],
              "reader": []}

    def ours(e):
        if e["verdict"] == "valid": return ["Valid", None]
        if e["verdict"] == "invalid": return ["Invalid", e["detail"]]
        if e["verdict"] == "waiting": return ["Waiting", None]
        if e.get("detail", "").startswith("recovery_commitment_"): return ["nothing", e["token"] + ":" + e["detail"]]
        return ["nothing", e["token"]]

    cc_place = {}                                     # case -> the reference reader's own Valid placement
    for c in cases:
        pj = cc_projections.get(c["id"])
        if pj is None: continue
        anc = anchor_cc(c["anchor"], pj["p"])
        later = "prev" in pj["p"]["refs"]
        prev = None
        for x in c["predecessors"]:
            prev = "not_valid" if "not_valid" in x else cc_place.get(x["case"])
        try:
            ans, out_ = ccm.read_bundle(pj["p"], pj["voices"], pj["rows"], anc, prev) if later else \
                ccm.read_bundle(pj["p"], pj["voices"], pj["rows"], anc)
        except Exception as ex:                       # the reference reader reads the CDDL-valid shape only
            ans, out_ = "error", repr(ex)
        if ans == "Valid": cc_place[c["id"]] = out_
        theirs = [ans, out_ if isinstance(out_, str) else None]
        mine = ours(c["expect"][0])
        cc_out["reader"].append({"case": c["id"], "reference": theirs, "ours": mine,
                                 "agree": theirs[0] == mine[0] and (theirs[1] == mine[1] or mine[0] in ("Valid", "Waiting"))})
    # The reference reader's own samples, by name, against the case that reproduces each.
    case_of = {"a missing holder signature": "missing_holder_signature",
               "an iat not floor(asserted_at / 1000), refused alone": "iat_off_by_one",
               "a seat whose binding is not in cites": "seat_binding_not_cited",
               "holders and serve_nodes overlapping": "holders_seats_overlap",
               "a holder not removable_offline": "holder_not_removable_offline",
               "a holder whose chain does not verify": "holder_chain_untrusted_root",
               "a holder set unlike the anchor": "anchor_thumbprints_mismatch",
               "an object id unlike the anchor": "anchor_object_id_mismatch",
               "a cited row not held": "cited_row_not_held",
               "a version 2 with no prev": "version_2_no_prev",
               "a scope out of set order": "scope_unsorted",
               "a seat whose record ends before the bundle": "seat_record_ended_before",
               "a seat whose binding does not name its record": "binding_names_no_record",
               "a seat binding with no identity_key_id": "binding_no_identity_key_id",
               "a seat binding without refs.head": "binding_no_head",
               "a seat binding of device_class phone": "binding_device_class_phone",
               "a later bundle whose prev is not held": "later_prev_not_held",
               "a later bundle whose prev is not Valid": "later_prev_not_valid",
               "a later bundle changing family_key_id": "later_family_key_id_changed",
               "an added holder who did not sign": "later_added_holder_unsigned",
               "a change on a minority": "later_minority",
               "a recovery under the holder's signing key": "recovery_under_signing_key",
               "a recovery keeping its signing key": "recovery_reuses_signing_key",
               "a recovery that also re-commits another holder": "recovery_changes_other_seat",
               "a recovery seating its own recovery key": "recovery_key_is_signing_key",
               "a recovery keeping the spent commitment": "recovery_keeps_commitment",
               "a recovery whose recovery key's record is not named": "recovery_key_record_not_named",
               "a roster change adding a holder, signed by a majority and the added holder": "later_valid",
               "a recovery by the recovery key alone": "recovery_valid"}
    _, _, breaks, later_ok = ccm.reader_samples()
    cc_out["reader_breaks"] = [{"name": why, "expect": list(want), "case": case_of[why]} for why, _, want in breaks]
    cc_out["reader_valid"] = [{"name": why, "case": case_of[why]} for why, _ in later_ok]
    # reader_problems' three checks across two recoveries, by the case that reproduces each.
    cc_out["reader_chain_checks"] = [
        {"name": "a second recovery naming the spent commitment", "case": "second_recovery_relists_spent"},
        {"name": "a second recovery under the spent recovery key", "case": "recovery_spent_key"},
        {"name": "a second recovery with a fresh commitment", "case": "second_recovery_valid"}]

out = {
    "_meta": {
        "spec": "CC 2.6.1.11 / 4.2.6 / 4.2.2.1 / 3.3.6.1 / 3.3.6.2 / 3.2 T3 / 5.3.4, CIRISConstitution v1.0-rc21 b016df4; dial_hints as proposed for rc22",
        "generator": "gen_genesis_bundles_v4.py (independent of verify)",
        "keys": "Key n: ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32. Holders A,B,C,D = 1,2,3,4; seats 11,12; "
                "witnesses 21,22,23; stranger 9; A's other key 31; C's rotated key 33; recovery key of holder n = n+50; "
                "A's signing key after its first recovery 41, after its second 42; A's next recovery keys 61, 62; "
                "a key no commitment names 71.",
        "verdicts": "valid | invalid (token genesis_bundle_malformed, detail = reason) | waiting {rows, prev, kids} | "
                    "nothing (token; detail = the row, custody or commitment fault)",
    },
    "attestation_root_der": ROOT.der.hex(),
    "untrusted_root_der": UNTRUSTED.der.hex(),
    "parties": {name_: {"n": k.n, "kid": k.kid.hex(), "iss": k.iss} for name_, k in
                (("A", A), ("B", B), ("C", C), ("D", D), ("S1", S1), ("S2", S2), ("W1", W1), ("W2", W2), ("W3", W3),
                 ("X", X), ("A2", A2), ("C2", C2), ("A_NEW", A_NEW), ("A_NEW2", A_NEW2), ("A_REC1", REC[1]),
                 ("A_REC2", A_REC2), ("A_REC3", A_REC3), ("WRONG", WRONG))},
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


write("genesis_bundles_v4.json", out)
for i, chars in enumerate(("01", "23", "45", "67", "89", "ab", "cd", "ef")):
    write("pool_v4_%d.json" % i, {k: v for k, v in POOL.items() if k[0] in chars})
