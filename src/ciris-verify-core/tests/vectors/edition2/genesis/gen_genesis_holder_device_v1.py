# Independent known answers for `holder_device_shared` (CC 4.2.3 "One device per holder", the Part 2
# refusal row; CIRISConstitution v1.0-rc21 b016df4):
#
#   Where the leaf of a holder's `chain` names its device, the holders a bundle seats name distinct
#   devices: for YubiKey_5_FIPS the device is the token serial the leaf carries in extension
#   1.3.6.1.4.1.41482.3.7. A bundle that seats two holders whose leaves name one device is Invalid,
#   holder_device_shared. Two holders' chains may share an intermediate or an attestation key [...].
#   The leaf's device decides, and each leaf still verifies through its own chain.
#
# It reuses gen_genesis_bundles_v3.py's encoder, signer, mock PKI and case machinery (loaded beside it and run
# into a scratch directory, whose output is discarded), and adds only the serial extension and the cases.
# It shares no code with verify. Run from this directory:
#
#   python3 -I gen_genesis_holder_device_v1.py > genesis_holder_device_v1.json
#
# The file has the v3 case file's shape, with the statements inline under `pool`.
import importlib.util, json, os, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
argv = sys.argv
with tempfile.TemporaryDirectory() as scratch:
    sys.argv = ["gen_genesis_bundles_v3.py", "--out", scratch]
    spec = importlib.util.spec_from_file_location("g3", os.path.join(here, "gen_genesis_bundles_v3.py"))
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
sys.argv = argv
g.cases.clear(); g.POOL.clear(); g.cc_projections.clear()

OID_SERIAL = "1.3.6.1.4.1.41482.3.7"


def der_uint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")      # a leading 0x00 keeps it non-negative
    return b"\x02" + bytes([len(b)]) + b


def chain(ed_pub, n, serial=None, f9n=None):
    """[9c leaf, f9] as v3's yubikey_chain, the leaf carrying `serial` in .3.7 when given; `f9n` picks the f9
    (default: the holder's own, n), so holders given one f9n share one f9 certificate and attestation key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    f9n = n if f9n is None else f9n
    f9k = Ed25519PrivateKey.from_private_bytes(g.sha(b"f9" + bytes([f9n]) + g.ROOT.cn.encode()))
    f9cn = "YubiKey PIV Attestation f9 (MOCK %d)" % f9n
    f9 = g.cert(f9cn, g.ROOT.cn, f9k.public_key(), g.ROOT.key, 100 + f9n, [(g.OID_FIPS, b"")])
    exts = [(g.OID_FW, b"\x04\x03\x05\x07\x04"), (g.OID_TOUCH, b"\x04\x02\x01\x02")]
    if serial is not None: exts.append((OID_SERIAL, der_uint(serial)))
    leaf = g.cert("YubiKey PIV Attestation 9c (MOCK %d)" % n, f9cn, Ed25519PublicKey.from_public_bytes(ed_pub), f9k,
                  200 + n, exts)
    return [leaf, f9]


A, B, C = g.A, g.B, g.C
an = g.TPS((A, B, C))


def device_case(cid, desc, devices, expect):
    """devices: holder -> (serial or None, f9n or None). Each holder's record is swapped for one whose chain
    names that device; seats and their bindings stay v3's."""
    recs, extra = {}, []
    for h, (serial, f9n) in devices.items():
        r = g.holder_record(h, ev={"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline",
                                   "chain": chain(h.ed_pk, h.n, serial, f9n)})
        recs[h] = (r[1], h)
        extra.append({"id": r[1].hex(), "statement": g.put(r[0])})
    swapped = {"rec_%d" % h.n for h in devices}
    names = [n for n in g.ALL if n not in swapped]
    p = g.payload(rows=g.ids(names) + [r for r, _ in recs.values()])
    oid = g.object_id(g.enc(p))
    if expect == "valid":
        e = g.bundle(oid, "valid", placement=g.placement_of(p, (A, B, C), (g.S1, g.S2), (), (A, B, C), recs=recs))
    else:
        e = g.bundle(oid, "invalid", "genesis_bundle_malformed", expect)
    g.case(cid, desc, [g.voice(k, p) for k in (A, B, C)], g.held(*names, extra=extra), an, [e])


JULY = {A: 38165850, B: 38165563, C: 38165401}               # the July ceremony's A1, B1, C1 token serials
device_case("distinct_serials", "Three holders, each leaf naming its own token serial (the July serials), each "
            "under its own f9: Valid.", {h: (s, None) for h, s in JULY.items()}, "valid")
device_case("shared_serial", "Holders A and B name one token serial (38165850); C names its own: Invalid, "
            "holder_device_shared.", {A: (JULY[A], None), B: (JULY[A], None), C: (JULY[C], None)},
            "holder_device_shared")
device_case("shared_serial_all", "All three holders name one token serial: Invalid, holder_device_shared.",
            {h: (JULY[A], None) for h in (A, B, C)}, "holder_device_shared")
device_case("shared_f9_distinct_serials", "All three leaves are signed by one f9 (one attestation key, as on the "
            "July bundle), each naming its own serial: Valid; the leaf's device decides.",
            {h: (s, 1) for h, s in JULY.items()}, "valid")
device_case("shared_f9_shared_serial", "One f9 for all three, and A and C name one serial: Invalid.",
            {A: (JULY[A], 1), B: (JULY[B], 1), C: (JULY[A], 1)}, "holder_device_shared")
device_case("one_leaf_names_no_device", "A's leaf carries no serial extension; B and C name their own: Valid. "
            "CC 4.2.3 binds only where a leaf names its device.", {A: (None, None), B: (JULY[B], None),
                                                                    C: (JULY[C], None)}, "valid")
device_case("two_leaves_name_no_device", "A's and B's leaves carry no serial; C names its own: Valid (no device "
            "is named twice).", {A: (None, None), B: (None, None), C: (JULY[C], None)}, "valid")

out = {
    "_meta": {
        "spec": "CC 4.2.3 One device per holder; CC 2.6.1.11 refusal holder_device_shared; "
                "CIRISConstitution v1.0-rc21 b016df4",
        "generator": "gen_genesis_holder_device_v1.py over gen_genesis_bundles_v3.py (independent of verify)",
        "keys": "as genesis_bundles_v3.json: holders A,B,C = keys 1,2,3; seats 11,12. The serial is a DER INTEGER "
                "in extension 1.3.6.1.4.1.41482.3.7 of the 9c leaf.",
        "verdicts": "valid | invalid (token genesis_bundle_malformed, detail = reason)",
    },
    "attestation_root_der": g.ROOT.der.hex(),
    "untrusted_root_der": g.UNTRUSTED.der.hex(),
    "seat_xwing": {n: {"transit_xwing_pubkey": g.seat_keys(k)[0].hex(), "onion_hop_xwing_pubkey": g.seat_keys(k)[1].hex()}
                   for n, k in (("S1", g.S1), ("S2", g.S2))},
    "cases": g.cases,
    "pool": dict(sorted(g.POOL.items())),
}
json.dump(out, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
