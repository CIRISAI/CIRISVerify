# Version 3: version 2 (gen_genesis_reseat_v2.py, kept as it was) over gen_genesis_bundles_v5.py, whose seat bindings carry
# dial_hints (CC 3.3.6.1). Nothing else changes.
# Independent generator of `ceg-genesis-bundle/2` known answers for a re-seated serve node (CC 2.6.1.11,
# CC 2.6.1.7, CC 3.3.6.2, CIRISConstitution rc21-wire e6fd7c6).
#
# A later bundle may seat a serve node at a new key while the seat keeps its identity reference: `iss` is the
# identity reference of the signer's genesis key, "so the issuer stays the same when the signing key rotates"
# (CC 2.6.1.7); "every holder's and seat's key record verifies under its own key" and a seat's standing "rides
# no key record, so it survives the seat's renewals and moves only by a later bundle" (CC 2.6.1.11); the
# binding is "authored and signed by the identity it binds" and names the seat's own key record (CC 3.3.6.2).
# Version 2 (rc21): the binding is the seat's own identity:occurrence, so it carries identity_key_id and
# occurrence_key_id, both the seat's identity reference (S1's, not the new key's), and device_class "server"
# (CC 2.6.1.11). gen_genesis_reseat_v1.py and genesis_reseat_v1.json stay as they were.
#
# Every case here is a later bundle over gen_genesis_bundles_v5.py's `first_valid`, which this file repeats
# (same statements, same rows) so it replays on its own.
#
# It reuses gen_genesis_bundles_v5.py's machinery (its CBOR encoder, composite signer, parties, records,
# payload and placement builders) by loading that file as a module. That file writes its own outputs when
# it runs, so it is loaded with `--out` pointed at a throwaway directory and without `--cc`; the published
# v3 files are never touched. Nothing here is shared with verify.
#
#   pip install dilithium-py kyber-py cryptography
#   python3 -I gen_genesis_reseat_v4.py --out .
#
# It writes genesis_reseat_v4.json: the cases, and under `pool` every statement they name.
import importlib.util, json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def load_v4():
    argv = sys.argv
    with tempfile.TemporaryDirectory() as scratch:
        sys.argv = [os.path.join(HERE, "gen_genesis_bundles_v5.py"), "--out", scratch]
        try:
            spec = importlib.util.spec_from_file_location("gen_genesis_bundles_v5", sys.argv[0])
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        finally:
            sys.argv = argv
    return m


g = load_v4()
g.POOL = {}                                   # this file's own pool: only the statements its cases name

A, B, C, S1, S2 = g.A, g.B, g.C, g.S1, g.S2
S1N = g.Key(13)                               # the key S1 is re-seated at
U = g.Key(14)                                 # a key unrelated to S1
T_SEAT = g.T2 - 1000                          # the new record's and binding's instant, before the bundle's


def reseat_record(seat, key):
    """The seat's new key:record: iss = author = sub = the seat's identity reference, signed by the new key."""
    p = {"key": key.cose, "author": seat.iss, "asserted_at": T_SEAT, "identity_type": ["node"],
         "valid_until": T_SEAT + g.YEAR}
    return g.row(key, "key:record", p, sub=seat.iss, iss=seat.iss)


def reseat_binding(seat, key, record_id, signer, ident=None):
    """The seat's binding at its new key: iss = author = sub = identity_key_id = occurrence_key_id = the seat's
    identity reference, device_class "server", the new key's X-Wing and RNS keys, refs naming `record_id`,
    signed by `signer`."""
    t, o = g.seat_keys(key)
    rx = g.x25519_pub(g.sha(b"rns-x" + bytes([key.n])))
    re_ = g.ed25519_pub(g.sha(b"rns-ed" + bytes([key.n])))
    td = {"reticulum_x25519_pubkey": rx, "reticulum_ed25519_pubkey": re_, "app_name": "ciris.federation",
          "aspects": ["serve"], "destination_hash": g.rns_destination_hash(rx, re_, "ciris.federation", ["serve"])}
    p = {"author": seat.iss, "asserted_at": T_SEAT, "transport_destination": td,
         "transit_xwing_pubkey": t, "onion_hop_xwing_pubkey": o,
         "identity_key_id": ident or seat.iss, "occurrence_key_id": ident or seat.iss, "device_class": "server",
         "dial_hints": g.seat_hints(seat.n),
         "refs": {"head": g.rref(R["rec_%d" % seat.n][1]), "also": {"cites": [g.rref(record_id)]}}}
    return g.row(signer, "identity:occurrence", p, sub=seat.iss, iss=seat.iss)


R = g.R
R["rec_s1n"] = reseat_record(S1, S1N)
R["bind_s1n"] = reseat_binding(S1, S1N, R["rec_s1n"][1], signer=S1N)
R["bind_s1n_by_s1"] = reseat_binding(S1, S1N, R["rec_s1n"][1], signer=S1)
R["bind_s1n_by_u"] = reseat_binding(S1, S1N, R["rec_s1n"][1], signer=U)
# The three bindings carry one payload under one (sub, author), so they share one row id; only the signer
# differs. The bundle names that row id; each case holds one of the three statements under it.
assert R["bind_s1n"][1] == R["bind_s1n_by_s1"][1] == R["bind_s1n_by_u"][1]
# The binding at S1N naming S1N's own identity reference as identity_key_id and occurrence_key_id: its own
# payload, so its own row id.
R["bind_s1n_ident_new"] = reseat_binding(S1, S1N, R["rec_s1n"][1], signer=S1N, ident=S1N.iss)

cases = []


def case(cid, desc, statements, rows, anchor, expect, predecessors=()):
    cases.append({"id": cid, "description": desc, "statements": [g.put(s) for s in statements], "rows": rows,
                  "anchor": anchor, "predecessors": list(predecessors), "expect": expect, "top_refused": []})


def held_as(pairs):
    """Rows held: (name of the row id, name of the statement held under it)."""
    return [{"id": R[i][1].hex(), "statement": g.put(R[s][0])} for i, s in pairs]


# ---------------------------------------------------------------- the predecessor: v3's first_valid, repeated
P = g.payload()
OID = g.object_id(g.enc(P))
GOOD = g.placement_of(P, (A, B, C), (S1, S2), (), (A, B, C))
case("first_valid", "v3's first_valid: three holders, two seats, every holder signed, thumbprint anchor.",
     [g.voice(k, P) for k in (A, B, C)], g.held(*g.ALL), g.TPS((A, B, C)), [g.bundle(OID, "valid", placement=GOOD)])
PRE = [{"case": "first_valid"}]

# ---------------------------------------------------------------- the later bundle re-seating S1 at S1N
NAMES = ["rec_1", "rec_2", "rec_3", "rec_s1n", "rec_12", "bind_s1n", "bind_12"]
PL = g.payload(rows=g.ids(NAMES), version=2, prev=OID, at=g.T2)
OL = g.object_id(g.enc(PL))
VOICES = [g.voice(k, PL) for k in (A, B, C)]

LP = g.placement_of(PL, (A, B, C), (S1, S2), (), (A, B, C), prev=GOOD)
t, o = g.seat_keys(S1N)
for s in LP["seats"]:
    if s["identity_ref"] == S1.iss:
        s.update(kid=S1N.kid.hex(), record=R["rec_s1n"][1].hex(), binding=R["bind_s1n"][1].hex(),
                 valid_until=T_SEAT + g.YEAR, transit_xwing_pubkey_sha256=g.sha(t).hex(),
                 onion_hop_xwing_pubkey_sha256=g.sha(o).hex(),
                 transit_seed=g.sha(b"transit" + bytes([S1N.n])).hex(),
                 onion_seed=g.sha(b"onion" + bytes([S1N.n])).hex(),
                 dial_hints=g.hints_json(g.seat_hints(S1.n)))


def rows_with(binding_stmt):
    return held_as([(n, n) for n in NAMES if n != "bind_s1n"] + [("bind_s1n", binding_stmt)])


case("reseat_seat_new_key",
     "A later bundle every holder signs re-seats S1 at a new key S1N. S1's new key record and its binding are "
     "authored with iss = author = S1's identity reference and signed by S1N; the binding names the new record. "
     "S1 is placed at S1N's key, record, binding and X-Wing keys.",
     VOICES, rows_with("bind_s1n"), None, [g.bundle(OL, "valid", placement=LP)], predecessors=PRE)
case("reseat_binding_signed_by_old_key",
     "The same bundle, with S1's binding signed by S1's previous key while the record the bundle places for S1 "
     "names S1N: the binding does not verify under the key placed for the seat.",
     VOICES, rows_with("bind_s1n_by_s1"), None,
     [g.bundle(OL, "nothing", "genesis_bundle_row_invalid", "row_signer")], predecessors=PRE)
case("reseat_binding_signed_by_unrelated_key",
     "The same bundle, with S1's binding (iss S1) signed by a key U unrelated to S1: the binding does not verify "
     "under the key placed for the seat.",
     VOICES, rows_with("bind_s1n_by_u"), None,
     [g.bundle(OL, "nothing", "genesis_bundle_row_invalid", "row_signer")], predecessors=PRE)

NAMES_IDENT = [n if n != "bind_s1n" else "bind_s1n_ident_new" for n in NAMES]
PI = g.payload(rows=g.ids(NAMES_IDENT), version=2, prev=OID, at=g.T2)
OI = g.object_id(g.enc(PI))
case("reseat_binding_names_new_key",
     "A later bundle re-seating S1 at S1N whose binding (author S1, signed by S1N) names S1N's identity reference "
     "as identity_key_id and occurrence_key_id: they must be the seat's identity reference, S1's (CC 2.6.1.11).",
     [g.voice(k, PI) for k in (A, B, C)], held_as([(n, n) for n in NAMES_IDENT]), None,
     [g.bundle(OI, "nothing", "genesis_bundle_row_invalid", "row_invalid")], predecessors=PRE)

out = {
    "_meta": {
        "spec": "CC 2.6.1.11 / 2.6.1.7 / 3.3.6.2, CIRISConstitution rc21-wire e6fd7c6",
        "generator": "gen_genesis_reseat_v4.py over gen_genesis_bundles_v5.py's machinery (independent of verify)",
        "keys": "As genesis_bundles_v5.json, plus S1N = Key 13 (S1's new key) and U = Key 14 (a key unrelated to "
                "S1). Key n: ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32.",
        "verdicts": "As genesis_bundles_v5.json.",
    },
    "attestation_root_der": g.ROOT.der.hex(),
    "parties": {n: {"n": k.n, "kid": k.kid.hex(), "iss": k.iss} for n, k in
                (("A", A), ("B", B), ("C", C), ("S1", S1), ("S2", S2), ("S1N", S1N), ("U", U))},
    "seat_xwing": {n: {"transit_xwing_pubkey": g.seat_keys(k)[0].hex(),
                       "onion_hop_xwing_pubkey": g.seat_keys(k)[1].hex()}
                   for n, k in (("S1", S1), ("S2", S2), ("S1N", S1N))},
    "cases": cases,
    "pool": g.POOL,
}
OUT = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "."
with open(os.path.join(OUT, "genesis_reseat_v4.json"), "w") as fh:
    json.dump(out, fh, indent=1, sort_keys=True)
    fh.write("\n")
