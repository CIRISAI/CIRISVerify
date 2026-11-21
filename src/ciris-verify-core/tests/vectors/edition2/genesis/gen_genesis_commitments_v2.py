# Independent known answers for two recovery-commitment rules of a genesis bundle (CC 4.2.6: each holder
# carries its own recovery key, held offline and apart from the signing key), on the first bundle as well
# as on later ones. Found by CIRISServer's trust-root audit: before these, verify checked the first bundle
# for one commitment per holder only.
#
#   recovery_commitment_shared         two holders the bundle seats carry one commitment
#   recovery_commitment_is_holder_key  a commitment is over a signing key the bundle seats (own or another's)
#
# A commitment hashes a key set (CC 3.2 T3), so only an equal set is visible to a reader; overlapping sets are
# the ceremony's to refuse at mint.
#
# It reuses gen_genesis_bundles_v5.py (loaded beside it, run into a scratch directory whose output is
# discarded), as gen_genesis_holder_device_v2.py does, and shares no code with verify:
#
#   python3 -I gen_genesis_commitments_v2.py > genesis_commitments_v2.json
import importlib.util, json, os, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
argv = sys.argv
with tempfile.TemporaryDirectory() as scratch:
    sys.argv = ["gen_genesis_bundles_v5.py", "--out", scratch]
    spec = importlib.util.spec_from_file_location("g5", os.path.join(here, "gen_genesis_bundles_v5.py"))
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
sys.argv = argv
g.cases.clear(); g.POOL.clear(); g.cc_projections.clear()

A, B, C = g.A, g.B, g.C
an = g.TPS((A, B, C))
com = lambda *ks: g.hd(g.commitment(list(ks)))
FRESH = g.Key(81)                                  # a recovery key no case has used


def first(cid, desc, commits, expect):
    p = g.payload(commits=commits)
    oid = g.object_id(g.enc(p))
    e = (g.bundle(oid, "valid", placement=g.placement_of(p, (A, B, C), (g.S1, g.S2), (), (A, B, C)))
         if expect == "valid" else g.bundle(oid, "invalid", "genesis_bundle_malformed", expect))
    g.case(cid, desc, [g.voice(k, p) for k in (A, B, C)], g.held(*g.ALL), an, [e])
    return p, oid


def own(): return {h.iss: com(g.REC[h.n]) for h in (A, B, C)}


P0, OID0 = first("first_valid", "The first bundle, each holder's commitment over its own recovery key: Valid; the "
                 "predecessor of the later cases.", own(), "valid")
c = own(); c[B.iss] = c[A.iss]
first("first_shared_commitment", "A and B carry one commitment (A's recovery key): Invalid.", c, "recovery_commitment_shared")
c = own(); c[A.iss] = com(A)
first("first_commitment_own_key", "A's commitment is over A's own signing key: Invalid.", c, "recovery_commitment_is_holder_key")
c = own(); c[A.iss] = com(B)
first("first_commitment_other_holder_key", "A's commitment is over B's signing key, so B could recover A's seat: Invalid.",
      c, "recovery_commitment_is_holder_key")

PRE = [{"case": "first_valid"}]
GOOD = g.placement_of(P0, (A, B, C), (g.S1, g.S2), (), (A, B, C))


def later(cid, desc, commits, expect):
    p = g.payload(version=2, prev=OID0, at=g.T2, commits=commits)
    oid = g.object_id(g.enc(p))
    e = (g.bundle(oid, "valid", placement=g.placement_of(p, (A, B, C), (g.S1, g.S2), (), (A, B, C), prev=GOOD))
         if expect == "valid" else g.bundle(oid, "invalid", "genesis_bundle_malformed", expect))
    g.case(cid, desc, [g.voice(k, p) for k in (A, B, C)], g.held(*g.ALL), None, [e], predecessors=PRE)


c = own(); c[B.iss] = com(FRESH)
later("later_new_commitment", "Version 2, every holder signs: B's commitment moves to a fresh recovery key: Valid.", c, "valid")
c = own(); c[B.iss] = com(B)
later("later_commitment_own_key", "Version 2, every holder signs: B's new commitment is over B's own signing key: Invalid.",
      c, "recovery_commitment_is_holder_key")
c = own(); c[C.iss] = c[B.iss]
later("later_shared_commitment", "Version 2, every holder signs: C's new commitment is B's: Invalid.", c,
      "recovery_commitment_shared")

out = {
    "_meta": {
        "spec": "CC 4.2.6 pre-committed recovery keys; CC 2.6.1.11; CIRISConstitution v1.0-rc21 b016df4",
        "generator": "gen_genesis_commitments_v2.py over gen_genesis_bundles_v5.py (independent of verify)",
        "keys": "as genesis_bundles_v5.json; recovery key of holder n = n+50; a fresh recovery key 81.",
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
