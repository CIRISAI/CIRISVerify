# gen_genesis_join_v1.py: a later genesis bundle that joins tips (CC 2.6.1.11, "A bundle that joins tips";
# CIRISConstitution rc23 lane, d103e60). genesis_bundles_v6.json and its pools are unchanged and still replayed.
#
# The rules these cases fix:
#   - `refs.further_prev`: a set of at least one object reference, beside `prev`, never without it, never naming
#     `prev` again (genesis_bundle_schema; federation_set_semantics_unsorted);
#   - `version` is one greater than the greatest among the predecessors named, and `prev` names the predecessor of
#     greatest version, among equals the least object id (version_prev_mismatch); one family_key_id
#     (family_key_id_changed); a predecessor in another's lineage past (further_prev_not_newest);
#   - Waiting on a predecessor not held (waiting.prev, waiting.further_prev); genesis_bundle_prev_not_valid;
#   - the count: a strict majority of EACH named predecessor's live holders, each voice under the key that
#     predecessor seats it at; a holder one branch rotated signs under each of its keys; a signing key a recovery
#     on any branch replaced is no voice, and the holder a predecessor still seats at it is no live holder of that
#     predecessor; a predecessor left with no live holder counts nothing;
#   - a holder in no predecessor signs, as does a holder whose commitment differs from a predecessor's (the
#     single-predecessor rule read over each predecessor; confirmed by the Constitution 2026-11-27);
#   - a join inherits the union: a key retired on any branch is holder_key_retired though another branch still
#     seats it; a commitment spent on any branch is recovery_commitment_spent;
#   - a recovery carries no further_prev (recovery_changes_other_seat);
#   - a recovery behind its holder's head (concludes nothing, token recovery_behind_head): the reader holds a Valid bundle of the lineage in
#     which the holder's statement counted, with the recovery's prev strictly behind what that bundle extends. A
#     bundle naming the same prev is a sibling, a fork (as v6's fork_roster_and_recovery).
#
# Reuses gen_genesis_bundles_v6.py's own CBOR encoder, composite signer, mock attestation PKI and parties (loaded with
# its output written to a scratch directory); shares no code with verify.
#   python3 -I gen_genesis_join_v1.py --out .
# It writes genesis_join_v1.json and pool_join_v1_0.json .. pool_join_v1_3.json.
import json, os, runpy, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "."
argv = sys.argv
with tempfile.TemporaryDirectory() as scratch:
    sys.argv = ["gen_genesis_bundles_v6.py", "--out", scratch]
    g = runpy.run_path(os.path.join(here, "gen_genesis_bundles_v6.py"))
sys.argv = argv
globals().update({k: v for k, v in g.items() if not k.startswith("__") and k not in ("OUT", "write", "out")})
cases.clear(); POOL.clear(); cc_projections.clear()

SEAT_ROWS = ["rec_11", "rec_12", "bind_11", "bind_12"]


def later(holders, names, version, prev, further=(), at=T2, commits=None, **kw):
    """A later bundle's payload; `further` the further predecessors, written as a set."""
    p = payload(holders=holders, rows=ids(names), version=version, prev=prev, at=at,
                commits=commits or {h.iss: hd(commitment([REC[h.n]])) for h in holders}, **kw)
    if further: p["refs"]["further_prev"] = cset([rref(x) for x in further])
    return p


def order(*oids_versions):
    """prev (greatest version, least object id) and the rest."""
    xs = sorted(oids_versions, key=lambda x: (-x[1], x[0]))
    return xs[0][0], [x[0] for x in xs[1:]]


def place(p, holders, counted, preds, recs=None, recovered=None, rk=None, old=None):
    """The placement of a Valid later bundle over `preds` (their placements): the union of what they retired and
    spent, the keys this bundle leaves, and its lineage past."""
    out = placement_of(p, holders, (S1, S2), (), counted, recs=recs)
    recs = recs or {}
    out["further_prev"] = [x[1][1].hex() for x in p["refs"].get("further_prev", [])]
    past, spent, lineage, retired, rret = set(), set(), set(), {}, {}
    for q in preds:
        past |= set(q.get("past", [])) | {q["object_id"]}
        spent |= set(q["spent_commitments"]); lineage |= set(q["lineage_commitments"])
        for k, v in q["retired_holder_keys"].items(): retired.setdefault(k, set()).update(v)
        for k, v in q.get("recovery_retired_keys", {}).items(): rret.setdefault(k, set()).update(v)
    for q in preds:
        for x in q["holders"]:
            h = next((h for h in holders if h.iss == x["identity_ref"]), None)
            if h is not None and recs.get(h, (None, h))[1].kid.hex() != x["kid"]:
                retired.setdefault(h.iss, set()).add(x["kid"])
    if recovered is not None:
        spent.add(next(x["recovery_commitment"] for x in preds[0]["holders"] if x["identity_ref"] == recovered.iss))
        retired.setdefault(recovered.iss, set()).add(rk.kid.hex())
        rret.setdefault(recovered.iss, set()).add(old.kid.hex())
        out["recovered"] = recovered.iss
    lineage |= {c[1].hex() for c in p["charter"]["recovery_commitments"].values()}
    out.update(past=sorted(past), spent_commitments=sorted(spent), lineage_commitments=sorted(lineage),
               retired_holder_keys={k: sorted(v) for k, v in retired.items()},
               recovery_retired_keys={k: sorted(v) for k, v in rret.items()})
    return out


def oid_of(p): return object_id(enc(p))
def valid(p, pl): return [bundle(oid_of(p), "valid", placement=pl)]
def inv(p, reason, refused=()): return [bundle(oid_of(p), "invalid", "genesis_bundle_malformed", reason, refused=refused)]
def none(p, token, detail=None, refused=()): return [bundle(oid_of(p), "nothing", token, detail, refused=refused)]
def pre(*names): return [{"case": n} for n in names]
def va(k, p): return voice(k, p, iss=A.iss)                 # A's statement under another of A's keys


G = dict(GOOD_PLACEMENT, past=[], further_prev=[], recovery_retired_keys={})
case("first", "The first bundle: A, B and C sign.", V3, held(*ALL), an, [bundle(OID, "valid", placement=G)])

# ---------------------------------------------------------------- the branches, each a successor of the first
LN = ["rec_1", "rec_2", "rec_4"] + SEAT_ROWS
PL1 = later((A, B, D), LN, 2, OID)
PL2 = later((A, B, D), LN, 2, OID, at=T2 + 1000)
L1 = place(PL1, (A, B, D), (A, B, D), [G])
L2 = place(PL2, (A, B, D), (A, B, D), [G])
case("swap_1", "C swapped for D; A, B and D sign.", [voice(k, PL1) for k in (A, B, D)], held(*LN), None,
     valid(PL1, L1), predecessors=pre("first"))
case("swap_2", "The same change a second later: a second successor of the first bundle.",
     [voice(k, PL2) for k in (A, B, D)], held(*LN), None, valid(PL2, L2), predecessors=pre("first"))
O1, O2 = oid_of(PL1), oid_of(PL2)

RN = ["recA", "rec_2", "rec_3"] + SEAT_ROWS
PROT = later((A, B, C), RN, 2, OID, at=T2 + 2000)
ROT = place(PROT, (A, B, C), (A, B, C), [G], recs={A: (R["recA"][1], A_NEW)})
case("rotation", "A rotates to a new key by a roster bundle every holder signs, A under its current key.",
     [voice(k, PROT) for k in (A, B, C)], held(*RN), None, valid(PROT, ROT), predecessors=pre("first"))
OROT = oid_of(PROT)

CN = ["recA", "rk_1", "rec_2", "rec_3"] + SEAT_ROWS
NEXT_A = {A.iss: hd(commitment([A_REC2])), B.iss: hd(commitment([REC[2]])), C.iss: hd(commitment([REC[3]]))}
PREC = later((A, B, C), CN, 2, OID, commits=NEXT_A)
RECV = place(PREC, (A, B, C), (A,), [G], recs={A: (R["recA"][1], A_NEW)}, recovered=A, rk=REC[1], old=A)
case("recovery", "A recovers under its recovery key: its genesis signing key is replaced.",
     [va(REC[1], PREC)], held(*CN), None, valid(PREC, RECV), predecessors=pre("first"))
OREC = oid_of(PREC)

# a third bundle on swap_1, in two readings: A and B sign it, or B and D do
PL3 = later((A, B, D), LN, 3, O1, at=T2 + 5000,
            commits={A.iss: hd(commitment([REC[1]])), B.iss: hd(commitment([WRONG])), D.iss: hd(commitment([REC[4]]))})
L3_AB = place(PL3, (A, B, D), (A, B), [L1])
L3_BD = place(PL3, (A, B, D), (B, D), [L1])
case("third_signed_by_a", "A third bundle on swap_1 re-committing B; A and B sign.",
     [voice(k, PL3) for k in (A, B)], held(*LN), None, valid(PL3, L3_AB), predecessors=pre("swap_1"))
case("third_not_signed_by_a", "The same bundle held with B's and D's statements only.",
     [voice(k, PL3) for k in (B, D)], held(*LN), None, valid(PL3, L3_BD), predecessors=pre("swap_1"))
O3 = oid_of(PL3)

# ---------------------------------------------------------------- the wire of a join
pv, fp = order((O1, 2), (O2, 2))
PJ = later((A, B, D), LN, 3, pv, fp, at=T2 + 9000)
J = place(PJ, (A, B, D), (A, B), [L1, L2])
case("join_valid", "A join of the two swaps: version 3, prev the lesser object id, the other in further_prev; A and "
     "B sign, a strict majority of each predecessor's holders.",
     [voice(k, PJ) for k in (A, B)], held(*LN), None, valid(PJ, J), predecessors=pre("swap_1", "swap_2"))
PJ_sw = later((A, B, D), LN, 3, fp[0], [pv], at=T2 + 9000)
case("join_prev_not_least_id", "The same join with prev and further_prev exchanged: among equal versions prev is the "
     "least object id.", [voice(k, PJ_sw) for k in (A, B)], held(*LN), None, inv(PJ_sw, "version_prev_mismatch"),
     predecessors=pre("swap_1", "swap_2"))
PJ_v = later((A, B, D), LN, 4, pv, fp, at=T2 + 9000)
case("join_version_not_greatest_plus_one", "The join at version 4 over two version-2 predecessors.",
     [voice(k, PJ_v) for k in (A, B)], held(*LN), None, inv(PJ_v, "version_prev_mismatch"),
     predecessors=pre("swap_1", "swap_2"))
PJ_u = later((A, B, D), LN, 4, O3, [O2], at=T2 + 9000,
             commits={A.iss: hd(commitment([REC[1]])), B.iss: hd(commitment([WRONG])), D.iss: hd(commitment([REC[4]]))})
case("join_unequal_versions", "A join of a version-3 and a version-2 bundle: version 4, prev the version-3 one. B's "
     "commitment differs from the version-2 predecessor's, so B signs; A and B do.",
     [voice(k, PJ_u) for k in (A, B)], held(*LN), None, valid(PJ_u, place(PJ_u, (A, B, D), (A, B), [L3_AB, L2])),
     predecessors=pre("third_signed_by_a", "swap_2"))
PJ_ul = later((A, B, D), LN, 4, O2, [O3], at=T2 + 9000,
              commits={A.iss: hd(commitment([REC[1]])), B.iss: hd(commitment([WRONG])), D.iss: hd(commitment([REC[4]]))})
case("join_prev_not_greatest_version", "The same join with prev naming the version-2 predecessor.",
     [voice(k, PJ_ul) for k in (A, B)], held(*LN), None, inv(PJ_ul, "version_prev_mismatch"),
     predecessors=pre("third_signed_by_a", "swap_2"))
PJ_past = later((A, B, D), LN, 4, O3, [O1], at=T2 + 9000,
                commits={A.iss: hd(commitment([REC[1]])), B.iss: hd(commitment([WRONG])), D.iss: hd(commitment([REC[4]]))})
case("join_names_a_predecessor_in_anothers_past", "A join naming the third bundle and swap_1, which the third "
     "extends.", [voice(k, PJ_past) for k in (A, B, D)], held(*LN), None, inv(PJ_past, "further_prev_not_newest"),
     predecessors=pre("swap_1", "third_signed_by_a"))


def edit_refs(f):
    def e(p): f(p["refs"])
    return e


PB_np = later((A, B, D), LN, 2, OID, edit=edit_refs(lambda r: (r.pop("prev"), r.__setitem__("further_prev", [rref(O2)]))))
case("further_prev_without_prev", "further_prev with no prev.", [voice(k, PB_np) for k in (A, B)], held(*LN), None,
     inv(PB_np, "genesis_bundle_schema"), predecessors=pre("swap_2"))
PB_em = later((A, B, D), LN, 3, O1, edit=edit_refs(lambda r: r.__setitem__("further_prev", [])))
case("further_prev_empty", "further_prev as an empty set: absence is its one encoding.",
     [voice(k, PB_em) for k in (A, B)], held(*LN), None, inv(PB_em, "genesis_bundle_schema"), predecessors=pre("swap_1"))
PB_dup = later((A, B, D), LN, 3, O1, edit=edit_refs(lambda r: r.__setitem__("further_prev", [rref(O1)])))
case("further_prev_names_prev", "further_prev naming prev again.", [voice(k, PB_dup) for k in (A, B)], held(*LN),
     None, inv(PB_dup, "genesis_bundle_schema"), predecessors=pre("swap_1"))
unsorted = list(reversed(cset([rref(O2), rref(O3)])))
PB_un = later((A, B, D), LN, 4, O1, edit=edit_refs(lambda r: r.__setitem__("further_prev", unsorted)))
case("further_prev_unsorted", "further_prev out of set order.", [voice(k, PB_un) for k in (A, B)], held(*LN), None,
     inv(PB_un, "federation_set_semantics_unsorted"), predecessors=pre("swap_1"))
PB_obj = later((A, B, D), LN, 3, O1, edit=edit_refs(lambda r: r.__setitem__("further_prev", [hd(O2)])))
case("further_prev_bare_digest", "further_prev holding a bare digest, not an object reference.",
     [voice(k, PB_obj) for k in (A, B)], held(*LN), None, inv(PB_obj, "genesis_bundle_schema"),
     predecessors=pre("swap_1"))

# ---------------------------------------------------------------- what a join waits on
w = lambda prev, further: {"rows": [], "kids": [], "prev": prev, "further_prev": further}
case("join_further_predecessor_not_held", "The join with only its prev held: Waiting on the further predecessor.",
     [voice(k, PJ) for k in (A, B)], held(*LN), None,
     [bundle(oid_of(PJ), "waiting", waiting=w(None, [fp[0].hex()]))],
     predecessors=pre("swap_1" if pv == O1 else "swap_2"))
case("join_prev_not_held", "The join with only its further predecessor held: Waiting on prev.",
     [voice(k, PJ) for k in (A, B)], held(*LN), None,
     [bundle(oid_of(PJ), "waiting", waiting=w(pv.hex(), []))],
     predecessors=pre("swap_2" if pv == O1 else "swap_1"))
case("join_no_predecessor_held", "The join with neither held: Waiting on both.",
     [voice(k, PJ) for k in (A, B)], held(*LN), None,
     [bundle(oid_of(PJ), "waiting", waiting=w(pv.hex(), [fp[0].hex()]))])
case("join_predecessor_not_valid", "The join where the further predecessor is held and not Valid.",
     [voice(k, PJ) for k in (A, B)], held(*LN), None, none(PJ, "genesis_bundle_prev_not_valid"),
     predecessors=pre("swap_1" if pv == O1 else "swap_2") + [{"not_valid": fp[0].hex()}])

# another lineage: its first bundle carries another family_key_id
P_other = payload(fam="another-accord", at=T1 + 5000)
case("first_of_another_lineage", "A first bundle of the same holders under another family_key_id.",
     [voice(k, P_other) for k in (A, B, C)], held(*ALL), an,
     valid(P_other, dict(placement_of(P_other, (A, B, C), (S1, S2), (), (A, B, C)), past=[], further_prev=[],
                         recovery_retired_keys={})))
PJ_fam = later((A, B, D), LN, 3, O1, [oid_of(P_other)], at=T2 + 9000)
case("join_across_lineages", "A join naming swap_1 and the first bundle of another lineage: the predecessors carry "
     "one family_key_id.", [voice(k, PJ_fam) for k in (A, B, D)], held(*LN), None,
     inv(PJ_fam, "family_key_id_changed"), predecessors=pre("swap_1", "first_of_another_lineage"))

# ---------------------------------------------------------------- the count, for each predecessor
ALLN = ["recA", "rec_2", "rec_3", "rec_4"] + SEAT_ROWS
pv2, fp2 = order((O1, 2), (OROT, 2))
PJR = later((A, B, C, D), ALLN, 3, pv2, fp2, at=T2 + 9000)
preds_r = [L1, ROT] if pv2 == O1 else [ROT, L1]
RECS_NEW = {A: (R["recA"][1], A_NEW)}
case("join_rotated_holder_signs_under_each_key", "A join of swap_1 (A at its genesis key, B, D) and the rotation (A "
     "at its new key, B, C), seating A, B, C and D. A signs under each of its keys and B signs: A and B of swap_1's "
     "three, A and B of the rotation's three.",
     [voice(A, PJR), va(A_NEW, PJR), voice(B, PJR)], held(*ALLN), None,
     valid(PJR, place(PJR, (A, B, C, D), (A, B), preds_r, recs=RECS_NEW)), predecessors=pre("swap_1", "rotation"))
case("join_counted_without_the_rotated_holder", "The same join signed by B, C and D: B and D of swap_1's three, B and "
     "C of the rotation's three.",
     [voice(k, PJR) for k in (B, C, D)], held(*ALLN), None,
     valid(PJR, place(PJR, (A, B, C, D), (B, C, D), preds_r, recs=RECS_NEW)), predecessors=pre("swap_1", "rotation"))
case("join_majority_of_one_predecessor_only", "The same join signed by A under its genesis key, B and D: all of "
     "swap_1's holders, and of the rotation's three only B. A majority of the holders taken together is no count.",
     [voice(k, PJR) for k in (A, B, D)], held(*ALLN), None, none(PJR, "genesis_bundle_count_unmet"),
     predecessors=pre("swap_1", "rotation"))
case("join_voice_under_a_key_no_predecessor_seats", "The same join with A's statement under a key neither "
     "predecessor seats for it, beside B's: the statement is refused alone, and B alone is no majority of either.",
     [va(A2, PJR), voice(B, PJR)], held(*ALLN), None,
     none(PJR, "genesis_bundle_count_unmet", refused=[(0, "statement_kid_not_iss")]),
     predecessors=pre("swap_1", "rotation"))
GENN = ["rec_1", "rec_2", "rec_3", "rec_4"] + SEAT_ROWS
PJR_back = later((A, B, C, D), GENN, 3, pv2, fp2, at=T2 + 9000)
case("join_revives_a_key_one_branch_retired", "The join seating A at its genesis key, which swap_1 still seats and the "
     "rotation's branch retired: a join revives nothing.",
     [voice(A, PJR_back), va(A_NEW, PJR_back), voice(B, PJR_back)], held(*GENN), None,
     inv(PJR_back, "holder_key_retired"), predecessors=pre("swap_1", "rotation"))

# a holder in no predecessor signs
PJ_add = later((A, B, C, D), GENN, 3, pv, fp, at=T2 + 9000)
case("join_added_holder_unsigned", "A join of the two swaps that seats C again; A, B and D sign and C does not.",
     [voice(k, PJ_add) for k in (A, B, D)], held(*GENN), None, none(PJ_add, "genesis_bundle_count_unmet"),
     predecessors=pre("swap_1", "swap_2"))
case("join_added_holder_signs", "The same join with C's statement under its record's key.",
     [voice(k, PJ_add) for k in (A, B, C)], held(*GENN), None,
     valid(PJ_add, place(PJ_add, (A, B, C, D), (A, B, C), [L1, L2])), predecessors=pre("swap_1", "swap_2"))

# ---------------------------------------------------------------- a join over a recovery
pv3, fp3 = order((O1, 2), (OREC, 2))
preds_c = [L1, RECV] if pv3 == O1 else [RECV, L1]
COM_J = {A.iss: hd(commitment([A_REC2])), B.iss: hd(commitment([REC[2]])), C.iss: hd(commitment([REC[3]])),
         D.iss: hd(commitment([REC[4]]))}
PJC = later((A, B, C, D), ALLN, 3, pv3, fp3, at=T2 + 9000, commits=COM_J)
case("join_over_a_recovery", "A join of swap_1 and A's recovery. A's genesis key, which swap_1 still seats, is no "
     "voice and A is no live holder of swap_1: its live holders are B and D. A under its recovered key, B and D "
     "sign: B and D of swap_1's two, A and B of the recovery's three.",
     [va(A_NEW, PJC), voice(B, PJC), voice(D, PJC)], held(*ALLN), None,
     valid(PJC, place(PJC, (A, B, C, D), (A, B, D), preds_c, recs=RECS_NEW)), predecessors=pre("swap_1", "recovery"))
case("join_replaced_key_is_no_voice", "The same join signed by A under its genesis key and its recovered key, B and "
     "C. A's statement under the replaced key is refused alone; of swap_1's live holders, B and D, only B signs.",
     [voice(A, PJC), va(A_NEW, PJC), voice(B, PJC), voice(C, PJC)], held(*ALLN), None,
     none(PJC, "genesis_bundle_count_unmet", refused=[(0, "statement_kid_not_iss")]),
     predecessors=pre("swap_1", "recovery"))
case("join_changed_commitment_holder_unsigned", "The same join signed by B, C and D: both counts are met, but A's "
     "commitment differs from the one swap_1 carries for it, and A has not signed.",
     [voice(k, PJC) for k in (B, C, D)], held(*ALLN), None, none(PJC, "genesis_bundle_count_unmet"),
     predecessors=pre("swap_1", "recovery"))
PJC_sp = later((A, B, C, D), ALLN, 3, pv3, fp3, at=T2 + 9000)
case("join_names_a_commitment_one_branch_spent", "The join keeping for A the commitment swap_1 carries, which the "
     "recovery spent.", [va(A_NEW, PJC_sp), voice(B, PJC_sp), voice(D, PJC_sp)], held(*ALLN), None,
     none(PJC_sp, "genesis_bundle_count_unmet", "recovery_commitment_spent"), predecessors=pre("swap_1", "recovery"))
PJC_back = later((A, B, C, D), GENN, 3, pv3, fp3, at=T2 + 9000, commits=COM_J)
case("join_seats_the_key_a_recovery_replaced", "The join seating A at its genesis key, which the recovery replaced.",
     [va(A_NEW, PJC_back), voice(B, PJC_back), voice(D, PJC_back)], held(*GENN), None,
     inv(PJC_back, "holder_key_retired"), predecessors=pre("swap_1", "recovery"))

# a recovery carries no further_prev
RJN = ["recA", "rk_1", "rec_2", "rec_4"] + SEAT_ROWS
PRJ = later((A, B, D), RJN, 3, pv, fp, at=T2 + 9000,
            commits={A.iss: hd(commitment([A_REC2])), B.iss: hd(commitment([REC[2]])), D.iss: hd(commitment([REC[4]]))})
case("recovery_with_further_prev", "A's recovery statement, alone, over a bundle that names two predecessors.",
     [va(REC[1], PRJ)], held(*RJN), None, inv(PRJ, "recovery_changes_other_seat"), predecessors=pre("swap_1", "swap_2"))

# ---------------------------------------------------------------- a predecessor with no live holder
ONE = ["rec_1"] + SEAT_ROWS
P1 = payload(holders=(A,), at=T1 + 7000)
G1 = dict(placement_of(P1, (A,), (S1, S2), (), (A,)), past=[], further_prev=[], recovery_retired_keys={})
case("first_of_one_holder", "A first bundle with one holder, A.", [voice(A, P1)], held(*ONE), TPS((A,)), valid(P1, G1))
OG1 = oid_of(P1)
ONE_R = ["recA", "rk_1"] + SEAT_ROWS
P1R = later((A,), ONE_R, 2, OG1, commits={A.iss: hd(commitment([A_REC2]))})
G1R = place(P1R, (A,), (A,), [G1], recs=RECS_NEW, recovered=A, rk=REC[1], old=A)
case("one_holder_recovery", "A recovers.", [va(REC[1], P1R)], held(*ONE_R), None, valid(P1R, G1R),
     predecessors=pre("first_of_one_holder"))
P1F = later((A,), ONE, 2, OG1, at=T2 + 1000, charter_edit=lambda c: c.__setitem__("halt_fuse_secs", 3600))
G1F = place(P1F, (A,), (A,), [G1])
case("one_holder_fuse", "A second successor: A, under its genesis key, shortens the fuse.", [voice(A, P1F)],
     held(*ONE), None, valid(P1F, G1F), predecessors=pre("first_of_one_holder"))
pv4, fp4 = order((oid_of(P1R), 2), (oid_of(P1F), 2))
P1J = later((A,), ["recA"] + SEAT_ROWS, 3, pv4, fp4, at=T2 + 9000, commits={A.iss: hd(commitment([A_REC2]))})
case("join_predecessor_with_no_live_holder", "A join of the two, signed by A under its recovered key. The fuse "
     "bundle seats A at the key the recovery replaced, so it has no live holder, and nothing is a majority of none.",
     [va(A_NEW, P1J)], held("recA", *SEAT_ROWS), None, none(P1J, "genesis_bundle_count_unmet"),
     predecessors=pre("one_holder_recovery", "one_holder_fuse"))

# ---------------------------------------------------------------- a recovery behind its holder's head
case("recovery_beside_a_sibling", "A's recovery read while the reader holds swap_1, a sibling A signed: the two "
     "name one prev, a fork, and the recovery counts.",
     [va(REC[1], PREC)], held(*CN), None, valid(PREC, RECV), predecessors=pre("first", "swap_1"))
case("recovery_behind_head", "A's recovery of the first bundle's seat read while the reader holds the third bundle, "
     "which A signed and which extends swap_1: the recovery's prev is behind A's own head.",
     [va(REC[1], PREC)], held(*CN), None, none(PREC, "recovery_behind_head"),
     predecessors=pre("first", "swap_1", "third_signed_by_a"))
case("recovery_behind_a_bundle_its_holder_did_not_sign", "The same with the third bundle counted on B and D: A "
     "signed nothing past the recovery's prev but its sibling, and the recovery counts.",
     [va(REC[1], PREC)], held(*CN), None, valid(PREC, RECV),
     predecessors=pre("first", "swap_1", "third_not_signed_by_a"))
PJ5 = later((A, B, C, D), ALLN, 4, O3, [OREC], at=T2 + 20000,
            commits={**COM_J, B.iss: hd(commitment([WRONG]))})
case("join_on_the_recovery", "A join of the third bundle (B and D counted) and A's recovery, signed by A under its "
     "recovered key, B and D.",
     [va(A_NEW, PJ5), voice(B, PJ5), voice(D, PJ5)], held(*ALLN), None,
     valid(PJ5, place(PJ5, (A, B, C, D), (A, B, D), [L3_BD, RECV], recs=RECS_NEW)),
     predecessors=pre("third_not_signed_by_a", "recovery"))
case("recovery_read_again_under_its_own_successor", "A's recovery read while the reader holds a join built on it "
     "(with the third bundle): a bundle with the recovery in its past never puts it behind.",
     [va(REC[1], PREC)], held(*CN), None, valid(PREC, RECV), predecessors=pre("first", "swap_1", "join_on_the_recovery"))

out = {
    "_meta": {
        "spec": "CC 2.6.1.11 (A bundle that joins tips; a recovery behind its holder's head), CIRISConstitution "
                "rc23 lane d103e60",
        "generator": "gen_genesis_join_v1.py over gen_genesis_bundles_v6.py (independent of verify)",
        "keys": "As genesis_bundles_v6.json: Key n = ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32. Holders A,B,C,D "
                "= 1,2,3,4; seats 11,12; A's other key 31; recovery key of holder n = n+50; A's signing key after "
                "its rotation or recovery 41; A's next recovery key 61; a key no commitment names 71.",
        "verdicts": "valid | invalid (token genesis_bundle_malformed, detail = reason) | waiting {rows, prev, "
                    "further_prev, kids} | nothing (token; detail)",
        "predecessors": "each names an earlier case of this file (every Valid bundle it read is held) or "
                        "{not_valid: object id}",
        "placement": "as v6, with further_prev, past (every bundle in the lineage past) and recovery_retired_keys "
                     "(the signing keys a counted recovery replaced, by holder)",
    },
    "attestation_root_der": ROOT.der.hex(),
    "parties": {n: {"n": k.n, "kid": k.kid.hex(), "iss": k.iss} for n, k in
                (("A", A), ("B", B), ("C", C), ("D", D), ("S1", S1), ("S2", S2), ("A2", A2), ("A_NEW", A_NEW),
                 ("A_REC1", REC[1]), ("A_REC2", A_REC2), ("WRONG", WRONG))},
    "seat_xwing": {n: {"transit_xwing_pubkey": seat_keys(k)[0].hex(), "onion_hop_xwing_pubkey": seat_keys(k)[1].hex()}
                   for n, k in (("S1", S1), ("S2", S2))},
    "cases": cases,
}


def write(name_, obj):
    with open(os.path.join(OUT, name_), "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")


write("genesis_join_v1.json", out)
for i, chars in enumerate(("0123", "4567", "89ab", "cdef")):
    write("pool_join_v1_%d.json" % i, {k: v for k, v in POOL.items() if k[0] in chars})
print(len(cases), "cases;", len(POOL), "pool entries")
