# Independent known answers for the reader-level shapes of CC's room-content and reply rules (CC rc22, for
# pre4; CIRISConstitution's messages of 2026-11-22):
#  - `refs.further_prev`: a non-empty row-ref set in set order, valid only beside `refs.prev`;
#  - `refs.trusted_through` holds at most 64 row-refs on any row (trusted_through_too_many), and
#    `refs.also.ack` at most 256 (ack_names_too_many);
#  - a reply (membership:acceptance / membership:decline) names what it answers in `refs.answers` and carries
#    neither `refs.target` nor `refs.head`; the earlier form's `proposal_hash` is malformed (CC 3.1.3.2);
#  - objection:{state} has exactly two states, assent and raised (CC 3.1.9.2), each naming what it answers in
#    `refs.answers`; the earlier form's `objects_to_attestation_id` and `dismisses_objection_id` are malformed.
#    (`proposal`, `dismissed`, `upheld` and `overruled` are not states of this form: once CC's registry closes
#    the vocabulary, a row under one is refused by the matcher, so no case is cut for them here.)
#  - a membership:keeps payload (payload level: the stage is registered by CC's next pre tag): counted, with
#    refs.head, refs.trusted_through and exactly one row in refs.also.cites (keeps_cites_no_end otherwise);
#  - an act:ack payload (payload level, for the same reason): refs.also.ack present, and no refs.head.
# None of prev / further_prev / trusted_through makes a statement wait: they are named for the fold.
#
# Reuses gen_row_statements_v4.py's own CBOR encoder and composite signer (loaded with its output discarded);
# shares no code with verify.
#   python3 -I gen_reply_shapes_v1.py > reply_shapes_v1.json
import contextlib, io, json, os, runpy, sys

here = os.path.dirname(os.path.abspath(__file__))
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(here, "gen_row_statements_v4.py"))
A, B, statement, enc, T0 = g["A"], g["B"], g["statement"], g["enc"], g["T0"]


def rref(n): return [2, [-16, bytes([n]) * 32]]


cases = []


def case(cid, desc, family, payload, expect, rtype="scores"):
    cases.append({"id": cid, "description": desc, "row_type": rtype, "family": family,
                  "statement_hex": statement(A, "s", rtype, family, payload)[0].hex(),
                  "held_key_seeds": [A.ml_seed[0]], "expect": expect})


# ---- refs.further_prev (on any row: the reader ties no refs member to a family) ----
FAM = "conscience:coherence"
base = {"asserted_at": T0, "author": A.iss}
case("further_prev_beside_prev", "prev and two further predecessors, in set order.", FAM,
     dict(base, refs={"prev": rref(1), "further_prev": [rref(2), rref(3)]}), "valid")
case("further_prev_one", "prev and one further predecessor.", FAM,
     dict(base, refs={"prev": rref(1), "further_prev": [rref(2)]}), "valid")
case("further_prev_without_prev", "further_prev with no prev.", FAM,
     dict(base, refs={"further_prev": [rref(2)]}), "invalid:malformed:further_prev")
case("further_prev_empty", "An empty further_prev.", FAM,
     dict(base, refs={"prev": rref(1), "further_prev": []}), "invalid:malformed:further_prev")
case("further_prev_unsorted", "further_prev out of set order.", FAM,
     dict(base, refs={"prev": rref(1), "further_prev": [rref(3), rref(2)]}), "invalid:set_order:further_prev")
case("further_prev_repeated", "A row-ref twice in further_prev.", FAM,
     dict(base, refs={"prev": rref(1), "further_prev": [rref(2), rref(2)]}), "invalid:set_order:further_prev")
case("further_prev_a_bare_ref", "further_prev as one row-ref, not a set.", FAM,
     dict(base, refs={"prev": rref(1), "further_prev": rref(2)}), "invalid:malformed:further_prev")
case("further_prev_edition_1", "An edition-1 row-ref in further_prev.", FAM,
     dict(base, refs={"prev": rref(1), "further_prev": [[1, [-16, bytes([2]) * 32]]]}),
     "invalid:malformed:further_prev")
case("prev_and_trusted_through", "prev beside trusted_through: neither makes the statement wait.", FAM,
     dict(base, refs={"prev": rref(1), "trusted_through": [rref(4), rref(5)]}), "valid")

# ---- refs.trusted_through: at most 64 on any row ----
def rset(n):  # n distinct row-refs in set order
    refs = [[2, [-16, i.to_bytes(32, "big")]] for i in range(1, n + 1)]
    return [r for _, r in sorted((enc(r), r) for r in refs)]


case("trusted_through_64", "64 row-refs in trusted_through.", FAM, dict(base, refs={"trusted_through": rset(64)}), "valid")
case("trusted_through_65", "65 row-refs in trusted_through.", FAM, dict(base, refs={"trusted_through": rset(65)}),
     "invalid:trusted_through_too_many")

case("ack_256", "256 row-refs in refs.also.ack.", FAM, dict(base, refs={"also": {"ack": rset(256)}}), "valid")
case("ack_257", "257 row-refs in refs.also.ack.", FAM, dict(base, refs={"also": {"ack": rset(257)}}),
     "invalid:ack_names_too_many")

# ---- a reply names what it answers in refs.answers; proposal_hash is the earlier form's ----
MEM = "membership:.stage"
reply = lambda dim: dict(base, dimension=dim, refs={"answers": rref(9)})
case("acceptance_answers", "An acceptance naming its proposal in refs.answers.", MEM,
     reply("membership:acceptance:v1"), "valid")
case("decline_answers", "A decline naming its proposal in refs.answers.", MEM, reply("membership:decline:v1"), "valid")
case("acceptance_with_proposal_hash", "An acceptance carrying proposal_hash.", MEM,
     dict(reply("membership:acceptance:v1"), proposal_hash=bytes([9]) * 32), "invalid:malformed:proposal_hash")
case("decline_with_proposal_hash", "A decline carrying proposal_hash.", MEM,
     dict(reply("membership:decline:v1"), proposal_hash="00" * 32), "invalid:malformed:proposal_hash")

case("acceptance_no_answers", "An acceptance that names nothing.", MEM,
     dict(base, dimension="membership:acceptance:v1"), "invalid:malformed:refs")
case("acceptance_target_not_answers", "An acceptance naming its proposal in refs.target.", MEM,
     dict(base, dimension="membership:acceptance:v1", refs={"target": rref(9)}), "invalid:malformed:refs")
case("acceptance_answers_and_target", "An acceptance with answers and a target.", MEM,
     dict(base, dimension="membership:acceptance:v1", refs={"answers": rref(9), "target": rref(8)}),
     "invalid:malformed:refs")
case("decline_with_head", "A decline naming a head: a reply is not counted over a roster.", MEM,
     dict(base, dimension="membership:decline:v1", refs={"answers": rref(9), "head": rref(7)}),
     "invalid:malformed:refs")
case("proposal_names_nothing", "A membership proposal is not a reply: no rule on its refs here.", MEM,
     dict(base, dimension="membership:proposal:v1"), "valid")

# ---- objection:{state}: objects_to_attestation_id is the earlier form's ----
OBJ = "objection:.state"
case("objection_assent_answers", "An assent naming its object in refs.answers.", OBJ,
     dict(base, dimension="objection:assent:v1", refs={"answers": rref(9)}), "valid")
case("objection_raised_with_earlier_member", "A raised objection carrying objects_to_attestation_id.", OBJ,
     dict(base, dimension="objection:raised:v1", refs={"answers": rref(9)}, objects_to_attestation_id="abc"),
     "invalid:malformed:objects_to_attestation_id")

case("objection_assent_with_dismisses_member", "An assent carrying dismisses_objection_id (a row named outside "
     "refs).", OBJ, dict(base, dimension="objection:assent:v1", refs={"answers": rref(9)},
                         dismisses_objection_id="abc"), "invalid:malformed:dismisses_objection_id")
case("objection_assent_no_answers", "An assent that names no object.", OBJ,
     dict(base, dimension="objection:assent:v1"), "invalid:malformed:refs")
case("objection_raised_no_answers", "A raised objection that names no object.", OBJ,
     dict(base, dimension="objection:raised:v1"), "invalid:malformed:refs")

# ---- membership:keeps, at payload level (check_membership_keeps over the payload's bytes) ----
import base64, hashlib
GREF = "group-" + base64.urlsafe_b64encode(hashlib.sha256(b"a room").digest()).rstrip(b"=").decode()
keeps = {"dimension": "membership:keeps:v1", "group_kind": "community", "group": GREF, "member": B.iss,
         "asserted_at": T0,
         "refs": {"head": rref(1), "trusted_through": rset(2), "also": {"cites": [rref(5)]}}}
payload_cases = []


def pcase(cid, desc, payload, expect):
    payload_cases.append({"id": cid, "description": desc, "payload_hex": enc(payload).hex(), "expect": expect})


def with_refs(**kw):
    r = dict(keeps["refs"]); r.update(kw)
    return dict(keeps, refs={k: v for k, v in r.items() if v is not None})


pcase("keeps_valid", "Counted, a head, two rows held good, one end cited.", keeps, "valid")
pcase("keeps_with_author", "A keeps row with an author: it is counted.", dict(keeps, author=A.iss), "invalid:malformed:author")
pcase("keeps_no_head", "No refs.head.", with_refs(head=None), "invalid:malformed:refs")
pcase("keeps_no_trusted_through", "No refs.trusted_through.", with_refs(trusted_through=None), "invalid:malformed:refs")
pcase("keeps_cites_none", "No refs.also.cites.", with_refs(also=None), "invalid:keeps_cites_no_end")
pcase("keeps_cites_two", "Two rows cited.", with_refs(also={"cites": [rref(5), rref(6)]}), "invalid:keeps_cites_no_end")
pcase("keeps_group_is_a_key", "group is an identity reference, not a group-ref.", dict(keeps, group=A.iss),
      "invalid:malformed:group")
pcase("keeps_member_not_a_ref", "member is not an identity reference.", dict(keeps, member="bob"),
      "invalid:malformed:member")
pcase("keeps_group_kind_other", "group_kind is neither family nor community.", dict(keeps, group_kind="room"),
      "invalid:malformed:group_kind")

# ---- act:ack, at payload level (check_act_ack over the payload's bytes) ----
ack = {"asserted_at": T0, "author": A.iss, "refs": {"also": {"ack": rset(2)}}}
ack_cases = []


def acase(cid, desc, payload, expect):
    ack_cases.append({"id": cid, "description": desc, "payload_hex": enc(payload).hex(), "expect": expect})


acase("ack_two_acts", "A receipt naming two acts.", ack, "valid")
acase("ack_one_act", "A receipt naming one act.", dict(ack, refs={"also": {"ack": rset(1)}}), "valid")
acase("ack_no_refs", "A receipt with no refs.", {"asserted_at": T0, "author": A.iss}, "invalid:malformed:refs")
acase("ack_cites_not_ack", "A receipt that cites rows but acknowledges none.",
      dict(ack, refs={"also": {"cites": rset(1)}}), "invalid:malformed:refs")
acase("ack_with_head", "A receipt carrying refs.head.", dict(ack, refs={"head": rref(1), "also": {"ack": rset(2)}}),
      "invalid:malformed:refs")

json.dump({"_meta": {"spec": "CC rc22 (pre4): refs.further_prev; proposal_hash and objects_to_attestation_id "
                             "refused as the earlier form's (CC 3.1.3.2)",
                     "generator": "gen_reply_shapes_v1.py (encoder and signer of gen_row_statements_v4.py; "
                                  "independent of verify)",
                     "level": "cases: statement (verify_row_statement); keeps_payloads: payload "
                              "(check_membership_keeps); act_ack_payloads: payload (check_act_ack)"},
           "cases": cases, "keeps_payloads": payload_cases, "act_ack_payloads": ack_cases}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
