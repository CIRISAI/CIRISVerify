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
#  - an act:ack payload (payload level, for the same reason): refs.also.ack present, and no refs.head;
#  - a trust:accepts row is one of three kinds, said by its payload (CC 3.2 T3/T4a, CC 2.7.11, CC 4.4.3.34):
#    with `attached_head_digest` (a hash-digest) it attaches a root; with `service_key` it is an edge to a
#    Transparency Service, `service_key` standing exactly where trust_classes contains `transparency`, never
#    beside the digest, and the CWT sub being the key's RFC 9679 thumbprint in the key-segment form (a COSE
#    key) or the identity (an identity reference); with neither it is an admission-walk or licensor edge. None
#    carries refs.head or scope. (trust_root_head_unnamed needs a held lineage, so it is the fold's.)
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


def case(cid, desc, family, payload, expect, rtype="scores", sub="s"):
    cases.append({"id": cid, "description": desc, "row_type": rtype, "family": family,
                  "statement_hex": statement(A, sub, rtype, family, payload)[0].hex(),
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

# ---- trust:accepts: the acceptance edge names the head it attaches on (CC 3.2 T4a) ----
TRU = "trust:.job:.version"
HEAD = [-16, bytes([0x44]) * 32]
edge = dict(base, dimension="trust:accepts:v1", attached_head_digest=HEAD)
case("edge_names_its_head", "An acceptance edge with attached_head_digest.", TRU, edge, "valid")
case("edge_no_head_digest", "An edge with neither a digest nor a service key: an admission-walk or licensor "
     "edge. (That a root edge owes a digest needs a held lineage: the fold's.)", TRU,
     dict(base, dimension="trust:accepts:v1"), "valid")
case("edge_head_digest_bare_bytes", "attached_head_digest as bare bytes, not a hash-digest.", TRU,
     dict(edge, attached_head_digest=bytes([0x44]) * 32), "invalid:malformed:attached_head_digest")
case("edge_head_digest_31_bytes", "A 31-byte digest.", TRU,
     dict(edge, attached_head_digest=[-16, bytes(31)]), "invalid:malformed:attached_head_digest")
case("edge_head_digest_other_alg", "A digest under another algorithm label.", TRU,
     dict(edge, attached_head_digest=[-43, bytes(32)]), "invalid:malformed:attached_head_digest")
case("edge_with_refs_head", "An edge carrying refs.head.", TRU, dict(edge, refs={"head": rref(1)}),
     "invalid:malformed:refs")
case("edge_with_scope", "An edge carrying scope.", TRU, dict(edge, scope=["infra:attest"]),
     "invalid:malformed:scope")
# An edge to a Transparency Service: service_key iff the class transparency; sub is the key's name.
import base64, hashlib
SK = {1: 2, 3: -7, -1: 1, -2: bytes([0x21]) * 32, -3: bytes([0x22]) * 32}                # EC2 P-256, with alg
seg = lambda members: base64.urlsafe_b64encode(hashlib.sha256(enc(members)).digest()).rstrip(b"=").decode()
SK_SEG = seg({1: 2, -1: 1, -2: SK[-2], -3: SK[-3]})                                      # RFC 9679: kty, crv, x, y
OKP = {1: 1, 3: -8, -1: 6, -2: bytes([0x23]) * 32}
svc = dict(base, dimension="trust:accepts:v1", trust_classes=["transparency"], service_key=SK)
case("service_edge_cose_key", "A service edge whose sub is the EC2 key's thumbprint in the key-segment form.", TRU,
     svc, "valid", sub=SK_SEG)
case("service_edge_okp_key", "A service edge under an OKP key (thumbprint over kty, crv, x).", TRU,
     dict(svc, service_key=OKP), "valid", sub=seg({1: 1, -1: 6, -2: OKP[-2]}))
case("service_edge_identity", "service_key an identity reference; sub is that identity.", TRU,
     dict(svc, service_key=B.iss), "valid", sub=B.iss)
case("service_edge_sub_other", "A service edge whose sub is not its key's thumbprint.", TRU, svc,
     "invalid:malformed:sub", sub="s")
case("service_edge_sub_full_ref", "sub is the thumbprint as a full identity reference, not the key segment.", TRU,
     svc, "invalid:malformed:sub", sub="urn:ietf:params:oauth:ckt:sha-256:" + SK_SEG)
case("service_edge_identity_sub_other", "service_key an identity reference; sub names another identity.", TRU,
     dict(svc, service_key=B.iss), "invalid:malformed:sub", sub=A.iss)
case("service_edge_key_id", "service_key a key id, not an identity reference.", TRU,
     dict(svc, service_key="A1"), "invalid:malformed:service_key", sub="A1")
case("service_edge_key_type_unknown", "service_key a COSE key of a key type with no thumbprint rule here.", TRU,
     dict(svc, service_key={1: 99, -1: bytes(32)}), "invalid:malformed:service_key", sub=SK_SEG)
case("service_key_without_class", "service_key on an edge whose trust_classes lacks transparency.", TRU,
     dict(svc, trust_classes=["audit"]), "invalid:malformed:service_key", sub=SK_SEG)
case("service_key_no_classes", "service_key with no trust_classes.", TRU,
     {k: v for k, v in svc.items() if k != "trust_classes"}, "invalid:malformed:service_key", sub=SK_SEG)
case("transparency_without_service_key", "The class transparency with no service_key.", TRU,
     dict(base, dimension="trust:accepts:v1", trust_classes=["transparency"]), "invalid:malformed:service_key")
case("service_key_and_digest", "service_key beside attached_head_digest.", TRU,
     dict(svc, attached_head_digest=HEAD), "invalid:malformed:attached_head_digest", sub=SK_SEG)
case("root_edge_sub_identity_form", "A digest on an edge whose sub has identity-ref form: a lineage's name is "
     "free text, so the reader refuses nothing.", TRU, edge, "valid", sub=A.iss)
case("confers_is_not_an_edge", "A trust:confers row is not an acceptance edge: no edge rule applies.", TRU,
     dict(base, dimension="trust:confers:v1", scope=["infra:attest"], refs={"head": rref(1)}), "valid")

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
