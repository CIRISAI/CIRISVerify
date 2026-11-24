# Independent known answers for the derived group id (CC rc22, ruled 2026-11-22; pre4):
#   group-id-input = ["CEG-group/2", group_kind, founders, founded_at, nonce]
#   id = "group-" || base64url-nopad(SHA-256(deterministic encoding of group-id-input))
#   group-ref = "group-[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]"
# group_kind and founded_at are the first group:roster version's own members; founders is the `key` of every
# entry of its `members` (any role), duplicates collapsed, in CC 2.6.1.2 set order (bytewise order of each
# element's deterministic encoding); nonce is a 32-byte member of the first version only. A first version is a
# group:roster statement with no refs.head, whatever its row type; a withdraws or recants is not a version.
#
# Reuses gen_row_statements_v4.py's own CBOR encoder and composite signer (loaded with its output discarded);
# shares no code with verify.
#   python3 -I gen_group_id_v1.py > group_id_v1.json
import base64, contextlib, hashlib, io, json, os, runpy, sys

here = os.path.dirname(os.path.abspath(__file__))
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(here, "gen_row_statements_v4.py"))
A, B, C, statement, enc, T0 = g["A"], g["B"], g["C"], g["statement"], g["enc"], g["T0"]

FAM = "group:roster"
NONCE = bytes(range(32))
FOUNDED = T0 - 5000


def group_id(kind, founders, founded_at, nonce):
    fs = [f for _, f in sorted({(enc(f), f) for f in founders})]
    d = hashlib.sha256(enc(["CEG-group/2", kind, fs, founded_at, nonce])).digest()
    return "group-" + base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def member(k, role="founder"):
    return {"key": k.iss, "joined_at": FOUNDED, "role": role}


def cset(items):  # a set in CC 2.6.1.2 order
    return [x for _, x in sorted(((enc(x), i), x) for i, x in enumerate(items))]


def founding(members, kind="community", founded_at=FOUNDED, nonce=NONCE, group=None, order=None):
    ms = cset(members) if order is None else order
    p = {"group_kind": kind, "name": "a room", "version": 1, "members": ms, "founded_at": founded_at,
         "consensus_protocol": "majority", "asserted_at": T0}
    if nonce is not None: p["nonce"] = nonce
    p["group"] = group if group is not None else group_id(kind, [m["key"] for m in ms], founded_at,
                                                          nonce if isinstance(nonce, bytes) and len(nonce) == 32 else NONCE)
    return p


AB = [member(A), member(B)]
GID = group_id("community", [A.iss, B.iss], FOUNDED, NONCE)
derivations, cases = [], []


def derive(did, kind, founders, founded_at, nonce):
    fs = [f for _, f in sorted({(enc(f), f) for f in founders})]
    pre = enc(["CEG-group/2", kind, fs, founded_at, nonce])
    derivations.append({"id": did, "group_kind": kind, "founders": founders, "founded_at": founded_at,
                        "nonce_hex": nonce.hex(), "input_hex": pre.hex(), "group": group_id(kind, founders, founded_at, nonce)})


derive("two_founders", "community", [A.iss, B.iss], FOUNDED, NONCE)
derive("two_founders_other_order", "community", [B.iss, A.iss], FOUNDED, NONCE)
derive("repeated_founder", "community", [A.iss, B.iss, A.iss], FOUNDED, NONCE)
derive("one_founder", "community", [A.iss], FOUNDED, NONCE)
derive("family_kind", "family", [A.iss, B.iss], FOUNDED, NONCE)
derive("other_founded_at", "community", [A.iss, B.iss], FOUNDED + 1, NONCE)
derive("other_nonce", "community", [A.iss, B.iss], FOUNDED, bytes([0xff]) * 32)
derive("three_founders", "community", [C.iss, A.iss, B.iss], FOUNDED, NONCE)
# CIRISConstitution's own known answer (its generator, sent 2026-11-22), reproduced here independently.
_P = "urn:ietf:params:oauth:ckt:sha-256:"
CC_FOUNDERS = [_P + "A" * 43, _P + "B" * 42 + "A"]
derive("cc_known_answer", "community", CC_FOUNDERS, 1763078400000, NONCE)
derive("cc_known_answer_other_order", "community", list(reversed(CC_FOUNDERS)), 1763078400000, NONCE)
derive("cc_known_answer_family", "family", CC_FOUNDERS, 1763078400000, NONCE)
_cc = {d["id"]: d for d in derivations}
assert _cc["cc_known_answer"]["input_hex"] == (
    "856b4345472d67726f75702f3269636f6d6d756e69747982784d75726e3a696574663a706172616d733a6f617574683a636b743a"
    "7368612d3235363a41414141414141414141414141414141414141414141414141414141414141414141414141414141414141784d"
    "75726e3a696574663a706172616d733a6f617574683a636b743a7368612d3235363a424242424242424242424242424242424242"
    "424242424242424242424242424242424242424242424242411b0000019a7fa968005820000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"), "preimage differs from CC's"
assert _cc["cc_known_answer"]["group"] == "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hI"
assert _cc["cc_known_answer_other_order"]["group"] == _cc["cc_known_answer"]["group"]
assert _cc["cc_known_answer_family"]["group"] == "group-ODjNYdkE6CL7viHGk4mFJRvuPtXGic_pxf-1iMrufE0"
assert derivations[0]["group"] == derivations[1]["group"] == derivations[2]["group"] == GID
assert len({d["group"] for d in derivations[3:8]} | {GID}) == 6


def case(cid, desc, payload, expect, rtype="scores", sub=None, signer=A):
    cases.append({"id": cid, "description": desc, "row_type": rtype,
                  "statement_hex": statement(signer, sub if sub is not None else payload.get("group", "s"), rtype,
                                             FAM, payload)[0].hex(),
                  "held_key_seeds": [signer.ml_seed[0]], "expect": expect})


case("valid_founding", "A first version: two founders, nonce 00..1f; group is the derived id.", founding(AB), "valid")
case("valid_members_other_order", "The same founding with members listed in the other order: the id is over the "
     "founders as a set, so it is the same id. (That `members` is itself in set order is the payload table's rule, "
     "the door's; this reader derives and compares.)", founding(AB, order=list(reversed(cset(AB)))), "valid")
case("valid_supersedes_no_head", "A supersedes with no refs.head is a first version and must derive.", founding(AB),
     "valid", rtype="supersedes")
later = {"group_kind": "community", "group": GID, "name": "a room", "version": 2, "members": cset(AB + [member(C, "member")]),
         "founded_at": FOUNDED, "consensus_protocol": "majority", "asserted_at": T0 + 1000,
         "refs": {"head": [2, [-16, bytes([0x21]) * 32]]}}
case("valid_later_version", "A later version (refs.head) with no nonce; its group is not re-derived.", later, "valid",
     rtype="supersedes")
case("chosen_id", "A first version whose group is a well-formed group-ref the founder chose.",
     founding(AB, group="group-" + base64.urlsafe_b64encode(bytes([7]) * 32).rstrip(b"=").decode()),
     "invalid:group_id_not_of_founding")
case("other_group_kind", "The id was derived for a community; the version says family.",
     dict(founding(AB), group_kind="family"), "invalid:group_id_not_of_founding")
case("other_founded_at", "founded_at differs from the one the id covers.",
     dict(founding(AB), founded_at=FOUNDED + 1), "invalid:group_id_not_of_founding")
case("member_not_covered", "A third member the id does not cover.",
     dict(founding(AB), members=cset(AB + [member(C)])), "invalid:group_id_not_of_founding")
case("other_nonce", "The nonce differs from the one the id covers.",
     dict(founding(AB), nonce=bytes([0xff]) * 32), "invalid:group_id_not_of_founding")
case("group_is_a_key_thumbprint", "group is an identity reference (a key's thumbprint URI), not a group-ref.",
     founding(AB, group=A.iss), "invalid:malformed:group", sub=A.iss)
case("group_is_a_lineage_name", "group is a root lineage's name.", founding(AB, group="humanity-accord"),
     "invalid:malformed:group")
case("group_ref_not_canonical", "group-ref whose last character leaves stray bits.",
     founding(AB, group=GID[:-1] + ("B" if GID[-1] != "B" else "C")), "invalid:malformed:group")
case("no_nonce", "A first version without a nonce.", founding(AB, nonce=None), "invalid:malformed:nonce")
case("nonce_16_bytes", "A 16-byte nonce.", founding(AB, nonce=bytes(16)), "invalid:malformed:nonce")
case("nonce_31_bytes", "A 31-byte nonce.", founding(AB, nonce=bytes(31)), "invalid:malformed:nonce")
case("nonce_text", "A nonce that is text.", founding(AB, nonce="00" * 32), "invalid:malformed:nonce")
case("nonce_on_later_version", "A later version carrying a nonce.", dict(later, nonce=NONCE),
     "invalid:malformed:nonce", rtype="supersedes")
case("member_key_not_identity_ref", "A member whose key is not an identity reference.",
     dict(founding(AB), members=cset([member(A), {"key": "bob", "joined_at": FOUNDED, "role": "founder"}])),
     "invalid:malformed:members")
case("no_group_kind", "A first version without group_kind.",
     {k: v for k, v in founding(AB).items() if k != "group_kind"}, "invalid:malformed:group_kind")
case("no_founded_at", "A first version without founded_at.",
     {k: v for k, v in founding(AB).items() if k != "founded_at"}, "invalid:malformed:founded_at")
case("no_members", "A first version without members.",
     {k: v for k, v in founding(AB).items() if k != "members"}, "invalid:malformed:members")
case("withdraws_is_not_a_version", "A withdraws on group:roster is a composer, not a roster version: no founding "
     "rule applies to it.", {"asserted_at": T0, "refs": {"target": [2, [-16, bytes([0x22]) * 32]]}}, "valid",
     rtype="withdraws", sub=GID)

json.dump({"_meta": {"spec": "CC rc22 derived group id (ruled 2026-11-22; pre4): CEG-group/2, group-ref",
                     "generator": "gen_group_id_v1.py (encoder and signer of gen_row_statements_v4.py; independent "
                                  "of verify)",
                     "level": "statement (verify_row_statement); derivations are the function's known answers"},
           "derivations": derivations, "cases": cases}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
