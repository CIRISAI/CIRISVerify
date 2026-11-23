# Independent known answers for whether a build pipeline's manifest row stands (FSD-008 Phase 1b; the shapes as
# settled with CIRISConstitution 2026-11-22, ahead of its next pre tag):
#
#   build row   scores, family provenance:build_manifest:{target}, authored (author = iss = CWT sub = the pipeline),
#               payload closed: author, dimension (provenance:build_manifest:{target}:v1), build (closed: project,
#               version, manifest_hash [-16, bstr32], manifest_size uint >= 1), evidence_refs (holding manifest_hash),
#               refs {head: the bundle the grant names}, asserted_at. A later row at the same (project, version,
#               target) is a supersedes naming the earlier in refs.target.
#   grant       delegates_to, dimension trust:confers:v1, COUNTED (no author), the grantee its CWT sub; payload closed:
#               dimension, scope (a set), projects (a set, optional), refs {head}, asserted_at. Counted at 2*yes > N over
#               the holders of the bundle refs.head names, each voice a holder of that bundle at the key it seats.
#   scope       CC 4.5.5: infra:attest or infra:attest:provenance:build_manifest satisfies "may attest
#               provenance:build_manifest"; whole tokens only. A grant carrying projects (a pipeline's) may carry no
#               other scope: pipeline_grant_out_of_role. build.project must be among projects.
#   answer      scores, membership:acceptance:v1 (or membership:decline:v1), authored by the grantee's owner (the
#               owner-binding is a caller-supplied verified input here), CWT sub the grantee, refs exactly
#               {answers: the grant}.
#   ends        a counted withdraws of the grant by a strict majority of the holders of the bundle it names; or the
#               owner's own withdraws of the acceptance.
#   row state   the pipeline's withdraws of the build row; a supersedes of it at the same three; another standing row at
#               the same three with a different build outside one supersedes chain (build_manifest_equivocation).
#   blob        length = manifest_size (before hashing), SHA-256 = manifest_hash, project/version/target = the row's;
#               any mismatch build_manifest_descriptor_mismatch.
#
# Reuses gen_row_statements_v5.py's CBOR encoder, composite signer and key:record helper, gen_binary_manifest_v1.py's
# blob builder, and gen_genesis_bundles_v6.py's bundle payloads and object ids (each loaded with its output
# discarded; v6 is run into a scratch directory). Shares no code with verify. Run from this directory:
#
#   python3 -I gen_build_standing_v1.py
#
# It writes build_standing_v1.json (the cases) and build_standing_pool_v1_N.json (the statements by SHA-256),
# each under the repository's 1000 KB limit.
import contextlib, hashlib, importlib.util, io, json, os, runpy, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
e2 = os.path.dirname(here)
argv, cwd = sys.argv, os.getcwd()
# Each loaded generator runs in a scratch directory: v5 writes its case files to the working directory.
with tempfile.TemporaryDirectory() as scratch, contextlib.redirect_stdout(io.StringIO()):
    os.chdir(scratch)
    g5 = runpy.run_path(os.path.join(e2, "gen_row_statements_v5.py"))
    gb = runpy.run_path(os.path.join(e2, "build_manifest", "gen_binary_manifest_v1.py"))
    sys.argv = ["gen_genesis_bundles_v6.py", "--out", scratch]
    spec = importlib.util.spec_from_file_location("g6", os.path.join(e2, "genesis", "gen_genesis_bundles_v6.py"))
    g6 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g6)
    os.chdir(cwd)
sys.argv = argv

Key, statement, enc, krec = g5["Key"], g5["statement"], g5["enc"], g5["krec"]
sha = lambda b: hashlib.sha256(b).digest()
def hd(d): return [-16, d]
def rref(d): return [2, hd(d)]
def cset(xs): return [x for _, x in sorted((enc(x), x) for x in xs)]

# ---- the lineage (v6's payloads; their object ids are the bundle ids) ----
A, B, C, D = Key(1), Key(2), Key(3), Key(4)          # holders, as everywhere: A/B/C seeds 1/2/3; D joins at G2
P, O, O2, Q, X, O3 = Key(5), Key(6), Key(7), Key(8), Key(9), Key(10)
#   P  the pipeline (a node key)        O  its owner (a user key)
#   O2 another person                   Q  another machine key, owned by O in one case
#   X  a stranger, no record            O3 an owner whose record is not held
_g1 = g6.payload()
G1 = g6.object_id(g6.enc(_g1))                                        # genesis: A, B, C
_g2 = g6.payload(holders=(g6.A, g6.B, g6.D), rows=g6.ids(g6.LATER), version=2, prev=G1, at=g6.T2)
G2 = g6.object_id(g6.enc(_g2))                                        # in force: A, B, D
_fork = g6.payload(version=2, prev=G1, at=g6.T2 + 1)
FORK = g6.object_id(g6.enc(_fork))                                    # a rival of G2: void
_g4 = g6.payload(holders=(g6.A, g6.B, g6.D), rows=g6.ids(g6.LATER), version=3, prev=G2, at=g6.T2 + 86_400_000)
G4 = g6.object_id(g6.enc(_g4))                                        # a later bundle of the lineage, held
_g3 = g6.payload(holders=(g6.A, g6.B, g6.D), rows=g6.ids(g6.LATER), version=4, prev=G4, at=g6.T2 + 2 * 86_400_000)
G3 = g6.object_id(g6.enc(_g3))                                        # a successor not held
_other = g6.payload(fam="another-accord")
OTHER = g6.object_id(g6.enc(_other))                                  # the genesis of another lineage
assert len({G1, G2, FORK, G3, G4, OTHER}) == 6
BUNDLES = [
    {"id": G1.hex(), "name": "G1", "view": "holders", "holder_seeds": [1, 2, 3], "prev": None,
     "description": "The genesis bundle (gen_genesis_bundles_v6 payload()), a predecessor of G2: A, B, C."},
    {"id": G2.hex(), "name": "G2", "view": "holders", "holder_seeds": [1, 2, 4], "prev": G1.hex(),
     "description": "Version 2 of the lineage (v6 payload, prev G1): A, B, D. The grants are counted here."},
    {"id": G4.hex(), "name": "G4", "view": "holders", "holder_seeds": [1, 2, 4], "prev": G2.hex(),
     "description": "Version 3 (prev G2), the bundle in force: A, B, D."},
    {"id": OTHER.hex(), "name": "OTHER", "view": "holders", "holder_seeds": [1, 2, 3], "prev": None,
     "description": "The genesis of another lineage (family_key_id another-accord): A, B, C."},
    {"id": FORK.hex(), "name": "FORK", "view": "void_fork", "holder_seeds": [1, 2, 3], "prev": G1.hex(),
     "description": "A version-2 rival of G2 on G1: a fork the reader holds void."},
    {"id": G3.hex(), "name": "G3", "view": "not_held", "holder_seeds": [], "prev": G4.hex(),
     "description": "A version-4 successor of G4 the reader does not hold."},
]

DAY = 86_400_000
TR = g6.T2                      # key records
TG = g6.T2 + 5 * DAY            # grant
TA = TG + 3_600_000             # acceptance
TB = g6.T2 + 10 * DAY           # build row
TW = g6.T2 + 20 * DAY           # withdrawals, supersedes
YEAR = 31_536_000_000

POOL = {}
def put(b):
    h = sha(b).hex()
    POOL[h] = b.hex()
    return h

def rid(rtype, family, sub, author, plb):
    return sha(enc(["CEG-row/2", rtype, family, sub, author, plb]))

ROWID = {}                      # statement bytes -> row id
def sign(k, sub, rtype, family, p):
    st, _, plb = statement(k, sub, rtype, family, p)
    ROWID[st] = rid(rtype, family, sub, p.get("author"), plb)
    return st, ROWID[st]

# ---- key records (CC 3.1.3, each signed by its own key) ----
KEY_RECORDS = [put(statement(P, P.iss, "scores", "key:record", krec(P, ["node"], TR + YEAR, t0=TR))[0]),
               put(statement(O, O.iss, "scores", "key:record", krec(O, ["user"], None, t0=TR))[0]),
               put(statement(O2, O2.iss, "scores", "key:record", krec(O2, ["user"], None, t0=TR))[0]),
               put(statement(Q, Q.iss, "scores", "key:record", krec(Q, ["node"], TR + YEAR, t0=TR))[0])]

# ---- the blob ----
TARGET = "x86_64-unknown-linux-gnu"
FS = [gb["fn"](n, i) for i, n in enumerate(["ciris_verify_attest", "ciris_verify_init", "ciris_verify_sign"])]
def blob(**edit):
    b = gb["blob"](FS, **dict({"project": "ciris-server", "version": "0.6.0", "target": TARGET}, **edit))
    return enc(b)
BLOB = blob()

# ---- the rows ----
BFAM, GFAM, MFAM = "provenance:build_manifest:.target", "trust:.job:.version", "membership:.stage"
NO_STAND = object()
def build_payload(b=BLOB, head=G2, at=TB, project="ciris-server", version="0.6.0", target=TARGET, edit=None,
                  stands_on=None):
    # refs.head: the bundle in force; refs.also.stands_on: the owner's acceptance the row stands on.
    refs = {"head": rref(head)}
    so = BASE_ACC_ID if stands_on is None else stands_on
    if so is not NO_STAND: refs["also"] = {"stands_on": [rref(so)]}
    p = {"author": P.iss, "dimension": "provenance:build_manifest:%s:v1" % target,
         "build": {"project": project, "version": version, "manifest_hash": hd(sha(b)), "manifest_size": len(b)},
         "evidence_refs": [hd(sha(b))], "refs": refs, "asserted_at": at}
    if edit: edit(p)
    return p
def build_row(signer=P, sub=None, rtype="scores", **kw):
    return sign(signer, sub or P.iss, rtype, BFAM, build_payload(**kw))


SCOPE_BUILD = "infra:attest:provenance:build_manifest"
PROJECTS = cset(["ciris-server", "ciris-verify"])
def grant_payload(scope=(SCOPE_BUILD,), projects=PROJECTS, head=G2, edit=None, raw_scope=None):
    p = {"dimension": "trust:confers:v1", "scope": raw_scope if raw_scope is not None else cset(list(scope)),
         "refs": {"head": rref(head)}, "asserted_at": TG}
    if projects is not None: p["projects"] = projects
    if edit: edit(p)
    return p
def grant(voices=(A, B), sub=None, **kw):
    p = grant_payload(**kw)
    sts = [sign(k, sub or P.iss, "delegates_to", GFAM, p) for k in voices]
    return [s for s, _ in sts], rid("delegates_to", GFAM, sub or P.iss, None, enc(p))

BASE_GRANT, BASE_GRANT_ID = grant()

# Owner-bindings: delegates_to rows from the owner to P with P as sub. Their payload shape is CC's, still to come,
# and the walk takes a binding as verified data {owner, key, row_id}; these row ids are stand-ins.
B0 = sha(b"owner-binding B0: O binds P")
B1 = sha(b"owner-binding B1: O2 re-binds P")
B2 = sha(b"owner-binding B2: O binds P again")
B9 = sha(b"owner-binding B9: some other binding")
def answer_payload(grant_id=BASE_GRANT_ID, author=O, dim="membership:acceptance:v1", refs=None, edit=None,
                   cites=B0):
    # An acceptance of a grant to a machine key cites the owner-binding it is made under (refs.also.cites).
    if refs is None:
        refs = {"answers": rref(grant_id)}
        if cites is not None: refs["also"] = {"cites": [rref(cites)]}
    p = {"author": author.iss, "dimension": dim, "refs": refs, "asserted_at": TA}
    if edit: edit(p)
    return p
def answer(signer=O, sub=None, **kw):
    kw.setdefault("author", signer)
    return sign(signer, sub or P.iss, "scores", MFAM, answer_payload(**kw))

BASE_ACC, BASE_ACC_ID = answer()
def binding(owner=O, key=P, row=B0, others=()):
    # The live binding the caller read, and every other binding of the key it holds.
    return {"owner": owner.iss, "key": key.iss, "row_id": row.hex(), "other_bindings": [o.hex() for o in others]}
BINDING = binding()
BASE_ROW, BASE_ROW_ID = build_row()

def grant_withdrawal(voices=(A, B), head=G2, target=BASE_GRANT_ID, lifts=False):
    p = {"refs": {"head": rref(head), "target": rref(target)}, "asserted_at": TW}
    if lifts: p["lifts"] = True
    return [sign(k, P.iss, "withdraws", GFAM, p)[0] for k in voices]

def acceptance_withdrawal(signer=O, target=BASE_ACC_ID, head=None):
    p = {"author": signer.iss, "refs": {"target": rref(target)}, "asserted_at": TW}
    if head is not None: p["refs"]["head"] = rref(head)
    return sign(signer, P.iss, "withdraws", MFAM, p)[0]

def build_withdrawal(signer=P, target=BASE_ROW_ID):
    p = {"author": signer.iss, "refs": {"target": rref(target)}, "asserted_at": TW}
    return sign(signer, P.iss, "withdraws", BFAM, p)[0]

cases = []
KERNEL = {}   # case id -> its graph-level counterpart in CIRISKernel's conferral_two.json (fa1dc1d)
def case(cid, desc, expect, row=None, b=None, grant_sts=None, gw=(), answers=None, aw=(), binding=BINDING,
         composers=(), wstate=None, kernel=None, **measure):
    e = {"verdict": expect}
    if wstate is not None: e["withdrawal_state"] = wstate
    e.update(measure)
    if kernel: KERNEL[cid] = kernel
    cases.append({
        "id": cid, "description": desc,
        "build_row": put(row if row is not None else (
            BASE_ROW if not answers else build_row(stands_on=ROWID[answers[0]])[0])),
        "blob_hex": (b if b is not None else BLOB).hex(),
        "grant": [put(s) for s in (grant_sts if grant_sts is not None else BASE_GRANT)],
        "grant_withdrawals": [put(s) for s in gw],
        "answers": [put(s) for s in (answers if answers is not None else [BASE_ACC])],
        "answer_withdrawals": [put(s) for s in aw],
        "owner_binding": binding,
        "composers": None if composers is None else [put(s) for s in composers],
        "expect": e,
    })

# ======================================================================== valid
case("stands_none_held", "The build row, its blob, a grant counted by A and B (2 of G2's 3) at the sub-scope "
     "infra:attest:provenance:build_manifest with projects holding ciris-server, the owner's acceptance; a "
     "composers view holding nothing: stands, none_held.", "stands", wstate="none_held", grant_voices=2,
     grant_scope=SCOPE_BUILD, grant_root=G2.hex())
case("stands_unknown", "As stands_none_held with no composers view: still stands, withdrawal_state unknown "
     "beside it.", "stands", composers=None, wstate="unknown")
_gp, _gpid = grant(voices=(A, C), head=G1)
case("stands_grant_under_predecessor", "The grant names G1, a predecessor of the bundle in force, and is counted "
     "there by A and C (C is no holder of G2): counted where made, stands. The build row names G1 too.", "stands",
     row=build_row(head=G1, stands_on=answer(grant_id=_gpid)[1])[0], grant_sts=_gp,
     answers=[answer(grant_id=_gpid)[0]], wstate="none_held",
     grant_voices=2, grant_root=G1.hex())
_gb, _gbid = grant(scope=("infra:attest",))
case("stands_bare_attest", "Scope infra:attest, bare: satisfies every attest family.", "stands", grant_sts=_gb,
     answers=[answer(grant_id=_gbid)[0]], wstate="none_held", grant_scope="infra:attest")
_gs, _gsid = grant(scope=(SCOPE_BUILD,), projects=["ciris-server"])
case("stands_sub_scope_one_project", "The sub-scope with projects = [ciris-server].", "stands", grant_sts=_gs,
     answers=[answer(grant_id=_gsid)[0]], wstate="none_held", grant_scope=SCOPE_BUILD)
_g2s, _g2sid = grant(scope=("infra:attest", SCOPE_BUILD))
case("stands_both_pipeline_scopes", "Both pipeline scopes: the first that satisfies is reported.", "stands",
     grant_sts=_g2s, answers=[answer(grant_id=_g2sid)[0]], wstate="none_held", grant_scope="infra:attest")
case("count_three_of_three", "All three holders of G2 sign the grant.", "stands",
     grant_sts=grant(voices=(A, B, D))[0], wstate="none_held", grant_voices=3)
case("count_stranger_voice_ignored", "A, B and the stranger X sign: X's key is not seated by G2, so it is not a "
     "voice; A and B count.", "stands", grant_sts=grant(voices=(A, B, X))[0], wstate="none_held", grant_voices=2)
case("count_same_holder_twice_plus_one", "A's statement twice and B's: A counts once, 2 of 3.", "stands",
     grant_sts=grant(voices=(A, A, B))[0], wstate="none_held", grant_voices=2)
case("count_two_of_three", "A and D (2 of G2's 3).", "stands", grant_sts=grant(voices=(A, D))[0],
     wstate="none_held", grant_voices=2)
_old_blob = blob(binary_hash=sha(b"the earlier final file"))
_old, _old_id = build_row(b=_old_blob, at=TB - DAY)
_succ, _succ_id = build_row(rtype="supersedes", edit=lambda p: p["refs"].__setitem__("target", rref(_old_id)))
case("stands_superseding_row", "The build row is a supersedes of an earlier row at the same (project, version, "
     "target) with another build; the view holds the earlier row: one supersedes chain, no equivocation.",
     "stands", row=_succ, composers=[_old], wstate="none_held", equivocation=False)
case("stands_peer_same_build", "The view holds another row of the signer at the same three with the same build "
     "(a re-statement at another instant): not an equivocation.", "stands",
     composers=[build_row(at=TB + 1000)[0]], wstate="none_held", equivocation=False)
case("stands_peer_other_version", "The view holds the signer's row for another version: another slot, ignored.",
     "stands", composers=[build_row(b=blob(version="0.6.1"), version="0.6.1")[0]], wstate="none_held",
     equivocation=False)

# ======================================================================== build row shape
def rcase(cid, desc, token, **kw):
    case(cid, desc, "refused:" + token, row=build_row(**kw)[0])
rcase("row_no_head", "The build row carries no refs.", "build_row_malformed:refs.head",
      edit=lambda p: p.pop("refs"))
rcase("row_dimension_v2", "The dimension's version is v2, not the family's v1.", "build_row_malformed:dimension",
      edit=lambda p: p.__setitem__("dimension", "provenance:build_manifest:%s:v2" % TARGET))
rcase("row_dimension_off_family", "The dimension is the locale family's while the header names "
      "provenance:build_manifest:{target}: the row reader refuses it.", "build_row_statement_invalid:dimension_family",
      edit=lambda p: p.__setitem__("dimension", "provenance:build_manifest:%s:locale:en:v1" % TARGET))
rcase("row_hash_not_in_evidence", "evidence_refs does not hold build.manifest_hash.",
      "build_row_malformed:evidence_refs", edit=lambda p: p.__setitem__("evidence_refs", [hd(sha(b"other"))]))
rcase("row_build_fifth_member", "build carries a fifth member (binary_hash).", "build_row_malformed:build",
      edit=lambda p: p["build"].__setitem__("binary_hash", sha(b"x")))
rcase("row_build_missing_member", "build lacks manifest_size.", "build_row_malformed:build",
      edit=lambda p: p["build"].pop("manifest_size"))
rcase("row_size_zero", "manifest_size 0.", "build_row_malformed:manifest_size",
      edit=lambda p: p["build"].__setitem__("manifest_size", 0))
case("row_payload_open", "The build row's payload carries a further member (cohort_scope): payloads are open "
     "(* tstr => ceg-value); only build is closed.", "stands", wstate="none_held",
     row=build_row(edit=lambda p: p.__setitem__("cohort_scope", "federation"))[0])
_gopen, _gopen_id = grant(edit=lambda p: p.__setitem__("purpose", "build pipeline"))
case("grant_payload_open", "The grant's payload carries a further member: open.", "stands", wstate="none_held",
     grant_sts=_gopen, answers=[answer(grant_id=_gopen_id)[0]])
case("acceptance_payload_open", "The acceptance's payload carries a further member: open.", "stands",
     wstate="none_held", answers=[answer(edit=lambda p: p.__setitem__("purpose", "my pipeline"))[0]])
rcase("row_sub_not_author", "The CWT sub is the owner, not the pipeline (author = iss).", "build_row_malformed:sub",
      sub=O.iss)
rcase("row_project_bad_charset", "build.project carries an upper-case letter.", "build_row_malformed:project",
      edit=lambda p: p["build"].__setitem__("project", "CIRIS-server"))

# ======================================================================== row vs blob
case("blob_size_mismatch", "manifest_size is one more than the blob's length: refused before hashing.",
     "refused:build_manifest_descriptor_mismatch", row=build_row(edit=lambda p: p["build"].__setitem__(
         "manifest_size", len(BLOB) + 1))[0], detail="manifest_size")
_other = blob(binary_hash=sha(b"another final file"))
assert len(_other) == len(BLOB)
case("blob_hash_mismatch", "A blob of the same length with another binary hash.",
     "refused:build_manifest_descriptor_mismatch", b=_other, detail="manifest_hash")
for member, val in (("project", "ciris-agent"), ("version", "0.6.1"), ("target", "aarch64-apple-darwin")):
    bb = blob(**{member: val})
    case("blob_%s_mismatch" % member, "The row describes this blob's bytes (size and hash) but the blob's %s is "
         "%s." % (member, val), "refused:build_manifest_descriptor_mismatch", b=bb, detail=member,
         row=build_row(b=bb)[0])

# ======================================================================== grant shape
def gcase(cid, desc, token, voices=(A, B), **kw):
    sts, gid = grant(voices=voices, **kw)
    case(cid, desc, "refused:" + token, grant_sts=sts, answers=[answer(grant_id=gid)[0]])
gcase("grant_author", "The grant carries an author: counted rows never do.", "grant_family:author_column",
      edit=lambda p: p.__setitem__("author", A.iss))
gcase("grant_no_head", "The grant carries no refs.", "grant_malformed:refs.head", edit=lambda p: p.pop("refs"))
gcase("grant_scope_unsorted", "scope not in set order.", "grant_set_order:scope",
      raw_scope=[SCOPE_BUILD, "infra:attest"])
gcase("grant_scope_repeated", "scope repeats an element.", "grant_set_order:scope",
      raw_scope=["infra:attest", "infra:attest"])
gcase("grant_projects_unsorted", "projects not in set order.", "grant_set_order:projects",
      projects=["ciris-verify", "ciris-server"])
gcase("grant_projects_repeated", "projects repeats an element.", "grant_set_order:projects",
      projects=["ciris-server", "ciris-server"])
gcase("grant_dimension_other", "dimension trust:accepts:v1, not trust:confers:v1. The statement reader refuses it "
      "first: a trust:accepts row names the trust root's head (23.5.1, trust_root_head_unnamed).",
      "grant_statement_invalid:trust_root_head_unnamed",
      edit=lambda p: p.__setitem__("dimension", "trust:accepts:v1"))
gcase("grant_other_grantee", "The grant's CWT sub is Q, not the build row's signer.", "grant_other_grantee",
      sub=Q.iss)
case("build_row_other_head", "The build row names G1, older than the grant's G2 (G2 descends from it).",
     "refused:build_row_other_head", row=build_row(head=G1)[0])
case("row_head_later_bundle", "The build row names G4, a later bundle of the lineage the grant was counted in (G2): "
     "the grant counted under G2 stands under G4.", "stands", row=build_row(head=G4)[0], wstate="none_held",
     grant_root=G2.hex())
case("row_head_other_lineage", "The build row names the genesis of another lineage.", "refused:build_row_other_head",
     row=build_row(head=OTHER)[0])
case("row_head_fork", "The build row names FORK, a rival of G2 on G1: not G2 nor a descendant of it.",
     "refused:build_row_other_head", row=build_row(head=FORK)[0])
case("row_head_not_held", "The build row names G3, a successor the reader does not hold: waits on it.",
     "waiting:bundle", row=build_row(head=G3)[0])

# ======================================================================== count
case("count_one_of_three", "Only A signs: 1 of 3; the row waits on the voices of B and D.", "waiting:voice",
     grant_sts=grant(voices=(A,))[0])
case("count_non_holder_not_counted", "A and C sign a grant naming G2: C holds no seat of G2, so 1 of 3.",
     "waiting:voice", grant_sts=grant(voices=(A, C))[0])
case("count_same_holder_twice", "A's statement twice: one voice.", "waiting:voice", grant_sts=grant(voices=(A, A))[0])
case("count_stranger_only", "Only the stranger X signs: no voice of any holder yet, the same short count; the row "
     "waits on the voices of A, B and D.", "waiting:voice",
     grant_sts=grant(voices=(X,))[0])
_g3g, _g3id = grant(head=G3)
case("count_bundle_not_held", "The grant names G3, a bundle the reader does not hold: waits on it.",
     "waiting:bundle", row=build_row(head=G3)[0], grant_sts=_g3g, answers=[answer(grant_id=_g3id)[0]])
_gf, _gfid = grant(head=FORK)
case("count_void_fork", "The grant names a bundle on a fork the reader holds void.", "refused:grant_head_void_fork",
     row=build_row(head=FORK)[0], grant_sts=_gf, answers=[answer(grant_id=_gfid)[0]])
case("grant_missing", "No grant statement at all.", "waiting:grant", grant_sts=[])

# ======================================================================== scope
for cid, desc, sc, pj, token in (
        ("scope_attest_assurance", "infra:attest_assurance only (another capability).", ["infra:attest_assurance"],
         PROJECTS, "pipeline_grant_out_of_role"),
        ("scope_other_family", "infra:attest:other_family.", ["infra:attest:other_family"], PROJECTS,
         "pipeline_grant_out_of_role"),
        ("scope_wider_second", "The sub-scope beside infra:serve.", [SCOPE_BUILD, "infra:serve"], PROJECTS,
         "pipeline_grant_out_of_role"),
        ("scope_prefix_confusion", "infra:attest:provenance:build_manifest_x.", [SCOPE_BUILD + "_x"], PROJECTS,
         "pipeline_grant_out_of_role"),
        ("scope_child_sub_scope", "infra:attest:provenance:build_manifest:" + TARGET + " (a child, unregistered).",
         [SCOPE_BUILD + ":" + TARGET], PROJECTS, "pipeline_grant_out_of_role"),
        ("scope_no_projects_assurance", "No projects (not a pipeline's grant), infra:attest_assurance: the CC 4.5.5 "
         "check refuses it.", ["infra:attest_assurance"], None, "build_manifest_scope_not_granted"),
        ("scope_no_projects_prefix", "No projects, infra:attest:provenance:build_manifest_x: a prefix is not a "
         "token.", [SCOPE_BUILD + "_x"], None, "build_manifest_scope_not_granted"),
        ("scope_no_projects_child", "No projects, a child of the family: a child never satisfies its parent.",
         [SCOPE_BUILD + ":" + TARGET], None, "build_manifest_scope_not_granted"),
):
    gcase(cid, desc, token, scope=sc, projects=pj)

# ======================================================================== projects
gcase("projects_not_listed", "projects = [ciris-agent, ciris-verify]: ciris-server is not granted.",
      "build_manifest_project_not_granted", projects=cset(["ciris-agent", "ciris-verify"]))
gcase("projects_absent", "infra:attest with no projects: no project is granted.",
      "build_manifest_project_not_granted", scope=("infra:attest",), projects=None)

# ======================================================================== the answer
case("acceptance_missing", "No answer from the owner.", "waiting:acceptance", answers=[])
case("owner_binding_missing", "No owner-binding supplied.", "waiting:owner_binding", binding=None)
case("acceptance_declined", "The owner's membership:decline:v1 answering the grant: the grant confers nothing.",
     "refused:grant_declined", answers=[answer(dim="membership:decline:v1")[0]])
_dec, _dec_id = answer(dim="membership:decline:v1")
case("acceptance_contested", "An acceptance and a decline of the grant by the owner both stand: contested, neither "
     "counts (CC 3.1.3.2, CC 2.7.7 rule 6).", "refused:grant_contested", answers=[BASE_ACC, _dec])
case("decline_not_by_owner", "O2 (not the owner the held binding names) declines beside the owner's acceptance: "
     "not this grant's decline, the acceptance stands.", "stands",
     answers=[BASE_ACC, answer(signer=O2, dim="membership:decline:v1")[0]], wstate="none_held")
case("contested_decline_withdrawn", "Both, and the owner withdraws the decline: the acceptance decides, in force.",
     "stands", answers=[BASE_ACC, _dec], aw=[acceptance_withdrawal(target=_dec_id)], wstate="none_held")
case("contested_acceptance_withdrawn", "Both, and the owner withdraws the acceptance: the decline decides.",
     "refused:grant_declined", answers=[BASE_ACC, _dec], aw=[acceptance_withdrawal()])
case("acceptance_by_grantee", "The acceptance is signed by the pipeline's own key.", "refused:acceptance_by_grantee",
     answers=[answer(signer=P)[0]])
case("acceptance_owner_of_other_key", "The binding supplied makes O the owner of Q, not of the grantee.",
     "refused:owner_binding_other_key", binding=binding(key=Q))
case("acceptance_not_by_owner", "O2 accepts; the binding names O.", "refused:acceptance_not_by_owner",
     answers=[answer(signer=O2)[0]])
case("acceptance_other_grant", "The acceptance answers another grant.", "refused:acceptance_other_grant",
     answers=[answer(grant_id=sha(b"another grant"))[0]])
case("acceptance_proposal_hash", "The acceptance carries proposal_hash (the earlier form).",
     "refused:acceptance_malformed:proposal_hash",
     answers=[answer(edit=lambda p: p.__setitem__("proposal_hash", hd(sha(b"proposal"))))[0]])
case("acceptance_refs_target", "refs.target where refs.answers belongs.", "refused:acceptance_malformed:refs",
     answers=[answer(refs={"target": rref(BASE_GRANT_ID)})[0]])
case("acceptance_refs_head", "refs.answers beside a refs.head.", "refused:acceptance_malformed:refs",
     answers=[answer(refs={"answers": rref(BASE_GRANT_ID), "head": rref(G2)})[0]])
case("acceptance_refs_neither", "No refs at all.", "refused:acceptance_malformed:refs",
     answers=[answer(edit=lambda p: p.pop("refs"))[0]])
case("acceptance_other_grantee", "The acceptance's CWT sub is Q.", "refused:acceptance_other_grantee",
     answers=[answer(sub=Q.iss)[0]])
case("acceptance_key_not_held", "The owner O3's key record is not held: the acceptance waits on its key.",
     "waiting:key", answers=[answer(signer=O3)[0]], binding=binding(owner=O3))

# ======================================================================== ends
case("end_counted_withdrawal", "A and B withdraw the grant from G2: counted, the grant ends.",
     "refused:grant_withdrawn", gw=grant_withdrawal())
case("end_counted_withdrawal_lifts", "The counted withdrawal carries lifts: true.", "refused:grant_withdrawn",
     gw=grant_withdrawal(lifts=True))
case("end_one_voice_only", "Only A withdraws: 1 of 3, the grant has not ended.", "stands", gw=grant_withdrawal((A,)),
     wstate="none_held")
case("end_owner_withdraws_acceptance", "The owner withdraws the acceptance: the grant ends from the grantee's side.",
     "refused:acceptance_withdrawn", aw=[acceptance_withdrawal()])
case("end_stranger_withdraws_acceptance", "O2 signs a withdraws of the owner's acceptance: not the owner's, not "
     "an end.", "stands", aw=[acceptance_withdrawal(signer=O2)], wstate="none_held")
case("end_owner_withdrawal_names_head", "The owner's withdrawal names a head: not the shape of an own end.",
     "stands", aw=[acceptance_withdrawal(head=G2)], wstate="none_held")

# ======================================================================== row state
case("state_withdrawn", "The pipeline withdraws the build row.", "refused:build_manifest_withdrawn",
     composers=[build_withdrawal()], wstate="withdrawn")
_new_blob = blob(binary_hash=sha(b"the rebuilt final file"))
_sup, _ = build_row(b=_new_blob, rtype="supersedes", at=TW,
                    edit=lambda p: p["refs"].__setitem__("target", rref(BASE_ROW_ID)))
case("state_superseded", "The pipeline supersedes the build row at the same three with another build.",
     "refused:build_manifest_superseded", composers=[_sup], wstate="superseded")
_eq, _eq_id = build_row(b=_new_blob, at=TB + 2000)
case("state_equivocation", "Another standing scores row of the signer at the same three with another build, no "
     "supersedes between them.", "refused:build_manifest_equivocation", composers=[_eq], wstate="none_held",
     equivocation=True)
case("state_withdrawn_peer", "The equivocating peer is withdrawn by the pipeline: not standing, no equivocation.",
     "stands", composers=[_eq, build_withdrawal(target=_eq_id)], wstate="none_held", equivocation=False)
case("state_stranger_withdrawal", "O2 signs a withdraws naming the build row: not the pipeline's, ignored.",
     "stands", composers=[build_withdrawal(signer=O2)], wstate="none_held")

KERNEL["stands_none_held"] = "names_bundle_and_acceptance"
KERNEL["end_counted_withdrawal"] = "grant_ended"

# ======================================================================== two standings
case("row_no_stands_on", kernel="names_bundle_alone", desc="The build row names the bundle alone: it stands on no "
     "acceptance and counts for nobody.", expect="refused:build_row_stands_on_nothing",
     row=build_row(stands_on=NO_STAND)[0])
case("row_stands_on_binding", kernel="names_the_binding", desc="stands_on names the owner-binding row itself.",
     expect="refused:build_row_stands_on_nothing", row=build_row(stands_on=B0)[0])
case("row_stands_on_grant", "stands_on names the grant (a row the reader holds, not an acceptance).",
     "refused:build_row_stands_on_nothing", row=build_row(stands_on=BASE_GRANT_ID)[0])
case("row_stands_on_row_not_held", "stands_on names a row the reader does not hold: the row waits on it.",
     "waiting:row", row=build_row(stands_on=sha(b"a row not held"))[0])
_acc_other, _acc_other_id = answer(grant_id=sha(b"another grant"))
case("row_stands_on_other_grants_acceptance", "stands_on names the owner's acceptance of a different grant (held); "
     "the acceptance of this grant is held too.", "refused:build_row_stands_on_nothing",
     answers=[BASE_ACC, _acc_other], row=build_row(stands_on=_acc_other_id)[0])
case("acceptance_cites_no_binding", "The acceptance carries refs.answers only, no owner-binding cited.",
     "refused:acceptance_other_binding", answers=[answer(cites=None)[0]])
case("acceptance_cites_binding_not_held", "The acceptance cites B9, a row the reader does not hold (it may be a "
     "binding): waits on it.", "waiting:row", answers=[answer(cites=B9)[0]])
case("acceptance_cites_other_held_binding", "The acceptance cites B9, another owner-binding of P the reader holds: "
     "made under another binding.", "refused:acceptance_other_binding", answers=[answer(cites=B9)[0]],
     binding=binding(others=[B9]))
case("acceptance_cites_two_bindings", "The acceptance cites B0 (the binding supplied) and B9, another held binding "
     "of P: an acceptance is made under one binding.", "refused:acceptance_other_binding",
     answers=[answer(edit=lambda p: p["refs"]["also"].__setitem__("cites", cset([rref(B0), rref(B9)])))[0]],
     binding=binding(others=[B9]))
case("acceptance_cites_binding_and_other_row", "The acceptance cites B0 and an unrelated row: cites is a set; it "
     "contains the binding supplied, so it stands.", "stands", wstate="none_held",
     answers=[answer(edit=lambda p: p["refs"]["also"].__setitem__("cites", cset([rref(B0), rref(sha(b"x"))])))[0]])
case("binding_sub_not_signer", "The binding supplied binds Q, not the build row's signer P.",
     "refused:owner_binding_other_key", binding=binding(key=Q, row=B0))
_a1, _a1_id = answer(signer=O2, cites=B1)
case("rebinding_old_acceptance", kernel="old_owners_act_after_the_rebinding", desc="P is re-bound to O2 (B1); the "
     "row stands on O's old acceptance: not by the owner the binding names.", expect="refused:acceptance_not_by_owner",
     binding=binding(owner=O2, row=B1, others=[B0]))
case("rebinding_before_new_acceptance", kernel="before_the_new_owners_acceptance", desc="Re-bound to O2; the row "
     "names the re-binding B1 rather than an acceptance.", expect="refused:build_row_stands_on_nothing",
     binding=binding(owner=O2, row=B1, others=[B0]), answers=[_a1], row=build_row(stands_on=B1)[0])
case("rebinding_new_owner_accepts", kernel="under_the_new_owner", desc="Re-bound to O2, who accepts citing B1; the "
     "row stands on that acceptance.", expect="stands", binding=binding(owner=O2, row=B1, others=[B0]), answers=[_a1],
     wstate="none_held")
_a2, _a2_id = answer(cites=B2)
case("second_stint_old_acceptance", kernel="second_stint_of_one_owner", desc="O is bound to P again (B2); only O's "
     "first acceptance (citing B0) is presented: a re-binding needs a new acceptance.",
     expect="refused:acceptance_other_binding", binding=binding(row=B2, others=[B0]))
case("second_stint_old_binding_not_held", "Bound again (B2), the reader not holding B0: O's first acceptance cites a "
     "row not held, so it waits on it.", "waiting:row", binding=binding(row=B2))
case("second_stint_row_names_old", kernel="second_stint_of_one_owner", desc="Bound again (B2), both acceptances "
     "held; the row stands on the first (citing B0).", expect="refused:build_row_stands_on_nothing",
     binding=binding(row=B2, others=[B0]), answers=[BASE_ACC, _a2], row=build_row(stands_on=BASE_ACC_ID)[0])
case("second_stint_row_names_new", kernel="second_stint_of_one_owner", desc="Bound again (B2); the row stands on the "
     "new acceptance citing B2.", expect="stands", binding=binding(row=B2, others=[B0]), answers=[BASE_ACC, _a2],
     row=build_row(stands_on=_a2_id)[0], wstate="none_held")

# ======================================================================== the scope matcher
SCOPE_MATCH = [{"held": h, "family": "provenance:build_manifest", "satisfies": s} for h, s in (
    ("infra:attest", True), (SCOPE_BUILD, True), ("infra:attest_assurance", False), (SCOPE_BUILD + "_x", False),
    (SCOPE_BUILD + ":" + TARGET, False), ("infra:attest:provenance", False), ("infra:attest:other_family", False),
    ("infra:attest:", False), ("infra", False), ("", False), ("infra:serve", False))]

ids = [c["id"] for c in cases]
assert len(ids) == len(set(ids)), "duplicate case id"

# ---- write ----
LIMIT = 900_000
pool_items = sorted(POOL.items())
pools, cur, size = [], {}, 0
for k, v in pool_items:
    if cur and size + len(v) + 80 > LIMIT:
        pools.append(cur); cur, size = {}, 0
    cur[k] = v; size += len(v) + 80
pools.append(cur)
for i, p in enumerate(pools):
    with open(os.path.join(here, "build_standing_pool_v1_%d.json" % i), "w") as f:
        json.dump({"statements": p}, f, indent=0, sort_keys=True); f.write("\n")
out = {
    "_meta": {
        "spec": "FSD-008 Phase 1b; the build row, grant, acceptance, ends and row state as settled with "
                "CIRISConstitution 2026-11-22; CC 4.5.5 scope match; CC 2.7.7 rule 2; CC 2.6.1.9 counted rows.",
        "generator": "gen_build_standing_v1.py over gen_row_statements_v5.py, gen_binary_manifest_v1.py and "
                     "gen_genesis_bundles_v6.py (independent of verify)",
        "keys": "Key(n): ML-DSA-65 seed [n]*32, Ed25519 seed [(n+100)%256]*32. Holders A,B,C,D = 1,2,3,4; pipeline "
                "P = 5 (node); owner O = 6 (user); O2 = 7 (user); Q = 8 (node); stranger X = 9 (no record); O3 = 10 "
                "(no record). key_records are inserted into a KeyRecordDirectory for every case.",
        "bundles": "bundle id -> view: holders (a roster of the listed seeds: in force or a predecessor), not_held, "
                   "void_fork. The ids are v6 genesis-bundle object ids; the reader takes the roster as data.",
        "statements": "every statement is named by its SHA-256 (hex) in the pool files",
        "receipts": "the walk reads no receipts: a build row whose grant has ended (or whose acceptance is "
                    "withdrawn) is refused, Kernel's 'counted but not in force' (CC 2.4.1.1, What stays in force); "
                    "see kernel_not_covered.",
        "lineage": "each bundle's prev; descends(head, from) follows prev from head over the bundles listed (a "
                   "not_held bundle is not held; a walk that ends without reaching from is not a descendant).",
        "verdicts": "stands | refused:{token} | waiting:{token+token} (key, voice, record, row, bundle, grant, "
                    "acceptance, owner_binding). withdrawal_state: unknown | none_held | withdrawn | superseded. "
                    "composers null = no view.",
        "pool_files": ["build_standing_pool_v1_%d.json" % i for i in range(len(pools))],
    },
    "kernel_counterparts": KERNEL,
    "kernel_not_covered": {
        "old_owners_act_receipted": "receipts are not read by this walk",
        "grant_ended_receipted": "receipts are not read by this walk",
        "grant_receipt_does_not_keep_the_binding": "receipts are not read by this walk; its unreceipted part is "
                                                   "rebinding_old_acceptance",
    },
    "key_records": KEY_RECORDS,
    "bundles": BUNDLES,
    "pipeline": P.iss, "owner": O.iss,
    "scope_match": SCOPE_MATCH,
    "cases": cases,
}
with open(os.path.join(here, "build_standing_v1.json"), "w") as f:
    json.dump(out, f, indent=1, sort_keys=True); f.write("\n")
print("%d cases, %d statements, %d pool file(s)" % (len(cases), len(POOL), len(pools)), file=sys.stderr)
