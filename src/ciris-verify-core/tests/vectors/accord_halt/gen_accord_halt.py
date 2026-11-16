# Independent generator of the edition-2 accord halt known answers (CC 4.2.1.1, CC 4.2.1.3, CC 4.2.6;
# CIRISConstitution rc20 64c5918): the invocation rows (constitutional, notify, drill), the counted lifecycle
# rows (confirmed, active), their refusals, and latch sequences.
#
# Its own CBOR deterministic encoder (RFC 8949 4.2.1 bytewise key order), dilithium-py (FIPS 204,
# deterministic) and pyca/cryptography (Ed25519), copied from ../edition2/gen_row_statements_v2.py. Shares no
# code with verify. Every expectation below is written from the text, not computed by a model of the reader.
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65

PREFIX = b"CompositeAlgorithmSignatures2025"
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"


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


class Key:
    def __init__(self, n):
        self.n = n
        self.ml_seed, self.ed_seed = bytes([n]) * 32, bytes([(n + 100) % 256]) * 32
        self.ml_pk, self.ml_sk = ML_DSA_65.key_derive(self.ml_seed)
        ed = Ed25519PrivateKey.from_private_bytes(self.ed_seed)
        self.ed = ed
        self.pub = self.ml_pk + ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        assert len(self.pub) == 1984
        self.kid = hashlib.sha256(enc({1: 7, 3: -70100, -1: self.pub})).digest()
        self.iss = "urn:ietf:params:oauth:ckt:sha-256:" + base64.urlsafe_b64encode(self.kid).rstrip(b"=").decode()

    def sign(self, m):
        mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(m).digest()
        s = ML_DSA_65.sign(self.ml_sk, mp, ctx=LABEL, deterministic=True) + self.ed.sign(mp)
        assert len(s) == 3373
        return s


def statement(k, sub, rtype, family, payload, iss=None, tamper=None):
    claims = {1: iss or k.iss, 2: sub, 6: payload["asserted_at"] // 1000, -70003: 2}
    if "valid_from" in payload: claims[5] = payload["valid_from"] // 1000
    if "valid_until" in payload: claims[4] = payload["valid_until"] // 1000
    prot = {1: -70100, 3: "application/vnd.ciris.row+cbor", 4: k.kid, 15: claims, 16: "ceg-row/2",
            -70001: rtype, -70002: family}
    pb, plb = enc(prot), enc(payload)
    sig = k.sign(enc(["Signature1", pb, b"", plb]))
    if tamper:  # the payload altered after signing
        plb = enc(tamper(dict(payload)))
    return enc(Tag(18, [pb, {}, plb, sig])), pb, plb


def hd(d): return [-16, d]
def rref(d): return [2, hd(d)]
def row_id(rtype, fam, sub, author, plb): return hashlib.sha256(enc(["CEG-row/2", rtype, fam, sub, author, plb])).digest()
def stmt_id(pb, plb): return hashlib.sha256(enc(["CEG-statement-id/2", pb, plb])).digest()


def show(v):
    """A JSON rendering of a payload value: bytes as {"bstr": hex}."""
    if isinstance(v, bytes): return {"bstr": v.hex()}
    if isinstance(v, list): return [show(x) for x in v]
    if isinstance(v, dict): return {k: show(x) for k, x in v.items()}
    return v


# ---- The roster: a placement-equivalent holder set of the bundle in force ----
A1, B1, C1 = Key(1), Key(2), Key(3)
OUTSIDER = Key(9)
HOLDERS = [("A1", A1), ("B1", B1), ("C1", C1)]
ACCORD_ROOT = "humanity-accord"
# The bundle in force's object id, stated (not minted here: the reader takes it with the holders).
BUNDLE = hashlib.sha256(b"accord_halt_v1: the bundle in force").digest()
HALT_FUSE_SECS = 3600   # the charter's halt_fuse_secs (absent would mean 86400)
SUB = ACCORD_ROOT        # the CWT sub of every accord row: the accord's family_key_id (CC ruling)
T0 = 1763300000000       # 2025-11-16T13:33:20Z
DAY = 86400000

FAM_CONST = "accord:invoke:constitutional:.halt_id"
FAM_NOTIFY = "accord:invoke:notify:.notify_id"
FAM_DRILL = "accord:invoke:drill:.drill_id"
FAM_LIFE = "accord:lifecycle:.kind"


def invocation(k, inv_id, nonce_byte, at, **extra):
    p = {"author": k.iss, "accord_root": ACCORD_ROOT, "invocation_id": inv_id, "nonce": bytes([nonce_byte]) * 32,
         "asserted_at": at, "valid_until": at + DAY}
    p.update(extra)
    return {k2: v for k2, v in p.items() if v is not None}


def lifecycle(kind, inv_id, nonce_byte, at, target, head=BUNDLE, **extra):
    p = {"refs": {"head": rref(head), "target": rref(target)}, "dimension": f"accord:lifecycle:{kind}:v1",
         "accord_root": ACCORD_ROOT, "invocation_id": inv_id, "nonce": bytes([nonce_byte]) * 32,
         "asserted_at": at, "valid_until": at + DAY}
    p.update(extra)
    return {k2: v for k2, v in p.items() if v is not None}


invocations, lifecycles, refusals = [], [], []
ROWS = {}  # case id -> row id


def stmt_record(name, k, st, pb, plb):
    return {"signer": name, "key_seed": k.n, "iss": k.iss, "kid_hex": k.kid.hex(), "statement_hex": st.hex(),
            "statement_id_hex": stmt_id(pb, plb).hex()}


def add_invocation(cid, desc, name, k, fam, kind, p):
    st, pb, plb = statement(k, SUB, "scores", fam, p)
    rid = row_id("scores", fam, SUB, p["author"], plb)
    ROWS[cid] = (rid, st, kind)
    invocations.append({"id": cid, "description": desc, "kind": kind, "row_type": "scores", "family": fam,
                        "sub": SUB, "members": show(p), "payload_hex": plb.hex(), "row_id_hex": rid.hex(),
                        "statement": stmt_record(name, k, st, pb, plb), "expect": "valid"})
    return rid


def add_lifecycle(cid, desc, kind, signers, p, halt, expect="valid", voices=None, extra_statements=(), sub=SUB):
    sts = []
    rid = None
    for name, k in signers:
        st, pb, plb = statement(k, sub, "scores", FAM_LIFE, p)
        rid = row_id("scores", FAM_LIFE, sub, None, plb)
        sts.append(stmt_record(name, k, st, pb, plb))
    for rec in extra_statements:
        sts.append(rec)
    case = {"id": cid, "description": desc, "kind": kind, "row_type": "scores", "family": FAM_LIFE, "sub": sub,
            "members": show(p), "payload_hex": enc(p).hex(), "row_id_hex": rid.hex(), "halt": halt,
            "statements": sts, "expect": expect}
    if voices is not None:
        case["voices"] = sorted(voices)
    lifecycles.append(case)
    ROWS[cid] = (rid, None, "lifecycle:" + kind)
    return case


# ---- Valid invocations ----
H = add_invocation("halt_constitutional_a1", "A constitutional halt by A1: one statement, the kind its family.",
                   "A1", A1, FAM_CONST, "constitutional", invocation(A1, "halt-2025-11-16", 0x11, T0))
N = add_invocation("notify_b1", "A notify by B1, with payload_digest naming its separate message object.",
                   "B1", B1, FAM_NOTIFY, "notify",
                   invocation(B1, "notify-1", 0x22, T0 + 1000,
                              payload_digest=hd(hashlib.sha256(b"The accord holders: a message.").digest())))
D = add_invocation("drill_c1", "A drill by C1: one holder's statement, as the fire (CC 4.2.1.1).",
                   "C1", C1, FAM_DRILL, "drill", invocation(C1, "drill-1", 0x33, T0 + 2000))
H2 = add_invocation("halt_constitutional_b1", "A second halt, by B1, that the other-halt refusals name.",
                    "B1", B1, FAM_CONST, "constitutional", invocation(B1, "halt-2", 0x44, T0 + 3000))

# ---- Counted lifecycle rows ----
P_CONF = lifecycle("confirmed", "confirm-1", 0x55, T0 + 600000, H)
add_lifecycle("confirmed_a1_b1", "lifecycle:confirmed by A1 and B1 over one payload naming the halt: 2 of 3, a "
              "strict majority; one row id, two statement ids.", "confirmed", [("A1", A1), ("B1", B1)], P_CONF,
              "halt_constitutional_a1", voices=[A1.iss, B1.iss])
P_ACT = lifecycle("active", "resume-1", 0x66, T0 + 1200000, H)
add_lifecycle("active_b1_c1", "lifecycle:active by B1 and C1 naming the halt: 2 of 3.", "active",
              [("B1", B1), ("C1", C1)], P_ACT, "halt_constitutional_a1", voices=[B1.iss, C1.iss])


def lrefuse(cid, desc, kind, signers, p, halt, expect, extra_statements=(), sub=SUB):
    add_lifecycle(cid, desc, kind, signers, p, halt, expect=expect, extra_statements=extra_statements, sub=sub)


lrefuse("confirmed_lone_a1", "A lone confirmed voice: 1 of 3 is no strict majority.", "confirmed",
        [("A1", A1)], P_CONF, "halt_constitutional_a1", "count_unmet:1:2")
lrefuse("confirmed_a1_twice", "A1's voice presented twice is one voice.", "confirmed",
        [("A1", A1), ("A1", A1)], P_CONF, "halt_constitutional_a1", "count_unmet:1:2")
# Two rows, one voice each: the voices of another row are refused other_row.
_p_other = lifecycle("confirmed", "confirm-1b", 0x56, T0 + 600000, H)
_st, _pb, _plb = statement(B1, SUB, "scores", FAM_LIFE, _p_other)
lrefuse("two_rows_one_voice_each", "A1 signs one confirmed row, B1 another (another nonce): two rows of one voice "
        "each; the count is unmet and B1's statement is refused other_row (or A1's, by the tie rule: the lowest "
        "row id is counted).", "confirmed", [("A1", A1)], P_CONF, "halt_constitutional_a1", "count_unmet:1:2",
        extra_statements=[stmt_record("B1", B1, _st, _pb, _plb)])
lrefuse("confirmed_names_other_halt", "A1 and B1 confirm halt-2 (B1's), presented against A1's halt.",
        "confirmed", [("A1", A1), ("B1", B1)], lifecycle("confirmed", "confirm-2", 0x57, T0 + 600000, H2),
        "halt_constitutional_a1", "other_halt")
lrefuse("active_names_drill", "A1 and B1 'resume' the drill: the row it names is no constitutional halt.",
        "active", [("A1", A1), ("B1", B1)], lifecycle("active", "resume-d", 0x58, T0 + 600000, D),
        "drill_c1", "target_not_a_halt")
_no_target = lifecycle("confirmed", "confirm-3", 0x59, T0 + 600000, H)
_no_target["refs"] = {"head": rref(BUNDLE)}
lrefuse("lifecycle_names_no_halt", "refs carries head and no target.", "confirmed", [("A1", A1), ("B1", B1)],
        _no_target, "halt_constitutional_a1", "member:target")
lrefuse("lifecycle_other_bundle", "refs.head names another bundle than the one in force.", "confirmed",
        [("A1", A1), ("B1", B1)],
        lifecycle("confirmed", "confirm-4", 0x5a, T0 + 600000, H, head=hashlib.sha256(b"another bundle").digest()),
        "halt_constitutional_a1", "other_bundle")
lrefuse("lifecycle_with_author", "A lifecycle row is counted: an author is refused by the family model.",
        "confirmed", [("A1", A1), ("B1", B1)],
        lifecycle("confirmed", "confirm-5", 0x5b, T0 + 600000, H, author=A1.iss),
        "halt_constitutional_a1", "family:author_column")
lrefuse("lifecycle_dimension_unversioned", "dimension accord:lifecycle:confirmed without its :vN tail.",
        "confirmed", [("A1", A1), ("B1", B1)],
        lifecycle("confirmed", "confirm-6", 0x5c, T0 + 600000, H, dimension="accord:lifecycle:confirmed"),
        "halt_constitutional_a1", "statement_invalid:dimension_refused:missing_version_segment")
lrefuse("lifecycle_outsider_voice", "A1 and the outsider: the outsider's statement is no holder's, so 1 of 3.",
        "confirmed", [("A1", A1), ("OUTSIDER", OUTSIDER)], P_CONF, "halt_constitutional_a1", "count_unmet:1:2")
lrefuse("lifecycle_sub_not_accord", "A lifecycle row whose CWT sub is not the accord's family_key_id.",
        "confirmed", [("A1", A1), ("B1", B1)], lifecycle("confirmed", "confirm-7", 0x5d, T0 + 600000, H),
        "halt_constitutional_a1", "member:sub", sub="the-halted-agents")
lrefuse("lifecycle_valid_until_before_asserted_at", "A lifecycle row whose valid_until precedes its asserted_at.",
        "confirmed", [("A1", A1), ("B1", B1)],
        lifecycle("confirmed", "confirm-8", 0x5e, T0 + 600000, H, valid_until=T0 + 599000),
        "halt_constitutional_a1", "valid_until_not_after_asserted_at")
# Cross-family replay: a halt statement's bytes presented as a lifecycle row.
_h_rec = invocations[0]["statement"]
lifecycles.append({"id": "replay_halt_as_lifecycle", "description": "The constitutional halt's statement bytes "
                   "presented as a lifecycle row: the family is the invocation's.", "kind": "confirmed",
                   "row_id_hex": invocations[0]["row_id_hex"], "halt": "halt_constitutional_a1",
                   "statements": [_h_rec], "expect": "wrong_family"})

# ---- Invocation refusals ----


def irefuse(cid, desc, name, k, fam, p, expect, iss=None, tamper=None, rtype="scores", sub=SUB):
    st, pb, plb = statement(k, sub, rtype, fam, p, iss=iss, tamper=tamper)
    # members: as signed; row_id_hex: of the row as presented (for tampered_member, the altered payload).
    refusals.append({"id": cid, "description": desc, "family": fam, "row_type": rtype, "sub": sub,
                     "members": show(p), "row_id_hex": row_id(rtype, fam, sub, p.get("author"), plb).hex(),
                     "statement": stmt_record(name, k, st, pb, plb), "expect": expect})


irefuse("outsider_halt", "A constitutional halt by a key the bundle in force does not list.", "OUTSIDER",
        OUTSIDER, FAM_CONST, invocation(OUTSIDER, "halt-x", 0x71, T0), "not_a_holder")
irefuse("iss_of_another_holder", "B1's key signs with A1's iss and author.", "B1", B1, FAM_CONST,
        invocation(A1, "halt-y", 0x72, T0), "iss_not_holder", iss=A1.iss)
irefuse("author_not_iss", "A1 signs a halt whose author is B1: the family names no role for A1.", "A1", A1,
        FAM_CONST, invocation(A1, "halt-z", 0x73, T0, author=B1.iss), "family:iss_not_in_role")
irefuse("tampered_member", "The halt's invocation_id altered after A1 signed it.", "A1", A1, FAM_CONST,
        invocation(A1, "halt-2025-11-16", 0x11, T0), "statement_invalid:bad_signature",
        tamper=lambda p: dict(p, invocation_id="halt-2025-11-17"))
irefuse("halt_carries_kind", "An invocation carrying invocation_kind: the map is closed.", "A1", A1, FAM_CONST,
        invocation(A1, "halt-k", 0x74, T0, invocation_kind="constitutional"), "member:closed_map")
irefuse("halt_with_payload_digest", "payload_digest on a constitutional halt: a notify only.", "A1", A1,
        FAM_CONST, invocation(A1, "halt-d", 0x75, T0, payload_digest=hd(bytes(32))), "member:payload_digest")
irefuse("notify_without_payload_digest", "A notify with no payload_digest.", "B1", B1, FAM_NOTIFY,
        invocation(B1, "notify-2", 0x76, T0), "member:payload_digest")
irefuse("nonce_31_bytes", "A nonce of 31 bytes.", "A1", A1, FAM_CONST,
        invocation(A1, "halt-n", 0x77, T0, nonce=bytes(31)), "member:nonce")
irefuse("other_accord_root", "accord_root names another accord.", "A1", A1, FAM_CONST,
        dict(invocation(A1, "halt-r", 0x78, T0), accord_root="another-accord"), "other_accord")
irefuse("halt_under_parent_family", "A halt under the parent family accord:* (accord:.): with no dimension its "
        "authorship is undetermined, and it is no invocation family.", "A1", A1, "accord:.",
        invocation(A1, "halt-p", 0x79, T0), "family:authorship_undetermined")
irefuse("halt_as_delegates_to", "A halt under row type delegates_to.", "A1", A1, FAM_CONST,
        invocation(A1, "halt-t", 0x7a, T0), "wrong_row_type", rtype="delegates_to")
irefuse("halt_sub_not_accord", "A halt whose CWT sub is not the accord's family_key_id.", "A1", A1, FAM_CONST,
        invocation(A1, "halt-s", 0x7b, T0), "member:sub", sub="the-halted-agents")
irefuse("halt_valid_until_equals_asserted_at", "A halt whose valid_until equals its asserted_at: not after it.",
        "A1", A1, FAM_CONST, dict(invocation(A1, "halt-v", 0x7c, T0), valid_until=T0),
        "valid_until_not_after_asserted_at")
# The reverse replay: a lifecycle statement presented as an invocation.
_lc = lifecycles[0]["statements"][0]
refusals.append({"id": "replay_lifecycle_as_invocation", "description": "A1's confirmed statement presented as "
                 "an invocation: the family is the lifecycle's.", "row_id_hex": lifecycles[0]["row_id_hex"],
                 "statement": _lc, "expect": "wrong_family"})

# ---- Latch sequences (the fuse is the roster's halt_fuse_secs, counted from receipt) ----
F = HALT_FUSE_SECS * 1000
R0 = 1800000000000  # a node's receipt clock, unrelated to asserted_at
latch = [
    {"id": "halt_then_fuse_lapses", "description": "A lone halt pauses on receipt and lapses halt_fuse_secs after "
     "receipt.", "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": R0, "outcome": "paused"},
        {"check": R0 + F - 1, "paused": True},
        {"check": R0 + F, "paused": False}]},
    {"id": "halt_then_confirmed_no_lapse", "description": "A halt confirmed by a strict majority before its fuse "
     "does not lapse.", "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": R0, "outcome": "paused"},
        {"apply": "confirmed_a1_b1", "at_ms": R0 + 600000, "outcome": "confirmed"},
        {"check": R0 + F, "paused": True},
        {"check": R0 + 1000 * F, "paused": True}]},
    {"id": "halt_then_active_cleared", "description": "A majority lifecycle:active ends the unconfirmed halt.",
     "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": R0, "outcome": "paused"},
        {"apply": "active_b1_c1", "at_ms": R0 + 60000, "outcome": "resumed"},
        {"check": R0 + 60000, "paused": False}]},
    {"id": "halt_confirmed_then_active", "description": "A confirmed halt stands until the majority resumption.",
     "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": R0, "outcome": "paused"},
        {"apply": "confirmed_a1_b1", "at_ms": R0 + 600000, "outcome": "confirmed"},
        {"apply": "active_b1_c1", "at_ms": R0 + 5 * F, "outcome": "resumed"},
        {"check": R0 + 5 * F, "paused": False}]},
    {"id": "late_confirmation_confirms_nothing", "description": "A confirmation received after the fuse lapsed "
     "confirms nothing.", "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": R0, "outcome": "paused"},
        {"apply": "confirmed_a1_b1", "at_ms": R0 + F, "outcome": "unchanged"},
        {"check": R0 + F, "paused": False}]},
    {"id": "notify_and_drill_never_latch", "description": "A notify and a drill verify and never touch the latch.",
     "steps": [
        {"apply": "notify_b1", "at_ms": R0, "outcome": "unchanged"},
        {"apply": "drill_c1", "at_ms": R0, "outcome": "unchanged"},
        {"check": R0, "paused": False}]},
    {"id": "second_halt_does_not_reset_fuse", "description": "A second halt while paused changes nothing; a "
     "resumption naming it moves nothing.", "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": R0, "outcome": "paused"},
        {"apply": "halt_constitutional_b1", "at_ms": R0 + F // 2, "outcome": "unchanged"},
        {"check": R0 + F, "paused": False}]},
    # CC 4.2.1.1: "A halt that arrives after its valid_until still fires, unless the node already holds a
    # resumption that names it." halt_constitutional_a1: asserted_at T0, valid_until T0 + DAY.
    {"id": "resumption_held_then_late_halt", "description": "lifecycle:active naming the halt is held first (no "
     "halt in force: unchanged); the halt then arrives after its valid_until and does not fire.", "steps": [
        {"apply": "active_b1_c1", "at_ms": T0 + 500, "outcome": "unchanged"},
        {"apply": "halt_constitutional_a1", "at_ms": T0 + DAY + 1, "outcome": "unchanged"},
        {"check": T0 + DAY + 1, "paused": False}]},
    {"id": "resumption_held_then_halt_at_valid_until", "description": "The same, the halt arriving at exactly its "
     "valid_until: not after it, so it fires.", "steps": [
        {"apply": "active_b1_c1", "at_ms": T0 + 500, "outcome": "unchanged"},
        {"apply": "halt_constitutional_a1", "at_ms": T0 + DAY, "outcome": "paused"},
        {"check": T0 + DAY, "paused": True}]},
    {"id": "resumption_held_then_halt_within_valid_until", "description": "The same resumption held, the halt "
     "arriving within its valid_until: the text's exception is only for a halt past its valid_until, so it fires; "
     "the held resumption, applied again, then ends it.", "steps": [
        {"apply": "active_b1_c1", "at_ms": T0 + 500, "outcome": "unchanged"},
        {"apply": "halt_constitutional_a1", "at_ms": T0 + 1000, "outcome": "paused"},
        {"check": T0 + 1000, "paused": True},
        {"apply": "active_b1_c1", "at_ms": T0 + 2000, "outcome": "resumed"},
        {"check": T0 + 2000, "paused": False}]},
    {"id": "late_halt_without_resumption_fires", "description": "A halt after its valid_until with no resumption "
     "held fires: valid_until bounds the nonce, never the reach of a halt.", "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": T0 + DAY + 1, "outcome": "paused"},
        {"check": T0 + DAY + 1, "paused": True}]},
    {"id": "other_resumption_held_then_late_halt", "description": "A resumption naming another halt is held; a late "
     "halt it does not name fires.", "steps": [
        {"apply": "halt_constitutional_a1", "at_ms": T0 + 100, "outcome": "paused"},
        {"apply": "active_b1_c1", "at_ms": T0 + 200, "outcome": "resumed"},
        {"apply": "halt_constitutional_b1", "at_ms": T0 + 3000 + DAY + 1, "outcome": "paused"},
        {"check": T0 + 3000 + DAY + 1, "paused": True}]},
]

assert len({c["id"] for c in invocations + lifecycles + refusals}) == len(invocations + lifecycles + refusals)
out = {
    "$schema_note": (
        "Edition-2 accord halt known answers (CC 4.2.1.1, CC 4.2.1.3, CC 4.2.6; CIRISConstitution rc20 64c5918). "
        "Key n: ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32; signatures deterministic. Generated independently "
        "of the Rust code by gen_accord_halt.py; see README.md. members render bytes as {\"bstr\": hex}. expect: "
        "valid, or the reader's refusal token (count_unmet:<have>:<need>)."),
    "roster": {"accord_root": ACCORD_ROOT, "bundle_object_id_hex": BUNDLE.hex(), "halt_fuse_secs": HALT_FUSE_SECS,
               "majority": 2,
               "holders": [{"label": n, "key_seed": k.n, "iss": k.iss, "kid_hex": k.kid.hex()} for n, k in HOLDERS]},
    "outsider": {"label": "OUTSIDER", "key_seed": OUTSIDER.n, "iss": OUTSIDER.iss, "kid_hex": OUTSIDER.kid.hex()},
    "invocations": invocations,
    "lifecycles": lifecycles,
    "invocation_refusals": refusals,
    "latch": latch,
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
print()
