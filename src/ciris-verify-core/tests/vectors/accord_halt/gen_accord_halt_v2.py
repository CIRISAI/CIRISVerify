# Independent generator of the edition-2 accord halt known answers, v2 (CC 4.2.1.1, CC 4.2.1.3, CC 4.2.6,
# CC 2.6.1.8; CIRISConstitution rc20 436b5bc): the invocation rows (constitutional, notify, drill), the counted
# lifecycle rows (confirmed, active), and latch sequences, each case read under a stated roster and answering
# valid, waiting:<what> or refused:<token>.
#
# v2 over v1 (gen_accord_halt.py, kept byte-identical): a statement under a key the roster does not hold, and
# a lifecycle row whose refs.head is not the roster's bundle, WAIT and are never refused (CC 2.6.1.8 step 6:
# "resolve the key record, or answer Waiting on it"; CC 2.7.3: "A row waits for what it names"; CC 4.2.1.1: "a
# missed halt is the one unrecoverable failure"). A reader cannot tell a stranger's key from a holder's key
# seated by a bundle it lacks (a rotation, a recovery). A lifecycle row counts when its held voices meet the
# strict majority; short of it, it waits where an unheld key could make up the count or a statement waits on a
# bundle, and is refused count_unmet otherwise. A refused statement never makes a row wait.
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


# ---- The rosters: placement-equivalent holder sets of two bundles ----
A1, B1, C1 = Key(1), Key(2), Key(3)
OUTSIDER = Key(9)
# A1 rotated: a new composite key (seed 11) that a later bundle seats for A1. The holder's identity reference
# stays A1's (the bundle seats a key for an identity), so the statement's iss and author are A1's.
A1R = Key(11)
A1R.iss = A1.iss
ACCORD_ROOT = "humanity-accord"
# The bundles' object ids, stated (not minted here: the reader takes them with the holders).
BUNDLE = hashlib.sha256(b"accord_halt_v1: the bundle in force").digest()
BUNDLE2 = hashlib.sha256(b"accord_halt_v2: the bundle seating A1's rotated key").digest()
HALT_FUSE_SECS = 3600   # the charter's halt_fuse_secs (absent would mean 86400)
SUB = ACCORD_ROOT        # the CWT sub of every accord row: the accord's family_key_id (CC ruling)
T0 = 1763300000000       # 2025-11-16T13:33:20Z
DAY = 86400000

ROSTERS = {
    "genesis": (BUNDLE, [("A1", A1), ("B1", B1), ("C1", C1)]),
    "rotated": (BUNDLE2, [("A1", A1R), ("B1", B1), ("C1", C1)]),
}

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


invocations, lifecycles = [], []


def stmt_record(name, k, st, pb, plb):
    return {"signer": name, "key_seed": k.n, "iss": k.iss, "kid_hex": k.kid.hex(), "statement_hex": st.hex(),
            "statement_id_hex": stmt_id(pb, plb).hex()}


def waiting(kids=(), bundles=()):
    """The expected Waiting: kids and bundles, each sorted, once each."""
    return {"kids_hex": sorted({k.kid.hex() for k in kids}), "bundles_hex": sorted({b.hex() for b in bundles})}


def expect_of(w):
    what = "+".join(x for x, v in (("kid", w["kids_hex"]), ("bundle", w["bundles_hex"])) if v)
    return "waiting:" + what


# ---- Invocations ----


def add_invocation(cid, desc, name, k, fam, p, expect="valid", roster="genesis", wait=None, iss=None, tamper=None,
                   rtype="scores", sub=SUB, kind=None):
    st, pb, plb = statement(k, sub, rtype, fam, p, iss=iss, tamper=tamper)
    # members: as signed; row_id_hex: of the row as presented (for tampered_member, the altered payload).
    case = {"id": cid, "description": desc, "roster": roster, "family": fam, "row_type": rtype, "sub": sub,
            "members": show(p), "payload_hex": plb.hex(),
            "row_id_hex": row_id(rtype, fam, sub, p.get("author"), plb).hex(),
            "statement": stmt_record(name, k, st, pb, plb), "expect": expect}
    if kind: case["kind"] = kind
    if wait is not None:
        case["waiting"] = wait
        assert expect == expect_of(wait)
    invocations.append(case)
    return bytes.fromhex(case["row_id_hex"])


H = add_invocation("halt_constitutional_a1", "A constitutional halt by A1: one statement, the kind its family.",
                   "A1", A1, FAM_CONST, invocation(A1, "halt-2025-11-16", 0x11, T0), kind="constitutional")
add_invocation("notify_b1", "A notify by B1, with payload_digest naming its separate message object.",
               "B1", B1, FAM_NOTIFY,
               invocation(B1, "notify-1", 0x22, T0 + 1000,
                          payload_digest=hd(hashlib.sha256(b"The accord holders: a message.").digest())),
               kind="notify")
D = add_invocation("drill_c1", "A drill by C1: one holder's statement, as the fire (CC 4.2.1.1).",
                   "C1", C1, FAM_DRILL, invocation(C1, "drill-1", 0x33, T0 + 2000), kind="drill")
H2 = add_invocation("halt_constitutional_b1", "A second halt, by B1, that the other-halt refusals name.",
                    "B1", B1, FAM_CONST, invocation(B1, "halt-2", 0x44, T0 + 3000), kind="constitutional")

# A holder rotated to a key this roster does not seat: the reader cannot tell it from a stranger, and a missed
# halt is the one unrecoverable failure (CC 4.2.1.1), so it waits on the key (CC 2.6.1.8 step 6). Read under the
# roster of the bundle that seats the key, the same statement is valid.
P_ROT = invocation(A1R, "halt-rotated", 0x12, T0 + 4000)
add_invocation("halt_rotated_a1_unseated", "A1's halt under its rotated key, read under the genesis roster, "
               "which seats A1 at its first key: Waiting on the rotated key, never refused.", "A1R", A1R,
               FAM_CONST, P_ROT, expect="waiting:kid", wait=waiting(kids=[A1R]))
add_invocation("halt_rotated_a1_seated", "The same statement read under the roster of the bundle that seats "
               "A1's rotated key: valid, author A1.", "A1R", A1R, FAM_CONST, P_ROT, roster="rotated",
               kind="constitutional")
add_invocation("outsider_halt", "A constitutional halt by a key the bundle in force does not list (v1: "
               "not_a_holder). The reader cannot tell it from a holder's key seated by a bundle it lacks: Waiting.",
               "OUTSIDER", OUTSIDER, FAM_CONST, invocation(OUTSIDER, "halt-x", 0x71, T0), expect="waiting:kid",
               wait=waiting(kids=[OUTSIDER]))
add_invocation("halt_a1_first_key_under_rotated", "A1's halt under its first key, read under the rotated "
               "roster, which no longer seats that key: Waiting on it (held inert; it never fires there).",
               "A1", A1, FAM_CONST, invocation(A1, "halt-old-key", 0x13, T0 + 5000), roster="rotated",
               expect="waiting:kid", wait=waiting(kids=[A1]))

# Refusals: the statement itself is wrong. These stay refused.
for cid, desc, name, k, fam, p, tok, kw in [
    ("iss_of_another_holder", "B1's key signs with A1's iss and author.", "B1", B1, FAM_CONST,
     invocation(A1, "halt-y", 0x72, T0), "iss_not_holder", {"iss": A1.iss}),
    ("author_not_iss", "A1 signs a halt whose author is B1: the family names no role for A1.", "A1", A1,
     FAM_CONST, invocation(A1, "halt-z", 0x73, T0, author=B1.iss), "family:iss_not_in_role", {}),
    ("tampered_member", "The halt's invocation_id altered after A1 signed it.", "A1", A1, FAM_CONST,
     invocation(A1, "halt-2025-11-16", 0x11, T0), "statement_invalid:bad_signature",
     {"tamper": lambda p: dict(p, invocation_id="halt-2025-11-17")}),
    ("halt_carries_kind", "An invocation carrying invocation_kind: the map is closed.", "A1", A1, FAM_CONST,
     invocation(A1, "halt-k", 0x74, T0, invocation_kind="constitutional"), "member:closed_map", {}),
    ("halt_with_payload_digest", "payload_digest on a constitutional halt: a notify only.", "A1", A1,
     FAM_CONST, invocation(A1, "halt-d", 0x75, T0, payload_digest=hd(bytes(32))), "member:payload_digest", {}),
    ("notify_without_payload_digest", "A notify with no payload_digest.", "B1", B1, FAM_NOTIFY,
     invocation(B1, "notify-2", 0x76, T0), "member:payload_digest", {}),
    ("nonce_31_bytes", "A nonce of 31 bytes.", "A1", A1, FAM_CONST,
     invocation(A1, "halt-n", 0x77, T0, nonce=bytes(31)), "member:nonce", {}),
    ("other_accord_root", "accord_root names another accord.", "A1", A1, FAM_CONST,
     dict(invocation(A1, "halt-r", 0x78, T0), accord_root="another-accord"), "other_accord", {}),
    ("halt_under_parent_family", "A halt under the parent family accord:* (accord:.): with no dimension its "
     "authorship is undetermined, and it is no invocation family.", "A1", A1, "accord:.",
     invocation(A1, "halt-p", 0x79, T0), "family:authorship_undetermined", {}),
    ("halt_as_delegates_to", "A halt under row type delegates_to.", "A1", A1, FAM_CONST,
     invocation(A1, "halt-t", 0x7a, T0), "wrong_row_type", {"rtype": "delegates_to"}),
    ("halt_sub_not_accord", "A halt whose CWT sub is not the accord's family_key_id.", "A1", A1, FAM_CONST,
     invocation(A1, "halt-s", 0x7b, T0), "member:sub", {"sub": "the-halted-agents"}),
    ("halt_valid_until_equals_asserted_at", "A halt whose valid_until equals its asserted_at: not after it.",
     "A1", A1, FAM_CONST, dict(invocation(A1, "halt-v", 0x7c, T0), valid_until=T0),
     "valid_until_not_after_asserted_at", {}),
]:
    add_invocation(cid, desc, name, k, fam, p, expect="refused:" + tok, **kw)

# ---- Counted lifecycle rows ----
ROWS = {}


def add_lifecycle(cid, desc, kind, signers, p, halt="halt_constitutional_a1", expect="valid", roster="genesis",
                  voices=None, counted=None, wait=None, count=None, extra_statements=(), sub=SUB, tamper=()):
    """signers: (name, key[, iss]) in input order; tamper: indices whose payload is altered after signing."""
    sts = []
    rid = row_id("scores", FAM_LIFE, sub, None, enc(p))
    for i, s in enumerate(signers):
        name, k = s[0], s[1]
        iss = s[2] if len(s) > 2 else None
        t = (lambda q: dict(q, invocation_id=q["invocation_id"] + "-altered")) if i in tamper else None
        st, pb, plb = statement(k, sub, "scores", FAM_LIFE, p, iss=iss, tamper=t)
        rec = stmt_record(name, k, st, pb, plb)
        if iss: rec["iss"] = iss
        sts.append(rec)
    sts.extend(extra_statements)
    case = {"id": cid, "description": desc, "roster": roster, "kind": kind, "row_type": "scores",
            "family": FAM_LIFE, "sub": sub, "members": show(p), "payload_hex": enc(p).hex(), "row_id_hex": rid.hex(),
            "halt": halt, "statements": sts, "expect": expect}
    if expect == "valid":
        case["voices"] = sorted(voices)
        case["counted"] = counted
    if wait is not None:
        case["waiting"] = wait
        assert expect == expect_of(wait)
    if count is not None:
        case["count"] = {"have": count[0], "need": count[1]}
    lifecycles.append(case)
    return case


P_CONF = lifecycle("confirmed", "confirm-1", 0x55, T0 + 600000, H)
P_ACT = lifecycle("active", "resume-1", 0x66, T0 + 1200000, H)
add_lifecycle("confirmed_a1_b1", "lifecycle:confirmed by A1 and B1 over one payload naming the halt: 2 of 3, a "
              "strict majority; one row id, two statement ids.", "confirmed", [("A1", A1), ("B1", B1)], P_CONF,
              voices=[A1.iss, B1.iss], counted=[0, 1])
add_lifecycle("active_b1_c1", "lifecycle:active by B1 and C1 naming the halt: 2 of 3.", "active",
              [("B1", B1), ("C1", C1)], P_ACT, voices=[B1.iss, C1.iss], counted=[0, 1])

# Counted with an unheld voice: the held voices decide where they meet the count (CC 4.2.1.3: a strict majority
# of the standing roster), and an unheld one is simply not counted.
add_lifecycle("confirmed_b1_c1_plus_rotated_a1", "B1, C1 and A1 under its rotated key (not held by the genesis "
              "roster): the held voices meet 2 of 3, so valid; A1's statement is not counted.", "confirmed",
              [("B1", B1), ("C1", C1), ("A1R", A1R)], P_CONF, voices=[B1.iss, C1.iss], counted=[0, 1])
add_lifecycle("confirmed_a1_b1_plus_outsider", "A1, B1 and the outsider: met by A1 and B1, so valid; the "
              "outsider's statement is not counted.", "confirmed", [("A1", A1), ("B1", B1), ("OUTSIDER", OUTSIDER)],
              P_CONF, voices=[A1.iss, B1.iss], counted=[0, 1])
add_lifecycle("confirmed_b1_rotated_a1_unmet_waits", "B1 and A1 under its rotated key, read under the genesis "
              "roster: one held voice of the two needed, and the unheld key could be the second (CC 2.6.1.8 step "
              "6): Waiting on it.", "confirmed", [("B1", B1), ("A1R", A1R)], P_CONF, expect="waiting:kid",
              wait=waiting(kids=[A1R]))
add_lifecycle("lifecycle_outsider_voice", "A1 and the outsider (v1: count_unmet): one held voice, and the "
              "outsider's key could be a holder's seated by a bundle the reader lacks: Waiting on it.",
              "confirmed", [("A1", A1), ("OUTSIDER", OUTSIDER)], P_CONF, expect="waiting:kid",
              wait=waiting(kids=[OUTSIDER]))
add_lifecycle("confirmed_unmet_refused_voices", "A1, B1's statement altered after signing (bad_signature) and "
              "C1's key under A1's iss (iss_not_holder): one held voice and two refused ones; a refused statement "
              "never makes a row wait, so count_unmet.", "confirmed",
              [("A1", A1), ("B1", B1), ("C1", C1, A1.iss)], P_CONF, expect="refused:count_unmet", count=(1, 2),
              tamper=(1,))

# A lifecycle row is counted over the bundle refs.head names (CC 4.2.1.1: "The reader verifies the row against
# the bundle in force ... that refs.head names on a lifecycle row"); read under any other roster it waits on
# that bundle (CC 2.7.3).
P_CONF_R = lifecycle("confirmed", "confirm-r", 0x60, T0 + 700000, H, head=BUNDLE2)
add_lifecycle("lifecycle_names_unheld_bundle", "A1 and B1 confirm over the rotated bundle, read under the genesis "
              "roster: each statement waits on that bundle (both keys are held here).",
              "confirmed", [("A1", A1), ("B1", B1)], P_CONF_R, expect="waiting:bundle", wait=waiting(bundles=[BUNDLE2]))
add_lifecycle("rotated_confirmation_unseated", "A1 under its rotated key and B1 confirm over the rotated bundle, "
              "read under the genesis roster: A1's statement waits on its key and the bundle, B1's on the bundle.",
              "confirmed", [("A1R", A1R), ("B1", B1)], P_CONF_R, expect="waiting:kid+bundle",
              wait=waiting(kids=[A1R], bundles=[BUNDLE2]))
add_lifecycle("rotated_confirmation_seated", "The same statements read under the rotated roster that refs.head "
              "names: valid, voices A1 and B1.", "confirmed", [("A1R", A1R), ("B1", B1)], P_CONF_R,
              roster="rotated", voices=[A1.iss, B1.iss], counted=[0, 1])
add_lifecycle("lifecycle_other_bundle", "refs.head names a bundle no roster here is of (v1: other_bundle): "
              "Waiting on it.", "confirmed", [("A1", A1), ("B1", B1)],
              lifecycle("confirmed", "confirm-4", 0x5a, T0 + 600000, H, head=hashlib.sha256(b"another bundle").digest()),
              expect="waiting:bundle", wait=waiting(bundles=[hashlib.sha256(b"another bundle").digest()]))

# Refused, as in v1.
add_lifecycle("confirmed_lone_a1", "A lone confirmed voice: 1 of 3 is no strict majority, and nothing waits.",
              "confirmed", [("A1", A1)], P_CONF, expect="refused:count_unmet", count=(1, 2))
add_lifecycle("confirmed_a1_twice", "A1's voice presented twice is one voice.", "confirmed",
              [("A1", A1), ("A1", A1)], P_CONF, expect="refused:count_unmet", count=(1, 2))
_p_other = lifecycle("confirmed", "confirm-1b", 0x56, T0 + 600000, H)
_st, _pb, _plb = statement(B1, SUB, "scores", FAM_LIFE, _p_other)
add_lifecycle("two_rows_one_voice_each", "A1 signs one confirmed row, B1 another (another nonce): two rows of one "
              "voice each; the count is unmet and one statement is refused other_row (the lowest row id is "
              "counted on a tie).", "confirmed", [("A1", A1)], P_CONF, expect="refused:count_unmet", count=(1, 2),
              extra_statements=[stmt_record("B1", B1, _st, _pb, _plb)])
add_lifecycle("confirmed_names_other_halt", "A1 and B1 confirm halt-2 (B1's), presented against A1's halt.",
              "confirmed", [("A1", A1), ("B1", B1)], lifecycle("confirmed", "confirm-2", 0x57, T0 + 600000, H2),
              expect="refused:other_halt")
add_lifecycle("active_names_drill", "A1 and B1 'resume' the drill: the row it names is no constitutional halt.",
              "active", [("A1", A1), ("B1", B1)], lifecycle("active", "resume-d", 0x58, T0 + 600000, D),
              halt="drill_c1", expect="refused:target_not_a_halt")
_no_target = lifecycle("confirmed", "confirm-3", 0x59, T0 + 600000, H)
_no_target["refs"] = {"head": rref(BUNDLE)}
add_lifecycle("lifecycle_names_no_halt", "refs carries head and no target.", "confirmed", [("A1", A1), ("B1", B1)],
              _no_target, expect="refused:member:target")
add_lifecycle("lifecycle_with_author", "A lifecycle row is counted: an author is refused by the family model.",
              "confirmed", [("A1", A1), ("B1", B1)],
              lifecycle("confirmed", "confirm-5", 0x5b, T0 + 600000, H, author=A1.iss),
              expect="refused:family:author_column")
add_lifecycle("lifecycle_dimension_unversioned", "dimension accord:lifecycle:confirmed without its :vN tail.",
              "confirmed", [("A1", A1), ("B1", B1)],
              lifecycle("confirmed", "confirm-6", 0x5c, T0 + 600000, H, dimension="accord:lifecycle:confirmed"),
              expect="refused:statement_invalid:dimension_refused:missing_version_segment")
add_lifecycle("lifecycle_sub_not_accord", "A lifecycle row whose CWT sub is not the accord's family_key_id.",
              "confirmed", [("A1", A1), ("B1", B1)], lifecycle("confirmed", "confirm-7", 0x5d, T0 + 600000, H),
              expect="refused:member:sub", sub="the-halted-agents")
add_lifecycle("lifecycle_valid_until_before_asserted_at", "A lifecycle row whose valid_until precedes its "
              "asserted_at.", "confirmed", [("A1", A1), ("B1", B1)],
              lifecycle("confirmed", "confirm-8", 0x5e, T0 + 600000, H, valid_until=T0 + 599000),
              expect="refused:valid_until_not_after_asserted_at")
# Cross-family replays.
_h = invocations[0]
lifecycles.append({"id": "replay_halt_as_lifecycle", "description": "The constitutional halt's statement bytes "
                   "presented as a lifecycle row: the family is the invocation's.", "roster": "genesis",
                   "kind": "confirmed", "row_id_hex": _h["row_id_hex"], "halt": "halt_constitutional_a1",
                   "statements": [_h["statement"]], "expect": "refused:wrong_family"})
_lc = lifecycles[0]
invocations.append({"id": "replay_lifecycle_as_invocation", "description": "A1's confirmed statement presented as "
                    "an invocation: the family is the lifecycle's.", "roster": "genesis",
                    "row_id_hex": _lc["row_id_hex"], "statement": _lc["statements"][0],
                    "expect": "refused:wrong_family"})

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
    {"id": "rotated_holder_halt_fires", "description": "A1's halt under its rotated key, read under the roster "
     "that seats it, pauses on receipt and lapses halt_fuse_secs after receipt, as any lone halt.",
     "steps": [
        {"apply": "halt_rotated_a1_seated", "at_ms": R0, "outcome": "paused"},
        {"check": R0 + F - 1, "paused": True},
        {"check": R0 + F, "paused": False}]},
]

assert len({c["id"] for c in invocations + lifecycles}) == len(invocations + lifecycles)


def roster_json(name):
    bundle, holders = ROSTERS[name]
    return {"accord_root": ACCORD_ROOT, "bundle_object_id_hex": bundle.hex(), "halt_fuse_secs": HALT_FUSE_SECS,
            "majority": 2,
            "holders": [{"label": n, "key_seed": k.n, "iss": k.iss, "kid_hex": k.kid.hex()} for n, k in holders]}


out = {
    "$schema_note": (
        "Edition-2 accord halt known answers, v2 (CC 4.2.1.1, CC 4.2.1.3, CC 4.2.6, CC 2.6.1.8; CIRISConstitution "
        "rc20 436b5bc). Key n: ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32; signatures deterministic. "
        "Generated independently of the Rust code by gen_accord_halt_v2.py; see README.md. members render bytes "
        "as {\"bstr\": hex}. Every case names the roster it is read under. expect: valid, waiting:<kid|bundle|"
        "kid+bundle> (with waiting.kids_hex / bundles_hex, sorted), or refused:<token> (count_unmet with "
        "count.have / count.need). A valid lifecycle case names its counted statements by index."),
    "rosters": {n: roster_json(n) for n in ROSTERS},
    "outsider": {"label": "OUTSIDER", "key_seed": OUTSIDER.n, "iss": OUTSIDER.iss, "kid_hex": OUTSIDER.kid.hex()},
    "invocations": invocations,
    "lifecycles": lifecycles,
    "latch": latch,
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
print()
