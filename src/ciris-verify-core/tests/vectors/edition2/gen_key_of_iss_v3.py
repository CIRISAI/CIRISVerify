# gen_key_of_iss_v3.py: gen_key_of_iss_v2.py (the key check of CC 2.6.1.8 step 8 as rc21 states it, ways
# (a)-(d), at CIRISConstitution v1.0-rc21-wire e6fd7c6; kept unchanged beside it) with the occurrence key's
# own voice signed as itself (rc21 90d537b): its proof of possession is way (a) of step 8, `iss` the
# occurrence key, since it is not yet an occurrence (CC 3.3.6, CC 3.3.6.4). v2 signed it under the
# identity's `iss`; that statement is no proof of possession, and the occurrence waits on one.
# Helpers below are gen_key_of_iss.py's, copied.
# Independent generator of known answers for the key check of CC 2.6.1's verification order (rc20):
# a row statement's signing key must be a key of its CWT `iss`, either the key `iss` names or one a
# rotation chain from that key reaches (CC 2.6.1.7, CC 2.4.1.1, CC 3.1.3). Refused: `kid_not_of_iss`.
# Its own CBOR deterministic encoder (RFC 8949 4.2.1 bytewise key order), dilithium-py (FIPS 204,
# deterministic) and pyca/cryptography (Ed25519), copied from gen_row_statements_v2.py. Shares no code
# with verify. Run: python gen_key_of_iss_v3.py > key_of_iss_v3.json
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
        self.seed = n
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


def statement(k, iss, sub, family, payload, rtype="scores"):
    """A row statement signed by k with the CWT iss `iss` (an identity reference)."""
    claims = {1: iss, 2: sub, 6: payload["asserted_at"] // 1000, -70003: 2}
    if "valid_until" in payload: claims[4] = payload["valid_until"] // 1000
    prot = {1: -70100, 3: "application/vnd.ciris.row+cbor", 4: k.kid, 15: claims, 16: "ceg-row/2",
            -70001: rtype, -70002: family}
    pb, plb = enc(prot), enc(payload)
    sig = k.sign(enc(["Signature1", pb, b"", plb]))
    return enc(Tag(18, [pb, {}, plb, sig]))


def row_id(rtype, family, sub, author, payload):
    return hashlib.sha256(enc(["CEG-row/2", rtype, family, sub, author, enc(payload)])).digest()


def rref(d): return [2, [-16, d]]


FAM = "evidence:.suite:.kind:.cell:.prefix"
KR = "key:record"
T0 = 1763200000000


A, B, C, D, E, R = Key(1), Key(2), Key(3), Key(20), Key(21), Key(7)
OCC = "identity:occurrence"
OREV = "identity:occurrence_revocation"


def krec(k, roles, t0=T0, target=None, until=None):
    p = {"key": {1: 7, 3: -70100, -1: k.pub}, "identity_type": sorted(roles, key=enc), "asserted_at": t0}
    if until is not None: p["valid_until"] = until
    if target is not None: p["refs"] = {"target": rref(target)}
    return p


class Row:
    """A row of `family` about `sub`: payload, row id, statements over it."""
    def __init__(self, family, sub, payload, author=None):
        self.family, self.sub, self.payload = family, sub, payload
        self.id = row_id("scores", family, sub, author, payload)

    def by(self, signer, iss):
        return statement(signer, iss.iss, self.sub, self.family, self.payload).hex()


def rec_row(k, roles, t0=T0, target=None, until=None):
    return Row(KR, k.iss, krec(k, list(roles), t0, target, until))


HEADS = {}   # identity -> the row id of its genesis key's own record: a first bind's refs.head (CC 3.3.6.4)


def occ_row(identity, key, device_class="phone", t0=T0, until=None, head=True):
    p = {"author": identity.iss, "identity_key_id": identity.iss, "occurrence_key_id": key.iss,
         "device_class": device_class, "asserted_at": t0}
    if head: p["refs"] = {"head": rref(HEADS[identity.seed])}
    if until is not None: p["valid_until"] = until
    return Row(OCC, key.iss, p, author=identity.iss)


def evict_row(identity, key, effective_at):
    p = {"author": identity.iss, "identity_key_id": identity.iss, "occurrence_key_id": key.iss,
         "revoked_at": effective_at, "effective_at": effective_at, "asserted_at": effective_at,
         "refs": {"head": rref(HEADS[identity.seed])}}
    return Row(OREV, key.iss, p, author=identity.iss)


# Held records: A a person (user), its genesis record self-signed; B another person; D a device key of A's
# person (user); E an agent key (agent, with an end); R a key with only its own record (iss R).
rA, rB = rec_row(A, ["user"]), rec_row(B, ["user"])
HEADS[A.seed], HEADS[B.seed] = rA.id, rB.id
recA, recB = rA.by(A, A), rB.by(B, B)
recD = rec_row(D, ["user"]).by(D, D)
recE = rec_row(E, ["agent"], until=T0 + 10_000_000).by(E, E)
recR = rec_row(R, ["user"]).by(R, R)

cases = []


def case(cid, desc, signer, iss, expect, at=T0 + 100, records=(), occurrences=(), evictions=(), seats=(),
         pending=None, payload=None, family=FAM, sub="subject-1", level="statement"):
    p = payload if payload is not None else {"asserted_at": at, "author": iss.iss}
    c = {"id": cid, "description": desc, "level": level,
         "statement_hex": statement(signer, iss.iss, sub, family, p).hex(), "expect": expect,
         "records_hex": list(records), "occurrences_hex": list(occurrences), "evictions_hex": list(evictions),
         "seats": [[i.seed, k.seed] for i, k in seats]}
    if pending is not None: c["pending_bundle_hex"] = pending.hex()
    if level == "family": c["model"] = "vendored"
    cases.append(c)


# ---- step 4: the end rule, and half-open coverage --------------------------------------------------------------
case("end_rule_equal", "A payload whose valid_until equals its asserted_at: step 4 refuses it.", A, A,
     "invalid:valid_until_not_after_asserted_at", payload={"asserted_at": T0 + 100, "valid_until": T0 + 100,
                                                           "author": A.iss}, records=[recA])
case("end_rule_before", "valid_until before asserted_at.", A, A, "invalid:valid_until_not_after_asserted_at",
     payload={"asserted_at": T0 + 100, "valid_until": T0 + 99, "author": A.iss}, records=[recA])
N = Key(30)
recN = rec_row(N, ["node"], until=T0 + 5000).by(N, N)
case("covered_last_ms", "A node key's record covers [T0, T0+5000): a statement at T0+4999 reads.", N, N, "valid",
     at=T0 + 4999, records=[recN])
case("not_covered_at_end", "At exactly valid_until (T0+5000) the record does not cover: Waiting on a covering record.",
     N, N, "waiting:covering", at=T0 + 5000, records=[recN])

# ---- way (b): a rotation waits on a voice it lacks -------------------------------------------------------------
rot = rec_row(B, ["user"], t0=T0 + 10, target=rA.id)   # A rotates to B
case("rotation_complete", "B's record names A's, voiced by B (possession) and by A: B is A's key.", B, A, "valid",
     records=[recA, rot.by(B, A), rot.by(A, A)])
case("rotation_lacks_predecessor_voice", "B's own statement over the rotation, A's not held: Waiting on A's voice.",
     B, A, "waiting:voice", records=[recA, rot.by(B, A)])
case("rotation_lacks_possession", "A's statement over the rotation, B's own not held: Waiting on B's voice.",
     B, A, "waiting:voice", records=[recA, rot.by(A, A)])
case("rotation_target_not_held", "The named record (A's) is not held: Waiting on it.", B, A, "waiting:record",
     records=[rot.by(B, A), rot.by(A, A)])

# ---- way (c): the bundle in force seats the key ----------------------------------------------------------------
case("seated_by_bundle", "The bundle in force seats R for A (a recovery): R signs as A.", R, A, "valid",
     records=[recA, recR], seats=[(A, R)])
case("seat_ended", "The bundle in force seats C for A, not R (a later bundle): kid_not_of_iss.", R, A,
     "invalid:kid_not_of_iss", records=[recA, recR], seats=[(A, C)])
case("bundle_pending", "The bundle in force is known and not held: Waiting on it.", R, A, "waiting:bundle",
     records=[recA, recR], pending=hashlib.sha256(b"bundle-in-force").digest())
case("seated_key_no_record", "The seated key needs no record of its own: the seat holds it.", R, A, "valid",
     records=[recA], seats=[(A, R)])

# ---- way (d): an occurrence of iss binds the key ----------------------------------------------------------------
oD = occ_row(A, D)
case("occurrence_binds", "A's occurrence binds D (phone), voiced by A and by D: D signs as A.", D, A, "valid",
     records=[recA, recD], occurrences=[oD.by(A, A), oD.by(D, D)])
case("possession_signed_as_identity", "D's voice over the occurrence is signed under A's iss (v2's form): no proof "
     "of possession, which is D's statement as itself (rc21 90d537b). Waiting on D's own voice.", D, A,
     "waiting:voice", records=[recA, recD], occurrences=[oD.by(A, A), oD.by(D, A)])
case("occurrence_lacks_possession", "Only A's voice is held: Waiting on D's.", D, A, "waiting:voice",
     records=[recA, recD], occurrences=[oD.by(A, A)])
case("occurrence_lacks_identity_voice", "Only D's voice is held: Waiting on a voice of A.", D, A, "waiting:voice",
     records=[recA, recD], occurrences=[oD.by(D, D)])
oE = occ_row(A, E, device_class="agent")
case("agent_under_person", "An agent key bound under a person's identity: never (CC 2.4.1.1).", E, A,
     "invalid:kid_not_of_iss", records=[recA, recE], occurrences=[oE.by(A, A), oE.by(E, E)])
oE2 = occ_row(A, E, device_class="server")
case("agent_record_under_person", "An agent-record key as a server occurrence of a person: never.", E, A,
     "invalid:kid_not_of_iss", records=[recA, recE], occurrences=[oE2.by(A, A), oE2.by(E, E)])
ev = evict_row(A, D, T0 + 50)
case("occurrence_evicted", "A evicts D effective T0+50; D's statement at T0+100: kid_not_of_iss.", D, A,
     "invalid:kid_not_of_iss", records=[recA, recD], occurrences=[oD.by(A, A), oD.by(D, D)], evictions=[ev.by(A, A)])
case("evicted_later", "The eviction is effective at T0+200; a statement at T0+100 still reads.", D, A, "valid",
     records=[recA, recD], occurrences=[oD.by(A, A), oD.by(D, D)], evictions=[evict_row(A, D, T0 + 200).by(A, A)])
case("eviction_by_stranger", "An eviction signed by B (not A's key) evicts nothing.", D, A, "valid",
     records=[recA, recB, recD], occurrences=[oD.by(A, A), oD.by(D, D)], evictions=[ev.by(B, B)])
oDnh = occ_row(A, D, head=False)
case("occurrence_names_no_head", "An occurrence whose refs name no self-roster head breaks its family's payload rule.",
     D, A, "invalid:kid_not_of_iss", records=[recA, recD], occurrences=[oDnh.by(A, A), oDnh.by(D, D)])
# Review findings (PR #350): an eviction whose signer is not held; a record filed under A's key by another
# key; a seated key with a bad record of its own; an occurrence payload keyed by an integer.
Z = Key(40)
case("eviction_signer_not_held", "An eviction of D signed by a key whose record is not held has not concluded; a "
     "Waiting row counts for nothing (CC 2.7), so D still signs as A. The caller sees it as a pending eviction.",
     D, A, "valid",
     records=[recA, recD], occurrences=[oD.by(A, A), oD.by(D, D)], evictions=[evict_row(A, D, T0 + 50).by(Z, A)])
forged = Row(KR, A.iss, krec(A, ["agent"], until=T0 + 10_000_000)).by(S_ := Key(5), S_)
case("forged_record_does_not_unperson", "S files a record of A's key saying agent; the guard reads only A's own "
     "verified record, so an agent occurrence under A stays refused.", E, A, "invalid:kid_not_of_iss",
     records=[recA, forged, recE], occurrences=[oE.by(A, A), oE.by(E, E)])
badR = rec_row(R, ["user"], until=T0 + 10_000_000).by(R, R)   # a user record may not state an end: refused
case("seat_shadows_bad_record", "R is seated for A, and R's own record breaks the end rule: the seat holds R.", R, A,
     "valid", records=[recA, badR], seats=[(A, R)])
oDint = occ_row(A, D)
oDint.payload[7] = 1
oDint.id = row_id("scores", OCC, oDint.sub, A.iss, oDint.payload)
case("occurrence_integer_key", "An occurrence payload with an integer-keyed member: its open tail admits text keys "
     "only.", D, A, "invalid:kid_not_of_iss", records=[recA, recD], occurrences=[oDint.by(A, A), oDint.by(D, D)])
oDB = occ_row(B, D)
case("occurrence_of_other_identity", "B's occurrence binds D; D signs as A: kid_not_of_iss.", D, A,
     "invalid:kid_not_of_iss", records=[recA, recB, recD], occurrences=[oDB.by(B, B), oDB.by(D, D)])
oDend = occ_row(A, D, until=T0 + 50)
case("occurrence_ended", "A's occurrence of D ends at T0+50; a statement at T0+100 waits on a covering one.", D, A,
     "waiting:covering", records=[recA, recD], occurrences=[oDend.by(A, A), oDend.by(D, D)])
case("occurrence_voiced_by_stranger", "The identity voice is B's (iss B), not A's: Waiting on a voice of A.", D, A,
     "waiting:voice", records=[recA, recB, recD], occurrences=[oD.by(B, B), oD.by(D, D)])

# ---- location_proof: authored by its subject alone (CC 2.6.1.3, rc21 family model) ----------------------------
LP = "location_proof:.version"
lp = {"asserted_at": T0 + 100, "author": A.iss, "dimension": "location_proof:v1"}
case("location_proof_by_subject", "location_proof with iss = sub = author: Valid under the vendored model.", A, A,
     "valid", payload=lp, family=LP, sub=A.iss, records=[recA], level="family")
case("location_proof_other_sub", "location_proof whose sub is B, author and iss A: the author is not the subject.",
     A, A, "family:iss_not_in_role", payload=lp, family=LP, sub=B.iss, records=[recA], level="family")
case("location_proof_by_other", "location_proof about A (author A) signed by B as itself: refused.", B, B,
     "family:iss_not_in_role", payload=lp, family=LP, sub=A.iss, records=[recB], level="family")

print(json.dumps({"description": "Known answers for the key check of CC 2.6.1.8 step 8 (rc21: ways (a)-(d), an occurrence key's proof of possession signed as itself (90d537b), "
                  "Waiting on what is not held, half-open coverage) and the end rule of step 4. Each case gives the "
                  "directory: key records, admitted occurrences, evictions, the bundle in force's seats as "
                  "[issuer seed, seated key seed], and a pending bundle. Keys are from seeds: ML-DSA-65 seed [n]*32, "
                  "Ed25519 seed [n+100]*32.", "generator": "gen_key_of_iss_v3.py", "cases": cases}, indent=1))
