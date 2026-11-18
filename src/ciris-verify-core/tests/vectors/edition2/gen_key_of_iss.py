# Independent generator of known answers for the key check of CC 2.6.1's verification order (rc20):
# a row statement's signing key must be a key of its CWT `iss`, either the key `iss` names or one a
# rotation chain from that key reaches (CC 2.6.1.7, CC 2.4.1.1, CC 3.1.3). Refused: `kid_not_of_iss`.
# Its own CBOR deterministic encoder (RFC 8949 4.2.1 bytewise key order), dilithium-py (FIPS 204,
# deterministic) and pyca/cryptography (Ed25519), copied from gen_row_statements_v2.py. Shares no code
# with verify. Run: python gen_key_of_iss.py > key_of_iss_v1.json
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

A, B, C, R, B2, B3 = Key(1), Key(2), Key(3), Key(7), Key(12), Key(13)


def krec(k, roles, t0=T0, target=None, until=None):
    p = {"key": {1: 7, 3: -70100, -1: k.pub}, "identity_type": sorted(roles, key=enc), "asserted_at": t0}
    if until is not None: p["valid_until"] = until
    if target is not None: p["refs"] = {"target": rref(target)}
    return p


class Record:
    """A key:record row about `subject`: its payload, row id and the statements over it."""
    def __init__(self, subject, payload):
        self.subject, self.payload = subject, payload
        self.sub = subject.iss
        self.id = row_id("scores", KR, self.sub, None, payload)

    def by(self, signer, iss):
        return statement(signer, iss.iss, self.sub, KR, self.payload).hex()


def self_record(k, roles=("user",), t0=T0, iss=None):
    r = Record(k, krec(k, list(roles), t0))
    return r, r.by(k, iss or k)


def rotation(new, issuer, prev_record, t0=T0 + 10, roles=("user",)):
    """The next key's record naming its predecessor's record in refs.target."""
    return Record(new, krec(new, list(roles), t0, target=prev_record.id))


rec_A, st_A = self_record(A)
rec_B, st_B = self_record(B)
rot_B2 = rotation(B2, B, rec_B)
st_B2_own, st_B2_by_B = rot_B2.by(B2, B), rot_B2.by(B, B)

cases = []


def case(cid, desc, signer, iss, author, expect, raw=None, records=None, level="statement"):
    p = {"asserted_at": T0 + 100, "author": author.iss}
    c = {"id": cid, "description": desc, "level": level,
         "statement_hex": statement(signer, iss.iss, "subject-1", FAM, p).hex(), "expect": expect}
    if raw is not None:
        c["directory"] = "raw"
        c["held_key_seeds"] = [k.seed for k in raw]
    else:
        c["directory"] = "records"
        c["records_hex"] = records
    if level == "family":
        c["model"] = "vendored"
    cases.append(c)


case("a_as_a_raw", "Signed by A with iss A and author A; raw directory holding A.", A, A, A, "valid", raw=[A])
case("b_as_b_raw", "Signed by B with iss B and author B; raw directory holding B.", B, B, B, "valid", raw=[B])
case("a_as_a_records", "Signed by A with iss A and author A; records: A's and B's self-signed records.",
     A, A, A, "valid", records=[st_A, st_B])
case("b_as_b_records", "Signed by B with iss B and author B; records: A's and B's self-signed records.",
     B, B, B, "valid", records=[st_A, st_B])
case("a_iss_b_raw", "Signed by A with iss B and author B; raw directory holding A and B.",
     A, B, B, "invalid:kid_not_of_iss", raw=[A, B])
case("a_iss_b_records", "Signed by A with iss B and author B; records: A's and B's self-signed records.",
     A, B, B, "invalid:kid_not_of_iss", records=[st_A, st_B])
case("a_iss_a_author_b_family", "Signed by A with iss A and author B, read with the vendored family model; "
     "raw directory holding A.", A, A, B, "family_invalid:iss_not_in_role", raw=[A], level="family")
case("a_not_held_raw", "Signed by A with iss A; raw directory holding nothing.", A, A, A,
     "waiting:kid:" + A.kid.hex(), raw=[])
case("a_not_held_records", "Signed by A with iss A; records: B's self-signed record only.", A, A, A,
     "waiting:kid:" + A.kid.hex(), records=[st_B])

case("rotation_b2_as_b", "Signed by B2 with iss B and author B; records: B's self-signed record and B2's record "
     "naming it in refs.target, with B2's statement and B's statement (iss B) over it.",
     B2, B, B, "valid", records=[st_B, st_B2_own, st_B2_by_B])
case("rotation_b2_as_b_reverse_order", "As rotation_b2_as_b, records inserted in the reverse order.",
     B2, B, B, "valid", records=[st_B2_by_B, st_B2_own, st_B])
case("rotation_genesis_not_held", "Signed by B2 with iss B; records: B2's rotation record with B2's and B's "
     "statements; B's own record not held.", B2, B, B, "waiting:kid:" + B.kid.hex(),
     records=[st_B2_own, st_B2_by_B])
case("rotation_without_predecessor_statement", "Signed by B2 with iss B; records: B's self-signed record and "
     "B2's record naming it, with B2's statement only.", B2, B, B, "invalid:kid_not_of_iss",
     records=[st_B, st_B2_own])
case("rotation_without_own_statement", "Signed by B2 with iss B; records: B's self-signed record and B2's record "
     "naming it, with B's statement only.", B2, B, B, "invalid:kid_not_of_iss",
     records=[st_B, st_B2_by_B])
rot_to_A_rec = rotation(B2, B, rec_A)
case("rotation_names_another_record", "Signed by B2 with iss B; records: A's and B's self-signed records and "
     "B2's record naming A's record in refs.target, with B2's and B's statements (iss B).",
     B2, B, B, "invalid:kid_not_of_iss",
     records=[st_A, st_B, rot_to_A_rec.by(B2, B), rot_to_A_rec.by(B, B)])
case("rotation_cosigned_by_another_key", "Signed by B2 with iss B; records: A's and B's self-signed records and "
     "B2's record naming A's record, with B2's statement (iss B) and A's statement (iss B).",
     B2, B, B, "invalid:kid_not_of_iss",
     records=[st_A, st_B, rot_to_A_rec.by(B2, B), rot_to_A_rec.by(A, B)])
rec_C_claims_B, st_C_claims_B = self_record(C, iss=B)
case("unrelated_key_claims_iss", "Signed by C with iss B and author B; records: B's self-signed record and C's "
     "record signed by C with iss B, naming no predecessor.", C, B, B, "invalid:kid_not_of_iss",
     records=[st_B, st_C_claims_B])
rec_C_by_A = Record(C, krec(C, ["user"]))
case("record_by_other_key_only", "Signed by C with iss A and author A; records: A's self-signed record and a "
     "record of C signed by A with iss A, without C's statement.", C, A, A, "invalid:kid_not_of_iss",
     records=[st_A, rec_C_by_A.by(A, A)])

# The predecessor named in refs.target is not held, though another record of B is.
rec_B_later, st_B_later = self_record(B, t0=T0 + 1)
rot_waits = rotation(B2, B, rec_B)
case("rotation_target_not_held", "Signed by B2 with iss B; records: a later self-signed record of B (not the "
     "one named), and B2's record naming B's first record, with B2's and B's statements.",
     B2, B, B, "waiting:record:" + rec_B.id.hex(),
     records=[st_B_later, rot_waits.by(B2, B), rot_waits.by(B, B)])

# Two hops: B -> B2 -> B3.
rot_B3 = rotation(B3, B, rot_B2, t0=T0 + 20)
case("rotation_two_hops", "Signed by B3 with iss B; records: B's self-signed record, B2's record naming it "
     "(B2's and B's statements), B3's record naming B2's (B3's and B2's statements, iss B).",
     B3, B, B, "valid",
     records=[st_B, st_B2_own, st_B2_by_B, rot_B3.by(B3, B), rot_B3.by(B2, B)])
case("rotation_two_hops_middle_missing", "As rotation_two_hops without B2's rotation record.",
     B3, B, B, "waiting:kid:" + B2.kid.hex(),
     records=[st_B, rot_B3.by(B3, B), rot_B3.by(B2, B)])

# Two rotations of B, neither naming the other.
rot_B3_rival = rotation(B3, B, rec_B, t0=T0 + 11)
case("rotation_contested", "Signed by B2 with iss B; records: B's self-signed record, B2's record naming it and "
     "B3's record naming it, each with its own and B's statements.", B2, B, B, "invalid:kid_not_of_iss",
     records=[st_B, st_B2_own, st_B2_by_B, rot_B3_rival.by(B3, B), rot_B3_rival.by(B, B)])

# A rival rotation whose named record of B is not one covering the rival's instant
# is no rival: the legitimate rotation still answers (the rule the chain itself
# applies to a predecessor's record, CC 2.4.1.1).
rec_B_late, st_B_late = self_record(B, t0=T0 + 50)
rot_B3_uncovered = rotation(B3, B, rec_B_late, t0=T0 + 11)
case("rotation_rival_names_uncovered_record", "Signed by B2 with iss B; records: B's self-signed record, B2's "
     "record naming it (B2's and B's statements), a later self-signed record of B (asserted at T0+50), and B3's "
     "record (asserted at T0+11) naming that later record, with B3's and B's statements.", B2, B, B, "valid",
     records=[st_B, st_B2_own, st_B2_by_B, st_B_late, rot_B3_uncovered.by(B3, B), rot_B3_uncovered.by(B, B)])

# A room key signs as itself: iss is its own key's reference.
rec_R, st_R = self_record(R, roles=("room",))
case("room_key_self", "Signed by room key R with iss R and author R; records: R's self-signed record "
     "(identity_type room).", R, R, R, "valid", records=[st_R])

assert len({c["id"] for c in cases}) == len(cases)
out = {
    "$schema_note": (
        "Known answers for the key check of CC 2.6.1's verification order (CIRISConstitution rc20): a row "
        "statement's signing key must be a key of its CWT iss (CC 2.6.1.7: iss names the signer's genesis key), "
        "the key iss names or one reached from it by rotation records (CC 2.4.1.1, CC 3.1.3: the next key's "
        "key:record, signed by that key, naming the predecessor's record by row-ref in refs.target, with the "
        "predecessor key's statement over the same row). Keys: ML-DSA-65 seed = [n]*32, Ed25519 seed = "
        "[n+100]*32; A=1, B=2, C=3, R=7, B2=12, B3=13. Generated by gen_key_of_iss.py, independently of the Rust "
        "code. directory: raw (held_key_seeds, keys by thumbprint) or records (records_hex, inserted in order into "
        "a key-record directory). level: statement (verify_row_statement) or family (verify_row_in_family under "
        "the model named). expect: valid, waiting:kid:<kid>, waiting:record:<row id>, invalid:<reason> or "
        "family_invalid:<fault>."),
    "cases": cases,
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
print()
