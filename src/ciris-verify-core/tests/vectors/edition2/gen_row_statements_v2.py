# Independent generator of CC 2.6.1 (rc20) edition-2 row statement known answers, v2: the clean
# mesh (CIRISConstitution rc20 0c9e17c). No row of this form names an object of the earlier form, a
# statement after its key record's valid_until waits on a covering record, and every case states its
# level. v1 (gen_row_statements.py, row_statements_v1.json) is kept unchanged beside it.
# Its own CBOR deterministic encoder (RFC 8949 4.2.1 bytewise key order), dilithium-py
# (FIPS 204, deterministic) and pyca/cryptography (Ed25519). Shares no code with verify.
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65

PREFIX = b"CompositeAlgorithmSignatures2025"
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"


class Tag:
    def __init__(self, n, v): self.n, self.v = n, v


class Simple:
    def __init__(self, n): self.n = n


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
    if isinstance(v, Simple): return head(7, v.n)
    raise TypeError(v)


class Key:
    def __init__(self, n):
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


def statement(k, sub, rtype, family, payload, claims_edit=None, prot_edit=None, unprot=None, sig_edit=None):
    claims = {1: k.iss, 2: sub, 6: payload["asserted_at"] // 1000, -70003: 2}
    if "valid_from" in payload: claims[5] = payload["valid_from"] // 1000
    if "valid_until" in payload: claims[4] = payload["valid_until"] // 1000
    if claims_edit: claims_edit(claims)
    prot = {1: -70100, 3: "application/vnd.ciris.row+cbor", 4: k.kid, 15: claims, 16: "ceg-row/2",
            -70001: rtype, -70002: family}
    if prot_edit: prot_edit(prot)
    pb, plb = enc(prot), enc(payload)
    m = enc(["Signature1", pb, b"", plb])
    sig = k.sign(m)
    if sig_edit: sig = sig_edit(sig, m)
    return enc(Tag(18, [pb, unprot or {}, plb, sig])), pb, plb


FAM = "evidence:.suite:.kind:.cell:.prefix"


def hd(d): return [-16, d]
def rref(n): return [2, hd(bytes([n]) * 32)]


A, B, C = Key(1), Key(2), Key(3)
P1 = {"author": A.iss, "asserted_at": 1763200000123, "dimension": "evidence:safety_battery:capture:a:b:v1",
      "score": 750000, "confidence": 900000, "evidence_refs": [hd(bytes([9]) * 32)]}
P2 = {"asserted_at": 1763200000999, "valid_from": 1763200000000, "valid_until": 1794736000500,
      "refs": {"head": rref(1), "further_heads": [rref(2), rref(3)], "also": {"ack": [rref(4)]}},
      "salt": bytes(range(16)), "body": {"note": "a note", Simple(59): [bytes([5]) * 32]},
      "list": [1, Tag(60, bytes([6]) * 32)]}

valid, refusals = [], []


# Every valid statement is also valid at the family level under CC's vendored model
# (manifests/family_authorship.json, rc20 e08bf05), with no caller-supplied selector keys.
VALID_LEVELS = {"level": "statement", "family_vendored_expect": "valid"}


def add_valid(cid, desc, k, sub, rt, fam, p):
    st, pb, plb = statement(k, sub, rt, fam, p)
    author = p.get("author")
    rid = hashlib.sha256(enc(["CEG-row/2", rt, fam, sub, author, plb])).digest()
    sid = hashlib.sha256(enc(["CEG-statement-id/2", pb, plb])).digest()
    valid.append(dict(VALID_LEVELS, id=cid, description=desc, key_seed=k.ml_seed[0], statement_hex=st.hex(),
                      kid_hex=k.kid.hex(), iss=k.iss, row_id_hex=rid.hex(), statement_id_hex=sid.hex()))
    return st


s1 = add_valid("authored_score", "An authored scores row signed by its author.", A, "subject-1", "scores",
               "evidence:.suite:.kind:.cell:.prefix", P1)
# group:roster is counted in CC's model (authorship `*` => counted), so the row has no author and each
# voice signs as itself: second_voice is a second voice of the same counted row.
COUNTED_FAM, COUNTED_SUB = "group:roster", "urn:ietf:params:oauth:ckt:sha-256:" + "A" * 43
add_valid("counted_with_refs", "A counted row (no author, on group:roster, counted in CC's model) with refs, a salt, "
          "nbf/exp and both redaction forms.", C, COUNTED_SUB, "supersedes", COUNTED_FAM, P2)
add_valid("second_voice", "The counted row above signed by a second key, a second voice: same row id, another "
          "statement id.", B, COUNTED_SUB, "supersedes", COUNTED_FAM, P2)


def refuse(cid, desc, verdict, st, keys=(A,)):
    refusals.append({"id": cid, "description": desc, "level": "statement", "expect": verdict,
                     "statement_hex": st.hex(), "held_key_seeds": [k.ml_seed[0] for k in keys]})


def edit(d, k, v):
    d = dict(d); d[k] = v; return d


def drop(d, k):
    d = dict(d); del d[k]; return d


refuse("waiting_on_key", "A valid statement whose key is not held: Waiting on its kid.", "waiting:kid:" + A.kid.hex(), s1, keys=())
refuse("bad_signature", "One signature byte flipped.", "invalid:bad_signature",
       statement(A, "s", "scores", FAM, P1, sig_edit=lambda s, m: s[:-1] + bytes([s[-1] ^ 1]))[0])
refuse("ml_dsa_empty_ctx", "The ML-DSA half signed with the empty FIPS 204 context.", "invalid:bad_signature",
       statement(A, "s", "scores", FAM, P1, sig_edit=lambda s, m: ML_DSA_65.sign(
           A.ml_sk, PREFIX + LABEL + b"\x00" + hashlib.sha512(m).digest(), deterministic=True) + s[3309:])[0])
refuse("iat_disagrees", "iat is not floor(asserted_at / 1000).", "invalid:time:iat",
       statement(A, "s", "scores", FAM, P1, claims_edit=lambda c: c.__setitem__(6, c[6] + 1))[0])
refuse("exp_missing", "valid_until present, exp absent.", "invalid:time:exp",
       statement(A, "s", "scores", FAM, P2, claims_edit=lambda c: c.__delitem__(4))[0])
refuse("cty_with_parameters", "cty carries parameters.", "invalid:malformed:cty",
       statement(A, "s", "scores", FAM, P1, prot_edit=lambda p: p.__setitem__(3, "application/vnd.ciris.row+cbor;type=scores"))[0])
refuse("extra_protected_member", "The protected header carries crit.", "invalid:unexpected:protected",
       statement(A, "s", "scores", FAM, P1, prot_edit=lambda p: p.__setitem__(2, [1]))[0])
refuse("no_family", "-70002 absent.", "invalid:unexpected:protected",
       statement(A, "s", "scores", FAM, P1, prot_edit=lambda p: p.__delitem__(-70002))[0])
refuse("unknown_row_type", "A row type outside the five.", "invalid:malformed:row-type",
       statement(A, "s", "endorses", FAM, P1)[0], keys=())
refuse("family_leaf_uppercase", "A family id with an upper-case letter.", "invalid:malformed:family-id",
       statement(A, "s", "scores", "Evidence", P1)[0])
refuse("edition_1", "edition claim 1.", "invalid:malformed:edition",
       statement(A, "s", "scores", FAM, P1, claims_edit=lambda c: c.__setitem__(-70003, 1))[0])
refuse("iss_bad_last_char", "iss whose 43rd character carries trailing bits.", "invalid:malformed:iss",
       statement(A, "s", "scores", FAM, P1, claims_edit=lambda c: c.__setitem__(1, c[1][:-1] + "B"))[0])
refuse("refs_unsorted_set", "further_heads out of order.", "invalid:set_order:further_heads",
       statement(A, "s", "scores", FAM, edit(P2, "refs", {"further_heads": [rref(3), rref(2)]}))[0])
refuse("refs_empty", "An empty refs map.", "invalid:malformed:refs",
       statement(A, "s", "scores", FAM, edit(P1, "refs", {}))[0])
refuse("also_unknown_role", "An also role outside {ack, cites}.", "invalid:unexpected:also",
       statement(A, "s", "scores", FAM, edit(P1, "refs", {"also": {"quotes": [rref(1)]}}))[0])
refuse("null_member", "A null member.", "invalid:malformed:ceg-value",
       statement(A, "s", "scores", FAM, edit(P1, "x", None))[0])
refuse("score_out_of_range", "score above 10^6.", "invalid:malformed:score",
       statement(A, "s", "scores", FAM, edit(P1, "score", 1000001))[0])
_c = {1: A.iss, 2: "s", 6: 0, -70003: 2}
_p = enc({1: -70100, 3: "application/vnd.ciris.row+cbor", 4: A.kid, 15: _c, 16: "ceg-row/2", -70001: "scores", -70002: FAM})
_pl = enc(drop(P1, "asserted_at"))
refuse("no_asserted_at", "asserted_at absent.", "invalid:malformed:asserted_at",
       enc(Tag(18, [_p, {}, _pl, A.sign(enc(["Signature1", _p, b"", _pl]))])))
# Non-deterministic encodings.
_good = bytes.fromhex(valid[0]["statement_hex"])
refuse("long_array_head", "The COSE_Sign1 array head in a two-byte form.", "invalid:not_deterministic:statement",
       _good[:1] + b"\x98\x04" + _good[2:])
refuse("untagged", "A COSE_Sign1 without tag 18.", "invalid:not_cose_sign1", _good[1:])
# Bytewise order puts the shorter "score" (0x65...) before "asserted_at" (0x6b...); here reversed.
_unsorted = b"\xa2" + enc("asserted_at") + enc(500) + enc("score") + enc(1)
refuse("payload_keys_unsorted", "The payload map's keys out of bytewise order.", "invalid:not_deterministic:payload",
       enc(Tag(18, [_p, {}, _unsorted, A.sign(enc(["Signature1", _p, b"", _unsorted]))])))
refuse("unprotected_text_label", "A text label in the unprotected header.", "invalid:unexpected:unprotected",
       statement(A, "s", "scores", FAM, P1, unprot={"note": 1})[0])
refuse("disclosure_short_salt", "An sd_claims disclosure with a 15-byte salt.", "invalid:malformed:sd-disclosure",
       statement(A, "s", "scores", FAM, P1, unprot={17: [enc([bytes(15), 1, "k"])]})[0])


# ---- More statement-level refusals (CC's list for the persist cut) ----
refuse("refs_duplicate", "further_heads repeats an element.", "invalid:set_order:further_heads",
       statement(A, "s", "scores", FAM, edit(P1, "refs", {"further_heads": [rref(2), rref(2)]}))[0])
refuse("refs_empty_set", "An empty further_heads set (a set is non-empty; absence is its one encoding).",
       "invalid:malformed:further_heads",
       statement(A, "s", "scores", FAM, edit(P1, "refs", {"further_heads": []}))[0])
refuse("row_ref_tuple_reversed", "A row-ref tuple with its members swapped: [id, edition].", "invalid:malformed:head",
       statement(A, "s", "scores", FAM, edit(P1, "refs", {"head": [hd(bytes([1]) * 32), 2]}))[0])
refuse("row_ref_other_hash", "A hash-digest under an algorithm other than -16.", "invalid:malformed:head",
       statement(A, "s", "scores", FAM, edit(P1, "refs", {"head": [2, [-44, bytes([1]) * 32]]}))[0])
refuse("confidence_negative", "confidence below 0.", "invalid:malformed:confidence",
       statement(A, "s", "scores", FAM, edit(P1, "confidence", -1))[0])
refuse("score_below_range", "score below -10^6.", "invalid:malformed:score",
       statement(A, "s", "scores", FAM, edit(P1, "score", -1000001))[0])
_f = b"\xa2" + enc("x") + b"\xf9\x3c\x00" + enc("asserted_at") + enc(1)   # x: 1.0 as a half float
refuse("float_member", "A CBOR float in the payload.", "invalid:not_deterministic:payload",
       enc(Tag(18, [_p, {}, _f, A.sign(enc(["Signature1", _p, b"", _f]))])))
refuse("no_row_type", "-70001 absent.", "invalid:unexpected:protected",
       statement(A, "s", "scores", FAM, P1, prot_edit=lambda p: p.__delitem__(-70001))[0])

# ---- Disclosures (SD-CWT -09) ----
def disclosure(salt, value, key=None):
    b = enc([bytes([salt]) * 16, value] + ([key] if key is not None else []))
    return b, hashlib.sha256(b).digest()
_nb, _nd = disclosure(1, "the note text", "note")
_eb, _ed = disclosure(2, 42)
P3 = {"asserted_at": 1763200001000, "author": A.iss, "body": {Simple(59): [_nd]}, "list": [Tag(60, _ed), 7]}
st3, pb3, plb3 = statement(A, "subject-3", "scores", FAM, P3, unprot={17: [_nb, _eb]})
valid.append({**VALID_LEVELS, "id": "disclosed",
              "description": "body.note and an array element blinded, both disclosed in sd_claims.", "key_seed": 1, "statement_hex": st3.hex(), "kid_hex": A.kid.hex(), "iss": A.iss,
              "row_id_hex": hashlib.sha256(enc(["CEG-row/2", "scores", FAM, "subject-3", A.iss, plb3])).digest().hex(),
              "statement_id_hex": hashlib.sha256(enc(["CEG-statement-id/2", pb3, plb3])).digest().hex(),
              "disclosed_digests_hex": sorted([_nd.hex(), _ed.hex()])})
_xb, _ = disclosure(3, "stray", "other")
refuse("disclosure_unmatched", "A disclosure whose digest the payload does not carry.", "invalid:disclosure_unmatched",
       statement(A, "s", "scores", FAM, P3, unprot={17: [_nb, _xb]})[0])
refuse("disclosure_twice", "The same disclosure presented twice.", "invalid:disclosure_unmatched",
       statement(A, "s", "scores", FAM, P3, unprot={17: [_nb, _nb]})[0])
_cb, _cd = disclosure(4, "x", "author")
refuse("disclosure_key_present", "A disclosure of a member its map already holds.", "invalid:disclosure_unmatched",
       statement(A, "s", "scores", FAM, edit(P3, Simple(59), [_cd]), unprot={17: [_cb]})[0])
refuse("digest_repeated", "One digest carried twice.", "invalid:duplicate_digest",
       statement(A, "s", "scores", FAM, edit(P3, "body", {Simple(59): [_nd, _nd]}))[0])

# ---- Rows naming the earlier form: refused (CC 2.6.1.3, 2.6.1.12; CDDL row-ref = [edition: 2, id]) ----
# v1's `names_earlier_form` statement, byte for byte: its refs name five earlier-form objects by
# [1, [-16, name]]. Under the clean mesh no row of this form names an earlier-form object, so it is
# refused at the first refs member the reader meets, `also` (CDE order puts "also" before "target").
def _ename(m): return hashlib.sha256(m).digest()
_inv_msg = (b"ciris.accord_invoke.v2\ninvocation_kind=constitutional\ninvocation_id=halt-2026-11-15\n"
            b"nonce=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\nasserted_at=2026-11-15T12:00:00.000Z\n"
            b"valid_until=2026-11-16T12:00:00.000Z\npayload_sha256=" + b"ab" * 32)
_conf_msg = (b"ciris.accord_lifecycle.v1\ninvocation_kind=lifecycle:confirmed\ninvocation_id=confirm-2026-11-15\n"
             b"confirms_halt_id=halt-2026-11-15\nnonce=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n"
             b"asserted_at=2026-11-15T12:00:00.000Z\nvalid_until=2026-11-16T12:00:00.000Z\npayload_sha256=" + b"ab" * 32)
def jcs(obj):  # ASCII strings and integers only, where RFC 8785 is sorted compact JSON
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
_reg = {"key_id": "node-1", "identity_type": "node", "pubkey_ed25519_base64": "A" * 43 + "=",
        "valid_from": "2026-11-15T00:00:00.000Z", "roles": [], "scrub_key_id": "node-1"}
_man = {"attestation_type": "scores", "dimension": "build:manifest:v1", "asserted_at": "2026-11-15T00:00:00.000Z",
        "facts": {"build": {"manifest_hash": "cd" * 32, "manifest_size": 4096}}, "evidence_refs": ["cd" * 32]}
_earlier_names = [_ename(_inv_msg), _ename(_conf_msg), _ename(jcs(_reg)), _ename(jcs(_man)), _ename(bytes(range(32)))]
_cites = sorted(([1, hd(n)] for n in _earlier_names), key=enc)
P4 = {"asserted_at": 1763200002000, "author": A.iss,
      "refs": {"target": [1, hd(_earlier_names[2])], "also": {"cites": _cites}}}
refuse("names_earlier_form", "v1's valid row naming five earlier-form objects by edition-1 row-refs (target the key "
       "record, cites all five), unchanged: no row of this form names the earlier form; refused at also.",
       "invalid:malformed:also", statement(A, "subject-4", "supersedes", FAM, P4)[0])
refuse("row_ref_edition_1", "A target row-ref of edition 1 naming an earlier-form key record (CDDL: the edition "
       "is the constant 2).", "invalid:malformed:target",
       statement(A, "subject-4", "supersedes", FAM, edit(P4, "refs", {"target": [1, hd(_earlier_names[2])]}))[0])

# ---- Key records: the end rule (CC 2.4.1.1), payload cases ----
T0 = 1763200000000
MAXMS = 31536000 * 1000
def krec(k, roles, until=None, t0=T0):
    p = {"key": {1: 7, 3: -70100, -1: k.pub}, "identity_type": sorted(roles, key=lambda r: enc(r)), "asserted_at": t0}
    if until is not None: p["valid_until"] = until
    return p
key_records = []
def kr(cid, desc, roles, until, expect, raw_roles=None):
    p = krec(B, roles, until)
    if raw_roles is not None: p["identity_type"] = raw_roles
    key_records.append({"id": cid, "description": desc, "payload_hex": enc(p).hex(), "expect": expect})
kr("node_at_bound", "node, valid_until exactly asserted_at + 365 days.", ["node"], T0 + MAXMS, "ok")
kr("node_one_ms_over", "node, one millisecond past the bound.", ["node"], T0 + MAXMS + 1, "key_record_out_of_window")
kr("node_one_second_over", "node, one second past the bound.", ["node"], T0 + MAXMS + 1000, "key_record_out_of_window")
kr("node_before_asserted", "valid_until before asserted_at.", ["node"], T0 - 1, "key_record_out_of_window")
kr("node_at_asserted", "valid_until equal to asserted_at.", ["node"], T0, "ok")
kr("agent_without_end", "agent with no valid_until (the private-room exception fails closed).", ["agent"], None, "key_record_out_of_window")
kr("user_without_end", "user with no valid_until.", ["user"], None, "ok")
kr("user_with_end", "user carrying valid_until.", ["user"], T0 + 1000, "key_record_out_of_window")
kr("accord_holder_with_end", "accord_holder carrying valid_until.", ["accord_holder"], T0 + 1000, "key_record_out_of_window")
kr("mixed_user_node", "A set mixing user and node.", ["node", "user"], T0 + 1000, "key_record_mixed_roles")
kr("pseudonym_with_end", "A pseudonym may carry valid_until.", ["pseudonym"], T0 + 1000, "ok")
kr("steward_no_end_rule", "A role outside both groups takes no end rule.", ["steward"], None, "ok")
kr("roles_unsorted", "identity_type not sorted.", ["node", "user"], None, "key_record_bad_identity_type",
   raw_roles=["user", "node"])
def kr_ev(cid, desc, ev, expect):
    p = krec(B, ["accord_holder"], None)
    p["attestation_evidence"] = ev
    key_records.append({"id": cid, "description": desc, "payload_hex": enc(p).hex(), "expect": expect})
kr_ev("pq_custody_removable_offline", "An accord holder's key: hardware_class names the Ed25519 half, pq_custody removable_offline (CC 4.2.2).",
      {"hardware_class": "YubiKey_5_FIPS", "pq_custody": "removable_offline"}, "ok")
kr_ev("pq_custody_missing", "hardware_class without pq_custody: carried (the consumer weighs it at 0.0), not refused.",
      {"hardware_class": "YubiKey_5_FIPS"}, "ok")
kr_ev("pq_custody_unknown", "pq_custody outside the three values.", {"hardware_class": "YubiKey_5_FIPS", "pq_custody": "tpm"},
      "key_record_bad_pq_custody")
kr_ev("attestation_evidence_not_map", "attestation_evidence that is not a map.", "YubiKey_5_FIPS", "key_record_bad_pq_custody")

# ---- Key directory: Waiting through records and on a half ----
def krow(signer, subject, roles, until):
    st, _, _ = statement(signer, subject.iss, "scores", "key:record", krec(subject, roles, until))
    return st.hex()
G = Key(9)   # never held
_s = {"asserted_at": T0 + 5, "author": B.iss}
key_directory = [
    {"id": "held_through_chain", "description": "B's record signed by A, A's self-signed: Valid.",
     "records_hex": [krow(A, A, ["user"], None), krow(A, B, ["node"], T0 + 1000)],
     "statement_hex": statement(B, "s", "scores", FAM, _s)[0].hex(), "expect": "valid"},
    {"id": "deep_waiting", "description": "B's record is signed by G, whom nobody holds: the statement waits on G, the deepest key.",
     "records_hex": [krow(G, B, ["node"], T0 + 1000)],
     "statement_hex": statement(B, "s", "scores", FAM, _s)[0].hex(), "expect": "waiting:kid:" + G.kid.hex()},
    {"id": "record_breaks_end_rule", "description": "B's record has no valid_until on a node: the key, and the statement, are Invalid.",
     "records_hex": [krow(A, A, ["user"], None), krow(A, B, ["node"], None)],
     "statement_hex": statement(B, "s", "scores", FAM, _s)[0].hex(), "expect": "invalid:key_not_valid"},
    {"id": "after_valid_until", "description": "A statement asserted after the held record's valid_until: no held "
     "record of B covers the instant, so it waits on one that does (CC 2.4.1.1: retryable).",
     "records_hex": [krow(A, A, ["user"], None), krow(A, B, ["node"], T0 + 1000)],
     "statement_hex": statement(B, "s", "scores", FAM, edit(_s, "asserted_at", T0 + 1001))[0].hex(),
     "expect": "waiting:covering_record:" + B.kid.hex() + ":" + str(T0 + 1001)},
]
for _c in key_directory:
    _c["level"] = "statement"

# ---- Family rules (caller-supplied model; CC's typed columns are pending) ----
family_model = {"conscience:coherence": {"authored": True, "roles": [["delegate", "delegate"], ["attested", "sub"]], "scores_dimension": False},
                "accord:lifecycle:.kind": {"authored": False, "roles": [], "scores_dimension": True}}
def fam(cid, desc, signer, sub, family, payload, expect, model="test"):
    return {"id": cid, "description": desc, "level": "family", "model": model,
            "statement_hex": statement(signer, sub, "scores", family, payload)[0].hex(),
            "held_key_seeds": [signer.ml_seed[0]], "expect": expect}
_ap = {"asserted_at": T0, "author": A.iss}
family = [
    fam("author_signs", "The author signs its own authored row.", A, "s", "conscience:coherence", _ap, "valid"),
    fam("authored_without_author", "An authored family whose payload has no author.", A, "s", "conscience:coherence", {"asserted_at": T0}, "family_invalid:author_column"),
    fam("counted_with_author", "A counted family whose payload names an author.", A, "s", "accord:lifecycle:.kind", edit(_ap, "dimension", "accord:lifecycle:confirmed:v1"), "family_invalid:author_column"),
    fam("other_signer_no_role", "A signer other than the author, in no role.", B, "s", "conscience:coherence", _ap, "family_invalid:iss_not_in_role"),
    fam("delegate_named", "A signer other than the author, named as the delegate.", B, "s", "conscience:coherence", edit(_ap, "delegate", B.iss), "valid:role:delegate"),
    fam("delegate_names_other", "The delegate member names someone else.", B, "s", "conscience:coherence", edit(_ap, "delegate", C.iss), "family_invalid:iss_not_in_role"),
    fam("attested_key", "The attested key (CWT sub) signs.", B, B.iss, "conscience:coherence", _ap, "valid:role:attested"),
    fam("unregistered_family", "-70002 names no family the CC registry registers (refused before any family model).", A, "s", "nobody:fam", _ap, "invalid:unregistered_family"),
    fam("dimension_missing", "A family that scores a dimension, without one.", A, "s", "accord:lifecycle:.kind", {"asserted_at": T0}, "family_invalid:dimension_missing"),
]

# ---- dimension -> family (CC 3.1.7, the one matcher) ----
refuse("dimension_other_family", "dimension resolves to evidence:.suite:.kind:.cell:.prefix; the header says conscience:coherence.",
       "invalid:dimension_family", statement(A, "s", "scores", "conscience:coherence", P1)[0])
refuse("dimension_less_specific_header", "accord:lifecycle:confirmed:v1 resolves to accord:lifecycle:.kind; a header of accord:. is refused.",
       "invalid:dimension_family",
       statement(A, "s", "scores", "accord:.", edit(P1, "dimension", "accord:lifecycle:confirmed:v1"))[0])
refuse("dimension_refused_by_matcher", "A closed vocab segment with an unregistered value.",
       "invalid:dimension_refused:namespace_vocab_value_unregistered",
       statement(A, "s", "scores", FAM, edit(P1, "dimension", "evidence:safety_battery:k:c:p:v1"))[0])
refuse("dimension_open_vocabulary", "A dimension no registered family claims.", "invalid:dimension_unregistered",
       statement(A, "s", "scores", FAM, edit(P1, "dimension", "x:v1"))[0])
refuse("family_unregistered", "-70002 well formed but not registered.", "invalid:unregistered_family",
       statement(A, "s", "scores", "nobody:fam", drop(P1, "dimension"))[0])

# ---- Non-row objects: header rules (payload rules come with the ceremony set) ----
def obj(k, typ, payload, prot_edit=None, iat=None):
    claims = {1: k.iss, -70003: 2}
    if iat is not None: claims[6] = iat
    prot = {1: -70100, 4: k.kid, 15: claims, 16: typ}
    if prot_edit: prot_edit(prot)
    pb, plb = enc(prot), enc(payload)
    return enc(Tag(18, [pb, {}, plb, k.sign(enc(["Signature1", pb, b"", plb]))])), pb, plb
_snap = {"author": A.iss, "refs": {"also": {"ack": [rref(7)]}}, "seq": 0, "revoked": []}
_ob, _opb, _oplb = obj(A, "ceg-revocation-snapshot/2", _snap)
objects = [
    {"id": "revocation_snapshot_header", "description": "A revocation snapshot's header: no cty, no -70001/-70002, no iat.",
     "statement_hex": _ob.hex(), "held_key_seeds": [1], "expect": "valid",
     "object_id_hex": hashlib.sha256(enc(["CEG-object/2", "ceg-revocation-snapshot/2", A.iss, _oplb])).digest().hex(),
     "statement_id_hex": hashlib.sha256(enc(["CEG-statement-id/2", _opb, _oplb])).digest().hex()},
    {"id": "object_with_row_type", "description": "-70001 on a non-row object.", "held_key_seeds": [1],
     "statement_hex": obj(A, "ceg-revocation-snapshot/2", _snap, lambda p: p.__setitem__(-70001, "scores"))[0].hex(),
     "expect": "invalid:unexpected:protected"},
    {"id": "object_with_family", "description": "-70002 on a non-row object.", "held_key_seeds": [1],
     "statement_hex": obj(A, "ceg-revocation-snapshot/2", _snap, lambda p: p.__setitem__(-70002, "key:record"))[0].hex(),
     "expect": "invalid:unexpected:protected"},
    {"id": "object_with_cty", "description": "cty on a non-row object.", "held_key_seeds": [1],
     "statement_hex": obj(A, "ceg-genesis-bundle/2", {"version": 1}, lambda p: p.__setitem__(3, "application/vnd.ciris.row+cbor"))[0].hex(),
     "expect": "invalid:unexpected:protected"},
    {"id": "object_unknown_typ", "description": "A typ outside the closed set.", "held_key_seeds": [1],
     "statement_hex": obj(A, "ceg-anything/2", {"version": 1})[0].hex(), "expect": "invalid:malformed:typ"},
    {"id": "row_typ_as_object", "description": "ceg-row/2 is not an object typ.", "held_key_seeds": [1],
     "statement_hex": obj(A, "ceg-row/2", {"version": 1})[0].hex(), "expect": "invalid:malformed:typ"},
]

# ---- References by form (CIRISKernel's Obj::from_reference) ----
_d = hashlib.sha256(b"a row").digest()
references = [
    {"id": "row_id", "cbor_hex": enc(hd(_d)).hex(), "form": "row", "digest_hex": _d.hex()},
    {"id": "row_id_of_vector", "cbor_hex": enc(hd(bytes.fromhex(valid[0]["row_id_hex"]))).hex(), "form": "row",
     "digest_hex": valid[0]["row_id_hex"]},
    {"id": "key_a", "cbor_hex": enc(A.iss).hex(), "form": "key", "identity_ref": A.iss},
    {"id": "key_b", "cbor_hex": enc(B.iss).hex(), "form": "key", "identity_ref": B.iss},
    {"id": "other_hash_alg", "cbor_hex": enc([-44, _d]).hex(), "form": "neither"},
    {"id": "short_digest", "cbor_hex": enc([-16, _d[:31]]).hex(), "form": "neither"},
    {"id": "row_ref_not_a_digest", "cbor_hex": enc([2, hd(_d)]).hex(), "form": "neither"},
    {"id": "identity_ref_42_chars", "cbor_hex": enc(A.iss[:-1]).hex(), "form": "neither"},
    {"id": "identity_ref_trailing_bits", "cbor_hex": enc(A.iss[:-1] + "B").hex(), "form": "neither"},
    {"id": "identity_ref_sha512", "cbor_hex": enc(A.iss.replace("sha-256", "sha-512")).hex(), "form": "neither"},
    {"id": "bare_hex", "cbor_hex": enc(_d.hex()).hex(), "form": "neither"},
]

# ---- Family rules under CC's vendored model (rc20 e08bf05 manifests/family_authorship.json) ----
# Selector cells are read by CC's one evaluator (tools/cc_family_select.py): the leaf is the row's
# dimension bound under its family; verb, identity, group, seats and act come from the case's `ctx`
# (absent: unknown). Each expectation below is what that evaluator answers for the cell, stated here.
def vfam(cid, desc, signer, sub, family, payload, expect, ctx=None):
    c = fam(cid, desc, signer, sub, family, payload, expect)
    if ctx is not None:
        c["ctx"] = ctx
    return c
_cp = {"asserted_at": T0}
family_vendored = [
    fam("v_delegate_is_sub", "self:delegates_to: the delegate (CWT sub) signs the author's payload.", B, B.iss,
        "self:delegates_to", _ap, "valid:role:delegate"),
    fam("v_delegate_not_sub", "self:delegates_to: a signer other than the author who is not the sub.", B, C.iss,
        "self:delegates_to", _ap, "family_invalid:iss_not_in_role"),
    fam("v_gap_role_not_admitted", "key:record's predecessor_key / anchor members are gap: no second signer is admitted.", B, "s",
        "key:record", _ap, "family_invalid:iss_not_in_role"),
    fam("v_author_signs", "key:record is authored; its author signs.", A, "s", "key:record", _ap, "valid"),
    fam("v_counted", "group:roster is counted: no author.", A, "s", "group:roster", {"asserted_at": T0}, "valid"),
    fam("v_counted_with_author", "group:roster with an author.", A, "s", "group:roster", _ap, "family_invalid:author_column"),
    fam("v_selector_undetermined", "accord:* arm 0 is leaf=lifecycle:{kind}; with no dimension the leaf is unknown, "
        "so the arm is unknown before the decider and the authorship is undetermined.", A, "s", "accord:.", _ap,
        "family_invalid:authorship_undetermined"),
    fam("v_gap_undetermined", "licensure:{authority_id} is a gap: the caller must decide.", A, "s", "licensure:.authority_id", _ap,
        "family_invalid:authorship_undetermined"),
    # the leaf decides
    vfam("v_leaf_counted", "membership:{stage}: leaf widening holds arm 0 (leaf=widening|removal): counted, no author.", A, "s",
         "membership:.stage", edit(_cp, "dimension", "membership:widening:v1"), "valid"),
    vfam("v_leaf_counted_with_author", "membership:widening is counted: an author is refused.", A, "s",
         "membership:.stage", edit(_ap, "dimension", "membership:widening:v1"), "family_invalid:author_column"),
    vfam("v_leaf_authored", "membership:{stage}: leaf proposal reads arm 0 false, so the `*` arm decides: authored.", A, "s",
         "membership:.stage", edit(_ap, "dimension", "membership:proposal:v1"), "valid"),
    vfam("v_leaf_authored_without_author", "membership:proposal is authored: a row with no author is refused.", A, "s",
         "membership:.stage", edit(_cp, "dimension", "membership:proposal:v1"), "family_invalid:author_column"),
    vfam("v_no_dimension_undetermined", "membership:{stage} with no dimension: arm 0 is unknown.", A, "s",
         "membership:.stage", _ap, "family_invalid:authorship_undetermined"),
    vfam("v_accord_lifecycle_counted", "accord:lifecycle:{kind} (the family accord:lifecycle:confirmed:v1 resolves to; "
         "under accord:* the same dimension binds leaf lifecycle:confirmed and arm 0 holds): counted.", A, "s",
         "accord:lifecycle:.kind", edit(_cp, "dimension", "accord:lifecycle:confirmed:v1"), "valid"),
    # a caller-supplied key decides
    vfam("v_act_group_counted", "collection:{kind} with act=group: arm 0 holds, counted.", A, "s",
         "collection:.kind", edit(_cp, "dimension", "collection:sample:v1"), "valid", {"act": "group"}),
    vfam("v_act_own_authored", "collection:{kind} with act=own: arm 0 is false, authored.", A, "s",
         "collection:.kind", edit(_ap, "dimension", "collection:sample:v1"), "valid", {"act": "own"}),
    vfam("v_act_own_counted_refused", "collection:{kind} with act=own is authored: a row with no author is refused.", A, "s",
         "collection:.kind", edit(_cp, "dimension", "collection:sample:v1"), "family_invalid:author_column", {"act": "own"}),
    vfam("v_act_unsupplied", "collection:{kind} with act not supplied: arm 0 is unknown.", A, "s",
         "collection:.kind", edit(_ap, "dimension", "collection:sample:v1"), "family_invalid:authorship_undetermined"),
    vfam("v_identity_user_counted", "identity:occurrence_revocation with identity {user}: counted.", A, "s",
         "identity:occurrence_revocation", edit(_cp, "dimension", "identity:occurrence_revocation:v1"), "valid",
         {"identity": ["user"]}),
    vfam("v_identity_node_authored", "identity:occurrence_revocation with identity {node}: arm 0 false, authored.", A, "s",
         "identity:occurrence_revocation", edit(_ap, "dimension", "identity:occurrence_revocation:v1"), "valid",
         {"identity": ["node"]}),
    vfam("v_group_seats_counted", "quarantine:{state} with group=affiliations and seats=1: counted.", A, "s",
         "quarantine:.state", _cp, "valid", {"group": "affiliations", "seats": 1}),
    vfam("v_false_beats_unknown", "quarantine:{state} with group=family and seats not supplied: group reads false, so arm 0 is "
         "false whatever seats reads, and the `*` arm decides: authored.", A, "s",
         "quarantine:.state", _ap, "valid", {"group": "family"}),
    # when-conditioned second signers
    vfam("v_when_role_admitted", "trust:{job}:{version}, leaf confers, act=own: the delegate (CWT sub) role's when holds.", B, B.iss,
         "trust:.job:.version", edit(_ap, "dimension", "trust:confers:v1"), "valid:role:delegate", {"act": "own"}),
    vfam("v_when_role_not_holding", "trust:{job}:{version}, leaf accepts: the delegate role's when is false.", B, B.iss,
         "trust:.job:.version", edit(_ap, "dimension", "trust:accepts:v1"), "family_invalid:iss_not_in_role", {"act": "own"}),
    vfam("v_when_role_unknown", "trust:{job}:{version} with no dimension and act=own: authored, but the roles' when is unknown, "
         "so no second signer is admitted.", B, B.iss,
         "trust:.job:.version", _ap, "family_invalid:iss_not_in_role", {"act": "own"}),
    vfam("v_when_gap_member", "retirement:{state}, leaf retired: the custodian role's when holds but its member is gap.", B, B.iss,
         "retirement:.state", edit(_ap, "dimension", "retirement:retired:v1"), "family_invalid:iss_not_in_role"),
    vfam("v_owner_of_sub_not_a_member", "self:delegates_to's delegate_owner role is by owner_of_sub, the owner the owner-binding "
         "of sub names; a payload member of that name does not admit the signer.", B, C.iss,
         "self:delegates_to", edit(_ap, "owner_of_sub", B.iss), "family_invalid:iss_not_in_role"),
]
for _c in family_vendored:
    _c["model"] = "vendored"
for _c in objects:
    _c["level"] = "object"
for _c in key_records:
    _c["level"] = "payload"
for _c in references:
    _c["level"] = "value"
assert len({r["id"] for r in refusals}) == len(refusals)
out = {
    "$schema_note": (
        "CC 2.6.1 (CIRISConstitution rc20 0c9e17c, the clean mesh; manifests/signed_object_v2.cddl) edition-2 row "
        "statement known answers, v2 (CIRISVerify#326). Keys: ML-DSA-65 seed = [n]*32, Ed25519 seed = [n+100]*32 for "
        "key_seed n. Signatures are deterministic (FIPS 204 deterministic variant; Ed25519). Generated "
        "independently of the Rust code by its own CBOR encoder over dilithium-py and pyca/cryptography; "
        "see README.md beside this file. Every case states its level: statement (verify_row_statement, no family "
        "model; key_directory through a key-record directory), family (verify_row_in_family under the named model: "
        "test or vendored), object (verify_object_statement), payload (check_key_record) or value "
        "(classify_reference). Every valid case is also valid at the family level under the vendored model "
        "(family_vendored_expect). expect: valid, waiting:kid:<kid>, waiting:covering_record:<kid>:<at_ms>, or "
        "invalid:<reason>[:<member>]. family_model is a stated test model. family_vendored is read under CC's family_authorship.json (rc20 e08bf05) by CC's selector "
        "evaluator (tools/cc_family_select.py): the leaf from the row's dimension, and verb, identity, group, seats and "
        "act from the case's optional ctx (absent: unknown)."),
    "valid": valid,
    "refusals": refusals,
    "key_records": key_records,
    "key_directory": key_directory,
    "family_model": family_model,
    "family": family,
    "objects": objects,
    "references": references,
    "family_vendored": family_vendored,
}
json.dump(out, sys.stdout, indent=2, sort_keys=True)
print()
