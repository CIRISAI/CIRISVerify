# Independent known answers for the wire of a private room (CC 2.6.1.11, CC 3.1.3.2, CC 3.3.6.1, CC 3.3.6.4, CC 5.1;
# CIRISConstitution v1.0-rc22 f467193):
#
#   seat commitment   SHA-256(CDE(["CEG-seat/2", room, room_key, person, nonce]))
#   binding key name  SHA-256(CDE(["CEG-binding-key/2", room_binding_xwing_pubkey]))   (the verifier's encoding,
#                     CC 2.6.1.12 open encodings)
#   binding           challenge = X-Wing Encaps to the person's binding key (ct_c, 1120 bytes); confirmation = RFC 9180
#                     HPKE mode_psk (KEM X-Wing 0x647a, HKDF-SHA256 0x0001, AES-256-GCM 0x0002) to the addressee's room
#                     key's kem_xwing_pubkey, psk = the challenge's shared secret, psk_id = SHA-256(ct_c), info =
#                     CDE(["CEG-binding/2", room, room_key, addressee_key, [-16, seat_commitment], binding key name]),
#                     aad empty, pt = CDE([person, nonce]). The addressee checks person and the seat commitment.
#   room-sealed       the closed map {dek?, claim?, challenge?, confirmation?}; a wrap to a room key and a sealed
#                     envelope are HPKE mode_base seals of it under info "CEG-room-wrap/2", enc ‖ ct; an invitation is
#                     sealed the same way under "CEG-invitation/2".
#   MLS group ids     SHA-256(CDE(["CEG-mls-group/2", room])), SHA-256(CDE(["CEG-mls-call-group/2", room, call]))
#   rows              refs.also.voice (a set of exactly one); the mls:leaf_vouch row and its door; the window:{state}
#                     rows; the room-key members of a key record; an occurrence's room_binding_xwing_pubkey.
#
# X-Wing is draft-connolly-cfrg-xwing-kem (over kyber_py's ML-KEM-768 and X25519); HPKE is written out here from RFC
# 9180 and checked against verify's vendored mode_base vector before anything is generated. Reuses
# gen_row_statements_v5.py's CBOR encoder and composite signer (loaded with its output discarded). Shares no code
# with verify.
# It writes private_room_v1.json (the derived values, the binding, the sealed plaintexts) and
# private_room_rows_v1.json (the rows, the leaf's door, key records, occurrences), each under the repository's
# 1000 KB limit.
#   python3 -I gen_private_room_v1.py
import base64, contextlib, hashlib, hmac, io, json, os, runpy, sys, tempfile

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from kyber_py.ml_kem import ML_KEM_768

here = os.path.dirname(os.path.abspath(__file__))
e2 = os.path.dirname(here)
cwd = os.getcwd()
with tempfile.TemporaryDirectory() as scratch, contextlib.redirect_stdout(io.StringIO()):
    os.chdir(scratch)
    g = runpy.run_path(os.path.join(e2, "gen_row_statements_v5.py"))
    os.chdir(cwd)
Key, statement, enc, Tag, T0 = g["Key"], g["statement"], g["enc"], g["Tag"], g["T0"]
sha = lambda b: hashlib.sha256(b).digest()

# ---------------------------------------------------------------- X-Wing
XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")
def x25519(k, u): return X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(u))
def x25519_base(k):
    return X25519PrivateKey.from_private_bytes(k).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def xw_expand(sk):
    e = hashlib.shake_256(sk).digest(96)
    pk_m, sk_m = ML_KEM_768._keygen_internal(e[0:32], e[32:64])
    return sk_m, e[64:96], pk_m, x25519_base(e[64:96])
def xw_comb(ss_m, ss_x, ct_x, pk_x): return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()
def xw_pk(sk):
    _, _, pk_m, pk_x = xw_expand(sk)
    return pk_m + pk_x
def xw_encaps(pk, eseed):
    assert len(pk) == 1216 and len(eseed) == 64
    pk_m, pk_x = pk[:1184], pk[1184:]
    ct_x = x25519_base(eseed[32:])
    ss_m, ct_m = ML_KEM_768._encaps_internal(pk_m, eseed[:32])
    return ct_m + ct_x, xw_comb(ss_m, x25519(eseed[32:], pk_x), ct_x, pk_x)
def xw_decaps(sk, ct):
    sk_m, sk_x, _, pk_x = xw_expand(sk)
    return xw_comb(ML_KEM_768._decaps_internal(sk_m, ct[:1088]), x25519(sk_x, ct[1088:]), ct[1088:], pk_x)

# ---------------------------------------------------------------- HPKE (RFC 9180), suite 0x647a / 0x0001 / 0x0002
SUITE = b"HPKE" + bytes.fromhex("647a00010002")
def hk_extract(salt, ikm): return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
def hk_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:n]
def lextract(salt, label, ikm): return hk_extract(salt, b"HPKE-v1" + SUITE + label + ikm)
def lexpand(prk, label, info, n): return hk_expand(prk, n.to_bytes(2, "big") + b"HPKE-v1" + SUITE + label + info, n)
def key_schedule(mode, ss, info, psk=b"", psk_id=b""):
    ctx = bytes([mode]) + lextract(b"", b"psk_id_hash", psk_id) + lextract(b"", b"info_hash", info)
    secret = lextract(ss, b"secret", psk)
    return lexpand(secret, b"key", ctx, 32), lexpand(secret, b"base_nonce", ctx, 12)
def hpke_seal(mode, pk, eseed, info, aad, pt, psk=b"", psk_id=b""):
    enc_, ss = xw_encaps(pk, eseed)
    key, nonce = key_schedule(mode, ss, info, psk, psk_id)
    return enc_, AESGCM(key).encrypt(nonce, pt, aad)
BASE, PSK = 0, 1

with open(os.path.join(e2, "..", "..", "..", "..", "ciris-crypto", "tests", "vectors", "xwing",
                       "hpke_xwing_aes256gcm.json")) as f:
    for v in json.load(f):
        h = lambda k: bytes.fromhex(v[k])
        assert xw_pk(h("skRm")) == h("pkRm")
        e_, c_ = hpke_seal(BASE, h("pkRm"), h("ikmE"), h("info"), h("aad"), h("pt"))
        assert e_ == h("enc") and c_ == h("ct"), "HPKE self-check against the vendored mode_base vector"

# ---------------------------------------------------------------- values
def gref(tag): return "group-" + base64.urlsafe_b64encode(sha(b"room " + tag)).rstrip(b"=").decode()
ROOM, ROOM2 = gref(b"one"), gref(b"two")
R, RA, RB = Key(21), Key(22), Key(23)          # room keys: M's (the one bound), A's, B's
PERSON, PERSON2, VOICE = Key(24), Key(25), Key(26)
NONCE = bytes(range(32))

def seat_input(room, room_key, person, nonce): return enc(["CEG-seat/2", room, room_key, person, nonce])
def seat(room, room_key, person, nonce): return sha(seat_input(room, room_key, person, nonce))
def bk_name(pk): return sha(enc(["CEG-binding-key/2", pk]))
def binding_info(room, room_key, addressee_key, commitment, binding_pk):
    return enc(["CEG-binding/2", room, room_key, addressee_key, [-16, commitment], bk_name(binding_pk)])

out = {}
out["seat_commitment"] = [
    {"id": i, "room": room, "room_key_hex": rk.hex(), "person": person, "nonce_hex": nonce.hex(),
     "input_hex": seat_input(room, rk, person, nonce).hex(), "commitment_hex": seat(room, rk, person, nonce).hex()}
    for i, room, rk, person, nonce in (
        ("base", ROOM, R.kid, PERSON.iss, NONCE),
        ("other_room", ROOM2, R.kid, PERSON.iss, NONCE),
        ("other_room_key", ROOM, RA.kid, PERSON.iss, NONCE),
        ("other_person", ROOM, R.kid, PERSON2.iss, NONCE),
        ("other_nonce", ROOM, R.kid, PERSON.iss, bytes([255]) * 32))]

BIND_SK, BIND2_SK = bytes([31]) * 32, bytes([32]) * 32      # the person's binding key; another's
KEM_A_SK, KEM_B_SK = bytes([33]) * 32, bytes([34]) * 32     # the KEM half of A's and B's room keys
BIND_PK, BIND2_PK, KEM_A, KEM_B = xw_pk(BIND_SK), xw_pk(BIND2_SK), xw_pk(KEM_A_SK), xw_pk(KEM_B_SK)
out["binding_key_name"] = [{"id": i, "key_hex": k.hex(), "name_hex": bk_name(k).hex()}
                           for i, k in (("person", BIND_PK), ("other", BIND2_PK))]
out["mls_group_id"] = [{"room": r, "id_hex": sha(enc(["CEG-mls-group/2", r])).hex()} for r in (ROOM, ROOM2)]
out["mls_call_group_id"] = [{"room": r, "call_hex": c.hex(), "id_hex": sha(enc(["CEG-mls-call-group/2", r, c])).hex()}
                            for r, c in ((ROOM, bytes(range(16))), (ROOM, b""), (ROOM2, bytes(range(16))))]

# ---------------------------------------------------------------- the binding
COMMIT = seat(ROOM, R.kid, PERSON.iss, NONCE)
def exchange(xid, addressee, kem_sk, ch_seed, cf_seed):
    kem = xw_pk(kem_sk)
    ct_c, ss = xw_encaps(BIND_PK, ch_seed)
    assert xw_decaps(BIND_SK, ct_c) == ss
    info = binding_info(ROOM, R.kid, addressee.kid, COMMIT, BIND_PK)
    pt = enc([PERSON.iss, NONCE])
    enc_, ct = hpke_seal(PSK, kem, cf_seed, info, b"", pt, ss, sha(ct_c))
    return {"id": xid, "room": ROOM, "room_key_hex": R.kid.hex(), "addressee_key_hex": addressee.kid.hex(),
            "seat_commitment_hex": COMMIT.hex(), "person": PERSON.iss, "nonce_hex": NONCE.hex(),
            "binding_secret_seed_hex": BIND_SK.hex(), "binding_key_hex": BIND_PK.hex(),
            "addressee_kem_seed_hex": kem_sk.hex(), "addressee_kem_key_hex": kem.hex(),
            "challenge_eseed_hex": ch_seed.hex(), "challenge_hex": ct_c.hex(), "challenge_secret_hex": ss.hex(),
            "psk_id_hex": sha(ct_c).hex(), "info_hex": info.hex(), "opening_hex": pt.hex(),
            "confirmation_eseed_hex": cf_seed.hex(), "confirmation": {"enc_hex": enc_.hex(), "ct_hex": ct.hex()}}
X0 = exchange("to_A", RA, KEM_A_SK, bytes([41]) * 64, bytes([42]) * 64)
X1 = exchange("to_B", RB, KEM_B_SK, bytes([43]) * 64, bytes([44]) * 64)   # a fresh challenge for each room key
out["binding"] = [X0, X1]

def open_case(cid, desc, expect, **edit):
    c = {"room": ROOM, "room_key_hex": X0["room_key_hex"], "addressee_key_hex": X0["addressee_key_hex"],
         "seat_commitment_hex": X0["seat_commitment_hex"], "binding_key_hex": X0["binding_key_hex"],
         "confirmation": dict(X0["confirmation"]), "challenge_hex": X0["challenge_hex"],
         "challenge_secret_hex": X0["challenge_secret_hex"], "addressee_kem_seed_hex": X0["addressee_kem_seed_hex"],
         "person_challenged": PERSON.iss}
    c.update(edit)
    return dict({"id": cid, "description": desc, "expect": expect}, **c)
def flip(hexs, i=-1):
    b = bytearray(bytes.fromhex(hexs)); b[i] ^= 1
    return bytes(b).hex()
def sealed_with(pt, info=None, mode=PSK, seed=bytes([45]) * 64):
    info = X0_INFO if info is None else info
    ss, ct_c = bytes.fromhex(X0["challenge_secret_hex"]), bytes.fromhex(X0["challenge_hex"])
    e_, c_ = hpke_seal(mode, KEM_A, seed, info, b"", pt, *((ss, sha(ct_c)) if mode == PSK else ()))
    return {"enc_hex": e_.hex(), "ct_hex": c_.hex()}
X0_INFO = bytes.fromhex(X0["info_hex"])
NONCE2 = bytes([9]) * 32
other_ct, other_ss = xw_encaps(BIND_PK, bytes([46]) * 64)
out["binding_open"] = [
    open_case("opens", "The addressee opens the confirmation it challenged for.", "ok"),
    open_case("other_person_challenged", "A challenged for another person than the opening names.",
              "binding_other_person", person_challenged=PERSON2.iss),
    open_case("opening_other_nonce", "The confirmation seals a nonce that does not open the commitment on R's record.",
              "binding_seat_commitment_mismatch", confirmation=sealed_with(enc([PERSON.iss, NONCE2]))),
    open_case("opening_other_person_same_challenge", "The confirmation seals another person; A challenged for that "
              "person, and the commitment on R's record is not over it.", "binding_seat_commitment_mismatch",
              confirmation=sealed_with(enc([PERSON2.iss, NONCE])), person_challenged=PERSON2.iss),
    open_case("ct_tampered", "One bit of the ciphertext flipped.", "binding_open_failed",
              confirmation={"enc_hex": X0["confirmation"]["enc_hex"], "ct_hex": flip(X0["confirmation"]["ct_hex"])}),
    open_case("enc_tampered", "One bit of the encapsulation flipped.", "binding_open_failed",
              confirmation={"enc_hex": flip(X0["confirmation"]["enc_hex"]), "ct_hex": X0["confirmation"]["ct_hex"]}),
    open_case("enc_short", "An encapsulation of 1119 bytes.", "binding_open_failed",
              confirmation={"enc_hex": X0["confirmation"]["enc_hex"][2:], "ct_hex": X0["confirmation"]["ct_hex"]}),
    open_case("other_challenge", "A opens against another challenge it made (psk_id differs).", "binding_open_failed",
              challenge_hex=other_ct.hex()),
    open_case("other_challenge_secret", "A opens with another challenge's secret.", "binding_open_failed",
              challenge_secret_hex=other_ss.hex()),
    open_case("replayed_to_other_addressee", "The confirmation made for A, opened by B under B's key and context.",
              "binding_open_failed", addressee_key_hex=RB.kid.hex(), addressee_kem_seed_hex=KEM_B_SK.hex()),
    open_case("other_addressee_key_in_info", "A's own KEM key, the context naming B's room key.", "binding_open_failed",
              addressee_key_hex=RB.kid.hex()),
    open_case("other_room", "The context names another room.", "binding_open_failed", room=ROOM2),
    open_case("other_room_key", "The context names another room key.", "binding_open_failed",
              room_key_hex=RA.kid.hex()),
    open_case("other_seat_commitment", "The context carries another commitment than the one sealed under.",
              "binding_open_failed", seat_commitment_hex=seat(ROOM, R.kid, PERSON.iss, NONCE2).hex()),
    open_case("other_binding_key", "The context names another binding key.", "binding_open_failed",
              binding_key_hex=BIND2_PK.hex()),
    open_case("sealed_in_mode_base", "The same opening sealed in mode_base under the same info.",
              "binding_open_failed", confirmation=sealed_with(enc([PERSON.iss, NONCE]), mode=BASE)),
    open_case("plaintext_not_an_opening", "A mode_psk seal that opens, over bytes that are no [person, nonce].",
              "binding_open_failed", confirmation=sealed_with(enc([PERSON.iss]))),
    open_case("plaintext_nonce_31", "A seal that opens over a 31-byte nonce.", "binding_open_failed",
              confirmation=sealed_with(enc([PERSON.iss, NONCE[:31]]))),
    open_case("room_not_group_ref", "The context's room is no group reference.", "room_not_group_ref", room="room-1"),
    open_case("binding_key_1215", "The context's binding key is 1215 bytes.", "xwing_key_malformed",
              binding_key_hex=BIND_PK[:-1].hex()),
]

# ---------------------------------------------------------------- room-sealed, wraps, invitations
DEK = bytes([7]) * 32
OCC = [b"\xd2\x84statement one", b"\xd2\x84statement two"]
def rs(dek=None, claim=None, challenge=None, confirmation=None):
    m = {}
    if dek is not None: m["dek"] = dek
    if claim is not None: m["claim"] = claim
    if challenge is not None: m["challenge"] = challenge
    if confirmation is not None: m["confirmation"] = confirmation
    return m
CT_C = bytes.fromhex(X0["challenge_hex"])
CONF = {"enc": bytes.fromhex(X0["confirmation"]["enc_hex"]), "ct": bytes.fromhex(X0["confirmation"]["ct_hex"])}
def rs_json(m):
    j = {}
    if "dek" in m: j["dek_hex"] = m["dek"].hex()
    if "claim" in m:
        j["claim"] = {"person": m["claim"]["person"], "occurrence_hex": [o.hex() for o in m["claim"].get("occurrence", [])]}
    if "challenge" in m: j["challenge_hex"] = m["challenge"].hex()
    if "confirmation" in m: j["confirmation"] = {"enc_hex": m["confirmation"]["enc"].hex(), "ct_hex": m["confirmation"]["ct"].hex()}
    return j
SEALED = [("wrap_dek_only", rs(dek=DEK)),
          ("wrap_with_claim", rs(dek=DEK, claim={"person": PERSON.iss})),
          ("wrap_with_claim_and_occurrence", rs(dek=DEK, claim={"person": PERSON.iss, "occurrence": OCC})),
          ("wrap_with_challenge", rs(dek=DEK, challenge=CT_C)),
          ("wrap_with_confirmation", rs(dek=DEK, confirmation=CONF)),
          ("wrap_with_challenge_and_confirmation", rs(dek=DEK, challenge=CT_C, confirmation=CONF)),
          ("envelope_claim", rs(claim={"person": PERSON.iss})),
          ("envelope_all_flows", rs(claim={"person": PERSON.iss}, challenge=CT_C, confirmation=CONF)),
          ("empty", rs())]
out["room_sealed"] = [dict({"id": i, "plaintext_hex": enc(m).hex()}, **rs_json(m)) for i, m in SEALED]
assert enc(rs(dek=DEK, claim={"person": PERSON.iss})).startswith(bytes([0xa2]) + enc("dek"))   # dek sorts first
def raw_map(pairs):  # a map with its pairs in the order given (to cut a non-deterministic encoding)
    assert len(pairs) < 24
    return bytes([0xa0 + len(pairs)]) + b"".join(enc(k) + enc(v) for k, v in pairs)
out["room_sealed_refused"] = [{"id": i, "description": d, "plaintext_hex": b.hex()} for i, d, b in (
    ("unknown_member", "A member the form does not name.", enc(dict(rs(dek=DEK), seed=b"x"))),
    ("dek_31", "A dek of 31 bytes.", enc(rs(dek=DEK[:31]))),
    ("challenge_1119", "A challenge of 1119 bytes.", enc(rs(challenge=CT_C[:-1]))),
    ("claim_no_person", "A claim with no person.", enc(rs(claim={"occurrence": OCC}))),
    ("claim_person_not_identity_ref", "A claim whose person is no identity reference.", enc(rs(claim={"person": "p"}))),
    ("claim_occurrence_empty", "An empty occurrence: absence is its one encoding.",
     enc(rs(claim={"person": PERSON.iss, "occurrence": []}))),
    ("claim_unknown_member", "A claim with a member the form does not name.",
     enc(rs(claim={"person": PERSON.iss, "key": b"k"}))),
    ("confirmation_no_ct", "A confirmation with no ct.", enc(rs(confirmation={"enc": CONF["enc"]}))),
    ("confirmation_enc_1119", "A confirmation whose enc is 1119 bytes.",
     enc(rs(confirmation={"enc": CONF["enc"][:-1], "ct": CONF["ct"]}))),
    ("confirmation_unknown_member", "A confirmation with a third member.",
     enc(rs(confirmation=dict(CONF, mac=b"m")))),
    ("keys_out_of_order", "The map's members not in deterministic order.",
     raw_map([("claim", {"person": PERSON.iss}), ("dek", DEK)])),
    ("not_a_map", "An array.", enc([DEK])),
    ("trailing_byte", "A valid map followed by one byte.", enc(rs(dek=DEK)) + b"\x00"))]
def wrap(wid, m, info, seed, kem_sk=KEM_A_SK):
    pt = m if isinstance(m, bytes) else enc(m)
    e_, c_ = hpke_seal(BASE, xw_pk(kem_sk), seed, info.encode(), b"", pt)
    return {"id": wid, "kem_seed_hex": kem_sk.hex(), "kem_key_hex": xw_pk(kem_sk).hex(), "eseed_hex": seed.hex(),
            "info": info, "plaintext_hex": pt.hex(), "sealed_hex": (e_ + c_).hex()}
out["room_wrap"] = [dict(wrap(i, m, "CEG-room-wrap/2", bytes([50 + n]) * 64), **rs_json(m))
                    for n, (i, m) in enumerate(SEALED[:8])]
out["invitation"] = [wrap("invitation", b"an invitation's plaintext, the transport's to define", "CEG-invitation/2",
                          bytes([60]) * 64),
                     wrap("invitation_empty", b"", "CEG-invitation/2", bytes([61]) * 64, KEM_B_SK)]

# ---------------------------------------------------------------- rows
def rref(n): return [2, [-16, bytes([n]) * 32]]
cases = []
def case(cid, desc, family, payload, expect, rtype="scores", sub="s", signer=None, unprot=None):
    k = signer or PERSON
    cases.append({"id": cid, "description": desc, "row_type": rtype, "family": family,
                  "statement_hex": statement(k, sub, rtype, family, payload, unprot=unprot)[0].hex(),
                  "held_key_seeds": [k.ml_seed[0]], "expect": expect})
    return cases[-1]

FAM = "conscience:coherence"
base = {"asserted_at": T0, "author": PERSON.iss}
case("voice_one", "refs.also.voice naming one row.", FAM, dict(base, refs={"also": {"voice": [rref(1)]}}), "valid")
case("voice_beside_cites", "voice beside cites.", FAM,
     dict(base, refs={"also": {"cites": [rref(1), rref(2)], "voice": [rref(3)]}}), "valid")
case("voice_two", "voice naming two rows: a set of exactly one.", FAM,
     dict(base, refs={"also": {"voice": [rref(1), rref(2)]}}), "invalid:malformed:voice")
case("voice_empty", "An empty voice set.", FAM, dict(base, refs={"also": {"voice": []}}), "invalid:malformed:also")
case("voice_not_a_set", "voice a bare row-ref.", FAM, dict(base, refs={"also": {"voice": rref(1)}}),
     "invalid:malformed:also")
case("voice_at_refs_top", "voice as a member of refs: it is a role of also.", FAM,
     dict(base, refs={"voice": [rref(1)]}), "invalid:unexpected_member:refs")

# ---- mls:leaf_vouch (CC 5.1) ----
LV = "mls:leaf_vouch"
DAY = 86_400_000
LEAF, LEAF2 = bytes([71]) * 32, bytes([72]) * 32
def disc(salt, value):
    b = enc([bytes([salt]) * 16, value])
    return b, sha(b)
D_ROOM, H_ROOM = disc(1, [LEAF, ROOM, 77])
D_ROOM2, H_ROOM2 = disc(2, [LEAF, ROOM2, 77])
PAD = [sha(b"pad %d" % i) for i in range(32)]
def leaves(n, real=(H_ROOM, H_ROOM2)):
    hs = (list(real) + PAD)[:n]
    return [Tag(60, h) for h in hs]
def vouch(n=8, member=PERSON, **edit):
    p = {"author": member.iss, "dimension": "mls:leaf_vouch:v1", "suite": 77, "leaves": leaves(n),
         "valid_from": T0, "valid_until": T0 + 30 * DAY, "asserted_at": T0}
    for k, v in edit.items():
        if v is None: p.pop(k, None)
        else: p[k] = v
    return p
def vcase(cid, desc, expect, signer=PERSON, sub=None, **kw):
    case(cid, desc, LV, vouch(member=signer, **kw), expect, sub=sub or signer.iss, signer=signer)
vcase("vouch_8", "Eight blinded elements, a term of exactly 30 days.", "valid")
vcase("vouch_1", "One element.", "valid", n=1)
vcase("vouch_32", "Thirty-two elements.", "valid", n=32)
vcase("vouch_short_term", "A term of one day.", "valid", valid_until=T0 + DAY)
for n in (0, 2, 7, 9, 31, 33):
    vcase("vouch_%d" % n, "%d elements: the length is exactly 1, 8 or 32." % n,
          "invalid:leaf_vouch_presentation_invalid", n=n)
vcase("vouch_leaves_absent", "No leaves member.", "invalid:leaf_vouch_presentation_invalid", leaves=None)
vcase("vouch_leaf_in_clear", "An element that is an entry in the clear, not a blinded element.",
      "invalid:malformed:leaves", leaves=[[LEAF, ROOM, 77]])
vcase("vouch_suite_76", "suite is not 0x004D.", "invalid:malformed:suite", suite=76)
vcase("vouch_suite_absent", "No suite.", "invalid:malformed:suite", suite=None)
vcase("vouch_no_valid_until", "No valid_until: it is required.", "invalid:malformed:valid_until", valid_until=None)
vcase("vouch_no_valid_from", "No valid_from.", "invalid:malformed:valid_from", valid_from=None)
vcase("vouch_term_over_30_days", "valid_until one millisecond past 30 days after valid_from.",
      "invalid:malformed:valid_until", valid_until=T0 + 30 * DAY + 1)
vcase("vouch_end_before_start", "valid_until earlier than valid_from (both after asserted_at).",
      "invalid:malformed:valid_until", valid_from=T0 + 2 * DAY, valid_until=T0 + DAY)
vcase("vouch_sub_not_author", "The CWT sub is another identity than the author.", "invalid:malformed:author",
      sub=PERSON2.iss)
vcase("vouch_room_key", "A room key's vouch: iss the voice, one element, the head of its voice roster under "
      "also.voice.", "valid", signer=VOICE, n=1, refs={"also": {"voice": [rref(1)]}})
vcase("vouch_room_key_8", "A row naming a voice roster with eight elements: a room key signs a row of one entry.",
      "invalid:malformed:leaves", signer=VOICE, refs={"also": {"voice": [rref(1)]}})
vcase("vouch_names_head", "The vouch names a head: it names no row but a voice roster's head.",
      "invalid:malformed:refs", n=1, refs={"head": rref(1)})
vcase("vouch_voice_and_cites", "also.voice beside also.cites.", "invalid:malformed:refs", n=1,
      refs={"also": {"cites": [rref(2)], "voice": [rref(1)]}})

# ---- window:{state} (CC 3.3.6.4) ----
WF = "window:.state"
def win(state, refs, **edit):
    p = {"author": PERSON.iss, "dimension": "window:%s:v1" % state, "refs": refs, "asserted_at": T0}
    p.update(edit)
    return p
def wcase(cid, desc, state, refs, expect, **edit):
    case(cid, desc, WF, win(state, refs, **edit) if refs is not None else
         {k: v for k, v in win(state, {}, **edit).items() if k != "refs"}, expect)
wcase("held", "A held row: the opener under target.", "held", {"target": rref(1)}, "valid")
wcase("held_names_other_rows", "A held row MAY name other rows.", "held",
      {"target": rref(1), "also": {"cites": [rref(2)]}}, "valid")
wcase("held_with_prev", "A held row names no row under prev.", "held", {"target": rref(1), "prev": rref(2)},
      "invalid:malformed:refs")
wcase("held_with_head", "A held row names no head.", "held", {"target": rref(1), "head": rref(2)},
      "invalid:malformed:refs")
wcase("held_no_target", "A held row that names no opener.", "held", {"also": {"cites": [rref(2)]}},
      "invalid:malformed:refs")
wcase("held_no_refs", "A held row with no refs.", "held", None, "invalid:malformed:refs")
wcase("held_with_score", "A window row carries no score.", "held", {"target": rref(1)}, "invalid:malformed:score",
      score=1000000)
wcase("landed", "A landing: the opener, its signer's held row under prev, what it counted under cites.", "landed",
      {"target": rref(1), "prev": rref(2), "also": {"cites": [rref(3), rref(4)]}}, "valid")
wcase("landed_counted_none", "A landing that counted no row.", "landed", {"target": rref(1), "prev": rref(2)}, "valid")
wcase("refused", "A landing that refuses.", "refused", {"target": rref(1), "prev": rref(2)}, "valid")
wcase("landed_no_prev", "A landing that names no held row.", "landed", {"target": rref(1)}, "invalid:malformed:refs")
wcase("landed_with_head", "A landing names no head.", "landed",
      {"target": rref(1), "prev": rref(2), "head": rref(3)}, "invalid:malformed:refs")
wcase("landed_with_ack", "A landing with a role beside cites.", "landed",
      {"target": rref(1), "prev": rref(2), "also": {"ack": [rref(3)]}}, "invalid:malformed:refs")
wcase("landed_with_further_prev", "A landing names exactly one row under prev.", "landed",
      {"target": rref(1), "prev": rref(2), "further_prev": [rref(3)]}, "invalid:malformed:refs")
wcase("landed_no_target", "A landing that names no opener.", "landed", {"prev": rref(2)}, "invalid:malformed:refs")
out["row_statements"] = cases

# ---- the leaf's door (CC 5.1) ----
D_BAD_SUITE, H_BAD_SUITE = disc(3, [LEAF, ROOM, 76])
D_TWO_MEMBERS, H_TWO = disc(4, [LEAF, ROOM])
door = []
def dcase(cid, desc, expect, st=None, absent=False, **kw):
    d = {"room": ROOM, "leaf_key_hex": LEAF.hex(), "member": PERSON.iss, "now_ms": T0 + DAY, "withdrawn": False}
    d.update(kw)
    door.append(dict({"id": cid, "description": desc, "statement_hex": None if absent else st.hex(),
                      "held_key_seeds": [PERSON.ml_seed[0], VOICE.ml_seed[0]], "expect": expect}, **d))
def vst(discs, signer=PERSON, **kw):
    return statement(signer, signer.iss, "scores", LV, vouch(member=signer, **kw),
                     unprot={17: list(discs)} if discs else None)[0]
ONE = vst([D_ROOM])
dcase("door_ok", "The row with the room's entry disclosed.", "ok", ONE)
dcase("door_absent", "No vouching row.", "leaf_vouch_absent", absent=True)
dcase("door_other_family", "A row of another family presented as the vouch.", "leaf_vouch_absent",
      statement(PERSON, "s", "scores", FAM, dict(base))[0])
dcase("door_none_disclosed", "The row presented with no entry disclosed.", "leaf_vouch_presentation_invalid", vst([]))
dcase("door_two_disclosed", "The row presented with two entries disclosed.", "leaf_vouch_presentation_invalid",
      vst([D_ROOM, D_ROOM2]))
dcase("door_entry_suite_76", "The disclosed entry's suite is not 0x004D.", "leaf_vouch_presentation_invalid",
      vst([D_BAD_SUITE], leaves=[Tag(60, H_BAD_SUITE)]))
dcase("door_entry_two_members", "The disclosed entry is not [leaf_key, room, suite].",
      "leaf_vouch_presentation_invalid", vst([D_TWO_MEMBERS], leaves=[Tag(60, H_TWO)]))
dcase("door_at_valid_from", "now is valid_from: covered.", "ok", ONE, now_ms=T0)
dcase("door_before_valid_from", "now is before valid_from: no vouch is in force for the leaf at that instant, and "
      "it has not ended (CIRISConstitution's reading of a text with five names, 2026-11-25).", "leaf_vouch_absent",
      vst([D_ROOM], valid_from=T0 + DAY, valid_until=T0 + 2 * DAY), now_ms=T0 + DAY - 1)
dcase("door_last_instant", "now is one millisecond before valid_until.", "ok", ONE, now_ms=T0 + 30 * DAY - 1)
dcase("door_at_valid_until", "now is valid_until: the term is [valid_from, valid_until).", "leaf_vouch_ended", ONE,
      now_ms=T0 + 30 * DAY)
dcase("door_withdrawn", "The signer withdrew the vouch.", "leaf_vouch_ended", ONE, withdrawn=True)
dcase("door_other_room", "The entry is for another room than the door's.", "leaf_vouch_other_room", vst([D_ROOM2]))
dcase("door_other_leaf", "The LeafNode's key is another than the entry's.", "leaf_vouch_other_leaf", ONE,
      leaf_key_hex=LEAF2.hex())
dcase("door_not_by_member", "The row is by another member than the leaf's.", "leaf_vouch_not_by_member", ONE,
      member=PERSON2.iss)
dcase("door_ended_before_other_room", "Ended and for another room: ended is named first.", "leaf_vouch_ended",
      vst([D_ROOM2]), now_ms=T0 + 30 * DAY)
dcase("door_other_room_before_other_leaf", "Another room and another leaf: the room is named first.",
      "leaf_vouch_other_room", vst([D_ROOM2]), leaf_key_hex=LEAF2.hex())
dcase("door_other_leaf_before_member", "Another leaf and another member: the leaf is named first.",
      "leaf_vouch_other_leaf", ONE, leaf_key_hex=LEAF2.hex(), member=PERSON2.iss)
dcase("door_room_key", "A room key's vouch of one entry, at its room's door; the member is the voice.", "ok",
      vst([D_ROOM], signer=VOICE, n=1, refs={"also": {"voice": [rref(1)]}}, leaves=[Tag(60, H_ROOM)]),
      member=VOICE.iss)
out["leaf_door"] = door

# ---- the room-key members of a key record (CC 2.4.1.1, CC 2.6.1.11) ----
YEAR = 31_536_000_000
def krec(k, roles, until=None, **room):
    p = {"key": {1: 7, 3: -70100, -1: k.pub}, "identity_type": sorted(roles, key=enc), "asserted_at": T0}
    if until is not None: p["valid_until"] = until
    p.update(room)
    return p
RM = {"room": ROOM, "kem_xwing_pubkey": KEM_A, "seat_commitment": [-16, COMMIT]}
def without(d, k): return {a: b for a, b in d.items() if a != k}
out["key_records"] = [{"id": i, "description": d, "payload_hex": enc(p).hex(), "expect": e} for i, d, p, e in (
    ("room_key_node_no_end", "A node's room key with no valid_until: a room key states no required end.",
     krec(R, ["node"], **RM), "valid"),
    ("room_key_agent_no_end", "An agent's room key with no valid_until.", krec(R, ["agent"], **RM), "valid"),
    ("room_key_node_with_end", "A node's room key that states an end inside the bound.",
     krec(R, ["node"], T0 + YEAR, **RM), "valid"),
    ("room_key_user", "A person's room key: no valid_until, as any person's key.", krec(R, ["user"], **RM), "valid"),
    ("room_key_user_with_end", "A person's room key with valid_until.", krec(R, ["user"], T0 + YEAR, **RM),
     "key_record_out_of_window"),
    ("room_key_node_end_out_of_bound", "A node's room key whose end is past the bound.",
     krec(R, ["node"], T0 + YEAR + 1, **RM), "key_record_out_of_window"),
    ("node_no_end", "A node's key that is no room key, with no valid_until.", krec(R, ["node"]),
     "key_record_out_of_window"),
    ("room_without_kem", "room and seat_commitment with no kem_xwing_pubkey.",
     krec(R, ["node"], **without(RM, "kem_xwing_pubkey")), "edition2_payload_invalid"),
    ("room_without_seat", "room and kem_xwing_pubkey with no seat_commitment.",
     krec(R, ["node"], **without(RM, "seat_commitment")), "edition2_payload_invalid"),
    ("room_alone", "room alone.", krec(R, ["node"], T0 + YEAR, room=ROOM), "edition2_payload_invalid"),
    ("kem_without_room", "kem_xwing_pubkey and seat_commitment with no room.",
     krec(R, ["node"], T0 + YEAR, **without(RM, "room")), "edition2_payload_invalid"),
    ("seat_alone", "seat_commitment alone.", krec(R, ["node"], T0 + YEAR, seat_commitment=[-16, COMMIT]),
     "edition2_payload_invalid"),
    ("room_not_group_ref", "room is an identity reference, not a group's id.",
     krec(R, ["node"], **dict(RM, room=PERSON.iss)), "edition2_payload_invalid"),
    ("kem_1215", "kem_xwing_pubkey of 1215 bytes.", krec(R, ["node"], **dict(RM, kem_xwing_pubkey=KEM_A[:-1])),
     "edition2_payload_invalid"),
    ("seat_bare_digest", "seat_commitment a bare 32 bytes, not [-16, digest].",
     krec(R, ["node"], **dict(RM, seat_commitment=COMMIT)), "edition2_payload_invalid"),
    ("seat_other_alg", "seat_commitment under another hash algorithm.",
     krec(R, ["node"], **dict(RM, seat_commitment=[-43, COMMIT])), "edition2_payload_invalid"),
    ("seat_31", "seat_commitment of 31 bytes.", krec(R, ["node"], **dict(RM, seat_commitment=[-16, COMMIT[:31]])),
     "edition2_payload_invalid"))]

# ---- an occurrence's binding key (CC 3.3.6.1) ----
OK_, DEV = Key(27), Key(28)
ENC_X, ENC_M = bytes([81]) * 32, KEM_B[:1184]
TRANSIT, ONION = xw_pk(bytes([35]) * 32), xw_pk(bytes([36]) * 32)
RNS_X = bytes([82]) * 32
def occ(**edit):
    p = {"author": PERSON.iss, "identity_key_id": PERSON.iss, "occurrence_key_id": DEV.iss, "device_class": "phone",
         "encryption_pubkeys": {"x25519": ENC_X, "ml_kem_768": ENC_M},
         "transport_destination": {"reticulum_x25519_pubkey": RNS_X, "reticulum_ed25519_pubkey": bytes([83]) * 32,
                                   "app_name": "ciris", "aspects": ["node"], "destination_hash": bytes([84]) * 16},
         "transit_xwing_pubkey": TRANSIT, "onion_hop_xwing_pubkey": ONION,
         "room_binding_xwing_pubkey": BIND_PK, "refs": {"head": rref(1)}, "asserted_at": T0}
    for k, v in edit.items():
        if v is None: p.pop(k, None)
        else: p[k] = v
    return p
M_, X_ = BIND_PK[:1184], BIND_PK[1184:]
out["occurrences"] = [{"id": i, "description": d, "payload_hex": enc(p).hex(), "expect": e} for i, d, p, e in (
    ("binding_key", "An occurrence carrying a binding key distinct from every other KEM key on the row.", occ(),
     "valid"),
    ("no_binding_key", "No binding key.", occ(room_binding_xwing_pubkey=None), "valid"),
    ("binding_key_alone", "The binding key with no other KEM key on the row.",
     occ(encryption_pubkeys=None, transport_destination=None, transit_xwing_pubkey=None,
         onion_hop_xwing_pubkey=None), "valid"),
    ("binding_key_1215", "A binding key of 1215 bytes.", occ(room_binding_xwing_pubkey=BIND_PK[:-1]),
     "invalid:malformed:room_binding_xwing_pubkey"),
    ("binding_key_text", "A binding key as text.", occ(room_binding_xwing_pubkey="key"),
     "invalid:malformed:room_binding_xwing_pubkey"),
    ("mlkem_is_content_kem", "Its ML-KEM-768 half is encryption_pubkeys.ml_kem_768.",
     occ(encryption_pubkeys={"x25519": ENC_X, "ml_kem_768": M_}), "invalid:room_binding_ml_kem_768_reuse"),
    ("x25519_is_content_kem", "Its X25519 half is encryption_pubkeys.x25519.",
     occ(encryption_pubkeys={"x25519": X_, "ml_kem_768": ENC_M}), "invalid:room_binding_x25519_reuse"),
    ("mlkem_is_transit", "Its ML-KEM-768 half is the transit key's.",
     occ(transit_xwing_pubkey=M_ + TRANSIT[1184:]), "invalid:room_binding_ml_kem_768_reuse"),
    ("x25519_is_transit", "Its X25519 half is the transit key's.",
     occ(transit_xwing_pubkey=TRANSIT[:1184] + X_), "invalid:room_binding_x25519_reuse"),
    ("mlkem_is_onion_hop", "Its ML-KEM-768 half is the onion hop key's.",
     occ(onion_hop_xwing_pubkey=M_ + ONION[1184:]), "invalid:room_binding_ml_kem_768_reuse"),
    ("x25519_is_onion_hop", "Its X25519 half is the onion hop key's.",
     occ(onion_hop_xwing_pubkey=ONION[:1184] + X_), "invalid:room_binding_x25519_reuse"),
    ("x25519_is_transport", "Its X25519 half is the transport x25519.",
     occ(transport_destination=dict(occ()["transport_destination"], reticulum_x25519_pubkey=X_)),
     "invalid:room_binding_x25519_reuse"),
    ("is_transit_key", "The binding key is the transit key, both halves: the first half is named.",
     occ(transit_xwing_pubkey=BIND_PK), "invalid:room_binding_ml_kem_768_reuse"))]

out = dict({"_meta": {
    "spec": "CIRISConstitution v1.0-rc22 (f4671933f2b22b33d2db868d4654036162104123): CC 2.6.1.11 (room keys, the "
            "binding of a voice to its person, a wrap to a room key, a room's MLS group ids), CC 2.4.1.1 (a key's own "
            "end), CC 3.3.6.1 (key separation), CC 3.3.6.4 (the window rows), CC 5.1 (the leaf vouch and its door).",
    "generator": "gen_private_room_v1.py (independent of verify): X-Wing over kyber_py and X25519, RFC 9180 HPKE "
                 "written out and checked against hpke_xwing_aes256gcm.json, gen_row_statements_v5.py's CBOR encoder "
                 "and composite signer.",
    "binding_key_name": "SHA-256(CDE([\"CEG-binding-key/2\", key])) over the 1216 bytes of room_binding_xwing_pubkey: "
                        "the verifier's encoding of the thumbprint a binding's info carries (CC 2.6.1.12).",
    "keys": "composite Key(n): ML-DSA-65 seed [n]*32, Ed25519 seed [(n+100)%256]*32. Room keys R=21 (bound), A=22, "
            "B=23; persons 24, 25; a voice 26; a device 28. X-Wing keys are from 32-byte seeds (the secret key), and "
            "each encapsulation from its 64-byte eseed (ML-KEM m then the X25519 ephemeral).",
    "binding": "each exchange gives every value of the three flows. A replay makes the challenge and the "
               "confirmation with an RNG that returns the eseed, and compares bytes.",
    "binding_open": "the addressee's inputs and its answer: ok, or the refusal. binding_open_failed is opaque.",
    "room_sealed": "the fields and the deterministic encoding of the map (closed: an unknown member is refused); "
                   "room_sealed_refused are plaintexts a reader refuses. room_wrap and invitation are mode_base seals "
                   "(enc then ct) under the info named. An invitation's plaintext here is opaque bytes: what it holds "
                   "beyond a binding's flows, and the key a first invitation is sealed to, are the transport's open "
                   "encoding (CC 2.6.1.12), not fixed by this file.",
    "room_key_vouch": "the cases vouch_room_key, vouch_room_key_8 and door_room_key are a room key's vouch (iss the "
                      "voice, one entry, also.voice). How 'signed under the member's device key' reads for a room "
                      "key is open with CIRISConstitution (#224); these cases are their own group and may move.",
    "row_statements": "expect is valid, invalid:{token}, invalid:malformed:{member} or "
                      "invalid:unexpected_member:{within}, read with the held keys.",
    "leaf_door": "the vouching row as presented (its disclosures in sd_claims) and the door's inputs; expect ok or "
                 "CC's refusal token. statement_hex null: no row presented.",
    "key_records": "key:record payloads: valid or the refusal token.",
    "occurrences": "identity:occurrence payloads: valid or the refusal."}}, **out)
ROWS = ("row_statements", "leaf_door", "key_records", "occurrences")
for name, keep in (("private_room_v1.json", lambda k: k not in ROWS), ("private_room_rows_v1.json", lambda k: k in ROWS)):
    with open(os.path.join(here, name), "w") as f:
        json.dump({k: v for k, v in out.items() if k == "_meta" or keep(k)}, f, indent=1, sort_keys=True)
        f.write("\n")
    assert os.path.getsize(os.path.join(here, name)) < 1_000_000, name
