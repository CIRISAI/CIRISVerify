#!/usr/bin/env python3
"""Independent known-answer generator for the CC 5.3.3.10 link handshake, CTKX v2.

Written from docs/TRANSIT_HANDSHAKE_V2.md, not from the Rust in
src/ciris-crypto/src/transit.rs. Every primitive is assembled here:

- X-Wing (draft-connolly-cfrg-xwing-kem-11) over kyber-py's
  `_keygen_internal` / `_encaps_internal` / `_decaps_internal` (FIPS 203),
  pyca/cryptography X25519 and hashlib SHA3-256 / SHAKE256;
- HKDF-SHA256 (RFC 5869) written out over the standard library's `hmac`;
- HMAC-SHA256 from the standard library;
- AES-256-GCM from pyca/cryptography.

Before emitting anything it checks the X-Wing code against every case of
tests/vectors/xwing/draft-connolly-cfrg-xwing-kem-11.json and the HKDF
against RFC 5869 A.1 and A.3.

Run (from the repository root, with a venv holding kyber-py and cryptography):

    python3 -I src/ciris-crypto/tests/vectors/transit/gen.py

It writes transit_ctkx_v2_v1.json beside itself.
"""

import hashlib
import hmac as std_hmac
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from kyber_py.ml_kem import ML_KEM_768

HERE = os.path.dirname(os.path.abspath(__file__))
XWING_KAT = os.path.join(HERE, "..", "xwing", "draft-connolly-cfrg-xwing-kem-11.json")
OUT = os.path.join(HERE, "transit_ctkx_v2_v1.json")

# --------------------------------------------------------------------------
# X-Wing, draft-11
# --------------------------------------------------------------------------

XWING_LABEL = b"\\.//^\\"  # 5c2e2f2f5e5c
assert XWING_LABEL.hex() == "5c2e2f2f5e5c"


def x25519(k: bytes, u: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(k)
    return sk.exchange(X25519PublicKey.from_public_bytes(u))


def x25519_base(k: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(k)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def xwing_expand(sk: bytes):
    """expandDecapsulationKey (draft-11 §5.2)."""
    assert len(sk) == 32
    expanded = hashlib.shake_256(sk).digest(96)
    pk_m, sk_m = ML_KEM_768._keygen_internal(expanded[0:32], expanded[32:64])
    sk_x = expanded[64:96]
    pk_x = x25519_base(sk_x)
    return sk_m, sk_x, pk_m, pk_x


def xwing_combiner(ss_m, ss_x, ct_x, pk_x):
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def xwing_pk(sk: bytes) -> bytes:
    _, _, pk_m, pk_x = xwing_expand(sk)
    return pk_m + pk_x


def xwing_encaps_derand(pk: bytes, eseed: bytes):
    """EncapsulateDerand (draft-11 §5.4): returns (ct, ss)."""
    assert len(pk) == 1216 and len(eseed) == 64
    pk_m, pk_x = pk[0:1184], pk[1184:1216]
    ek_x = eseed[32:64]
    ct_x = x25519_base(ek_x)
    ss_x = x25519(ek_x, pk_x)
    ss_m, ct_m = ML_KEM_768._encaps_internal(pk_m, eseed[0:32])
    return ct_m + ct_x, xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def xwing_decaps(sk: bytes, ct: bytes) -> bytes:
    assert len(ct) == 1120
    sk_m, sk_x, _, pk_x = xwing_expand(sk)
    ct_m, ct_x = ct[0:1088], ct[1088:1120]
    ss_m = ML_KEM_768._decaps_internal(sk_m, ct_m)
    ss_x = x25519(sk_x, ct_x)
    return xwing_combiner(ss_m, ss_x, ct_x, pk_x)


def self_check_xwing():
    with open(XWING_KAT) as f:
        cases = json.load(f)
    assert len(cases) >= 1
    for i, c in enumerate(cases):
        seed = bytes.fromhex(c["seed"])
        assert bytes.fromhex(c["sk"]) == seed, f"case {i}: sk is the seed"
        pk = xwing_pk(seed)
        assert pk.hex() == c["pk"], f"case {i}: pk"
        ct, ss = xwing_encaps_derand(pk, bytes.fromhex(c["eseed"]))
        assert ct.hex() == c["ct"], f"case {i}: ct"
        assert ss.hex() == c["ss"], f"case {i}: ss"
        assert xwing_decaps(seed, ct) == ss, f"case {i}: decaps"
    return len(cases)


# --------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869), written out
# --------------------------------------------------------------------------


def hmac256(k: bytes, m: bytes) -> bytes:
    return std_hmac.new(k, m, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, n: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:n]


def hkdf(salt, ikm, info, n):
    return hkdf_expand(hkdf_extract(salt, ikm), info, n)


def self_check_hkdf():
    # RFC 5869 A.1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    assert hkdf_extract(salt, ikm).hex() == (
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    assert hkdf(salt, ikm, info, 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    # RFC 5869 A.3 (empty salt and info)
    assert hkdf(b"", ikm, b"", 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


# --------------------------------------------------------------------------
# CTKX v2, from docs/TRANSIT_HANDSHAKE_V2.md
# --------------------------------------------------------------------------

SUITE = b"transit_xwing_hkdf_sha256"
SUITE_V1 = b"transit_x25519_mlkem768_hkdf_sha256"
PROTO = b"ciris-transit/v2"
L_IDENTITY = b"ciris-transit/v2/identity"
L_I2R = b"ciris-transit/v2/initiator-to-responder"
L_R2I = b"ciris-transit/v2/responder-to-initiator"
L_CONF = b"ciris-transit/v2/confirm"
MAX_KEY_ID_LEN = 1024
MAX_MESSAGE_LEN = 8192


class Refusal(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def H(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def u16(n):
    return n.to_bytes(2, "big")


def u32(n):
    return n.to_bytes(4, "big")


def check_key_id(kid: bytes):
    if not (1 <= len(kid) <= MAX_KEY_ID_LEN):
        raise Refusal("key_id_invalid")


def bound(iid: bytes, rid: bytes) -> bytes:
    return bytes([len(SUITE)]) + SUITE + u16(len(iid)) + iid + u16(len(rid)) + rid


def key_schedule(salt: bytes, ikm: bytes, bnd: bytes):
    prk = hkdf_extract(salt, ikm)
    return (
        hkdf_expand(prk, L_I2R + bnd, 32),
        hkdf_expand(prk, L_R2I + bnd, 32),
        hkdf_expand(prk, L_CONF + bnd, 32),
    )


class Reader:
    def __init__(self, b):
        self.b = b

    def take(self, n):
        if len(self.b) < n:
            raise Refusal("truncated")
        out, self.b = self.b[:n], self.b[n:]
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), "big")

    def end(self):
        if self.b:
            raise Refusal("trailing_bytes")


def initiator_start(link_id, pk_sr, rid, iid, pk_si, e_seed, ct1_rand):
    check_key_id(iid)
    check_key_id(rid)
    pk_ei = xwing_pk(e_seed)
    h0 = H(PROTO, link_id, pk_sr)
    ct1, ss1 = xwing_encaps_derand(pk_sr, ct1_rand)
    h1 = H(h0, pk_ei, ct1)
    k_id = hkdf(h1, ss1, L_IDENTITY, 32)
    if pk_si is None:
        id_block = u16(len(iid)) + iid + b"\x00"
    else:
        id_block = u16(len(iid)) + iid + b"\x01" + H(pk_si)
    id_ct = AESGCM(k_id).encrypt(b"\x00" * 12, id_block, h1)
    h2 = H(h1, id_ct)
    msg1 = (
        b"\x01" + bytes([len(SUITE)]) + SUITE + u16(len(rid)) + rid
        + pk_ei + ct1 + u16(len(id_ct)) + id_ct
    )
    st = dict(
        iid=iid, rid=rid, e_seed=e_seed, has_static=pk_si is not None,
        ss1=ss1, h0=h0, h1=h1, h2=h2, k_id=k_id, id_block=id_block,
    )
    return st, msg1


def responder_accept(link_id, sk_sr, rid_expected, lookup, msg1, ct2_rand, ct3_rand):
    pk_sr = xwing_pk(sk_sr)
    r = Reader(msg1)
    if r.u8() != 0x01:
        raise Refusal("message_type")
    suite = r.take(r.u8())
    if suite == SUITE_V1:
        raise Refusal("suite_v1_refused")
    if suite != SUITE:
        raise Refusal("suite_unknown")
    rid = r.take(r.u16())
    check_key_id(rid)
    if rid != rid_expected:
        raise Refusal("responder_key_id_mismatch")
    pk_ei = r.take(1216)
    ct1 = r.take(1120)
    id_ct = r.take(r.u16())
    r.end()
    if len(id_ct) < 16:
        raise Refusal("bad_length")
    h0 = H(PROTO, link_id, pk_sr)
    ss1 = xwing_decaps(sk_sr, ct1)
    h1 = H(h0, pk_ei, ct1)
    k_id = hkdf(h1, ss1, L_IDENTITY, 32)
    try:
        id_block = AESGCM(k_id).decrypt(b"\x00" * 12, id_ct, h1)
    except Exception:
        raise Refusal("identity_open_failed")
    ib = Reader(id_block)
    try:
        iid = ib.take(ib.u16())
        hs = ib.u8()
        if hs == 0:
            commitment = None
        elif hs == 1:
            commitment = ib.take(32)
        else:
            raise Refusal("identity_block_malformed")
        ib.end()
    except Refusal:
        raise Refusal("identity_block_malformed")
    check_key_id(iid)
    h2 = H(h1, id_ct)
    pk_si = None
    if commitment is not None:
        cand = lookup(iid, commitment)
        if cand is not None and H(cand) == commitment:
            pk_si = cand
    ct2, ss2 = xwing_encaps_derand(pk_ei, ct2_rand)
    if pk_si is not None:
        ct3, ss3 = xwing_encaps_derand(pk_si, ct3_rand)
        flags = b"\x01"
        h3 = H(h2, flags, ct2, ct3)
        ikm = ss1 + ss2 + ss3
        tail = ct3
    else:
        flags = b"\x00"
        h3 = H(h2, flags, ct2)
        ikm = ss1 + ss2
        tail = b""
    bnd = bound(iid, rid)
    k_i2r, k_r2i, k_conf = key_schedule(h3, ikm, bnd)
    confirm_r = hmac256(k_conf, b"responder" + h3)
    msg2 = b"\x02" + flags + ct2 + tail + confirm_r
    st = dict(
        iid=iid, rid=rid, bnd=bnd, h3=h3, k_i2r=k_i2r, k_r2i=k_r2i, k_conf=k_conf,
        mode="mutual" if pk_si is not None else "first_contact",
        commitment=commitment, confirmed=False,
    )
    return st, msg2


def initiator_finish(st, msg2, sk_si):
    r = Reader(msg2)
    if r.u8() != 0x02:
        raise Refusal("message_type")
    flags = r.u8()
    if flags & ~0x01:
        raise Refusal("flags_unknown")
    mutual = bool(flags & 1)
    ct2 = r.take(1120)
    ct3 = r.take(1120) if mutual else b""
    confirm_r = r.take(32)
    r.end()
    if mutual and (not st["has_static"] or sk_si is None):
        raise Refusal("mode_mismatch")
    ss2 = xwing_decaps(st["e_seed"], ct2)
    h3 = H(st["h2"], bytes([flags]), ct2, ct3)
    ikm = st["ss1"] + ss2
    if mutual:
        ikm += xwing_decaps(sk_si, ct3)
    bnd = bound(st["iid"], st["rid"])
    k_i2r, k_r2i, k_conf = key_schedule(h3, ikm, bnd)
    if not std_hmac.compare_digest(hmac256(k_conf, b"responder" + h3), confirm_r):
        raise Refusal("confirm_mismatch")
    ctkc = b"CTKC" + hmac256(k_conf, b"initiator" + h3)
    return dict(
        iid=st["iid"], rid=st["rid"], bnd=bnd, h3=h3, k_i2r=k_i2r, k_r2i=k_r2i,
        k_conf=k_conf, mode="mutual" if mutual else "first_contact",
        has_static=st["has_static"],
    ), ctkc


def check_ctkc(payload, k_conf, transcript):
    if len(payload) < 4 or payload[:4] != b"CTKC":
        raise Refusal("not_ctkc")
    if len(payload) < 36:
        raise Refusal("truncated")
    if len(payload) > 36:
        raise Refusal("trailing_bytes")
    if not std_hmac.compare_digest(payload[4:], hmac256(k_conf, b"initiator" + transcript)):
        raise Refusal("ctkc_mismatch")


def responder_confirm(st, payload):
    check_ctkc(payload, st["k_conf"], st["h3"])
    st["confirmed"] = True
    return "attributed" if st["mode"] == "mutual" else "first_contact_confirmed"


def promotion_rekey(h3, ct3p, k_i2r, k_r2i, ss3p, bnd):
    h3p = H(h3, b"promote", ct3p)
    return (h3p,) + key_schedule(h3p, k_i2r + k_r2i + ss3p, bnd)


def responder_promote(st, pk_si, ct3p_rand):
    if st["mode"] != "first_contact" or st["commitment"] is None or not st["confirmed"]:
        raise Refusal("not_promotable")
    if H(pk_si) != st["commitment"]:
        raise Refusal("promotion_commitment_mismatch")
    ct3p, ss3p = xwing_encaps_derand(pk_si, ct3p_rand)
    h3p, a, b, c = promotion_rekey(st["h3"], ct3p, st["k_i2r"], st["k_r2i"], ss3p, st["bnd"])
    st.update(h3p=h3p, k_i2r_p=a, k_r2i_p=b, k_conf_p=c)
    return b"\x03" + ct3p


def initiator_on_promote(ist, msg3, sk_si):
    if ist["mode"] != "first_contact" or not ist["has_static"]:
        raise Refusal("not_promotable")
    r = Reader(msg3)
    if r.u8() != 0x03:
        raise Refusal("message_type")
    ct3p = r.take(1120)
    r.end()
    ss3p = xwing_decaps(sk_si, ct3p)
    h3p, a, b, c = promotion_rekey(ist["h3"], ct3p, ist["k_i2r"], ist["k_r2i"], ss3p, ist["bnd"])
    ist.update(h3p=h3p, k_i2r_p=a, k_r2i_p=b, k_conf_p=c)
    return b"CTKC" + hmac256(c, b"initiator" + h3p)


# Part framing (doc "Framing, sizes, limits")


def encode_parts(msg, max_part_len):
    if not (1 <= len(msg) <= MAX_MESSAGE_LEN):
        raise Refusal("framing_too_large")
    first = max_part_len - 10
    rest = max_part_len - 6
    parts = [b"CTKX\x02\x00" + u32(len(msg)) + msg[:first]]
    off = first
    while off < len(msg):
        parts.append(b"CTKX\x02\x01" + msg[off:off + rest])
        off += rest
    return parts


def reassemble(parts):
    total, buf = None, b""
    for i, p in enumerate(parts):
        if len(p) < 6 or p[:4] != b"CTKX":
            raise Refusal("framing_malformed")
        if p[4] == 0x01:
            raise Refusal("framing_v1_refused")
        if p[4] != 0x02:
            raise Refusal("framing_version_unsupported")
        kind = p[5]
        if kind == 0x00:
            if total is not None:
                raise Refusal("framing_out_of_order")
            if len(p) < 10:
                raise Refusal("framing_malformed")
            total = int.from_bytes(p[6:10], "big")
            if total == 0 or total > MAX_MESSAGE_LEN:
                raise Refusal("framing_too_large")
            body = p[10:]
        elif kind == 0x01:
            if total is None or len(buf) >= total:
                raise Refusal("framing_out_of_order")
            body = p[6:]
        else:
            raise Refusal("framing_part_kind")
        if len(buf) + len(body) > total:
            raise Refusal("trailing_bytes")
        buf += body
        if len(buf) == total:
            if i != len(parts) - 1:
                raise Refusal("framing_out_of_order")
            return buf
    raise Refusal("truncated")


# --------------------------------------------------------------------------
# Fixed inputs
# --------------------------------------------------------------------------


def seed32(label):
    return hashlib.sha256(b"ctkx-v2-kat/" + label.encode()).digest()


def rand64(label):
    return hashlib.shake_256(b"ctkx-v2-kat/" + label.encode()).digest(64)


def hx(b):
    return b.hex()


def expect_refusal(code, fn):
    try:
        fn()
    except Refusal as e:
        assert e.code == code, f"expected {code}, got {e.code}"
        return code
    raise AssertionError(f"expected refusal {code}, none raised")


def flip(b, i, mask=0x01):
    b = bytearray(b)
    b[i] ^= mask
    return bytes(b)


def run_case(name, link_id, iid, rid, sr, si, si_bound, e, r1, r2, r3):
    """Run one handshake end to end. `si` is the initiator static seed (None
    for has_static = 0); `si_bound` says whether the responder holds it."""
    sk_sr = seed32(sr)
    pk_sr = xwing_pk(sk_sr)
    sk_si = seed32(si) if si else None
    pk_si = xwing_pk(sk_si) if si else None
    e_seed, ct1_rand, ct2_rand, ct3_rand = seed32(e), rand64(r1), rand64(r2), rand64(r3)

    ist, msg1 = initiator_start(link_id, pk_sr, rid, iid, pk_si, e_seed, ct1_rand)

    def lookup(kid, commitment):
        assert kid == iid
        return pk_si if si_bound else None

    rst, msg2 = responder_accept(link_id, sk_sr, rid, lookup, msg1, ct2_rand, ct3_rand)
    ilink, ctkc = initiator_finish(ist, msg2, sk_si)
    assert (ilink["k_i2r"], ilink["k_r2i"], ilink["k_conf"]) == (
        rst["k_i2r"], rst["k_r2i"], rst["k_conf"]
    )
    outcome = responder_confirm(rst, ctkc)
    case = {
        "name": name,
        "inputs": {
            "link_id": hx(link_id),
            "initiator_key_id": iid.decode(),
            "responder_key_id": rid.decode(),
            "responder_static_seed": hx(sk_sr),
            "initiator_static_seed": hx(sk_si) if sk_si else None,
            "responder_holds_initiator_binding": si_bound,
            "initiator_ephemeral_seed": hx(e_seed),
            "ct1_encaps_rand": hx(ct1_rand),
            "ct2_encaps_rand": hx(ct2_rand),
            "ct3_encaps_rand": hx(ct3_rand),
        },
        "responder_static_pk": hx(pk_sr),
        "initiator_static_pk": hx(pk_si) if pk_si else None,
        "initiator_ephemeral_pk": hx(xwing_pk(e_seed)),
        "intermediate": {
            "h0": hx(ist["h0"]),
            "h1": hx(ist["h1"]),
            "k_id": hx(ist["k_id"]),
            "id_block": hx(ist["id_block"]),
            "h2": hx(ist["h2"]),
            "h3": hx(rst["h3"]),
            "bound": hx(rst["bnd"]),
        },
        "msg1": hx(msg1),
        "msg2": hx(msg2),
        "ctkc": hx(ctkc),
        "mode": rst["mode"],
        "confirm_outcome": outcome,
        "k_i2r": hx(rst["k_i2r"]),
        "k_r2i": hx(rst["k_r2i"]),
        "k_conf": hx(rst["k_conf"]),
    }
    ctx = dict(
        link_id=link_id, iid=iid, rid=rid, sk_sr=sk_sr, pk_sr=pk_sr, sk_si=sk_si,
        pk_si=pk_si, e_seed=e_seed, ct1_rand=ct1_rand, ct2_rand=ct2_rand,
        ct3_rand=ct3_rand, lookup=lookup, msg1=msg1, msg2=msg2, ctkc=ctkc,
        ist=ist, rst=rst, ilink=ilink,
    )
    return case, ctx


def main():
    n_xwing = self_check_xwing()
    self_check_hkdf()
    print(f"self-check: X-Wing draft-11, {n_xwing}/{n_xwing} cases; HKDF RFC 5869 A.1, A.3", file=sys.stderr)

    link_id = H(b"ctkx-v2-kat/link")[:16]
    iid = b"node-initiator-" + H(b"ctkx-v2-kat/iid").hex()[:32].encode()
    rid = b"node-responder-" + H(b"ctkx-v2-kat/rid").hex()[:32].encode()

    mutual, mctx = run_case(
        "mutual", link_id, iid, rid, "responder-static", "initiator-static", True,
        "mutual/ephemeral", "mutual/ct1", "mutual/ct2", "mutual/ct3",
    )
    assert mutual["mode"] == "mutual" and len(bytes.fromhex(mutual["msg2"])) == 2274
    fc0, f0ctx = run_case(
        "first_contact_no_static", link_id, b"phone-" + iid[15:], rid,
        "responder-static", None, False,
        "fc0/ephemeral", "fc0/ct1", "fc0/ct2", "fc0/ct3",
    )
    assert fc0["mode"] == "first_contact" and len(bytes.fromhex(fc0["msg2"])) == 1154
    fc1, f1ctx = run_case(
        "first_contact_unbound_static", link_id, iid, rid, "responder-static",
        "initiator-static", False, "fc1/ephemeral", "fc1/ct1", "fc1/ct2", "fc1/ct3",
    )
    assert fc1["mode"] == "first_contact"

    # Promotion of the first-contact link with a static.
    ct3p_rand = rand64("promote/ct3")
    msg3 = responder_promote(f1ctx["rst"], f1ctx["pk_si"], ct3p_rand)
    ctkc_p = initiator_on_promote(f1ctx["ilink"], msg3, f1ctx["sk_si"])
    rst, il = f1ctx["rst"], f1ctx["ilink"]
    assert (il["k_i2r_p"], il["k_r2i_p"], il["k_conf_p"]) == (rst["k_i2r_p"], rst["k_r2i_p"], rst["k_conf_p"])
    check_ctkc(ctkc_p, rst["k_conf_p"], rst["h3p"])
    # A pre-promotion CTKC never verifies as CTKC'.
    expect_refusal("ctkc_mismatch", lambda: check_ctkc(f1ctx["ctkc"], rst["k_conf_p"], rst["h3p"]))
    promotion = {
        "name": "promotion",
        "base": "first_contact_unbound_static",
        "inputs": {"ct3_prime_encaps_rand": hx(ct3p_rand)},
        "msg3": hx(msg3),
        "h3_prime": hx(rst["h3p"]),
        "ctkc_prime": hx(ctkc_p),
        "k_i2r": hx(rst["k_i2r_p"]),
        "k_r2i": hx(rst["k_r2i_p"]),
        "k_conf": hx(rst["k_conf_p"]),
    }

    # Part framing of the mutual messages at a 400-byte part limit.
    framing = []
    for which in ("msg1", "msg2"):
        msg = mctx[which]
        parts = encode_parts(msg, 400)
        assert reassemble(parts) == msg
        framing.append({
            "name": f"mutual_{which}_400",
            "message": which,
            "base": "mutual",
            "max_part_len": 400,
            "parts": [hx(p) for p in parts],
        })

    # ---------------- refusals ----------------
    refusals = []
    m1, m2 = mctx["msg1"], mctx["msg2"]
    sl = 1 + 1 + len(SUITE)  # offset of responder_key_id's length
    rid_off = sl + 2
    pk_off = rid_off + len(rid)
    ct1_off = pk_off + 1216
    idlen_off = ct1_off + 1120
    idct_off = idlen_off + 2

    def resp(msg1, rid_expected=rid):
        return lambda: responder_accept(
            link_id, mctx["sk_sr"], rid_expected, mctx["lookup"], msg1,
            mctx["ct2_rand"], mctx["ct3_rand"],
        )

    def add_msg1(name, msg1, code, **extra):
        expect_refusal(code, resp(msg1, extra.get("_rid", rid)))
        entry = {"name": name, "base": "mutual", "side": "responder_accept", "msg1": hx(msg1), "error": code}
        if "_rid" in extra:
            entry["responder_key_id_expected"] = extra["_rid"].decode()
        refusals.append(entry)

    wrong_suite = m1[:2] + b"transit_xwing_hkdf_sha384" + m1[sl:]
    add_msg1("wrong_suite", wrong_suite, "suite_unknown")
    v1_suite = m1[:1] + bytes([len(SUITE_V1)]) + SUITE_V1 + m1[sl:]
    add_msg1("v1_suite_string", v1_suite, "suite_v1_refused")
    add_msg1("msg_type_not_msg1", b"\x02" + m1[1:], "message_type")
    add_msg1("truncated_msg1_last_byte", m1[:-1], "truncated")
    add_msg1("truncated_msg1_in_ct1", m1[:ct1_off + 500], "truncated")
    add_msg1("trailing_bytes_msg1", m1 + b"\x00", "trailing_bytes")
    add_msg1("tampered_id_ct", flip(m1, idct_off + 3), "identity_open_failed")
    add_msg1("tampered_id_ct_tag", flip(m1, len(m1) - 1), "identity_open_failed")
    add_msg1("tampered_ct1", flip(m1, ct1_off + 10), "identity_open_failed")
    add_msg1("wrong_responder_key_id", m1, "responder_key_id_mismatch",
             _rid=b"node-responder-someone-else")
    add_msg1("empty_responder_key_id", m1[:sl] + u16(0) + m1[pk_off:], "key_id_invalid")

    def init_finish(base_ctx, msg2):
        def f():
            ist, _ = initiator_start(
                link_id, base_ctx["pk_sr"], base_ctx["rid"], base_ctx["iid"], base_ctx["pk_si"],
                base_ctx["e_seed"], base_ctx["ct1_rand"],
            )
            initiator_finish(ist, msg2, base_ctx["sk_si"])
        return f

    def add_msg2(name, base, ctx, msg2, code):
        expect_refusal(code, init_finish(ctx, msg2))
        refusals.append({"name": name, "base": base, "side": "initiator_finish", "msg2": hx(msg2), "error": code})

    add_msg2("tampered_confirm_r", "mutual", mctx, flip(m2, len(m2) - 1), "confirm_mismatch")
    add_msg2("tampered_ct2", "mutual", mctx, flip(m2, 2 + 7), "confirm_mismatch")
    add_msg2("truncated_msg2", "mutual", mctx, m2[:-1], "truncated")
    add_msg2("truncated_msg2_short", "mutual", mctx, m2[:600], "truncated")
    add_msg2("trailing_bytes_msg2", "mutual", mctx, m2 + b"\x00", "trailing_bytes")
    add_msg2("unknown_flags", "mutual", mctx, m2[:1] + b"\x03" + m2[2:], "flags_unknown")
    add_msg2("msg_type_not_msg2", "mutual", mctx, b"\x03" + m2[1:], "message_type")
    f0m2 = f0ctx["msg2"]
    # A responder claiming mutual to an initiator that has no static.
    forged = f0m2[:1] + b"\x01" + f0m2[2:2 + 1120] + b"\x00" * 1120 + f0m2[-32:]
    add_msg2("mutual_to_no_static", "first_contact_no_static", f0ctx, forged, "mode_mismatch")

    def add_ctkc(name, base, ctx, payload, code):
        rst = dict(ctx["rst"], confirmed=False)
        expect_refusal(code, lambda: responder_confirm(rst, payload))
        refusals.append({"name": name, "base": base, "side": "responder_confirm", "ctkc": hx(payload), "error": code})

    c = mctx["ctkc"]
    add_ctkc("ctkc_wrong_tag", "mutual", mctx, b"CTKD" + c[4:], "not_ctkc")
    add_ctkc("ctkc_other_frame", "mutual", mctx, b"\x01\x02", "not_ctkc")
    add_ctkc("ctkc_bad_mac", "mutual", mctx, flip(c, 20), "ctkc_mismatch")
    add_ctkc("ctkc_truncated", "mutual", mctx, c[:-1], "truncated")
    add_ctkc("ctkc_trailing", "mutual", mctx, c + b"\x00", "trailing_bytes")
    add_ctkc("ctkc_from_other_handshake", "mutual", mctx, f1ctx["ctkc"], "ctkc_mismatch")

    # Promotion refusals: re-derive the confirmed first-contact state.
    def fresh_fc1():
        _, ctx = run_case(
            "x", link_id, iid, rid, "responder-static", "initiator-static", False,
            "fc1/ephemeral", "fc1/ct1", "fc1/ct2", "fc1/ct3",
        )
        return ctx

    other_seed = seed32("other-static")
    other_pk = xwing_pk(other_seed)
    ctx = fresh_fc1()
    expect_refusal("promotion_commitment_mismatch", lambda: responder_promote(ctx["rst"], other_pk, ct3p_rand))
    refusals.append({
        "name": "promotion_different_static", "base": "first_contact_unbound_static",
        "side": "responder_promote", "promote_static_seed": hx(other_seed),
        "promote_encaps_rand": hx(ct3p_rand), "error": "promotion_commitment_mismatch",
    })
    rctx = dict(mctx["rst"])
    expect_refusal("not_promotable", lambda: responder_promote(rctx, mctx["pk_si"], ct3p_rand))
    refusals.append({
        "name": "promotion_of_mutual_link", "base": "mutual", "side": "responder_promote",
        "promote_static_seed": hx(mctx["sk_si"]), "promote_encaps_rand": hx(ct3p_rand),
        "error": "not_promotable",
    })
    ctx = fresh_fc1()
    responder_promote(ctx["rst"], ctx["pk_si"], ct3p_rand)
    expect_refusal("ctkc_mismatch", lambda: check_ctkc(ctx["ctkc"], ctx["rst"]["k_conf_p"], ctx["rst"]["h3p"]))
    refusals.append({
        "name": "promotion_old_ctkc", "base": "first_contact_unbound_static",
        "side": "responder_confirm_promotion", "ctkc": hx(ctx["ctkc"]), "error": "ctkc_mismatch",
    })
    ctx = fresh_fc1()
    expect_refusal("truncated", lambda: initiator_on_promote(ctx["ilink"], msg3[:-1], ctx["sk_si"]))
    refusals.append({
        "name": "msg3_truncated", "base": "first_contact_unbound_static",
        "side": "initiator_on_promote", "msg3": hx(msg3[:-1]), "error": "truncated",
    })
    ctx = fresh_fc1()
    expect_refusal("trailing_bytes", lambda: initiator_on_promote(ctx["ilink"], msg3 + b"\x00", ctx["sk_si"]))
    refusals.append({
        "name": "msg3_trailing", "base": "first_contact_unbound_static",
        "side": "initiator_on_promote", "msg3": hx(msg3 + b"\x00"), "error": "trailing_bytes",
    })

    # Framing refusals.
    parts = encode_parts(m1, 400)

    def add_frame(name, ps, code):
        expect_refusal(code, lambda: reassemble(ps))
        refusals.append({"name": name, "side": "reassemble", "parts": [hx(p) for p in ps], "error": code})

    add_frame("ctkx_v1", [b"CTKX\x01" + parts[0][5:]] + parts[1:], "framing_v1_refused")
    add_frame("ctkx_v3", [b"CTKX\x03" + parts[0][5:]] + parts[1:], "framing_version_unsupported")
    add_frame("ctkx_bad_magic", [b"CTKY" + parts[0][4:]] + parts[1:], "framing_malformed")
    add_frame("ctkx_part_kind", [parts[0]] + [parts[1][:5] + b"\x02" + parts[1][6:]] + parts[2:], "framing_part_kind")
    add_frame("ctkx_too_large", [b"CTKX\x02\x00" + u32(8193) + parts[0][10:]], "framing_too_large")
    add_frame("ctkx_continuation_first", parts[1:], "framing_out_of_order")
    add_frame("ctkx_missing_part", parts[:-1], "truncated")
    add_frame("ctkx_overrun", parts[:-1] + [parts[-1] + b"\x00"], "trailing_bytes")

    doc = {
        "description": (
            "CC 5.3.3.10 link handshake CTKX v2 (docs/TRANSIT_HANDSHAKE_V2.md), suite "
            "transit_xwing_hkdf_sha256. Generated by gen.py independently of the Rust; "
            "all lengths big-endian. Key ids are UTF-8 bytes."
        ),
        "suite": SUITE.decode(),
        "self_check": {
            "xwing_draft_11_cases": n_xwing,
            "hkdf_rfc5869": ["A.1", "A.3"],
        },
        "handshakes": [mutual, fc0, fc1],
        "promotions": [promotion],
        "framing": framing,
        "refusals": refusals,
    }
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    print(
        f"wrote {OUT}: {len(doc['handshakes'])} handshakes, {len(doc['promotions'])} promotion, "
        f"{len(framing)} framing, {len(refusals)} refusals",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
