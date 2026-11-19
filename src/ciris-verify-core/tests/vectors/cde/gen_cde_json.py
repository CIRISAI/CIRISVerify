#!/usr/bin/env python3
"""
gen_cde_json.py: known answers for JSON -> CDE (CC 2.7.11) and the derived digests CEG-call/2, CEG-review/2 and
CEG-profile/2, written to cde_json_v1.json beside it.

Independent of CIRISVerify's Rust: its own CBOR encoder (RFC 8949 4.2.1 deterministic: shortest heads, map keys in
the bytewise order of their encodings) and Python's Decimal for numbers. The number rule: an integral value within
[-2^64, 2^64 - 1] is that integer; a non-integral value is tag 4 [exponent, mantissa] normalised (negative
exponent, mantissa not divisible by 10); anything outside the range is refused, number_unrepresentable.

    python3 -I gen_cde_json.py      (re-writes cde_json_v1.json)
"""
import hashlib
import json
import os
from decimal import Decimal

HERE = os.path.dirname(os.path.abspath(__file__))
LO, HI = -(1 << 64), (1 << 64) - 1


class Unrep(Exception):
    pass


class Tag:
    def __init__(self, n, v):
        self.n, self.v = n, v


def head(major, n):
    m = major << 5
    if n < 24:
        return bytes([m | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([m | ai]) + n.to_bytes(size, "big")
    raise Unrep


def enc(v):
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        if not LO <= v <= HI:
            raise Unrep
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted((enc(k), enc(x)) for k, x in v.items())
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return head(6, v.n) + enc(v.v)
    raise TypeError(v)


def number(d):
    """A JSON number (as an exact Decimal) under CC 2.7.11."""
    if d == 0:
        return 0
    sign, digits, exp = d.as_tuple()
    m = int("".join(map(str, digits)))
    while m % 10 == 0:
        m //= 10
        exp += 1
    if exp >= 0:
        v = m * 10 ** exp if exp < 100 else None
        if v is None or v > (1 << 64):
            raise Unrep
        v = -v if sign else v
        if not LO <= v <= HI:
            raise Unrep
        return v
    m = -m if sign else m
    if not LO <= m <= HI or exp < LO:
        raise Unrep
    return Tag(4, [exp, m])


def to_value(x):
    if isinstance(x, Decimal):
        return number(x)
    if isinstance(x, list):
        return [to_value(y) for y in x]
    if isinstance(x, dict):
        return {to_value(k): to_value(y) for k, y in x.items()}
    if isinstance(x, str):
        try:
            x.encode("utf-8")   # a lone surrogate is not text
        except UnicodeEncodeError as e:
            raise ValueError("lone surrogate") from e
    return x


def no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def no_constant(name):
    raise ValueError(f"not JSON: {name}")


def from_json(text):
    return to_value(json.loads(text, parse_float=Decimal, parse_int=Decimal, parse_constant=no_constant,
                               object_pairs_hook=no_dupes))


def digest(tag, members):
    return hashlib.sha256(enc([tag] + members)).digest()


def dv(d):
    return [-16, d]


JSON_CASES = [
    ("integer", "7"), ("negative", "-12"), ("2^32", "4294967296"), ("max", "18446744073709551615"),
    ("min", "-18446744073709551616"), ("over max", "18446744073709551616"), ("under min", "-18446744073709551617"),
    ("exponent integral", "1e2"), ("integral with fraction text", "2.0"), ("2^53+1 exact", "9007199254740993.0"),
    ("negative zero", "-0.0"), ("zero exponent", "0e999999"), ("half", "0.5"), ("1.25", "1.25"),
    ("trailing zero", "1.10"), ("small", "1e-3"), ("negative fraction", "-2.5"), ("0.1", "0.1"),
    ("halfway above one", "1.00000000000000011102230246251565404236316680908203125"),
    ("1e300", "1e300"), ("1e400", "1e400"), ("tiny", "1e-400"),
    ("mantissa max", "0.18446744073709551615"), ("mantissa over", "0.18446744073709551616"),
    ("map, keys out of order", '{"b": 1, "a": [true, false, null], "aa": "x"}'),
    ("nested", '{"z": {"y": {"x": -1.5}}, "a": []}'),
    ("escapes", '"tab\\tquote\\"slash\\/u\\u00e9 pair\\ud83d\\ude00"'),
    ("empty", "{}"),
]
REFUSE_SYNTAX = [
    ("duplicate key", '{"a": 1, "a": 2}'), ("leading zero", "01"), ("bare dot", "1."), ("plus sign", "+1"),
    ("NaN", "NaN"), ("Infinity", "Infinity"), ("lone surrogate", '"\\ud800"'), ("trailing comma", "[1,]"),
    ("control character", '"a\nb"'), ("two values", "1 2"),
]
DECODE_REFUSALS = [
    ("tag 4, positive exponent", enc(Tag(4, [1, 5]))),
    ("tag 4, zero exponent", enc(Tag(4, [0, 5]))),
    ("tag 4, mantissa divisible by ten", enc(Tag(4, [-2, 10]))),
    ("tag 4, zero mantissa", enc(Tag(4, [-1, 0]))),
    ("tag 4, not a pair", enc(Tag(4, [-1]))),
    ("tag 4, bignum mantissa", enc(Tag(4, [-1, Tag(2, b"\x01")]))),
]


def main():
    out = {"_note": "JSON -> CDE (CC 2.7.11: no floats; integral -> int, else tag-4 decimal from the exact text) and "
                    "the derived digests; written by gen_cde_json.py, independent of CIRISVerify.",
           "json": [], "json_refusals": [], "decode_refusals": [], "call": [], "review": [], "profile": []}
    for what, text in JSON_CASES:
        try:
            out["json"].append({"what": what, "json": text, "cde_hex": enc(from_json(text)).hex()})
        except Unrep:
            out["json"].append({"what": what, "json": text, "refused": "number_unrepresentable"})
    for what, text in REFUSE_SYNTAX:
        try:
            from_json(text)
            raise SystemExit(f"accepted {what}")
        except (ValueError, json.JSONDecodeError):
            out["json_refusals"].append({"what": what, "json": text})
    for what, b in DECODE_REFUSALS:
        out["decode_refusals"].append({"what": what, "cde_hex": b.hex(), "refused": "decimal_not_normal"})
    calls = [
        ("a secret stands as its reference", "tool", "http_get", '{"url": "https://example.org/a", "token": "{SECRET:7f3c}"}', "c1"),
        ("numbers of every kind", "tool", "calc", '{"n": -3, "big": 4294967296, "x": 0.5, "y": 1.10, "z": 2.0}', ""),
        ("nested, keys out of order", "tool", "write", '{"z": {"b": null, "a": true}, "a": [1, -1.25, "s"]}', "ch"),
        ("2^53+1 exact", "tool", "t", '{"id": 9007199254740993.0}', ""),
        ("unrepresentable", "tool", "t", '{"n": 1e300}', ""),
    ]
    for what, verb, tool, args, chan in calls:
        try:
            a = from_json(args)
            m = [verb, tool, a, chan]
            out["call"].append({"what": what, "verb": verb, "tool": tool, "arguments_json": args, "channel": chan,
                                "cde_hex": enc(["CEG-call/2"] + m).hex(), "digest": digest("CEG-call/2", m).hex()})
        except Unrep:
            out["call"].append({"what": what, "verb": verb, "tool": tool, "arguments_json": args, "channel": chan,
                                "refused": "call_argument_unrepresentable"})
    fp = bytes.fromhex(out["call"][0]["digest"])
    o1 = hashlib.sha256(b"objection-1").digest()
    rows = [
        ("objection", {"fingerprint": dv(fp), "thought": "th-1", "outcome": "objected", "faculties": ["optimization_veto"]}),
        ("pass", {"fingerprint": dv(fp), "thought": "th-1", "outcome": "passed",
                  "faculties": ["coherence", "entropy", "epistemic_humility", "optimization_veto"]}),
        ("pass with discharges, considered, derived_from",
         {"fingerprint": dv(fp), "thought": "th-1", "outcome": "passed",
          "faculties": ["coherence", "entropy", "epistemic_humility", "optimization_veto"],
          "discharges": [[dv(o1), [2, dv(hashlib.sha256(b"row-1").digest())]]], "considered": [dv(o1)],
          "derived_from": ["request", "tool_output"]}),
    ]
    for what, rec in rows:
        out["review"].append({"what": what, "record_cde_hex": enc(rec).hex(),
                              "cde_hex": enc(["CEG-review/2", rec]).hex(), "digest": digest("CEG-review/2", [rec]).hex()})
    links = [hashlib.sha256(f"link-{i}".encode()).digest() for i in range(3)]
    for what, ls in (("base alone", links[:1]), ("base and two", links), ("reordered", [links[2], links[0], links[1]])):
        m = [dv(d) for d in ls]
        out["profile"].append({"what": what, "links": [d.hex() for d in ls], "cde_hex": enc(["CEG-profile/2"] + m).hex(),
                               "digest": digest("CEG-profile/2", m).hex()})
    with open(os.path.join(HERE, "cde_json_v1.json"), "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print({k: len(v) for k, v in out.items() if isinstance(v, list)})


if __name__ == "__main__":
    main()
