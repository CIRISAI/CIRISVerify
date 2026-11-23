# Independent known answers for the build-manifest blob, ciris-binary-manifest/1 (FSD-008 §6; accepted by
# CIRISConstitution 2026-11-22 for CC 3.1.2.1; schema binary_manifest_v1.cddl beside this file). CC vendors
# this file, binary_manifest_v1.cddl and binary_manifest_v1_vectors.json as manifests/binary_manifest_v1*.
#
# The blob is CC 2.6.1.2's deterministic encoding, no floats, no typ (not a signed object).
#
# The tree rule is CC 3.1.2.1's, the paragraphs beginning "A locale manifest is a Merkle tree of one leaf per
# locale" (a leaf hashed under the RFC 6962 leaf prefix 0x00, a parent SHA-256 over 0x01, left, right) and
# "Locale ordering: ... Padding: repeat the last leaf to the next power of two" (not RFC 6962's split, not CC
# 6.1.1's per-level duplication). CC carries no known answers for it, so section "merkle_tree" is generic over
# leaf byte strings, in the order given, for counts 1, 2, 3, 4, 5, 8, 96: the shared set for locale manifests
# and function tables alike. Ordering is each use's own: a function table's leaves are in the byte order of the
# names, each leaf CDE({name, offset, size, hash}) (section "function_tables").
#
# Every hash in the blob and the leaf (binary_hash, functions_root, each function's hash) is a plain bstr .size
# 32, no [-16, digest] wrapper: the format string pins SHA-256 for version 1. (In this JSON file they appear as
# *_hex.) The blob carries nothing about the run: no generated_at (refused as an unknown member), and tool names
# the generator and its version only. project / version / target are text exactly as given, compared byte for
# byte with the build row's members.
#
# Reuses gen_row_statements_v4.py's own CBOR deterministic encoder (RFC 8949 4.2.1 bytewise key order; loaded
# with its output discarded); the Merkle tree and every expectation are computed here with hashlib. Shares no
# code with verify.
#   python3 -I gen_binary_manifest_v1.py > binary_manifest_v1_vectors.json
import contextlib, hashlib, io, json, os, runpy, struct

here = os.path.dirname(os.path.abspath(__file__))
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(os.path.dirname(here), "gen_row_statements_v4.py"))
enc, Tag = g["enc"], g["Tag"]

FORMAT = "ciris-binary-manifest/1"
MAX_BLOB_LEN = 1 << 20
sha = lambda b: hashlib.sha256(b).digest()


def fn(name, i):
    return {"name": name, "offset": 0x1000 + 0x40 * i, "size": 0x40 + i, "hash": sha(b"fn:" + name.encode())}


def names(n):
    if n == 2:
        return ["ciris_verify_b", "ciris_verify_aa"]   # CDE key order is "b" first, name byte order "aa" first
    return [f"ciris_verify_f{i}" for i in range(n)]    # "f10" < "f2" by bytes, "f2" first in CDE order


def jleaf(f):   # a leaf in JSON: the hash as hex (it is a bstr .size 32 in CBOR)
    return {"name": f["name"], "offset": f["offset"], "size": f["size"], "hash_hex": f["hash"].hex()}


def leaf_bytes(f):
    return enc({"name": f["name"], "offset": f["offset"], "size": f["size"], "hash": f["hash"]})


def tree_levels(leaf_strings):
    """Every level of the tree over leaf byte strings in the given order, leaf hashes (padded) first."""
    layer = [sha(b"\x00" + x) for x in leaf_strings]
    size = 1
    while size < len(layer):
        size *= 2
    layer += [layer[-1]] * (size - len(layer))
    levels = [layer]
    while len(layer) > 1:
        layer = [sha(b"\x01" + layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        levels.append(layer)
    return levels


def root_of(fs):
    leaves = sorted(fs, key=lambda f: f["name"].encode())
    layer = [sha(b"\x00" + leaf_bytes(f)) for f in leaves]
    size = 1
    while size < len(layer):
        size *= 2
    layer += [layer[-1]] * (size - len(layer))
    while len(layer) > 1:
        layer = [sha(b"\x01" + layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def table(fs):
    return {f["name"]: {"offset": f["offset"], "size": f["size"], "hash": f["hash"]} for f in fs}


def blob(fs, inline=True, **edit):
    b = {"format": FORMAT, "project": "ciris-server", "version": "0.6.0", "target": "aarch64-apple-darwin",
         "binary_hash": sha(b"final file"), "functions_root": root_of(fs), "tool": "ciris-manifest-tool/23.6.0"}
    if inline:
        b["functions"] = table(fs)
    for k, v in edit.items():
        if v is DROP:
            b.pop(k)
        else:
            b[k] = v
    return b


DROP = object()


def tables():
    out = {}
    for n in (1, 2, 3, 5, 96):
        fs = [fn(nm, i) for i, nm in enumerate(names(n))]
        if n == 5:   # every uint head width, and offset 0
            for f, (o, s) in zip(fs, ((0, 1), (23, 24), (255, 256), (65535, 65536), (1 << 32, (1 << 40) + 7))):
                f["offset"], f["size"] = o, s
        out[n] = fs
    return out


T = tables()

# The generic tree: leaf i is the bytes of "leaf " + i, given in order (so leaf 10 follows leaf 9: no sort).
tree = []
for n in (1, 2, 3, 4, 5, 8, 96):
    leaves = [f"leaf {i}".encode() for i in range(n)]
    lv = tree_levels(leaves)
    c = {"id": f"tree_{n}", "leaf_count": n, "padded_to": len(lv[0]), "leaves_hex": [x.hex() for x in leaves],
         "leaf_hashes_hex": [h.hex() for h in lv[0][:n]], "root_hex": lv[-1][0].hex()}
    if n <= 8:
        c["levels_hex"] = [[h.hex() for h in l] for l in lv]
    tree.append(c)
# The padding pins: 3 leaves is node(node(h0, h1), node(h2, h2)), 5 repeats h4 three times.
h = lambda x: sha(b"\x00" + x)
nd = lambda a, b: sha(b"\x01" + a + b)
L3 = [h(f"leaf {i}".encode()) for i in range(3)]
assert tree[2]["root_hex"] == nd(nd(L3[0], L3[1]), nd(L3[2], L3[2])).hex()
assert tree[0]["root_hex"] == h(b"leaf 0").hex()

merkle = []
for n, fs in T.items():
    leaves = sorted(fs, key=lambda f: f["name"].encode())
    assert tree_levels([leaf_bytes(f) for f in leaves])[-1][0] == root_of(fs)
    merkle.append({"id": f"functions_{n}", "leaf_count": n, "padded_to": 1 << (n - 1).bit_length(),
                   "functions": [jleaf(f) for f in leaves],
                   "leaf_bytes_hex": [leaf_bytes(f).hex() for f in leaves],
                   "leaf_hashes_hex": [sha(b"\x00" + leaf_bytes(f)).hex() for f in leaves],
                   "root_hex": root_of(fs).hex()})


def expect_of(fs, inline):
    return {"project": "ciris-server", "version": "0.6.0", "target": "aarch64-apple-darwin",
            "binary_hash_hex": sha(b"final file").hex(), "functions_root_hex": root_of(fs).hex(),
            "functions": [jleaf(f) for f in sorted(fs, key=lambda f: f["name"].encode())] if inline else None,
            "tool": "ciris-manifest-tool/23.6.0"}


valid = []
for n, fs in T.items():
    for inline in (True, False):
        b = enc(blob(fs, inline))
        valid.append({"id": f"{'inline' if inline else 'root_only'}_{n}",
                      "description": f"{n} function(s), {'table inline' if inline else 'root only, no table'}.",
                      "blob_hex": b.hex(), "blob_len": len(b), "expect": expect_of(fs, inline)})

refusals = []


def refuse(cid, desc, b, token, detail=None):
    r = {"id": cid, "description": desc, "blob_hex": b.hex(), "expect": token}
    if detail is not None:
        r["detail"] = detail
    refusals.append(r)


F3 = T[3]
ok = lambda **e: enc(blob(F3, **e))

# Members.
refuse("unknown_member", "A member the blob does not admit.", ok(extra="x"), "build_manifest_unknown_member", "blob")
refuse("unknown_int_key", "An integer key.", enc({**blob(F3), 1: 2}), "build_manifest_unknown_member", "blob")
refuse("typ_member", "A typ: the blob is not a signed object.", ok(typ="ciris-binary-manifest/1"),
       "build_manifest_unknown_member", "blob")
refuse("text_section_offset_member", "No offset metadata rides the blob (Q16).", ok(text_section_offset=4096),
       "build_manifest_unknown_member", "blob")
t = table(F3)
t["ciris_verify_f0"]["first_bytes"] = "00"
refuse("unknown_entry_member", "A function entry with a member it does not admit (first_bytes).", ok(functions=t),
       "build_manifest_unknown_member", "function")
t = table(F3)
t["ciris_verify_f0"]["name"] = "ciris_verify_f0"
refuse("entry_name_duplicate_member", "The entry repeats its name: the map key is the name.", ok(functions=t),
       "build_manifest_unknown_member", "function")
for m in ("project", "version", "target", "binary_hash", "functions_root", "tool"):
    refuse(f"missing_{m}", f"No {m}.", ok(**{m: DROP}), "build_manifest_missing_member", m)
refuse("missing_format", "No format.", ok(format=DROP), "build_manifest_missing_member", "format")
for m in ("offset", "size", "hash"):
    t = table(F3)
    del t["ciris_verify_f1"][m]
    refuse(f"missing_entry_{m}", f"A function entry with no {m}.", ok(functions=t), "build_manifest_missing_member", m)

# Format, read first.
refuse("wrong_format", "Another format string.", ok(format="ciris-binary-manifest/2"), "build_manifest_wrong_format")
refuse("format_not_text", "format as an integer.", ok(format=1), "build_manifest_wrong_format")
refuse("wrong_format_before_unknown", "format is read before the member set: another format with an unknown member "
       "is the wrong format.", ok(format="ciris-function-manifest/1", extra=1), "build_manifest_wrong_format")
refuse("missing_format_before_unknown", "No format and an unknown member: format is read first.",
       ok(format=DROP, extra=1), "build_manifest_missing_member", "format")

# Not a map.
refuse("top_level_array", "The top level is an array.", enc([FORMAT]), "build_manifest_not_a_map")

# Not the deterministic encoding.
good = ok()
assert good[0] == 0xa8   # eight members
refuse("non_deterministic_keys_out_of_order", "Map keys in insertion order, not the bytewise order of their "
       "encodings (format before tool).",
       b"\xa8" + b"".join(enc(k) + enc(v) for k, v in blob(F3).items()), "build_manifest_not_deterministic")
refuse("non_deterministic_long_head", "The top-level map head in a non-shortest form (0xb8 0x08).",
       b"\xb8\x08" + good[1:], "build_manifest_not_deterministic")
refuse("non_deterministic_indefinite", "An indefinite-length map.", b"\xbf" + good[1:] + b"\xff",
       "build_manifest_not_deterministic")
refuse("trailing_bytes", "A byte after the blob.", good + b"\x00", "build_manifest_not_deterministic")
big = (1 << 32) + 0x1234
w = ok(functions={**table(F3), "ciris_verify_f0": {"offset": big, "size": 1, "hash": bytes(32)}})
eight = b"\x1b" + big.to_bytes(8, "big")
assert w.count(eight) == 1
refuse("non_deterministic_uint_head", "An offset of 0x1234 written with an eight-byte head.",
       w.replace(eight, b"\x1b" + (0x1234).to_bytes(8, "big")), "build_manifest_not_deterministic")

# Floats.
refuse("float_offset", "An offset written as a double (1.5).", w.replace(eight, b"\xfb" + struct.pack(">d", 1.5)),
       "build_manifest_float")
tl = enc("ciris-manifest-tool/23.6.0")
assert ok().count(tl) == 1
refuse("float_tool", "tool as a half float.", ok().replace(tl, b"\xf9\x3c\x00"), "build_manifest_float")

# Member types and ranges.
bh = sha(b"final file")
refuse("binary_hash_hex", "binary_hash as hex text: hashes are bstr .size 32.", ok(binary_hash=bh.hex()),
       "build_manifest_malformed", "binary_hash")
refuse("binary_hash_prefixed", "binary_hash as the sha256:-prefixed text of the JSON manifests.",
       ok(binary_hash="sha256:" + bh.hex()), "build_manifest_malformed", "binary_hash")
refuse("binary_hash_31", "binary_hash of 31 bytes.", ok(binary_hash=bh[:31]), "build_manifest_malformed",
       "binary_hash")
refuse("binary_hash_33", "binary_hash of 33 bytes.", ok(binary_hash=bh + b"\x00"), "build_manifest_malformed",
       "binary_hash")
refuse("binary_hash_digest_wrapper", "binary_hash as a [-16, digest] hash-digest: no wrapper, the format pins SHA-256.",
       ok(binary_hash=[-16, bh]), "build_manifest_malformed", "binary_hash")
refuse("functions_root_31", "functions_root of 31 bytes.", ok(functions_root=b"\x00" * 31), "build_manifest_malformed",
       "functions_root")
refuse("functions_root_hex", "functions_root as hex text.", ok(functions_root=root_of(F3).hex()),
       "build_manifest_malformed", "functions_root")
refuse("project_upper", "project outside [a-z0-9-].", ok(project="CIRIS-server"), "build_manifest_malformed", "project")
refuse("project_long", "project of 65 bytes.", ok(project="a" * 65), "build_manifest_malformed", "project")
refuse("version_empty", "An empty version.", ok(version=""), "build_manifest_malformed", "version")
refuse("version_long", "version of 65 bytes.", ok(version="1" * 65), "build_manifest_malformed", "version")
refuse("target_space", "A target with a space.", ok(target="aarch64 apple"), "build_manifest_malformed", "target")
refuse("tool_empty", "An empty tool.", ok(tool=""), "build_manifest_malformed", "tool")
refuse("generated_at_member", "A generated_at: the blob carries nothing about the run.",
       ok(generated_at="2026-11-22T00:00:00Z"), "build_manifest_unknown_member", "blob")
t = table(F3)
t["ciris_verify_f1"]["offset"] = -1
refuse("offset_negative", "A negative offset.", ok(functions=t), "build_manifest_malformed", "offset")
t = table(F3)
t["ciris_verify_f1"]["size"] = Tag(4, [-1, 15])
refuse("size_decimal", "A size as a tag-4 decimal (1.5): normalised, so deterministic, but not a uint.",
       ok(functions=t), "build_manifest_malformed", "size")
t = table(F3)
t["ciris_verify_f1"]["hash"] = t["ciris_verify_f1"]["hash"].hex()
refuse("entry_hash_hex", "A function hash as hex text.", ok(functions=t), "build_manifest_malformed", "hash")
t = table(F3)
t["ciris_verify_f1"]["hash"] = t["ciris_verify_f1"]["hash"][:31]
refuse("entry_hash_31", "A function hash of 31 bytes.", ok(functions=t), "build_manifest_malformed", "hash")
t = table(F3)
t["ciris_verify_f1"]["hash"] = [-16, t["ciris_verify_f1"]["hash"]]
refuse("entry_hash_digest_wrapper", "A function hash as a [-16, digest] hash-digest.", ok(functions=t),
       "build_manifest_malformed", "hash")
refuse("functions_array", "functions as an array.", ok(functions=[1]), "build_manifest_malformed", "functions")
refuse("function_name_int", "A function keyed by an integer.", ok(functions={1: table(F3)["ciris_verify_f0"]}),
       "build_manifest_malformed", "functions")
refuse("function_name_empty", "A function with an empty name.", ok(functions={"": table(F3)["ciris_verify_f0"]}),
       "build_manifest_malformed", "functions")

# The table and its root.
refuse("functions_empty", "A table of zero functions.", ok(functions={}), "build_manifest_empty_functions")
refuse("root_mismatch_root", "functions_root differs from the inline table's root.",
       ok(functions_root=bytes([root_of(F3)[0] ^ 1]) + root_of(F3)[1:]), "build_manifest_functions_root_mismatch")
t = table(F3)
t["ciris_verify_f2"]["size"] += 1
refuse("root_mismatch_entry", "One entry's size changed under the same root.", ok(functions=t),
       "build_manifest_functions_root_mismatch")
refuse("root_mismatch_order", "A root computed over the leaves in CDE key order instead of name byte order.",
       ok(functions=table(T[2]), functions_root=(lambda ls: sha(b"\x01" + ls[0] + ls[1]))(
           [sha(b"\x00" + leaf_bytes(f)) for f in sorted(T[2], key=lambda f: enc(f["name"]))])),
       "build_manifest_functions_root_mismatch")
refuse("root_mismatch_rfc6962_split", "A 3-leaf root under RFC 6962's split instead of last-leaf padding.",
       ok(functions_root=(lambda h: sha(b"\x01" + sha(b"\x01" + h[0] + h[1]) + h[2]))(
           [sha(b"\x00" + leaf_bytes(f)) for f in sorted(F3, key=lambda f: f["name"].encode())])),
       "build_manifest_functions_root_mismatch")

# Size. Given as head + a run of one byte + tail, so the file stays small.
def run_case(cid, desc, total, token, detail=None):
    pre = enc(blob(F3, tool=""))   # tool is the first key: its text head and bytes come first
    k = total - len(pre) - 4   # text of k bytes: head 0x7a + 4-byte length
    b = enc(blob(F3, tool="a" * k))
    assert len(b) == total and b[1:6] == enc("tool") and b[6] == 0x7a
    head, tail = b[:11], b[11 + k:]
    assert b[11:11 + k] == b"a" * k
    r = {"id": cid, "description": desc, "blob": {"head_hex": head.hex(), "run_byte_hex": "61", "run_len": k,
                                                    "tail_hex": tail.hex()}, "blob_len": total, "expect": token}
    if detail is not None:
        r["detail"] = detail
    refusals.append(r)


run_case("oversize", f"A blob of {MAX_BLOB_LEN + 1} bytes: refused before decoding.", MAX_BLOB_LEN + 1,
         "build_manifest_oversize")
run_case("at_cap_not_oversize", f"A blob of exactly {MAX_BLOB_LEN} bytes is decoded (and refused for its long tool).",
         MAX_BLOB_LEN, "build_manifest_malformed", "tool")

ids = [c["id"] for c in valid + refusals + merkle + tree]
assert len(ids) == len(set(ids))
print(json.dumps({
    "description": "ciris-binary-manifest/1 known answers (FSD-008 §6, CC 3.1.2.1 as accepted 2026-11-22): valid "
                   "blobs with and without the inline table, functions_root per leaf count, and refusals by token.",
    "format": FORMAT,
    "max_blob_len": MAX_BLOB_LEN,
    "merkle_rule": "CC 3.1.2.1 (\"A locale manifest is a Merkle tree of one leaf per locale\"; \"Locale ordering: ... "
                   "Padding: repeat the last leaf to the next power of two\"): leaf SHA-256(0x00 || leaf); node "
                   "SHA-256(0x01 || left || right); a non-power-of-two count padded by repeating the last leaf to the "
                   "next power of two. merkle_tree: generic over leaf byte strings in the order given. "
                   "function_tables: leaves in name byte order, each CDE({name, offset, size, hash}).",
    "generator": "gen_binary_manifest_v1.py",
    "merkle_tree": tree,
    "function_tables": merkle,
    "valid": valid,
    "refusals": refusals,
}, indent=1))
