# Independent known answers for `stream:head` (CC rc22 5.3.3.8, as agreed by verify, Edge, persist and CC):
# the row's own payload rule (the door), a service's successor rule (keyed on its own last head for the sub;
# consistency decides; refs.prev judged only when the service holds the named head; a first head registers),
# and a verifier's check of the head's room against the stream's binding. It shares no code with verify: its
# own CBOR encoder (copied from the genesis generators) and its own RFC 9162 tree.
#
#   python3 -I gen_stream_heads.py > stream_heads_v1.json
import hashlib, json, sys


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
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)


sha = lambda b: hashlib.sha256(b).digest()
lh = lambda b: sha(b"\x00" + b)
nh = lambda a, b: sha(b"\x01" + a + b)


def mth(hs):
    if len(hs) == 1: return hs[0]
    k = 1
    while k * 2 < len(hs): k *= 2
    return nh(mth(hs[:k]), mth(hs[k:]))


def subproof(m, d, b):
    n = len(d)
    if m == n: return [] if b else [mth(d)]
    k = 1
    while k * 2 < n: k *= 2
    return subproof(m, d[:k], b) + [mth(d[k:])] if m <= k else subproof(m - k, d[k:], False) + [mth(d[:k])]


IREF = "urn:ietf:params:oauth:ckt:sha-256:"
PRODUCER = IREF + "P" * 43
STREAM = "av-" + "ab" * 32
SUB = "stream:" + STREAM
ROOM = "community-kat-room"
CHUNKS = [lh(b"chunk %d" % i) for i in range(12)]
root = lambda n: mth(CHUNKS[:n])
hd = lambda d: [-16, d]
rref = lambda d: [2, hd(d)]


def payload(size, epoch=1, sealed=None, room=ROOM, prev=None, edit=None):
    p = {"author": PRODUCER, "asserted_at": 1767312000000 + size, "epoch": epoch, "tree_size": size, "root": hd(root(size))}
    if sealed is not None: p["sealed"] = sealed
    if room is not None: p["room"] = room
    if prev is not None: p["refs"] = {"prev": rref(prev)}
    if edit: edit(p)
    return p


door = []


def dcase(cid, desc, p, sub, expect):
    door.append({"id": cid, "description": desc, "payload_hex": enc(p).hex(), "sub": sub, "expect": expect})


H4, H8 = sha(b"head 4"), sha(b"head 8")
dcase("accountable", "An accountable head: a room names its receipt policy.", payload(4), SUB, "ok")
dcase("best_effort", "A best-effort head: no room.", payload(4, room=None), SUB, "ok")
dcase("with_prev_sealed", "A sealing head naming its previous head.", payload(8, epoch=2, sealed=True, prev=H4), SUB, "ok")
dcase("file_stream", "A file delivery stream's head: its own id spelling under stream:, no room.",
      payload(1, room=None), "stream:file-" + "cd" * 16, "ok")
dcase("sub_bare_hex", "sub names a bare 64-hex id: that space is the inline-blob log's.", payload(4), "stream:" + "ab" * 32,
      "malformed:sub")
dcase("sub_no_prefix", "sub without the stream: prefix.", payload(4), STREAM, "malformed:sub")
dcase("tree_size_zero", "tree_size 0.", payload(4, edit=lambda p: p.__setitem__("tree_size", 0)), SUB, "malformed:tree_size")
dcase("sealed_false", "sealed is only ever true.", payload(4, sealed=False), SUB, "malformed:sealed")
dcase("room_empty", "An empty room.", payload(4, room=""), SUB, "malformed:room")
dcase("refs_target", "refs carries a target.", payload(4, edit=lambda p: p.__setitem__("refs", {"target": rref(H4)})), SUB,
      "unexpected:refs")
dcase("unknown_member", "A profile member: not in the closed payload.", payload(4, edit=lambda p: p.__setitem__("profile", 1)),
      SUB, "unexpected:stream-head")
dcase("root_raw", "root as raw bytes, not a hash-digest.", payload(4, edit=lambda p: p.__setitem__("root", root(4))), SUB,
      "malformed:root")
dcase("author_label", "author as a bare label, not an identity reference.",
      payload(4, edit=lambda p: p.__setitem__("author", "producer")), SUB, "malformed:author")

succ = []
L4 = {"row_id": H4.hex(), "epoch": 1, "tree_size": 4, "root": root(4).hex(), "sealed": False}
L4S = dict(L4, sealed=True)


def scase(cid, desc, last, size, epoch=1, sealed=False, prev=None, holds=(), proof=None, recomputed=None, new_root=None,
          expect="ok"):
    c = {"id": cid, "description": desc, "last": last,
         "head": {"tree_size": size, "epoch": epoch, "sealed": sealed, "root": (new_root or root(size)).hex(),
                  "prev": prev.hex() if prev else None},
         "holds": [h.hex() for h in holds], "expect": expect}
    if recomputed is not None: c["recomputed"] = [x.hex() for x in recomputed]
    else: c["proof"] = [h.hex() for h in (proof if proof is not None else subproof(4, CHUNKS[:size], True) if size > 4 else [])]
    succ.append(c)


scase("first", "No last head: the service registers this as its first, with any prev.", None, 8, prev=H4)
scase("extends", "Size 4 -> 8, consistency proof, prev names the last head.", L4, 8, prev=H4, holds=[H4])
scase("missed_one", "The producer's prev is a head the service never saw: carried, not judged; consistency decides.",
      L4, 12, prev=H8, holds=[H4], proof=subproof(4, CHUNKS[:12], True))
scase("prev_not_last", "prev names a held head that is not the service's last.", L4, 8, prev=H8, holds=[H4, H8],
      expect="stream_head_prev_not_last")
scase("epoch_regressed", "The epoch drops from 1 to 0.", L4, 8, epoch=0, expect="stream_head_epoch_regressed")
scase("sealing_repeat", "The sealing head repeats size 4 with the identical root.", L4, 4, sealed=True)
scase("repeat_not_sealed", "Size 4 again with the identical root, not sealing.", L4, 4, expect="stream_head_repeated")
scase("equivocation", "Size 4 again with another root.", L4, 4, sealed=True, new_root=sha(b"other"),
      expect="stream_head_equivocation")
scase("smaller", "A head at size 3 after size 4.", L4, 3, expect="stream_head_inconsistent")
scase("bad_proof", "Size 8 with a proof for 5 -> 8.", L4, 8, proof=subproof(5, CHUNKS[:8], True), expect="stream_head_inconsistent")
scase("forked_root", "Size 8 with a root that does not extend the last.", L4, 8, new_root=mth(CHUNKS[:3] + [lh(b"x")] + CHUNKS[4:8]),
      expect="stream_head_inconsistent")
scase("after_seal", "The service registered the sealing head at size 4: a later head at size 8 is refused.", L4S, 8,
      expect="stream_head_after_seal")
scase("recomputed_ok", "A holder recomputed both roots from its chunks.", L4, 8, recomputed=(root(4), root(8)))
scase("recomputed_differs", "A holder's own root for size 8 differs from the head's.", L4, 8,
      recomputed=(root(4), mth(CHUNKS[:7] + [lh(b"y")])), expect="stream_head_inconsistent")

binding = [{"id": "accountable_match", "profile": 1, "binding_room": ROOM, "payload_hex": enc(payload(4)).hex(), "expect": "ok"},
           {"id": "accountable_other_room", "profile": 1, "binding_room": "another-room", "payload_hex": enc(payload(4)).hex(),
            "expect": "stream_head_room_mismatch"},
           {"id": "accountable_no_room", "profile": 1, "binding_room": ROOM, "payload_hex": enc(payload(4, room=None)).hex(),
            "expect": "stream_head_room_mismatch"},
           {"id": "best_effort_ok", "profile": 0, "binding_room": ROOM, "payload_hex": enc(payload(4, room=None)).hex(), "expect": "ok"},
           {"id": "best_effort_names_room", "profile": 0, "binding_room": ROOM, "payload_hex": enc(payload(4)).hex(),
            "expect": "stream_head_room_mismatch"}]

json.dump({"_meta": {"spec": "CC rc22 5.3.3.8 stream:head, as agreed by verify, Edge, persist and CC",
                     "generator": "gen_stream_heads.py (independent of verify)", "sub": SUB,
                     "chunks": "leaf hash i = SHA-256(0x00 || 'chunk i'), i = 0..11"},
           "door": door, "successor": succ, "binding": binding}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
