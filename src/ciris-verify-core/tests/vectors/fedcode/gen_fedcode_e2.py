# Independent known answers for the edition-2 FedCode (CIRIS-V4-), the layout verify proposes for
# CC 2.6.8 rc22: a code over the composite key's thumbprint (CC 2.6.1.7, 2.6.1.12), embedding nodes
# with their full RNS transport identity (X25519 || Ed25519, CC 3.3.6.2) and an ordered list of typed
# dial hints. It shares no code with verify: its own CRC-16, base32 and CBOR for the COSE_Key thumbprint,
# dilithium-py (ML-DSA-65) and pyca/cryptography (Ed25519, X25519).
#
#   python3 -I gen_fedcode_e2.py > fedcode_e2_v1.json
#
# Payload (before the CRC), all integers big-endian:
#   version(1)=0x04 | kind(1) | kid(32)
#   kind=user:              node_count(1) 0..=4 | node_count x ( node_kid(32) | endpoint )
#   kind=node:              endpoint                       (the node the kid names)
#   kind=agent/family/community: nothing                   (any byte after kid: fedcode_nodes_not_user)
#   endpoint = transport_identity(64: x25519 32 | ed25519 32) | hint_count(1) 0..=4 | hint_count x hint
#   hint     = type(1) | len(1) | body(len)        an ordered sequence, most preferred first
# then CRC-16-CCITT (poly 0x1021, init 0xFFFF, no xor) of the payload, 2 bytes; RFC 4648 base32 of
# payload || crc (no padding); prefix CIRIS-V4-; displayed in dash-separated groups of 4, the QR form
# ungrouped. Payload <= 1024 bytes.
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
from dilithium_py.ml_dsa import ML_DSA_65

RAW = (ser.Encoding.Raw, ser.PublicFormat.Raw)
VERSION, PREFIX, MAX_PAYLOAD, MAX_NODES, MAX_HINTS = 4, "CIRIS-V4-", 1024, 4, 8
KINDS = {"user": 1, "agent": 2, "node": 3, "family": 4, "community": 5}
TCP, UDP, AUTO, RNODE, HTTP, I2P, KISS, BLE = 1, 2, 3, 4, 5, 6, 7, 8
SCOPES = ["link", "admin", "site", "organisation", "global"]


def crc16(b):
    c = 0xFFFF
    for x in b:
        c ^= x << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def b32(b): return base64.b32encode(b).decode().rstrip("=")


def render(payload):
    s = b32(payload + crc16(payload).to_bytes(2, "big"))
    return PREFIX + "-".join(s[i:i + 4] for i in range(0, len(s), 4)), PREFIX + s


def cbor_cose_key(pub):          # {1: 7, 3: -70100, -1: pub}, deterministic (keys 1, 3, -1)
    assert len(pub) == 1984
    return bytes([0xa3, 0x01, 0x07, 0x03, 0x3a]) + (70099).to_bytes(4, "big") + b"\x20\x59" + len(pub).to_bytes(2, "big") + pub


class Party:
    """A composite federation key (ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32) and, for a node, a
    transport identity (X25519 seed [n+150]*32, Ed25519 seed [n+200]*32)."""
    def __init__(self, n):
        ml_pk, _ = ML_DSA_65.key_derive(bytes([n]) * 32)
        self.fed_ed = Ed25519PrivateKey.from_private_bytes(bytes([n + 100]) * 32).public_key().public_bytes(*RAW)
        self.composite = ml_pk + self.fed_ed
        self.kid = hashlib.sha256(cbor_cose_key(self.composite)).digest()
        x = X25519PrivateKey.from_private_bytes(bytes([n + 150]) * 32).public_key().public_bytes(*RAW)
        e = Ed25519PrivateKey.from_private_bytes(bytes([n + 200]) * 32).public_key().public_bytes(*RAW)
        self.transport = x + e


U, AG, FAM, COM = Party(1), Party(2), Party(4), Party(5)
N = [Party(11 + i) for i in range(5)]


def hint(t, body): return bytes([t, len(body)]) + body
def tcp(host, port, t=TCP): return hint(t, port.to_bytes(2, "big") + host.encode())
def auto(scope, group): return hint(AUTO, bytes([SCOPES.index(scope)]) + group.encode())
def rnode(f, bw, sf, cr): return hint(RNODE, f.to_bytes(4, "big") + bw.to_bytes(4, "big") + bytes([sf, cr]))
def http(url): return hint(HTTP, url.encode())
def i2p(dest): return hint(I2P, dest)
def kiss(f, br, cs=b""): return hint(KISS, f.to_bytes(4, "big") + br.to_bytes(4, "big") + cs)
def ble(): return hint(BLE, b"")


def endpoint(transport, hints): return transport + bytes([len(hints)]) + b"".join(hints)
def user(nodes, kid=None): return bytes([VERSION, 1]) + (kid or U.kid) + bytes([len(nodes)]) + b"".join(nodes)
def node_entry(p, hints, transport=None): return p.kid + endpoint(transport or p.transport, hints)


def id_hash(transport): return hashlib.sha256(transport).digest()[:16]


def hint_json(h):
    t, body = h[0], h[2:]
    if t in (TCP, UDP):
        return {"type": "tcp" if t == TCP else "udp", "host": body[2:].decode(), "port": int.from_bytes(body[:2], "big")}
    if t == AUTO: return {"type": "auto", "scope": SCOPES[body[0]], "group_id": body[1:].decode()}
    if t == RNODE:
        return {"type": "rnode", "frequency_hz": int.from_bytes(body[:4], "big"), "bandwidth_hz": int.from_bytes(body[4:8], "big"),
                "spreading_factor": body[8], "coding_rate": body[9]}
    if t == HTTP: return {"type": "http", "url": body.decode()}
    if t == I2P: return {"type": "i2p", "destination_hex": body.hex()}
    if t == KISS:
        return {"type": "kiss", "frequency_hz": int.from_bytes(body[:4], "big"), "bitrate": int.from_bytes(body[4:8], "big"),
                "callsign": body[8:].decode() if body[8:] else None}
    if t == BLE: return {"type": "ble"}
    return {"type": "unknown", "tag": t, "body_hex": body.hex()}


def ep_json(transport, hints):
    return {"transport_identity_hex": transport.hex(), "rns_identity_hash_hex": id_hash(transport).hex(),
            "hints": [hint_json(h) for h in hints]}


valid, refusals, key_checks = [], [], []


def ok(cid, desc, payload, decoded):
    assert len(payload) <= MAX_PAYLOAD
    disp, qr = render(payload)
    valid.append({"id": cid, "description": desc, "code": disp, "qr": qr, "payload_hex": payload.hex(),
                  "payload_len": len(payload), "decoded": decoded})


def bad(cid, desc, code, error):
    refusals.append({"id": cid, "description": desc, "code": code, "error": error})


def bad_payload(cid, desc, payload, error): bad(cid, desc, render(payload)[0], error)


RELAY = tcp("relay.example.net", 4242)
H1 = [RELAY]
# ---------------------------------------------------------------- valid
ok("user_no_nodes", "A user code naming only the identity: resolves through the directory.",
   user([]), {"kind": "user", "kid_hex": U.kid.hex(), "nodes": []})
ok("user_one_node", "The common case: a user code with one reachable node and one relay hint.",
   user([node_entry(N[0], H1)]),
   {"kind": "user", "kid_hex": U.kid.hex(), "nodes": [{"kid_hex": N[0].kid.hex(), **ep_json(N[0].transport, H1)}]})
ok("user_one_node_no_hints", "A node with zero hints is a valid entry: it is dialled over an interface the dialler "
   "already shares, or via an RNS path request.", user([node_entry(N[0], [])]),
   {"kind": "user", "kid_hex": U.kid.hex(), "nodes": [{"kid_hex": N[0].kid.hex(), **ep_json(N[0].transport, [])}]})
TWO = [tcp("node1.example.org", 4965), auto("link", "reticulum")]
ok("node_two_hints", "One node with two hints, most preferred first: its own listener, then the LAN group.",
   user([node_entry(N[0], TWO)]),
   {"kind": "user", "kid_hex": U.kid.hex(), "nodes": [{"kid_hex": N[0].kid.hex(), **ep_json(N[0].transport, TWO)}]})
FOUR = [http("https://node1.example.org/rns"), tcp("relay.example.net", 4242), tcp("10.0.0.7", 4242, UDP),
        rnode(868_000_000, 125_000, 8, 5), i2p(bytes(range(32))), kiss(144_390_000, 1200, b"N0CALL-7"), kiss(433_000_000, 9600),
        ble()]
ok("node_max_hints", "One node with the maximum eight hints: http, tcp, udp, rnode, i2p, kiss with and without a callsign, "
   "ble.",
   user([node_entry(N[0], FOUR)]),
   {"kind": "user", "kid_hex": U.kid.hex(), "nodes": [{"kid_hex": N[0].kid.hex(), **ep_json(N[0].transport, FOUR)}]})
MAXN = [node_entry(N[i], [tcp("relay%d.example.net" % i, 4242 + i)]) for i in range(MAX_NODES)]
ok("user_max_nodes", "A user code with the maximum four nodes, one hint each.", user(MAXN),
   {"kind": "user", "kid_hex": U.kid.hex(),
    "nodes": [{"kid_hex": N[i].kid.hex(), **ep_json(N[i].transport, [tcp("relay%d.example.net" % i, 4242 + i)])}
              for i in range(MAX_NODES)]})
UNK = [hint(0x09, b"\x01\x02\x03"), RELAY]
ok("unknown_hint_skipped", "A hint of an unassigned type (0x09) is carried as unknown and skipped by "
   "a dialler, never refused; the tcp hint after it stands.", user([node_entry(N[0], UNK)]),
   {"kind": "user", "kid_hex": U.kid.hex(), "nodes": [{"kid_hex": N[0].kid.hex(), **ep_json(N[0].transport, UNK)}]})
V6 = [tcp("::1", 4242), tcp("2001:db8::7", 4242)]
ok("ipv6_hosts", "IPv6 hosts as CC 2.6.8 writes them: no brackets, no zone id (the port is its own field).",
   user([node_entry(N[0], V6)]),
   {"kind": "user", "kid_hex": U.kid.hex(), "nodes": [{"kid_hex": N[0].kid.hex(), **ep_json(N[0].transport, V6)}]})
ok("node_code", "A kind=node code names one node: its kid, then its endpoint.",
   bytes([VERSION, 3]) + N[0].kid + endpoint(N[0].transport, H1),
   {"kind": "node", "kid_hex": N[0].kid.hex(), "endpoint": ep_json(N[0].transport, H1)})
for k, p in (("agent", AG), ("family", FAM), ("community", COM)):
    ok("%s_code" % k, "A kind=%s code: the identity alone." % k, bytes([VERSION, KINDS[k]]) + p.kid,
       {"kind": k, "kid_hex": p.kid.hex()})
# The largest code: exactly the 1024-byte payload cap. Node 0 carries three tcp hints with 253-byte hosts
# (257 bytes each); node 1 carries one hint sized to land on the cap.
big = [(N[0], [tcp(("n0h%d-" % j) + "x" * 244 + ".net", 4000 + j) for j in range(3)])]
rest = MAX_PAYLOAD - 35 - (97 + sum(map(len, big[0][1]))) - 97
big.append((N[1], [tcp("r" * (rest - 4), 4242)]))
pl = user([node_entry(p, hs) for p, hs in big])
ok("largest_within_cap", "Near the 1024-byte payload cap: the size a QR must render at worst.", pl,
   {"kind": "user", "kid_hex": U.kid.hex(), "nodes": [{"kid_hex": p.kid.hex(), **ep_json(p.transport, hs)} for p, hs in big]})

# ---------------------------------------------------------------- refusals
good = render(user([node_entry(N[0], H1)]))[0]
flip = list(good); i = len(good) - 1; flip[i] = "A" if flip[i] != "A" else "B"
bad("bad_crc", "The last base32 character changed: the CRC does not match.", "".join(flip), "fedcode_crc")
v3 = "CIRIS-V3-" + good[len(PREFIX):]
bad("v3_presented", "An earlier-form prefix (CIRIS-V3-) to the edition-2 decoder: refused by its prefix, before any "
    "payload byte is read.", v3, "fedcode_earlier_form")
bad("unknown_prefix", "A prefix that is no FedCode.", "CIRIS-X9-" + good[len(PREFIX):], "fedcode_prefix")
bad("not_base32", "A character outside the base32 alphabet (1).", good[:-2] + "1" + good[-1], "fedcode_base32")
bad_payload("wrong_version_byte", "The CIRIS-V4- prefix over a payload whose version byte is 3.",
            bytes([3, 1]) + U.kid + b"\x00", "fedcode_version")
bad_payload("unknown_kind", "kind 6.", bytes([VERSION, 6]) + U.kid, "fedcode_kind")
bad_payload("truncated", "A user code cut inside its node entry.", user([node_entry(N[0], H1)])[:-5], "fedcode_truncated")
bad_payload("trailing_bytes", "A node code with a byte after its endpoint.",
            bytes([VERSION, 3]) + N[0].kid + endpoint(N[0].transport, H1) + b"\x00", "fedcode_trailing_bytes")
bad_payload("agent_embeds_nodes", "A kind=agent code followed by a node list: only kind=user embeds nodes.",
            bytes([VERSION, 2]) + AG.kid + bytes([1]) + node_entry(N[0], H1), "fedcode_nodes_not_user")
bad_payload("community_embeds_nodes", "A kind=community code followed by an empty node list: nothing follows a "
            "group's kid.", bytes([VERSION, 5]) + COM.kid + b"\x00", "fedcode_nodes_not_user")
bad_payload("too_many_nodes", "node_count 5.", user([node_entry(N[i], []) for i in range(5)]), "fedcode_node_count")
bad_payload("too_many_hints", "A node with nine hints.", user([node_entry(N[0], [RELAY] * 9)]), "fedcode_hint_count")
bad_payload("hint_i2p_short", "An i2p hint of 31 bytes.", user([node_entry(N[0], [i2p(bytes(31))])]), "fedcode_hint_malformed")
bad_payload("hint_kiss_lowercase", "A kiss callsign in lowercase.", user([node_entry(N[0], [kiss(144_390_000, 1200, b"n0call")])]),
            "fedcode_hint_malformed")
bad_payload("hint_kiss_two_dashes", "A kiss callsign with two dashes.",
            user([node_entry(N[0], [kiss(144_390_000, 1200, b"N0-CA-7")])]), "fedcode_hint_malformed")
bad_payload("hint_kiss_long", "A kiss callsign of 10 bytes.", user([node_entry(N[0], [kiss(144_390_000, 1200, b"N0CALLS-15")])]),
            "fedcode_hint_malformed")
bad_payload("hint_kiss_zero_rate", "A kiss bit rate of 0.", user([node_entry(N[0], [kiss(144_390_000, 0)])]), "fedcode_hint_malformed")
bad_payload("hint_ble_body", "A ble hint carrying a device identifier: the body must be empty.",
            user([node_entry(N[0], [hint(BLE, bytes(6))])]), "fedcode_hint_malformed")
bad_payload("hint_host_empty", "A tcp hint with an empty host.",
            user([node_entry(N[0], [tcp("", 4242)])]), "fedcode_hint_malformed")
bad_payload("hint_host_space", "A tcp hint whose host carries a space.",
            user([node_entry(N[0], [tcp("relay example.net", 4242)])]), "fedcode_hint_malformed")
bad_payload("hint_host_bracketed_ipv6", "A tcp host [::1]: IPv6 is written without brackets.",
            user([node_entry(N[0], [tcp("[::1]", 4242)])]), "fedcode_hint_malformed")
bad_payload("hint_host_zone_id", "A tcp host fe80::1%eth0: no zone id.",
            user([node_entry(N[0], [tcp("fe80::1%eth0", 4242)])]), "fedcode_hint_malformed")
bad_payload("hint_port_zero", "A tcp hint with port 0.", user([node_entry(N[0], [tcp("relay.example.net", 0)])]),
            "fedcode_hint_malformed")
bad_payload("hint_http_not_https", "An http hint whose URL is not https.",
            user([node_entry(N[0], [http("http://node1.example.org/")])]), "fedcode_hint_malformed")
bad_payload("hint_rnode_bad_sf", "An rnode hint with spreading factor 13 (7..=12).",
            user([node_entry(N[0], [rnode(868_000_000, 125_000, 13, 5)])]), "fedcode_hint_malformed")
bad_payload("hint_auto_bad_scope", "An auto hint with scope byte 5 (0..=4).",
            user([node_entry(N[0], [hint(AUTO, b"\x05reticulum")])]), "fedcode_hint_malformed")
bad_payload("hint_overruns", "A hint whose length runs past the payload.",
            user([node_entry(N[0], [])])[:-1] + b"\x01" + bytes([TCP, 40]) + b"\x10\x92abc", "fedcode_truncated")
bad_payload("node_is_identity", "A user code embedding a node whose kid is the user's own kid.",
            user([node_entry(U, H1)]), "fedcode_duplicate_node")
bad_payload("duplicate_node", "The same node twice.", user([node_entry(N[0], H1), node_entry(N[0], [])]),
            "fedcode_duplicate_node")
bad_payload("duplicate_transport", "Two nodes with one transport identity.",
            user([node_entry(N[0], H1), node_entry(N[1], [], transport=N[0].transport)]), "fedcode_duplicate_node")
over = user([node_entry(N[i], [tcp("x" * 250, 4242)] * 4) for i in range(MAX_NODES)])
assert len(over) > MAX_PAYLOAD
bad_payload("payload_too_large", "A payload of %d bytes (the cap is 1024)." % len(over), over, "fedcode_payload_too_large")

# ---------------------------------------------------------------- the transport-key check at resolution
# Constraint 1: an embedded transport key is never a federation key. The code carries kids only, so the
# check runs once the reader holds the composite keys: the transport identity's Ed25519 half must differ
# from the Ed25519 half of the owner's composite key and of the node's.
def kc(cid, desc, payload, owner, nodes, expect):
    key_checks.append({"id": cid, "description": desc, "code": render(payload)[0], "owner_composite_hex": owner.composite.hex(),
                       "node_composites_hex": {p.kid.hex(): p.composite.hex() for p in nodes}, "expect": expect})


kc("transport_distinct", "Each transport identity's Ed25519 half differs from both federation keys.",
   user([node_entry(N[0], H1)]), U, [N[0]], "ok")
kc("transport_is_owner_key", "The node's transport Ed25519 is the owner's federation Ed25519.",
   user([node_entry(N[0], H1, transport=N[0].transport[:32] + U.fed_ed)]), U, [N[0]], "fedcode_transport_is_federation_key")
kc("transport_is_node_key", "The node's transport Ed25519 is the node's own federation Ed25519.",
   user([node_entry(N[0], H1, transport=N[0].transport[:32] + N[0].fed_ed)]), U, [N[0]], "fedcode_transport_is_federation_key")
kc("node_code_transport_is_own_key", "A kind=node code whose transport Ed25519 is the node's federation Ed25519.",
   bytes([VERSION, 3]) + N[0].kid + endpoint(N[0].transport[:32] + N[0].fed_ed, H1), N[0], [], "fedcode_transport_is_federation_key")

json.dump({
    "_meta": {"spec": "edition-2 FedCode as verify proposes it for CC 2.6.8 (rc22); CC 2.6.1.7 thumbprint; CC 3.3.6.2 "
                      "transport identity", "generator": "gen_fedcode_e2.py (independent of verify)",
              "layout": "see the generator's header",
              "parties": "composite key n: ML-DSA-65 seed [n]*32, Ed25519 seed [n+100]*32; transport X25519 seed [n+150]*32, "
                         "Ed25519 [n+200]*32. User 1, agent 2, family 4, community 5, nodes 11..15.",
              "limits": {"max_payload": MAX_PAYLOAD, "max_nodes": MAX_NODES, "max_hints": MAX_HINTS}},
    "valid": valid, "refusals": refusals, "key_checks": key_checks}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
