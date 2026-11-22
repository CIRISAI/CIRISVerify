# Independent known answers for the StreamKeyBinding READER (CC 5.3.3.5) and the file stream id (CC 5.3.3.8,
# rc22 0774639). It reads the released binding vectors stream_key_binding_v2_composite_v3.json (kept byte-identical)
# for the valid encodings and the publisher key, and derives each refusal by one mutation of a valid encoding; it
# shares no code with verify.
#
#   python3 -I gen_stream_binding_reader_v1.py > stream_binding_reader_v1.json
import hashlib, json, os, sys

here = os.path.dirname(os.path.abspath(__file__))
v3 = json.load(open(os.path.join(here, "stream_key_binding_v2_composite_v3.json")))
u16 = lambda n: n.to_bytes(2, "big")


def offsets(enc):
    """Byte offsets of the fields, read with the CC 5.3.3.5 layout."""
    o = {"version": 0}
    i = 1
    for f in ("room", "publisher"):
        n = int.from_bytes(enc[i:i + 2], "big"); o[f] = i; i += 2 + n
    o["join_nonce"] = i; i += 32
    o["stream_id"] = i; i += 32
    o["epoch"] = i; i += 8
    o["chunk_key"] = i; i += 32
    o["codec_count"] = i; c = enc[i]; i += 1
    for _ in range(c):
        n = int.from_bytes(enc[i + 1:i + 3], "big"); i += 3 + n
    o["replaces"] = i; i += 1 + (32 if enc[i] == 1 else 0)
    o["end"] = i; e = enc[i]; i += 1 + (8 if e else 0)
    o["kind"] = i; o["framing"] = i + 1; o["profile"] = i + 2; p = enc[i + 2]; i += 3
    if p == 1: o["head_interval"] = i; i += 4
    o["sig_len"] = i
    return o


valid, refusals = [], []
for c in v3["cases"]:
    valid.append({"id": c["id"], "encoding_hex": c["encoding_hex"], "stream_id_hex": None})
full = bytes.fromhex(next(c for c in v3["cases"] if c["id"] == "v2_minimal")["encoding_hex"])
o = offsets(full)


def bad(rid, desc, enc, error):
    refusals.append({"id": rid, "description": desc, "encoding_hex": enc.hex(), "error": error})


def at(enc, off, b): return enc[:off] + b + enc[off + len(b):]


bad("version_3", "The version byte is 0x03.", at(full, 0, b"\x03"), "binding_version")
bad("trailing_byte", "One byte after the signature.", full + b"\x00", "binding_trailing_bytes")
bad("truncated", "The signature cut short.", full[:-1], "binding_truncated")
bad("too_large", "Over 8192 bytes.", full + bytes(8193 - len(full)), "binding_too_large")
bad("stream_id_other", "stream_id is not the derivation from room, publisher and join nonce.",
    at(full, o["stream_id"], bytes([full[o["stream_id"]] ^ 1])), "binding_stream_id_mismatch")
bad("framing_2", "framing 2.", at(full, o["framing"], b"\x02"), "binding_malformed")
bad("profile_2", "profile 2.", at(full, o["profile"], b"\x02"), "binding_malformed")
bad("end_4", "end 4.", at(full, o["end"], b"\x04"), "binding_malformed")
bad("replaces_2", "replaces 2.", at(full, o["replaces"], b"\x02"), "binding_malformed")
bad("sig_len_3372", "The signature length says 3372.", at(full, o["sig_len"], u16(3372)), "binding_malformed")
bad("room_empty", "A room of length 0.", full[:1] + u16(0) + full[1 + 2 + int.from_bytes(full[1:3], "big"):], "binding_malformed")
for r in v3["refusals"]:
    refusals.append({"id": r["id"], "description": r["description"], "encoding_hex": r["encoding_hex"],
                     "error": "stream_head_interval_below_floor" if r["error"] == "stream_head_interval_below_floor"
                     # profile 1 with no interval: the next four bytes (the signature's length and its first
                     # two bytes) read as the interval, then the length check fails on signature bytes.
                     else "binding_malformed"})
sig_flip = bytearray(full); sig_flip[-1] ^= 1
signature_cases = [{"id": "v2_minimal_signature_flipped", "encoding_hex": bytes(sig_flip).hex(), "expect": "binding_bad_signature"}] + \
                  [{"id": c["id"], "encoding_hex": c["encoding_hex"], "expect": "ok"} for c in v3["cases"]]


def file_id(producer, nonce):
    p = producer.encode()
    return "file-" + hashlib.sha256(b"ciris:file-stream:v1" + u16(len(p)) + p + nonce).hexdigest()


files = [{"id": "persist_kat", "producer": "urn:ietf:params:oauth:ckt:sha-256:0Zcq7RqtYdKHPIqlYmB2iv-jR9nBZ8-ZpOFf3L4Uu4g",
          "nonce_hex": bytes(range(32)).hex()},
         {"id": "one_byte_producer", "producer": "p", "nonce_hex": bytes(32).hex()},
         {"id": "max_producer", "producer": "x" * 1024, "nonce_hex": (bytes([0xff]) * 32).hex()}]
for f in files: f["stream_id"] = file_id(f["producer"], bytes.fromhex(f["nonce_hex"]))
assert files[0]["stream_id"] == "file-efd767fd93bf8682744b8f88c04986b211fde338c46edb6f826bca047bfe56e9"
file_refusals = [{"id": "empty_producer", "producer": "", "nonce_hex": bytes(32).hex()},
                 {"id": "producer_1025", "producer": "x" * 1025, "nonce_hex": bytes(32).hex()}]

json.dump({"_meta": {"spec": "CC 5.3.3.5 StreamKeyBinding v2 (rc22, head_interval_s); CC 5.3.3.8 file stream id (rc22 0774639)",
                     "generator": "gen_stream_binding_reader_v1.py over stream_key_binding_v2_composite_v3.json (independent of verify)",
                     "publisher_composite_public_key_hex": v3["publisher_composite_public_key_hex"]},
           "valid": valid, "refusals": refusals, "signature": signature_cases,
           "file_stream_ids": files, "file_stream_id_refusals": file_refusals}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
