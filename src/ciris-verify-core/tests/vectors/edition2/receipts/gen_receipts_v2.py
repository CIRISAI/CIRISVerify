# gen_receipts_v2.py: cases added to receipts_v1.json, which is unchanged and still replayed.
#
# A receipt carries its service's instant of issue (CC 2.6.1.11; the Constitution's ruling of 2026-11-27): a receipt
# whose protected CWT claims name no `iat` is refused, `receipt_no_instant`, whatever it is a receipt of. Before
# CIRISVerify 23.8.0 only a head receipt was refused for it. The refusal comes after the signature and before the
# subject: a receipt nobody signed is `receipt_bad_signature` with or without an instant.
#
# Reuses gen_receipts.py's own tree, signers and statements (loaded with its output discarded); shares no code
# with verify.
#   python3 -I gen_receipts_v2.py > receipts_v2.json
import contextlib, io, json, os, runpy, sys

here = os.path.dirname(os.path.abspath(__file__))
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(here, "gen_receipts.py"))
receipt, LOG, HEAD, S1, ED, ix = g["receipt"], g["LOG"], g["HEAD"], g["S1"], g["ED"], g["ix"]

cases = []
def add(cid, desc, rc, key, expect, **kw):
    cases.append(dict({"id": cid, "description": desc, "statement_hex": HEAD[0].hex(), "receipt_hex": rc.hex(),
                       "key": key, "expect": expect}, **kw))

add("with_instant", "S1's receipt for head statement A, with its iat: the control.", receipt(LOG, ix, S1), "S1", "ok",
    tree_size=7, leaf_index=ix, iat=1767312000)
add("no_instant", "The same receipt minted with no iat: it proves a registration and no time.",
    receipt(LOG, ix, S1, drop_iat=True), "S1", "receipt_no_instant")
add("no_instant_ed25519", "An Ed25519 service's receipt with no iat: the rule is the receipt's, whatever the key.",
    receipt(LOG, ix, ED, drop_iat=True), "ED", "receipt_no_instant")
add("no_instant_other_subject", "No iat and a sub that is not the statement's: the missing instant answers first.",
    receipt(LOG, ix, S1, drop_iat=True, sub="another-lineage"), "S1", "receipt_no_instant")
add("no_instant_wrong_key", "No iat, read under another service's key of the same algorithm and no kid: the "
    "signature answers first.", receipt(LOG, ix, S1, drop_iat=True, kid=False), "S2", "receipt_bad_signature")

json.dump({"_meta": {"spec": "RFC 9942 / RFC 9943; CC 2.6.1.11 (a receipt carries its service's instant of issue)",
                     "generator": "gen_receipts_v2.py over gen_receipts.py (independent of verify)",
                     "keys": "as receipts_v1.json, whose `keys` section the replay reads"},
           "verify": cases}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
