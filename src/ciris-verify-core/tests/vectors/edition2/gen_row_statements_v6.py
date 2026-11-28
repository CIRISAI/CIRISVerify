# gen_row_statements_v6.py: two cases added to row_statements_v5.json, which is unchanged and still replayed.
#
# The unprotected header is outside the signature, the row id and the statement id (CC 2.6.1.1, CC 2.6.1.3;
# draft-moore-scitt-ciris-ceg-04 Appendix B.3): one payload, one protected header, one signature, two unprotected
# headers. Both statements have one row id, one statement id and one answer, Valid. The pair was proposed by
# CIRISConstitution (2026-11-25); the added entry is label 394 holding one byte string that is no receipt. A reader
# admits any integer label there and reads only 17 (sd_claims).
#
# Reuses gen_row_statements_v5.py's own CBOR encoder and composite signer (loaded with its output discarded); shares
# no code with verify.
#   python3 -I gen_row_statements_v6.py > row_statements_v6.json
import contextlib, hashlib, io, json, os, runpy, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
cwd = os.getcwd()
with tempfile.TemporaryDirectory() as scratch, contextlib.redirect_stdout(io.StringIO()):
    os.chdir(scratch)
    g = runpy.run_path(os.path.join(here, "gen_row_statements_v5.py"))
    os.chdir(cwd)
A, statement, enc, P1, FAM = g["A"], g["statement"], g["enc"], g["P1"], g["FAM"]
sha = lambda b: hashlib.sha256(b).digest()

PU = dict(P1, asserted_at=1763200000124)
SUB = "subject-u"
valid = []
def add(cid, desc, unprot):
    st, pb, plb = statement(A, SUB, "scores", FAM, PU, unprot=unprot)
    valid.append({"id": cid, "description": desc, "level": "statement", "family_vendored_expect": "valid",
                  "key_seed": 1, "kid_hex": A.kid.hex(), "iss": A.iss, "statement_hex": st.hex(),
                  "unprotected_header_hex": enc(unprot or {}).hex(),
                  "row_id_hex": sha(enc(["CEG-row/2", "scores", FAM, SUB, PU["author"], plb])).hex(),
                  "statement_id_hex": sha(enc(["CEG-statement-id/2", pb, plb])).hex()})
add("unprotected_empty", "An authored scores row with an empty unprotected header.", None)
add("unprotected_added", "The statement above with one entry added to its unprotected header (label 394, one byte "
    "string that is no receipt): the same protected header, payload and signature, so the same row id, the same "
    "statement id and the same answer.", {394: [b"\x00"]})
a, b = valid
assert a["row_id_hex"] == b["row_id_hex"] and a["statement_id_hex"] == b["statement_id_hex"]
assert a["statement_hex"] != b["statement_hex"] and b["unprotected_header_hex"] == "a119018a814100"
print(json.dumps({"adds_to": "row_statements_v5.json", "generator": "gen_row_statements_v6.py",
                  "description": "Two statements that differ only in the unprotected header: one row id, one "
                                 "statement id, one answer (Valid).", "valid": valid}, indent=1))
