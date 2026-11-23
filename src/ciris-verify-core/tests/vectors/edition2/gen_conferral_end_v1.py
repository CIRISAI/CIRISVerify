# Independent known answers for the two payload members of CC's standing-end rule that a row alone decides
# (CC 2.4.1.1, CC 2.6.1; CIRISConstitution's answers of 2026-11-22, ahead of its next pre tag):
#  - `lifts` is present only as `true` (never false, never another value);
#  - `receipter` is an identity reference;
#  - `lifts` on one signer's own act (act = own, derived per CC 2.6.1.9 from a row with an author) is refused,
#    token lifts_on_own_end: it belongs only to a counted end.
# Which families are an offer or an end is CC's per-family column, not checked here.
#
# Reuses gen_row_statements_v4.py's own CBOR encoder and composite signer (loaded with its output discarded);
# shares no code with verify.
#   python3 -I gen_conferral_end_v1.py > conferral_end_v1.json
import contextlib, io, json, os, runpy, sys

here = os.path.dirname(os.path.abspath(__file__))
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(here, "gen_row_statements_v4.py"))
A, B, statement, T0 = g["A"], g["B"], g["statement"], g["T0"]

TARGET = [2, [-16, bytes([0x7a]) * 32]]
counted_end = {"asserted_at": T0, "refs": {"target": TARGET}}
own_end = dict(counted_end, author=A.iss)
offer = {"asserted_at": T0, "author": A.iss}

cases = []


def case(cid, desc, level, rtype, family, payload, expect, signer=A, sub="s"):
    cases.append({"id": cid, "description": desc, "level": level, "row_type": rtype, "family": family,
                  "statement_hex": statement(signer, sub, rtype, family, payload)[0].hex(),
                  "held_key_seeds": [signer.ml_seed[0]], "expect": expect})


# ---- lifts ----
case("lifts_true_on_counted_end", "A counted withdraws (no author; group:roster is counted) carrying lifts: true.",
     "family", "withdraws", "group:roster", dict(counted_end, lifts=True), "valid")
case("lifts_false", "lifts: false. The member is present only as true.", "statement", "withdraws", "group:roster",
     dict(counted_end, lifts=False), "invalid:malformed:lifts")
case("lifts_one", "lifts: 1.", "statement", "withdraws", "group:roster", dict(counted_end, lifts=1),
     "invalid:malformed:lifts")
case("lifts_text", "lifts: \"true\".", "statement", "withdraws", "group:roster", dict(counted_end, lifts="true"),
     "invalid:malformed:lifts")
case("lifts_on_own_end", "An authored withdraws (act own, derived from the author) carrying lifts: a self end "
     "does not lift.", "family", "withdraws", "conscience:coherence", dict(own_end, lifts=True),
     "family_invalid:lifts_on_own_end")
case("own_end_without_lifts", "The same authored withdraws without lifts.", "family", "withdraws",
     "conscience:coherence", own_end, "valid")
case("lifts_on_own_scores", "lifts on any row that is one signer's own act is refused the same way.", "family",
     "scores", "conscience:coherence", dict(offer, lifts=True), "family_invalid:lifts_on_own_end")

# ---- receipter ----
case("receipter_identity_ref", "An authored row naming a receipter by identity reference.", "family",
     "delegates_to", "conscience:coherence", dict(offer, receipter=B.iss), "valid")
case("receipter_not_a_ref", "receipter is text that is not an identity reference.", "statement", "delegates_to",
     "conscience:coherence", dict(offer, receipter="bob"), "invalid:malformed:receipter")
case("receipter_bytes", "receipter is a byte string (a bare thumbprint).", "statement", "delegates_to",
     "conscience:coherence", dict(offer, receipter=B.kid), "invalid:malformed:receipter")
case("receipter_true", "receipter: true.", "statement", "delegates_to", "conscience:coherence",
     dict(offer, receipter=True), "invalid:malformed:receipter")

json.dump({"_meta": {"spec": "CC 2.4.1.1 / CC 2.6.1 standing-end members a row alone decides (lifts, receipter); "
                             "CIRISConstitution's answers of 2026-11-22",
                     "generator": "gen_conferral_end_v1.py (encoder and signer of gen_row_statements_v4.py; "
                                  "independent of verify)",
                     "model": "vendored", "levels": "statement: verify_row_statement; family: "
                                                    "verify_row_in_family under the vendored model"},
           "cases": cases}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
