# Independent known answers for composers (supersedes / withdraws / recants) under CC rc22 db989df: a composer
# carries no `dimension` (it scores nothing); its leaf, and so its authorship, are those of the row it names in
# refs.target, which the caller holds and supplies (target: row id, family id, payload); where the caller
# supplies none and the composer's rule reads the leaf, it waits on that row. The header's family stays the
# family of the act. Read under CC's vendored family model (rc22, membership:{stage}: leaf widening|removal =>
# counted ; authored).
#
# Reuses gen_row_statements_v4.py's own CBOR encoder and composite signer (loaded with its output discarded);
# shares no code with verify.
#   python3 -I gen_composer_v1.py > composer_v1.json
import contextlib, io, json, os, runpy, sys

here = os.path.dirname(os.path.abspath(__file__))
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(here, "gen_row_statements_v4.py"))
A, B, statement, enc, T0 = g["A"], g["B"], g["statement"], g["enc"], g["T0"]

FAM = "membership:.stage"
TARGET_ID = bytes([0x7a]) * 32
OTHER_ID = bytes([0x7b]) * 32
tref = lambda d: [2, [-16, d]]
target = lambda dim: {"row_id_hex": TARGET_ID.hex(), "family_id": FAM,
                      "payload_hex": enc({"asserted_at": T0 - 1000, "dimension": dim}).hex()}
counted = {"asserted_at": T0, "refs": {"target": tref(TARGET_ID)}}
authored = dict(counted, author=A.iss)

cases = []


def case(cid, desc, rtype, payload, expect, tgt=None, family=FAM, signer=A):
    c = {"id": cid, "description": desc, "row_type": rtype, "family": family,
         "statement_hex": statement(signer, "s", rtype, family, payload)[0].hex(),
         "held_key_seeds": [signer.ml_seed[0]], "expect": expect}
    if tgt is not None:
        c["target"] = tgt
    cases.append(c)


for rt in ("supersedes", "withdraws", "recants"):
    case(f"{rt}_states_dimension", f"A {rt} carrying its target's dimension: a composer scores nothing.", rt,
         dict(counted, dimension="membership:widening:v1"), "invalid:malformed:dimension",
         target("membership:widening:v1"))
case("withdraws_target_counted", "A withdraws whose target is membership:widening: counted (no author).", "withdraws",
     counted, "valid", target("membership:widening:v1"))
case("withdraws_target_counted_with_author", "The target's leaf makes it counted: an author is refused.", "withdraws",
     authored, "family_invalid:author_column", target("membership:widening:v1"))
case("withdraws_target_authored", "A withdraws whose target is membership:proposal: authored, its author signs.",
     "withdraws", authored, "valid", target("membership:proposal:v1"))
case("recants_target_authored_without_author", "Target membership:proposal is authored: no author is refused.",
     "recants", counted, "family_invalid:author_column", target("membership:proposal:v1"))
case("withdraws_target_not_supplied", "No target supplied and the rule reads the leaf: waits on refs.target.",
     "withdraws", counted, "waiting:row:" + TARGET_ID.hex())
case("withdraws_target_other_row", "The supplied target is not the row refs.target names.", "withdraws", counted,
     "family_invalid:target_mismatch", dict(target("membership:widening:v1"), row_id_hex=OTHER_ID.hex()))
case("withdraws_names_no_target_supplied", "A composer naming no target, with a target supplied.", "withdraws",
     {"asserted_at": T0}, "family_invalid:target_mismatch", target("membership:widening:v1"))
case("withdraws_names_no_target", "A composer naming no target, none supplied: the leaf is unknown.", "withdraws",
     {"asserted_at": T0}, "family_invalid:authorship_undetermined")
case("withdraws_leaf_free_family", "group:roster's rule reads no leaf: no target needed, counted.", "withdraws",
     counted, "valid", family="group:roster")
case("scores_ignores_target", "A scores row (not a composer) reads its own dimension; a supplied target is ignored.",
     "scores", {"asserted_at": T0, "dimension": "membership:widening:v1"}, "valid", target("membership:proposal:v1"))

json.dump({"_meta": {"spec": "CC rc22 db989df: a composer carries no dimension; its leaf is its target's",
                     "generator": "gen_composer_v1.py (encoder and signer of gen_row_statements_v4.py; independent of verify)",
                     "model": "vendored"},
           "cases": cases}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
