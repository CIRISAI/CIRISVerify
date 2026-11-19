#!/usr/bin/env python3
"""
revendor_cc.py: re-vendor CIRISConstitution's manifests into ciris-verify-core at one CC commit.

    python3 -I scripts/revendor_cc.py <cc-commit-or-tag> [--cc ../CIRISConstitution]

Writes data/cc/{family_authorship,namespace_registry}.json and tests/vectors/cc/{family_select_vectors,
namespace_match_vectors,family_count_cells}.json from that commit, then rewrites every pinned digest and the
commit constants (FAMILY_MODEL_CC_COMMIT, NAMESPACE_REGISTRY_CC_COMMIT) from their old values to the new ones.
Counts asserted by the tests (vector totals, cell splits) are printed for a person to update; prose in
data/cc/README.md is left for a person too.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "ciris-verify-core")
FILES = {
    "data/cc/family_authorship.json": "manifests/family_authorship.json",
    "data/cc/namespace_registry.json": "manifests/namespace_registry.json",
    "tests/vectors/cc/family_select_vectors.json": "manifests/family_select_vectors.json",
    "tests/vectors/cc/namespace_match_vectors.json": "manifests/namespace_match_vectors.json",
}
PINNED = ["src/edition2/family.rs", "src/namespace_match.rs", "tests/family_select_vectors.rs",
          "tests/namespace_match_vectors.rs"]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    commit = sys.argv[1]
    cc = sys.argv[sys.argv.index("--cc") + 1] if "--cc" in sys.argv else os.path.join(ROOT, "..", "..", "..", "CIRISConstitution")
    show = lambda path: subprocess.run(["git", "-C", cc, "show", f"{commit}:{path}"], check=True, capture_output=True).stdout
    full = subprocess.run(["git", "-C", cc, "rev-parse", f"{commit}^{{commit}}"], check=True, capture_output=True, text=True).stdout.strip()
    swaps = {}
    for dst, src in FILES.items():
        p = os.path.join(ROOT, dst)
        old = sha(open(p, "rb").read()) if os.path.exists(p) else None
        new_bytes = show(src)
        open(p, "wb").write(new_bytes)
        swaps[old] = sha(new_bytes)
        print(f"{dst}: {old} -> {sha(new_bytes)}")
    # the source model digest and the count cells
    raw = show("manifests/family_model.json")
    m = json.loads(raw)
    meta_old = json.load(open(os.path.join(ROOT, "tests/vectors/cc/family_count_cells.json")))["_meta"]["source_sha256"]
    swaps[meta_old] = sha(raw)
    cells = {"_meta": {"source": "manifests/family_model.json", "source_sha256": sha(raw), "cells": "count"},
             "families": {r["family"]: {"value": r["count"].get("value"), "source": r["count"].get("source"),
                                        "arms": [{"when": a["when"], "doors": a["doors"]} for a in r["count"]["arms"]]}
                          for r in m["rows"] if r["count"].get("arms")}}
    open(os.path.join(ROOT, "tests/vectors/cc/family_count_cells.json"), "w").write(json.dumps(cells, indent=1, sort_keys=True) + "\n")
    print(f"family_model.json source: {meta_old} -> {sha(raw)}")
    for f in PINNED:
        p = os.path.join(ROOT, f)
        s = open(p).read()
        for o, n in swaps.items():
            if o:
                s = s.replace(o, n)
        s = re.sub(r'(FAMILY_MODEL_CC_COMMIT: &str = ")[0-9a-f]+(")', rf"\g<1>{full[:7]}\2", s)
        s = re.sub(r'(NAMESPACE_REGISTRY_CC_COMMIT: &str = ")[0-9a-f]+(")', rf"\g<1>{full}\2", s)
        s = re.sub(r'(assert_eq!\(FAMILY_MODEL_CC_COMMIT, ")[0-9a-f]+(")', rf"\g<1>{full[:7]}\2", s)
        open(p, "w").write(s)
    nv = json.load(open(os.path.join(ROOT, "tests/vectors/cc/namespace_match_vectors.json")))
    fv = json.load(open(os.path.join(ROOT, "tests/vectors/cc/family_select_vectors.json")))
    count = lambda v: len(v) if isinstance(v, list) else len(v.get("vectors", v.get("cases", [])))
    print(f"commit {full}; namespace vectors {count(nv)}; family-select vectors {count(fv)}")
    print("update by hand: vector counts and cell splits asserted in the tests, and data/cc/README.md")


if __name__ == "__main__":
    main()
