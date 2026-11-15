# Extract the authorship and second_signers columns of CC's family model
# into the compact file verify embeds (data/cc/family_columns.json).
#   python3 -I extract_family_columns.py <CC manifests/family_model.json> > family_columns.json
import hashlib, json, sys
raw = open(sys.argv[1], "rb").read()
d = json.loads(raw)
out = {"_source": {"file": "manifests/family_model.json", "sha256": hashlib.sha256(raw).hexdigest()}, "families": {}}
for r in d["rows"]:
    a, s = r["authorship"], r.get("second_signers", {"value": []})
    out["families"][r["family"]] = {
        "authorship": a.get("value"), "authorship_source": a.get("source"),
        "second_signers": [{k: x[k] for k in ("role", "member", "when") if k in x} for x in (s.get("value") or [])],
    }
json.dump(out, sys.stdout, indent=1, sort_keys=True)
print()
