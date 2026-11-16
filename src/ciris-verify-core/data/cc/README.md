# Vendored CIRISConstitution data

| File | CC source | CC commit | SHA-256 (LF) |
|------|-----------|-----------|--------------|
| `family_authorship.json` | `manifests/family_authorship.json`, CC's canonical extract of the `authorship` and `second_signers` cells of `manifests/family_model.json` (CC 1.0-rc20) | `e08bf05` | `334027850f9c2d7fd382249b5bb188533a25307082794bce168625d1e5cfaf93`; source model `3c64403a56b0da0138433041af972ee552ead95d5f129f1f5fad26df6a8d1caf` |
| `namespace_registry.json` | `manifests/namespace_registry.json` (CC 1.0-rc20) | `09907aa345ebd71fed6f0103ad58514ce2438741` (`origin/rc20`) | `0f1709ae2c588b5ccf0174bd52807eb0eb4b50457abce78c07d0d89abad06177` |

`namespace_registry.json` is embedded by `src/namespace_match.rs` (`include_str!`), the
port of CC's reference matcher `tools/cc_namespace_match.py`. Its replay vectors are
vendored from the same commit at `tests/vectors/cc/namespace_match_vectors.json`
(SHA-256 `ec66568522df903198320bb858132a1b9de2227d134bab0767792fb28db61069`) and run by
`tests/namespace_match_vectors.rs`, which also checks the registry digest above.
Between 09907aa and e08bf05 the registry changed only in two `description` strings and
its own `_meta` digests; no family, segment or pattern moved.

To refresh: `git -C ../CIRISConstitution show <commit>:manifests/namespace_registry.json`
(and the vectors), then update the commit and digests here and the constants in
`src/namespace_match.rs`.

`family_authorship.json` is embedded by `src/edition2/family.rs` (`include_str!`,
`FAMILY_AUTHORSHIP_JSON`) and read by `VendoredFamilyModel`. Its selector arms are
evaluated by `edition2::family::select`, the port of CC's reference evaluator
`tools/cc_family_select.py`, against the row's leaf (its `dimension` bound under the
family by `namespace_match::bind_leaf`) and the caller's `SelectContext`. CC's replay
vectors `manifests/family_select_vectors.json` (e08bf05) are vendored at
`tests/vectors/cc/family_select_vectors.json` (SHA-256
`d1e5879ae953839fe3723b3db71449976856906532876c5a0b8aadd7376c14a4`) and run by
`tests/family_select_vectors.rs`, which pins both digests, the commit and the source
model digest. The `count` cells those vectors also exercise are not in CC's extract:
`tests/vectors/cc/family_count_cells.json` carries the count cells written as arms, cut
from the same model (test-only; not embedded):

    git -C ../CIRISConstitution show e08bf05:manifests/family_model.json > /tmp/fm.json
    python3 -I -c 'import hashlib,json,sys; raw=open(sys.argv[1],"rb").read(); m=json.loads(raw); print(json.dumps({"_meta":{"source":"manifests/family_model.json","source_sha256":hashlib.sha256(raw).hexdigest(),"cells":"count"},"families":{r["family"]:{"value":r["count"].get("value"),"source":r["count"].get("source"),"arms":[{"when":a["when"],"doors":a["doors"]} for a in r["count"]["arms"]]} for r in m["rows"] if r["count"].get("arms")}},indent=1,sort_keys=True))' /tmp/fm.json > family_count_cells.json

To refresh the family files: `git -C ../CIRISConstitution show <commit>:manifests/family_authorship.json`
and `:manifests/family_select_vectors.json`, regenerate the count cells as above, then
update the commit and digests here, the constants in `src/edition2/family.rs` and in
`tests/family_select_vectors.rs`.

What the vendored model admits: an `authored` / `counted` answer sets the author column;
`unknown` and `gap` are `FamilyFault::AuthorshipUndetermined`, a null answer (every arm
false) `FamilyFault::NoArmHolds`. A second-signer role is admitted when its `when` holds;
when any entry's `when` is unknown the cell is unknown and no second signer is admitted.
A `gap` member, and `owner_of_sub` (the owner the owner-binding of `sub` names, which the
row does not carry), are never admitted from the vendored model.
