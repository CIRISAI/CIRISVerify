# Vendored CIRISConstitution data

| File | CC source | CC commit | SHA-256 (LF) |
|------|-----------|-----------|--------------|
| `family_authorship.json` | `manifests/family_authorship.json`, CC's canonical extract of the `authorship` and `second_signers` cells of `manifests/family_model.json` (CC 1.0-rc20) | `d4bd2a6` (tag `v1.0-rc20`) | `2732a2de3368bb97750de39e4b44613e40979ad80343dfebe59d8515d28a9c0b`; source model `04446a5b50ee07b94c21139cd770e0de84317fe9e84240e6f0d68ee574b8caa0` |
| `namespace_registry.json` | `manifests/namespace_registry.json` (CC 1.0-rc20) | `d4bd2a6b0583b8bc57c06a89f265557d357a3191` (tag `v1.0-rc20`) | `5c8bcf87732b37f9e653e0e45190ae599d6f86f077b5ca02bd6c7a7039806002` |

`namespace_registry.json` is embedded by `src/namespace_match.rs` (`include_str!`), the
port of CC's reference matcher `tools/cc_namespace_match.py`. Its replay vectors are
vendored from the same commit at `tests/vectors/cc/namespace_match_vectors.json`
(SHA-256 `1312c45ada371caa7217417c5ebbcb81abbb8dcf7c45dff832f3dfa9ae02c00b`, 1,311
vectors) and run by `tests/namespace_match_vectors.rs`, which also checks the registry
digest above. The registry at v1.0-rc20 adds `location_proof:{version}` and
`trust:blessing` (`trust:blessing:v1` resolves to the literal family `trust:blessing`).

To refresh: `git -C ../CIRISConstitution show <commit>:manifests/namespace_registry.json`
(and the vectors), then update the commit and digests here and the constants in
`src/namespace_match.rs`.

`family_authorship.json` is embedded by `src/edition2/family.rs` (`include_str!`,
`FAMILY_AUTHORSHIP_JSON`) and read by `VendoredFamilyModel`. Its selector arms are
evaluated by `edition2::family::select`, the port of CC's reference evaluator
`tools/cc_family_select.py`, against the row's leaf (its `dimension` bound under the
family by `namespace_match::bind_leaf`) and the caller's `SelectContext`. CC's replay
vectors `manifests/family_select_vectors.json` (d4bd2a6, 177 vectors) are vendored at
`tests/vectors/cc/family_select_vectors.json` (SHA-256
`da3bfc60023c46fd0e287dd209742c273565edb77c4f01851c30f3b1df52b616`) and run by
`tests/family_select_vectors.rs`, which pins both digests, the commit and the source
model digest. The `count` cells those vectors also exercise are not in CC's extract:
`tests/vectors/cc/family_count_cells.json` carries the count cells written as arms, cut
from the same model (test-only; not embedded):

    git -C ../CIRISConstitution show v1.0-rc20:manifests/family_model.json > /tmp/fm.json
    python3 -I -c 'import hashlib,json,sys; raw=open(sys.argv[1],"rb").read(); m=json.loads(raw); print(json.dumps({"_meta":{"source":"manifests/family_model.json","source_sha256":hashlib.sha256(raw).hexdigest(),"cells":"count"},"families":{r["family"]:{"value":r["count"].get("value"),"source":r["count"].get("source"),"arms":[{"when":a["when"],"doors":a["doors"]} for a in r["count"]["arms"]]} for r in m["rows"] if r["count"].get("arms")}},indent=1,sort_keys=True))' /tmp/fm.json > family_count_cells.json

To refresh the family files: `git -C ../CIRISConstitution show <commit>:manifests/family_authorship.json`
and `:manifests/family_select_vectors.json`, regenerate the count cells as above, then
update the commit and digests here, the constants in `src/edition2/family.rs` and in
`tests/family_select_vectors.rs`.

What the vendored model admits: an `authored` / `counted` answer sets the author column;
`unknown` and `gap` are `FamilyFault::AuthorshipUndetermined`, a null answer (every arm
false) `FamilyFault::NoArmHolds`. A second-signer role is admitted when its `when` holds;
when any entry's `when` is unknown the cell is unknown and no second signer is admitted.
A `gap` member, `owner_of_sub` (the owner the owner-binding of `sub` names, which the
row does not carry) and `target` (`key:record`'s `predecessor_key`: the issuer of the row
`refs.target` names, CC 3.1.3) are never admitted from the vendored model.

`act` is never a payload member (CC 2.6.1.9): the family check derives it when the
caller's `SelectContext` leaves it out. One statement of a row that carries an `author`
is `own` (`statement_act`), and the statements of one counted row read together
(`verify_group_row_in_family`) are `group`; `verify_row_in_family_as_given` derives
nothing (a harness withholding `act`).

Known gap, pending CC's next edition: the v1.0-rc20 registry lists
`location_proof:{version}` and `trust:blessing`, but its family model does not. CC adds
them next edition with authorship `subject` (`iss` == `sub`, positive only), and
`trust:blessing` counted under the conferring family's `consensus_protocol`. Until then a
`location_proof:v1` row passes the statement reader (the family is registered) and reads
`FamilyFault::UnregisteredFamily` under `VendoredFamilyModel`
(`edition2::family::tests::location_proof_is_registered_but_not_in_the_family_model`).
