# Vendored CIRISConstitution data

| File | CC source | CC commit | SHA-256 (LF) |
|------|-----------|-----------|--------------|
| `family_authorship.json` | `manifests/family_authorship.json`, CC's canonical extract of the `authorship` and `second_signers` cells of `manifests/family_model.json` (CC 1.0-rc22) | `f467193` (v1.0-rc22) | `6b7e3f81a92ad4197097759088b3784ba2f6431b7252e4928fe9e622f1653c40`; source model `82327420ab6dccc046698d5c7cad2227ee085469293cfc970cfc361f4ed6449b` |
| `namespace_registry.json` | `manifests/namespace_registry.json` (CC 1.0-rc22) | `f467193` (v1.0-rc22) | `1886df7fb71d91bc00b8faea6ae453b21bc189cf404467bd5e63aa57c01e556a` |

`namespace_registry.json` is embedded by `src/namespace_match.rs` (`include_str!`), the
port of CC's reference matcher `tools/cc_namespace_match.py`. Its replay vectors are
vendored from the same commit at `tests/vectors/cc/namespace_match_vectors.json`
(SHA-256 `74b1cef61ddea817febd583ef9492c1b0b66f922853287cedbd82c2abdadd7ee`, 1,334
vectors) and run by `tests/namespace_match_vectors.rs`, which also checks the registry
digest above. The registry at v1.0-rc22 holds 187 families: over v1.0-rc22-pre4 (185) it adds
`mls:leaf_vouch` and `window:{state}`. (pre4 added `act:ack`, `delivery_ack:{stream_id}` and
`holon:claim`, and retired `delivery_receipt`, the three `transparency_log` families,
`lineage_witness`, `trust:blessing` and `cosign`; `trust:blessing:v1` binds under
`trust:{job}:{version}` like any other job.)

To refresh every vendored file at once: `python3 -I scripts/revendor_cc.py <commit-or-tag>`
(it rewrites the pinned digests and commit constants; vector counts asserted by the tests and
this README are updated by hand). By hand: `git -C ../CIRISConstitution show <commit>:manifests/namespace_registry.json`
(and the vectors), then update the commit and digests here and the constants in
`src/namespace_match.rs`.

`family_authorship.json` is embedded by `src/edition2/family.rs` (`include_str!`,
`FAMILY_AUTHORSHIP_JSON`) and read by `VendoredFamilyModel`. Its selector arms are
evaluated by `edition2::family::select`, the port of CC's reference evaluator
`tools/cc_family_select.py`, against the row's leaf (its `dimension` bound under the
family by `namespace_match::bind_leaf`) and the caller's `SelectContext`. CC's replay
vectors `manifests/family_select_vectors.json` (267 vectors) are vendored at
`tests/vectors/cc/family_select_vectors.json` (SHA-256
`51b7b3ae34df6192f2a3771c2255b860a78981cc2e28ec710141d92be1bcfc52`) and run by
`tests/family_select_vectors.rs`, which pins both digests, the commit and the source
model digest. The `count` cells those vectors also exercise are not in CC's extract:
`tests/vectors/cc/family_count_cells.json` carries the count cells written as arms, cut
from the same model (test-only; not embedded):

    git -C ../CIRISConstitution show f467193:manifests/family_model.json > /tmp/fm.json
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

`location_proof:{version}` reads authorship `subject` (CC 2.6.1.3): the row is authored by the
attested key, so `author` MUST be the CWT `sub` and `iss` the author, with no second signer. The
vendored model carries it as the role `edition2::family::AUTHOR_IS_SUBJECT` on an authored rule.
