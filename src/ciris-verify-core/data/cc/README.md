# Vendored CIRISConstitution data

| File | CC source | CC commit (`origin/rc20`) | SHA-256 (LF) |
|------|-----------|---------------------------|--------------|
| `family_columns.json` | the `authorship` and `second_signers` columns of `manifests/family_model.json` | `a15ce94` | source `daa803a680e49d6013fcd41435c4e5d2a725d52b36db568d3523e365c848757e` |
| `namespace_registry.json` | `manifests/namespace_registry.json` (CC 1.0-rc20) | `09907aa345ebd71fed6f0103ad58514ce2438741` | `0f1709ae2c588b5ccf0174bd52807eb0eb4b50457abce78c07d0d89abad06177` |

`namespace_registry.json` is embedded by `src/namespace_match.rs` (`include_str!`), the
port of CC's reference matcher `tools/cc_namespace_match.py`. Its replay vectors are
vendored from the same commit at `tests/vectors/cc/namespace_match_vectors.json`
(SHA-256 `ec66568522df903198320bb858132a1b9de2227d134bab0767792fb28db61069`) and run by
`tests/namespace_match_vectors.rs`, which also checks the registry digest above.

To refresh: `git -C ../CIRISConstitution show <commit>:manifests/namespace_registry.json`
(and the vectors), then update the commit and digests here and the constants in
`src/namespace_match.rs`.

`family_columns.json` is the compact extract `src/edition2/family.rs` embeds (the full
model is 1.8 MB and is not vendored). To regenerate:
`git -C ../CIRISConstitution show a15ce94:manifests/family_model.json > /tmp/fm.json &&
python3 -I extract_family_columns.py /tmp/fm.json > family_columns.json`; the source
digest above must match. `tests/family_model_columns.rs` pins it and the cell counts. Plain `authored` / `counted` cells are
read as given. A `gap` cell or a per-leaf selector answers "caller must supply" until
CC publishes its reference evaluator (`tools/cc_family_select.py`). A `gap` member or a
`when`-conditioned role is not admitted from the vendored model.
