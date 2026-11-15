# Vendored CIRISConstitution data

| File | CC source | CC commit (`origin/rc20`) | SHA-256 (LF) |
|------|-----------|---------------------------|--------------|
| `namespace_registry.json` | `manifests/namespace_registry.json` (CC 1.0-rc20) | `09907aa345ebd71fed6f0103ad58514ce2438741` | `0f1709ae2c588b5ccf0174bd52807eb0eb4b50457abce78c07d0d89abad06177` |

`namespace_registry.json` is embedded by `src/namespace_match.rs` (`include_str!`), the
port of CC's reference matcher `tools/cc_namespace_match.py`. Its replay vectors are
vendored from the same commit at `tests/vectors/cc/namespace_match_vectors.json`
(SHA-256 `ec66568522df903198320bb858132a1b9de2227d134bab0767792fb28db61069`) and run by
`tests/namespace_match_vectors.rs`, which also checks the registry digest above.

To refresh: `git -C ../CIRISConstitution show <commit>:manifests/namespace_registry.json`
(and the vectors), then update the commit and digests here and the constants in
`src/namespace_match.rs`.
