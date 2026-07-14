# Release Checklist

Security-critical gates to confirm before publishing a CIRISVerify wheel /
release artifact.

## 🔒 `test-anchor` MUST be absent from production artifacts (CIRISVerify#202)

The `test-anchor` Cargo feature enables a **test-only** relaxation of the
constitutional trust root — a software single-key accord anchor
(`CIRIS_TEST_TRUST_ROOT`) and a software-only accord holder with **no** YubiKey /
FIPS / touch custody floor. It exists solely for the local two-node mesh
reproduction harness.

Because the production `ciris-server` container is **zero-env by design** (all
behaviour comes from signed CEG objects, no `environment:` block), a runtime flag
could never be the boundary — *"env unset"* and *"production"* are
indistinguishable at runtime. **The compile-time absence of the feature is the
real boundary.** The bypass code is `#[cfg(feature = "test-anchor")]`; without the
feature it is physically not in the binary.

### Automated (enforced in CI)

`scripts/check-no-test-anchor-in-release.sh` (wired into the CI clippy job) fails
the build if `test-anchor` appears in any crate's `default` features **or**
anywhere in `.github/workflows/release.yml`. So the published wheel lane
(`-p ciris-verify-ffi` with `matrix.features` ∈ {`tpm-plugin`, `tpm-windows`, ∅})
cannot enable it.

### Manual probe (run on the shipped artifact before deploy)

Every build — prod and test — exports `ciris_verify_test_anchor_compiled_in()`.
It returns `0` iff the bypass is absent. **Require `0` on the production wheel:**

```python
from ciris_verify import test_anchor_compiled_in
assert not test_anchor_compiled_in(), \
    "REFUSE TO DEPLOY: test-anchor bypass is compiled into this artifact"
```

(Or directly against a `.so`/`.dll`:
`ctypes.CDLL(path).ciris_verify_test_anchor_compiled_in()` — must return `0`.)

A `1` on a production artifact is a **release-process failure** — do not deploy;
the wheel was built with `--features test-anchor`.

### The harness build (the only place the feature is allowed)

The `harness/mesh-repro` stack builds `ciris-verify-ffi --features test-anchor`
and, per node, sets `CIRIS_TESTING_MODE=true` + `CIRIS_TEST_TRUST_ROOT=<b64 sw
pubkey>`. Even there, an explicit `ENVIRONMENT`/`CIRIS_ENV` of
`production`/`prod`/`staging` trips the anti-production refusal and the bypass
stays off.
