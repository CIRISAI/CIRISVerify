#!/usr/bin/env bash
# CIRISVerify#202 — the TEST-ONLY `test-anchor` feature (software trust-root +
# software accord-holder, no FIPS) must NEVER be built into a production artifact.
# The prod ciris-server container is zero-env by design, so the compile-time
# feature is the REAL boundary; a runtime flag cannot be. This guard asserts the
# release/wheel workflow never enables it, and that it is not in any default feature set.
set -euo pipefail
fail=0

# 1. Never in a crate's default feature set.
for toml in src/ciris-verify-core/Cargo.toml src/ciris-verify-ffi/Cargo.toml; do
  if awk -F= '/^default *=/{print}' "$toml" | grep -q 'test-anchor'; then
    echo "::error::$toml lists test-anchor in its default feature set — it must be opt-in only."
    fail=1
  fi
done

# 2. Never referenced by the release workflow (the wheel/FFI publish lane).
if grep -rniE 'test-anchor' .github/workflows/release.yml >/dev/null 2>&1; then
  echo "::error::.github/workflows/release.yml references test-anchor — the prod wheel MUST NOT carry the bypass."
  grep -niE 'test-anchor' .github/workflows/release.yml
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "test-anchor leaked toward a production artifact — refusing."
  exit 1
fi
echo "test-anchor is opt-in only and absent from the release lane ✓"
