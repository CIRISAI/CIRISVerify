#!/usr/bin/env bash
# TEST-ONLY features must never reach a production artifact:
#
#   - test-anchor  (CIRISVerify#202) — software trust-root / custody relaxation.
#     The prod ciris-server container is zero-env by design, so the compile-time
#     feature is the REAL boundary; a runtime flag cannot be.
#   - test-support (CIRISVerify#219) — fabricated YubiKey-PIV custody artifacts.
#     Inert against the real pinned Yubico root (can't forge a real-gate pass),
#     but still fenced so the rcgen dep + fabrication code are absent from prod.
#
# This guard asserts neither feature is in any crate's `default` set, nor
# anywhere in the release/wheel workflow.
set -euo pipefail
fail=0

FEATURES=("test-anchor" "test-support")

for feat in "${FEATURES[@]}"; do
  # 1. Never in a crate's default feature set.
  for toml in src/ciris-verify-core/Cargo.toml src/ciris-verify-ffi/Cargo.toml; do
    if awk -F= '/^default *=/{print}' "$toml" | grep -q "$feat"; then
      echo "::error::$toml lists $feat in its default feature set — it must be opt-in only."
      fail=1
    fi
  done

  # 2. Never referenced by the release workflow (the wheel/FFI publish lane).
  if grep -rniE "$feat" .github/workflows/release.yml >/dev/null 2>&1; then
    echo "::error::.github/workflows/release.yml references $feat — the prod wheel MUST NOT carry it."
    grep -niE "$feat" .github/workflows/release.yml
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "a test-only feature leaked toward a production artifact — refusing."
  exit 1
fi
echo "test-anchor + test-support are opt-in only and absent from the release lane ✓"
