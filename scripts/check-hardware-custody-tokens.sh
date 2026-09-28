#!/usr/bin/env bash
# CIRISVerify#296 — every `hardware_custody:{platform}:{version}` dimension this
# crate can emit must be ACCEPTED by CIRISConstitution's own namespace matcher.
#
# Why a script and not only a Rust test: the authority is CC's matcher, not our
# reading of its registry JSON. Reading the JSON is what produced the wrong
# conclusion during #296 triage — `hardware_custody:{platform}` has no
# `{version}` segment in its own `segments` array, yet R3's version grammar is
# GLOBAL and the matcher requires the tail. Only running the matcher settles it.
#
# Skips (exit 0) when CIRISConstitution is not checked out beside this repo, so
# CI without the sibling stays green; the Rust test
# `every_hardware_type_maps_to_a_registered_platform_token` is the always-on half.
set -euo pipefail

CC="${CIRIS_CONSTITUTION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/CIRISConstitution}"
MATCHER="$CC/tools/cc_namespace_match.py"

if [[ ! -f "$MATCHER" ]]; then
  echo "SKIP: CC matcher not found at $MATCHER (set CIRIS_CONSTITUTION_DIR)"
  exit 0
fi

# The tokens come from the one source of truth, not a second hand-written list.
TOKENS=$(grep -A 40 'pub const ALL_PLATFORMS' src/ciris-keyring/src/types.rs \
         | grep -oE '"[a-z_]+"' | tr -d '"' | sed '/^$/d')
if [[ -z "$TOKENS" ]]; then
  echo "FAIL: could not read ALL_PLATFORMS from src/ciris-keyring/src/types.rs"
  exit 1
fi

VERSION=$(grep -oE 'HARDWARE_CUSTODY_VERSION: &str = "v[0-9]+"' \
          src/ciris-verify-core/src/federation_provenance.rs | grep -oE 'v[0-9]+')
if [[ -z "$VERSION" ]]; then
  echo "FAIL: could not read HARDWARE_CUSTODY_VERSION"
  exit 1
fi

DIMS=()
while read -r tok; do DIMS+=("hardware_custody:${tok}:${VERSION}"); done <<< "$TOKENS"

echo "replaying ${#DIMS[@]} dimensions through $MATCHER"
OUT=$(cd "$CC" && python3 "$MATCHER" "${DIMS[@]}")
echo "$OUT"

if grep -qv 'refusal=None' <<< "$OUT"; then
  echo
  echo "FAIL: at least one emitted dimension is REFUSED by the CC matcher:"
  grep -v 'refusal=None' <<< "$OUT"
  exit 1
fi

# Negative control: the pre-18.0.0 forms MUST still be refused, or the matcher
# is not actually gating anything.
BAD=("hardware_custody:android" "hardware_custody:tpm" "hardware_custody:tpmfirmware" \
     "hardware_custody:software_fallback" "hardware_custody:android_strongbox")
BADOUT=$(cd "$CC" && python3 "$MATCHER" "${BAD[@]}")
if grep -q 'refusal=None' <<< "$BADOUT"; then
  echo
  echo "FAIL: a known-bad dimension was ACCEPTED — the check proves nothing:"
  grep 'refusal=None' <<< "$BADOUT"
  exit 1
fi

echo
echo "hardware_custody tokens: ${#DIMS[@]} accepted, ${#BAD[@]} known-bad forms still refused ✓"
