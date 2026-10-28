#!/usr/bin/env bash
# The retired EU registry hostname must not reappear in any live code path
# (CIRISVerify#11).
#
# `eu.registry.ciris-services-eu-1.com` is NXDOMAIN — wrong sub-zone AND TLD.
# A live reference fails silently: a dead source degrades rather than erroring,
# so no other test notices it.
#
# Source-level, so it fires in every build configuration. Historical mentions in
# a `//` comment are allowed — the point is that nothing RESOLVES it.
set -euo pipefail
cd "$(dirname "$0")/.."

RETIRED='ciris-services-eu-1\.com'
# Strip comment-only lines before matching, so the changelog note in config.rs
# (and any future "was X" annotation) stays legal.
hits=$(grep -rn "$RETIRED" --include='*.rs' src/ 2>/dev/null \
       | grep -vE ':[[:space:]]*//' || true)

if [ -n "$hits" ]; then
    echo "ERROR: retired EU registry hostname in a live code path:" >&2
    echo "$hits" >&2
    echo >&2
    echo "  eu.registry.ciris-services-eu-1.com is NXDOMAIN." >&2
    echo "  Use eu.registry.ciris-services-1.ai (see config.rs)." >&2
    exit 1
fi
echo "no retired registry hostnames in live code ✓"
