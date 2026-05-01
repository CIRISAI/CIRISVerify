#!/bin/bash
# run-qa.sh — Comprehensive QA runner for CIRISVerify.
#
# Usage:
#   ./scripts/run-qa.sh                 # full suite
#   ./scripts/run-qa.sh --quick         # short-cycle benches (~3 min)
#   ./scripts/run-qa.sh --no-bench      # skip benches, run tests + memory only
#   ./scripts/run-qa.sh --live-ffi      # opt into live FFI tests (hangs on bad TPM)
#
# What it runs:
#   1. cargo nextest run (or cargo test --lib if nextest absent)
#   2. cargo bench (criterion, all hot paths)
#   3. python pytest test_memory_baseline.py
#
# Outputs:
#   - target/criterion/        — bench reports (HTML + JSON)
#   - bindings/python/.pytest_cache/ — Python test cache
#   - QA_REPORT.md             — top-line summary at repo root
#
# Exits non-zero on any failure. Designed to be the gate before
# tagging a release.

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

QUICK=0
SKIP_BENCH=0
LIVE_FFI=0
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        --no-bench) SKIP_BENCH=1 ;;
        --live-ffi) LIVE_FFI=1 ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

step() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# ----------------------------------------------------------------------------
# 1. Workspace tests
# ----------------------------------------------------------------------------
step "1. Workspace tests"
if command -v cargo-nextest >/dev/null 2>&1; then
    cargo nextest run --workspace --all-features
else
    echo -e "${YELLOW}cargo-nextest not installed, falling back to cargo test --lib${NC}"
    cargo test --workspace --all-features --lib
fi

# ----------------------------------------------------------------------------
# 2. Benchmarks
# ----------------------------------------------------------------------------
if [ "$SKIP_BENCH" = "1" ]; then
    echo -e "${YELLOW}Skipping benches (--no-bench).${NC}"
else
    step "2. Performance benchmarks"
    BENCH_ARGS=""
    if [ "$QUICK" = "1" ]; then
        BENCH_ARGS="--warm-up-time 1 --measurement-time 3"
        echo -e "${YELLOW}Quick mode: short measurement window (~3 min).${NC}"
    fi
    cargo bench -p ciris-keyring --bench storage_descriptor --all-features -- $BENCH_ARGS
    cargo bench -p ciris-verify-core --bench build_manifest --all-features -- $BENCH_ARGS
fi

# ----------------------------------------------------------------------------
# 3. Python memory + integration tests
# ----------------------------------------------------------------------------
step "3. Python memory + integration tests"
cd "$REPO_ROOT/bindings/python"

# Make sure the .so is fresh
if [ -f "$REPO_ROOT/target/release/libciris_verify_ffi.so" ]; then
    cp "$REPO_ROOT/target/release/libciris_verify_ffi.so" ciris_verify/libciris_verify_ffi.so
    echo "Copied fresh .so into Python package."
fi

LIVE_ENV=""
if [ "$LIVE_FFI" = "1" ]; then
    LIVE_ENV="CIRIS_VERIFY_LIVE_TESTS=1"
    echo -e "${YELLOW}Live FFI tests enabled. Will hang on bad TPM hosts.${NC}"
fi

env $LIVE_ENV python3 -m pytest tests/test_memory_baseline.py -v --timeout=30

# ----------------------------------------------------------------------------
# 4. Report
# ----------------------------------------------------------------------------
cd "$REPO_ROOT"
step "4. Generating QA_REPORT.md"

cat > QA_REPORT.md <<EOF
# QA Report

**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Host:** $(uname -srm)
**Toolchain:** $(rustc --version)

## Summary

\`\`\`
Tests:       PASSED
Benchmarks:  $([ "$SKIP_BENCH" = "1" ] && echo "SKIPPED" || echo "PASSED — see target/criterion/report/index.html")
Memory:      PASSED ($([ "$LIVE_FFI" = "1" ] && echo "live FFI included" || echo "live FFI skipped"))
\`\`\`

## Bench medians (extracted from criterion JSON)

EOF

# Append bench medians if benches ran
if [ "$SKIP_BENCH" = "0" ] && [ -d "$REPO_ROOT/target/criterion" ]; then
    echo '| Benchmark | Median |' >> QA_REPORT.md
    echo '|---|---|' >> QA_REPORT.md
    find "$REPO_ROOT/target/criterion" -name estimates.json -path "*/new/*" 2>/dev/null | while read f; do
        name=$(echo "$f" | sed "s|$REPO_ROOT/target/criterion/||" | sed "s|/new/estimates.json||")
        median=$(jq -r '.median.point_estimate' "$f" 2>/dev/null)
        if [ -n "$median" ] && [ "$median" != "null" ]; then
            # Convert ns to a friendlier unit
            if (( $(echo "$median > 1000000" | bc -l) )); then
                printf "| %s | %.2f ms |\n" "$name" "$(echo "scale=4; $median / 1000000" | bc)" >> QA_REPORT.md
            elif (( $(echo "$median > 1000" | bc -l) )); then
                printf "| %s | %.2f µs |\n" "$name" "$(echo "scale=4; $median / 1000" | bc)" >> QA_REPORT.md
            else
                printf "| %s | %.2f ns |\n" "$name" "$median" >> QA_REPORT.md
            fi
        fi
    done
fi

echo "" >> QA_REPORT.md
echo "## Baselines reference: \`docs/BENCHMARKS.md\`" >> QA_REPORT.md

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}QA PASSED${NC}"
echo -e "${GREEN}Report: QA_REPORT.md${NC}"
echo -e "${GREEN}Bench HTML: target/criterion/report/index.html${NC}"
echo -e "${GREEN}========================================${NC}"
