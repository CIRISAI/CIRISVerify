#!/bin/bash
# pre-commit.sh — local mirror of the CI gates that block on push.
#
# Run on every `git commit`. Mirrors three jobs from .github/workflows/ci.yml:
#   1. Format    (cargo fmt --all -- --check)
#   2. Clippy    (cargo clippy --all-targets -- -D warnings)
#   3. Cargo Deny  (cargo deny check) — skipped if cargo-deny isn't installed.
#
# Install: scripts/install-hooks.sh

set -e
set -o pipefail

# Skip when CI itself runs the hook (it's already running these jobs).
if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
    exit 0
fi

# Allow opt-out for emergency commits — but warn loudly.
if [ -n "$SKIP_PRECOMMIT" ]; then
    echo "[pre-commit] SKIP_PRECOMMIT set — skipping all checks. Push at your own risk."
    exit 0
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

fail() {
    echo -e "${RED}[pre-commit] FAILED:${NC} $1"
    echo -e "${YELLOW}Bypass (only if you know why):${NC} SKIP_PRECOMMIT=1 git commit ..."
    exit 1
}

# Only run if there are staged Rust changes — formatting/lints don't matter
# for doc-only or workflow-only commits.
if ! git diff --cached --name-only | grep -qE '\.rs$|Cargo\.(toml|lock)$|deny\.toml$'; then
    exit 0
fi

# Add the standard rustup install location to PATH if cargo isn't already
# visible — git-bash on Windows and some bare shells inherit a stripped PATH.
have_cargo() {
    command -v cargo >/dev/null 2>&1 || command -v cargo.exe >/dev/null 2>&1
}
if ! have_cargo; then
    for candidate in "$HOME/.cargo/bin" "${USERPROFILE:-}/.cargo/bin"; do
        [ -z "$candidate" ] && continue
        if [ -x "$candidate/cargo" ] || [ -x "$candidate/cargo.exe" ]; then
            PATH="$candidate:$PATH"
            export PATH
            break
        fi
    done
fi
if ! have_cargo; then
    fail "cargo not on PATH — install rustup before committing Rust changes"
fi

echo -e "${YELLOW}[pre-commit]${NC} cargo fmt --all -- --check"
cargo fmt --all -- --check || fail "cargo fmt: run 'cargo fmt --all' and re-stage"

echo -e "${YELLOW}[pre-commit]${NC} cargo clippy --all-targets -- -D warnings"
cargo clippy --all-targets -- -D warnings 2>&1 | tail -30
# shellcheck disable=SC2181
[ "${PIPESTATUS[0]}" -eq 0 ] || fail "cargo clippy reported warnings"

if command -v cargo-deny >/dev/null 2>&1; then
    echo -e "${YELLOW}[pre-commit]${NC} cargo deny check"
    cargo deny check 2>&1 | tail -10 || fail "cargo deny: see deny.toml or update advisories"
else
    echo -e "${YELLOW}[pre-commit] note:${NC} cargo-deny not installed — skipping. Install with 'cargo install cargo-deny --locked' to mirror CI."
fi

echo -e "${GREEN}[pre-commit] OK${NC}"
