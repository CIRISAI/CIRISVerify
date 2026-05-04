#!/usr/bin/env bash
# clean-stale-targets.sh — prune cargo `target/` artifacts older than N days
# across CIRIS* repos. Recovers disk from cross-compile outputs + incremental
# query caches that accumulate over time.
#
# Usage:
#     scripts/clean-stale-targets.sh [DAYS_OLD]
#
# DAYS_OLD defaults to 14. Override the parent dir with PARENT_DIR env var.
#
# Cron-friendly. Recommended weekly:
#     0 3 * * 0 ~/CIRISVerify/scripts/clean-stale-targets.sh 14
#
# Mechanism:
#   - Prefers `cargo-sweep` (proper artifact-walker, respects build graph).
#     Install with: `cargo install cargo-sweep`
#   - Falls back to a `find`-based sweep targeting the worst accumulators
#     (per-target `incremental/` dirs and `release/build/`) older than N days.
#
# What this does NOT do:
#   - Touch `target/` for repos with active commits in the last 24h (dev
#     guard so an in-progress session isn't disrupted).
#   - Run `cargo clean` (full nuke). Use `cargo clean` directly when you
#     want that.
#   - Touch anything outside the listed repo-name patterns.

set -euo pipefail

DAYS_OLD="${1:-14}"
PARENT_DIR="${PARENT_DIR:-$HOME}"
ACTIVE_GUARD_HOURS="${ACTIVE_GUARD_HOURS:-24}"

if ! [[ "$DAYS_OLD" =~ ^[0-9]+$ ]] || [ "$DAYS_OLD" -lt 1 ]; then
    echo "ERROR: DAYS_OLD must be a positive integer, got: $DAYS_OLD" >&2
    exit 2
fi

echo "Pruning cargo target/ artifacts older than ${DAYS_OLD} days under ${PARENT_DIR}/"

if command -v cargo-sweep >/dev/null 2>&1; then
    method="cargo-sweep"
else
    method="find+rm"
    echo "(cargo-sweep not installed; using find+rm fallback)"
    echo "  install with: cargo install cargo-sweep"
fi
echo

human_bytes() {
    local n="${1:-0}"
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec-i --suffix=B "$n" 2>/dev/null || echo "${n}B"
    else
        echo "${n}B"
    fi
}

du_bytes() {
    local path="$1"
    [ -d "$path" ] || { echo 0; return; }
    du -sb "$path" 2>/dev/null | cut -f1 || echo 0
}

is_repo_active() {
    # Skip repos with commits in the last $ACTIVE_GUARD_HOURS — don't disrupt
    # in-progress dev sessions.
    local repo="$1"
    [ -d "$repo/.git" ] || return 1
    local head_age
    head_age=$(git -C "$repo" log -1 --format=%ct 2>/dev/null || echo 0)
    local now
    now=$(date +%s)
    local age_hours=$(( (now - head_age) / 3600 ))
    [ "$age_hours" -lt "$ACTIVE_GUARD_HOURS" ]
}

total_freed=0
repos_processed=0
repos_skipped_active=0
repos_skipped_no_target=0

for repo in "${PARENT_DIR}"/CIRIS* "${PARENT_DIR}"/RATCHET; do
    [ -d "$repo" ] || continue
    [ -d "$repo/target" ] || { repos_skipped_no_target=$(( repos_skipped_no_target + 1 )); continue; }

    if is_repo_active "$repo"; then
        printf "  %-40s SKIP (active in last %sh)\n" "$(basename "$repo")" "$ACTIVE_GUARD_HOURS"
        repos_skipped_active=$(( repos_skipped_active + 1 ))
        continue
    fi

    before=$(du_bytes "$repo/target")

    if [ "$method" = "cargo-sweep" ]; then
        (cd "$repo" && cargo sweep --time "$DAYS_OLD" >/dev/null 2>&1) || true
    else
        # Fallback: prune incremental/ dirs (worst accumulators) + per-target
        # build/ output dirs older than N days. Conservative — avoids touching
        # release/ artifacts since they may be referenced by tarballs.
        find "$repo/target" -type d -name "incremental" -mtime "+${DAYS_OLD}" -print0 2>/dev/null \
            | xargs -0 -r rm -rf 2>/dev/null || true
        find "$repo/target" -maxdepth 4 -type d -name "build" -mtime "+${DAYS_OLD}" -print0 2>/dev/null \
            | xargs -0 -r rm -rf 2>/dev/null || true
    fi

    after=$(du_bytes "$repo/target")
    freed=$(( before - after ))
    if [ "$freed" -gt 0 ]; then
        printf "  %-40s freed %s\n" "$(basename "$repo")" "$(human_bytes "$freed")"
        total_freed=$(( total_freed + freed ))
    else
        printf "  %-40s (nothing stale)\n" "$(basename "$repo")"
    fi
    repos_processed=$(( repos_processed + 1 ))
done

echo
echo "Total freed: $(human_bytes "$total_freed")"
echo "  Processed:    $repos_processed repo(s)"
[ "$repos_skipped_active" -gt 0 ] && echo "  Skipped (active): $repos_skipped_active"
[ "$repos_skipped_no_target" -gt 0 ] && echo "  Skipped (no target/): $repos_skipped_no_target"
