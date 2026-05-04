# Dev hygiene — keep `target/` from eating the disk

This page documents the self-cleaning behaviors built into the CIRISVerify dev process. They were added after a 2026-05-04 session that bumped the workspace version six times in one afternoon and accumulated ~180GB in `target/debug/` before the filesystem ran out and shell tooling started failing mid-commit.

The fixes are layered. Each level catches a different scale of accumulation.

## Layer 1 — disable incremental compilation (root `Cargo.toml`)

```toml
[profile.dev]
incremental = false
```

`target/debug/incremental/` is a hash-keyed query cache that's never garbage-collected — it grows monotonically with every change. For this workspace specifically, every release bumps `[workspace.package].version`, which invalidates *every* incremental key at once. The cache provides no benefit and costs the bulk of `target/debug/` size. Disabling it keeps `target/debug/` proportional to actual artifacts, not change history.

Trade-off: clean rebuilds after every change instead of incremental rebuilds. Acceptable here because (a) workspace version churn already invalidated the cache anyway, and (b) `cargo check` (no codegen) covers the tight-feedback-loop case faster than `cargo build` ever did.

## Layer 2 — `bump-version.sh` runs `cargo clean` after each bump

`scripts/bump-version.sh` ends with a `cargo clean` step. A workspace version bump invalidates the incremental cache and per-version build artifacts; the next `cargo check`/`cargo build` rebuilds whatever's needed. The clean costs nothing perf-wise (caches were dead anyway) and prevents stale per-version dirs from accumulating.

Skip the clean for a particular bump with `BUMP_NO_CLEAN=1 scripts/bump-version.sh <version>` if you're debugging a build issue that needs target/ preserved.

## Layer 3 — periodic `clean-stale-targets.sh`

`scripts/clean-stale-targets.sh` walks `~/CIRIS*` + `~/RATCHET` and prunes `target/` artifacts older than N days (default 14):

```bash
scripts/clean-stale-targets.sh         # 14-day default
scripts/clean-stale-targets.sh 7       # 7-day cutoff
DAYS_OLD=30 scripts/clean-stale-targets.sh   # via env
```

Mechanism: prefers `cargo-sweep` (proper artifact-walker, respects build graph; install with `cargo install cargo-sweep`); falls back to a `find`-based sweep that targets the worst accumulators (`incremental/` + `build/` dirs) when cargo-sweep isn't installed.

Active-repo guard: skips any repo with a commit in the last 24h (`ACTIVE_GUARD_HOURS=24`) so an in-progress session isn't disrupted.

### Recommended cron entry

```cron
# Weekly, Sunday at 3am: prune cargo target/ artifacts older than 14 days
0 3 * * 0  /home/emoore/CIRISVerify/scripts/clean-stale-targets.sh 14 >> /var/log/ciris-target-sweep.log 2>&1
```

Or as a systemd timer if you prefer; the script is cron/systemd-friendly (idempotent, returns 0 on success, no interactive prompts).

## What none of these do

- **`cargo clean` on `release/`**. The release tarball process needs `target/release/` artifacts present. Cleaning release would force every CI re-run to rebuild from scratch, and `bump-version.sh`'s clean correctly leaves release alone via `cargo clean` (which by default cleans both, but is fine to re-run since the next `cargo build --release` rebuilds). `clean-stale-targets.sh` with cargo-sweep similarly respects build-graph reachability.
- **Touch `~/CIRISPersist/target/`** when persist's 94GB problem turns out to be something other than cargo (e.g., a runaway test database in a non-`target/` path). Investigate persist's usage separately.
- **Anything outside `~/CIRIS*` or `~/RATCHET`**.

## Diagnostic recipe

If `target/` size feels off:

```bash
# What's biggest right now?
du -sh ~/CIRISVerify/target/* | sort -h

# Just the incremental layer:
du -sh ~/CIRISVerify/target/*/incremental 2>/dev/null

# Quick win without losing release artifacts:
rm -rf ~/CIRISVerify/target/debug/

# Nuclear:
cargo clean
```
