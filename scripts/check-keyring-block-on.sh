#!/usr/bin/env bash
# CIRISVerify#204 — ciris-keyring must NEVER build+block_on a fresh tokio runtime
# directly from its synchronous surface. `Runtime::block_on` panics
# ("Cannot start a runtime from within a runtime") whenever the calling thread is
# already inside a runtime — ALWAYS true on the CIRISAgent embedded topology
# (Python asyncio + in-process Engine), and it was FATAL on the android fold boot.
#
# Every such site must go through `crate::rt::keyring_block_on`, which checks
# `Handle::try_current()` and hops to a scratch thread when a runtime is active.
# This guard fails if a raw `Builder::new*().build()...block_on` is reintroduced
# anywhere in the keyring except the one blessed home (src/rt.rs).
set -euo pipefail
SRC="src/ciris-keyring/src"
# Any current/multi-thread runtime BUILD outside rt.rs is the footgun (each such
# build is paired with a block_on; catching the build catches the pattern).
hits="$(grep -rnE 'Builder::new_(current|multi)_thread' "$SRC" \
          --include='*.rs' | grep -v '/rt.rs:' | grep -vE ':[0-9]+:\s*//' || true)"
if [ -n "$hits" ]; then
  echo "::error::CIRISVerify#204 — a raw tokio runtime build was reintroduced in ciris-keyring."
  echo "$hits"
  echo "Use crate::rt::keyring_block_on(fut) instead — a bare Runtime::block_on panics"
  echo "under an ambient runtime (the mobile fold-boot topology) and was FATAL on android."
  exit 1
fi
echo "keyring block_on is reentrancy-safe: no raw runtime builds outside rt.rs ✓"
