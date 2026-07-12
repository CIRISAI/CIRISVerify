#!/usr/bin/env bash
# CIRISVerify#197 — the FFI must be COMPLETELY PASSIVE at load time.
#
# `early_verify()` builds a Tokio runtime and block_on's an HTTPS fetch. Running
# that from any loader callback deadlocks the loader (the callback holds the
# loader lock; the runtime worker needs that same lock to start). This bit us on
# Linux (#51) and again on Windows (#197 — `import ciris_server` hung forever).
#
# Guard: no DllMain / #[ctor::ctor] / .init_array / .CRT$ hooks in the FFI crate.
set -euo pipefail
SRC="src/ciris-verify-ffi/src"
# Strip comments + doc-comments, then look for real code.
hits="$(
  grep -rnE '^[^/]*(\bDllMain\b|#\[ctor::ctor\]|#\[ctor\]|link_section\s*=\s*"\.init_array|link_section\s*=\s*"\.CRT)' "$SRC"/*.rs \
    | grep -vE '^\S+:[0-9]+:\s*//' || true
)"
if [ -n "$hits" ]; then
  echo "::error::CIRISVerify#197 — a loader callback was reintroduced into ciris-verify-ffi."
  echo "$hits"
  echo "early_verify() must stay lazily triggered from ciris_verify_init(); a Tokio"
  echo "runtime + HTTPS fetch under the loader lock DEADLOCKS (DllMain / dlopen / dyld)."
  exit 1
fi
echo "ffi load path is passive: no DllMain / ctor / .init_array hooks ✓"
