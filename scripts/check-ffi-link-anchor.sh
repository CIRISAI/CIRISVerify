#!/usr/bin/env bash
# CIRISVerify#189 — ensure every `#[no_mangle] pub extern "C" fn` in
# ciris-verify-ffi is referenced by `ciris_verify_ffi_link_anchor()`. If one is
# missing, it dead-strips out of ciris-server's cdylib fold (CIRISServer#232)
# per-platform-silently. Source-level (no nm/dumpbin) so it runs anywhere.
set -euo pipefail
SRC="src/ciris-verify-ffi/src"
mapfile -t fns < <(
  grep -rhoE 'extern "C" fn ciris_verify_[a-z_0-9]+' "$SRC"/*.rs \
    | sed 's/.*extern "C" fn //' \
    | grep -v '^ciris_verify_ffi_link_anchor$' | sort -u
)
# The anchor fn body: from its signature to its matching top-level close.
anchor="$(awk '/pub extern "C" fn ciris_verify_ffi_link_anchor/{f=1} f{print} f&&/^}/{exit}' "$SRC/lib.rs")"
missing=0
for fn in "${fns[@]}"; do
  grep -qE "\\b${fn}\\b" <<<"$anchor" || { echo "::error::FFI export '${fn}' is NOT in ciris_verify_ffi_link_anchor() — add it (CIRISVerify#189)"; missing=1; }
done
if [ "$missing" -eq 0 ]; then
  echo "ffi link-anchor covers all ${#fns[@]} exported ciris_verify_* symbols ✓"
fi
exit "$missing"
