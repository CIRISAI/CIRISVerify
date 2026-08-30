#!/usr/bin/env bash
# CIRIS Logging Standard §5 — "what must never be logged" (CIRISVerify#265).
#
# Verify handles seeds, private keys, PINs and DEKs. Today no `tracing` event
# interpolates one: the crate logs `alias`, `key_id` and public halves only.
# This guard keeps that true, because §5 asks for redaction "with a test", and
# the honest test for "we never log secrets" is one that fails when someone
# starts.
#
# It scans the BALANCED ARGUMENT LIST of each tracing macro — not a fixed
# window of trailing lines, which would flag ordinary code that merely follows
# a log call. It matches an interpolated secret-shaped binding (`seed = %x`),
# not the mention of the word, so `warn!("no identity key loaded")` stays legal.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 - "$@" <<'PY'
import re, sys, pathlib

NAMES = (r'seed|secret|private_key|privkey|priv_key|password|passphrase'
         r'|pin|dek|master_key|wrap_key')
# Three ways a secret reaches a tracing event, all of which must be caught
# (#268 P2 — the first version only caught the explicit-field form, so
# `?seed` and `"seed: {:?}", seed` both slipped through):
#   1. explicit field   seed = %x        / seed = x
#   2. shorthand field  %seed  ?seed  seed,        (tracing's own sugar)
#   3. positional arg   info!("seed: {:?}", seed)
SECRET = re.compile(
    r'(?<![a-z_])(?:' + NAMES + r')\s*=\s*[%?]?\s*[A-Za-z_&*(]'     # 1
    r'|[%?](?:' + NAMES + r')(?![a-z_])'                             # 2 sigil
    r'|(?<![a-z_.])(?:' + NAMES + r')\s*(?:,|\)|$)',                 # 2 bare / 3
    re.I)
# public by construction, or a non-secret that merely contains the substring
ALLOW = re.compile(r'key_id|pubkey|public_key|_pub\b|seed_dir|seed_file|seed_path'
                   r'|pin_policy|pin_required|has_pin|pin\s*=\s*(true|false)', re.I)
MACRO = re.compile(r'\b(?:tracing::)?(warn|info|error|debug|trace)!\(')

bad = []
for f in sorted(pathlib.Path("src").rglob("*.rs")):
    if "/tests/" in str(f):
        continue
    src = f.read_text(errors="ignore")
    for m in MACRO.finditer(src):
        i, depth = m.end(), 1
        while i < len(src) and depth:
            depth += (src[i] == "(") - (src[i] == ")")
            i += 1
        args = src[m.end():i-1]
        for line in args.split("\n"):
            code = line.split("//")[0]
            if SECRET.search(code) and not ALLOW.search(code):
                ln = src[:m.start()].count("\n") + 1
                bad.append(f"  {f}:{ln}: {code.strip()[:90]}")

if bad:
    print("ERROR: a tracing event interpolates secret material:", file=sys.stderr)
    print("\n".join(bad), file=sys.stderr)
    print("\n  CIRIS Logging Standard §5: secrets must never reach the log.", file=sys.stderr)
    print("  Log a non-reversible handle (alias, key_id, fingerprint) instead.", file=sys.stderr)
    sys.exit(1)
print("no secret-shaped values in tracing events ✓")
PY
