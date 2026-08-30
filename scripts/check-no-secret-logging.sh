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
# Optional argv[1]: directory to scan (default `src`). Used by
# scripts/test-secret-logging-guard.sh to run the matrix against fixtures.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 - "${1:-src}" <<'PY'
import re, sys, pathlib

NAMES = (r'seed|secret|private_key|privkey|priv_key|password|passphrase'
         r'|pin|dek|master_key|wrap_key')
# Three ways a secret reaches a tracing event, all of which must be caught
# (#268 P2 — the first version only caught the explicit-field form, so
# `?seed` and `"seed: {:?}", seed` both slipped through):
#   1. explicit field    seed = %x        / seed = x
#   2. shorthand field   %seed  ?seed  seed,       (tracing's own sugar)
#   3. inline capture    info!("seed={seed:?}")    (Rust 2021 implicit capture)
#   4. positional / member
#                        info!("s: {:?}", seed) / info!("{:?}", cfg.pin)
#
# 3 and 4 were added after review (#268): the first version required a
# following `=`, and the fourth case additionally required the name NOT be
# preceded by a dot — which silently exempted every `self.seed` / `cfg.pin`.
SECRET = re.compile(
    r'(?<![a-z_])(?:' + NAMES + r')\s*=\s*[%?]?\s*[A-Za-z_&*(]'     # 1 explicit field
    r'|[%?](?:' + NAMES + r')(?![a-z_])'                             # 2 sigil shorthand
    r'|\{[a-z_.]*(?:' + NAMES + r')[a-z_.]*[:}]'                     # 3 inline capture
    r'|(?<![a-z_])(?:[a-z_]+\.)*(?:' + NAMES + r')\s*(?:,|\)|$)',    # 4 positional / member
    re.I)
# public by construction, or a non-secret that merely contains the substring
ALLOW = re.compile(r'key_id|pubkey|public_key|_pub\b|seed_dir|seed_file|seed_path'
                   r'|pin_policy|pin_required|has_pin|pin\s*=\s*(true|false)', re.I)
MACRO = re.compile(r'\b(?:tracing::)?(warn|info|error|debug|trace)!\(')

bad = []

def scan_macro_args(src, open_at):
    """Return the macro's argument text, comments removed, literals kept.

    ONE pass that understands strings, chars, line comments and (nesting)
    block comments — rather than a paren counter and a comment stripper that
    each know about half the syntax and disagree about where the code ends.

    That disagreement was not hypothetical: review found the counter fooled by
    a `)` inside a string, then the stripper cutting at a `//` inside a URL,
    then the counter fooled by a `)` inside a comment — three instances of one
    class, fixed one at a time. This function is the class.

    String CONTENTS are preserved, because a secret can legitimately appear
    inside a format string (`"seed={seed:?}"` is Rust 2021 implicit capture).
    Comment contents are dropped, because a comment cannot log anything.
    """
    out = []
    i, depth = open_at, 1
    n = len(src)
    while i < n and depth:
        c = src[i]
        # line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        # block comment (Rust's nest)
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            nest, i = 1, i + 2
            while i < n and nest:
                if src.startswith("/*", i):
                    nest, i = nest + 1, i + 2
                elif src.startswith("*/", i):
                    nest, i = nest - 1, i + 2
                else:
                    i += 1
            continue
        # string literal — copied out, parens inside do not count
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if src[i] == "\\":
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        # char literal, but not a lifetime (`'a`)
        if c == "'" and not (i + 1 < n and src[i + 1].isalpha()
                             and (i + 2 >= n or src[i + 2] != "'")):
            out.append(c)
            i += 1
            while i < n:
                if src[i] == "\\":
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == "'":
                    i += 1
                    break
                i += 1
            continue
        depth += (c == "(") - (c == ")")
        if depth:
            out.append(c)
        i += 1
    return "".join(out)


SCAN_ROOT = sys.argv[1] if len(sys.argv) > 1 else "src"
INSTRUMENT = re.compile(r'#\[instrument([^\]]*)\]\s*(?:pub\s+)?(?:async\s+)?fn\s+\w+\s*\(', re.S)

def instrumented_params(src, m):
    """Secret-shaped params an `#[instrument]` fn records but does not skip.

    `#[instrument]` records EVERY argument as a span field unless listed in
    `skip`/`skip_all`, with no logging macro anywhere — so scanning only the
    macros misses it entirely (#268). The attribute IS the log statement.
    """
    attr = m.group(1)
    if "skip_all" in attr:
        return []
    skipped = set(re.findall(r'[\w]+', attr[attr.index("skip"):]) if "skip" in attr else [])
    # balanced param list
    i, depth = m.end(), 1
    while i < len(src) and depth:
        depth += (src[i] == "(") - (src[i] == ")")
        i += 1
    params = src[m.end():i-1]
    out = []
    for part in params.split(","):
        if ":" not in part:
            continue
        name, ty = part.split(":", 1)
        name = name.strip().lstrip("&").replace("mut ", "").strip()
        ty = ty.strip()
        if not name or name == "self" or name in skipped:
            continue
        if not re.fullmatch(r'(?:%s)' % NAMES, name, re.I) or ALLOW.search(name):
            continue
        # A primitive integer cannot CARRY key material — a 32-byte key does
        # not fit in a u64. `audit::verify_spot_check(seed: u64)` is a sampling
        # seed for reproducible spot checks, and logging it is useful rather
        # than dangerous. Byte- and string-typed params are still caught, which
        # is where real key material lives.
        if re.fullmatch(r'(?:u|i)(?:8|16|32|64|128|size)', ty):
            continue
        out.append(name)
    return out


for f in sorted(pathlib.Path(SCAN_ROOT).rglob("*.rs")):
    if "/tests/" in str(f):
        continue
    src = f.read_text(errors="ignore")
    for m in INSTRUMENT.finditer(src):
        for name in instrumented_params(src, m):
            ln = src[:m.start()].count("\n") + 1
            bad.append(
                f"  {f}:{ln}: #[instrument] records `{name}` (add it to skip(...))"
            )
    for m in MACRO.finditer(src):
        args = scan_macro_args(src, m.end())
        for hit in SECRET.finditer(args):
            if ALLOW.search(hit.group(0)):
                continue
            ln = src[:m.start()].count("\n") + 1
            bad.append(f"  {f}:{ln}: {hit.group(0).strip()[:90]}")
            break

if bad:
    print("ERROR: a tracing event interpolates secret material:", file=sys.stderr)
    print("\n".join(bad), file=sys.stderr)
    print("\n  CIRIS Logging Standard §5: secrets must never reach the log.", file=sys.stderr)
    print("  Log a non-reversible handle (alias, key_id, fingerprint) instead.", file=sys.stderr)
    sys.exit(1)
print("no secret-shaped values in tracing events ✓")
PY
