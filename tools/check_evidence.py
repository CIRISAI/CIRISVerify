#!/usr/bin/env python3
"""Resolve every symbol cited in ``evidence/cc_impl.tsv`` against the tree.

CIRISVerify#233 / CIRISConstitution#17.

CIRISVerify is the most-cited repo in the CC evidence layer — CIRISServer's
manifest alone names verify symbols for ~30 CC decimals — but verify published
no manifest of its own, so those pointers were asserted by a third party with
**no verify-side gate** confirming the symbols still resolve. A refactor here
silently rotted a constitutional citation over there.

This is that gate: a moved or renamed symbol is a build failure.

Deliberately a *source-level* resolver, not a doc check, for the same reason
``check-ffi-link-anchor.sh`` is: it runs in every configuration, including ones
where the cited item is behind a ``#[cfg]`` that this build does not enable.

It also pins each cited item's **source span** (CIRISVerify#233 follow-up): the
``span_sha256`` column is the SHA-256 of the item's own text, from its
declaration keyword to its closing ``}`` or ``;`` (doc comments and attributes
above it excluded; CRLF read as LF). A symbol whose body changes under an
unchanged name is then a failure too: the claim it backs must be re-read, and
the new hash recorded with ``--update-hashes`` in the same commit, so the change
shows in review.

Usage::

    python3 tools/check_evidence.py                 # verify
    python3 tools/check_evidence.py --list          # print resolved rows
    python3 tools/check_evidence.py --update-hashes # re-record span_sha256

Exit 0 = every citation resolves; 1 = at least one does not.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

#: The required first non-comment line of the manifest (CIRISVerify#250).
HEADER = "decimal_id\tclaim_id\trepo\tpath#symbol\tcrate@version\tspan_sha256"

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "evidence" / "cc_impl.tsv"

# `fn foo`, `struct Foo`, `const FOO`, … — the declaration forms a citation may
# name. `async`/`unsafe`/`pub(...)` prefixes are skipped by searching for the
# keyword itself rather than anchoring at line start.
ITEM_KINDS = "fn|struct|enum|const|static|trait|type|mod|union|macro_rules!"


def declares(text: str, symbol: str) -> bool:
    """Does `text` declare `symbol`?

    Handles both bare (`verify_transport_binding`) and qualified
    (`SignedTreeHead::cosign`) citations. For a qualified name BOTH halves must
    be present — the type must exist and the member must be declared — so a
    citation cannot silently resolve against an unrelated free function that
    happens to share the member's name.
    """
    if "::" in symbol:
        owner, _, member = symbol.rpartition("::")
        owner = owner.split("::")[-1]
        owner_ok = re.search(rf"\b(struct|enum|trait|type|union)\s+{re.escape(owner)}\b", text)
        member_ok = re.search(rf"\b({ITEM_KINDS})\s+{re.escape(member)}\b", text)
        return bool(owner_ok and member_ok)
    return bool(re.search(rf"\b({ITEM_KINDS})\s+{re.escape(symbol)}\b", text))


# --- source spans ------------------------------------------------------------

#: Kinds whose item ends at the closing brace of their body; the rest end at a
#: top-level `;` (a `const`'s block initializer is not its end).
BRACE_BODIED = {"fn", "struct", "enum", "trait", "mod", "union", "impl", "macro_rules!"}


def _code_mask(text: str) -> list[bool]:
    """True where `text[i]` is code: not in a comment, string or char literal."""
    n = len(text)
    code = [True] * n
    i = 0
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                code[k] = False
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            for k in range(i, j):
                code[k] = False
            i = j
        elif re.match(r'b?r#*"', text[i : i + 64]) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = re.match(r'b?r(#*)"', text[i:])
            close = '"' + m.group(1)
            j = text.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            for k in range(i, j):
                code[k] = False
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            for k in range(i, j):
                code[k] = False
            i = j
        elif c == "'":
            # A char literal ('x', '\n', '\u{..}') rather than a lifetime ('a).
            m = re.match(r"'(\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'", text[i : i + 16])
            if m:
                for k in range(i, i + m.end()):
                    code[k] = False
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return code


def _item_end(text: str, code: list[bool], start: int, kind: str) -> int:
    """Index one past the end of the item whose declaration starts at `start`."""
    depth = 0
    for j in range(start, len(text)):
        if not code[j]:
            continue
        ch = text[j]
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
            if depth == 0 and ch == "}" and kind in BRACE_BODIED:
                return j + 1
        elif ch == ";" and depth == 0:
            return j + 1
    raise ValueError("item never closes")


def _decls(text: str, code: list[bool], kind_re: str, name: str, lo: int = 0, hi: int | None = None):
    hi = len(text) if hi is None else hi
    pat = re.compile(rf"\b({kind_re})\s+{re.escape(name)}\b")
    for m in pat.finditer(text, lo, hi):
        # `'static T` is a lifetime, not a `static` item.
        if code[m.start()] and (m.start() == 0 or text[m.start() - 1] != "'"):
            yield m.start(), m.group(1)


def span_of(text: str, symbol: str) -> str:
    """The cited item's source text. Raises ValueError if not exactly one."""
    text = text.replace("\r\n", "\n")
    code = _code_mask(text)
    if "::" in symbol:
        owner, _, member = symbol.rpartition("::")
        owner = owner.split("::")[-1]
        hits = []
        blocks = re.compile(rf"\b(impl\b[^;{{]*?\b{re.escape(owner)}\b[^;{{]*|trait\s+{re.escape(owner)}\b[^;{{]*)\{{")
        for b in blocks.finditer(text):
            if not code[b.start()]:
                continue
            kind = "trait" if b.group(0).lstrip().startswith("trait") else "impl"
            end = _item_end(text, code, b.start(), kind)
            hits += [(s, k) for s, k in _decls(text, code, ITEM_KINDS, member, b.start() + 1, end)]
        if not hits:
            # A type-level constant or alias: fall back to the bare member.
            hits = list(_decls(text, code, ITEM_KINDS, member))
    else:
        hits = list(_decls(text, code, ITEM_KINDS, symbol))
    if len(hits) != 1:
        raise ValueError(f"{len(hits)} declarations of {symbol}; cite it unambiguously (Owner::member)")
    start, kind = hits[0]
    return text[start : _item_end(text, code, start, kind)]


def span_sha256(text: str, symbol: str) -> str:
    return hashlib.sha256(span_of(text, symbol).encode("utf-8")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print each resolved row")
    ap.add_argument(
        "--update-hashes",
        action="store_true",
        help="re-record every span_sha256 (after re-reading the claims whose spans changed)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the guards actually reject bad manifests, then exit",
    )
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.update_hashes:
        return _update_hashes()
    return _check(list_rows=args.list)


def _update_hashes() -> int:
    """Rewrite the span_sha256 column in place; print each row that changed."""
    out, changed = [], 0
    seen_header = False
    for raw in MANIFEST.read_text().splitlines():
        if not raw.strip() or raw.startswith("#"):
            out.append(raw)
            continue
        if not seen_header:
            seen_header = True
            out.append(HEADER)
            continue
        fields = raw.split("\t")
        fields += [""] * (6 - len(fields))
        path_str, _, symbol = fields[3].partition("#")
        new = span_sha256((REPO / path_str).read_text(errors="ignore"), symbol) if symbol else ""
        if new != fields[5]:
            changed += 1
            print(f"  span changed: CC {fields[0]} ({fields[1]}) {fields[3]}")
        fields[5] = new
        out.append("\t".join(fields[:6]))
    MANIFEST.write_text("\n".join(out) + "\n")
    print(f"evidence: {changed} span hash(es) re-recorded")
    return 0


def _check(list_rows: bool) -> int:
    """Validate the manifest at :data:`MANIFEST`. Returns a process exit code."""
    if not MANIFEST.exists():
        print(f"ERROR: {MANIFEST} not found", file=sys.stderr)
        return 1

    resolved = 0
    unassigned = 0
    failures: list[str] = []

    seen_header = False
    for lineno, raw in enumerate(MANIFEST.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # The first non-comment line is the column header (CIRISVerify#250).
        # It is VALIDATED rather than skipped: a reordered or renamed column
        # would otherwise pass silently while every downstream consumer that
        # reads by position started reading the wrong field.
        if not seen_header:
            seen_header = True
            if raw != HEADER:
                failures.append(
                    f"{MANIFEST.name}:{lineno}: first non-comment line must be the "
                    f"column header\n    expected: {HEADER!r}\n    found:    {raw!r}"
                )
            continue

        fields = raw.split("\t")
        if len(fields) < 4:
            failures.append(f"{MANIFEST.name}:{lineno}: expected >=4 tab-separated fields")
            continue

        decimal, clm, _repo, ref = fields[0], fields[1], fields[2], fields[3]
        pinned = fields[5] if len(fields) > 5 else ""
        path_str, _, symbol = ref.partition("#")
        path = REPO / path_str

        if not path.exists():
            failures.append(f"CC {decimal} ({clm}): file not found — {path_str}")
            continue
        text = path.read_text(errors="ignore")
        if symbol and not declares(text, symbol):
            failures.append(f"CC {decimal} ({clm}): symbol not declared — {ref}")
            continue
        if symbol:
            try:
                actual = span_sha256(text, symbol)
            except ValueError as e:
                failures.append(f"CC {decimal} ({clm}): {e} — {ref}")
                continue
            if not re.fullmatch(r"[0-9a-f]{64}", pinned):
                failures.append(f"CC {decimal} ({clm}): no span_sha256 recorded — {ref}")
                continue
            if actual != pinned:
                failures.append(
                    f"CC {decimal} ({clm}): the cited item's source changed under its name — {ref}\n"
                    f"    re-read the claim; if it still holds, record the new span with --update-hashes"
                )
                continue

        resolved += 1
        if decimal == "UNASSIGNED":
            unassigned += 1
        if list_rows:
            print(f"  ok  CC {decimal:<12} {clm:<44} {ref}")

    if not seen_header:
        failures.append(f"{MANIFEST.name}: no column header row found")

    print(
        f"evidence: {resolved} citation(s) resolved, {len(failures)} unresolved"
        + (f", {unassigned} awaiting a CC decimal" if unassigned else "")
    )
    if unassigned:
        # Not a failure: shipped surface with no CC identifier yet. Surfaced so
        # the Constitution can issue decimals against a real implementation
        # rather than against a proposal (CIRISVerify#233).
        print(
            f"  note: {unassigned} row(s) marked UNASSIGNED — symbols resolve, "
            "decimals pending CC assignment"
        )
    for f in failures:
        print(f"  ✗ {f}", file=sys.stderr)

    if failures:
        print(
            "\nA cited symbol moved, was renamed, or its source changed. Update "
            "evidence/cc_impl.tsv in the same commit — a constitutional citation must "
            "not rot silently (CIRISVerify#233).",
            file=sys.stderr,
        )
        return 1
    return 0


def _with_hash(row: str, value: str) -> str:
    f = row.split("\t")
    f += [""] * (6 - len(f))
    f[5] = value
    return "\t".join(f[:6])


def _span_self_test() -> int:
    """The span extractor on the shapes it must get right."""
    src = (
        "/// doc { not code\n"
        "#[inline]\n"
        "pub fn a(x: &str) -> u8 { let s = \"}\"; let c = '}'; let r = r#\"}\"#; /* } */ 1 } // }\n"
        "pub const B: u8 = { 2 };\n"
        "pub struct T(u8);\n"
        "pub struct U { f: u8 }\n"
        "impl U { pub fn a(&self) -> u8 { 3 } }\n"
        "fn life<'a>(x: &'a u8) -> &'a u8 { x }\n"
        "fn lookup() -> Option<&'static U> { None }\n"
    )
    want = {
        "B": "const B: u8 = { 2 };",
        "T": "struct T(u8);",
        "U": "struct U { f: u8 }",
        "U::a": "fn a(&self) -> u8 { 3 }",
        "life": "fn life<'a>(x: &'a u8) -> &'a u8 { x }",
    }
    failed = 0
    for sym, exp in want.items():
        got = span_of(src, sym)
        ok = got == exp
        failed += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} span {sym}: {got!r}")
    try:
        span_of(src, "a")  # a free fn and U::a: ambiguous by bare name
        print("  FAIL span a: ambiguity not refused")
        failed += 1
    except ValueError:
        print("  ok   span a: ambiguous bare name refused")
    return failed


def self_test() -> int:
    """Prove the guards reject what they claim to reject.

    A validator nobody tests is a validator that silently stops validating —
    which is the exact failure class this manifest exists to prevent, so it
    would be poor form for the checker itself to carry it (CIRISVerify#250).
    """
    import tempfile

    global MANIFEST

    real = MANIFEST.read_text()
    data_rows = [
        l for l in real.splitlines() if l.strip() and not l.startswith("#") and l != HEADER
    ]
    cases: list[tuple[str, str, bool]] = [
        (
            "reordered header",
            "\n".join(["claim_id\tdecimal_id\trepo\tpath#symbol\tcrate@version", *data_rows]),
            True,
        ),
        ("missing header", "\n".join(data_rows), True),
        (
            "moved symbol",
            "\n".join(
                [HEADER, "9.9.9\tCLM-nope\tCIRISVerify\tsrc/ciris-verify-core/src/jcs.rs#no_such_fn_xyz\tx@v1"]
            ),
            True,
        ),
        (
            "a span hash that does not match the source",
            "\n".join([HEADER, *(_with_hash(r, "0" * 64) for r in data_rows[:1])]),
            True,
        ),
        (
            "a row with no span hash",
            "\n".join([HEADER, *(_with_hash(r, "") for r in data_rows[:1])]),
            True,
        ),
        ("the real manifest", real, False),
    ]

    original = MANIFEST
    failed = _span_self_test()
    try:
        for name, body, must_fail in cases:
            with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as fh:
                fh.write(body)
                MANIFEST = Path(fh.name)
            rc = _check(list_rows=False)
            ok = (rc != 0) if must_fail else (rc == 0)
            print(f"  {'ok  ' if ok else 'FAIL'} {name}: rc={rc} (expected {'nonzero' if must_fail else '0'})")
            if not ok:
                failed += 1
            MANIFEST.unlink(missing_ok=True)
    finally:
        MANIFEST = original

    print(f"self-test: {'all passed' if not failed else f'{failed} failed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
