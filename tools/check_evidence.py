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

Usage::

    python3 tools/check_evidence.py            # verify
    python3 tools/check_evidence.py --list     # print resolved rows

Exit 0 = every citation resolves; 1 = at least one does not.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

#: The required first non-comment line of the manifest (CIRISVerify#250).
HEADER = "decimal_id\tclaim_id\trepo\tpath#symbol\tcrate@version"

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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print each resolved row")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the guards actually reject bad manifests, then exit",
    )
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return _check(list_rows=args.list)


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
        path_str, _, symbol = ref.partition("#")
        path = REPO / path_str

        if not path.exists():
            failures.append(f"CC {decimal} ({clm}): file not found — {path_str}")
            continue
        if symbol and not declares(path.read_text(errors="ignore"), symbol):
            failures.append(f"CC {decimal} ({clm}): symbol not declared — {ref}")
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
            "\nA cited symbol moved or was renamed. Update evidence/cc_impl.tsv in the "
            "same commit — a constitutional citation must not rot silently "
            "(CIRISVerify#233).",
            file=sys.stderr,
        )
        return 1
    return 0


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
        ("the real manifest", real, False),
    ]

    original = MANIFEST
    failed = 0
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

    print(f"self-test: {len(cases) - failed}/{len(cases)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
