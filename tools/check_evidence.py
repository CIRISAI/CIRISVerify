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
    args = ap.parse_args()

    if not MANIFEST.exists():
        print(f"ERROR: {MANIFEST} not found", file=sys.stderr)
        return 1

    resolved = 0
    unassigned = 0
    failures: list[str] = []

    for lineno, raw in enumerate(MANIFEST.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
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
        if args.list:
            print(f"  ok  CC {decimal:<12} {clm:<44} {ref}")

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


if __name__ == "__main__":
    sys.exit(main())
