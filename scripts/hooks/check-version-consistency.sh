#!/usr/bin/env bash
set -euo pipefail

CARGO_VER=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
PYPROJECT_VER=$(grep '^version = ' bindings/python/pyproject.toml | cut -d'"' -f2)
INIT_VER=$(grep '^__version__' bindings/python/ciris_verify/__init__.py | cut -d'"' -f2)

if [ "$CARGO_VER" != "$PYPROJECT_VER" ] || [ "$CARGO_VER" != "$INIT_VER" ]; then
    echo "ERROR: Version mismatch!"
    echo "  Cargo.toml:     $CARGO_VER"
    echo "  pyproject.toml: $PYPROJECT_VER"
    echo "  __init__.py:    $INIT_VER"
    exit 1
fi

echo "Version consistent: $CARGO_VER"
