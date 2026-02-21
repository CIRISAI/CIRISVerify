#!/bin/bash
# bump-version.sh - Bump version across all CIRISVerify components
#
# Usage: ./scripts/bump-version.sh 0.6.1
#
# Updates:
#   - Cargo.toml (workspace version)
#   - bindings/python/pyproject.toml
#   - bindings/python/ciris_verify/__init__.py

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory and repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Validate arguments
if [ -z "$1" ]; then
    echo -e "${RED}Error: Version argument required${NC}"
    echo "Usage: $0 <version>"
    echo "Example: $0 0.6.1"
    exit 1
fi

NEW_VERSION="$1"

# Validate version format (semver)
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo -e "${RED}Error: Invalid version format '$NEW_VERSION'${NC}"
    echo "Expected semver format: X.Y.Z or X.Y.Z-suffix"
    exit 1
fi

echo -e "${YELLOW}Bumping version to ${NEW_VERSION}${NC}"
echo ""

# Track changes
CHANGES=()

# 1. Update Cargo.toml workspace version
CARGO_TOML="$REPO_ROOT/Cargo.toml"
if [ -f "$CARGO_TOML" ]; then
    OLD_VERSION=$(grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"' "$CARGO_TOML" | head -1 | sed 's/version = "\(.*\)"/\1/')
    if [ "$OLD_VERSION" != "$NEW_VERSION" ]; then
        sed -i "s/^version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
        CHANGES+=("Cargo.toml: $OLD_VERSION -> $NEW_VERSION")
        echo -e "${GREEN}✓${NC} Cargo.toml: $OLD_VERSION -> $NEW_VERSION"
    else
        echo -e "${YELLOW}○${NC} Cargo.toml: already at $NEW_VERSION"
    fi
else
    echo -e "${RED}✗${NC} Cargo.toml not found"
fi

# 2. Update Python pyproject.toml
PYPROJECT="$REPO_ROOT/bindings/python/pyproject.toml"
if [ -f "$PYPROJECT" ]; then
    OLD_VERSION=$(grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"' "$PYPROJECT" | head -1 | sed 's/version = "\(.*\)"/\1/')
    if [ -n "$OLD_VERSION" ] && [ "$OLD_VERSION" != "$NEW_VERSION" ]; then
        sed -i "s/^version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" "$PYPROJECT"
        CHANGES+=("pyproject.toml: $OLD_VERSION -> $NEW_VERSION")
        echo -e "${GREEN}✓${NC} pyproject.toml: $OLD_VERSION -> $NEW_VERSION"
    elif [ "$OLD_VERSION" = "$NEW_VERSION" ]; then
        echo -e "${YELLOW}○${NC} pyproject.toml: already at $NEW_VERSION"
    else
        echo -e "${RED}✗${NC} pyproject.toml: could not find version"
    fi
else
    echo -e "${RED}✗${NC} pyproject.toml not found"
fi

# 3. Update Python __init__.py
INIT_PY="$REPO_ROOT/bindings/python/ciris_verify/__init__.py"
if [ -f "$INIT_PY" ]; then
    OLD_VERSION=$(grep -E '^__version__ = "[0-9]+\.[0-9]+\.[0-9]+"' "$INIT_PY" | sed 's/__version__ = "\(.*\)"/\1/')
    if [ -n "$OLD_VERSION" ] && [ "$OLD_VERSION" != "$NEW_VERSION" ]; then
        sed -i "s/^__version__ = \"$OLD_VERSION\"/__version__ = \"$NEW_VERSION\"/" "$INIT_PY"
        CHANGES+=("__init__.py: $OLD_VERSION -> $NEW_VERSION")
        echo -e "${GREEN}✓${NC} __init__.py: $OLD_VERSION -> $NEW_VERSION"
    elif [ "$OLD_VERSION" = "$NEW_VERSION" ]; then
        echo -e "${YELLOW}○${NC} __init__.py: already at $NEW_VERSION"
    else
        echo -e "${RED}✗${NC} __init__.py: could not find __version__"
    fi
else
    echo -e "${RED}✗${NC} __init__.py not found"
fi

# 4. Update Cargo.lock
echo ""
echo -e "${YELLOW}Updating Cargo.lock...${NC}"
cd "$REPO_ROOT"
cargo check --quiet 2>/dev/null || cargo check
echo -e "${GREEN}✓${NC} Cargo.lock updated"

# Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Version bump complete: ${NEW_VERSION}${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ ${#CHANGES[@]} -gt 0 ]; then
    echo "Files changed:"
    for change in "${CHANGES[@]}"; do
        echo "  - $change"
    done
    echo ""
    echo "Next steps:"
    echo "  1. Review changes: git diff"
    echo "  2. Commit: git add -A && git commit -m \"chore: bump version to $NEW_VERSION\""
    echo "  3. Tag: git tag v$NEW_VERSION"
    echo "  4. Push: git push && git push origin v$NEW_VERSION"
else
    echo "No changes needed - all files already at version $NEW_VERSION"
fi
