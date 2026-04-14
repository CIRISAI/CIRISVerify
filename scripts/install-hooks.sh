#!/bin/bash
# install-hooks.sh — symlink scripts/pre-commit.sh into .git/hooks/pre-commit.
#
# Run once per clone:  ./scripts/install-hooks.sh
#
# Tracked in repo so every contributor installs the same hook.

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_SRC="$REPO_ROOT/scripts/pre-commit.sh"
HOOK_DST="$REPO_ROOT/.git/hooks/pre-commit"

if [ ! -f "$HOOK_SRC" ]; then
    echo "ERROR: $HOOK_SRC missing"
    exit 1
fi

mkdir -p "$REPO_ROOT/.git/hooks"

# On Windows / msys, symlinks need extra perms — copy as a fallback.
if ln -sf "$HOOK_SRC" "$HOOK_DST" 2>/dev/null; then
    echo "Linked $HOOK_DST -> $HOOK_SRC"
else
    cp "$HOOK_SRC" "$HOOK_DST"
    echo "Copied $HOOK_SRC -> $HOOK_DST (symlink unavailable)"
fi
chmod +x "$HOOK_DST"
echo "Pre-commit hook installed."
