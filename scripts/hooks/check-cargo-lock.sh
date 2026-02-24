#!/usr/bin/env bash
set -euo pipefail

cargo update -w --locked 2>/dev/null || {
    echo "ERROR: Cargo.lock is out of date. Run: cargo update -w"
    exit 1
}
