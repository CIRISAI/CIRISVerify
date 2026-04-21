#!/bin/bash
#
# Run CIRISVerify conformance tests on macOS
#
# Usage: ./run_conformance_macos.sh [arm64|x86_64]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Detect or use specified architecture
if [ -n "$1" ]; then
    ARCH="$1"
else
    ARCH=$(uname -m)
fi

case "$ARCH" in
    arm64|aarch64)
        RUST_TARGET="aarch64-apple-darwin"
        ;;
    x86_64)
        RUST_TARGET="x86_64-apple-darwin"
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "=== CIRISVerify macOS Conformance Test ==="
echo "Architecture: $ARCH"
echo "Rust target: $RUST_TARGET"
echo ""

# Check if library exists, build if needed
LIB_PATH="$PROJECT_ROOT/target/$RUST_TARGET/release/libciris_verify_ffi.dylib"
if [ ! -f "$LIB_PATH" ]; then
    echo "Building library for $RUST_TARGET..."
    cd "$PROJECT_ROOT"
    cargo build --release --target "$RUST_TARGET" -p ciris-verify-ffi
fi

if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: Library not found at $LIB_PATH"
    exit 1
fi
echo "Library: $LIB_PATH"
echo ""

# Compile and run Swift test
echo "Running Swift conformance test..."
echo "========================================"

# Use swiftc to compile and run
cd "$SCRIPT_DIR"
swiftc -O -import-objc-header /dev/null \
    -L "$(dirname "$LIB_PATH")" \
    -lciris_verify_ffi \
    -o conformance_test_macos \
    ConformanceTest.swift \
    -DXCTEST=0

# Run with library path
DYLD_LIBRARY_PATH="$(dirname "$LIB_PATH")" ./conformance_test_macos

RESULT=$?

# Cleanup
rm -f conformance_test_macos

exit $RESULT
