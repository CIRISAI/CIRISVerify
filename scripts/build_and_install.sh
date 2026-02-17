#!/bin/bash
# Build CIRISVerify Rust binary and install Python bindings.
#
# Usage:
#   ./scripts/build_and_install.sh          # Build + install (editable)
#   ./scripts/build_and_install.sh --release # Build release + install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_PKG="$PROJECT_ROOT/bindings/python"
CIRIS_VERIFY_PKG="$PYTHON_PKG/ciris_verify"

echo "=== Building CIRISVerify ==="
cd "$PROJECT_ROOT"
cargo build --release

echo "=== Copying binary to Python package ==="
PLATFORM="$(uname -s)"
ARCH="$(uname -m)"

case "$PLATFORM" in
    Darwin)
        BINARY="target/release/libciris_verify_ffi.dylib"
        ;;
    Linux)
        BINARY="target/release/libciris_verify_ffi.so"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        BINARY="target/release/ciris_verify_ffi.dll"
        ;;
    *)
        echo "Unsupported platform: $PLATFORM"
        exit 1
        ;;
esac

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    exit 1
fi

cp "$BINARY" "$CIRIS_VERIFY_PKG/"
echo "  Copied $BINARY -> $CIRIS_VERIFY_PKG/"

echo "=== Installing Python package (editable) ==="
pip3 install -e "$PYTHON_PKG"

echo "=== Verifying installation ==="
python -c "from ciris_verify import CIRISVerify, MockCIRISVerify, LicenseStatus; print('ciris-verify package installed successfully')"

echo "=== Done ==="
echo "Binary: $BINARY ($PLATFORM/$ARCH)"
echo "Package: ciris-verify $(python -c 'import ciris_verify; print(ciris_verify.__version__)')"
