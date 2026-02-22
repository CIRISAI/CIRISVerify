#!/bin/bash
# build_ios_xcframework.sh
#
# Cross-compiles CIRISVerify for iOS (device + simulator) and packages
# as an XCFramework for integration into the iOS app.
#
# Usage: ./scripts/build_ios_xcframework.sh [--output DIR]
#
# Requirements:
#   - Rust toolchain with aarch64-apple-ios and aarch64-apple-ios-sim targets
#   - cbindgen (cargo install cbindgen)
#   - Xcode command line tools (xcodebuild)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/target/ios-xcframework"
OUTPUT_DIR="${1:-${PROJECT_DIR}/target/CIRISVerify.xcframework}"

# Framework name
FRAMEWORK_NAME="CIRISVerify"
FFI_CRATE="ciris-verify-ffi"
LIBRARY_NAME="libciris_verify_ffi"

# Read version from workspace Cargo.toml
VERSION=$(grep '^version = ' "${PROJECT_DIR}/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')

echo "=== CIRISVerify iOS XCFramework Builder ==="
echo "Project: ${PROJECT_DIR}"
echo "Version: ${VERSION}"
echo "Output:  ${OUTPUT_DIR}"
echo ""

# Check prerequisites
command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo not found"; exit 1; }
command -v cbindgen >/dev/null 2>&1 || { echo "ERROR: cbindgen not found. Install with: cargo install cbindgen"; exit 1; }
command -v xcodebuild >/dev/null 2>&1 || { echo "ERROR: xcodebuild not found. Install Xcode command line tools."; exit 1; }

# Verify targets are installed
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Installing Rust target: $target"
        rustup target add "$target"
    fi
done

# Clean previous build artifacts
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Step 1: Cross-compile for iOS device (arm64)
echo ">>> Building for iOS device (aarch64-apple-ios)..."
cargo build --release \
    --target aarch64-apple-ios \
    -p "${FFI_CRATE}" \
    --features ios

DEVICE_LIB="${PROJECT_DIR}/target/aarch64-apple-ios/release/${LIBRARY_NAME}.a"
if [ ! -f "${DEVICE_LIB}" ]; then
    echo "ERROR: Device static library not found at ${DEVICE_LIB}"
    exit 1
fi
echo "    Built: ${DEVICE_LIB}"

# Step 2: Cross-compile for iOS simulator (arm64)
echo ">>> Building for iOS simulator (aarch64-apple-ios-sim)..."
cargo build --release \
    --target aarch64-apple-ios-sim \
    -p "${FFI_CRATE}" \
    --features ios

SIM_LIB="${PROJECT_DIR}/target/aarch64-apple-ios-sim/release/${LIBRARY_NAME}.a"
if [ ! -f "${SIM_LIB}" ]; then
    echo "ERROR: Simulator static library not found at ${SIM_LIB}"
    exit 1
fi
echo "    Built: ${SIM_LIB}"

# Step 3: Generate C header
echo ">>> Generating C header with cbindgen..."
HEADER_FILE="${BUILD_DIR}/ciris_verify.h"
cbindgen --config "${PROJECT_DIR}/cbindgen.toml" \
    --crate "${FFI_CRATE}" \
    --output "${HEADER_FILE}" \
    "${PROJECT_DIR}"
echo "    Generated: ${HEADER_FILE}"

# Step 4: Create .framework bundles for each architecture

# Helper function to create a framework bundle
create_framework() {
    local ARCH_DIR="$1"
    local STATIC_LIB="$2"
    local FRAMEWORK_DIR="${BUILD_DIR}/${ARCH_DIR}/${FRAMEWORK_NAME}.framework"

    mkdir -p "${FRAMEWORK_DIR}/Headers"

    # Copy the static library as the framework binary
    cp "${STATIC_LIB}" "${FRAMEWORK_DIR}/${FRAMEWORK_NAME}"

    # Copy the header
    cp "${HEADER_FILE}" "${FRAMEWORK_DIR}/Headers/"

    # Create Info.plist
    cat > "${FRAMEWORK_DIR}/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>${FRAMEWORK_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>ai.ciris.verify</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${FRAMEWORK_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>15.0</string>
</dict>
</plist>
PLIST

    echo "    Framework: ${FRAMEWORK_DIR}"
}

echo ">>> Creating framework bundles..."
create_framework "ios-arm64" "${DEVICE_LIB}"
create_framework "ios-arm64-simulator" "${SIM_LIB}"

# Step 5: Create XCFramework
echo ">>> Creating XCFramework..."
rm -rf "${OUTPUT_DIR}"

xcodebuild -create-xcframework \
    -framework "${BUILD_DIR}/ios-arm64/${FRAMEWORK_NAME}.framework" \
    -framework "${BUILD_DIR}/ios-arm64-simulator/${FRAMEWORK_NAME}.framework" \
    -output "${OUTPUT_DIR}"

echo ""
echo "=== XCFramework created successfully ==="
echo "Output: ${OUTPUT_DIR}"
echo ""
echo "Contents:"
find "${OUTPUT_DIR}" -type f | sort | head -20
# Copy Swift bindings alongside XCFramework
SWIFT_DIR="$(dirname "${OUTPUT_DIR}")/swift"
mkdir -p "${SWIFT_DIR}"
cp "${PROJECT_DIR}/bindings/swift/CIRISVerify.swift" "${SWIFT_DIR}/"
cp "${PROJECT_DIR}/bindings/swift/CIRISVerify-Bridging-Header.h" "${SWIFT_DIR}/"
echo "Swift bindings: ${SWIFT_DIR}/"
echo ""
echo "To use in your iOS project:"
echo "  1. Add ${FRAMEWORK_NAME}.xcframework to your Xcode project"
echo "  2. Add CIRISVerify.swift and CIRISVerify-Bridging-Header.h from ${SWIFT_DIR}/"
echo "  3. Set the bridging header in Build Settings > Objective-C Bridging Header"
echo "  4. Link against Security.framework (for Secure Enclave)"
echo "  5. Add keychain-access-groups entitlement"
