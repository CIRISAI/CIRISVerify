#!/bin/bash
#
# Build and run CIRISVerify conformance tests on Android device
#
# Prerequisites:
# - Android NDK installed (ANDROID_NDK_HOME set or ~/Android/Sdk/ndk/*)
# - adb in PATH or ~/Android/Sdk/platform-tools/
# - Device connected (check with: adb devices)
#
# Usage: ./run_conformance.sh [armeabi-v7a|arm64-v8a|x86_64]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Add adb to PATH
export PATH="$PATH:$HOME/Android/Sdk/platform-tools"

# Find NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    NDK_DIR=$(ls -d ~/Android/Sdk/ndk/* 2>/dev/null | sort -V | tail -1)
    if [ -z "$NDK_DIR" ]; then
        echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME or install via Android Studio."
        exit 1
    fi
    export ANDROID_NDK_HOME="$NDK_DIR"
fi
echo "Using NDK: $ANDROID_NDK_HOME"

# Detect device ABI or use argument
if [ -n "$1" ]; then
    ABI="$1"
else
    ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
    echo "Detected device ABI: $ABI"
fi

# Map ABI to Rust target and NDK toolchain
case "$ABI" in
    armeabi-v7a)
        RUST_TARGET="armv7-linux-androideabi"
        NDK_TRIPLE="armv7a-linux-androideabi"
        NDK_ARCH="arm"
        ;;
    arm64-v8a)
        RUST_TARGET="aarch64-linux-android"
        NDK_TRIPLE="aarch64-linux-android"
        NDK_ARCH="aarch64"
        ;;
    x86_64)
        RUST_TARGET="x86_64-linux-android"
        NDK_TRIPLE="x86_64-linux-android"
        NDK_ARCH="x86_64"
        ;;
    *)
        echo "ERROR: Unsupported ABI: $ABI"
        exit 1
        ;;
esac

echo "Rust target: $RUST_TARGET"

# Find NDK toolchain
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
if [ ! -d "$TOOLCHAIN" ]; then
    echo "ERROR: NDK toolchain not found at $TOOLCHAIN"
    exit 1
fi

# Use API level 21 (Android 5.0) for maximum compatibility
API_LEVEL=21
CC="$TOOLCHAIN/bin/${NDK_TRIPLE}${API_LEVEL}-clang"

if [ ! -f "$CC" ]; then
    echo "ERROR: Compiler not found: $CC"
    exit 1
fi

echo "Compiler: $CC"

# Check if library exists, build if needed
LIB_PATH="$PROJECT_ROOT/target/$RUST_TARGET/release/libciris_verify_ffi.so"
if [ ! -f "$LIB_PATH" ]; then
    echo ""
    echo "Building library for $RUST_TARGET..."
    cd "$PROJECT_ROOT"
    cargo ndk -t "$ABI" build --release -p ciris-verify-ffi --features android
fi

if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: Library not found at $LIB_PATH"
    exit 1
fi
echo "Library: $LIB_PATH"

# Compile test program
echo ""
echo "Compiling conformance test..."
TEST_BIN="$SCRIPT_DIR/conformance_test_$ABI"
"$CC" -o "$TEST_BIN" "$SCRIPT_DIR/conformance_test.c" -ldl -fPIE -pie
echo "Built: $TEST_BIN"

# Push to device
echo ""
echo "Pushing to device..."
DEVICE_DIR="/data/local/tmp/ciris_test"
adb shell "mkdir -p $DEVICE_DIR"
adb push "$LIB_PATH" "$DEVICE_DIR/libciris_verify_ffi.so"
adb push "$TEST_BIN" "$DEVICE_DIR/conformance_test"
adb shell "chmod 755 $DEVICE_DIR/conformance_test"

# Run test
echo ""
echo "Running conformance test on device..."
echo "========================================"
adb shell "cd $DEVICE_DIR && LD_LIBRARY_PATH=. ./conformance_test ./libciris_verify_ffi.so"
RESULT=$?

# Also capture logcat output for detailed test results
echo ""
echo "========================================"
echo "Logcat output (last 50 lines with CIRISVerify):"
adb logcat -d | grep -i "ciris\|conformance" | tail -50

exit $RESULT
