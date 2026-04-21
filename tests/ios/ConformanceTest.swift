#!/usr/bin/env swift
//
// CIRISVerify iOS/macOS Conformance Test
//
// Run conformance tests on iOS device or macOS.
//
// Usage:
//   macOS:  swift ConformanceTest.swift [path/to/libciris_verify_ffi.dylib]
//   iOS:    Build as part of test target in Xcode
//

import Foundation

// MARK: - FFI Type Definitions

typealias CirisVerifyHandle = UnsafeMutableRawPointer

// MARK: - FFI Function Declarations

@_silgen_name("ciris_verify_init")
func ciris_verify_init() -> CirisVerifyHandle?

@_silgen_name("ciris_verify_destroy")
func ciris_verify_destroy(_ handle: CirisVerifyHandle)

@_silgen_name("ciris_verify_run_conformance_tests")
func ciris_verify_run_conformance_tests(_ handle: CirisVerifyHandle) -> Int32

@_silgen_name("ciris_verify_version")
func ciris_verify_version() -> UnsafePointer<CChar>?

// MARK: - Test Runner

class ConformanceTestRunner {

    /// Run all conformance tests
    /// - Returns: Number of failures (0 = all passed)
    static func run() -> Int32 {
        print("=== CIRISVerify Conformance Test ===\n")

        // Print version
        if let versionPtr = ciris_verify_version() {
            let version = String(cString: versionPtr)
            print("Library version: \(version)")
        }

        // Platform info
        #if os(iOS)
        print("Platform: iOS")
        #elseif os(macOS)
        print("Platform: macOS")
        #if arch(arm64)
        print("Architecture: Apple Silicon")
        #else
        print("Architecture: Intel")
        #endif
        #else
        print("Platform: Unknown")
        #endif

        print("")

        // Initialize
        print("Initializing CIRISVerify...")
        guard let handle = ciris_verify_init() else {
            print("ERROR: Failed to initialize CIRISVerify")
            return -1
        }
        print("Initialized successfully\n")

        // Run conformance tests
        print("Running conformance tests...")
        print("(Detailed results logged to console)\n")

        let failures = ciris_verify_run_conformance_tests(handle)

        // Cleanup
        print("\nCleaning up...")
        ciris_verify_destroy(handle)

        // Report result
        print("\n=== RESULT ===")
        if failures == 0 {
            print("✓ ALL TESTS PASSED")
        } else {
            print("✗ FAILED: \(failures) test(s) failed")
        }

        return failures
    }
}

// MARK: - XCTest Integration (for iOS/Xcode)

#if canImport(XCTest)
import XCTest

class CIRISVerifyConformanceTests: XCTestCase {

    func testConformanceSuite() {
        let failures = ConformanceTestRunner.run()
        XCTAssertEqual(failures, 0, "Conformance tests failed: \(failures) failures")
    }
}
#endif

// MARK: - Command Line Entry Point (for macOS standalone)

#if os(macOS) && !XCTEST
// Check if running as standalone script
if CommandLine.arguments.count > 0 {
    // Load library if path provided
    if CommandLine.arguments.count > 1 {
        let libPath = CommandLine.arguments[1]
        print("Loading library: \(libPath)")
        guard dlopen(libPath, RTLD_NOW) != nil else {
            print("ERROR: Failed to load library: \(String(cString: dlerror()))")
            exit(1)
        }
        print("Library loaded successfully\n")
    }

    let result = ConformanceTestRunner.run()
    exit(result)
}
#endif
