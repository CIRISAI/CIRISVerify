// CIRISVerify iOS Conformance Test - App Entry Point
//
// Loads libciris_verify_ffi.dylib dynamically at runtime via dlopen(),
// matching the real deployment model where CIRISVerify loads as a module
// into an already-running process (Python/CIRISAgent). This ensures the
// ctor-based function integrity check runs after iOS is fully bootstrapped.

import UIKit
import Foundation

// MARK: - Dynamic FFI Loading

/// Dynamically loaded FFI function pointers
class CIRISVerifyFFI {
    typealias InitFn = @convention(c) () -> UnsafeMutableRawPointer?
    typealias DestroyFn = @convention(c) (UnsafeMutableRawPointer) -> Void
    typealias ConformanceFn = @convention(c) (UnsafeMutableRawPointer) -> Int32
    typealias VersionFn = @convention(c) () -> UnsafePointer<CChar>?

    let handle: UnsafeMutableRawPointer
    let initFn: InitFn
    let destroyFn: DestroyFn
    let conformanceFn: ConformanceFn
    let versionFn: VersionFn

    init?(libraryPath: String) {
        guard let h = dlopen(libraryPath, RTLD_NOW) else {
            let err = String(cString: dlerror())
            print("ERROR: dlopen failed: \(err)")
            return nil
        }
        self.handle = h

        guard let initSym = dlsym(h, "ciris_verify_init"),
              let destroySym = dlsym(h, "ciris_verify_destroy"),
              let conformanceSym = dlsym(h, "ciris_verify_run_conformance_tests"),
              let versionSym = dlsym(h, "ciris_verify_version") else {
            let err = String(cString: dlerror())
            print("ERROR: dlsym failed: \(err)")
            dlclose(h)
            return nil
        }

        self.initFn = unsafeBitCast(initSym, to: InitFn.self)
        self.destroyFn = unsafeBitCast(destroySym, to: DestroyFn.self)
        self.conformanceFn = unsafeBitCast(conformanceSym, to: ConformanceFn.self)
        self.versionFn = unsafeBitCast(versionSym, to: VersionFn.self)
    }

    deinit {
        dlclose(handle)
    }
}

// MARK: - App

class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        let vc = ConformanceViewController()
        window?.rootViewController = vc
        window?.makeKeyAndVisible()
        return true
    }
}

class ConformanceViewController: UIViewController {
    private let textView = UITextView()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        textView.frame = view.bounds
        textView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        textView.backgroundColor = .black
        textView.textColor = .green
        textView.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.isEditable = false
        textView.contentInset = UIEdgeInsets(top: 60, left: 10, bottom: 40, right: 10)
        view.addSubview(textView)

        log("=== CIRISVerify iOS Conformance Test ===\n")
        log("Platform: iOS (device)")
        log("Architecture: arm64")
        log("Loading model: dlopen (matches CIRISAgent deployment)\n")

        // Use a thread with explicit 8MB stack (default DispatchQueue threads
        // have 512KB which may be insufficient for unoptimized Rust debug builds)
        let thread = Thread(target: self, selector: #selector(runTestsObjC), object: nil)
        thread.stackSize = 8 * 1024 * 1024  // 8MB stack
        thread.start()
    }

    @objc private func runTestsObjC() {
        runTests()
    }

    private func runTests() {
        // Find the dylib in the app bundle
        let bundlePath = Bundle.main.bundlePath
        let libPath = bundlePath + "/Frameworks/libciris_verify_ffi.dylib"

        log("Loading library: \(libPath)")
        guard let ffi = CIRISVerifyFFI(libraryPath: libPath) else {
            log("ERROR: Failed to load library via dlopen")
            return
        }
        log("Library loaded via dlopen\n")

        // Version
        if let versionPtr = ffi.versionFn() {
            let version = String(cString: versionPtr)
            log("Library version: \(version)")
        }

        // Init
        log("\nCalling ciris_verify_init()...")
        guard let handle = ffi.initFn() else {
            log("ERROR: ciris_verify_init() returned nil")
            return
        }
        log("Initialized successfully\n")

        // Conformance tests
        log("Running conformance tests...")
        log("(Detailed results in device console)\n")

        let failures = ffi.conformanceFn(handle)

        log("\nCleaning up...")
        ffi.destroyFn(handle)

        log("\n=== RESULT ===")
        if failures == 0 {
            log("ALL TESTS PASSED")
        } else {
            log("FAILED: \(failures) test(s) failed")
        }
    }

    private func log(_ message: String) {
        print(message)
        NSLog("%@", message)
        DispatchQueue.main.async { [weak self] in
            self?.textView.text += message + "\n"
            let bottom = NSRange(location: (self?.textView.text.count ?? 1) - 1, length: 1)
            self?.textView.scrollRangeToVisible(bottom)
        }
    }
}

UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(AppDelegate.self))
