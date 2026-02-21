//! Build script for ciris-verify-core.
//!
//! Captures compile-time information for binary self-verification.

fn main() {
    // Capture the target triple at compile time
    // This is used for Level 4 binary self-verification
    println!(
        "cargo::rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );

    // Re-run if TARGET changes
    println!("cargo::rerun-if-env-changed=TARGET");
}
