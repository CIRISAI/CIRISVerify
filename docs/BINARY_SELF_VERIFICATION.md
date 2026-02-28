# Binary Self-Verification: Technical Deep Dive

**Last Updated**: 2026-02-28 (v1.0.8)

*For the plain-English overview, see [HOW_IT_WORKS.md](./HOW_IT_WORKS.md).*

---

> **Research Context**: This software is developed as part of ongoing AI alignment and safety research. It represents one approach to agent verification—not a complete solution. No security system is perfect, and determined adversaries with sufficient resources can potentially bypass any software-based protection. This documentation is provided for educational and research purposes.

---

## The Vehicle Inspection Problem

Before any car can drive on public roads, it needs to pass inspection. The inspector verifies the brakes work, the lights function, and nothing's been tampered with since the manufacturer built it.

But who inspects the inspection station?

CIRISVerify faces the same challenge. Before it can verify agent software, license status, or cryptographic signatures, it must first prove **it hasn't been tampered with itself**. This is Level 2 attestation: **"Who watches the watchmen?"**

---

## How It Works (Simple Version)

1. **Hash Yourself**: CIRISVerify computes a SHA-256 fingerprint of its own binary
2. **Check the Manifest**: Fetches the official fingerprint from the registry
3. **Compare**: If they match, the binary is authentic

The challenge? Finding "yourself" when you're a shared library loaded into another process.

---

## Platform-Specific Detection

CIRISVerify is typically loaded as a shared library (`.so`, `.dylib`, `.dll`) by a host application. On each platform, we use different techniques to find our own binary on disk.

### Linux: Reading the Process Memory Map

**The Problem**: When Python imports `ciris_verify`, calling `std::env::current_exe()` returns `/usr/bin/python3.12`—the host process, not our library.

**The Solution**: Parse `/proc/self/maps` to find our `.so` file.

```
# /proc/self/maps format:
# address          perms offset  dev   inode   pathname
7f1234567000-... r-xp  00000000 fd:01 1234567 /path/to/libciris_verify_ffi.so
```

**Code**: [`registry.rs:1298-1346`](../src/ciris-verify-core/src/registry.rs#L1298)

```rust
fn find_library_path_linux(lib_name: &str) -> Option<PathBuf> {
    let maps_file = File::open("/proc/self/maps")?;
    let reader = BufReader::new(maps_file);

    for line in reader.lines() {
        if line.contains(lib_name) {
            // Extract path from last column
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                return Some(PathBuf::from(parts[5..].join(" ")));
            }
        }
    }
    None
}
```

---

### Android: Same Technique, Different Context

**The Problem**: On Android, `current_exe()` returns `/system/bin/app_process64`—the Android runtime, not our native library.

**The Solution**: Same `/proc/self/maps` parsing as Linux. Android is Linux under the hood.

**Code**: [`registry.rs:1248-1289`](../src/ciris-verify-core/src/registry.rs#L1248)

**Additional Complexity**: Android uses ABI names (`android-arm64-v8a`) while Rust uses target triples (`aarch64-linux-android`). The `current_target()` function translates:

```rust
#[cfg(all(target_arch = "aarch64", target_os = "android"))]
return "android-arm64-v8a";

#[cfg(all(target_arch = "arm", target_os = "android"))]
return "android-armeabi-v7a";

#[cfg(all(target_arch = "x86_64", target_os = "android"))]
return "android-x86_64";
```

---

### macOS & iOS: Iterating dyld Images

**The Problem**: Apple doesn't have `/proc`. When loaded by an iOS app or Python, `current_exe()` returns the host app binary.

**The Solution**: Use Apple's `dyld` (dynamic linker) API to enumerate all loaded images.

**Code**: [`registry.rs:1353-1394`](../src/ciris-verify-core/src/registry.rs#L1353)

```rust
fn find_library_path_dyld() -> Option<PathBuf> {
    extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(image_index: u32) -> *const c_char;
    }

    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            let name = CStr::from_ptr(name_ptr).to_string_lossy();

            if name.contains("libciris_verify_ffi") || name.contains("CIRISVerify") {
                return Some(PathBuf::from(name.into_owned()));
            }
        }
    }
    None
}
```

**iOS Code Signing Complication**: Apple's code signing modifies Mach-O load commands (specifically `LC_CODE_SIGNATURE` offset). To get consistent hashes:

1. Parse the Mach-O binary with `goblin`
2. Find the `__TEXT` segment
3. Hash only the code portion, skipping the mutable header area

**Code**: [`registry.rs:1187-1240`](../src/ciris-verify-core/src/registry.rs#L1187)

```rust
fn extract_text_code_region(data: &[u8]) -> Option<(usize, usize)> {
    let macho = Mach::parse(data)?;

    // Header + load commands = mutable area
    let header_size = if macho.is_64 { 32 } else { 28 };
    let cmds_end = header_size + macho.header.sizeofcmds;
    let page_aligned = (cmds_end + 0xFFF) & !0xFFF; // Round to 4096

    for seg in &macho.segments {
        if seg.name() == "__TEXT" {
            let hash_start = page_aligned.max(seg.fileoff);
            let hash_size = seg.filesize - (hash_start - seg.fileoff);
            return Some((hash_start, hash_size));
        }
    }
    None
}
```

---

### Windows: Standard Executable Path

**The Situation**: On Windows, CIRISVerify is typically used as a standalone CLI binary, not an FFI library. `std::env::current_exe()` works correctly.

**Code**: [`registry.rs:1127-1136`](../src/ciris-verify-core/src/registry.rs#L1127)

```rust
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos", target_os = "linux")))]
let exe_path = std::env::current_exe()?;
```

---

## The Hash Comparison

Once we have the binary path, verification is straightforward:

```rust
pub fn verify_self_against_manifest(manifest: &BinaryManifest) -> Result<bool, VerifyError> {
    let target = current_target();
    let actual_hash = compute_self_hash()?;

    let expected_hash = manifest.binaries.get(target)?;
    let expected = expected_hash.strip_prefix("sha256:").unwrap_or(expected_hash);

    // Constant-time comparison (prevents timing attacks)
    use subtle::ConstantTimeEq;
    Ok(actual_bytes.ct_eq(&expected_bytes).into())
}
```

**Security Note**: We use constant-time comparison to prevent timing side-channel attacks that could leak information about the expected hash.

---

## Registry Manifest Format

The registry stores binary hashes at:
```
GET /v1/verify/binary-manifest/{version}
```

Response:
```json
{
  "version": "1.0.8",
  "binaries": {
    "x86_64-unknown-linux-gnu": "sha256:63d2d68b3dedde90...",
    "aarch64-apple-darwin": "sha256:9b457096927e5a8f...",
    "android-arm64-v8a": "sha256:b0b104a8ece24e73...",
    "aarch64-apple-ios": "sha256:bcf0bfc0ccac8b99..."
  },
  "generated_at": "2026-02-28T15:59:42Z"
}
```

---

## Trust Boundaries and Limitations

Binary self-verification is **one layer** in a defense-in-depth approach. It is not foolproof.

**Known limitations** (this list is not exhaustive):

1. **Compromised Registry**: An attacker controlling the registry could update both binary and manifest
2. **Compromised Initial Install**: Malicious app store listing or PyPI package
3. **Sophisticated Runtime Attacks**: Memory manipulation, hypervisor-level attacks, or hardware implants
4. **Side-Channel Attacks**: Timing attacks, power analysis, or other covert channels
5. **Social Engineering**: Convincing users to disable verification or accept warnings
6. **Zero-Day Vulnerabilities**: Unknown bugs in this code, dependencies, or the OS

**Partial mitigations we attempt** (not guarantees):

| Attack Vector | Our Attempt | Caveat |
|---------------|-------------|--------|
| Registry MITM | Multi-source consensus (2/3 geo-distributed) | Attacker with 2+ sources wins |
| Malicious initial install | Encourage trusted channels (Play Store, App Store, PyPI) | We can't control distribution |
| Manifest forgery | Steward key signature verification | Key compromise defeats this |
| Timing attacks | Constant-time comparison | Implementation may have flaws |

**We make no guarantees.** This is research software exploring approaches to agent verification.

---

## Recursive Trust Dependency

Binary self-verification has an inherent recursion:

1. To verify the binary, we fetch the manifest from the registry
2. To trust the manifest, we need Level 3 multi-source validation
3. But Level 3 validation is performed BY this binary

**Resolution**: The initial provisioning moment breaks the cycle. The FIRST installation must come from a trusted source. After that, the binary can verify future updates.

---

## CLI Commands

```bash
# Verify this binary's integrity
ciris-verify self-check

# With custom registry
ciris-verify self-check --registry https://custom.registry.example.com

# JSON output for automation
ciris-verify self-check --format json
```

---

## Platform Detection Summary

| Platform | Detection Method | Key Function | Code Location |
|----------|-----------------|--------------|---------------|
| **Linux** | `/proc/self/maps` parsing | `find_library_path_linux()` | `registry.rs:1298` |
| **Android** | `/proc/self/maps` parsing | `find_library_path()` | `registry.rs:1248` |
| **macOS** | `_dyld_get_image_name()` | `find_library_path_dyld()` | `registry.rs:1353` |
| **iOS** | `_dyld_get_image_name()` + `__TEXT` hashing | `find_library_path_dyld()` + `extract_text_code_region()` | `registry.rs:1353`, `1187` |
| **Windows** | `std::env::current_exe()` | (fallback) | `registry.rs:1127` |

---

## Related Documentation

- [HOW_IT_WORKS.md](./HOW_IT_WORKS.md) - Overview of CIRISVerify
- [THREAT_MODEL.md](./THREAT_MODEL.md) - Security threat analysis
- [REGISTRY_BINARY_MANIFEST.md](./REGISTRY_BINARY_MANIFEST.md) - Manifest API specification

---

## Version History

| Version | Changes |
|---------|---------|
| 1.0.8 | Fixed Android ABI name mapping (`android-arm64-v8a` vs `aarch64-linux-android`) |
| 1.0.4 | Added Linux FFI library self-detection via `/proc/self/maps` |
| 1.0.0 | Production release with full platform support |
