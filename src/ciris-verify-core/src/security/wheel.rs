//! A Python wheel's own identity, read from its bytes, and the check that binds
//! a signed build manifest to it (CIRISVerify#306, CIRISPersist#1029).
//!
//! ## The gap this closes
//!
//! A `BuildManifest` signs `binary_hash` and `binary_version` side by side, but
//! nothing related one to the other. CIRISPersist's CI signed v53.1.8 manifests
//! whose `binary_hash` was the sha256 of a **v29.0.0** wheel (the signer took
//! `ls … | head -1` from a cache-restored `target/wheels/`). Every signature was
//! genuine, so:
//!
//! - the real v53.1.8 wheel was refused as tampered, and
//! - **the v29 wheel passed, attested as v53.1.8** — a rollback under the
//!   current version's signed name, with nothing in the chain able to object.
//!
//! A wheel states its own version and platform inside its `*.dist-info`, so the
//! mismatch is detectable from the bytes alone, offline. [`read_wheel_identity`]
//! reads them; [`check_wheel_matches`] compares them to what a manifest claims.
//! The signer (`ciris-build-sign`) refuses to sign a mismatch and the verifier
//! ([`super::build_manifest::verify_wheel_blob`]) refuses to accept one, through
//! this one implementation, so the two ends cannot disagree.
//!
//! ## Untrusted input
//!
//! The bytes are whatever was presented. Exactly one top-level `*.dist-info`
//! directory must carry `METADATA` (none, or two, is refused rather than
//! guessed between), and each file read is capped at [`MAX_DIST_INFO_FILE`]
//! inflated bytes, so a crafted archive cannot exhaust memory.

use std::io::Read;

use crate::error::VerifyError;

/// Largest `METADATA` / `WHEEL` file this module will inflate. Real ones are a
/// few KiB; this bound exists for crafted archives.
pub const MAX_DIST_INFO_FILE: u64 = 1024 * 1024;

/// What a wheel says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelIdentity {
    /// `Name:` from `METADATA`.
    pub name: String,
    /// `Version:` from `METADATA`.
    pub version: String,
    /// Every `Tag:` from `WHEEL` (`py3-none-manylinux_2_17_x86_64`, …).
    pub tags: Vec<String>,
}

impl WheelIdentity {
    /// The platform part of every tag, compressed sets split (`a.b` → `a`, `b`).
    #[must_use]
    pub fn platforms(&self) -> Vec<&str> {
        self.tags
            .iter()
            .filter_map(|t| t.rsplit('-').next())
            .flat_map(|p| p.split('.'))
            .collect()
    }
}

fn bad(message: impl Into<String>) -> VerifyError {
    VerifyError::IntegrityError {
        message: message.into(),
    }
}

/// Read a wheel's identity from its bytes.
///
/// # Errors
///
/// `IntegrityError` if the bytes are not a zip, carry no (or more than one)
/// top-level `*.dist-info/METADATA`, lack a `Version:` or `Name:`, or exceed
/// [`MAX_DIST_INFO_FILE`].
pub fn read_wheel_identity(bytes: &[u8]) -> Result<WheelIdentity, VerifyError> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| bad(format!("not a wheel (zip): {e}")))?;

    let dist_infos: Vec<String> = zip
        .file_names()
        .filter_map(|n| {
            let (dir, file) = n.split_once('/')?;
            (file == "METADATA" && dir.ends_with(".dist-info")).then(|| dir.to_string())
        })
        .collect();
    let dist_info = match dist_infos.as_slice() {
        [one] => one.clone(),
        [] => return Err(bad("wheel has no top-level *.dist-info/METADATA")),
        _ => {
            return Err(bad(format!(
                "wheel has {} *.dist-info/METADATA files; refusing to guess which is its own",
                dist_infos.len()
            )))
        },
    };

    let metadata = read_capped(&mut zip, &format!("{dist_info}/METADATA"))?;
    let wheel = read_capped(&mut zip, &format!("{dist_info}/WHEEL"))?;

    let header = |text: &str, key: &str| -> Option<String> {
        text.lines()
            .take_while(|l| !l.is_empty())
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    };
    let name = header(&metadata, "Name:").ok_or_else(|| bad("METADATA has no Name:"))?;
    let version = header(&metadata, "Version:").ok_or_else(|| bad("METADATA has no Version:"))?;
    let tags = wheel
        .lines()
        .filter_map(|l| l.strip_prefix("Tag:").map(|t| t.trim().to_string()))
        .collect();
    Ok(WheelIdentity {
        name,
        version,
        tags,
    })
}

fn read_capped(
    zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    path: &str,
) -> Result<String, VerifyError> {
    let file = zip
        .by_name(path)
        .map_err(|e| bad(format!("wheel has no {path}: {e}")))?;
    let mut out = String::new();
    let read = file
        .take(MAX_DIST_INFO_FILE + 1)
        .read_to_string(&mut out)
        .map_err(|e| bad(format!("{path}: {e}")))?;
    if read as u64 > MAX_DIST_INFO_FILE {
        return Err(bad(format!(
            "{path} inflates past {MAX_DIST_INFO_FILE} bytes; refused"
        )));
    }
    Ok(out)
}

/// Does platform tag `plat` fit Rust target triple `target`?
///
/// `None` when `target` is not a triple this function knows (e.g. a non-binary
/// target like `python-source-tree`), so the caller does not judge rather than
/// guess. `any` fits every target.
#[must_use]
pub fn platform_fits_target(plat: &str, target: &str) -> Option<bool> {
    if plat == "any" {
        return Some(true);
    }
    let arch_ok = |linux: &str| plat.ends_with(&format!("_{linux}"));
    let fits = match target {
        "x86_64-unknown-linux-gnu" => {
            (plat.starts_with("manylinux") || plat.starts_with("linux")) && arch_ok("x86_64")
        },
        "aarch64-unknown-linux-gnu" => {
            (plat.starts_with("manylinux") || plat.starts_with("linux")) && arch_ok("aarch64")
        },
        "x86_64-unknown-linux-musl" => plat.starts_with("musllinux") && arch_ok("x86_64"),
        "aarch64-unknown-linux-musl" => plat.starts_with("musllinux") && arch_ok("aarch64"),
        "x86_64-pc-windows-msvc" => plat == "win_amd64",
        "aarch64-pc-windows-msvc" => plat == "win_arm64",
        "i686-pc-windows-msvc" => plat == "win32",
        "x86_64-apple-darwin" => {
            plat.starts_with("macosx")
                && (plat.ends_with("_x86_64")
                    || plat.ends_with("_universal2")
                    || plat.ends_with("_intel"))
        },
        "aarch64-apple-darwin" => {
            plat.starts_with("macosx")
                && (plat.ends_with("_arm64") || plat.ends_with("_universal2"))
        },
        _ => return None,
    };
    Some(fits)
}

/// Check a wheel's own identity against what a manifest claims for it.
///
/// - `claimed_version` must equal `METADATA`'s `Version:` exactly, after
///   removing at most one leading `v` from the claim (release tags are often
///   written `v53.1.8`; wheels never carry the `v`). No other normalisation:
///   two spellings of a version that a human would call equal are refused,
///   because the check exists to stop a near-match passing.
/// - When `target` is a triple [`platform_fits_target`] knows, at least one of
///   the wheel's platform tags must fit it.
///
/// # Errors
///
/// `IntegrityError` naming what disagreed.
pub fn check_wheel_matches(
    identity: &WheelIdentity,
    claimed_version: &str,
    target: &str,
) -> Result<(), VerifyError> {
    let claimed = claimed_version.strip_prefix('v').unwrap_or(claimed_version);
    if identity.version != claimed {
        return Err(bad(format!(
            "wheel {} is version {:?}, but the manifest claims {:?} — a signed hash \
             of one version's wheel under another's name (CIRISVerify#306)",
            identity.name, identity.version, claimed_version
        )));
    }
    let plats = identity.platforms();
    let judged: Vec<bool> = plats
        .iter()
        .filter_map(|p| platform_fits_target(p, target))
        .collect();
    if !judged.is_empty() && !judged.iter().any(|&f| f) {
        return Err(bad(format!(
            "wheel {} {} is built for {:?}, not target {:?} (CIRISVerify#306)",
            identity.name, identity.version, plats, target
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_wheels {
    //! Build real wheel archives in memory for tests.
    use std::io::Write;

    /// A wheel with one dist-info carrying `version` and platform `plat`.
    pub(crate) fn wheel(name: &str, version: &str, plat: &str) -> Vec<u8> {
        wheel_with(
            name,
            &[(format!("{name}-{version}.dist-info"), version, plat)],
        )
    }

    pub(crate) fn wheel_with(name: &str, dist_infos: &[(String, &str, &str)]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            z.start_file(format!("{name}/__init__.py"), opts).unwrap();
            z.write_all(b"# payload\n").unwrap();
            for (dir, version, plat) in dist_infos {
                z.start_file(format!("{dir}/METADATA"), opts).unwrap();
                write!(z, "Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nlong description\nVersion: 0.0.0-in-the-body\n").unwrap();
                z.start_file(format!("{dir}/WHEEL"), opts).unwrap();
                write!(z, "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: false\nTag: cp311-abi3-{plat}\n").unwrap();
            }
            z.finish().unwrap();
        }
        buf.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::test_wheels::{wheel, wheel_with};
    use super::*;

    #[test]
    fn reads_name_version_and_tags_from_the_dist_info() {
        let w = wheel(
            "ciris_persist",
            "53.1.8",
            "manylinux_2_17_aarch64.manylinux2014_aarch64",
        );
        let id = read_wheel_identity(&w).unwrap();
        assert_eq!(id.name, "ciris_persist");
        assert_eq!(
            id.version, "53.1.8",
            "the header, not a Version: in the body"
        );
        assert_eq!(
            id.platforms(),
            ["manylinux_2_17_aarch64", "manylinux2014_aarch64"]
        );
    }

    /// The incident itself: a v29 wheel under a v53.1.8 claim.
    #[test]
    fn the_cirispersist_1029_mismatch_is_refused() {
        let id = read_wheel_identity(&wheel("ciris_persist", "29.0.0", "win_amd64")).unwrap();
        let err = check_wheel_matches(&id, "53.1.8", "x86_64-pc-windows-msvc").unwrap_err();
        assert!(err.to_string().contains("29.0.0"), "{err}");
        assert!(check_wheel_matches(&id, "29.0.0", "x86_64-pc-windows-msvc").is_ok());
    }

    #[test]
    fn a_leading_v_on_the_claim_is_the_only_normalisation() {
        let id = read_wheel_identity(&wheel("p", "53.1.8", "win_amd64")).unwrap();
        assert!(check_wheel_matches(&id, "v53.1.8", "x86_64-pc-windows-msvc").is_ok());
        for near in ["53.1.8.0", "53.1.80", " 53.1.8", "V53.1.8", "vv53.1.8"] {
            assert!(
                check_wheel_matches(&id, near, "x86_64-pc-windows-msvc").is_err(),
                "{near:?}"
            );
        }
    }

    #[test]
    fn a_wheel_for_another_platform_is_refused() {
        let id = read_wheel_identity(&wheel("p", "1.0.0", "manylinux_2_17_x86_64")).unwrap();
        assert!(check_wheel_matches(&id, "1.0.0", "x86_64-unknown-linux-gnu").is_ok());
        assert!(check_wheel_matches(&id, "1.0.0", "aarch64-unknown-linux-gnu").is_err());
        assert!(check_wheel_matches(&id, "1.0.0", "x86_64-pc-windows-msvc").is_err());
        // A target that is not a triple is not judged on platform.
        assert!(check_wheel_matches(&id, "1.0.0", "python-source-tree").is_ok());
        let pure = read_wheel_identity(&wheel("p", "1.0.0", "any")).unwrap();
        assert!(check_wheel_matches(&pure, "1.0.0", "aarch64-apple-darwin").is_ok());
    }

    #[test]
    fn ambiguous_or_missing_dist_info_is_refused() {
        let two = wheel_with(
            "p",
            &[
                ("p-1.0.0.dist-info".into(), "1.0.0", "any"),
                ("q-9.9.9.dist-info".into(), "9.9.9", "any"),
            ],
        );
        assert!(read_wheel_identity(&two).is_err());
        assert!(read_wheel_identity(b"not a zip").is_err());
        let none = {
            let mut buf = std::io::Cursor::new(Vec::new());
            let mut z = zip::ZipWriter::new(&mut buf);
            z.start_file("p/__init__.py", zip::write::SimpleFileOptions::default())
                .unwrap();
            z.finish().unwrap();
            buf.into_inner()
        };
        assert!(read_wheel_identity(&none).is_err());
    }

    #[test]
    fn platform_mapping_covers_the_release_matrix() {
        for (plat, target) in [
            ("manylinux_2_17_x86_64", "x86_64-unknown-linux-gnu"),
            ("manylinux_2_17_aarch64", "aarch64-unknown-linux-gnu"),
            ("musllinux_1_2_aarch64", "aarch64-unknown-linux-musl"),
            ("win_amd64", "x86_64-pc-windows-msvc"),
            ("macosx_10_12_x86_64", "x86_64-apple-darwin"),
            ("macosx_11_0_arm64", "aarch64-apple-darwin"),
            ("macosx_10_9_universal2", "aarch64-apple-darwin"),
        ] {
            assert_eq!(
                platform_fits_target(plat, target),
                Some(true),
                "{plat} {target}"
            );
        }
        assert_eq!(
            platform_fits_target("macosx_11_0_arm64", "x86_64-apple-darwin"),
            Some(false)
        );
        assert_eq!(
            platform_fits_target("manylinux_2_17_x86_64", "x86_64-unknown-linux-musl"),
            Some(false)
        );
        assert_eq!(
            platform_fits_target("win_amd64", "riscv64gc-unknown-linux-gnu"),
            None
        );
    }
}
