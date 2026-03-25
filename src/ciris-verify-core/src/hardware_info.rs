//! Hardware information and security limitations detection.
//!
//! Detects hardware characteristics that affect attestation trust level:
//! - Emulators (no real hardware security)
//! - Vulnerable SoCs (e.g., MediaTek CVE-2026-20435)
//! - Rooted/jailbroken devices
//! - Missing security features
//!
//! Devices with known limitations are treated similarly to emulators:
//! attestation level is capped because hardware security cannot be trusted.
//!
//! This module centralizes hardware detection and uses the existing
//! `security::platform` module for emulator/root detection.

use crate::security::{is_device_compromised, is_emulator, is_suspicious_emulator};
use serde::{Deserialize, Serialize};

/// Known security advisories affecting hardware trust.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityAdvisory {
    /// CVE identifier (e.g., "CVE-2026-20435").
    pub cve: String,
    /// Short description of the vulnerability.
    pub title: String,
    /// Impact on CIRISVerify attestation.
    pub impact: String,
    /// Whether this vulnerability is patchable via software.
    pub software_patchable: bool,
    /// Minimum patch level that fixes this (if patchable).
    pub min_patch_level: Option<String>,
}

/// Hardware security limitations that affect attestation level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HardwareLimitation {
    /// Running in an emulator - no real hardware security.
    Emulator,
    /// SoC has known boot ROM vulnerability (physical access attack).
    VulnerableSoC {
        /// SoC manufacturer (e.g., "MediaTek").
        manufacturer: String,
        /// Security advisory details.
        advisory: SecurityAdvisory,
    },
    /// TEE implementation has known weaknesses.
    WeakTEE {
        /// Description of the weakness.
        reason: String,
    },
    /// Device is rooted/jailbroken.
    RootedDevice,
    /// Bootloader is unlocked.
    UnlockedBootloader,
    /// Security patch level is outdated.
    OutdatedPatchLevel {
        /// Current security patch level (e.g., "2025-01-01").
        current: String,
        /// Minimum required patch level.
        minimum_required: String,
    },
}

impl HardwareLimitation {
    /// Human-readable description of this limitation.
    pub fn description(&self) -> String {
        match self {
            Self::Emulator => "Running in emulator - no hardware security".to_string(),
            Self::VulnerableSoC {
                manufacturer,
                advisory,
            } => {
                format!(
                    "{} SoC affected by {} - {}",
                    manufacturer, advisory.cve, advisory.impact
                )
            },
            Self::WeakTEE { reason } => format!("TEE security weakness: {}", reason),
            Self::RootedDevice => "Device is rooted - hardware security bypassed".to_string(),
            Self::UnlockedBootloader => "Bootloader unlocked - secure boot compromised".to_string(),
            Self::OutdatedPatchLevel {
                current,
                minimum_required,
            } => {
                format!(
                    "Security patch {} is below minimum {} - known vulnerabilities unpatched",
                    current, minimum_required
                )
            },
        }
    }

    /// Whether this limitation should cap attestation at software-only level.
    pub fn caps_attestation(&self) -> bool {
        match self {
            Self::Emulator => true,
            Self::VulnerableSoC { .. } => true,
            Self::WeakTEE { .. } => true,
            Self::RootedDevice => true,
            Self::UnlockedBootloader => true,
            Self::OutdatedPatchLevel { .. } => false, // Warning only
        }
    }
}

/// Complete hardware information for a device.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardwareInfo {
    /// Platform (e.g., "android", "ios", "linux", "windows", "macos").
    pub platform: String,
    /// SoC/chip manufacturer (e.g., "MediaTek", "Qualcomm", "Apple").
    pub soc_manufacturer: Option<String>,
    /// SoC model (e.g., "Dimensity 7300", "Snapdragon 8 Gen 2").
    pub soc_model: Option<String>,
    /// Android security patch level (YYYY-MM-DD format).
    pub security_patch_level: Option<String>,
    /// Whether device appears to be an emulator.
    pub is_emulator: bool,
    /// Whether the emulator is suspicious (mobile emulator vs desktop VM).
    pub is_suspicious_emulator: bool,
    /// Whether bootloader is unlocked (Android).
    pub bootloader_unlocked: Option<bool>,
    /// TEE implementation (e.g., "Trustonic", "Qualcomm", "Apple SEP").
    pub tee_implementation: Option<String>,
    /// Whether device is rooted/jailbroken.
    pub is_rooted: bool,
    /// Detected security limitations.
    pub limitations: Vec<HardwareLimitation>,
    /// Whether hardware-backed attestation should be trusted.
    pub hardware_trust_degraded: bool,
    /// Reason for trust degradation (if any).
    pub trust_degradation_reason: Option<String>,
}

impl HardwareInfo {
    /// Create hardware info for current platform.
    ///
    /// Uses the centralized `security::platform` module for detection.
    pub fn detect() -> Self {
        let mut info = Self {
            platform: current_platform().to_string(),
            is_emulator: is_emulator(),
            is_suspicious_emulator: is_suspicious_emulator(),
            is_rooted: is_device_compromised(),
            ..Default::default()
        };

        // Add limitations based on detected issues
        if info.is_suspicious_emulator {
            info.limitations.push(HardwareLimitation::Emulator);
        }

        if info.is_rooted {
            info.limitations.push(HardwareLimitation::RootedDevice);
        }

        #[cfg(target_os = "ios")]
        {
            info.soc_manufacturer = Some("Apple".to_string());
            info.tee_implementation = Some("Apple SEP".to_string());
        }

        // Update trust status based on limitations
        info.update_trust_status();

        info
    }

    /// Update hardware info with Android system properties.
    ///
    /// Called from FFI layer after reading properties via JNI.
    /// This is the main entry point for Android hardware detection.
    pub fn update_from_android_properties(
        &mut self,
        hardware: &str,
        board: &str,
        manufacturer: &str,
        model: &str,
        security_patch: &str,
        fingerprint: &str,
    ) {
        self.platform = "android".to_string();

        // Detect SoC manufacturer and check for vulnerabilities
        let hardware_lower = hardware.to_lowercase();
        let board_lower = board.to_lowercase();
        let manufacturer_lower = manufacturer.to_lowercase();

        if hardware_lower.contains("mt")
            || board_lower.contains("mt")
            || manufacturer_lower.contains("mediatek")
        {
            self.soc_manufacturer = Some("MediaTek".to_string());

            // Check for vulnerable Dimensity chips with Trustonic TEE
            // CVE-2026-20435 affects Dimensity 7300 and similar chips
            if self.is_mediatek_vulnerable(&hardware_lower, &board_lower) {
                self.tee_implementation = Some("Trustonic".to_string());
                self.limitations.push(HardwareLimitation::VulnerableSoC {
                    manufacturer: "MediaTek".to_string(),
                    advisory: SecurityAdvisory {
                        cve: "CVE-2026-20435".to_string(),
                        title: "MediaTek Boot ROM EMFI vulnerability".to_string(),
                        impact: "Physical access can extract Keystore keys in <45 seconds"
                            .to_string(),
                        software_patchable: false, // Boot ROM is in silicon
                        min_patch_level: None,
                    },
                });
            }
        } else if hardware_lower.contains("qcom")
            || hardware_lower.contains("sm")
            || hardware_lower.contains("sdm")
            || manufacturer_lower.contains("qualcomm")
        {
            self.soc_manufacturer = Some("Qualcomm".to_string());
            self.tee_implementation = Some("Qualcomm".to_string());
        } else if hardware_lower.contains("exynos") || manufacturer_lower.contains("samsung") {
            self.soc_manufacturer = Some("Samsung".to_string());
            self.tee_implementation = Some("Samsung Knox".to_string());
        } else if hardware_lower.contains("tensor") {
            self.soc_manufacturer = Some("Google".to_string());
            self.tee_implementation = Some("Titan M2".to_string());
        }

        self.soc_model = Some(format!("{} ({})", hardware, board));
        self.security_patch_level = Some(security_patch.to_string());

        // Use centralized emulator detection enhanced with JNI-provided data
        let jni_emulator = is_android_emulator_from_properties(fingerprint, hardware, model);
        if jni_emulator && !self.is_emulator {
            self.is_emulator = true;
            self.is_suspicious_emulator = true;
        }

        // Add emulator limitation if detected
        if self.is_suspicious_emulator
            && !self
                .limitations
                .iter()
                .any(|l| matches!(l, HardwareLimitation::Emulator))
        {
            self.limitations.push(HardwareLimitation::Emulator);
        }

        self.update_trust_status();
    }

    /// Check if this is a vulnerable MediaTek chipset.
    fn is_mediatek_vulnerable(&self, hardware: &str, board: &str) -> bool {
        // MediaTek chipsets vulnerable to CVE-2026-20435 (Boot ROM EMFI)
        // These chips have Trustonic TEE with exploitable boot ROM
        let vulnerable_chips = [
            "mt6878", // Dimensity 7300
            "mt6886", // Dimensity 7200
            "mt6893", // Dimensity 1200
            "mt6895", // Dimensity 8100
            "mt6983", // Dimensity 9000
            "mt6985", // Dimensity 9200
        ];

        for chip in vulnerable_chips {
            if hardware.contains(chip) {
                return true;
            }
        }

        // Also check board name for Dimensity branding
        if board.contains("dimensity") {
            return true;
        }

        false
    }

    /// Update trust status based on detected limitations.
    fn update_trust_status(&mut self) {
        let capping_limitations: Vec<_> = self
            .limitations
            .iter()
            .filter(|l| l.caps_attestation())
            .collect();

        if !capping_limitations.is_empty() {
            self.hardware_trust_degraded = true;
            let reasons: Vec<_> = capping_limitations
                .iter()
                .map(|l| l.description())
                .collect();
            self.trust_degradation_reason = Some(reasons.join("; "));
        }
    }

    /// Check if attestation should be capped at software-only level.
    pub fn should_cap_attestation(&self) -> bool {
        self.hardware_trust_degraded
    }

    /// Get a summary of security concerns for logging/display.
    pub fn security_summary(&self) -> String {
        if self.limitations.is_empty() {
            "No known hardware security limitations".to_string()
        } else {
            let concerns: Vec<_> = self.limitations.iter().map(|l| l.description()).collect();
            format!("Hardware security concerns: {}", concerns.join("; "))
        }
    }
}

/// Detect Android emulator from JNI-provided properties.
///
/// This supplements the system property checks in `security::platform`
/// with properties that can only be read via JNI (Build.FINGERPRINT, etc.).
fn is_android_emulator_from_properties(fingerprint: &str, hardware: &str, model: &str) -> bool {
    let fingerprint_lower = fingerprint.to_lowercase();
    let hardware_lower = hardware.to_lowercase();
    let model_lower = model.to_lowercase();

    // Known emulator fingerprints
    fingerprint_lower.contains("generic")
        || fingerprint_lower.contains("sdk")
        || fingerprint_lower.contains("emulator")
        || fingerprint_lower.contains("android sdk built for")
        // Emulator hardware identifiers
        || hardware_lower.contains("goldfish")
        || hardware_lower.contains("ranchu")
        || hardware_lower.contains("vbox")
        // Emulator model names
        || model_lower.contains("sdk")
        || model_lower.contains("emulator")
        || model_lower.contains("android sdk")
}

/// Get current platform name.
fn current_platform() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "android"
    }

    #[cfg(target_os = "ios")]
    {
        "ios"
    }

    #[cfg(target_os = "linux")]
    {
        "linux"
    }

    #[cfg(target_os = "windows")]
    {
        "windows"
    }

    #[cfg(target_os = "macos")]
    {
        "macos"
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_creates_valid_info() {
        let info = HardwareInfo::detect();

        // Platform should be set
        assert!(!info.platform.is_empty());

        // On desktop, is_suspicious_emulator should be false
        // (desktop VMs are not suspicious)
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        assert!(!info.is_suspicious_emulator);
    }

    #[test]
    fn test_mediatek_detection() {
        let mut info = HardwareInfo::default();
        info.update_from_android_properties(
            "mt6878",
            "dimensity7300",
            "Xiaomi",
            "Redmi Note 13",
            "2026-03-01",
            "Xiaomi/redmi/device:14/fingerprint",
        );

        assert_eq!(info.soc_manufacturer, Some("MediaTek".to_string()));
        assert!(info.hardware_trust_degraded);
        assert!(info.should_cap_attestation());
        assert!(info
            .limitations
            .iter()
            .any(|l| matches!(l, HardwareLimitation::VulnerableSoC { .. })));
    }

    #[test]
    fn test_mediatek_other_chips_vulnerable() {
        // Test other vulnerable chips
        for chip in ["mt6886", "mt6893", "mt6895", "mt6983", "mt6985"] {
            let mut info = HardwareInfo::default();
            info.update_from_android_properties(
                chip,
                "board",
                "MediaTek",
                "Device",
                "2026-03-01",
                "fingerprint",
            );

            assert!(
                info.limitations
                    .iter()
                    .any(|l| matches!(l, HardwareLimitation::VulnerableSoC { .. })),
                "Chip {} should be detected as vulnerable",
                chip
            );
        }
    }

    #[test]
    fn test_mediatek_safe_chips() {
        // MediaTek chips NOT affected by CVE-2026-20435
        let mut info = HardwareInfo::default();
        info.update_from_android_properties(
            "mt6765", // Helio P35 - older, not affected
            "helio_p35",
            "MediaTek",
            "Device",
            "2026-03-01",
            "fingerprint",
        );

        // Should be MediaTek but not vulnerable
        assert_eq!(info.soc_manufacturer, Some("MediaTek".to_string()));
        assert!(!info
            .limitations
            .iter()
            .any(|l| matches!(l, HardwareLimitation::VulnerableSoC { .. })));
    }

    #[test]
    fn test_qualcomm_no_limitation() {
        let mut info = HardwareInfo::default();
        info.update_from_android_properties(
            "qcom",
            "sm8550",
            "Samsung",
            "Galaxy S24",
            "2026-03-01",
            "samsung/galaxy/s24:14/fingerprint",
        );

        assert_eq!(info.soc_manufacturer, Some("Qualcomm".to_string()));
        assert!(!info.hardware_trust_degraded);
        assert!(!info.should_cap_attestation());
    }

    #[test]
    fn test_samsung_exynos_detection() {
        let mut info = HardwareInfo::default();
        info.update_from_android_properties(
            "exynos2200",
            "s5e9925",
            "Samsung",
            "Galaxy S22",
            "2026-03-01",
            "samsung/galaxy/s22:13/fingerprint",
        );

        assert_eq!(info.soc_manufacturer, Some("Samsung".to_string()));
        assert_eq!(info.tee_implementation, Some("Samsung Knox".to_string()));
    }

    #[test]
    fn test_google_tensor_detection() {
        let mut info = HardwareInfo::default();
        info.update_from_android_properties(
            "tensor",
            "gs201",
            "Google",
            "Pixel 7",
            "2026-03-01",
            "google/pixel/7:14/fingerprint",
        );

        assert_eq!(info.soc_manufacturer, Some("Google".to_string()));
        assert_eq!(info.tee_implementation, Some("Titan M2".to_string()));
    }

    #[test]
    fn test_emulator_detection_from_properties() {
        let mut info = HardwareInfo::default();
        info.update_from_android_properties(
            "goldfish",
            "ranchu",
            "Google",
            "Android SDK built for x86",
            "2026-03-01",
            "generic/sdk_gphone64/emulator:14/fingerprint",
        );

        assert!(info.is_emulator);
        assert!(info.is_suspicious_emulator);
        assert!(info.hardware_trust_degraded);
        assert!(info.should_cap_attestation());
        assert!(info
            .limitations
            .iter()
            .any(|l| matches!(l, HardwareLimitation::Emulator)));
    }

    #[test]
    fn test_emulator_detection_various_indicators() {
        // Test various emulator detection patterns
        let test_cases = [
            ("ranchu", "ranchu", "sdk_gphone64", "generic/sdk"),
            ("goldfish", "goldfish", "Emulator", "generic"),
            ("vbox86", "vbox86p", "VirtualBox", "vbox"),
        ];

        for (hw, board, model, fp) in test_cases {
            let mut info = HardwareInfo::default();
            info.update_from_android_properties(hw, board, "Google", model, "2026-03-01", fp);

            assert!(
                info.is_emulator || info.is_suspicious_emulator,
                "Should detect emulator for hw={}, model={}",
                hw,
                model
            );
        }
    }

    #[test]
    fn test_limitation_descriptions() {
        let emulator = HardwareLimitation::Emulator;
        assert!(emulator.description().contains("emulator"));
        assert!(emulator.caps_attestation());

        let vuln = HardwareLimitation::VulnerableSoC {
            manufacturer: "MediaTek".to_string(),
            advisory: SecurityAdvisory {
                cve: "CVE-2026-20435".to_string(),
                title: "Test".to_string(),
                impact: "Key extraction".to_string(),
                software_patchable: false,
                min_patch_level: None,
            },
        };
        assert!(vuln.description().contains("CVE-2026-20435"));
        assert!(vuln.caps_attestation());

        let rooted = HardwareLimitation::RootedDevice;
        assert!(rooted.description().contains("rooted"));
        assert!(rooted.caps_attestation());

        let unlocked = HardwareLimitation::UnlockedBootloader;
        assert!(unlocked.description().contains("Bootloader"));
        assert!(unlocked.caps_attestation());

        let weak_tee = HardwareLimitation::WeakTEE {
            reason: "test reason".to_string(),
        };
        assert!(weak_tee.description().contains("test reason"));
        assert!(weak_tee.caps_attestation());
    }

    #[test]
    fn test_outdated_patch_level_warning_only() {
        let limitation = HardwareLimitation::OutdatedPatchLevel {
            current: "2025-01-01".to_string(),
            minimum_required: "2026-03-01".to_string(),
        };

        // Outdated patch is a warning, doesn't cap attestation
        assert!(!limitation.caps_attestation());
        assert!(limitation.description().contains("2025-01-01"));
        assert!(limitation.description().contains("2026-03-01"));
    }

    #[test]
    fn test_security_summary() {
        let mut info = HardwareInfo::default();
        assert_eq!(
            info.security_summary(),
            "No known hardware security limitations"
        );

        info.limitations.push(HardwareLimitation::Emulator);
        assert!(info.security_summary().contains("emulator"));
    }

    #[test]
    fn test_multiple_limitations() {
        let mut info = HardwareInfo::default();
        info.limitations.push(HardwareLimitation::Emulator);
        info.limitations.push(HardwareLimitation::RootedDevice);
        info.update_trust_status();

        assert!(info.hardware_trust_degraded);
        let reason = info.trust_degradation_reason.as_ref().unwrap();
        assert!(reason.contains("emulator"));
        assert!(reason.contains("rooted"));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let info = HardwareInfo {
            platform: "android".to_string(),
            soc_manufacturer: Some("MediaTek".to_string()),
            soc_model: Some("mt6878 (dimensity7300)".to_string()),
            is_emulator: false,
            is_suspicious_emulator: false,
            is_rooted: false,
            limitations: vec![HardwareLimitation::VulnerableSoC {
                manufacturer: "MediaTek".to_string(),
                advisory: SecurityAdvisory {
                    cve: "CVE-2026-20435".to_string(),
                    title: "MediaTek Boot ROM EMFI".to_string(),
                    impact: "Key extraction".to_string(),
                    software_patchable: false,
                    min_patch_level: None,
                },
            }],
            hardware_trust_degraded: true,
            trust_degradation_reason: Some("test".to_string()),
            ..Default::default()
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: HardwareInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(info.platform, deserialized.platform);
        assert_eq!(info.soc_manufacturer, deserialized.soc_manufacturer);
        assert_eq!(
            info.hardware_trust_degraded,
            deserialized.hardware_trust_degraded
        );
    }
}
