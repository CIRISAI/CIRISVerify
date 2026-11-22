//! The host's monotonic clock and boot identity for the halt fuse (FSD-007
//! §3.3). The clock must not go back and must not be settable; it should count
//! time the device spends suspended (a clock that stops in suspend extends a
//! halt, which is safe).
//!
//! | Platform        | Clock                          | Boot identity                          |
//! |-----------------|--------------------------------|----------------------------------------|
//! | Linux, Android  | `CLOCK_BOOTTIME` (counts suspend) | `/proc/sys/kernel/random/boot_id`   |
//! | macOS, iOS      | `CLOCK_MONOTONIC` (counts sleep on Apple) | SHA-256 of `kern.boottime`, first 16 bytes |
//! | anything else   | `std::time::Instant` from process start | one per process                |
//!
//! Where the platform gives no boot identity (or reading it fails), every
//! process start is a new boot: [`super::HaltLatch::advance`] adds zero across
//! it, so a restart only ever extends a halt.

use std::sync::OnceLock;

use super::MonotonicReading;

/// Reads the platform's monotonic clock and boot identity.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseMeter;

impl FuseMeter {
    /// The platform meter.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// One reading.
    #[must_use]
    pub fn read(&self) -> MonotonicReading {
        match platform::read() {
            Some(r) => r,
            None => process_reading(),
        }
    }
}

/// The fallback: milliseconds since this process first read the meter, under
/// a boot identity drawn once per process.
fn process_reading() -> MonotonicReading {
    static START: OnceLock<(std::time::Instant, [u8; 16])> = OnceLock::new();
    let (start, boot) = START.get_or_init(|| (std::time::Instant::now(), process_boot_id()));
    MonotonicReading {
        monotonic_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        boot: *boot,
    }
}

/// An identity for this process: distinct across restarts, not secret.
fn process_boot_id() -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ciris.fuse.process-boot.v1");
    h.update(std::process::id().to_le_bytes());
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.update(d.as_nanos().to_le_bytes());
    }
    let mut seed = [0u8; 16];
    // A draw that fails leaves the hash of pid and time, still distinct enough.
    let _ = ciris_crypto::random::fill(&mut seed);
    h.update(seed);
    let d: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::MonotonicReading;
    use std::sync::OnceLock;

    pub(super) fn read() -> Option<MonotonicReading> {
        static BOOT: OnceLock<Option<[u8; 16]>> = OnceLock::new();
        let boot = (*BOOT.get_or_init(boot_id))?;
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, writable timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
            return None;
        }
        let ms = u64::try_from(ts.tv_sec).ok()?.checked_mul(1000)?
            + u64::try_from(ts.tv_nsec).ok()? / 1_000_000;
        Some(MonotonicReading {
            monotonic_ms: ms,
            boot,
        })
    }

    /// `/proc/sys/kernel/random/boot_id`: a UUID, fresh each boot.
    fn boot_id() -> Option<[u8; 16]> {
        let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let hex: String = s.trim().chars().filter(|c| *c != '-').collect();
        hex::decode(hex).ok()?.try_into().ok()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod platform {
    use super::MonotonicReading;
    use std::sync::OnceLock;

    pub(super) fn read() -> Option<MonotonicReading> {
        static BOOT: OnceLock<Option<[u8; 16]>> = OnceLock::new();
        let boot = (*BOOT.get_or_init(boot_id))?;
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, writable timespec. On Apple platforms
        // CLOCK_MONOTONIC keeps counting while the system sleeps.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
            return None;
        }
        let ms = u64::try_from(ts.tv_sec).ok()?.checked_mul(1000)?
            + u64::try_from(ts.tv_nsec).ok()? / 1_000_000;
        Some(MonotonicReading {
            monotonic_ms: ms,
            boot,
        })
    }

    /// The first 16 bytes of SHA-256 over `kern.boottime`.
    fn boot_id() -> Option<[u8; 16]> {
        use sha2::{Digest, Sha256};
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut len = core::mem::size_of::<libc::timeval>();
        let name = c"kern.boottime";
        // SAFETY: `tv` and `len` are valid for writes of `len` bytes; no new
        // value is set.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut tv as *mut libc::timeval).cast(),
                &mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len != core::mem::size_of::<libc::timeval>() {
            return None;
        }
        let mut h = Sha256::new();
        h.update(b"ciris.fuse.apple-boot.v1");
        h.update(i64::from(tv.tv_sec).to_le_bytes());
        h.update(i64::from(tv.tv_usec).to_le_bytes());
        let d: [u8; 32] = h.finalize().into();
        d[..16].try_into().ok()
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
mod platform {
    pub(super) fn read() -> Option<super::MonotonicReading> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readings_do_not_go_back_and_keep_their_boot() {
        let m = FuseMeter::new();
        let a = m.read();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = m.read();
        assert_eq!(a.boot, b.boot);
        assert!(b.monotonic_ms >= a.monotonic_ms + 10, "{a:?} {b:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reads_the_kernel_boot_id() {
        let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let want = hex::decode(s.trim().replace('-', "")).unwrap();
        assert_eq!(FuseMeter::new().read().boot.as_slice(), want.as_slice());
    }
}
