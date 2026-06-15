//! Startup RNG health-check (CIRISVerify#55 Gap H, v4.9.0+).
//!
//! A NIST SP 800-90B-shaped startup health-check on the OS RNG, plus a
//! process-global fail-secure gate. The federation's RNG facade
//! ([`crate::random`]) routes every entropy draw through one audit
//! point; this module adds a one-time "is the entropy source obviously
//! broken / stuck?" gate in front of that draw so a degraded OS CSPRNG
//! (e.g. an early-boot or virtualized environment whose `getrandom(2)`
//! is mis-wired to a constant) fails *closed* rather than silently
//! emitting predictable nonces/salts/keys.
//!
//! ## What it tests
//!
//! Two of the SP 800-90B startup health tests, run over a single fresh
//! draw from `OsRng`, treating the source as a byte (8-bit symbol)
//! stream:
//!
//! - **Repetition-count test** (SP 800-90B §4.4.1): catch a *stuck*
//!   source that emits the same value over and over. We fail if any
//!   byte value repeats consecutively more than `REPETITION_CUTOFF`
//!   times.
//! - **Adaptive-proportion test** (SP 800-90B §4.4.2): catch a source
//!   that is biased toward (but not stuck at) one value. Over a sliding
//!   window of `ADAPTIVE_WINDOW` bytes we fail if any single byte
//!   value occurs more than `ADAPTIVE_CUTOFF` times.
//!
//! The expensive per-block min-entropy estimators (SP 800-90B §6) are
//! **intentionally deferred** — the issue marks them optional. The two
//! startup tests above are stuck/biased-source detectors, not entropy
//! quantifiers; they are cheap, deterministic, and have a negligible
//! false-positive rate on a real full-entropy source (see the cutoff
//! justifications below).
//!
//! ## Fail-secure latch
//!
//! [`run_startup_health_check`] runs the check ONCE and latches the
//! verdict in a process-global. [`crate::random::fill`] reads that
//! latch via [`is_rng_failed`] on every call and refuses to draw if it
//! is `Failed`. The gate only *reads* the latch — it never re-runs the
//! check (which would itself draw, risking recursion).

use rand_core::{OsRng, RngCore};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

/// Number of bytes drawn for the startup sample. 4096 bytes = 4096
/// 8-bit symbols, comfortably more than the SP 800-90B startup test
/// minimum (1024 samples) while staying a single cheap draw.
const SAMPLE_LEN: usize = 4096;

/// Repetition-count cutoff `C` (SP 800-90B §4.4.1).
///
/// Fail if any byte value appears more than `C` times *in a row*. For a
/// full-entropy byte source, consecutive bytes are independent and
/// uniform over 256 values, so the probability that a given position
/// starts a run of length `k` of one specific value is `256^-(k-1)`.
/// At `k = 32`, the per-position probability of such a run is
/// `256^-31 = 2^-248` — astronomically below any realistic false-alarm
/// budget even multiplied by the ~4096 starting positions in the
/// sample (`< 2^-235`). A run this long is a clear "the source is stuck
/// / wired to a constant" signal, so 32 is a safe broken-RNG detector
/// with no plausible false positive on healthy hardware.
const REPETITION_CUTOFF: usize = 32;

/// Adaptive-proportion sliding-window size `W` (SP 800-90B §4.4.2).
const ADAPTIVE_WINDOW: usize = 512;

/// Adaptive-proportion count cutoff (occurrences of one byte value
/// within any `ADAPTIVE_WINDOW`-byte window).
///
/// For a uniform byte source the count `X` of any fixed value in a
/// window of `W = 512` is `Binomial(512, 1/256)`, with mean
/// `E[X] = W/256 = 2`. We fail at `count > W/4 = 128`, i.e. one value
/// occupying more than a quarter of the window. That cutoff sits ~126
/// standard-deviations-worth above the mean (the binomial here is
/// near-Poisson(2); the upper tail `P(X > 128)` is bounded far below
/// `2^-256` by a Chernoff/Poisson-tail argument — `P(X >= k)` for
/// `lambda = 2` falls off faster than `2^-k log k`). Multiplied by the
/// 256 possible values and the ~3585 windows in a 4096-byte sample, the
/// aggregate false-positive probability is still negligible, while a
/// source biased enough to put one value at >25% density is plainly
/// detected.
const ADAPTIVE_CUTOFF: usize = ADAPTIVE_WINDOW / 4;

/// Result of the startup RNG health-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RngHealth {
    /// All SP 800-90B startup tests passed.
    Healthy,
    /// A test failed — the OS RNG is producing detectably non-random
    /// output. Carries which test + detail.
    Failed {
        /// Which startup test failed (`"repetition-count"` or
        /// `"adaptive-proportion"`).
        test: &'static str,
        /// Human-readable detail (e.g. the offending byte value and
        /// observed count) for logs / the `RngHealthCheckFailed` error.
        detail: String,
    },
}

/// Test name constant for the repetition-count test.
pub const TEST_REPETITION_COUNT: &str = "repetition-count";
/// Test name constant for the adaptive-proportion test.
pub const TEST_ADAPTIVE_PROPORTION: &str = "adaptive-proportion";

// Latch encoding. The verdict is stored in an `AtomicU8` so the
// test-only override (`__force_health_for_test`) can RESET it between
// fail-secure-path tests — a bare `OnceLock` could not be un-set. The
// `OnceLock` below guards only the *first real* run so that
// `run_startup_health_check` is genuinely idempotent (draws once) in
// production. Encoding:
//   0 = UNKNOWN (not yet checked)
//   1 = HEALTHY
//   2 = FAILED
const STATE_UNKNOWN: u8 = 0;
const STATE_HEALTHY: u8 = 1;
const STATE_FAILED: u8 = 2;

static RNG_STATE: AtomicU8 = AtomicU8::new(STATE_UNKNOWN);

/// One-shot latch for the *real* startup verdict (so we draw exactly
/// once). Holds the full `RngHealth` (including failure detail) for the
/// idempotent return value.
static STARTUP_VERDICT: OnceLock<RngHealth> = OnceLock::new();

#[cfg(test)]
thread_local! {
    /// Per-thread override for the fail-secure-path test. `Some(state)`
    /// shadows the process-global latch for the current thread only, so
    /// forcing `Failed` cannot poison the shared global for tests that
    /// race on other threads. See [`__force_health_for_test`].
    static TEST_OVERRIDE: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
}

/// Repetition-count test (SP 800-90B §4.4.1).
///
/// Returns `Failed` if any byte value repeats consecutively more than
/// `REPETITION_CUTOFF` times.
fn repetition_count(sample: &[u8]) -> RngHealth {
    if sample.is_empty() {
        return RngHealth::Healthy;
    }
    let mut prev = sample[0];
    // `run` counts how many times `prev` has appeared in a row,
    // including the first occurrence.
    let mut run: usize = 1;
    for &b in &sample[1..] {
        if b == prev {
            run += 1;
            if run > REPETITION_CUTOFF {
                return RngHealth::Failed {
                    test: TEST_REPETITION_COUNT,
                    detail: format!(
                        "byte value 0x{prev:02x} repeated > {REPETITION_CUTOFF} times consecutively"
                    ),
                };
            }
        } else {
            prev = b;
            run = 1;
        }
    }
    RngHealth::Healthy
}

/// Adaptive-proportion test (SP 800-90B §4.4.2).
///
/// Over every sliding window of `ADAPTIVE_WINDOW` bytes, fail if any
/// single byte value occurs more than `ADAPTIVE_CUTOFF` times.
fn adaptive_proportion(sample: &[u8]) -> RngHealth {
    if sample.len() < ADAPTIVE_WINDOW {
        // Too short for a full window — nothing to test. (The real
        // startup sample is always SAMPLE_LEN >> ADAPTIVE_WINDOW; this
        // guard only matters for tiny injected test samples.)
        return RngHealth::Healthy;
    }
    // Rolling per-value counts over the current window. Seed with the
    // first full window, then slide one byte at a time.
    let mut counts = [0usize; 256];
    for &b in &sample[..ADAPTIVE_WINDOW] {
        counts[b as usize] += 1;
    }
    let check = |counts: &[usize; 256]| -> Option<(u8, usize)> {
        for (value, &c) in counts.iter().enumerate() {
            if c > ADAPTIVE_CUTOFF {
                // value is 0..=255 by construction.
                return Some((value as u8, c));
            }
        }
        None
    };
    if let Some((value, c)) = check(&counts) {
        return RngHealth::Failed {
            test: TEST_ADAPTIVE_PROPORTION,
            detail: format!(
                "byte value 0x{value:02x} occurred {c} times in a {ADAPTIVE_WINDOW}-byte window (cutoff {ADAPTIVE_CUTOFF})"
            ),
        };
    }
    for i in ADAPTIVE_WINDOW..sample.len() {
        let leaving = sample[i - ADAPTIVE_WINDOW] as usize;
        let entering = sample[i] as usize;
        counts[leaving] -= 1;
        counts[entering] += 1;
        // Only the entering value can have crossed the cutoff this step.
        if counts[entering] > ADAPTIVE_CUTOFF {
            return RngHealth::Failed {
                test: TEST_ADAPTIVE_PROPORTION,
                detail: format!(
                    "byte value 0x{:02x} occurred {} times in a {ADAPTIVE_WINDOW}-byte window (cutoff {ADAPTIVE_CUTOFF})",
                    entering as u8, counts[entering]
                ),
            };
        }
    }
    RngHealth::Healthy
}

/// Pure SP 800-90B startup-test logic over an injected sample.
///
/// Factored out so the test logic is deterministic and unit-testable
/// without a real broken RNG. Runs repetition-count first (cheapest,
/// catches a fully stuck source), then adaptive-proportion.
fn check_sample(sample: &[u8]) -> RngHealth {
    match repetition_count(sample) {
        RngHealth::Healthy => adaptive_proportion(sample),
        failed => failed,
    }
}

/// Run the startup health-check ONCE and latch the result in a
/// process-global. Idempotent: subsequent calls return the latched
/// result without re-drawing. Returns the latched [`RngHealth`].
///
/// The check draws a fresh `SAMPLE_LEN`-byte sample from `OsRng` and
/// runs `check_sample` over it. On `Failed`, [`is_rng_failed`] starts
/// returning `true` and every [`crate::random::fill`] thereafter
/// fail-secures with `CryptoError::RngHealthCheckFailed`.
pub fn run_startup_health_check() -> RngHealth {
    STARTUP_VERDICT
        .get_or_init(|| {
            let mut sample = [0u8; SAMPLE_LEN];
            let verdict = match OsRng.try_fill_bytes(&mut sample) {
                Ok(()) => check_sample(&sample),
                Err(e) => RngHealth::Failed {
                    test: "os-rng-draw",
                    detail: format!("OsRng failed to provide a health-check sample: {e}"),
                },
            };
            store_state(&verdict);
            verdict
        })
        .clone()
}

/// True iff the RNG has been health-checked AND failed. Returns `false`
/// before the check runs (unknown) and `false` when healthy. Used by
/// [`crate::random::fill`] to fail-secure.
///
/// In test builds, a per-thread override (set by
/// [`__force_health_for_test`]) takes precedence over the process-global
/// latch. That keeps the fail-secure-path test from poisoning the shared
/// global for tests running concurrently on other threads — the forced
/// `Failed` verdict is visible only on the thread that set it, so the
/// test is deterministic under nextest/`cargo test` parallelism.
#[must_use]
pub fn is_rng_failed() -> bool {
    #[cfg(test)]
    {
        if let Some(forced) = TEST_OVERRIDE.with(|c| c.get()) {
            return forced == STATE_FAILED;
        }
    }
    RNG_STATE.load(Ordering::Acquire) == STATE_FAILED
}

/// Latch the atomic state byte from a verdict.
fn store_state(h: &RngHealth) {
    let s = match h {
        RngHealth::Healthy => STATE_HEALTHY,
        RngHealth::Failed { .. } => STATE_FAILED,
    };
    RNG_STATE.store(s, Ordering::Release);
}

/// Test-only: force the health state read by [`is_rng_failed`] for
/// fail-secure-path testing, and reset it afterward.
///
/// In test builds this sets a **per-thread** override (a `Cell`)
/// consulted by [`is_rng_failed`] ahead of the process-global latch, so
/// forcing `Failed` on this thread cannot make a concurrently-running
/// test on another thread see a failed RNG — the override is thread-
/// scoped, which is what makes the fail-secure test non-flaky under
/// parallel execution. In non-test builds it falls back to the global
/// `AtomicU8` latch (the `OnceLock` startup verdict is left untouched).
///
/// Not part of the stable API; hidden from docs.
#[doc(hidden)]
pub fn __force_health_for_test(h: RngHealth) {
    let s = match h {
        RngHealth::Healthy => STATE_HEALTHY,
        RngHealth::Failed { .. } => STATE_FAILED,
    };
    #[cfg(test)]
    {
        TEST_OVERRIDE.with(|c| c.set(Some(s)));
    }
    #[cfg(not(test))]
    {
        RNG_STATE.store(s, Ordering::Release);
    }
}

/// Test-only helpers shared across the crate's keygen fail-secure
/// proof tests (CIRISVerify#74). Compiled only under `#[cfg(test)]`.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{__force_health_for_test, RngHealth};

    /// Run `f` with the RNG health latch forced to `Failed` (per-thread
    /// override), then ALWAYS restore the latch to `Healthy` — even if
    /// `f` panics. Lets a keygen module assert its fail-secure path
    /// without poisoning the process-global latch for other tests.
    ///
    /// The override is thread-local (see [`super::is_rng_failed`]), so no
    /// cross-test serialization mutex is needed: a concurrently-running
    /// test on another thread never observes this thread's forced
    /// `Failed`.
    pub(crate) fn with_forced_failed<R>(f: impl FnOnce() -> R) -> R {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                __force_health_for_test(RngHealth::Healthy);
            }
        }
        __force_health_for_test(RngHealth::Failed {
            test: "test-injected",
            detail: "forced for keygen fail-secure proof".to_string(),
        });
        let _restore = Restore;
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Draw a real sample and confirm the startup tests pass on healthy
    /// hardware.
    #[test]
    fn check_sample_passes_on_real_random() {
        let mut sample = [0u8; SAMPLE_LEN];
        OsRng.try_fill_bytes(&mut sample).unwrap();
        assert_eq!(check_sample(&sample), RngHealth::Healthy);
    }

    /// An all-zeros buffer is a stuck source: caught by repetition-count
    /// first (a 4096-long run of 0x00).
    #[test]
    fn check_sample_fails_all_zeros() {
        let sample = [0u8; SAMPLE_LEN];
        match check_sample(&sample) {
            RngHealth::Failed { test, .. } => assert_eq!(test, TEST_REPETITION_COUNT),
            other => panic!("expected repetition-count failure, got {other:?}"),
        }
    }

    /// A single repeated non-zero value is likewise a stuck source.
    #[test]
    fn check_sample_fails_single_repeated_value() {
        let sample = [0x42u8; SAMPLE_LEN];
        match check_sample(&sample) {
            RngHealth::Failed { test, .. } => assert_eq!(test, TEST_REPETITION_COUNT),
            other => panic!("expected repetition-count failure, got {other:?}"),
        }
    }

    /// Construct a sample that PASSES repetition-count (no long run) but
    /// has one value at >50% density in a window, so adaptive-proportion
    /// catches it. We alternate 0xAA with a varying filler byte so 0xAA
    /// never appears twice in a row (max run = 1), yet 0xAA is exactly
    /// half of every window — far over the W/4 cutoff.
    #[test]
    fn check_sample_fails_adaptive_proportion() {
        let mut sample = vec![0u8; SAMPLE_LEN];
        for (i, slot) in sample.iter_mut().enumerate() {
            if i % 2 == 0 {
                *slot = 0xAA;
            } else {
                // Filler that is never 0xAA and varies so it forms no
                // long run of its own. (i/2 mod 256, skipping 0xAA.)
                let mut f = (i / 2 % 256) as u8;
                if f == 0xAA {
                    f = 0x01;
                }
                *slot = f;
            }
        }
        // Sanity: repetition-count alone must pass on this construction.
        assert_eq!(repetition_count(&sample), RngHealth::Healthy);
        match check_sample(&sample) {
            RngHealth::Failed { test, .. } => assert_eq!(test, TEST_ADAPTIVE_PROPORTION),
            other => panic!("expected adaptive-proportion failure, got {other:?}"),
        }
    }

    /// The startup entry point is idempotent and Healthy on real
    /// hardware.
    #[test]
    fn startup_check_is_idempotent() {
        let first = run_startup_health_check();
        let second = run_startup_health_check();
        assert_eq!(first, second);
        assert_eq!(first, RngHealth::Healthy);
    }

    /// Empty / sub-window samples are treated as "nothing to test" so we
    /// never false-fail on a zero-length draw.
    #[test]
    fn check_sample_empty_is_healthy() {
        assert_eq!(check_sample(&[]), RngHealth::Healthy);
        assert_eq!(check_sample(&[0u8; 8]), RngHealth::Healthy);
    }
}
