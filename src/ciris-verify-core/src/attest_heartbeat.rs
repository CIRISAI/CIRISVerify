//! Self-diagnosing heartbeat for long-running attestation operations.
//!
//! Spawns a tokio task that emits a `tracing::warn!` line every
//! [`HEARTBEAT_INTERVAL`] (5s) with elapsed time and current phase.
//! When the returned [`HeartbeatGuard`] is dropped, the heartbeat
//! task is aborted via [`tokio::task::JoinHandle::abort`].
//!
//! Motivation (Bug C, issue #52): Eric's S21U/Verizon-LTE trace showed
//! `ciris_verify_run_attestation` going silent for 89.98s — only one
//! log line emitted in the entire hang window. The Python verifier_runner
//! had to bring its own 90s watchdog to detect the hang. With this guard,
//! verify self-diagnoses by emitting a warn-level heartbeat every 5s.
//!
//! Usage in `unified::run_attestation_inner`:
//!
//! ```ignore
//! let _hb = HeartbeatGuard::spawn("attestation");
//! _hb.set_phase("phase 1/5: parallel manifest fetch");
//! // ...do work...
//! _hb.set_phase("phase 2/5: parallel validation");
//! // ...do work...
//! // _hb dropped here → background task aborted
//! ```

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

/// Interval between consecutive heartbeat log lines.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// RAII guard that owns a background heartbeat task.
///
/// Dropping aborts the task. The phase string is hot-mutable —
/// updates via [`HeartbeatGuard::set_phase`] are visible to the
/// next heartbeat tick.
pub struct HeartbeatGuard {
    handle: JoinHandle<()>,
    phase: Arc<Mutex<String>>,
}

impl HeartbeatGuard {
    /// Spawn a heartbeat task tagged with `operation`.
    ///
    /// First heartbeat fires at [`HEARTBEAT_INTERVAL`] (NOT immediately —
    /// short operations under 5s emit zero heartbeats, by design).
    #[must_use]
    pub fn spawn(operation: &'static str) -> Self {
        Self::spawn_with_interval(operation, HEARTBEAT_INTERVAL)
    }

    /// Spawn a heartbeat task with a custom interval.
    ///
    /// Public so tests can use short intervals without a paused tokio
    /// runtime (which would require the `tokio/test-util` feature).
    /// Production code should use [`HeartbeatGuard::spawn`].
    #[must_use]
    pub fn spawn_with_interval(operation: &'static str, interval: Duration) -> Self {
        let phase = Arc::new(Mutex::new(String::from("initializing")));
        let phase_for_task = Arc::clone(&phase);
        let started = Instant::now();

        let handle = tokio::spawn(async move {
            // First tick at +interval, not immediately. interval_at's
            // first tick is at the supplied start instant.
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            loop {
                ticker.tick().await;
                let elapsed = started.elapsed();
                let phase_snapshot = phase_for_task
                    .lock()
                    .map(|g| g.clone())
                    .unwrap_or_else(|_| String::from("<poisoned>"));
                tracing::warn!(
                    operation,
                    elapsed_ms = %elapsed.as_millis(),
                    phase = %phase_snapshot,
                    "attestation still running"
                );
            }
        });

        Self { handle, phase }
    }

    /// Update the phase string. The next heartbeat tick will see it.
    pub fn set_phase(&self, phase: impl Into<String>) {
        if let Ok(mut g) = self.phase.lock() {
            *g = phase.into();
        }
    }
}

impl Drop for HeartbeatGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// Short interval used by tests so the suite runs in <1s on
    /// real wall-clock time, avoiding the tokio `test-util` feature
    /// dependency that `start_paused = true` would require.
    const TEST_INTERVAL: Duration = Duration::from_millis(100);

    /// In-process `MakeWriter` that captures all emitted log bytes
    /// into a shared `Vec<u8>` for assertion.
    #[derive(Clone, Default)]
    struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturingWriter {
        type Writer = CapturingWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured(buf: &CapturingWriter) -> String {
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
    }

    fn count_heartbeats(s: &str) -> usize {
        s.matches("attestation still running").count()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn heartbeat_does_not_fire_before_interval() {
        let buf = CapturingWriter::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let _g = tracing::subscriber::set_default(sub);

        let _hb = HeartbeatGuard::spawn_with_interval("attestation", TEST_INTERVAL);
        // 80ms < 100ms interval → 0 heartbeats expected.
        tokio::time::sleep(Duration::from_millis(80)).await;

        let logs = captured(&buf);
        assert_eq!(count_heartbeats(&logs), 0, "logs: {logs}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn heartbeat_fires_at_interval_boundary() {
        let buf = CapturingWriter::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let _g = tracing::subscriber::set_default(sub);

        let _hb = HeartbeatGuard::spawn_with_interval("attestation", TEST_INTERVAL);
        // ~1.5x interval → exactly 1 heartbeat.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let logs = captured(&buf);
        assert_eq!(count_heartbeats(&logs), 1, "logs: {logs}");
        assert!(logs.contains("operation=\"attestation\""), "logs: {logs}");
        assert!(logs.contains("elapsed_ms="), "logs: {logs}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn heartbeat_fires_repeatedly() {
        let buf = CapturingWriter::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let _g = tracing::subscriber::set_default(sub);

        let _hb = HeartbeatGuard::spawn_with_interval("attestation", TEST_INTERVAL);
        // ~3.5x interval → exactly 3 heartbeats (at ~100, ~200, ~300ms).
        tokio::time::sleep(Duration::from_millis(350)).await;

        let logs = captured(&buf);
        assert_eq!(count_heartbeats(&logs), 3, "logs: {logs}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_phase_updates_visible_to_next_tick() {
        let buf = CapturingWriter::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let _g = tracing::subscriber::set_default(sub);

        let hb = HeartbeatGuard::spawn_with_interval("attestation", TEST_INTERVAL);
        // Update phase before the first tick fires.
        tokio::time::sleep(Duration::from_millis(60)).await;
        hb.set_phase("phase 2");
        // Cross the first tick boundary.
        tokio::time::sleep(Duration::from_millis(90)).await;

        let logs = captured(&buf);
        assert_eq!(count_heartbeats(&logs), 1, "logs: {logs}");
        assert!(logs.contains("phase=phase 2"), "logs: {logs}");
        assert!(!logs.contains("phase=initializing"), "logs: {logs}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drop_aborts_heartbeat_task() {
        let buf = CapturingWriter::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let _g = tracing::subscriber::set_default(sub);

        let hb = HeartbeatGuard::spawn_with_interval("attestation", TEST_INTERVAL);
        // Drop well before the first tick.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(hb);
        // Wait long past several intervals — no heartbeat should ever fire.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let logs = captured(&buf);
        assert_eq!(count_heartbeats(&logs), 0, "logs: {logs}");
    }
}
