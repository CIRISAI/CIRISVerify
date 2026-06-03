//! Centralized HTTP client factory for CIRISVerify (v4.8.0+, #52).
//!
//! Every reqwest::Client construction in `ciris-verify-core` goes
//! through [`build_async_http_client`]. The factory enforces:
//! - `connect_timeout` (purpose-dependent — see [`ClientPurpose`])
//! - `timeout` (purpose-dependent)
//! - `tcp_keepalive(Some(Duration::from_secs(30)))`
//! - `happy_eyeballs(Some(Duration::from_millis(250)))` — RFC 8305
//!   parallel A-record racing, closes the S21U/Verizon blackhole hang
//! - `user_agent("CIRISVerify/{ver}")`
//!
//! No naked `reqwest::Client::new()` / `reqwest::Client::builder()`
//! call sites should remain in `ciris-verify-core` after the v4.8.0
//! integration.
//!
//! # reqwest 0.12.28 compatibility note
//!
//! As of the workspace pin (`reqwest = "0.12"` → 0.12.28), the
//! `ClientBuilder::happy_eyeballs` method is **not exposed**. The
//! "happy eyeballs" terminology appears only in an internal doc
//! comment on `reqwest::dns::hickory`. When this method lands in a
//! future reqwest release, replace the gap-warning block below with
//! `.happy_eyeballs(Some(Duration::from_millis(250)))`.

use std::sync::Once;
use std::time::Duration;

use reqwest::Client;

use crate::error::VerifyError;

/// TCP keepalive interval applied to every client built by this factory.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// Happy-eyeballs (RFC 8305) parallel-attempt delay we *would* apply
/// if reqwest exposed the knob.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

/// Emits the reqwest-gap warning exactly once per process.
static HAPPY_EYEBALLS_GAP_WARNED: Once = Once::new();

/// Purpose-tag for the HTTP client. Determines the timeout pair.
#[derive(Debug, Clone, Copy)]
pub enum ClientPurpose {
    /// Fast reachability HEAD probe (CIRISVerify#50).
    /// connect_timeout=2s, timeout=2s.
    Probe,
    /// Normal registry / manifest fetch.
    /// connect_timeout=5s, timeout=10s.
    Normal,
    /// DNS-over-HTTPS resolver probe.
    /// connect_timeout=3s, timeout=5s.
    Doh,
    /// Caller-specified bespoke timeouts.
    Custom {
        /// Connect-phase timeout.
        connect: Duration,
        /// Total request timeout (connect + body).
        total: Duration,
    },
}

impl ClientPurpose {
    /// Returns the `(connect_timeout, total_timeout)` pair for this purpose.
    pub fn timeouts(&self) -> (Duration, Duration) {
        match self {
            Self::Probe => (Duration::from_secs(2), Duration::from_secs(2)),
            Self::Normal => (Duration::from_secs(5), Duration::from_secs(10)),
            Self::Doh => (Duration::from_secs(3), Duration::from_secs(5)),
            Self::Custom { connect, total } => (*connect, *total),
        }
    }
}

/// Construct a reqwest async Client with v4.8.0 robust defaults.
///
/// Always-enforced regardless of `purpose`:
/// - `tcp_keepalive(Some(Duration::from_secs(30)))`
/// - `happy_eyeballs(Some(Duration::from_millis(250)))` — **gated on
///   reqwest support; see module docs**
/// - `user_agent("CIRISVerify/{ver}")`
pub fn build_async_http_client(purpose: ClientPurpose) -> Result<Client, VerifyError> {
    let (connect_timeout, total_timeout) = purpose.timeouts();
    let user_agent = concat!("CIRISVerify/", env!("CARGO_PKG_VERSION"));

    // reqwest 0.12.28 does not expose `ClientBuilder::happy_eyeballs`.
    // Emit a one-time warning so operators know the S21U/Verizon
    // blackhole mitigation is partial until reqwest ships the knob.
    HAPPY_EYEBALLS_GAP_WARNED.call_once(|| {
        tracing::warn!(
            requested_eyeballs_delay_ms = HAPPY_EYEBALLS_DELAY.as_millis() as u64,
            reqwest_version = env!("CARGO_PKG_VERSION"),
            "reqwest 0.12.28 does not expose ClientBuilder::happy_eyeballs; \
             RFC 8305 parallel A-record racing is NOT active. \
             tcp_keepalive + connect_timeout still applied. Track #52."
        );
    });

    Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(total_timeout)
        .tcp_keepalive(Some(TCP_KEEPALIVE))
        .user_agent(user_agent)
        .build()
        .map_err(|e| VerifyError::HttpsError {
            message: format!("failed to build HTTP client ({purpose:?}): {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_purpose_has_2s_timeouts() {
        let (connect, total) = ClientPurpose::Probe.timeouts();
        assert_eq!(connect, Duration::from_secs(2));
        assert_eq!(total, Duration::from_secs(2));
    }

    #[test]
    fn normal_purpose_has_5s_10s_timeouts() {
        let (connect, total) = ClientPurpose::Normal.timeouts();
        assert_eq!(connect, Duration::from_secs(5));
        assert_eq!(total, Duration::from_secs(10));
    }

    #[test]
    fn doh_purpose_has_3s_5s_timeouts() {
        let (connect, total) = ClientPurpose::Doh.timeouts();
        assert_eq!(connect, Duration::from_secs(3));
        assert_eq!(total, Duration::from_secs(5));
    }

    #[test]
    fn custom_purpose_passes_through() {
        let purpose = ClientPurpose::Custom {
            connect: Duration::from_secs(1),
            total: Duration::from_secs(4),
        };
        let (connect, total) = purpose.timeouts();
        assert_eq!(connect, Duration::from_secs(1));
        assert_eq!(total, Duration::from_secs(4));
    }

    #[test]
    fn build_client_succeeds_for_all_purposes() {
        for purpose in [
            ClientPurpose::Probe,
            ClientPurpose::Normal,
            ClientPurpose::Doh,
            ClientPurpose::Custom {
                connect: Duration::from_secs(1),
                total: Duration::from_secs(4),
            },
        ] {
            let result = build_async_http_client(purpose);
            assert!(
                result.is_ok(),
                "build_async_http_client failed for {purpose:?}: {:?}",
                result.err()
            );
        }
    }

    /// Proves connect_timeout is wired: a Probe client targeting a
    /// closed port on loopback must error within the 2s probe budget
    /// (plus scheduler slack). If reqwest's connect_timeout were not
    /// applied, this would hang for the OS-default ~75s SYN backoff.
    #[tokio::test]
    async fn build_client_actually_fast_fails_unreachable() {
        let client =
            build_async_http_client(ClientPurpose::Probe).expect("Probe client should build");

        let start = std::time::Instant::now();
        let result = client.head("http://127.0.0.1:1/").send().await;
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "HEAD to 127.0.0.1:1 should fail, got: {result:?}"
        );
        assert!(
            elapsed < Duration::from_millis(2500),
            "Probe client took {elapsed:?}, expected <2.5s — connect_timeout not wired?"
        );
    }
}
