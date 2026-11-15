//! The smoke node: a minimal node module that calls `clock`, `random` and
//! `log` through the wrappers and draws through every getrandom generation
//! in the lock (0.2 via `rand_core::OsRng`, 0.3, 0.4). It contains no
//! `cfg(target_*)`.
//!
//! Build it as a core module and gate it (README, "Smoke test"):
//!
//! ```text
//! CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="custom"' \
//!   cargo build -p ciris-host-abi --example smoke-node \
//!   --target wasm32-unknown-unknown --release --features getrandom-backend
//! cargo run -p ciris-host-abi --bin ciris-abi-gate -- \
//!   target/wasm32-unknown-unknown/release/examples/smoke_node.wasm
//! ```

use ciris_host_abi::log::Level;
use ciris_host_abi::{clock, log, random, Event, Node};
use rand_core::RngCore as _;

struct Smoke;

/// Draw 32 bytes through each source; refuse an all-zero draw.
fn draw_all() -> Result<[u8; 4], String> {
    let mut direct = [0u8; 32];
    random::fill_bytes(&mut direct);

    let mut os = [0u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut os)
        .map_err(|e| format!("OsRng: {e}"))?;

    let mut g02 = [0u8; 32];
    getrandom02::getrandom(&mut g02).map_err(|e| format!("getrandom 0.2: {e}"))?;
    let mut g03 = [0u8; 32];
    getrandom03::fill(&mut g03).map_err(|e| format!("getrandom 0.3: {e}"))?;
    let mut g04 = [0u8; 32];
    getrandom04::fill(&mut g04).map_err(|e| format!("getrandom 0.4: {e}"))?;

    let firsts = [os[0], g02[0], g03[0], g04[0]];
    for (name, buf) in [
        ("direct", direct),
        ("OsRng", os),
        ("0.2", g02),
        ("0.3", g03),
        ("0.4", g04),
    ] {
        if buf == [0u8; 32] {
            return Err(format!("{name}: all-zero draw"));
        }
    }
    Ok(firsts)
}

impl Node for Smoke {
    fn init() -> Result<(), String> {
        let t = clock::monotonic_us();
        let firsts = draw_all()?;
        log::record(
            Level::Info,
            "smoke",
            &format!(
                "init at {t}us, wall {:?}, draws {firsts:02x?}",
                clock::wall_ms()
            ),
        );
        Ok(())
    }

    fn tick(budget_us: u32) -> u64 {
        let now = clock::monotonic_us();
        log::metric(
            "smoke.tick_budget_us",
            log::MetricKind::Gauge,
            f64::from(budget_us),
            &[("node".to_owned(), "smoke".to_owned())],
        );
        now + 1_000_000
    }

    fn on_event(e: Event) {
        log::record(Level::Debug, "smoke", &format!("event {e:?}"));
    }

    fn api(req: Vec<u8>, _local: bool) -> Vec<u8> {
        req
    }
}

ciris_host_abi::export_node!(Smoke);
