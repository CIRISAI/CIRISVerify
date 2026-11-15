//! The ciris-rt smoke node: a core wasm module whose `init` spawns a task
//! that draws randomness, sleeps 20 ms through the runtime's timers, and
//! logs when the timer fired. The host's `wake.next-deadline` / `tick`
//! loop is what makes it fire. No `cfg(target_*)`.
//!
//! ```text
//! cargo build -p ciris-rt --example rt-smoke-node --target wasm32-unknown-unknown --release
//! cargo run -p ciris-host-abi --bin ciris-abi-gate -- \
//!   target/wasm32-unknown-unknown/release/examples/rt_smoke_node.wasm
//! ```

use std::cell::Cell;

use ciris_host_abi::log::{self, Level, MetricKind};
use ciris_host_abi::random;
use ciris_rt::time::{sleep, Duration, Instant};
use ciris_rt::{spawn, RtNode};

std::thread_local! {
    static FIRED: Cell<u64> = const { Cell::new(0) };
}

struct Smoke;

impl RtNode for Smoke {
    fn init() -> Result<(), String> {
        let draw = random::fill(8);
        if draw == [0; 8] {
            return Err("all-zero random draw".into());
        }
        let t0 = Instant::now();
        spawn(async move {
            sleep(Duration::from_millis(20)).await;
            let waited = t0.elapsed().as_micros();
            FIRED.with(|f| f.set(1));
            log::metric(
                "rt_smoke.slept_us",
                MetricKind::Gauge,
                waited as f64,
                &[("node".to_owned(), "rt-smoke".to_owned())],
            );
            log::record(
                Level::Info,
                "rt-smoke",
                &format!("timer fired after {waited}us (draw {:02x})", draw[0]),
            );
        });
        log::record(Level::Info, "rt-smoke", "init: task spawned");
        Ok(())
    }

    /// Returns `[1]` once the timer has fired, else `[0]`.
    fn api(_req: Vec<u8>, _local: bool) -> Vec<u8> {
        vec![u8::try_from(FIRED.with(Cell::get)).unwrap_or(0)]
    }
}

ciris_rt::node!(Smoke);
