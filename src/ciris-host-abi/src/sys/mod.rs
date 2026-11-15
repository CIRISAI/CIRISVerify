//! THE target boundary (FSD §4.1.2). Every `cfg(target_*)` a node build
//! depends on is here; the rest of the crate, and every node crate, is
//! target-independent. `wasm.rs` calls the `ciris:node/*` imports;
//! `native.rs` calls the thread's installed [`crate::host::Host`]. Both
//! define the same items with the same signatures.

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::*;
