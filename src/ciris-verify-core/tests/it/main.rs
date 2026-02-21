//! Consolidated integration tests for ciris-verify-core.
//!
//! This module structure avoids the "cargo test hang" issue that occurs
//! when multiple external test files with proptest run in parallel.
//! See: https://matklad.github.io/2021/02/27/delete-cargo-integration-tests.html

mod security;
mod validation;
