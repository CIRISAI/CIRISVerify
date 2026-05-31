//! Wheel-surface FFI for the v4.5.0 [`ReconsiderDosGuard`]
//! (F-AV-RECONSIDER-DOS defense primitives — CIRISVerify#46 / #50,
//! v4.7.0 wheel-surface work).
//!
//! Unlike the v4.2.0 conformance fns in `lib.rs` (stateless,
//! input-JSON → output-JSON), `ReconsiderDosGuard` holds mutable
//! in-process state (per-event concurrent counters, per-actor rolling
//! budget, per-pair harassment cluster scores) which must persist
//! across `admit_filing` / `record_outcome` calls. So this surface is
//! **handle-based**: the guard is leaked through `Box::into_raw` and
//! the caller is responsible for calling
//! [`ciris_verify_reconsider_guard_free`] once before drop.
//!
//! ## Handle lifecycle
//!
//! - [`ciris_verify_reconsider_guard_new`] returns an opaque
//!   `*mut c_void` minted via `Box::into_raw(Box::new(guard))`. The
//!   Rust allocator owns the box; the caller owns the pointer.
//! - [`ciris_verify_reconsider_guard_free`] reclaims the box via
//!   `Box::from_raw` and drops it. After this call the handle MUST
//!   NOT be reused (the FFI does NOT zero a magic field — handles
//!   are opaque opaque pointers, not first-class objects like the
//!   `CirisVerifyHandle` in `lib.rs`).
//! - All other fns take `*mut c_void` and reborrow it as
//!   `&mut ReconsiderDosGuard` for the duration of the call. The
//!   caller is responsible for NOT calling these fns concurrently on
//!   the same handle from multiple threads (the struct is not `Sync`
//!   and the FFI does not lock internally — Python `threading.Lock`
//!   is the right place for that policy).
//!
//! ## Output JSON shapes
//!
//! `ciris_verify_reconsider_admit_filing`:
//! - On admission: `{"admitted": true}`
//! - On rejection: `{"admitted": false, "rejection": <ReconsiderRejection>}`
//!   where the inner value is the serde-tagged enum from
//!   `ciris-verify-core::reconsider_dos`.
//!
//! `ciris_verify_reconsider_record_outcome`:
//! - Always `{}` on success. Errors return a non-zero status code
//!   without writing the output buffer.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

use ciris_verify_core::reconsider_dos::{FilingOutcome, ReconsiderDosGuard, ReconsiderRejection};

use crate::CirisVerifyError;

// ---------------------------------------------------------------------------
// Local panic-guard macro
//
// `lib.rs`'s `ffi_guard!` is `macro_rules!` and not exported to submodules
// without `#[macro_export]`. Duplicating the small wrapper here keeps the
// reconsider_dos surface self-contained and avoids touching `lib.rs`.
// ---------------------------------------------------------------------------

macro_rules! ffi_guard {
    ($fn_name:expr, $body:expr) => {{
        let result = catch_unwind(AssertUnwindSafe(|| $body));
        match result {
            Ok(code) => code,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!("PANIC in {}: {}", $fn_name, msg);
                CirisVerifyError::InternalError as i32
            },
        }
    }};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Copy `s.as_bytes()` into a fresh `libc::malloc` buffer and write
/// the pointer + length into `*result_out` / `*result_len_out`.
///
/// # Safety
///
/// `result_out` and `result_len_out` must be valid pointers.
unsafe fn write_json_buffer(
    s: &str,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> Result<(), CirisVerifyError> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return Err(CirisVerifyError::InternalError);
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
    *result_out = ptr;
    *result_len_out = len;
    Ok(())
}

/// Read a UTF-8 string slice from a `*const u8` + len pair.
///
/// # Safety
///
/// `ptr` must point to at least `len` valid bytes (or be null with
/// `len == 0`).
unsafe fn read_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    std::str::from_utf8(slice).ok()
}

// ---------------------------------------------------------------------------
// Handle lifecycle
// ---------------------------------------------------------------------------

/// Construct a fresh [`ReconsiderDosGuard`] with default thresholds
/// and return an opaque handle.
///
/// The caller MUST eventually pass the returned pointer to
/// [`ciris_verify_reconsider_guard_free`] to release the boxed
/// allocation. Reusing the handle after `_free` is undefined behavior.
///
/// Returns null on allocation failure / panic.
#[no_mangle]
pub extern "C" fn ciris_verify_reconsider_guard_new() -> *mut c_void {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = Box::new(ReconsiderDosGuard::new());
        Box::into_raw(guard) as *mut c_void
    }));
    match result {
        Ok(p) => p,
        Err(_) => {
            tracing::error!("PANIC in ciris_verify_reconsider_guard_new");
            std::ptr::null_mut()
        },
    }
}

/// Reclaim and drop a [`ReconsiderDosGuard`] handle previously
/// returned by [`ciris_verify_reconsider_guard_new`].
///
/// No-op if `handle` is null. Calling this twice on the same non-null
/// handle is a double-free and undefined behavior — the Python
/// wrapper guards against this by zeroing its inner pointer after
/// the first call.
///
/// # Safety
///
/// `handle` must be either null or a pointer returned by
/// `ciris_verify_reconsider_guard_new` that has not yet been freed.
#[no_mangle]
pub unsafe extern "C" fn ciris_verify_reconsider_guard_free(handle: *mut c_void) {
    let _ = ffi_guard!("ciris_verify_reconsider_guard_free", {
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut ReconsiderDosGuard));
        }
        CirisVerifyError::Success as i32
    });
}

// ---------------------------------------------------------------------------
// admit_filing
// ---------------------------------------------------------------------------

/// Run [`ReconsiderDosGuard::admit_filing`] against the guard pointed
/// to by `handle`.
///
/// On admission, writes `{"admitted": true}`. On rejection, writes
/// `{"admitted": false, "rejection": <ReconsiderRejection>}` where
/// the inner value is the serde-tagged enum variant (one of
/// `EventRateLimited`, `ActorBudgetExhausted`,
/// `HarassmentClusterDetected`).
///
/// Returns `Success (0)` on a successful FFI call (regardless of
/// whether the filing was admitted or rejected — both decisions are
/// represented in the output JSON). Returns a non-zero status code
/// only on FFI-level failure (null pointer, non-UTF-8 input, OOM,
/// panic).
///
/// # Safety
///
/// All `*const u8` inputs must point to valid memory of at least the
/// declared length. `result_out` and `result_len_out` must be valid
/// pointers. `handle` must be a live (un-freed) pointer returned by
/// [`ciris_verify_reconsider_guard_new`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ciris_verify_reconsider_admit_filing(
    handle: *mut c_void,
    event_id: *const u8,
    event_id_len: usize,
    requester_id: *const u8,
    requester_id_len: usize,
    target_id: *const u8,
    target_id_len: usize,
    now_ms: u64,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_reconsider_admit_filing", {
        admit_filing_inner(
            handle,
            event_id,
            event_id_len,
            requester_id,
            requester_id_len,
            target_id,
            target_id_len,
            now_ms,
            result_out,
            result_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn admit_filing_inner(
    handle: *mut c_void,
    event_id: *const u8,
    event_id_len: usize,
    requester_id: *const u8,
    requester_id_len: usize,
    target_id: *const u8,
    target_id_len: usize,
    now_ms: u64,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if handle.is_null() || result_out.is_null() || result_len_out.is_null() {
        return CirisVerifyError::InvalidArgument as i32;
    }
    let event_id = match read_str(event_id, event_id_len) {
        Some(s) => s,
        None => return CirisVerifyError::InvalidArgument as i32,
    };
    let requester_id = match read_str(requester_id, requester_id_len) {
        Some(s) => s,
        None => return CirisVerifyError::InvalidArgument as i32,
    };
    let target_id = match read_str(target_id, target_id_len) {
        Some(s) => s,
        None => return CirisVerifyError::InvalidArgument as i32,
    };

    let guard = &mut *(handle as *mut ReconsiderDosGuard);

    let decision = guard.admit_filing(event_id, requester_id, target_id, now_ms);
    let json_value = match decision {
        Ok(()) => serde_json::json!({"admitted": true}),
        Err(rej) => {
            // `ReconsiderRejection` is `Serialize` via the externally-
            // tagged default — that's the wire shape the Python side
            // pattern-matches on.
            let rej_value = match serde_json::to_value(&rej) {
                Ok(v) => v,
                Err(_) => return CirisVerifyError::SerializationError as i32,
            };
            serde_json::json!({
                "admitted": false,
                "rejection": rej_value,
            })
        },
    };

    let json = json_value.to_string();
    match write_json_buffer(&json, result_out, result_len_out) {
        Ok(()) => CirisVerifyError::Success as i32,
        Err(e) => e as i32,
    }
}

// ---------------------------------------------------------------------------
// record_outcome
// ---------------------------------------------------------------------------

/// Run [`ReconsiderDosGuard::record_outcome`] against the guard
/// pointed to by `handle`.
///
/// `outcome`:
/// - `0` → [`FilingOutcome::Rejected`] (releases rate-limit slot,
///   does NOT refill the actor budget).
/// - `1` → [`FilingOutcome::Successful`] (releases rate-limit slot
///   AND refills one budget slot for the requester).
///
/// Writes `{}` on success.
///
/// # Safety
///
/// All `*const u8` inputs must point to valid memory of at least the
/// declared length. `result_out` and `result_len_out` must be valid
/// pointers. `handle` must be a live (un-freed) pointer returned by
/// [`ciris_verify_reconsider_guard_new`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ciris_verify_reconsider_record_outcome(
    handle: *mut c_void,
    event_id: *const u8,
    event_id_len: usize,
    requester_id: *const u8,
    requester_id_len: usize,
    outcome: i32,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    ffi_guard!("ciris_verify_reconsider_record_outcome", {
        record_outcome_inner(
            handle,
            event_id,
            event_id_len,
            requester_id,
            requester_id_len,
            outcome,
            result_out,
            result_len_out,
        )
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn record_outcome_inner(
    handle: *mut c_void,
    event_id: *const u8,
    event_id_len: usize,
    requester_id: *const u8,
    requester_id_len: usize,
    outcome: i32,
    result_out: *mut *mut u8,
    result_len_out: *mut usize,
) -> i32 {
    if handle.is_null() || result_out.is_null() || result_len_out.is_null() {
        return CirisVerifyError::InvalidArgument as i32;
    }
    let event_id = match read_str(event_id, event_id_len) {
        Some(s) => s,
        None => return CirisVerifyError::InvalidArgument as i32,
    };
    let requester_id = match read_str(requester_id, requester_id_len) {
        Some(s) => s,
        None => return CirisVerifyError::InvalidArgument as i32,
    };
    let outcome = match outcome {
        0 => FilingOutcome::Rejected,
        1 => FilingOutcome::Successful,
        _ => return CirisVerifyError::InvalidArgument as i32,
    };

    let guard = &mut *(handle as *mut ReconsiderDosGuard);
    guard.record_outcome(event_id, requester_id, outcome);

    match write_json_buffer("{}", result_out, result_len_out) {
        Ok(()) => CirisVerifyError::Success as i32,
        Err(e) => e as i32,
    }
}

// ---------------------------------------------------------------------------
// Suppress dead-code warning on unused imports needed by macros / helpers.
// Touching `ReconsiderRejection` here keeps the cross-module type
// reachable via doc-link without needing it in fn signatures.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn _type_anchor() -> Option<ReconsiderRejection> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const T0: u64 = 1_700_000_000_000;

    /// Helper: call admit_filing and parse the JSON output.
    unsafe fn call_admit(
        handle: *mut c_void,
        event_id: &str,
        requester_id: &str,
        target_id: &str,
        now_ms: u64,
    ) -> (i32, Value) {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_reconsider_admit_filing(
            handle,
            event_id.as_ptr(),
            event_id.len(),
            requester_id.as_ptr(),
            requester_id.len(),
            target_id.as_ptr(),
            target_id.len(),
            now_ms,
            &mut out as *mut *mut u8,
            &mut out_len as *mut usize,
        );
        if rc != 0 {
            return (rc, Value::Null);
        }
        let slice = std::slice::from_raw_parts(out, out_len);
        let json: Value = serde_json::from_slice(slice).expect("output is valid JSON");
        libc::free(out as *mut std::ffi::c_void);
        (rc, json)
    }

    /// Helper: call record_outcome and parse the JSON output.
    unsafe fn call_record_outcome(
        handle: *mut c_void,
        event_id: &str,
        requester_id: &str,
        outcome: i32,
    ) -> (i32, Value) {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = ciris_verify_reconsider_record_outcome(
            handle,
            event_id.as_ptr(),
            event_id.len(),
            requester_id.as_ptr(),
            requester_id.len(),
            outcome,
            &mut out as *mut *mut u8,
            &mut out_len as *mut usize,
        );
        if rc != 0 {
            return (rc, Value::Null);
        }
        let slice = std::slice::from_raw_parts(out, out_len);
        let json: Value = serde_json::from_slice(slice).expect("output is valid JSON");
        libc::free(out as *mut std::ffi::c_void);
        (rc, json)
    }

    #[test]
    fn guard_new_and_free_round_trip() {
        // Allocate + free a few guards to exercise the boxed-handle
        // lifecycle. miri / valgrind would catch a leak or double-free
        // here; the cheap-and-cheerful version is just "doesn't crash".
        for _ in 0..16 {
            let h = ciris_verify_reconsider_guard_new();
            assert!(!h.is_null(), "guard_new returned null");
            unsafe { ciris_verify_reconsider_guard_free(h) };
        }
        // Free on null is a no-op.
        unsafe { ciris_verify_reconsider_guard_free(std::ptr::null_mut()) };
    }

    #[test]
    fn admit_filing_happy_path_returns_admitted_true() {
        let h = ciris_verify_reconsider_guard_new();
        assert!(!h.is_null());
        unsafe {
            let (rc, json) = call_admit(h, "event-1", "alice", "bob", T0);
            assert_eq!(rc, 0);
            assert_eq!(json["admitted"], Value::Bool(true));
            assert!(json.get("rejection").is_none());
            ciris_verify_reconsider_guard_free(h);
        }
    }

    #[test]
    fn admit_filing_rejection_path_carries_typed_enum() {
        let h = ciris_verify_reconsider_guard_new();
        assert!(!h.is_null());
        unsafe {
            // §6.5 cross-event harassment: the same (alice, bob) pair
            // across two distinct events hits the harassment cluster
            // threshold (DEFAULT = 2.0).
            let (rc, _) = call_admit(h, "evt-A", "alice", "bob", T0);
            assert_eq!(rc, 0);
            let (rc, _) = call_admit(h, "evt-B", "alice", "bob", T0 + 1_000);
            assert_eq!(rc, 0);

            // Third try — cluster fires.
            let (rc, json) = call_admit(h, "evt-C", "alice", "bob", T0 + 2_000);
            assert_eq!(rc, 0);
            assert_eq!(json["admitted"], Value::Bool(false));
            let rejection = json.get("rejection").expect("rejection field present");
            // Externally-tagged enum: the variant name is the key.
            assert!(
                rejection.get("HarassmentClusterDetected").is_some(),
                "expected HarassmentClusterDetected variant, got: {rejection:?}"
            );
            let inner = &rejection["HarassmentClusterDetected"];
            assert_eq!(inner["requester_id"], "alice");
            assert_eq!(inner["target_id"], "bob");
            assert_eq!(inner["threshold"], 2.0);

            ciris_verify_reconsider_guard_free(h);
        }
    }

    #[test]
    fn record_outcome_successful_refills_rejected_does_not() {
        // Mirror the core `outcome_success_refills_budget_failure_does_not`
        // test, but driven through the FFI surface.
        use ciris_verify_core::reconsider_dos::DEFAULT_ACTOR_BUDGET;

        let h = ciris_verify_reconsider_guard_new();
        assert!(!h.is_null());
        unsafe {
            // Fill the budget across distinct (event, target) pairs so
            // the harassment cluster + per-event rate-limit don't fire.
            for i in 0..DEFAULT_ACTOR_BUDGET {
                let event = format!("event-{i}");
                let target = format!("target-{i}");
                let (rc, json) = call_admit(h, &event, "actor", &target, T0 + u64::from(i) * 1_000);
                assert_eq!(rc, 0);
                assert_eq!(json["admitted"], Value::Bool(true));
            }

            // At cap — admit fails with ActorBudgetExhausted.
            let (rc, json) = call_admit(h, "event-next", "actor", "target-next", T0 + 10_000_000);
            assert_eq!(rc, 0);
            assert_eq!(json["admitted"], Value::Bool(false));
            assert!(json["rejection"]["ActorBudgetExhausted"].is_object());

            // Rejected outcome — budget NOT refilled, still at cap.
            let (rc, _) = call_record_outcome(h, "event-0", "actor", /* Rejected */ 0);
            assert_eq!(rc, 0);
            let (rc, json) = call_admit(h, "event-next", "actor", "target-next", T0 + 10_001_000);
            assert_eq!(rc, 0);
            assert_eq!(json["admitted"], Value::Bool(false));
            assert!(json["rejection"]["ActorBudgetExhausted"].is_object());

            // Successful outcome — budget refilled, next admit succeeds.
            let (rc, _) = call_record_outcome(h, "event-1", "actor", /* Successful */ 1);
            assert_eq!(rc, 0);
            let (rc, json) =
                call_admit(h, "event-next-2", "actor", "target-next-2", T0 + 10_002_000);
            assert_eq!(rc, 0);
            assert_eq!(json["admitted"], Value::Bool(true));

            ciris_verify_reconsider_guard_free(h);
        }
    }

    #[test]
    fn admit_filing_null_handle_returns_invalid_argument() {
        // Defensive: the Python wrapper is supposed to guard against
        // this, but the FFI must not segfault if it slips through.
        unsafe {
            let mut out: *mut u8 = std::ptr::null_mut();
            let mut out_len: usize = 0;
            let event = b"evt";
            let req = b"alice";
            let tgt = b"bob";
            let rc = ciris_verify_reconsider_admit_filing(
                std::ptr::null_mut(),
                event.as_ptr(),
                event.len(),
                req.as_ptr(),
                req.len(),
                tgt.as_ptr(),
                tgt.len(),
                T0,
                &mut out as *mut *mut u8,
                &mut out_len as *mut usize,
            );
            assert_eq!(rc, CirisVerifyError::InvalidArgument as i32);
            assert!(out.is_null());
        }
    }
}
