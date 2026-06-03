//! Race-to-first-success helper with strict wall-clock budget.
//!
//! Used by [`crate::registry::ResilientRegistryClient`] (v4.8.0+) to
//! convert sequential endpoint failover into parallel racing. The
//! first future to return `Ok` wins; remaining futures are cancelled
//! (cooperative cancellation via drop). If the budget expires before
//! any future returns `Ok`, returns the last seen error.

use std::future::Future;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};

/// Race N futures, return the first `Ok` result, cancel the rest.
///
/// Strict wall-clock cap: the entire race is bounded by `budget` via
/// [`tokio::time::timeout`]. If the budget expires:
/// - and at least one future returned an error → return the last error
/// - and no future returned at all → return the budget-exceeded error
///   built by `budget_exceeded_err` (caller supplies the type-appropriate
///   error variant)
///
/// Semantics:
/// - First `Ok` wins; pending futures are dropped before this function returns.
/// - Errors are tallied; if all futures error and none succeed, returns
///   the LAST seen error (not the first).
/// - Empty future list → calls `empty_err()` and returns.
pub async fn race_first_ok_within_budget<F, T, E>(
    futures: Vec<F>,
    budget: Duration,
    budget_exceeded_err: impl FnOnce(Duration) -> E,
    empty_err: impl FnOnce() -> E,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>> + Send,
    T: Send,
    E: Send,
{
    if futures.is_empty() {
        return Err(empty_err());
    }

    let mut unordered: FuturesUnordered<F> = futures.into_iter().collect();
    let mut last_err: Option<E> = None;

    let race = async {
        while let Some(result) = unordered.next().await {
            match result {
                Ok(value) => return Ok(value),
                Err(e) => last_err = Some(e),
            }
        }
        // All futures completed; none succeeded.
        Err(last_err
            .take()
            .expect("non-empty FuturesUnordered must yield at least one result"))
    };

    match tokio::time::timeout(budget, race).await {
        Ok(inner) => inner,
        Err(_elapsed) => Err(last_err.unwrap_or_else(|| budget_exceeded_err(budget))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::time::sleep;

    #[derive(Debug, Clone, PartialEq)]
    enum TestErr {
        Inner(&'static str),
        BudgetExceeded(Duration),
        Empty,
    }

    type TestFut<T> = std::pin::Pin<Box<dyn Future<Output = Result<T, TestErr>> + Send>>;

    fn budget_exceeded(d: Duration) -> TestErr {
        TestErr::BudgetExceeded(d)
    }

    fn empty() -> TestErr {
        TestErr::Empty
    }

    #[tokio::test]
    async fn race_returns_first_ok_and_cancels_rest() {
        let start = Instant::now();
        let futs: Vec<TestFut<u32>> = vec![
            Box::pin(async {
                sleep(Duration::from_millis(50)).await;
                Ok(42)
            }),
            Box::pin(async {
                sleep(Duration::from_millis(500)).await;
                Ok(99)
            }),
            Box::pin(async {
                sleep(Duration::from_millis(500)).await;
                Ok(99)
            }),
        ];
        let result =
            race_first_ok_within_budget(futs, Duration::from_secs(5), budget_exceeded, empty).await;
        let elapsed = start.elapsed();
        assert_eq!(result, Ok(42));
        assert!(
            elapsed < Duration::from_millis(200),
            "expected cancellation; elapsed={elapsed:?}"
        );
    }

    #[tokio::test]
    async fn race_returns_last_error_when_all_fail() {
        let futs: Vec<TestFut<u32>> = vec![
            Box::pin(async {
                sleep(Duration::from_millis(20)).await;
                Err(TestErr::Inner("first"))
            }),
            Box::pin(async {
                sleep(Duration::from_millis(50)).await;
                Err(TestErr::Inner("second"))
            }),
            Box::pin(async {
                sleep(Duration::from_millis(80)).await;
                Err(TestErr::Inner("third"))
            }),
        ];
        let result =
            race_first_ok_within_budget(futs, Duration::from_secs(5), budget_exceeded, empty).await;
        assert_eq!(result, Err(TestErr::Inner("third")));
    }

    #[tokio::test]
    async fn race_returns_budget_exceeded_when_all_hang() {
        let start = Instant::now();
        let futs: Vec<TestFut<u32>> = vec![
            Box::pin(async {
                std::future::pending::<()>().await;
                Ok(0)
            }),
            Box::pin(async {
                std::future::pending::<()>().await;
                Ok(0)
            }),
            Box::pin(async {
                std::future::pending::<()>().await;
                Ok(0)
            }),
        ];
        let budget = Duration::from_millis(200);
        let result = race_first_ok_within_budget(futs, budget, budget_exceeded, empty).await;
        let elapsed = start.elapsed();
        assert_eq!(result, Err(TestErr::BudgetExceeded(budget)));
        assert!(
            elapsed < Duration::from_millis(300),
            "expected timely budget expiry; elapsed={elapsed:?}"
        );
    }

    #[tokio::test]
    async fn race_empty_input_returns_empty_err() {
        let futs: Vec<TestFut<u32>> = vec![];
        let result =
            race_first_ok_within_budget(futs, Duration::from_secs(1), budget_exceeded, empty).await;
        assert_eq!(result, Err(TestErr::Empty));
    }

    #[tokio::test]
    async fn race_single_future_succeeds_normally() {
        let futs: Vec<TestFut<u32>> = vec![Box::pin(async {
            sleep(Duration::from_millis(10)).await;
            Ok(7)
        })];
        let result =
            race_first_ok_within_budget(futs, Duration::from_secs(1), budget_exceeded, empty).await;
        assert_eq!(result, Ok(7));
    }

    #[tokio::test]
    async fn race_mixed_error_then_success_returns_success() {
        let futs: Vec<TestFut<u32>> = vec![
            Box::pin(async {
                sleep(Duration::from_millis(30)).await;
                Err(TestErr::Inner("early-fail"))
            }),
            Box::pin(async {
                sleep(Duration::from_millis(80)).await;
                Ok(123)
            }),
        ];
        let result =
            race_first_ok_within_budget(futs, Duration::from_secs(1), budget_exceeded, empty).await;
        assert_eq!(result, Ok(123));
    }
}
