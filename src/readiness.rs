//! Cached dependency readiness, independent of process liveness and requests.
//!
//! A single background task checks the core runtime. HTTP probes only inspect
//! its last bounded result: they never acquire a database connection or trigger
//! work. Optional services such as embedding and OIDC discovery are not gates.

use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::telemetry::{self, Outcome};

const CHECK_INTERVAL: Duration = Duration::from_secs(5);
const CHECK_DEADLINE: Duration = Duration::from_secs(3);
const MAX_AGE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
struct Observation {
    ready: bool,
    at: Instant,
    timestamp: f64,
}

#[derive(Debug, Default)]
struct State {
    observation: Option<Observation>,
    stopped: bool,
}

/// An empty, failed, poisoned, or stale observation is never ready.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<RwLock<State>>);

impl Readiness {
    /// Start one sequential, deadline-bounded probe on the current Tokio runtime.
    /// Keep the returned task guard alive for the HTTP server's lifetime.
    pub fn start<F, Fut>(check: F) -> (Self, ReadinessTask)
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = bool> + Send,
    {
        let readiness = Self::default();
        let state = readiness.clone();
        let task = tokio::spawn(async move { state.run(check).await });
        let guard = ReadinessTask {
            task,
            readiness: readiness.clone(),
        };
        (readiness, guard)
    }

    pub fn is_ready(&self) -> bool {
        self.snapshot().0
    }

    /// Content-free values used by the private metrics exporter. Freshness is
    /// evaluated at scrape time, so a stalled checker cannot leave a green gauge.
    pub(crate) fn snapshot(&self) -> (bool, f64) {
        self.0.read().ok().map_or((false, 0.0), |state| {
            state.observation.map_or((false, 0.0), |observation| {
                (
                    !state.stopped && observation.ready && observation.at.elapsed() < MAX_AGE,
                    observation.timestamp,
                )
            })
        })
    }

    fn observe(&self, ready: bool) {
        if let Ok(mut state) = self.0.write()
            && !state.stopped
        {
            state.observation = Some(Observation {
                ready,
                at: Instant::now(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            });
        }
    }

    async fn run<F, Fut>(&self, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let mut interval = tokio::time::interval(CHECK_INTERVAL);
        // A slow or paused runtime must not run a backlog of dependency probes.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let operation = telemetry::start("runtime", "readiness");
            let result = tokio::time::timeout(CHECK_DEADLINE, check()).await;
            self.observe(matches!(result, Ok(true)));
            operation.finish(match result {
                Ok(true) => Outcome::Success,
                Ok(false) => Outcome::Error,
                Err(_) => Outcome::Timeout,
            });
        }
    }
}

/// Dropping the server's guard stops the checker and immediately removes readiness.
pub struct ReadinessTask {
    task: JoinHandle<()>,
    readiness: Readiness,
}

impl Drop for ReadinessTask {
    fn drop(&mut self) {
        // Mark stopped under the same lock as observation publication. A probe
        // racing this drop cannot restore readiness after shutdown.
        if let Ok(mut state) = self.readiness.0.write() {
            state.stopped = true;
        }
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    #[allow(clippy::float_cmp)] // An uninitialized timestamp is exactly the zero sentinel.
    async fn startup_failure_recovery_staleness_and_shutdown_fail_closed() {
        let readiness = Readiness::default();
        assert!(!readiness.is_ready());
        assert_eq!(readiness.snapshot().1, 0.0);
        readiness.observe(true);
        assert!(readiness.is_ready());
        tokio::time::advance(MAX_AGE).await;
        assert!(!readiness.is_ready());
        readiness.observe(false);
        assert!(!readiness.is_ready());

        let available = Arc::new(AtomicBool::new(false));
        let state = available.clone();
        let (readiness, task) = Readiness::start(move || {
            let ready = state.load(Ordering::SeqCst);
            async move { ready }
        });
        assert!(!readiness.is_ready());
        tokio::task::yield_now().await;
        assert!(!readiness.is_ready());
        assert!(readiness.snapshot().1 > 0.0);
        available.store(true, Ordering::SeqCst);
        tokio::time::advance(CHECK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(readiness.is_ready());
        available.store(false, Ordering::SeqCst);
        tokio::time::advance(CHECK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(!readiness.is_ready());
        available.store(true, Ordering::SeqCst);
        tokio::time::advance(CHECK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(readiness.is_ready());
        drop(task);
        assert!(!readiness.is_ready());
        readiness.observe(true);
        assert!(
            !readiness.is_ready(),
            "a completion racing shutdown cannot reopen readiness"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_cancels_probe_without_overlap_or_request_fanout() {
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let check_calls = calls.clone();
        let check_active = active.clone();
        let (readiness, _task) = Readiness::start(move || {
            check_calls.fetch_add(1, Ordering::SeqCst);
            let active = check_active.clone();
            async move {
                assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                let _active = Active(active);
                std::future::pending::<bool>().await
            }
        });
        tokio::task::yield_now().await;
        assert_eq!(active.load(Ordering::SeqCst), 1);
        for _ in 0..100 {
            assert!(!readiness.is_ready());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(CHECK_DEADLINE).await;
        tokio::task::yield_now().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(!readiness.is_ready());
        tokio::time::advance(CHECK_INTERVAL.checked_sub(CHECK_DEADLINE).unwrap()).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn metrics_recompute_staleness_without_http_probe() {
        let readiness = Readiness::default();
        let metrics = crate::telemetry::Telemetry::new();
        metrics.set_readiness(readiness.clone());
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("\nfleet_recall_ready 0\n")
        );
        readiness.observe(true);
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("\nfleet_recall_ready 1\n")
        );
        tokio::time::advance(MAX_AGE).await;
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("\nfleet_recall_ready 0\n")
        );
    }
}
