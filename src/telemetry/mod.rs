//! Operational measurements, separate from the governed evidence ledger.
//!
//! Labels are compile-time categories only. Never pass content, credentials,
//! scope, source identifiers, URLs, or error messages to this module. Metrics
//! are process-local; JSON events go through tracing to stderr, never MCP stdout.

use std::sync::{LazyLock, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder,
};

pub mod http;
pub mod runtime;

static TELEMETRY: LazyLock<Telemetry> = LazyLock::new(Telemetry::new);

#[cfg(test)]
pub(crate) fn prepare_test_capture() {
    // tracing-core 0.1.36's Rebuilder::JustOne consults the registering
    // thread's default subscriber. Ordinary parallel tests have none and can
    // otherwise cache a shared operation callsite as disabled for the capture
    // test. Retaining this silent registrar makes each scoped capture a second
    // subscriber, so registration consults every subscriber on every thread.
    // It is never installed as a default and emits no output.
    static BASELINE: LazyLock<tracing::Dispatch> =
        LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::registry()));
    LazyLock::force(&BASELINE);
}

/// Terminal operational outcome. `Cancelled` does not assert that a write was
/// rolled back: a disconnected or timed-out caller can have an unknown outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Success,
    Error,
    Refused,
    Invalid,
    Timeout,
    Cancelled,
    Skipped,
    Degraded,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Refused => "refused",
            Self::Invalid => "invalid",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
            Self::Degraded => "degraded",
        }
    }
}

/// A registry can be constructed independently for isolated tests. Production
/// adapters share the process registry through [`start`] and [`render`].
pub struct Telemetry {
    registry: Registry,
    operations: IntCounterVec,
    duration: HistogramVec,
    in_flight: IntGaugeVec,
    units: IntCounterVec,
    readiness: RwLock<crate::readiness::Readiness>,
    started: Instant,
    start_timestamp: f64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    pub fn new() -> Self {
        let registry = Registry::new();
        let operations = IntCounterVec::new(
            Opts::new(
                "fleet_recall_operations_total",
                "Completed operations, including cancellations.",
            ),
            &["component", "operation", "outcome"],
        )
        .expect("fixed metric definition");
        let duration = HistogramVec::new(
            HistogramOpts::new(
                "fleet_recall_operation_duration_seconds",
                "Operation wall time, including failures and cancellations.",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
                300.0,
            ]),
            &["component", "operation"],
        )
        .expect("fixed metric definition");
        let in_flight = IntGaugeVec::new(
            Opts::new(
                "fleet_recall_operations_in_flight",
                "Currently executing operations.",
            ),
            &["component", "operation"],
        )
        .expect("fixed metric definition");
        let units = IntCounterVec::new(
            Opts::new(
                "fleet_recall_units_total",
                "Work units processed; the unit label identifies the counter.",
            ),
            &["component", "operation", "unit"],
        )
        .expect("fixed metric definition");
        registry
            .register(Box::new(operations.clone()))
            .expect("unique metric");
        registry
            .register(Box::new(duration.clone()))
            .expect("unique metric");
        registry
            .register(Box::new(in_flight.clone()))
            .expect("unique metric");
        registry
            .register(Box::new(units.clone()))
            .expect("unique metric");
        Self {
            registry,
            operations,
            duration,
            in_flight,
            units,
            readiness: RwLock::new(crate::readiness::Readiness::default()),
            started: Instant::now(),
            start_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        }
    }

    /// Both labels must be drawn from finite, code-owned sets.
    pub fn start(&self, component: &'static str, operation: &'static str) -> OperationGuard {
        // Publish zero baselines as soon as an operation is seen, so a later
        // first failure is visible to rate/increase queries between scrapes.
        for outcome in [
            Outcome::Success,
            Outcome::Error,
            Outcome::Refused,
            Outcome::Invalid,
            Outcome::Timeout,
            Outcome::Cancelled,
            Outcome::Skipped,
            Outcome::Degraded,
        ] {
            self.operations
                .with_label_values(&[component, operation, outcome.as_str()]);
        }
        let in_flight = self.in_flight.with_label_values(&[component, operation]);
        in_flight.inc();
        let operation_id = uuid::Uuid::now_v7().to_string();
        let span = tracing::info_span!("operation", operation_id, component, operation);
        OperationGuard {
            component,
            operation,
            started: Instant::now(),
            operations: self.operations.clone(),
            duration: self.duration.with_label_values(&[component, operation]),
            in_flight,
            span,
            finished: false,
        }
    }

    pub fn render(&self) -> prometheus::Result<String> {
        use std::fmt::Write as _;
        let mut output = TextEncoder::new().encode_to_string(&self.registry.gather())?;
        // These are fixed names and numeric/build-time values, never user data.
        let _ = write!(
            output,
            "# HELP fleet_recall_build_info Build information.\n# TYPE fleet_recall_build_info gauge\nfleet_recall_build_info{{version=\"{}\"}} 1\n# HELP fleet_recall_process_start_time_seconds Process telemetry start time.\n# TYPE fleet_recall_process_start_time_seconds gauge\nfleet_recall_process_start_time_seconds {}\n# HELP fleet_recall_process_uptime_seconds Process telemetry uptime.\n# TYPE fleet_recall_process_uptime_seconds gauge\nfleet_recall_process_uptime_seconds {}\n",
            env!("CARGO_PKG_VERSION"),
            self.start_timestamp,
            self.started.elapsed().as_secs_f64()
        );
        let (ready, checked_at) = self
            .readiness
            .read()
            .map_or((false, 0.0), |readiness| readiness.snapshot());
        let _ = write!(
            output,
            "# HELP fleet_recall_ready Fresh successful core runtime readiness check.\n# TYPE fleet_recall_ready gauge\nfleet_recall_ready {}\n# HELP fleet_recall_readiness_last_check_timestamp_seconds Last completed core runtime readiness check, including failures.\n# TYPE fleet_recall_readiness_last_check_timestamp_seconds gauge\nfleet_recall_readiness_last_check_timestamp_seconds {checked_at}\n",
            u8::from(ready),
        );
        Ok(output)
    }

    pub(crate) fn set_readiness(&self, readiness: crate::readiness::Readiness) {
        if let Ok(mut state) = self.readiness.write() {
            *state = readiness;
        }
    }
}

/// Bind the HTTP runtime's cached readiness to the private scrape listener.
/// Scrapes recompute freshness even when the background task is stalled.
pub fn set_readiness(readiness: crate::readiness::Readiness) {
    TELEMETRY.set_readiness(readiness);
}

/// Begin an operation with finite, code-owned labels.
pub fn start(component: &'static str, operation: &'static str) -> OperationGuard {
    TELEMETRY.start(component, operation)
}

/// Add a numeric work counter. Every label, including `unit`, must be selected
/// from a finite compile-time vocabulary, never from a provider payload.
pub fn add_units(
    component: &'static str,
    operation: &'static str,
    unit: &'static str,
    amount: u64,
) {
    TELEMETRY
        .units
        .with_label_values(&[component, operation, unit])
        .inc_by(amount);
}

pub fn render() -> prometheus::Result<String> {
    TELEMETRY.render()
}

/// Owns the in-flight gauge and records exactly one terminal observation.
#[must_use]
pub struct OperationGuard {
    component: &'static str,
    operation: &'static str,
    started: Instant,
    operations: IntCounterVec,
    duration: prometheus::Histogram,
    in_flight: prometheus::IntGauge,
    span: tracing::Span,
    finished: bool,
}

impl OperationGuard {
    /// Instrument the future with this span to correlate nested operations.
    pub fn span(&self) -> tracing::Span {
        self.span.clone()
    }

    pub fn finish(mut self, outcome: Outcome) {
        self.record(outcome);
    }

    fn record(&mut self, outcome: Outcome) {
        let elapsed = self.started.elapsed().as_secs_f64();
        self.operations
            .with_label_values(&[self.component, self.operation, outcome.as_str()])
            .inc();
        self.duration.observe(elapsed);
        self.in_flight.dec();
        self.finished = true;
        tracing::info!(parent: &self.span, event = "operation.completed", event_version = 1_u64, component = self.component, operation = self.operation, outcome = outcome.as_str(), duration_seconds = elapsed, "operation completed");
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.record(if std::thread::panicking() {
                Outcome::Error
            } else {
                Outcome::Cancelled
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_and_cancelled_operations_balance_gauges_and_histograms() {
        let metrics = Telemetry::new();
        let first = metrics.start("test", "read");
        let second = metrics.start("test", "read");
        assert_eq!(
            metrics.in_flight.with_label_values(&["test", "read"]).get(),
            2
        );
        first.finish(Outcome::Success);
        drop(second);
        assert_eq!(
            metrics.in_flight.with_label_values(&["test", "read"]).get(),
            0
        );
        assert_eq!(
            metrics
                .operations
                .with_label_values(&["test", "read", "success"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .operations
                .with_label_values(&["test", "read", "cancelled"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .duration
                .with_label_values(&["test", "read"])
                .get_sample_count(),
            2
        );
        let text = metrics.render().unwrap();
        assert!(text.contains("fleet_recall_operation_duration_seconds_bucket"));
        assert!(text.contains("le=\"+Inf\""));
        assert!(text.contains("fleet_recall_build_info"));
    }

    #[tokio::test]
    async fn dropping_an_instrumented_future_releases_capacity() {
        let metrics = Telemetry::new();
        let guard = metrics.start("test", "pending");
        let result = tokio::time::timeout(std::time::Duration::from_millis(1), async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            metrics
                .in_flight
                .with_label_values(&["test", "pending"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .operations
                .with_label_values(&["test", "pending", "cancelled"])
                .get(),
            1
        );
    }
}
