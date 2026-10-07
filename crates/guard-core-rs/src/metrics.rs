//! The reference metrics surface: the exact `METRIC_*` names, the
//! `SecurityMetric` telemetry record, and the [`MetricsCollector`] that
//! mirrors `guard_core/core/events/metrics.py`.
//!
//! The seven metric types are the guard-agent wire model's
//! `METRIC_TYPES` (`request_count`, `response_time`, `error_rate`,
//! `bandwidth_usage`, `threat_level`, `block_rate`, `cache_hit_rate`).
//! The collector stands in for the Python `agent_handler.send_metric`
//! transport the same way [`crate::events::SecurityEventBus`] stands in
//! for `send_event`: handlers registered with
//! [`MetricsCollector::with_handler`] receive every allowed metric and
//! own the transport. Handler failures cannot break the pipeline: a
//! panicking handler is caught and dropped, mirroring the reference's
//! `except Exception` guard around `send_metric`.
//!
//! Where the reference emits: `MetricsCollector.collect_request_metrics`
//! runs in the response factory (`core/responses/factory.py`, between the
//! behavioral rules and the security headers), tagging the redacted
//! endpoint and method. The same emission is wired into
//! [`crate::process_response::ResponseProcessor`] via
//! [`crate::process_response::ResponseProcessor::with_metrics`].
//!
//! # Example
//!
//! ```
//! use std::collections::BTreeMap;
//! use std::sync::{Arc, Mutex};
//!
//! use guard_core_rs::metrics::{
//!     MetricsCollector, METRIC_ERROR_RATE, METRIC_REQUEST_COUNT, METRIC_RESPONSE_TIME,
//! };
//!
//! let seen: Arc<Mutex<Vec<(String, f64)>>> = Arc::new(Mutex::new(Vec::new()));
//! let sink = seen.clone();
//! let collector = MetricsCollector::new(true)
//!     .with_handler(Arc::new(move |metric: &guard_core_rs::metrics::SecurityMetric| {
//!         sink.lock().expect("sink").push((metric.metric_type.clone(), metric.value));
//!     }));
//!
//! let mut tags = BTreeMap::new();
//! tags.insert("endpoint".to_owned(), "/api".to_owned());
//! tags.insert("method".to_owned(), "GET".to_owned());
//! collector.send_metric(METRIC_REQUEST_COUNT, 1.0, tags);
//!
//! collector.collect_request_metrics("/api", "GET", Some(0.5), 404);
//!
//! let seen = seen.lock().expect("sink");
//! // The explicit send_metric lands first, then collect_request_metrics
//! // emits response_time (when present), request_count, and error_rate
//! // (status >= 400).
//! assert_eq!(seen[0], (METRIC_REQUEST_COUNT.to_owned(), 1.0));
//! assert_eq!(seen[1], (METRIC_RESPONSE_TIME.to_owned(), 0.5));
//! assert_eq!(seen[2], (METRIC_REQUEST_COUNT.to_owned(), 1.0));
//! assert_eq!(seen[3], (METRIC_ERROR_RATE.to_owned(), 1.0));
//! ```

use std::collections::{BTreeMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::SystemTime;

/// `METRIC_RESPONSE_TIME` (latency samples, seconds).
pub const METRIC_RESPONSE_TIME: &str = "response_time";
/// `METRIC_REQUEST_COUNT` (requests observed).
pub const METRIC_REQUEST_COUNT: &str = "request_count";
/// `METRIC_ERROR_RATE` (one sample per `>= 400` response).
pub const METRIC_ERROR_RATE: &str = "error_rate";
/// `METRIC_BANDWIDTH_USAGE` (bytes transferred).
pub const METRIC_BANDWIDTH_USAGE: &str = "bandwidth_usage";
/// `METRIC_THREAT_LEVEL` (aggregate threat score).
pub const METRIC_THREAT_LEVEL: &str = "threat_level";
/// `METRIC_BLOCK_RATE` (ratio of blocked requests).
pub const METRIC_BLOCK_RATE: &str = "block_rate";
/// `METRIC_CACHE_HIT_RATE` (ratio of cache hits).
pub const METRIC_CACHE_HIT_RATE: &str = "cache_hit_rate";

/// Every wire-legal metric type (the agent model's `METRIC_TYPES`).
pub const METRIC_TYPE_VALUES: [&str; 7] = [
    METRIC_RESPONSE_TIME,
    METRIC_REQUEST_COUNT,
    METRIC_ERROR_RATE,
    METRIC_BANDWIDTH_USAGE,
    METRIC_THREAT_LEVEL,
    METRIC_BLOCK_RATE,
    METRIC_CACHE_HIT_RATE,
];

/// A registered metric sink (`agent_handler.send_metric`'s Rust stand-in).
pub type MetricHandler = Arc<dyn Fn(&SecurityMetric) + Send + Sync>;

/// One security metric: the reference `SecurityMetric` telemetry record,
/// field for field (the guard-agent wire model).
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityMetric {
    /// When the metric fired (`datetime.now(timezone.utc)`).
    pub timestamp: SystemTime,
    /// The `METRIC_*` value (e.g. `request_count`).
    pub metric_type: String,
    /// The sampled value.
    pub value: f64,
    /// The redacted endpoint when the emitter carries one.
    pub endpoint: Option<String>,
    /// The per-site tags (`endpoint`, `method`, `status`).
    pub tags: BTreeMap<String, String>,
}

/// The metric filter (the reference `EventFilter`'s metric half):
/// `muted_metric_types` never reach the handler.
#[derive(Debug, Clone, Default)]
pub struct MetricFilter {
    muted_metric_types: HashSet<String>,
}

impl MetricFilter {
    /// A filter muting exactly `muted_metric_types`.
    #[must_use]
    pub fn new<I>(muted_metric_types: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        Self {
            muted_metric_types: muted_metric_types.into_iter().map(Into::into).collect(),
        }
    }

    /// The reference `EventFilter.is_metric_allowed`.
    #[must_use]
    pub fn is_metric_allowed(&self, metric_type: &str) -> bool {
        !self.muted_metric_types.contains(metric_type)
    }
}

/// The reference `MetricsCollector`: gates on the agent handler and the
/// `agent_enable_metrics` flag, filters muted metric types, then hands the
/// [`SecurityMetric`] to the transport.
#[derive(Clone)]
pub struct MetricsCollector {
    handler: Option<MetricHandler>,
    enabled: bool,
    filter: MetricFilter,
}

impl MetricsCollector {
    /// Build a collector; `enabled` is the reference
    /// `config.agent_enable_metrics`. Without a handler nothing is ever
    /// sent, exactly like the reference's `if not self.agent_handler`
    /// guard.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            handler: None,
            enabled,
            filter: MetricFilter {
                muted_metric_types: HashSet::new(),
            },
        }
    }

    /// Register the transport.
    #[must_use]
    pub fn with_handler(mut self, handler: MetricHandler) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Replace the filter.
    #[must_use]
    pub fn with_filter(mut self, filter: MetricFilter) -> Self {
        self.filter = filter;
        self
    }

    /// The reference `send_metric`: one gated emission.
    pub fn send_metric(&self, metric_type: &str, value: f64, tags: BTreeMap<String, String>) {
        let Some(handler) = &self.handler else {
            return;
        };
        if !self.enabled {
            return;
        }
        if !self.filter.is_metric_allowed(metric_type) {
            return;
        }
        let metric = SecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: metric_type.to_owned(),
            value,
            endpoint: None,
            tags,
        };
        // A panicking transport cannot break the pipeline (the
        // reference's `except Exception` guard).
        let _ = catch_unwind(AssertUnwindSafe(|| handler(&metric)));
    }

    /// The reference `collect_request_metrics`: the response-time sample
    /// (when the caller measured one), the request count, and one error
    /// sample per `>= 400` status, each tagged with the redacted endpoint,
    /// the method, and (where the reference tags it) the status.
    pub fn collect_request_metrics(
        &self,
        endpoint: &str,
        method: &str,
        response_time: Option<f64>,
        status_code: u16,
    ) {
        if self.handler.is_none() || !self.enabled {
            return;
        }
        let mut base_tags = BTreeMap::new();
        base_tags.insert("endpoint".to_owned(), endpoint.to_owned());
        base_tags.insert("method".to_owned(), method.to_owned());
        if let Some(seconds) = response_time {
            let mut tags = base_tags.clone();
            tags.insert("status".to_owned(), status_code.to_string());
            self.send_metric(METRIC_RESPONSE_TIME, seconds, tags);
        }
        self.send_metric(METRIC_REQUEST_COUNT, 1.0, base_tags.clone());
        if status_code >= 400 {
            let mut tags = base_tags;
            tags.insert("status".to_owned(), status_code.to_string());
            self.send_metric(METRIC_ERROR_RATE, 1.0, tags);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        METRIC_BANDWIDTH_USAGE, METRIC_BLOCK_RATE, METRIC_CACHE_HIT_RATE, METRIC_ERROR_RATE,
        METRIC_REQUEST_COUNT, METRIC_RESPONSE_TIME, METRIC_THREAT_LEVEL, METRIC_TYPE_VALUES,
        MetricFilter, MetricsCollector, SecurityMetric,
    };
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<SecurityMetric>>>;

    fn recording_collector(enabled: bool) -> (MetricsCollector, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let collector = MetricsCollector::new(enabled).with_handler(Arc::new(
            move |metric: &SecurityMetric| {
                sink.lock().expect("sink").push(metric.clone());
            },
        ));
        (collector, seen)
    }

    #[test]
    fn the_seven_wire_metric_types_are_locked() {
        assert_eq!(
            METRIC_TYPE_VALUES,
            [
                METRIC_RESPONSE_TIME,
                METRIC_REQUEST_COUNT,
                METRIC_ERROR_RATE,
                METRIC_BANDWIDTH_USAGE,
                METRIC_THREAT_LEVEL,
                METRIC_BLOCK_RATE,
                METRIC_CACHE_HIT_RATE,
            ]
        );
        assert_eq!(
            METRIC_TYPE_VALUES,
            [
                "response_time",
                "request_count",
                "error_rate",
                "bandwidth_usage",
                "threat_level",
                "block_rate",
                "cache_hit_rate"
            ]
        );
    }

    #[test]
    fn a_disabled_collector_never_sends() {
        let (collector, seen) = recording_collector(false);
        collector.send_metric(METRIC_REQUEST_COUNT, 1.0, BTreeMap::new());
        assert!(seen.lock().expect("sink").is_empty());
    }

    #[test]
    fn a_disabled_collector_never_collects_request_metrics() {
        let (collector, seen) = recording_collector(false);
        collector.collect_request_metrics("/api", "GET", Some(0.5), 500);
        assert!(seen.lock().expect("sink").is_empty());
    }

    #[test]
    fn a_handlerless_collector_never_sends() {
        let collector = MetricsCollector::new(true);
        // No panic, no send (there is nowhere to send).
        collector.send_metric(METRIC_REQUEST_COUNT, 1.0, BTreeMap::new());
    }

    #[test]
    fn a_handlerless_collector_never_collects_request_metrics() {
        let collector = MetricsCollector::new(true);
        // No panic, no send (there is nowhere to send).
        collector.collect_request_metrics("/api", "GET", Some(0.5), 500);
    }

    #[test]
    fn a_panicking_transport_cannot_break_the_caller() {
        let collector = MetricsCollector::new(true).with_handler(Arc::new(|_: &SecurityMetric| {
            panic!("transport exploded");
        }));
        collector.send_metric(METRIC_REQUEST_COUNT, 1.0, BTreeMap::new());
    }

    #[test]
    fn a_panicking_transport_cannot_break_collect_request_metrics() {
        let collector = MetricsCollector::new(true).with_handler(Arc::new(|_: &SecurityMetric| {
            panic!("transport exploded");
        }));
        collector.collect_request_metrics("/api", "GET", Some(0.5), 500);
    }

    #[test]
    fn muted_metric_types_never_reach_the_handler() {
        let (collector, seen) = recording_collector(true);
        let collector = collector.with_filter(MetricFilter::new([METRIC_REQUEST_COUNT]));
        collector.send_metric(METRIC_REQUEST_COUNT, 1.0, BTreeMap::new());
        collector.send_metric(METRIC_ERROR_RATE, 1.0, BTreeMap::new());
        let seen = seen.lock().expect("sink").clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].metric_type, METRIC_ERROR_RATE);
    }

    #[test]
    fn request_metrics_carry_the_reference_tags_and_counts() {
        let (collector, seen) = recording_collector(true);
        collector.collect_request_metrics("/api", "GET", Some(0.5), 200);
        let collected = seen.lock().expect("sink").clone();
        let seen = &collected;
        assert_eq!(seen.len(), 2, "response_time + request_count, no error");
        assert_eq!(seen[0].metric_type, METRIC_RESPONSE_TIME);
        assert!((seen[0].value - 0.5).abs() < f64::EPSILON);
        assert_eq!(seen[0].tags.get("status").map(String::as_str), Some("200"));
        assert_eq!(seen[1].metric_type, METRIC_REQUEST_COUNT);
        assert!((seen[1].value - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            seen[1].tags.get("endpoint").map(String::as_str),
            Some("/api")
        );
        assert_eq!(seen[1].tags.get("method").map(String::as_str), Some("GET"));
        assert!(!seen[1].tags.contains_key("status"));
    }

    #[test]
    fn an_error_status_adds_the_error_rate_sample() {
        let (collector, seen) = recording_collector(true);
        collector.collect_request_metrics("/api", "GET", Some(0.5), 404);
        let seen = seen.lock().expect("sink").clone();
        assert_eq!(seen.len(), 3, "response_time + request_count + error_rate");
        assert_eq!(seen[2].metric_type, METRIC_ERROR_RATE);
        assert_eq!(seen[2].tags.get("status").map(String::as_str), Some("404"));
    }

    #[test]
    fn an_unmeasured_response_skips_the_response_time_sample() {
        let (collector, seen) = recording_collector(true);
        collector.collect_request_metrics("/api", "GET", None, 200);
        let seen = seen.lock().expect("sink").clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].metric_type, METRIC_REQUEST_COUNT);
    }
}
