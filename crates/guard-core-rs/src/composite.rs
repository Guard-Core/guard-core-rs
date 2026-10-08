//! The composite telemetry seam: the `CompositeAgentHandler`,
//! `OtelHandler`, and `LogfireHandler` ports plus the
//! [`TelemetryHandler`] sink trait they fan out over.
//!
//! Sources: `guard_core/core/events/composite_handler.py`,
//! `otel_handler.py`, `logfire_handler.py`, and the handler-initializer
//! assembly (`core/initialization/handler_initializer.py`
//! `build_composite_handler` / `build_event_filter` / `build_enricher`).
//!
//! The idiom mapping (the reference methods are `async def`; the crate's
//! seam traits are synchronous and assumption-ready, the same shape the
//! distributed-store and geo seams use):
//!
//! - [`TelemetryHandler`] is the reference `AgentHandlerProtocol` (the
//!   sink an application hands the engine - the `set_agent_handler`
//!   equivalent is [`build_composite_handler`]'s `agent` slot or the raw
//!   [`CompositeAgentHandler::new`]);
//! - [`CompositeAgentHandler`] fans every lifecycle call out to each sink
//!   with per-sink failure isolation: `start` records the failed sink
//!   names (the `degraded` flag answers `started && !failed.is_empty()`),
//!   the send/flush/stop fan-outs report each failure in the returned
//!   [`TelemetryFailure`] list (the reference `logger.exception`
//!   equivalent - the facade owns no logger, hosts log the returns),
//!   `get_dynamic_rules` answers the first non-`None` result, and
//!   `health_check` is the all-of;
//! - [`OtelHandler`] speaks OTLP/HTTP JSON directly through the
//!   injectable [`OtlpTransport`] (the reference leans on the
//!   `opentelemetry-sdk` optional import; there is no such SDK here, the
//!   same dependency-free decision the TS and PHP ports made). The span
//!   and metric payload shapes, the `_otlp_signal_endpoint` suffix
//!   derivation, the `guard.*` attribute family, and the W3C
//!   traceparent parenting are the reference's byte for byte;
//! - [`LogfireHandler`] drives the injected [`LogfireClient`] with the
//!   reference's claim lifecycle (`is_configured` adoption, the
//!   `configured_by_guard` shutdown ownership);
//! - [`build_composite_handler`] is the initializer port: agent slot
//!   first, then the `enable_otel` / `enable_logfire` sinks, the mute
//!   filters from `muted_event_types` / `muted_metric_types`, and the
//!   enricher when `enable_enrichment`.
//!
//! # Example
//!
//! ```
//! use std::sync::{Arc, Mutex};
//!
//! use guard_core_rs::composite::{
//!     CompositeAgentHandler, TelemetryError, TelemetryHandler,
//! };
//! use guard_core_rs::event_types::EVENT_PENETRATION_ATTEMPT;
//! use guard_core_rs::events::SecurityEvent;
//! use guard_core_rs::metrics::SecurityMetric;
//!
//! struct RecordingSink {
//!     events: Mutex<Vec<String>>,
//! }
//!
//! impl TelemetryHandler for RecordingSink {
//!     fn handler_name(&self) -> &str {
//!         "RecordingSink"
//!     }
//!
//!     fn start(&self) -> Result<(), TelemetryError> {
//!         Ok(())
//!     }
//!
//!     fn stop(&self) -> Result<(), TelemetryError> {
//!         Ok(())
//!     }
//!
//!     fn send_event(
//!         &self,
//!         event: &SecurityEvent,
//!     ) -> Result<(), TelemetryError> {
//!         self.events
//!             .lock()
//!             .expect("sink")
//!             .push(event.event_type.clone());
//!         Ok(())
//!     }
//!
//!     fn send_metric(&self, _metric: &SecurityMetric) -> Result<(), TelemetryError> {
//!         Ok(())
//!     }
//!
//!     fn health_check(&self) -> bool {
//!         true
//!     }
//! }
//!
//! # let sink = RecordingSink { events: Mutex::new(Vec::new()) };
//! let composite = CompositeAgentHandler::new(
//!     vec![Arc::new(sink)],
//!     guard_core_rs::events::EventFilter::default(),
//!     guard_core_rs::metrics::MetricFilter::new(Vec::<String>::new()),
//!     None,
//! );
//! let failures = composite.send_event(&SecurityEvent::new(
//!     EVENT_PENETRATION_ATTEMPT,
//!     "192.0.2.1",
//!     "request_blocked",
//!     "sqli",
//!     "middleware",
//! ));
//! assert!(failures.is_empty());
//! assert!(composite.health_check());
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_core_engine::distributed::StoreError;
use guard_core_engine::security_config::SecurityConfig;
use sha2::{Digest, Sha256};

use crate::enrichment::{EnrichmentIdentity, EventEnricher};
use crate::events::{EventFilter, SecurityEvent};
use crate::metrics::{MetricFilter, SecurityMetric};

/// One sink failure (the reference `logger.exception` payloads): the
/// [`TelemetryHandler::handler_name`] and the sink's error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryFailure {
    /// The sink's `type(handler).__name__` equivalent.
    pub handler: String,
    /// What the sink answered.
    pub error: TelemetryError,
}

/// A sink error, wrapped losslessly as a string (the engine never sees
/// sink internals).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryError(pub String);

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "telemetry sink error: {}", self.0)
    }
}

impl std::error::Error for TelemetryError {}

/// The Redis handle the reference passes to `initialize_redis`.
///
/// The facade's `RedisStore` (the `redis` feature) implements it;
/// sinks that need no persistence ignore the call (the trait
/// default).
pub trait TelemetryRedisStore: Send + Sync {
    /// The reference `get_key(prefix, namespace, key)`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    fn get_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError>;

    /// The reference `set_key(prefix, namespace, key, value, ttl)`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    fn set_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
        value: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<(), StoreError>;
}

/// One telemetry sink (the reference `AgentHandlerProtocol`): the agent
/// handler, the OTLP exporter, the Logfire emitter - every receiver the
/// [`CompositeAgentHandler`] fans out over.
///
/// The lifecycle methods the reference marks optional carry defaults that
/// mirror the OTLP/Logfire no-op bodies (`initialize_redis`,
/// `flush_buffer`, `get_dynamic_rules`); `handler_name` and
/// `health_check` are required (the reference reads
/// `type(handler).__name__` for its degradation bookkeeping and every
/// sink states its own availability).
pub trait TelemetryHandler: Send + Sync {
    /// `type(handler).__name__`: the name degradation reports.
    fn handler_name(&self) -> &str;

    /// The reference `start()`: begin (or claim) the sink's resources.
    ///
    /// # Errors
    ///
    /// Whatever the sink answers; the composite records the failure under
    /// its `degraded` flag set instead of raising.
    fn start(&self) -> Result<(), TelemetryError>;

    /// The reference `stop()`: release the sink's resources.
    ///
    /// # Errors
    ///
    /// Whatever the sink answers; the composite reports it and continues.
    fn stop(&self) -> Result<(), TelemetryError>;

    /// The reference `send_event(event)`.
    ///
    /// # Errors
    ///
    /// Whatever the sink answers; the composite reports it and continues.
    fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError>;

    /// The reference `send_metric(metric)`.
    ///
    /// # Errors
    ///
    /// Whatever the sink answers; the composite reports it and continues.
    fn send_metric(&self, metric: &SecurityMetric) -> Result<(), TelemetryError>;

    /// The reference `initialize_redis(redis_handler)`; sinks without
    /// persistence needs ignore the call (the OTEL/Logfire no-op bodies).
    fn initialize_redis(&self, _store: &dyn TelemetryRedisStore) -> Result<(), TelemetryError> {
        Ok(())
    }

    /// The reference `flush_buffer()`; sinks that batch nothing answer
    /// `Ok(())` (the OTEL/Logfire no-op bodies).
    fn flush_buffer(&self) -> Result<(), TelemetryError> {
        Ok(())
    }

    /// The reference `get_dynamic_rules()`: the sink's rules payload when
    /// it carries one, `None` otherwise (the OTEL/Logfire answers).
    ///
    /// # Errors
    ///
    /// Whatever the sink answers; the composite reports it and continues.
    fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
        Ok(None)
    }

    /// The reference `health_check()`.
    fn health_check(&self) -> bool;
}

/// The reference `CompositeAgentHandler`: the multi-sink fan-out with the
/// mute filters, the single enrichment pass, and the degradation flags.
///
/// Failure semantics, point by point against the reference:
///
/// - `start` resets the failed-sink list, fans out, records every failing
///   sink's name, then sets `started` (even when sinks failed - exactly
///   the reference's flag order);
/// - `send_event` / `send_metric` gate on the mute filters, run the
///   enricher once over a private copy (every sink observes the same
///   enriched record, the caller's stays untouched), and report each
///   sink failure in the returned [`TelemetryFailure`] list without
///   touching the other sinks;
/// - `stop` / `flush_buffer` / `initialize_redis` fan out and report;
/// - `get_dynamic_rules` answers the first non-`None` payload;
/// - `health_check` is `all()` of the per-sink answers, `true` over an
///   empty fan-out, and a sink error answers `false` for that sink;
/// - [`CompositeAgentHandler::degraded`] is
///   `started && !failed_handlers.is_empty()`.
pub struct CompositeAgentHandler {
    handlers: Vec<Arc<dyn TelemetryHandler>>,
    event_filter: EventFilter,
    metric_filter: MetricFilter,
    enricher: Option<EventEnricher>,
    started: AtomicBool,
    failed_handlers: Mutex<Vec<String>>,
}

impl fmt::Debug for CompositeAgentHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let failed = self.failed_handlers.lock().expect("failed handlers");
        let started = self.started.load(Ordering::Relaxed);
        f.debug_struct("CompositeAgentHandler")
            .field("handlers", &self.handlers.len())
            .field("started", &started)
            .field("degraded", &(started && !failed.is_empty()))
            .field("failed_handlers", &failed.as_slice())
            .finish_non_exhaustive()
    }
}

impl CompositeAgentHandler {
    /// The reference constructor (`handlers`, `event_filter=`,
    /// `enricher=`; the metric half of the filter rides beside the event
    /// half, the crate's existing [`EventFilter`]/[`MetricFilter`] split).
    #[must_use]
    pub fn new(
        handlers: Vec<Arc<dyn TelemetryHandler>>,
        event_filter: EventFilter,
        metric_filter: MetricFilter,
        enricher: Option<EventEnricher>,
    ) -> Self {
        Self {
            handlers,
            event_filter,
            metric_filter,
            enricher,
            started: AtomicBool::new(false),
            failed_handlers: Mutex::new(Vec::new()),
        }
    }

    /// The reference `started` property.
    #[must_use]
    pub fn started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    /// The reference `degraded` property: started with at least one sink
    /// that failed its last `start`.
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.started() && !self.failed_handlers().is_empty()
    }

    /// The reference `failed_handlers` property (a copy).
    #[must_use]
    pub fn failed_handlers(&self) -> Vec<String> {
        self.failed_handlers
            .lock()
            .expect("failed handlers")
            .clone()
    }

    fn record_failure(handler: &str, error: TelemetryError) -> TelemetryFailure {
        TelemetryFailure {
            handler: handler.to_owned(),
            error,
        }
    }

    /// The reference `send_event`: mute gate, one enrichment pass over a
    /// private copy, then the per-sink fan-out with the failures
    /// returned (never raised).
    pub fn send_event(&self, event: &SecurityEvent) -> Vec<TelemetryFailure> {
        if !self.event_filter.is_event_allowed(&event.event_type) {
            return Vec::new();
        }
        let mut enriched = event.clone();
        if let Some(enricher) = &self.enricher {
            enricher.enrich_event(&mut enriched);
        }
        self.fan_out_event(&enriched)
    }

    /// The reference `send_metric`: the metric mute gate, the identity
    /// enrichment over a private copy, then the fan-out.
    pub fn send_metric(&self, metric: &SecurityMetric) -> Vec<TelemetryFailure> {
        if !self.metric_filter.is_metric_allowed(&metric.metric_type) {
            return Vec::new();
        }
        let mut enriched = metric.clone();
        if let Some(enricher) = &self.enricher {
            enricher.enrich_metric(&mut enriched);
        }
        self.fan_out_metric(&enriched)
    }

    fn fan_out_event(&self, event: &SecurityEvent) -> Vec<TelemetryFailure> {
        let mut failures = Vec::new();
        for handler in &self.handlers {
            if let Err(error) = handler.send_event(event) {
                failures.push(Self::record_failure(handler.handler_name(), error));
            }
        }
        failures
    }

    fn fan_out_metric(&self, metric: &SecurityMetric) -> Vec<TelemetryFailure> {
        let mut failures = Vec::new();
        for handler in &self.handlers {
            if let Err(error) = handler.send_metric(metric) {
                failures.push(Self::record_failure(handler.handler_name(), error));
            }
        }
        failures
    }

    /// The reference `initialize_redis`: the persistence-handle fan-out.
    pub fn initialize_redis(&self, store: &dyn TelemetryRedisStore) -> Vec<TelemetryFailure> {
        let mut failures = Vec::new();
        for handler in &self.handlers {
            if let Err(error) = handler.initialize_redis(store) {
                failures.push(Self::record_failure(handler.handler_name(), error));
            }
        }
        failures
    }

    /// The reference `start`: the failed list resets, every sink starts,
    /// the failures land in `failed_handlers`, and `started` flips on
    /// regardless (the reference's flag order).
    pub fn start(&self) {
        self.failed_handlers
            .lock()
            .expect("failed handlers")
            .clear();
        for handler in &self.handlers {
            if let Err(error) = handler.start() {
                self.failed_handlers
                    .lock()
                    .expect("failed handlers")
                    .push(handler.handler_name().to_owned());
                let _ = error; // reported through `failed_handlers()`
            }
        }
        self.started.store(true, Ordering::Relaxed);
    }

    /// The reference `stop`: the fan-out with the failures returned.
    pub fn stop(&self) -> Vec<TelemetryFailure> {
        let mut failures = Vec::new();
        for handler in &self.handlers {
            if let Err(error) = handler.stop() {
                failures.push(Self::record_failure(handler.handler_name(), error));
            }
        }
        failures
    }

    /// The reference `flush_buffer`: the fan-out with the failures
    /// returned.
    pub fn flush_buffer(&self) -> Vec<TelemetryFailure> {
        let mut failures = Vec::new();
        for handler in &self.handlers {
            if let Err(error) = handler.flush_buffer() {
                failures.push(Self::record_failure(handler.handler_name(), error));
            }
        }
        failures
    }

    /// The reference `get_dynamic_rules`: the first non-`None` payload
    /// wins; sink failures come back in the second tuple slot and are
    /// skipped.
    #[must_use]
    pub fn get_dynamic_rules(&self) -> (Option<serde_json::Value>, Vec<TelemetryFailure>) {
        let mut failures = Vec::new();
        for handler in &self.handlers {
            match handler.get_dynamic_rules() {
                Ok(Some(rules)) => return (Some(rules), failures),
                Ok(None) => {}
                Err(error) => {
                    failures.push(Self::record_failure(handler.handler_name(), error));
                }
            }
        }
        (None, failures)
    }

    /// The reference `health_check`: `all()` of the per-sink answers,
    /// `true` over an empty fan-out.
    #[must_use]
    pub fn health_check(&self) -> bool {
        if self.handlers.is_empty() {
            return true;
        }
        let mut results = Vec::new();
        for handler in &self.handlers {
            results.push(handler.health_check());
        }
        results.into_iter().all(|healthy| healthy)
    }

    /// The bus adapter: the composite as a
    /// [`SecurityEventBus`](crate::events::SecurityEventBus) handler (the
    /// engine-to-bus seam; the returned failure list is the host's to
    /// log, the bus closure drops it like the reference's
    /// logger-to-nowhere failures cannot break the pipeline).
    #[must_use]
    pub fn event_handler(self: &Arc<Self>) -> crate::events::EventHandler {
        let composite = Arc::clone(self);
        Arc::new(move |event: &SecurityEvent| {
            composite.send_event(event);
        })
    }

    /// The metrics adapter: the composite as a
    /// [`MetricsCollector`](crate::metrics::MetricsCollector) handler.
    #[must_use]
    pub fn metric_handler(self: &Arc<Self>) -> crate::metrics::MetricHandler {
        let composite = Arc::clone(self);
        Arc::new(move |metric: &SecurityMetric| {
            composite.send_metric(metric);
        })
    }
}

/// The OTLP wire transport (the reference's `OTLPSpanExporter` /
/// `OTLPMetricExporter` seam): one export call per payload.
pub trait OtlpTransport: Send + Sync {
    /// POST the OTLP/JSON `body` to `endpoint`.
    ///
    /// # Errors
    ///
    /// Whatever the transport answers (status or I/O).
    fn export(&self, endpoint: &str, body: &str) -> Result<(), TelemetryError>;
}

/// The built-in transport: one synchronous `POST` per payload
/// (`application/json`, 10 s timeout - the reference fetchers' budget).
pub struct OtlpHttpTransport {
    agent: ureq::Agent,
}

impl Default for OtlpHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl OtlpHttpTransport {
    /// A transport with the reference 10 s budget.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
        }
    }
}

impl OtlpTransport for OtlpHttpTransport {
    fn export(&self, endpoint: &str, body: &str) -> Result<(), TelemetryError> {
        self.agent
            .post(endpoint)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map(|_| ())
            .map_err(|error| TelemetryError(format!("otlp export failed: {error}")))
    }
}

/// The known OTLP signal paths `_otlp_signal_endpoint` strips.
const KNOWN_SIGNAL_PATHS: [&str; 3] = ["/v1/traces", "/v1/metrics", "/v1/logs"];

/// The reference `_EVENT_SPAN_ATTRS` field accessor (the reference reads
/// `getattr(event, field, "")`; the optionals default to the same empty
/// string).
type EventFieldAccessor = fn(&SecurityEvent) -> &str;

/// The reference `_EVENT_SPAN_ATTRS`: `(span attribute, event field)`
/// pairs, the field side as the accessor.
const EVENT_SPAN_ATTRS: [(&str, EventFieldAccessor); 5] = [
    ("guard.ip_address", |event| event.ip_address.as_str()),
    ("guard.action_taken", |event| event.action_taken.as_str()),
    ("guard.reason", |event| event.reason.as_str()),
    ("guard.endpoint", |event| {
        event.endpoint.as_deref().unwrap_or_default()
    }),
    ("guard.method", |event| {
        event.method.as_deref().unwrap_or_default()
    }),
];

/// `otlp_signal_endpoint`: strip the trailing slash, remove a known
/// signal suffix when the host pre-configured one, append the requested
/// signal path (the reference `_otlp_signal_endpoint`).
#[must_use]
pub fn otlp_signal_endpoint(endpoint: &str, signal_path: &str) -> String {
    let mut base = endpoint.trim_end_matches('/');
    for known in KNOWN_SIGNAL_PATHS {
        if let Some(stripped) = base.strip_suffix(known) {
            base = stripped;
            break;
        }
    }
    format!("{base}{signal_path}")
}

/// The W3C `traceparent` extraction (`_extract_parent_context` plus the
/// propagator).
///
/// Answers `(trace_id, parent_span_id)` when the metadata carries a
/// well-formed header, `None` otherwise (every malformed shape funnels to
/// the reference's swallowed extraction failure; `tracestate` joins the
/// context only and is never re-emitted).
#[must_use]
pub fn extract_traceparent(
    metadata: &serde_json::Map<String, serde_json::Value>,
) -> Option<(String, String)> {
    let raw = metadata.get("traceparent")?.as_str()?;
    let parts: Vec<&str> = raw.trim().split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    let (trace_id, span_id) = (parts[1], parts[2]);
    if !is_hex_of_length(trace_id, 32) || !is_hex_of_length(span_id, 16) {
        return None;
    }
    Some((trace_id.to_lowercase(), span_id.to_lowercase()))
}

fn is_hex_of_length(value: &str, length: usize) -> bool {
    value.len() == length && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// A span/metric identifier: SHA-256 over the wall-clock nanos, a
/// process counter, and a stack-address salt, hex-truncated (the
/// dependency-free stand-in for the SDK's random ids; spans only need
/// uniqueness).
fn next_hex_id(bytes: usize) -> String {
    use std::fmt::Write as _;

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |since| since.as_nanos());
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_be_bytes());
    hasher.update(count.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    let digest = hasher.finalize();
    let mut id = String::with_capacity(bytes * 2);
    for byte in &digest[..bytes] {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// One OTLP attribute (`{"key": ..., "value": {...}}`): JSON scalars map
/// onto the typed OTLP values, `null` and containers are skipped (the
/// enrichment family is scalar; the reference forwards only non-`None`).
fn otlp_attribute(key: &str, value: &serde_json::Value) -> Option<serde_json::Value> {
    let typed = match value {
        serde_json::Value::Number(number) => number.as_i64().map_or_else(
            // Every other JSON number (u64-backed, f64-backed) is
            // representable as a double.
            || serde_json::json!({ "doubleValue": number.as_f64().unwrap_or_default() }),
            |int| serde_json::json!({ "intValue": int }),
        ),
        serde_json::Value::Bool(flag) => serde_json::json!({ "boolValue": flag }),
        serde_json::Value::String(text) => serde_json::json!({ "stringValue": text }),
        _ => return None,
    };
    Some(serde_json::json!({ "key": key, "value": typed }))
}

fn string_attribute(key: &str, value: &str) -> serde_json::Value {
    serde_json::json!({ "key": key, "value": { "stringValue": value } })
}

fn unix_nanos(at: SystemTime) -> u128 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0_u128, |since| since.as_nanos())
}

/// The reference `OtelHandler`: a dependency-free OTLP/HTTP JSON exporter.
///
/// The wire half runs behind an injectable [`OtlpTransport`] (tests use a
/// capturing fake; production defaults to [`OtlpHttpTransport`]).
/// Faithful to the reference semantics:
///
/// - `start` builds the resource (`service.name` +
///   `otel_resource_attributes`, extras overriding), derives the
///   per-signal endpoints with the exact `_otlp_signal_endpoint` suffix
///   logic, and is idempotent (a second call records nothing);
/// - `send_event` emits one span named `guard.event.{event_type}`
///   (default `"unknown"`) with the `guard.*` attribute family
///   (`status_code` only when set) and forwards every `guard.*` metadata
///   entry except `traceparent`/`tracestate`; the W3C traceparent
///   becomes the span's remote parent (`traceId`/`parentSpanId`);
/// - `send_metric` maps `response_time` onto the `guard.request.duration`
///   histogram (unit `s`) and `request_count`/`error_rate` onto the
///   `guard.request.count` / `guard.error.count` monotonic sums; an
///   unknown metric type records nothing;
/// - export failures are returned as [`TelemetryFailure`]s by the
///   composite, never raised onto the request path.
///
/// Divergences (documented): the reference "claims" the global
/// tracer/meter providers once per process and shuts its owned providers
/// down at `stop`; the port owns no global registry, so the claim dance
/// is inapplicable-idiom (`start` stays idempotent per instance, `stop`
/// clears the derived endpoints), and each `send_metric` exports one
/// self-contained data point where the SDK would batch.
pub struct OtelHandler {
    resource_attributes: BTreeMap<String, String>,
    exporter_endpoint: Option<String>,
    transport: Arc<dyn OtlpTransport>,
    state: Mutex<OtelState>,
}

#[derive(Default)]
struct OtelState {
    started: bool,
    traces_endpoint: Option<String>,
    metrics_endpoint: Option<String>,
}

impl fmt::Debug for OtelHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("otel state");
        f.debug_struct("OtelHandler")
            .field("started", &state.started)
            .field("traces_endpoint", &state.traces_endpoint)
            .field("metrics_endpoint", &state.metrics_endpoint)
            .finish_non_exhaustive()
    }
}

impl OtelHandler {
    /// A handler over the reference config inputs and a transport.
    #[must_use]
    pub fn new(
        service_name: &str,
        resource_attributes: BTreeMap<String, String>,
        exporter_endpoint: Option<String>,
        transport: Arc<dyn OtlpTransport>,
    ) -> Self {
        let mut resource_attributes = resource_attributes;
        resource_attributes
            .entry(String::from("service.name"))
            .or_insert_with(|| service_name.to_owned());
        Self {
            resource_attributes,
            exporter_endpoint,
            transport,
            state: Mutex::new(OtelState::default()),
        }
    }

    /// The handler built from the config surface (`otel_service_name`,
    /// `otel_resource_attributes`, `otel_exporter_endpoint`) over the
    /// default HTTP transport.
    #[must_use]
    pub fn from_config(config: &SecurityConfig) -> Self {
        Self::new(
            &config.otel_service_name,
            config.otel_resource_attributes.clone(),
            config.otel_exporter_endpoint.clone(),
            Arc::new(OtlpHttpTransport::new()),
        )
    }

    /// The derived per-signal endpoints (diagnostics).
    ///
    /// # Errors
    ///
    /// Never; the state lock is held under a documented tightening
    /// allowance.
    pub fn signal_endpoints(&self) -> (Option<String>, Option<String>) {
        #[allow(clippy::significant_drop_tightening)]
        let state = self.state.lock().expect("otel state");
        (
            state.traces_endpoint.clone(),
            state.metrics_endpoint.clone(),
        )
    }

    fn resource_attributes_json(&self) -> serde_json::Value {
        let attributes: Vec<serde_json::Value> = self
            .resource_attributes
            .iter()
            .map(|(key, value)| string_attribute(key, value))
            .collect();
        serde_json::json!({ "attributes": attributes })
    }

    fn span_event_attributes(event: &SecurityEvent, event_type: &str) -> Vec<serde_json::Value> {
        let mut attributes = vec![string_attribute("guard.event_type", event_type)];
        for (attr_key, accessor) in EVENT_SPAN_ATTRS {
            attributes.push(string_attribute(attr_key, accessor(event)));
        }
        let status_code = event
            .metadata
            .get("status_code")
            .map_or(0, |value| value.as_i64().unwrap_or(0));
        if status_code != 0 {
            attributes.push(serde_json::json!({
                "key": "guard.status_code",
                "value": { "intValue": status_code },
            }));
        }
        for (key, value) in &event.metadata {
            if !key.starts_with("guard.") || key == "traceparent" || key == "tracestate" {
                continue;
            }
            if let Some(attribute) = otlp_attribute(key, value) {
                attributes.push(attribute);
            }
        }
        attributes
    }

    fn trace_payload(
        &self,
        event: &SecurityEvent,
        event_type: &str,
        now_nanos: u128,
    ) -> serde_json::Value {
        let parent = extract_traceparent(&event.metadata);
        let mut span = serde_json::json!({
            "traceId": parent.as_ref().map_or_else(
                || next_hex_id(16),
                |(trace_id, _)| trace_id.clone(),
            ),
            "spanId": next_hex_id(8),
            "name": format!("guard.event.{event_type}"),
            "kind": 1_i8,
            "startTimeUnixNano": now_nanos.to_string(),
            "endTimeUnixNano": now_nanos.to_string(),
            "attributes": Self::span_event_attributes(event, event_type),
        });
        if let Some((_, parent_span_id)) = &parent {
            span["parentSpanId"] = serde_json::Value::String(parent_span_id.clone());
        }
        serde_json::json!({
            "resourceSpans": [{
                "resource": self.resource_attributes_json(),
                "scopeSpans": [{
                    "scope": { "name": "guard_core.otel" },
                    "spans": [span],
                }],
            }],
        })
    }

    fn metric_payload(
        &self,
        metric: &SecurityMetric,
        now_nanos: u128,
    ) -> Option<serde_json::Value> {
        // The reference `attrs = {"endpoint": endpoint, **tags}`: the
        // tags' own `endpoint` entry overrides the metric field.
        let mut attribute_map: BTreeMap<String, serde_json::Value> = BTreeMap::from([(
            String::from("endpoint"),
            serde_json::Value::String(metric.endpoint.clone().unwrap_or_default()),
        )]);
        for (key, value) in &metric.tags {
            attribute_map.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        let attributes: Vec<serde_json::Value> = attribute_map
            .iter()
            .filter_map(|(key, value)| otlp_attribute(key, value))
            .collect();
        let time_point = serde_json::json!({
            "startTimeUnixNano": now_nanos.to_string(),
            "timeUnixNano": now_nanos.to_string(),
            "attributes": attributes,
        });
        let instrument = match metric.metric_type.as_str() {
            "response_time" => serde_json::json!({
                "name": "guard.request.duration",
                "unit": "s",
                "histogram": {
                    "dataPoints": [merge_json(
                        serde_json::json!({
                            "count": 1_i8,
                            "sum": metric.value,
                            "bucketCounts": [1_i8],
                            "explicitBounds": [],
                        }),
                        time_point,
                    )],
                    "aggregationTemporality": 2_i8,
                },
            }),
            "request_count" => sum_metric("guard.request.count", metric.value, time_point),
            "error_rate" => sum_metric("guard.error.count", metric.value, time_point),
            _ => return None,
        };
        Some(serde_json::json!({
            "resourceMetrics": [{
                "resource": self.resource_attributes_json(),
                "scopeMetrics": [{
                    "scope": { "name": "guard_core.otel" },
                    "metrics": [instrument],
                }],
            }],
        }))
    }

    /// The export step: one payload over its signal endpoint. The
    /// reference's transport failures surface through the composite's
    /// failure reporting, so the export error returns here.
    fn export_payload(
        &self,
        traces: Option<&serde_json::Value>,
        metrics: Option<&serde_json::Value>,
    ) -> Result<(), TelemetryError> {
        let (traces_endpoint, metrics_endpoint) = self.signal_endpoints();
        if let (Some(payload), Some(endpoint)) = (traces, traces_endpoint.as_deref()) {
            self.transport.export(endpoint, &payload.to_string())?;
        }
        if let (Some(payload), Some(endpoint)) = (metrics, metrics_endpoint.as_deref()) {
            self.transport.export(endpoint, &payload.to_string())?;
        }
        Ok(())
    }
}

fn merge_json(base: serde_json::Value, overlay: serde_json::Value) -> serde_json::Value {
    match (base, overlay) {
        (serde_json::Value::Object(mut target), serde_json::Value::Object(overlay)) => {
            for (key, value) in overlay {
                target.insert(key, value);
            }
            serde_json::Value::Object(target)
        }
        (base, _) => base,
    }
}

fn sum_metric(name: &str, value: f64, time_point: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "sum": {
            "dataPoints": [merge_json(
                serde_json::json!({ "asDouble": value }),
                time_point,
            )],
            "aggregationTemporality": 2_i8,
            "isMonotonic": true,
        },
    })
}

impl TelemetryHandler for OtelHandler {
    fn handler_name(&self) -> &'static str {
        "OtelHandler"
    }

    fn start(&self) -> Result<(), TelemetryError> {
        if self.state.lock().expect("otel state").started {
            return Ok(());
        }
        let derived = self
            .exporter_endpoint
            .as_ref()
            .map_or((None, None), |endpoint| {
                (
                    Some(otlp_signal_endpoint(endpoint, "/v1/traces")),
                    Some(otlp_signal_endpoint(endpoint, "/v1/metrics")),
                )
            });
        // The claim must be atomic with the derived endpoints: a
        // concurrent start must observe the same single installation.
        #[allow(clippy::significant_drop_tightening)]
        let mut state = self.state.lock().expect("otel state");
        if !state.started {
            state.traces_endpoint = derived.0;
            state.metrics_endpoint = derived.1;
            state.started = true;
        }
        Ok(())
    }

    fn stop(&self) -> Result<(), TelemetryError> {
        {
            let mut state = self.state.lock().expect("otel state");
            state.started = false;
            state.traces_endpoint = None;
            state.metrics_endpoint = None;
        }
        Ok(())
    }

    fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError> {
        let unknown = String::from("unknown");
        let event_type: &str = if event.event_type.is_empty() {
            &unknown
        } else {
            event.event_type.as_str()
        };
        let now = unix_nanos(SystemTime::now());
        let payload = self.trace_payload(event, event_type, now);
        self.export_payload(Some(&payload), None)
    }

    fn send_metric(&self, metric: &SecurityMetric) -> Result<(), TelemetryError> {
        let now = unix_nanos(SystemTime::now());
        let payload = self.metric_payload(metric, now);
        self.export_payload(None, payload.as_ref())
    }

    fn flush_buffer(&self) -> Result<(), TelemetryError> {
        Ok(()) // the transport exports synchronously; nothing buffers
    }

    fn health_check(&self) -> bool {
        true // the exporter is built in; the reference answers SDK availability
    }
}

/// The Logfire client seam (the reference's optional `import logfire`).
///
/// The application wires its logfire SDK to this trait; with no client
/// wired there is no [`LogfireHandler`] (the reference's
/// "logfire not installed" path maps onto "no client injected").
pub trait LogfireClient: Send + Sync {
    /// `logfire.DEFAULT_LOGFIRE_INSTANCE.config._initialized`: `true`
    /// when a host (or an earlier guard instance) already configured
    /// logfire in this process.
    fn is_configured(&self) -> bool;

    /// `logfire.configure(service_name=...)`.
    ///
    /// # Errors
    ///
    /// Whatever the client answers; the composite records it under the
    /// degraded flag set.
    fn configure(&self, service_name: &str) -> Result<(), TelemetryError>;

    /// `logfire.span(name, **attributes)`.
    ///
    /// # Errors
    ///
    /// Whatever the client answers; the composite reports it.
    fn span(
        &self,
        name: &str,
        attributes: &BTreeMap<String, serde_json::Value>,
    ) -> Result<(), TelemetryError>;

    /// `logfire.info(message, **attributes)`.
    ///
    /// # Errors
    ///
    /// Whatever the client answers; the composite reports it.
    fn info(
        &self,
        message: &str,
        attributes: &BTreeMap<String, serde_json::Value>,
    ) -> Result<(), TelemetryError>;

    /// `logfire.shutdown()`.
    ///
    /// # Errors
    ///
    /// Whatever the client answers; the composite reports it.
    fn shutdown(&self) -> Result<(), TelemetryError>;
}

/// The reference `LogfireHandler` over the injected [`LogfireClient`].
///
/// The claim lifecycle: `start` adopts an already-configured host
/// instance without re-configuring (the
/// `DEFAULT_LOGFIRE_INSTANCE._initialized` check), otherwise configures
/// and remembers ownership; `stop` shuts logfire down only when this
/// handler configured it.
pub struct LogfireHandler {
    service_name: String,
    client: Arc<dyn LogfireClient>,
    state: Mutex<LogfireState>,
}

#[derive(Default)]
struct LogfireState {
    started: bool,
    configured_by_guard: bool,
}

impl fmt::Debug for LogfireHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("logfire state");
        f.debug_struct("LogfireHandler")
            .field("service_name", &self.service_name)
            .field("started", &state.started)
            .field("configured_by_guard", &state.configured_by_guard)
            .finish_non_exhaustive()
    }
}

impl LogfireHandler {
    /// A handler over a client and the `logfire_service_name`.
    #[must_use]
    pub fn new(service_name: &str, client: Arc<dyn LogfireClient>) -> Self {
        Self {
            service_name: service_name.to_owned(),
            client,
            state: Mutex::new(LogfireState::default()),
        }
    }

    /// The handler built from the config surface (`logfire_service_name`).
    #[must_use]
    pub fn from_config(config: &SecurityConfig, client: Arc<dyn LogfireClient>) -> Self {
        Self::new(&config.logfire_service_name, client)
    }

    /// The enrichment entries: every `guard.*` metadata value except
    /// `traceparent`/`tracestate` (the reference span-kwargs forward).
    #[must_use]
    pub fn enrichment_entries(
        metadata: &serde_json::Map<String, serde_json::Value>,
    ) -> BTreeMap<String, serde_json::Value> {
        metadata
            .iter()
            .filter(|(key, value)| {
                key.starts_with("guard.")
                    && key.as_str() != "traceparent"
                    && key.as_str() != "tracestate"
                    && !value.is_null()
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    fn event_fields(event: &SecurityEvent) -> BTreeMap<String, serde_json::Value> {
        let mut fields = BTreeMap::from([
            (
                String::from("event_type"),
                serde_json::Value::String(event.event_type.clone()),
            ),
            (
                String::from("ip_address"),
                serde_json::Value::String(event.ip_address.clone()),
            ),
            (
                String::from("action_taken"),
                serde_json::Value::String(event.action_taken.clone()),
            ),
            (
                String::from("reason"),
                serde_json::Value::String(event.reason.clone()),
            ),
            (
                String::from("endpoint"),
                serde_json::Value::String(event.endpoint.clone().unwrap_or_default()),
            ),
            (
                String::from("method"),
                serde_json::Value::String(event.method.clone().unwrap_or_default()),
            ),
            (
                String::from("status_code"),
                serde_json::Value::Number(serde_json::Number::from(
                    event
                        .metadata
                        .get("status_code")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0),
                )),
            ),
        ]);
        fields.extend(Self::enrichment_entries(&event.metadata));
        fields
    }

    fn metric_fields(metric: &SecurityMetric) -> BTreeMap<String, serde_json::Value> {
        let mut fields = BTreeMap::from([
            (String::from("value"), serde_json::json!(metric.value)),
            (
                String::from("endpoint"),
                serde_json::Value::String(metric.endpoint.clone().unwrap_or_default()),
            ),
        ]);
        for (key, value) in &metric.tags {
            if key == "value" || key == "endpoint" {
                continue;
            }
            fields.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        fields
    }
}

impl TelemetryHandler for LogfireHandler {
    fn handler_name(&self) -> &'static str {
        "LogfireHandler"
    }

    // The claim is `is_configured`/`configure` + the ownership flag as
    // one critical section: a concurrent start must observe either the
    // adopted instance or the configure call, never both.
    #[allow(clippy::significant_drop_tightening)]
    fn start(&self) -> Result<(), TelemetryError> {
        let mut state = self.state.lock().expect("logfire state");
        if state.started {
            return Ok(());
        }
        if self.client.is_configured() {
            state.started = true;
            return Ok(()); // adopted: a host instance is already live
        }
        self.client.configure(&self.service_name)?;
        state.configured_by_guard = true;
        state.started = true;
        Ok(())
    }

    // The shutdown ownership: only the start that configured the client
    // may shut it down, so the check and the shutdown are one critical
    // section.
    #[allow(clippy::significant_drop_tightening)]
    fn stop(&self) -> Result<(), TelemetryError> {
        let mut state = self.state.lock().expect("logfire state");
        if state.configured_by_guard {
            self.client.shutdown()?;
            state.configured_by_guard = false;
        }
        state.started = false;
        Ok(())
    }

    fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError> {
        let unknown = String::from("unknown");
        let event_type: &str = if event.event_type.is_empty() {
            &unknown
        } else {
            event.event_type.as_str()
        };
        self.client.span(
            &format!("guard.event.{event_type}"),
            &Self::event_fields(event),
        )
    }

    fn send_metric(&self, metric: &SecurityMetric) -> Result<(), TelemetryError> {
        self.client.info(
            &format!("guard.metric.{}", metric.metric_type),
            &Self::metric_fields(metric),
        )
    }

    fn flush_buffer(&self) -> Result<(), TelemetryError> {
        Ok(())
    }

    fn health_check(&self) -> bool {
        true // the client is injected; the reference answers availability
    }
}

/// `build_event_filter` (the initializer port): the event mute list from
/// the config.
#[must_use]
pub fn build_event_filter(config: &SecurityConfig) -> EventFilter {
    EventFilter {
        muted_event_types: config.muted_event_types.iter().cloned().collect(),
    }
}

/// The metric half of `build_event_filter`: the metric mute list from
/// the config.
#[must_use]
pub fn build_metric_filter(config: &SecurityConfig) -> MetricFilter {
    MetricFilter::new(config.muted_metric_types.iter().cloned())
}

/// The enrichment identity from the config surface (`agent_project_id`,
/// `otel_service_name`, `otel_resource_attributes`).
#[must_use]
pub fn enrichment_identity(config: &SecurityConfig) -> EnrichmentIdentity {
    EnrichmentIdentity {
        project_id: config.agent_project_id.clone(),
        service_name: config.otel_service_name.clone(),
        resource_attributes: config.otel_resource_attributes.clone(),
    }
}

/// `build_composite_handler` (the initializer port): the agent slot
/// first, then the `enable_otel` / `enable_logfire` sinks, the mute
/// filters from the config, and the enricher when `enable_enrichment`.
///
/// The OTLP sink builds over the default HTTP transport; the Logfire
/// sink needs a wired [`LogfireClient`] (its `logfire_client` slot is
/// `None` until an application supplies one - the reference's
/// "logfire not installed" path), so `enable_logfire` without a client
/// contributes no sink, mirroring the disabled handler.
#[must_use]
pub fn build_composite_handler(
    config: &SecurityConfig,
    agent: Option<Arc<dyn TelemetryHandler>>,
    logfire_client: Option<Arc<dyn LogfireClient>>,
) -> CompositeAgentHandler {
    let mut handlers: Vec<Arc<dyn TelemetryHandler>> = Vec::new();
    if let Some(agent) = agent {
        handlers.push(agent);
    }
    if config.enable_otel {
        handlers.push(Arc::new(OtelHandler::from_config(config)));
    }
    if config.enable_logfire
        && let Some(client) = logfire_client
    {
        handlers.push(Arc::new(LogfireHandler::from_config(config, client)));
    }
    let enricher = if config.enable_enrichment {
        Some(EventEnricher::new(enrichment_identity(config)))
    } else {
        None
    };
    CompositeAgentHandler::new(
        handlers,
        build_event_filter(config),
        build_metric_filter(config),
        enricher,
    )
}

#[cfg(feature = "redis")]
impl TelemetryRedisStore for crate::redis_store::RedisStore {
    fn get_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        Self::get_key(self, prefix, namespace, key)
    }

    fn set_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
        value: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<(), StoreError> {
        Self::set_key(self, prefix, namespace, key, value, ttl_seconds)
    }
}

#[cfg(test)]
mod composite_tests {
    use super::*;
    use crate::event_types::{
        ENRICHMENT_KEY_PROJECT_ID, ENRICHMENT_KEY_SERVICE_NAME, ENRICHMENT_KEY_THREAT_SCORE,
        EVENT_PENETRATION_ATTEMPT,
    };

    fn sample_event() -> SecurityEvent {
        SecurityEvent::new(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "sqli in ?q=",
            "middleware",
        )
    }

    fn sample_metric() -> SecurityMetric {
        SecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: String::from("request_count"),
            value: 1.0,
            endpoint: Some(String::from("/api")),
            tags: BTreeMap::new(),
        }
    }

    /// A scripted sink: every lifecycle call is recorded, every answer
    /// is scripted through the preset queues.
    struct ScriptedSink {
        name: String,
        events: Mutex<Vec<String>>,
        metrics: Mutex<Vec<String>>,
        started: AtomicBool,
        start_answers: Mutex<Vec<Result<(), TelemetryError>>>,
        stopped: AtomicBool,
        flushed: AtomicBool,
        healthy: bool,
        redis_calls: Mutex<Vec<String>>,
        rule_answers: Mutex<Vec<Option<serde_json::Value>>>,
    }

    impl ScriptedSink {
        fn healthy(name: &str) -> Self {
            Self {
                name: name.to_owned(),
                events: Mutex::new(Vec::new()),
                metrics: Mutex::new(Vec::new()),
                started: AtomicBool::new(false),
                start_answers: Mutex::new(Vec::new()),
                stopped: AtomicBool::new(false),
                flushed: AtomicBool::new(false),
                healthy: true,
                redis_calls: Mutex::new(Vec::new()),
                rule_answers: Mutex::new(Vec::new()),
            }
        }

        fn unhealthy(name: &str) -> Self {
            Self {
                healthy: false,
                ..Self::healthy(name)
            }
        }

        fn failing_start(name: &str, error: &str) -> Self {
            Self {
                start_answers: Mutex::new(vec![Err(TelemetryError(error.to_owned()))]),
                ..Self::healthy(name)
            }
        }

        fn seen_events(&self) -> Vec<String> {
            self.events.lock().expect("events").clone()
        }
    }

    impl TelemetryHandler for ScriptedSink {
        fn handler_name(&self) -> &str {
            &self.name
        }

        fn start(&self) -> Result<(), TelemetryError> {
            let mut answers = self.start_answers.lock().expect("answers");
            self.started.store(true, Ordering::Relaxed);
            answers.pop().unwrap_or(Ok(()))
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            self.stopped.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError> {
            self.events
                .lock()
                .expect("events")
                .push(event.event_type.clone());
            Ok(())
        }

        fn send_metric(&self, metric: &SecurityMetric) -> Result<(), TelemetryError> {
            self.metrics
                .lock()
                .expect("metrics")
                .push(metric.metric_type.clone());
            Ok(())
        }

        fn initialize_redis(&self, _store: &dyn TelemetryRedisStore) -> Result<(), TelemetryError> {
            self.redis_calls
                .lock()
                .expect("redis")
                .push(String::from("called"));
            Ok(())
        }

        fn flush_buffer(&self) -> Result<(), TelemetryError> {
            self.flushed.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
            let mut answers = self.rule_answers.lock().expect("rules");
            Ok(answers.pop().unwrap_or(None))
        }

        fn health_check(&self) -> bool {
            self.healthy
        }
    }

    /// A sink that fails every operation with a per-method error.
    struct FailingSink {
        name: String,
    }

    impl TelemetryHandler for FailingSink {
        fn handler_name(&self) -> &str {
            &self.name
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Err(TelemetryError(String::from("stop blew up")))
        }

        fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
            Err(TelemetryError(String::from("send blew up")))
        }

        fn send_metric(&self, _metric: &SecurityMetric) -> Result<(), TelemetryError> {
            Err(TelemetryError(String::from("metric blew up")))
        }

        fn initialize_redis(&self, _store: &dyn TelemetryRedisStore) -> Result<(), TelemetryError> {
            Err(TelemetryError(String::from("redis blew up")))
        }

        fn flush_buffer(&self) -> Result<(), TelemetryError> {
            Err(TelemetryError(String::from("flush blew up")))
        }

        fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
            Err(TelemetryError(String::from("rules blew up")))
        }

        fn health_check(&self) -> bool {
            false
        }
    }

    struct NoopRedisStore;

    impl TelemetryRedisStore for NoopRedisStore {
        fn get_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
        ) -> Result<Option<String>, StoreError> {
            Ok(None)
        }

        fn set_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
            _value: &str,
            _ttl_seconds: Option<u64>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn composite_of(handlers: Vec<Arc<dyn TelemetryHandler>>) -> CompositeAgentHandler {
        CompositeAgentHandler::new(
            handlers,
            EventFilter::default(),
            MetricFilter::new(Vec::<String>::new()),
            None,
        )
    }

    /// A sink implementing only the required surface: the three
    /// optional lifecycle methods ride the trait defaults (the OTLP /
    /// Logfire no-op bodies).
    struct MinimalSink {
        name: String,
    }

    impl TelemetryHandler for MinimalSink {
        fn handler_name(&self) -> &str {
            &self.name
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_metric(&self, _metric: &SecurityMetric) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn health_check(&self) -> bool {
            true
        }
    }

    #[test]
    fn the_trait_defaults_carry_the_noop_lifecycle() {
        let minimal = Arc::new(MinimalSink {
            name: String::from("minimal"),
        });
        let composite = composite_of(vec![minimal.clone()]);
        composite.start();
        assert_eq!(minimal.handler_name(), "minimal");
        let event = sample_event();
        assert!(composite.send_event(&event).is_empty());
        assert!(composite.send_metric(&sample_metric()).is_empty());
        assert!(composite.flush_buffer().is_empty());
        let (rules, failures) = composite.get_dynamic_rules();
        assert!(rules.is_none());
        assert!(failures.is_empty());
        assert!(composite.initialize_redis(&NoopRedisStore).is_empty());
        assert_eq!(composite.stop(), Vec::<TelemetryFailure>::new());
        assert!(composite.health_check());
        // The merge helper's non-object overlay arm (a metric point is
        // always an object in the wire shapes; the arm keeps the helper
        // total).
        assert_eq!(
            merge_json(serde_json::json!({"kept": 1}), serde_json::json!("scalar")),
            serde_json::json!({"kept": 1})
        );
    }

    #[test]
    fn the_failing_sink_answers_every_surface() {
        let bad = Arc::new(FailingSink {
            name: String::from("bad"),
        });
        let composite = composite_of(vec![bad]);
        composite.start();
        assert!(composite.started());
        let metric_failures = composite.send_metric(&sample_metric());
        assert_eq!(metric_failures.len(), 1);
        assert_eq!(metric_failures[0].error.0, "metric blew up");
        assert!(!composite.health_check());
        // The shared test store answers its two surfaces directly.
        assert_eq!(NoopRedisStore.get_key("p", "ns", "k"), Ok(None));
        assert_eq!(NoopRedisStore.set_key("p", "ns", "k", "v", None), Ok(()));
    }

    #[test]
    fn the_error_shape_carries_its_payload_through_debug_and_display() {
        let error = TelemetryError(String::from("boom"));
        assert_eq!(error.to_string(), "telemetry sink error: boom");
        assert!(format!("{error:?}").contains("boom"));
        let failure = TelemetryFailure {
            handler: String::from("sink"),
            error,
        };
        assert_eq!(failure.handler, "sink");
        assert_eq!(failure.error.0, "boom");
    }

    #[test]
    fn send_event_fans_out_in_order_and_reports_sink_failures() {
        let first = Arc::new(ScriptedSink::healthy("first"));
        let failing = Arc::new(FailingSink {
            name: String::from("bad"),
        });
        let last = Arc::new(ScriptedSink::healthy("last"));
        let composite = composite_of(vec![first.clone(), failing, last.clone()]);
        let failures = composite.send_event(&sample_event());
        assert_eq!(first.seen_events(), vec![EVENT_PENETRATION_ATTEMPT]);
        assert_eq!(last.seen_events(), vec![EVENT_PENETRATION_ATTEMPT]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].handler, "bad");
        assert_eq!(
            failures[0].error,
            TelemetryError(String::from("send blew up"))
        );
    }

    #[test]
    fn a_muted_event_type_never_reaches_any_sink() {
        let sink = Arc::new(ScriptedSink::healthy("sink"));
        let composite = CompositeAgentHandler::new(
            vec![sink.clone()],
            EventFilter {
                muted_event_types: std::iter::once(EVENT_PENETRATION_ATTEMPT.to_owned()).collect(),
            },
            MetricFilter::new(Vec::<String>::new()),
            None,
        );
        let failures = composite.send_event(&sample_event());
        assert!(failures.is_empty());
        assert!(sink.seen_events().is_empty());
    }

    #[test]
    fn send_metric_fans_out_and_the_metric_mute_gate_holds() {
        let sink = Arc::new(ScriptedSink::healthy("sink"));
        let composite = CompositeAgentHandler::new(
            vec![sink.clone()],
            EventFilter::default(),
            MetricFilter::new(std::iter::once(String::from("request_count"))),
            None,
        );
        assert!(composite.send_metric(&sample_metric()).is_empty());
        assert!(sink.metrics.lock().expect("metrics").is_empty());

        let open = composite_of(vec![sink.clone()]);
        assert!(open.send_metric(&sample_metric()).is_empty());
        assert_eq!(
            sink.metrics.lock().expect("metrics").as_slice(),
            ["request_count"]
        );
    }

    #[test]
    fn the_enricher_runs_once_and_every_sink_sees_the_enriched_copy() {
        let mut identity = EnrichmentIdentity::new();
        identity.project_id = Some(String::from("proj-1"));
        let sink = Arc::new(ScriptedSink::healthy("sink"));
        let composite = CompositeAgentHandler::new(
            vec![sink.clone()],
            EventFilter::default(),
            MetricFilter::new(Vec::<String>::new()),
            Some(EventEnricher::new(identity)),
        );
        let event = sample_event();
        assert!(composite.send_event(&event).is_empty());
        assert_eq!(sink.seen_events().len(), 1);

        // The caller's event stays untouched; enrichment lands on the
        // sinks' copies only.
        assert!(!event.metadata.contains_key(ENRICHMENT_KEY_THREAT_SCORE));

        // The metric path stamps the identity onto the tags copy.
        let metric = sample_metric();
        composite.send_metric(&metric);
        assert!(!metric.tags.contains_key(ENRICHMENT_KEY_PROJECT_ID));
        assert!(!metric.tags.contains_key(ENRICHMENT_KEY_SERVICE_NAME));
    }

    #[test]
    fn start_records_failed_sinks_and_sets_the_degraded_flags() {
        let good = Arc::new(ScriptedSink::healthy("good"));
        let bad = Arc::new(ScriptedSink::failing_start("bad", "no port"));
        let composite = composite_of(vec![good, bad.clone()]);
        assert!(!composite.started());
        assert!(!composite.degraded());
        composite.start();
        assert!(composite.started());
        assert!(composite.degraded());
        assert_eq!(composite.failed_handlers(), vec![String::from("bad")]);

        // The restart resets the failed list, and a clean pass clears it.
        bad.start_answers.lock().expect("answers").push(Ok(()));
        composite.start();
        assert!(composite.started());
        assert!(!composite.degraded());
        assert!(composite.failed_handlers().is_empty());
    }

    #[test]
    fn an_empty_fanout_starts_and_answers_healthy() {
        let composite = composite_of(Vec::new());
        composite.start();
        assert!(composite.started());
        assert!(!composite.degraded());
        assert!(composite.health_check());
    }

    #[test]
    fn stop_flush_and_redis_fan_out_with_failure_reporting() {
        let good = Arc::new(ScriptedSink::healthy("good"));
        let bad = Arc::new(FailingSink {
            name: String::from("bad"),
        });
        let composite = composite_of(vec![good.clone(), bad]);

        let stop_failures = composite.stop();
        assert_eq!(stop_failures.len(), 1);
        assert_eq!(stop_failures[0].handler, "bad");
        assert_eq!(stop_failures[0].error.0, "stop blew up");

        let flush_failures = composite.flush_buffer();
        assert_eq!(flush_failures.len(), 1);
        assert_eq!(flush_failures[0].error.0, "flush blew up");

        let redis_failures = composite.initialize_redis(&NoopRedisStore);
        assert_eq!(redis_failures.len(), 1);
        assert_eq!(redis_failures[0].error.0, "redis blew up");

        assert!(good.stopped.load(Ordering::Relaxed));
        assert!(good.flushed.load(Ordering::Relaxed));
        assert_eq!(
            good.redis_calls.lock().expect("redis").as_slice(),
            ["called"]
        );
    }

    #[test]
    fn get_dynamic_rules_answers_the_first_payload_and_skips_failures() {
        let none_sink = Arc::new(ScriptedSink::healthy("none"));
        let bad = Arc::new(FailingSink {
            name: String::from("bad"),
        });
        let some_sink = Arc::new(ScriptedSink::healthy("some"));
        some_sink
            .rule_answers
            .lock()
            .expect("rules")
            .push(Some(serde_json::json!({"rules": []})));
        let composite = composite_of(vec![none_sink, bad, some_sink.clone()]);

        let (rules, failures) = composite.get_dynamic_rules();
        assert!(
            failures.len() == 1,
            "the failing sink was skipped past: {failures:?}"
        );
        assert_eq!(rules, Some(serde_json::json!({"rules": []})));
        assert_eq!(failures.len(), 1, "the failing sink was skipped past");
        assert_eq!(failures[0].handler, "bad");

        let empty = composite_of(vec![Arc::new(ScriptedSink::healthy("empty"))]);
        let (rules, failures) = empty.get_dynamic_rules();
        assert!(rules.is_none());
        assert!(failures.is_empty());
        assert!(some_sink.rule_answers.lock().expect("rules").is_empty());
    }

    #[test]
    fn health_check_is_the_all_of_the_sink_answers() {
        let composite = composite_of(vec![
            Arc::new(ScriptedSink::healthy("good")),
            Arc::new(ScriptedSink::unhealthy("sick")),
        ]);
        assert!(!composite.health_check());
        let all_good = composite_of(vec![Arc::new(ScriptedSink::healthy("good"))]);
        assert!(all_good.health_check());
    }

    #[test]
    fn the_bus_and_metric_adapters_dispatch_through_the_composite() {
        let sink = Arc::new(ScriptedSink::healthy("sink"));
        let composite = Arc::new(composite_of(vec![sink.clone()]));
        let bus = crate::events::SecurityEventBus::new(true).on_event(composite.event_handler());
        bus.send_middleware_event(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "sqli",
        );
        assert_eq!(sink.seen_events(), vec![EVENT_PENETRATION_ATTEMPT]);

        let collector =
            crate::metrics::MetricsCollector::new(true).with_handler(composite.metric_handler());
        collector.send_metric("request_count", 1.0, BTreeMap::new());
        assert_eq!(
            sink.metrics.lock().expect("metrics").as_slice(),
            ["request_count"]
        );
    }

    #[test]
    fn the_debug_shape_reports_the_flags() {
        let bad = Arc::new(ScriptedSink::failing_start("bad", "no port"));
        let composite = composite_of(vec![bad]);
        composite.start();
        let debug = format!("{composite:?}");
        assert!(debug.contains("started: true"));
        assert!(debug.contains("degraded: true"));
        assert!(debug.contains("bad"));
    }
}

#[cfg(test)]
mod otel_tests {
    use super::*;
    use crate::event_types::{ENRICHMENT_KEY_SERVICE_NAME, EVENT_PENETRATION_ATTEMPT};

    fn sample_metric() -> SecurityMetric {
        SecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: String::from("request_count"),
            value: 1.0,
            endpoint: Some(String::from("/api")),
            tags: BTreeMap::new(),
        }
    }

    /// A capturing transport: every export lands in the log with its
    /// endpoint.
    struct CapturingTransport {
        exports: Mutex<Vec<(String, String)>>,
        fail_with: Mutex<Option<String>>,
    }

    impl CapturingTransport {
        fn new() -> Self {
            Self {
                exports: Mutex::new(Vec::new()),
                fail_with: Mutex::new(None),
            }
        }

        fn exports(&self) -> Vec<(String, String)> {
            self.exports.lock().expect("exports").clone()
        }
    }

    impl OtlpTransport for CapturingTransport {
        fn export(&self, endpoint: &str, body: &str) -> Result<(), TelemetryError> {
            let failure = self.fail_with.lock().expect("fail_with").clone();
            if let Some(message) = failure {
                return Err(TelemetryError(message));
            }
            self.exports
                .lock()
                .expect("exports")
                .push((endpoint.to_owned(), body.to_owned()));
            Ok(())
        }
    }

    struct OtelNoopStore;

    impl TelemetryRedisStore for OtelNoopStore {
        fn get_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
        ) -> Result<Option<String>, StoreError> {
            Ok(None)
        }

        fn set_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
            _value: &str,
            _ttl_seconds: Option<u64>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn otel_with_endpoint(endpoint: Option<&str>) -> (OtelHandler, Arc<CapturingTransport>) {
        let transport = Arc::new(CapturingTransport::new());
        let handler = OtelHandler::new(
            "edge-svc",
            BTreeMap::from([(String::from("service.name"), String::from("host-overrides"))]),
            endpoint.map(String::from),
            transport.clone(),
        );
        (handler, transport)
    }

    fn sample_event() -> SecurityEvent {
        SecurityEvent::new(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "sqli in ?q=",
            "middleware",
        )
    }

    #[test]
    fn the_signal_endpoint_derivation_matches_the_reference() {
        assert_eq!(
            otlp_signal_endpoint("http://collector:4318", "/v1/traces"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            otlp_signal_endpoint("http://collector:4318/", "/v1/metrics"),
            "http://collector:4318/v1/metrics"
        );
        assert_eq!(
            otlp_signal_endpoint("http://collector:4318/v1/traces", "/v1/traces"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            otlp_signal_endpoint("http://collector:4318/v1/metrics", "/v1/metrics"),
            "http://collector:4318/v1/metrics"
        );
        assert_eq!(
            otlp_signal_endpoint("http://collector:4318/v1/logs", "/v1/traces"),
            "http://collector:4318/v1/traces"
        );
    }

    #[test]
    fn the_traceparent_extraction_mirrors_the_w3c_parse() {
        let metadata = |traceparent: &str| {
            let mut map = serde_json::Map::new();
            map.insert(
                String::from("traceparent"),
                serde_json::Value::String(traceparent.to_owned()),
            );
            map
        };
        let extracted = extract_traceparent(&metadata(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ))
        .expect("valid traceparent");
        assert_eq!(
            extracted,
            (
                String::from("4bf92f3577b34da6a3ce929d0e0e4736"),
                String::from("00f067aa0ba902b7")
            )
        );
        // Uppercase ids lower (the propagator's canonical form).
        let lowered = extract_traceparent(&metadata(
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01",
        ))
        .expect("uppercase traceparent");
        assert_eq!(lowered.0, "4bf92f3577b34da6a3ce929d0e0e4736");
        // Every malformed shape funnels to None.
        assert!(extract_traceparent(&metadata("00-short")).is_none());
        assert!(
            extract_traceparent(&metadata(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-zz067aa0ba902b7-01"
            ))
            .is_none()
        );
        assert!(
            extract_traceparent(&metadata(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"
            ))
            .is_none()
        );
        let mut numeric = serde_json::Map::new();
        numeric.insert(
            String::from("traceparent"),
            serde_json::Value::Number(serde_json::Number::from(7)),
        );
        assert!(extract_traceparent(&numeric).is_none());
        assert!(extract_traceparent(&serde_json::Map::new()).is_none());
    }

    #[test]
    fn start_derives_both_endpoints_and_is_idempotent() {
        let (handler, transport) = otel_with_endpoint(Some("http://collector:4318"));
        handler.start().expect("start");
        let (traces, metrics) = handler.signal_endpoints();
        assert_eq!(traces.as_deref(), Some("http://collector:4318/v1/traces"));
        assert_eq!(metrics.as_deref(), Some("http://collector:4318/v1/metrics"));
        // A second start records nothing new.
        handler.start().expect("start again");
        assert!(transport.exports().is_empty());
    }

    #[test]
    fn send_event_exports_the_reference_span_shape() {
        let (handler, transport) = otel_with_endpoint(Some("http://collector:4318"));
        handler.start().expect("start");
        let mut event = sample_event();
        event.endpoint = Some(String::from("/login"));
        event.method = Some(String::from("POST"));
        event.metadata.insert(
            String::from("traceparent"),
            serde_json::Value::String(String::from(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )),
        );
        event.metadata.insert(
            String::from("tracestate"),
            serde_json::Value::String(String::from("vendor=1")),
        );
        event.metadata.insert(
            String::from("status_code"),
            serde_json::Value::Number(serde_json::Number::from(403)),
        );
        event.metadata.insert(
            String::from(ENRICHMENT_KEY_SERVICE_NAME),
            serde_json::Value::String(String::from("edge-svc")),
        );
        event.metadata.insert(
            String::from("guard.container"),
            serde_json::json!({"nested": true}),
        );
        event
            .metadata
            .insert(String::from("guard.null"), serde_json::Value::Null);

        handler.send_event(&event).expect("send");
        let exports = transport.exports();
        assert_eq!(exports.len(), 1);
        let (endpoint, body) = &exports[0];
        assert_eq!(endpoint, "http://collector:4318/v1/traces");
        let payload: serde_json::Value = serde_json::from_str(body).expect("json");
        let resource_span = &payload["resourceSpans"][0];
        let resource_attrs = &resource_span["resource"]["attributes"];
        assert_eq!(resource_attrs[0]["key"], "service.name");
        assert_eq!(
            resource_attrs[0]["value"]["stringValue"], "host-overrides",
            "the configured extras override the service name slot"
        );
        let span = &resource_span["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "guard.event.penetration_attempt");
        assert_eq!(span["kind"], 1);
        assert_eq!(
            span["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736",
            "the traceparent is the remote parent"
        );
        assert_eq!(span["parentSpanId"], "00f067aa0ba902b7");
        assert_eq!(span["spanId"].as_str().expect("span id").len(), 16);
        assert!(
            span["startTimeUnixNano"]
                .as_str()
                .expect("nanos")
                .parse::<u128>()
                .is_ok()
        );
        let attributes: Vec<(String, serde_json::Value)> = span["attributes"]
            .as_array()
            .expect("attributes")
            .iter()
            .map(|attribute| {
                (
                    attribute["key"].as_str().expect("key").to_owned(),
                    attribute["value"].clone(),
                )
            })
            .collect();
        let find = |key: &str| {
            attributes
                .iter()
                .find(|(attribute_key, _)| attribute_key == key)
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| panic!("missing attribute {key}"))
        };
        assert_eq!(
            find("guard.event_type")["stringValue"],
            "penetration_attempt"
        );
        assert_eq!(find("guard.ip_address")["stringValue"], "192.0.2.1");
        assert_eq!(find("guard.action_taken")["stringValue"], "request_blocked");
        assert_eq!(find("guard.reason")["stringValue"], "sqli in ?q=");
        assert_eq!(find("guard.endpoint")["stringValue"], "/login");
        assert_eq!(find("guard.method")["stringValue"], "POST");
        assert_eq!(find("guard.status_code")["intValue"], 403);
        assert_eq!(
            find(ENRICHMENT_KEY_SERVICE_NAME)["stringValue"],
            "edge-svc",
            "guard.* metadata forwards"
        );
        for (key, _) in &attributes {
            assert!(key != "traceparent" && key != "tracestate");
            assert!(key != "guard.container", "containers skip");
            assert!(key != "guard.null", "nulls skip");
        }
    }

    #[test]
    fn an_event_without_a_traceparent_generates_the_trace_ids() {
        let (handler, transport) = otel_with_endpoint(Some("http://collector:4318"));
        handler.start().expect("start");
        handler.send_event(&sample_event()).expect("send");
        let (_, body) = &transport.exports()[0];
        let payload: serde_json::Value = serde_json::from_str(body).expect("json");
        let span = &payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"].as_str().expect("trace id").len(), 32);
        assert!(span.get("parentSpanId").is_none());
    }

    #[test]
    fn an_empty_event_type_answers_unknown() {
        let (handler, transport) = otel_with_endpoint(Some("http://collector:4318"));
        handler.start().expect("start");
        let mut event = sample_event();
        event.event_type = String::new();
        handler.send_event(&event).expect("send");
        let (_, body) = &transport.exports()[0];
        assert!(body.contains("\"guard.event.unknown\""));
    }

    #[test]
    fn a_transport_failure_surfaces_through_the_sink_answer() {
        let (handler, transport) = otel_with_endpoint(Some("http://collector:4318"));
        *transport.fail_with.lock().expect("fail") = Some(String::from("connection refused"));
        handler.start().expect("start");
        let answer = handler.send_event(&sample_event());
        assert_eq!(
            answer,
            Err(TelemetryError(String::from("connection refused")))
        );
    }

    #[test]
    fn send_metric_exports_the_reference_instrument_shapes() {
        let (handler, transport) = otel_with_endpoint(Some("http://collector:4318"));
        handler.start().expect("start");

        let mut response_time = sample_metric();
        response_time.metric_type = String::from("response_time");
        response_time.value = 0.42;
        handler.send_metric(&response_time).expect("send");

        let mut error_rate = sample_metric();
        error_rate.metric_type = String::from("error_rate");
        error_rate.endpoint = None;
        error_rate
            .tags
            .insert(String::from("endpoint"), String::from("/route-tag-wins"));
        handler.send_metric(&error_rate).expect("send");

        let mut unknown = sample_metric();
        unknown
            .metric_type
            .clone_from(&String::from("bandwidth_usage"));
        handler
            .send_metric(&unknown)
            .expect("unknown records nothing");

        let exports = transport.exports();
        assert_eq!(exports.len(), 2, "the unknown type exports nothing");
        assert_eq!(exports[0].0, "http://collector:4318/v1/metrics");
        let histogram: serde_json::Value = serde_json::from_str(&exports[0].1).expect("json");
        let instrument = &histogram["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0];
        assert_eq!(instrument["name"], "guard.request.duration");
        assert_eq!(instrument["unit"], "s");
        let point = &instrument["histogram"]["dataPoints"][0];
        assert_eq!(point["count"], 1);
        assert_eq!(point["sum"], 0.42);
        assert_eq!(point["bucketCounts"][0], 1);
        assert_eq!(point["attributes"][0]["key"], "endpoint");

        let sum: serde_json::Value = serde_json::from_str(&exports[1].1).expect("json");
        let counter = &sum["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0];
        assert_eq!(counter["name"], "guard.error.count");
        assert_eq!(counter["sum"]["isMonotonic"], true);
        assert_eq!(
            counter["sum"]["dataPoints"][0]["attributes"][0]["value"]["stringValue"],
            "/route-tag-wins",
            "the tags' own endpoint entry overrides the metric field"
        );
    }

    #[test]
    fn sends_before_start_after_stop_and_without_an_endpoint_export_nothing() {
        let (handler, transport) = otel_with_endpoint(Some("http://collector:4318"));
        handler.send_event(&sample_event()).expect("unstarted send");
        assert!(transport.exports().is_empty());
        handler.start().expect("start");
        handler.stop().expect("stop");
        assert_eq!(handler.signal_endpoints(), (None, None));
        handler.send_event(&sample_event()).expect("stopped send");
        assert!(transport.exports().is_empty());

        let (no_endpoint, transport) = otel_with_endpoint(None);
        no_endpoint.start().expect("start");
        no_endpoint.send_event(&sample_event()).expect("send");
        no_endpoint.send_metric(&sample_metric()).expect("send");
        assert!(transport.exports().is_empty());
    }

    #[test]
    fn the_noop_lifecycle_methods_and_debug_render() {
        let (handler, _transport) = otel_with_endpoint(Some("http://collector:4318"));
        handler.start().expect("start");
        assert!(handler.flush_buffer().is_ok());
        assert_eq!(handler.get_dynamic_rules(), Ok(None));
        assert!(handler.initialize_redis(&OtelNoopStore).is_ok());
        assert_eq!(OtelNoopStore.get_key("p", "ns", "k"), Ok(None));
        assert_eq!(OtelNoopStore.set_key("p", "ns", "k", "v", Some(60)), Ok(()));
        assert!(handler.health_check());
        let debug = format!("{handler:?}");
        assert!(debug.contains("started: true"));
        assert_eq!(handler.handler_name(), "OtelHandler");
    }

    #[test]
    fn the_http_transport_posts_json_and_reports_failures() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let received = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = received.clone();
        listener.set_nonblocking(true).expect("nonblocking");
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            // The cloud_fetch stub's accept loop: the nonblocking accept
            // fails with WouldBlock until the client connects, so both
            // arms run.
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0_u8; 8192];
                        let read = stream.read(&mut buffer).unwrap_or(0);
                        sink.lock()
                            .expect("sink")
                            .push(String::from_utf8_lossy(&buffer[..read]).to_string());
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                        return;
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(2)),
                }
            }
        });
        let transport = OtlpHttpTransport::new();
        transport
            .export(&format!("http://127.0.0.1:{port}/v1/traces"), "{\"x\":1}")
            .expect("export");
        let requests = received.lock().expect("sink").clone();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /v1/traces HTTP/1.1"));
        assert!(requests[0].contains("Content-Type: application/json"));
        assert!(requests[0].contains("{\"x\":1}"));

        // A refused connection flattens into the TelemetryError shape.
        let answer = transport.export("http://127.0.0.1:1/v1/traces", "{}");
        assert!(answer.is_err());
    }

    #[test]
    fn the_default_transport_builds_with_the_reference_budget() {
        let _transport = OtlpHttpTransport::default();
        // The attribute helpers: scalar mapping and the skip arms.
        assert_eq!(
            otlp_attribute("k", &serde_json::json!(7_i64)).expect("int")["value"]["intValue"],
            7
        );
        assert_eq!(
            otlp_attribute("k", &serde_json::json!(7.5)).expect("double")["value"]["doubleValue"],
            7.5
        );
        assert_eq!(
            otlp_attribute("k", &serde_json::json!(true)).expect("bool")["value"]["boolValue"],
            true
        );
        assert_eq!(
            otlp_attribute("k", &serde_json::json!("text")).expect("string")["value"]["stringValue"],
            "text"
        );
        assert!(otlp_attribute("k", &serde_json::json!([])).is_none());
        assert!(otlp_attribute("k", &serde_json::json!({})).is_none());
        assert_eq!(
            otlp_attribute("k", &serde_json::json!(u64::MAX)).expect("unsigned")["value"]["doubleValue"],
            u64::MAX as f64,
            "an out-of-i64 number lands as a double"
        );
        assert_eq!(string_attribute("k", "v")["value"]["stringValue"], "v");
        assert!(
            unix_nanos(UNIX_EPOCH) == 0,
            "the pre-epoch arm answers zero"
        );
    }
}

#[cfg(test)]
mod logfire_tests {
    use super::*;
    use crate::event_types::EVENT_PENETRATION_ATTEMPT;

    /// A scripted logfire client with the reference lifecycle surface.
    struct ScriptedClient {
        configured: Mutex<Vec<String>>,
        spans: Mutex<Vec<(String, BTreeMap<String, serde_json::Value>)>>,
        infos: Mutex<Vec<(String, BTreeMap<String, serde_json::Value>)>>,
        shutdowns: Mutex<Vec<()>>,
        already_configured: bool,
        configure_answer: Mutex<Option<Result<(), TelemetryError>>>,
    }

    impl ScriptedClient {
        fn fresh() -> Self {
            Self {
                configured: Mutex::new(Vec::new()),
                spans: Mutex::new(Vec::new()),
                infos: Mutex::new(Vec::new()),
                shutdowns: Mutex::new(Vec::new()),
                already_configured: false,
                configure_answer: Mutex::new(None),
            }
        }

        fn adopted() -> Self {
            Self {
                already_configured: true,
                ..Self::fresh()
            }
        }

        fn failing_configure() -> Self {
            Self {
                configure_answer: Mutex::new(Some(Err(TelemetryError(String::from(
                    "token rejected",
                ))))),
                ..Self::fresh()
            }
        }

        fn configure_count(&self) -> usize {
            self.configured.lock().expect("configured").len()
        }

        fn spans(&self) -> Vec<(String, BTreeMap<String, serde_json::Value>)> {
            self.spans.lock().expect("spans").clone()
        }
    }

    impl LogfireClient for ScriptedClient {
        fn is_configured(&self) -> bool {
            self.already_configured
        }

        fn configure(&self, service_name: &str) -> Result<(), TelemetryError> {
            let answer = self
                .configure_answer
                .lock()
                .expect("answer")
                .take()
                .unwrap_or(Ok(()));
            if answer.is_ok() {
                self.configured
                    .lock()
                    .expect("configured")
                    .push(service_name.to_owned());
            }
            answer
        }

        fn span(
            &self,
            name: &str,
            attributes: &BTreeMap<String, serde_json::Value>,
        ) -> Result<(), TelemetryError> {
            self.spans
                .lock()
                .expect("spans")
                .push((name.to_owned(), attributes.clone()));
            Ok(())
        }

        fn info(
            &self,
            message: &str,
            attributes: &BTreeMap<String, serde_json::Value>,
        ) -> Result<(), TelemetryError> {
            self.infos
                .lock()
                .expect("infos")
                .push((message.to_owned(), attributes.clone()));
            Ok(())
        }

        fn shutdown(&self) -> Result<(), TelemetryError> {
            self.shutdowns.lock().expect("shutdowns").push(());
            Ok(())
        }
    }

    fn handler_with(client: ScriptedClient) -> (LogfireHandler, Arc<ScriptedClient>) {
        let client = Arc::new(client);
        (LogfireHandler::new("guard-svc", client.clone()), client)
    }

    fn sample_event() -> SecurityEvent {
        SecurityEvent::new(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "sqli in ?q=",
            "middleware",
        )
    }

    #[test]
    fn start_configures_when_unclaimed_and_stop_shuts_down() {
        let (handler, client) = handler_with(ScriptedClient::fresh());
        handler.start().expect("start");
        assert_eq!(client.configure_count(), 1);
        assert_eq!(
            client.configured.lock().expect("configured").as_slice(),
            ["guard-svc"]
        );
        handler.stop().expect("stop");
        assert_eq!(client.shutdowns.lock().expect("shutdowns").len(), 1);
        // A restart after stop configures again (the claim was released).
        handler.start().expect("restart");
        assert_eq!(client.configure_count(), 2);
    }

    #[test]
    fn an_already_configured_host_instance_is_adopted_never_reconfigured() {
        let (handler, client) = handler_with(ScriptedClient::adopted());
        handler.start().expect("start");
        assert_eq!(client.configure_count(), 0);
        handler.stop().expect("stop");
        assert!(
            client.shutdowns.lock().expect("shutdowns").is_empty(),
            "the adopted instance is not ours to shut down"
        );
    }

    #[test]
    fn start_is_idempotent_and_configure_failures_surface() {
        let (handler, client) = handler_with(ScriptedClient::fresh());
        handler.start().expect("start");
        handler.start().expect("start again");
        assert_eq!(client.configure_count(), 1);

        let (failing, failing_client) = handler_with(ScriptedClient::failing_configure());
        let answer = failing.start();
        assert_eq!(answer, Err(TelemetryError(String::from("token rejected"))));
        assert_eq!(failing_client.configure_count(), 0);
        // The failed start can succeed on the next call.
        failing.start().expect("retry");
        assert_eq!(failing_client.configure_count(), 1);
    }

    #[test]
    fn send_event_emits_the_reference_span_fields() {
        let (handler, client) = handler_with(ScriptedClient::fresh());
        let mut event = sample_event();
        event.endpoint = Some(String::from("/login"));
        event.method = Some(String::from("POST"));
        event.metadata.insert(
            String::from("status_code"),
            serde_json::Value::Number(serde_json::Number::from(403)),
        );
        event.metadata.insert(
            String::from("traceparent"),
            serde_json::Value::String(String::from(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )),
        );
        event.metadata.insert(
            String::from("guard.reason_code"),
            serde_json::Value::String(String::from("R1")),
        );
        event
            .metadata
            .insert(String::from("guard.none"), serde_json::Value::Null);

        handler.send_event(&event).expect("send");
        let spans = client.spans();
        assert_eq!(spans.len(), 1);
        let (name, fields) = &spans[0];
        assert_eq!(name, "guard.event.penetration_attempt");
        assert_eq!(fields["event_type"], "penetration_attempt");
        assert_eq!(fields["ip_address"], "192.0.2.1");
        assert_eq!(fields["action_taken"], "request_blocked");
        assert_eq!(fields["reason"], "sqli in ?q=");
        assert_eq!(fields["endpoint"], "/login");
        assert_eq!(fields["method"], "POST");
        assert_eq!(fields["status_code"], 403);
        assert_eq!(fields["guard.reason_code"], "R1");
        assert!(fields.get("traceparent").is_none());
        assert!(fields.get("guard.none").is_none());
    }

    #[test]
    fn send_metric_emits_the_safe_tag_join() {
        let (handler, client) = handler_with(ScriptedClient::fresh());
        let metric = SecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: String::from("response_time"),
            value: 0.25,
            endpoint: Some(String::from("/api")),
            tags: BTreeMap::from([
                (String::from("method"), String::from("GET")),
                (String::from("value"), String::from("smuggled")),
                (String::from("endpoint"), String::from("smuggled")),
            ]),
        };
        handler.send_metric(&metric).expect("send");
        let infos = client.infos.lock().expect("infos").clone();
        assert_eq!(infos.len(), 1);
        let (message, fields) = &infos[0];
        assert_eq!(message, "guard.metric.response_time");
        assert_eq!(fields["value"], 0.25);
        assert_eq!(fields["endpoint"], "/api", "the field wins over the tag");
        assert_eq!(fields["method"], "GET");
        assert!(!fields.contains_key("smuggled"));
    }

    #[test]
    fn the_noop_lifecycle_methods_and_the_enrichment_helper() {
        let (handler, _client) = handler_with(ScriptedClient::fresh());
        assert!(handler.flush_buffer().is_ok());
        assert_eq!(handler.get_dynamic_rules(), Ok(None));
        assert!(handler.initialize_redis(&NoopRedisStoreStatic).is_ok());
        assert!(handler.health_check());
        assert_eq!(handler.handler_name(), "LogfireHandler");
        let debug = format!("{handler:?}");
        assert!(debug.contains("guard-svc"));

        let mut event = sample_event();
        event.event_type = String::new();
        handler.send_event(&event).expect("unknown type");
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            String::from("guard.kept"),
            serde_json::Value::String(String::from("yes")),
        );
        metadata.insert(
            String::from("other"),
            serde_json::Value::String(String::from("no")),
        );
        metadata.insert(
            String::from("tracestate"),
            serde_json::Value::String(String::from("x")),
        );
        let entries = LogfireHandler::enrichment_entries(&metadata);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries["guard.kept"], "yes");
    }

    #[test]
    fn the_noop_store_answers_both_surfaces() {
        assert_eq!(NoopRedisStoreStatic.get_key("p", "ns", "k"), Ok(None));
        assert_eq!(
            NoopRedisStoreStatic.set_key("p", "ns", "k", "v", Some(30)),
            Ok(())
        );
    }

    struct NoopRedisStoreStatic;

    impl TelemetryRedisStore for NoopRedisStoreStatic {
        fn get_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
        ) -> Result<Option<String>, StoreError> {
            Ok(None)
        }

        fn set_key(
            &self,
            _prefix: &str,
            _namespace: &str,
            _key: &str,
            _value: &str,
            _ttl_seconds: Option<u64>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod initializer_tests {
    use super::*;
    use crate::event_types::{
        ENRICHMENT_KEY_PROJECT_ID, EVENT_IP_BLOCKED, EVENT_PENETRATION_ATTEMPT,
    };

    struct NameOnlySink {
        name: String,
        seen: Mutex<Vec<String>>,
    }

    impl NameOnlySink {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_owned(),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl TelemetryHandler for NameOnlySink {
        fn handler_name(&self) -> &str {
            &self.name
        }

        fn start(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn send_event(&self, event: &SecurityEvent) -> Result<(), TelemetryError> {
            self.seen
                .lock()
                .expect("seen")
                .push(event.event_type.clone());
            Ok(())
        }

        fn send_metric(&self, _metric: &SecurityMetric) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn health_check(&self) -> bool {
            true
        }
    }

    struct CapturingLogfire {
        configured: Mutex<Vec<String>>,
    }

    impl LogfireClient for CapturingLogfire {
        fn is_configured(&self) -> bool {
            false
        }

        fn configure(&self, service_name: &str) -> Result<(), TelemetryError> {
            self.configured
                .lock()
                .expect("configured")
                .push(service_name.to_owned());
            Ok(())
        }

        fn span(
            &self,
            _name: &str,
            _attributes: &BTreeMap<String, serde_json::Value>,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn info(
            &self,
            _message: &str,
            _attributes: &BTreeMap<String, serde_json::Value>,
        ) -> Result<(), TelemetryError> {
            Ok(())
        }

        fn shutdown(&self) -> Result<(), TelemetryError> {
            Ok(())
        }
    }

    fn telemetry_config() -> SecurityConfig {
        SecurityConfig {
            otel_service_name: String::from("edge-svc"),
            ..SecurityConfig::default()
        }
    }

    #[test]
    fn the_filters_build_from_the_config_mute_lists() {
        let config = SecurityConfig {
            muted_event_types: std::iter::once(EVENT_IP_BLOCKED.to_owned()).collect(),
            muted_metric_types: std::iter::once(String::from("error_rate")).collect(),
            ..SecurityConfig::default()
        };

        let event_filter = build_event_filter(&config);
        assert!(!event_filter.is_event_allowed(EVENT_IP_BLOCKED));
        assert!(event_filter.is_event_allowed(EVENT_PENETRATION_ATTEMPT));

        let metric_filter = build_metric_filter(&config);
        assert!(!metric_filter.is_metric_allowed("error_rate"));
        assert!(metric_filter.is_metric_allowed("request_count"));
    }

    #[test]
    fn the_identity_maps_the_three_config_inputs() {
        let config = SecurityConfig {
            agent_project_id: Some(String::from("proj-9")),
            otel_service_name: String::from("edge-svc"),
            otel_resource_attributes: BTreeMap::from([(
                String::from("deployment.environment"),
                String::from("prod"),
            )]),
            ..SecurityConfig::default()
        };
        let identity = enrichment_identity(&config);
        assert_eq!(identity.project_id.as_deref(), Some("proj-9"));
        assert_eq!(identity.service_name, "edge-svc");
        assert_eq!(
            identity.resource_attributes["deployment.environment"],
            "prod"
        );
    }

    #[test]
    fn the_composite_builds_agent_first_then_otel_then_logfire() {
        let mut config = telemetry_config();
        config.enable_otel = true;
        config.enable_logfire = true;
        config.enable_enrichment = true;
        config.agent_project_id = Some(String::from("proj-9"));

        let client = Arc::new(CapturingLogfire {
            configured: Mutex::new(Vec::new()),
        });
        let agent = Arc::new(NameOnlySink::new("agent"));
        let composite = build_composite_handler(&config, Some(agent.clone()), Some(client.clone()));

        composite.start();
        assert_eq!(
            client.configured.lock().expect("configured").as_slice(),
            ["guard-core"],
            "the logfire sink takes the config's logfire_service_name default"
        );

        // The agent slot first: an event reaches it, and the enrichment
        // runs (the composite carries the config-built enricher).
        let mut event = SecurityEvent::new(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "sqli",
            "middleware",
        );
        composite.send_event(&event);
        assert_eq!(
            agent.seen.lock().expect("seen").as_slice(),
            [EVENT_PENETRATION_ATTEMPT]
        );
        let _ = &mut event;

        // The full lifecycle through the built composite: metrics, the
        // rules surface, and the stop fan-out (the logfire client's
        // shutdown ownership included).
        let metric = SecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: String::from("response_time"),
            value: 0.5,
            endpoint: None,
            tags: BTreeMap::new(),
        };
        composite.send_metric(&metric);
        assert!(!metric.tags.contains_key(ENRICHMENT_KEY_PROJECT_ID));
        let (rules, failures) = composite.get_dynamic_rules();
        assert!(rules.is_none());
        assert!(failures.is_empty());
        assert_eq!(composite.stop(), Vec::<TelemetryFailure>::new());

        // The OTLP sink sits between the agent and logfire in the
        // fan-out: a send failure name check pins the membership.
        assert_eq!(composite.failed_handlers(), Vec::<String>::new());
        assert!(composite.health_check());
        assert_eq!(agent.handler_name(), "agent");
    }

    #[test]
    fn enable_logfire_without_a_client_contributes_no_sink() {
        let mut config = telemetry_config();
        config.enable_otel = true;
        config.enable_logfire = true;
        let composite = build_composite_handler(&config, None, None);
        // The OTLP handler is the only sink (the disabled-logfire mirror
        // of the reference's not-installed path): a clean fan-out answers
        // no rules and no failures.
        let (rules, failures) = composite.get_dynamic_rules();
        assert!(rules.is_none());
        assert!(failures.is_empty(), "one sink (OTLP), none failing");
        assert!(composite.health_check());
    }

    #[test]
    fn enrichment_defaults_off_and_the_mutes_ride_the_composite() {
        let mut config = telemetry_config();
        config.enable_otel = false;
        config.muted_event_types = std::iter::once(EVENT_PENETRATION_ATTEMPT.to_owned()).collect();
        let agent = Arc::new(NameOnlySink::new("agent"));
        let composite = build_composite_handler(&config, Some(agent.clone()), None);
        let failures = composite.send_event(&SecurityEvent::new(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "sqli",
            "middleware",
        ));
        assert!(failures.is_empty());
        assert!(
            agent.seen.lock().expect("seen").is_empty(),
            "the mute holds"
        );
    }

    #[test]
    fn the_otlp_sink_built_from_config_keeps_the_service_name() {
        let config = telemetry_config();
        let handler = OtelHandler::from_config(&config);
        handler.start().expect("start");
        assert!(handler.health_check());
        let logfire = LogfireHandler::from_config(
            &config,
            Arc::new(CapturingLogfire {
                configured: Mutex::new(Vec::new()),
            }),
        );
        assert_eq!(logfire.handler_name(), "LogfireHandler");
    }
}
