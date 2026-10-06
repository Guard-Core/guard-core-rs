//! The reference event surface: the exact `EVENT_*` names and the
//! `SecurityEvent` fields, plus the [`SecurityEventBus`] hook seam.
//!
//! The constants come from `guard_core/core/events/event_types.py`, the
//! event fields from `_build_event` in
//! `guard_core/core/events/middleware_events.py`, and the bus stands in
//! for the Python `agent_handler.send_event` transport (the accepted
//! `OnGeoEvent` registration pattern from the Go port's PR #27).
//!
//! The bus stays I/O-free: handlers registered with
//! [`SecurityEventBus::on_event`] receive every allowed event and own the
//! transport (the guard-agent HTTP client, a log sink, metrics, tests).
//! Handler failures cannot break the pipeline: a panicking handler is
//! caught and dropped, mirroring the reference's `except Exception`
//! guard around `send_event`.
//!
//! # Example
//!
//! ```
//! use std::sync::{Arc, Mutex};
//!
//! use guard_core_rs::event_types::EVENT_PENETRATION_ATTEMPT;
//! use guard_core_rs::events::{SecurityEvent, SecurityEventBus};
//!
//! let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
//! let sink = seen.clone();
//! let bus = SecurityEventBus::new(true).on_event(Arc::new(move |event: &SecurityEvent| {
//!     sink.lock().expect("sink").push(event.event_type.clone());
//! }));
//!
//! bus.send_middleware_event(
//!     EVENT_PENETRATION_ATTEMPT,
//!     "192.0.2.1",
//!     "request_blocked",
//!     "Penetration attempt detected: sqli in ?q=",
//! );
//!
//! assert_eq!(seen.lock().expect("sink").as_slice(), ["penetration_attempt"]);
//! ```

use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::SystemTime;

use crate::enrichment::EventEnricher;

pub use crate::event_types::EVENT_TYPE_VALUES;

/// A registered event sink (`agent_handler.send_event`'s Rust stand-in).
pub type EventHandler = Arc<dyn Fn(&SecurityEvent) + Send + Sync>;

/// `handler_name` for middleware-emitted events
/// (`_MIDDLEWARE_HANDLER_NAME`).
pub const MIDDLEWARE_HANDLER_NAME: &str = "middleware";

/// `handler_name` for rate-limit events (`_RATE_LIMIT_HANDLER_NAME`).
pub const RATE_LIMIT_HANDLER_NAME: &str = "rate_limit";

/// `handler_name` for IP ban events (`_IP_BAN_HANDLER_NAME`).
pub const IP_BAN_HANDLER_NAME: &str = "ip_ban";

/// The mutable state one bus family shares.
#[derive(Default)]
struct BusInner {
    handlers: Vec<EventHandler>,
}

/// One security event: the reference `SecurityEvent` telemetry record,
/// field for field (`SecurityEventBus._build_event`).
///
/// Free-form per-site kwargs (`trigger_info`, `request_count`,
/// `redirect_url`, ...) land in [`SecurityEvent::metadata`], the
/// reference's `metadata` dict.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    /// When the event fired (`datetime.now(timezone.utc)`).
    pub timestamp: SystemTime,
    /// The `EVENT_*` value (e.g. `penetration_attempt`).
    pub event_type: String,
    /// The client IP (`ip_address`).
    pub ip_address: String,
    /// The resolved country when a geo handler is wired, `None` otherwise.
    pub country: Option<String>,
    /// The redacted `User-Agent` when one was present.
    pub user_agent: Option<String>,
    /// What the pipeline did (`request_blocked`, `logged_only`, ...).
    pub action_taken: String,
    /// Why, the reference reason string.
    pub reason: String,
    /// The redacted endpoint.
    pub endpoint: Option<String>,
    /// The HTTP method.
    pub method: Option<String>,
    /// The pipeline response time in seconds when measured.
    pub response_time: Option<f64>,
    /// The decorator kind for decorator violations.
    pub decorator_type: Option<String>,
    /// The rule kind for behavioral events.
    pub rule_type: Option<String>,
    /// The emitting handler (`middleware`, `rate_limit`, `ip_ban`).
    pub handler_name: Option<String>,
    /// Every other per-site kwarg, trace headers included.
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl SecurityEvent {
    /// A minimal event with the optional fields unset (the Python
    /// `None`s). Sites that carry endpoint/method/user-agent fields fill
    /// them in on the returned value.
    #[must_use]
    pub fn new(
        event_type: &str,
        ip_address: &str,
        action_taken: &str,
        reason: &str,
        handler_name: &str,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            event_type: event_type.to_owned(),
            ip_address: ip_address.to_owned(),
            country: None,
            user_agent: None,
            action_taken: action_taken.to_owned(),
            reason: reason.to_owned(),
            endpoint: None,
            method: None,
            response_time: None,
            decorator_type: None,
            rule_type: None,
            handler_name: Some(handler_name.to_owned()),
            metadata: serde_json::Map::new(),
        }
    }
}

/// The event mute list (`EventFilter`): a muted event type never reaches
/// the handlers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    /// The `EVENT_*` values muted from telemetry dispatch.
    pub muted_event_types: HashSet<String>,
}

impl EventFilter {
    /// `true` unless the type is muted (`is_event_allowed`).
    #[must_use]
    pub fn is_event_allowed(&self, event_type: &str) -> bool {
        !self.muted_event_types.contains(event_type)
    }
}

/// The event bus over the registered sinks. Cheaply clonable; clones made
/// before [`SecurityEventBus::on_event`] registrations keep an empty list
/// (fork-on-write), so build the bus before sharing it.
///
/// With an enricher installed ([`SecurityEventBus::with_enricher`]) the bus
/// plays the reference `CompositeAgentHandler` role: the filter applies
/// first, then the enrichment runs once, then every handler observes the
/// same enriched event.
#[derive(Clone, Default)]
pub struct SecurityEventBus {
    enabled: bool,
    filter: Option<EventFilter>,
    enricher: Option<Arc<EventEnricher>>,
    inner: Arc<BusInner>,
}

impl SecurityEventBus {
    /// A bus that forwards to handlers when `enabled` (the
    /// `agent_enable_events` gate; the reference sends nothing while it
    /// is off).
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            filter: None,
            enricher: None,
            inner: Arc::default(),
        }
    }

    /// Set the mute list (`event_filter=` in the reference constructor).
    #[must_use]
    pub fn with_filter(mut self, filter: EventFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Install the enrichment pass (`CompositeAgentHandler(enricher=...)`):
    /// every dispatched event is enriched once before the handlers run.
    #[must_use]
    pub fn with_enricher(mut self, enricher: EventEnricher) -> Self {
        self.enricher = Some(Arc::new(enricher));
        self
    }

    /// Register one handler; later registrations fire after earlier ones.
    #[must_use]
    pub fn on_event(self, handler: EventHandler) -> Self {
        let mut handlers: Vec<EventHandler> = Arc::try_unwrap(self.inner)
            .map_or_else(|shared| shared.handlers.clone(), |inner| inner.handlers);
        handlers.push(handler);
        Self {
            enabled: self.enabled,
            filter: self.filter,
            enricher: self.enricher,
            inner: Arc::new(BusInner { handlers }),
        }
    }

    /// Dispatch one built event to every handler, one panic per handler
    /// swallowed (the reference's `except Exception` around `send_event`).
    pub fn send_event(&self, event: &SecurityEvent) {
        if !self.enabled {
            return;
        }
        if let Some(filter) = &self.filter
            && !filter.is_event_allowed(&event.event_type)
        {
            return;
        }
        let mut enriched = event.clone();
        if let Some(enricher) = &self.enricher {
            enricher.enrich_event(&mut enriched);
        }
        for handler in &self.inner.handlers {
            let _ = catch_unwind(AssertUnwindSafe(|| handler(&enriched)));
        }
    }

    /// The middleware-event emission (`send_middleware_event`): builds
    /// the `SecurityEvent` under `handler_name = "middleware"` and
    /// dispatches it. `ip_address` is the caller-resolved client IP; the
    /// reference's per-site kwargs arrive through
    /// [`SecurityEvent::metadata`] on the pre-built path
    /// ([`SecurityEventBus::send_event`]).
    pub fn send_middleware_event(
        &self,
        event_type: &str,
        ip_address: &str,
        action_taken: &str,
        reason: &str,
    ) {
        self.send_event(&SecurityEvent::new(
            event_type,
            ip_address,
            action_taken,
            reason,
            MIDDLEWARE_HANDLER_NAME,
        ));
    }
}

#[cfg(test)]
mod enrichment_tests {
    use super::*;
    use crate::enrichment::{EnrichmentIdentity, EventEnricher};
    use crate::event_types::{
        ENRICHMENT_KEY_RECENT_EVENT_COUNT, ENRICHMENT_KEY_SERVICE_NAME,
        ENRICHMENT_KEY_THREAT_SCORE, EVENT_IP_BLOCKED, EVENT_PENETRATION_ATTEMPT,
    };
    use std::sync::Mutex;

    #[test]
    fn an_installed_enricher_enriches_before_the_handlers() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = SecurityEventBus::new(true)
            .with_enricher(EventEnricher::new(EnrichmentIdentity {
                service_name: "edge-svc".to_owned(),
                ..EnrichmentIdentity::new()
            }))
            .on_event(Arc::new(move |event: &SecurityEvent| {
                sink.lock()
                    .expect("sink")
                    .push(event.metadata[ENRICHMENT_KEY_SERVICE_NAME].clone());
            }));
        bus.send_middleware_event(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "sqli",
        );
        let records = seen.lock().expect("sink").clone();
        assert_eq!(records, vec![serde_json::json!("edge-svc")]);
    }

    #[test]
    fn every_handler_observes_the_same_enriched_event_and_the_input_is_untouched() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = SecurityEventBus::new(true)
            .with_enricher(EventEnricher::new(EnrichmentIdentity::new()))
            .on_event(Arc::new(move |event: &SecurityEvent| {
                sink.lock().expect("sink").push(event.clone());
            }))
            .on_event(Arc::new(|_: &SecurityEvent| {}));
        let event = SecurityEvent::new(
            EVENT_IP_BLOCKED,
            "192.0.2.9",
            "request_blocked",
            "r",
            "middleware",
        );
        bus.send_event(&event);
        let events = seen.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].metadata[ENRICHMENT_KEY_THREAT_SCORE], 50);
        assert!(
            !event.metadata.contains_key(ENRICHMENT_KEY_THREAT_SCORE),
            "the caller's event stays unenriched"
        );
    }

    #[test]
    fn muted_events_skip_enrichment_and_disabled_buses_skip_dispatch() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = SecurityEventBus::new(true)
            .with_filter(EventFilter {
                muted_event_types: HashSet::from([EVENT_IP_BLOCKED.to_owned()]),
            })
            .with_enricher(EventEnricher::new(EnrichmentIdentity::new()))
            .on_event(Arc::new(move |event: &SecurityEvent| {
                sink.lock().expect("sink").push(event.clone());
            }));
        bus.send_middleware_event(EVENT_IP_BLOCKED, "192.0.2.9", "request_blocked", "r");
        assert!(
            seen.lock().expect("sink").is_empty(),
            "muted events never enrich"
        );

        let sink2 = Arc::clone(&seen);
        let silent = SecurityEventBus::new(false)
            .with_enricher(EventEnricher::new(EnrichmentIdentity::new()))
            .on_event(Arc::new(move |event: &SecurityEvent| {
                sink2.lock().expect("sink").push(event.clone());
            }));
        silent.send_middleware_event(EVENT_IP_BLOCKED, "192.0.2.9", "request_blocked", "r");
        assert!(
            seen.lock().expect("sink").is_empty(),
            "disabled buses never dispatch"
        );
    }

    #[test]
    fn the_enrichment_collaborators_reach_the_bus_dispatch() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = SecurityEventBus::new(true)
            .with_enricher(
                EventEnricher::new(EnrichmentIdentity::new())
                    .with_recent_event_count(Arc::new(|_, _| 3)),
            )
            .on_event(Arc::new(move |event: &SecurityEvent| {
                sink.lock()
                    .expect("sink")
                    .push(event.metadata[ENRICHMENT_KEY_RECENT_EVENT_COUNT].clone());
            }));
        bus.send_middleware_event(EVENT_IP_BLOCKED, "192.0.2.9", "request_blocked", "r");
        assert_eq!(
            seen.lock().expect("sink").as_slice(),
            [serde_json::json!(3)]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::{
        EVENT_IP_BANNED, EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY, EVENT_PENETRATION_ATTEMPT,
        EVENT_RATE_LIMITED,
    };
    use std::sync::Mutex;

    fn collect() -> (Arc<Mutex<Vec<String>>>, SecurityEventBus) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = SecurityEventBus::new(true).on_event(Arc::new(move |event: &SecurityEvent| {
            sink.lock().expect("sink").push(event.event_type.clone());
        }));
        (seen, bus)
    }

    #[test]
    fn middleware_event_carries_the_reference_fields() {
        let (seen, bus) = collect();
        bus.send_middleware_event(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.7",
            "request_blocked",
            "Penetration attempt detected: xss",
        );
        let events = seen.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "penetration_attempt");
    }

    #[test]
    fn disabled_bus_sends_nothing() {
        let bus = SecurityEventBus::new(false);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let handler: EventHandler = Arc::new(move |_: &SecurityEvent| {
            sink.lock().expect("sink").push("fired".to_owned());
        });
        // the handler itself records when its transport is invoked
        handler(&SecurityEvent::new(
            EVENT_RATE_LIMITED,
            "192.0.2.1",
            "request_blocked",
            "r",
            MIDDLEWARE_HANDLER_NAME,
        ));
        assert_eq!(*seen.lock().expect("sink"), vec!["fired".to_owned()]);
        // the disabled bus never drives it
        let bus = bus.on_event(handler);
        bus.send_middleware_event(EVENT_RATE_LIMITED, "192.0.2.1", "request_blocked", "r");
        assert_eq!(
            seen.lock().expect("sink").len(),
            1,
            "the disabled bus must not fire the handler again"
        );
    }

    #[test]
    fn muted_types_skip_handlers() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = SecurityEventBus::new(true)
            .with_filter(EventFilter {
                muted_event_types: HashSet::from([EVENT_PENETRATION_ATTEMPT.to_owned()]),
            })
            .on_event(Arc::new(move |event: &SecurityEvent| {
                sink.lock().expect("sink").push(event.event_type.clone());
            }));
        bus.send_middleware_event(EVENT_PENETRATION_ATTEMPT, "192.0.2.1", "logged_only", "r");
        bus.send_middleware_event(EVENT_RATE_LIMITED, "192.0.2.1", "request_blocked", "r");
        assert_eq!(seen.lock().expect("sink").as_slice(), ["rate_limited"]);
    }

    #[test]
    fn handler_panics_do_not_break_the_bus() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let panicky: EventHandler = Arc::new(|_: &SecurityEvent| panic!("handler blew up"));
        let good: EventHandler = Arc::new(move |event: &SecurityEvent| {
            sink.lock().expect("sink").push(event.event_type.clone());
        });
        let bus = SecurityEventBus::new(true).on_event(panicky).on_event(good);
        bus.send_middleware_event(EVENT_IP_BANNED, "192.0.2.1", "banned", "threshold");
        assert_eq!(seen.lock().expect("sink").as_slice(), ["ip_banned"]);
    }

    #[test]
    fn event_type_values_cover_the_reference_set() {
        assert_eq!(EVENT_TYPE_VALUES.len(), 39);
        assert!(EVENT_TYPE_VALUES.contains(&EVENT_PENETRATION_ATTEMPT));
        assert!(EVENT_TYPE_VALUES.contains(&EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn a_registered_sink_receives_the_sent_event() {
        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&seen);
        let bus = SecurityEventBus::new(true).on_event(Arc::new(move |_: &SecurityEvent| {
            sink.lock().expect("sink").push("fired".to_owned());
        }));
        let event = SecurityEvent::new(
            "rate_limited",
            "192.0.2.9",
            "request_blocked",
            "rate limited",
            "rate_limit",
        );
        bus.send_event(&event);
        assert_eq!(seen.lock().expect("sink").len(), 1);
    }

    #[test]
    fn chaining_two_registrations_keeps_both_handlers() {
        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // registering on a bus already holding a handler takes the shared
        // clone path: both handlers fire, in registration order
        let first = std::sync::Arc::clone(&seen);
        let bus = SecurityEventBus::new(true).on_event(Arc::new(move |_: &SecurityEvent| {
            first.lock().expect("sink").push("first".to_owned());
        }));
        let second = std::sync::Arc::clone(&seen);
        let bus = bus.on_event(Arc::new(move |_: &SecurityEvent| {
            second.lock().expect("sink").push("second".to_owned());
        }));
        let event = SecurityEvent::new(
            "rate_limited",
            "192.0.2.9",
            "request_blocked",
            "rate limited",
            "rate_limit",
        );
        bus.send_event(&event);
        let log = seen.lock().expect("sink").clone();
        assert_eq!(log, vec!["first".to_owned(), "second".to_owned()]);
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;
    use crate::event_types::EVENT_PENETRATION_ATTEMPT;
    use std::sync::Mutex;

    #[test]
    fn registering_on_a_shared_bus_forks_the_shared_handler_list() {
        // a clone taken before the registration keeps the inner Arc shared,
        // so the fork-on-write registration clones the shared handler list
        let bus = SecurityEventBus::new(true);
        let shared = bus.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = bus.on_event(Arc::new(move |event: &SecurityEvent| {
            sink.lock().expect("sink").push(event.event_type.clone());
        }));
        bus.send_middleware_event(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "Penetration attempt detected",
        );
        assert_eq!(
            *seen.lock().expect("sink"),
            vec![EVENT_PENETRATION_ATTEMPT.to_owned()]
        );
        // the pre-registration clone forked before the handler landed: it
        // holds no handlers and still dispatches nothing
        shared.send_middleware_event(
            EVENT_PENETRATION_ATTEMPT,
            "192.0.2.1",
            "request_blocked",
            "Penetration attempt detected",
        );
        assert_eq!(
            seen.lock().expect("sink").len(),
            1,
            "the forked handle never grew the registered handler"
        );
    }
}
