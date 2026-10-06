//! The event enrichment layer: the reference `enricher.py`
//! (`EventEnricher` + `ThreatScorer`) and the `ENRICHMENT_KEY_*` family
//! from `event_types.py`.
//!
//! Four steps, always in this order, matching the reference:
//!
//! 1. identity - `guard.project_id` (when configured), `guard.service.name`
//!    (always), `guard.deployment.environment` (when present in the
//!    resource attributes under `deployment.environment`);
//! 2. threat score - the deterministic event-type map
//!    ([`ThreatScorer::score_for`], default 20);
//! 3. dynamic-rule correlation - the injected matcher answers
//!    `(rule_id, rule_version)` or `None` (the reference
//!    `dynamic_rule_handler.match_event`; this port keeps the collaborator
//!    a closure because the unified config/manager surface is the engine's
//!    caller-driven shape);
//! 4. behavior correlation - the injected recent-count closure answers the
//!    in-window hit count for the IP (the reference
//!    `BehaviorTracker.get_recent_event_count`), and the correlation key is
//!    `sha256(ip|service|bucket)[:16]` with `bucket = floor(now / 300)`, so
//!    the IP never reaches the wire.
//!
//! Failure semantics mirror the reference exactly: the enrichment runs
//! against the event in place under one guard, so the steps that completed
//! before a panicking collaborator keep their mutations and the event still
//! dispatches (the reference's log line promises "the event will be sent
//! unenriched"; the Rust failure channel is the same silent-skip convention
//! the bus and collector keep around handler panics).
//!
//! # Example
//!
//! ```
//! use guard_core_rs::enrichment::{EnrichmentIdentity, EventEnricher, ThreatScorer};
//! use guard_core_rs::event_types::{
//!     ENRICHMENT_KEY_PROJECT_ID, ENRICHMENT_KEY_SERVICE_NAME, ENRICHMENT_KEY_THREAT_SCORE,
//!     EVENT_PENETRATION_ATTEMPT,
//! };
//! use guard_core_rs::events::SecurityEvent;
//!
//! let mut enricher = EventEnricher::new(EnrichmentIdentity {
//!     project_id: Some("proj-42".to_owned()),
//!     service_name: "checkout-api".to_owned(),
//!     resource_attributes: Default::default(),
//! });
//! let mut event = SecurityEvent::new(
//!     EVENT_PENETRATION_ATTEMPT,
//!     "192.0.2.1",
//!     "request_blocked",
//!     "sqli",
//!     "middleware",
//! );
//! enricher.enrich_event(&mut event);
//!
//! assert_eq!(event.metadata[ENRICHMENT_KEY_SERVICE_NAME], "checkout-api");
//! assert_eq!(event.metadata[ENRICHMENT_KEY_PROJECT_ID], "proj-42");
//! assert_eq!(
//!     event.metadata[ENRICHMENT_KEY_THREAT_SCORE],
//!     ThreatScorer::score_for(EVENT_PENETRATION_ATTEMPT)
//! );
//! ```

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::event_types::{
    ENRICHMENT_KEY_BEHAVIOR_KEY, ENRICHMENT_KEY_DEPLOYMENT_ENV, ENRICHMENT_KEY_PROJECT_ID,
    ENRICHMENT_KEY_RECENT_EVENT_COUNT, ENRICHMENT_KEY_RULE_ID, ENRICHMENT_KEY_RULE_VERSION,
    ENRICHMENT_KEY_SERVICE_NAME, ENRICHMENT_KEY_THREAT_SCORE,
};
use crate::events::SecurityEvent;
use crate::metrics::SecurityMetric;

/// `EVENT_BEHAVIOR_VIOLATION`-window constant
/// (`_BEHAVIOR_CORRELATION_WINDOW_SECONDS`).
pub const BEHAVIOR_CORRELATION_WINDOW_SECONDS: u64 = 300;

/// `_DEFAULT_THREAT_SCORE`: the score an event type missing from the map
/// takes.
pub const DEFAULT_THREAT_SCORE: u32 = 20;

/// The dynamic-rule correlation collaborator (`match_event`): answers the
/// matched `(rule_id, rule_version)` or `None`.
pub type RuleMatcher = Arc<dyn Fn(&SecurityEvent) -> Option<(String, String)> + Send + Sync>;

/// The behavior-correlation collaborator (`get_recent_event_count`): the
/// in-window event count for one IP over `window_seconds`.
pub type RecentEventCount = Arc<dyn Fn(&str, u64) -> u64 + Send + Sync>;

/// The unix-seconds clock (`time.time()`); injectable for deterministic
/// bucket tests.
pub type EnrichmentClock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// The identity inputs the reference reads off `SecurityConfig`
/// (`agent_project_id`, `otel_service_name`, `otel_resource_attributes`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrichmentIdentity {
    /// `agent_project_id`; stamped as [`ENRICHMENT_KEY_PROJECT_ID`] when
    /// set.
    pub project_id: Option<String>,
    /// `otel_service_name`; stamped as [`ENRICHMENT_KEY_SERVICE_NAME`]
    /// always.
    pub service_name: String,
    /// `otel_resource_attributes`; `deployment.environment` becomes
    /// [`ENRICHMENT_KEY_DEPLOYMENT_ENV`].
    pub resource_attributes: BTreeMap<String, String>,
}

impl EnrichmentIdentity {
    /// The default identity: the reference config defaults
    /// (`service_name = "guard-core"`, no project id, no attributes).
    #[must_use]
    pub fn new() -> Self {
        Self {
            project_id: None,
            service_name: String::from("guard-core"),
            resource_attributes: BTreeMap::new(),
        }
    }
}

/// The deterministic event-type threat score (`ThreatScorer`).
pub struct ThreatScorer;

impl ThreatScorer {
    /// `score_for`: the reference `_THREAT_SCORE_MAP` values, default
    /// [`DEFAULT_THREAT_SCORE`] for a type outside the map.
    #[must_use]
    pub fn score_for(event_type: &str) -> u32 {
        match event_type {
            crate::event_types::EVENT_PENETRATION_ATTEMPT => 90,
            crate::event_types::EVENT_IP_BANNED => 70,
            crate::event_types::EVENT_EMERGENCY_MODE => 60,
            crate::event_types::EVENT_IP_BLOCKED
            | crate::event_types::EVENT_BEHAVIOR_VIOLATION
            | crate::event_types::EVENT_CLOUD_BLOCKED
            | crate::event_types::EVENT_COUNTRY_BLOCKED
            | crate::event_types::EVENT_DECORATOR_VIOLATION
            | crate::event_types::EVENT_AUTHENTICATION_FAILED
            | crate::event_types::EVENT_EMERGENCY_MODE_BLOCK
            | crate::event_types::EVENT_DYNAMIC_RULE_VIOLATION
            | crate::event_types::EVENT_PATTERN_DETECTED
            | crate::event_types::EVENT_SUSPICIOUS_REQUEST => 50,
            crate::event_types::EVENT_DYNAMIC_RULE_APPLIED
            | crate::event_types::EVENT_CSP_VIOLATION
            | crate::event_types::EVENT_CONTENT_FILTERED
            | crate::event_types::EVENT_CUSTOM_REQUEST_CHECK
            | crate::event_types::EVENT_DECODING_ERROR
            | crate::event_types::EVENT_REDIS_ERROR
            | crate::event_types::EVENT_IP_BAN_FAILED
            | crate::event_types::EVENT_DETECTION_ENGINE_CALLBACK_ERROR
            | crate::event_types::EVENT_PATTERN_ANOMALY_TIMEOUT
            | crate::event_types::EVENT_PATTERN_ANOMALY_SLOW_EXECUTION
            | crate::event_types::EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY => 40,
            crate::event_types::EVENT_ACCESS_DENIED
            | crate::event_types::EVENT_USER_AGENT_BLOCKED
            | crate::event_types::EVENT_SECURITY_BYPASS => 30,
            crate::event_types::EVENT_RATE_LIMITED
            | crate::event_types::EVENT_GEO_LOOKUP_FAILED
            | crate::event_types::EVENT_REDIS_CONNECTION
            | crate::event_types::EVENT_ROUTE_UNRESOLVED => 20,
            crate::event_types::EVENT_IP_UNBANNED
            | crate::event_types::EVENT_HTTPS_ENFORCED
            | crate::event_types::EVENT_DYNAMIC_RULE_UPDATED
            | crate::event_types::EVENT_PATH_EXCLUDED
            | crate::event_types::EVENT_PATTERN_ADDED
            | crate::event_types::EVENT_PATTERN_REMOVED
            | crate::event_types::EVENT_RATE_LIMIT_SCRIPT_RELOADED
            | crate::event_types::EVENT_SECURITY_HEADERS_APPLIED => 10,
            _ => DEFAULT_THREAT_SCORE,
        }
    }
}

/// The enrichment pass (`EventEnricher`). Clone-safe; install one on the
/// [`crate::events::SecurityEventBus`] with
/// [`crate::events::SecurityEventBus::with_enricher`] or drive it directly.
#[derive(Clone)]
pub struct EventEnricher {
    identity: EnrichmentIdentity,
    rule_matcher: Option<RuleMatcher>,
    recent_event_count: Option<RecentEventCount>,
    clock: EnrichmentClock,
}

impl core::fmt::Debug for EventEnricher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventEnricher")
            .field("identity", &self.identity)
            .field("rule_matcher", &self.rule_matcher.is_some())
            .field("recent_event_count", &self.recent_event_count.is_some())
            .finish_non_exhaustive()
    }
}

impl EventEnricher {
    /// An enricher over the identity inputs; the collaborators attach via
    /// the builders.
    #[must_use]
    pub fn new(identity: EnrichmentIdentity) -> Self {
        Self {
            identity,
            rule_matcher: None,
            recent_event_count: None,
            clock: Arc::new(default_clock),
        }
    }

    /// Attach the dynamic-rule correlation (`match_event`).
    #[must_use]
    pub fn with_rule_matcher(mut self, matcher: RuleMatcher) -> Self {
        self.rule_matcher = Some(matcher);
        self
    }

    /// Attach the behavior correlation (`get_recent_event_count`).
    #[must_use]
    pub fn with_recent_event_count(mut self, counter: RecentEventCount) -> Self {
        self.recent_event_count = Some(counter);
        self
    }

    /// Override the clock (deterministic buckets in tests).
    #[must_use]
    pub fn with_clock(mut self, clock: EnrichmentClock) -> Self {
        self.clock = clock;
        self
    }

    /// `enrich_event`: the four steps in reference order, in place, under
    /// one panic guard (completed steps keep their mutations, the event
    /// always dispatches).
    pub fn enrich_event(&self, event: &mut SecurityEvent) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            self.apply_identity(&mut event.metadata);
            Self::apply_threat_score(event);
            self.apply_rule_correlation(event);
            self.apply_behavior_correlation(event);
        }));
    }

    /// `enrich_metric`: the identity stamping onto the tags bag, under the
    /// same guard.
    pub fn enrich_metric(&self, metric: &mut SecurityMetric) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let mut bag: BTreeMap<String, String> = BTreeMap::new();
            self.apply_identity_strings(&mut bag);
            for (key, value) in bag {
                metric.tags.insert(key, value);
            }
        }));
    }

    /// `_apply_identity` over a `serde_json` metadata bag.
    fn apply_identity(&self, bag: &mut serde_json::Map<String, serde_json::Value>) {
        if let Some(project_id) = &self.identity.project_id {
            bag.insert(
                ENRICHMENT_KEY_PROJECT_ID.to_owned(),
                serde_json::Value::String(project_id.clone()),
            );
        }
        bag.insert(
            ENRICHMENT_KEY_SERVICE_NAME.to_owned(),
            serde_json::Value::String(self.identity.service_name.clone()),
        );
        if let Some(env) = self
            .identity
            .resource_attributes
            .get("deployment.environment")
        {
            bag.insert(
                ENRICHMENT_KEY_DEPLOYMENT_ENV.to_owned(),
                serde_json::Value::String(env.clone()),
            );
        }
    }

    /// `_apply_identity` over the metric tags bag.
    fn apply_identity_strings(&self, bag: &mut BTreeMap<String, String>) {
        if let Some(project_id) = &self.identity.project_id {
            bag.insert(ENRICHMENT_KEY_PROJECT_ID.to_owned(), project_id.clone());
        }
        bag.insert(
            ENRICHMENT_KEY_SERVICE_NAME.to_owned(),
            self.identity.service_name.clone(),
        );
        if let Some(env) = self
            .identity
            .resource_attributes
            .get("deployment.environment")
        {
            bag.insert(ENRICHMENT_KEY_DEPLOYMENT_ENV.to_owned(), env.clone());
        }
    }

    /// `_apply_threat_score`.
    fn apply_threat_score(event: &mut SecurityEvent) {
        if event.event_type.is_empty() {
            return;
        }
        event.metadata.insert(
            ENRICHMENT_KEY_THREAT_SCORE.to_owned(),
            serde_json::Value::Number(serde_json::Number::from(ThreatScorer::score_for(
                &event.event_type,
            ))),
        );
    }

    /// `_apply_rule_correlation`: the matcher is optional; `None` match
    /// leaves the rule keys out.
    fn apply_rule_correlation(&self, event: &mut SecurityEvent) {
        let Some(matcher) = &self.rule_matcher else {
            return;
        };
        let Some((rule_id, rule_version)) = matcher(event) else {
            return;
        };
        event.metadata.insert(
            ENRICHMENT_KEY_RULE_ID.to_owned(),
            serde_json::Value::String(rule_id),
        );
        event.metadata.insert(
            ENRICHMENT_KEY_RULE_VERSION.to_owned(),
            serde_json::Value::String(rule_version),
        );
    }

    /// `_apply_behavior_correlation`: empty IPs and absent collaborators
    /// skip; the key hashes `ip|service|bucket` and truncates to 16 hex.
    fn apply_behavior_correlation(&self, event: &mut SecurityEvent) {
        let Some(counter) = &self.recent_event_count else {
            return;
        };
        if event.ip_address.is_empty() {
            return;
        }
        let count = counter(&event.ip_address, BEHAVIOR_CORRELATION_WINDOW_SECONDS);
        event.metadata.insert(
            ENRICHMENT_KEY_RECENT_EVENT_COUNT.to_owned(),
            serde_json::Value::Number(serde_json::Number::from(count)),
        );
        let bucket = ((self.clock)() / BEHAVIOR_CORRELATION_WINDOW_SECONDS_F64).floor();
        // The floor of a non-negative clock; the clamp keeps a warped
        // (pre-epoch) clock from wrapping through the sign bit.
        #[allow(clippy::cast_sign_loss)]
        let bucket = bucket.max(0.0) as u64;
        let raw = format!(
            "{}|{}|{}",
            event.ip_address, self.identity.service_name, bucket
        );
        let digest = Sha256::digest(raw.as_bytes());
        event.metadata.insert(
            ENRICHMENT_KEY_BEHAVIOR_KEY.to_owned(),
            serde_json::Value::String(hex_prefix(&digest)),
        );
    }
}

/// The behavior-correlation window as a float (the reference
/// `time // window_seconds` arithmetic).
const BEHAVIOR_CORRELATION_WINDOW_SECONDS_F64: f64 = 300.0;

/// The first 8 digest bytes as 16 lowercase hex chars.
fn hex_prefix(digest: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn default_clock() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| 0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::{
        EVENT_IP_BANNED, EVENT_IP_BLOCKED, EVENT_PENETRATION_ATTEMPT, EVENT_RATE_LIMITED,
    };

    fn event(event_type: &str, ip: &str) -> SecurityEvent {
        SecurityEvent::new(event_type, ip, "request_blocked", "r", "middleware")
    }

    #[test]
    fn the_score_map_carries_the_reference_values() {
        assert_eq!(ThreatScorer::score_for(EVENT_PENETRATION_ATTEMPT), 90);
        assert_eq!(ThreatScorer::score_for(EVENT_IP_BANNED), 70);
        assert_eq!(
            ThreatScorer::score_for(crate::event_types::EVENT_EMERGENCY_MODE),
            60
        );
        assert_eq!(ThreatScorer::score_for(EVENT_IP_BLOCKED), 50);
        assert_eq!(
            ThreatScorer::score_for(crate::event_types::EVENT_SUSPICIOUS_REQUEST),
            50
        );
        assert_eq!(
            ThreatScorer::score_for(crate::event_types::EVENT_REDIS_ERROR),
            40
        );
        assert_eq!(
            ThreatScorer::score_for(crate::event_types::EVENT_PATTERN_ANOMALY_TIMEOUT),
            40
        );
        assert_eq!(
            ThreatScorer::score_for(crate::event_types::EVENT_ACCESS_DENIED),
            30
        );
        assert_eq!(ThreatScorer::score_for(EVENT_RATE_LIMITED), 20);
        assert_eq!(
            ThreatScorer::score_for(crate::event_types::EVENT_IP_UNBANNED),
            10
        );
        assert_eq!(
            ThreatScorer::score_for(crate::event_types::EVENT_SECURITY_HEADERS_APPLIED),
            10
        );
        assert_eq!(
            ThreatScorer::score_for("totally_unknown_type"),
            DEFAULT_THREAT_SCORE
        );
    }

    #[test]
    fn every_reference_event_type_lands_in_the_10_to_90_band() {
        for value in crate::event_types::EVENT_TYPE_VALUES {
            let score = ThreatScorer::score_for(value);
            assert!((10..=90).contains(&score), "{value} scored {score}");
        }
    }

    #[test]
    fn identity_stamps_service_always_and_the_rest_when_configured() {
        let bare = EventEnricher::new(EnrichmentIdentity::new());
        let mut e = event(EVENT_IP_BLOCKED, "192.0.2.1");
        bare.enrich_event(&mut e);
        assert_eq!(e.metadata[ENRICHMENT_KEY_SERVICE_NAME], "guard-core");
        assert!(e.metadata.get(ENRICHMENT_KEY_PROJECT_ID).is_none());
        assert!(e.metadata.get(ENRICHMENT_KEY_DEPLOYMENT_ENV).is_none());

        let mut attributes = BTreeMap::new();
        attributes.insert("deployment.environment".to_owned(), "production".to_owned());
        attributes.insert("service.version".to_owned(), "4.3.1".to_owned());
        let configured = EventEnricher::new(EnrichmentIdentity {
            project_id: Some("proj-42".to_owned()),
            service_name: "checkout-api".to_owned(),
            resource_attributes: attributes,
        });
        let mut e = event(EVENT_IP_BLOCKED, "192.0.2.1");
        configured.enrich_event(&mut e);
        assert_eq!(e.metadata[ENRICHMENT_KEY_PROJECT_ID], "proj-42");
        assert_eq!(e.metadata[ENRICHMENT_KEY_SERVICE_NAME], "checkout-api");
        assert_eq!(e.metadata[ENRICHMENT_KEY_DEPLOYMENT_ENV], "production");
        assert!(
            e.metadata.get("service.version").is_none(),
            "non-guard resource attributes stay out of the bag"
        );
    }

    #[test]
    fn the_threat_score_follows_the_event_type() {
        let enricher = EventEnricher::new(EnrichmentIdentity::new());
        let mut e = event(EVENT_PENETRATION_ATTEMPT, "192.0.2.1");
        enricher.enrich_event(&mut e);
        assert_eq!(e.metadata[ENRICHMENT_KEY_THREAT_SCORE], 90);
    }

    #[test]
    fn rule_correlation_needs_a_matcher_and_a_match() {
        let none = EventEnricher::new(EnrichmentIdentity::new());
        let mut e = event(EVENT_IP_BLOCKED, "192.0.2.1");
        none.enrich_event(&mut e);
        assert!(e.metadata.get(ENRICHMENT_KEY_RULE_ID).is_none());

        let null_match = EventEnricher::new(EnrichmentIdentity::new())
            .with_rule_matcher(Arc::new(|_: &SecurityEvent| None));
        let mut e = event(EVENT_IP_BLOCKED, "192.0.2.1");
        null_match.enrich_event(&mut e);
        assert!(e.metadata.get(ENRICHMENT_KEY_RULE_ID).is_none());

        let matcher = EventEnricher::new(EnrichmentIdentity::new()).with_rule_matcher(Arc::new(
            |_: &SecurityEvent| Some(("rule-7".to_owned(), "v3".to_owned())),
        ));
        let mut e = event(EVENT_IP_BLOCKED, "192.0.2.1");
        matcher.enrich_event(&mut e);
        assert_eq!(e.metadata[ENRICHMENT_KEY_RULE_ID], "rule-7");
        assert_eq!(e.metadata[ENRICHMENT_KEY_RULE_VERSION], "v3");
    }

    #[test]
    fn behavior_correlation_hashes_ip_service_bucket() {
        let enricher = EventEnricher::new(EnrichmentIdentity {
            service_name: "svc".to_owned(),
            ..EnrichmentIdentity::new()
        })
        .with_recent_event_count(Arc::new(|_, _| 7))
        .with_clock(Arc::new(|| 1_000_000.0));
        let mut e = event(EVENT_IP_BLOCKED, "198.51.100.9");
        enricher.enrich_event(&mut e);
        assert_eq!(e.metadata[ENRICHMENT_KEY_RECENT_EVENT_COUNT], 7);
        #[allow(clippy::cast_sign_loss)] // the fixed positive test clock
        let bucket = (1_000_000.0_f64 / 300.0_f64).floor() as u64;
        let expected_input = format!("198.51.100.9|svc|{bucket}");
        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(expected_input.as_bytes());
            hex_prefix(&hasher.finalize())
        };
        assert_eq!(e.metadata[ENRICHMENT_KEY_BEHAVIOR_KEY], expected);
        assert_eq!(
            e.metadata[ENRICHMENT_KEY_BEHAVIOR_KEY]
                .as_str()
                .map(str::len),
            Some(16)
        );
    }

    #[test]
    fn empty_ip_and_absent_tracker_skip_behavior_correlation() {
        let enricher = EventEnricher::new(EnrichmentIdentity::new())
            .with_recent_event_count(Arc::new(|_, _| 5));
        let mut e = event(EVENT_IP_BLOCKED, "");
        enricher.enrich_event(&mut e);
        assert!(e.metadata.get(ENRICHMENT_KEY_RECENT_EVENT_COUNT).is_none());

        let bare = EventEnricher::new(EnrichmentIdentity::new());
        let mut e = event(EVENT_IP_BLOCKED, "192.0.2.1");
        bare.enrich_event(&mut e);
        assert!(e.metadata.get(ENRICHMENT_KEY_RECENT_EVENT_COUNT).is_none());
    }

    #[test]
    fn a_panicking_collaborator_keeps_the_completed_steps_and_the_event() {
        let enricher = EventEnricher::new(EnrichmentIdentity::new()).with_rule_matcher(Arc::new(
            |_: &SecurityEvent| {
                panic!("matcher blew up");
            },
        ));
        let mut e = event(EVENT_IP_BLOCKED, "192.0.2.1");
        enricher.enrich_event(&mut e);
        // identity + threat score already applied (in-place semantics like
        // the reference's mutable metadata dict), rule keys absent, no
        // panic escaped.
        assert_eq!(e.metadata[ENRICHMENT_KEY_SERVICE_NAME], "guard-core");
        assert_eq!(e.metadata[ENRICHMENT_KEY_THREAT_SCORE], 50);
        assert!(e.metadata.get(ENRICHMENT_KEY_RULE_ID).is_none());
    }

    #[test]
    fn metric_enrichment_stamps_the_identity_tags_only() {
        let mut attributes = BTreeMap::new();
        attributes.insert("deployment.environment".to_owned(), "staging".to_owned());
        let enricher = EventEnricher::new(EnrichmentIdentity {
            project_id: Some("proj-1".to_owned()),
            service_name: "edge".to_owned(),
            resource_attributes: attributes,
        });
        let mut tags = BTreeMap::new();
        tags.insert("endpoint".to_owned(), "/pay".to_owned());
        let mut metric = SecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: crate::metrics::METRIC_RESPONSE_TIME.to_owned(),
            value: 0.25,
            endpoint: None,
            tags,
        };
        enricher.enrich_metric(&mut metric);
        assert_eq!(
            metric
                .tags
                .get(ENRICHMENT_KEY_PROJECT_ID)
                .map(String::as_str),
            Some("proj-1")
        );
        assert_eq!(
            metric
                .tags
                .get(ENRICHMENT_KEY_SERVICE_NAME)
                .map(String::as_str),
            Some("edge")
        );
        assert_eq!(
            metric
                .tags
                .get(ENRICHMENT_KEY_DEPLOYMENT_ENV)
                .map(String::as_str),
            Some("staging")
        );
        assert!(
            !metric.tags.contains_key(ENRICHMENT_KEY_THREAT_SCORE),
            "metrics carry no threat score"
        );
        assert_eq!(
            metric.tags.get("endpoint").map(String::as_str),
            Some("/pay")
        );
    }
}
