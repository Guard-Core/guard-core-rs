//! The response-side pass, ported from the reference `process_response`.
//!
//! This is the pass every other engine runs on the way out (the go
//! `Engine.ProcessResponse` is the structural template): the global
//! `return_pattern` behavior rules evaluate the produced response and may
//! ban, the security-header set lands on the response, and the CORS
//! verdict headers compose on top for a request carrying an `Origin`.
//! Reference source: `core/responses/factory.py`.
//!
//! Return rules never modify the response: a matched rule dispatches its
//! configured action (the `ban` action lands in the caller's IP-ban store
//! with the reference `behavioral_violation` reason) and the response
//! passes through with the headers applied.
//!
//! The response-body capture is the caller's seam, bounded by the
//! reference `behavior_max_response_body_inspect_bytes` budget: `status:`
//! patterns never touch it, and the other pattern kinds see only the
//! leading prefix passed in (`body_prefix`).
//!
//! # Example
//!
//! ```
//! use std::sync::{Arc, Mutex};
//! use std::time::SystemTime;
//!
//! use guard_core_engine::behavior::{BehaviorRule, BehaviorTracker};
//! use guard_core_engine::ip_ban::IpBanManager;
//! use guard_core_engine::security_headers::SecurityHeadersConfig;

//! use guard_core_rs::process_response::{RequestBits, ResponseBits, ResponseProcessor};
//!
//! let global_rules = vec![BehaviorRule {
//!     rule_type: "return_pattern".to_owned(),
//!     threshold: 2,
//!     window: 3600,
//!     pattern: "status:404".to_owned(),
//!     action: "ban".to_owned(),
//!     ban_duration: Some(900),
//!     correlate_with_detection: false,
//! }];
//! let processor = ResponseProcessor::new(
//!     Some(SecurityHeadersConfig::reference_default()),
//!     None,
//!     global_rules,
//!     Arc::new(Mutex::new(BehaviorTracker::new())),
//!     IpBanManager::new(),
//!     true,
//!     262_144,
//!     false,
//! );
//! let request = RequestBits {
//!     method: "GET".to_owned(),
//!     url_path: "/api".to_owned(),
//!     client_ip: "192.0.2.10".to_owned(),
//!     origin: None,
//! };
//! let mut response = ResponseBits {
//!     status: 404,
//!     body: Some("ok".to_owned()),
//!     headers: std::collections::BTreeMap::default(),
//! };
//! let action = processor.process(&request, &mut response, None, SystemTime::now());
//! assert_eq!(action, None, "below the threshold the rule only tracks");
//! assert_eq!(response.status, 404, "return rules never modify the response");
//! assert_eq!(
//!     response.headers.get("X-Content-Type-Options").map(String::as_str),
//!     Some("nosniff"),
//!     "the security-header set lands on the response"
//! );
//! ```

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::metrics::MetricsCollector;
use guard_core_engine::behavior::{
    BehaviorAction, BehaviorRule, BehaviorTracker, DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
};
use guard_core_engine::cors::{CorsConfig, cors_response_headers, downgrade_wildcard_credentials};
use guard_core_engine::ip_ban::IpBanManager;
use guard_core_engine::security_headers::{
    SecurityHeadersConfig, security_headers as render_security_headers,
};

pub use guard_core_engine::behavior::rule_from_config;

/// The request facts the pass needs (the subset of the reference
/// `GuardRequest` the response factory reads).
#[derive(Debug, Clone, Default)]
pub struct RequestBits {
    pub method: String,
    pub url_path: String,
    pub client_ip: String,
    /// The request's `Origin` header value, `None` when absent.
    pub origin: Option<String>,
}

/// The response the pass mutates in place: the status and body pass
/// through untouched, the headers gain the security-header set and the
/// CORS verdict.
#[derive(Debug, Clone, Default)]
pub struct ResponseBits {
    pub status: u16,
    pub body: Option<String>,
    pub headers: std::collections::BTreeMap<String, String>,
}

/// The `process_response` pass over one response.
///
/// `tracker` and `bans` are shared state (the reference `BehaviorTracker`
/// singleton and `ip_ban_manager`): behavior windows and bans recorded
/// here are visible to the request-side pipeline.
pub struct ResponseProcessor {
    security_headers: Option<SecurityHeadersConfig>,
    cors: Option<CorsConfig>,
    global_rules: Vec<BehaviorRule>,
    tracker: Arc<Mutex<BehaviorTracker>>,
    bans: IpBanManager,
    scan_response_body: bool,
    max_inspect_bytes: usize,
    passive_mode: bool,
    metrics: Option<MetricsCollector>,
}

impl ResponseProcessor {
    /// Build the pass. `security_headers: None` (or a disabled config)
    /// renders no security headers, exactly like the reference
    /// `apply_security_headers` guard; the CORS config is downgraded (the
    /// wildcard + credentials resolution) once at construction.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        security_headers: Option<SecurityHeadersConfig>,
        cors: Option<CorsConfig>,
        global_rules: Vec<BehaviorRule>,
        tracker: Arc<Mutex<BehaviorTracker>>,
        bans: IpBanManager,
        scan_response_body: bool,
        max_inspect_bytes: usize,
        passive_mode: bool,
    ) -> Self {
        let mut cors = cors;
        if let Some(cors) = cors.as_mut() {
            downgrade_wildcard_credentials(cors);
        }
        Self {
            security_headers,
            cors,
            global_rules,
            tracker,
            bans,
            scan_response_body,
            max_inspect_bytes,
            passive_mode,
            metrics: None,
        }
    }

    /// Wire the reference `MetricsCollector` (the `agent_enable_metrics`
    /// emission point: the response factory's
    /// `collect_request_metrics`, between the behavioral rules and the
    /// security headers). Without this builder nothing is emitted.
    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricsCollector) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Run the pass: the global `return_pattern` rules first (the route's
    /// own rules are the caller's per-route extension with the same seam),
    /// then the security headers, then the CORS verdict. Returns the
    /// action the last tripped rule dispatched, if any.
    pub fn process(
        &self,
        request: &RequestBits,
        response: &mut ResponseBits,
        body_prefix: Option<&[u8]>,
        now: SystemTime,
    ) -> Option<BehaviorAction> {
        let mut last_action = None;
        if !self.global_rules.is_empty() {
            let prefix = self.scan_response_body.then_some(body_prefix).flatten();
            let mut tracker = self.tracker.lock().expect("behavior tracker");
            for rule in &self.global_rules {
                if rule.rule_type != "return_pattern" {
                    continue;
                }
                let tripped = tracker.track_return_pattern(
                    &format!("{}:{}", request.method, request.url_path),
                    &request.client_ip,
                    response.status,
                    prefix,
                    rule,
                    self.max_inspect_bytes,
                    now,
                );
                if tripped {
                    let action = BehaviorTracker::dispatch_action(
                        rule,
                        &request.client_ip,
                        self.passive_mode,
                    );
                    if let (BehaviorAction::Ban { duration }, Ok(ip)) =
                        (&action, request.client_ip.parse())
                    {
                        let _ = self.bans.ban_ip(ip, *duration, "behavioral_violation");
                    }
                    last_action = Some(action);
                }
            }
            drop(tracker);
        }

        // The reference emits the per-request metrics between the
        // behavioral rules and the security headers (`factory.py`); the
        // pass itself never times the request, so the response-time
        // sample is the caller's to add.
        if let Some(metrics) = &self.metrics {
            metrics.collect_request_metrics(
                &request.url_path,
                &request.method,
                None,
                response.status,
            );
        }

        if let Some(config) = self
            .security_headers
            .as_ref()
            .filter(|config| config.enabled)
        {
            for (name, value) in render_security_headers(config) {
                response.headers.insert(name, value);
            }
        }

        if let Some(cors) = self.cors.as_ref() {
            for (name, value) in cors_response_headers(cors, request.origin.as_deref()) {
                response.headers.insert(name, value);
            }
        }

        last_action
    }
}

/// The free-function shape for a caller that owns the pieces.
///
/// Global `return_pattern` rules against the tracker, then the security
/// headers, then the CORS verdict, in the reference `process_response`
/// order. See [`ResponseProcessor`] for the stateful shape.
#[allow(clippy::too_many_arguments)]
pub fn process_response(
    security_headers: Option<&SecurityHeadersConfig>,
    cors: Option<&CorsConfig>,
    global_rules: &[BehaviorRule],
    tracker: &Arc<Mutex<BehaviorTracker>>,
    request: &RequestBits,
    response: &mut ResponseBits,
    passive_mode: bool,
    now: SystemTime,
) -> Vec<BehaviorAction> {
    let mut actions = Vec::new();
    if !global_rules.is_empty() {
        let mut tracker = tracker.lock().expect("behavior tracker");
        for rule in global_rules {
            if rule.rule_type != "return_pattern" {
                continue;
            }
            // `status:` patterns need no body; a body pattern without the
            // caller's captured prefix cannot evaluate (no match), so the
            // free-function shape passes no prefix.
            if tracker.track_return_pattern(
                &format!("{}:{}", request.method, request.url_path),
                &request.client_ip,
                response.status,
                None,
                rule,
                DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
                now,
            ) {
                let action =
                    BehaviorTracker::dispatch_action(rule, &request.client_ip, passive_mode);
                actions.push(action);
            }
        }
    }
    if let Some(config) = security_headers.filter(|config| config.enabled) {
        for (name, value) in render_security_headers(config) {
            response.headers.insert(name, value);
        }
    }
    if let Some(cors) = cors {
        let mut resolved = cors.clone();
        downgrade_wildcard_credentials(&mut resolved);
        for (name, value) in cors_response_headers(&resolved, request.origin.as_deref()) {
            response.headers.insert(name, value);
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core_engine::security_headers::HstsConfig;

    fn processor(
        rules: Vec<BehaviorRule>,
        headers: Option<SecurityHeadersConfig>,
        cors: Option<CorsConfig>,
        bans: IpBanManager,
    ) -> ResponseProcessor {
        ResponseProcessor::new(
            headers,
            cors,
            rules,
            Arc::new(Mutex::new(BehaviorTracker::new())),
            bans,
            true,
            DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
            false,
        )
    }

    fn request(origin: Option<&str>) -> RequestBits {
        RequestBits {
            method: "GET".to_owned(),
            url_path: "/api".to_owned(),
            client_ip: "192.0.2.10".to_owned(),
            origin: origin.map(ToOwned::to_owned),
        }
    }

    fn ban_rule(threshold: u32) -> BehaviorRule {
        BehaviorRule {
            rule_type: "return_pattern".to_owned(),
            threshold,
            window: 3600,
            pattern: "status:404".to_owned(),
            action: "ban".to_owned(),
            ban_duration: Some(900),
            correlate_with_detection: false,
        }
    }

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn the_pass_renders_headers_and_leaves_the_response_alone() {
        let mut response = ResponseBits {
            status: 404,
            body: Some("ok".to_owned()),
            headers: std::collections::BTreeMap::default(),
        };
        let processor = processor(
            vec![ban_rule(2)],
            Some(SecurityHeadersConfig::reference_default()),
            None,
            IpBanManager::new(),
        );
        let now = SystemTime::now();
        assert_eq!(
            processor.process(&request(None), &mut response, None, now),
            None
        );
        assert_eq!(response.status, 404);
        assert_eq!(response.body.as_deref(), Some("ok"));
        assert_eq!(
            response
                .headers
                .get("Strict-Transport-Security")
                .map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
    }

    #[test]
    fn disabled_security_headers_render_nothing() {
        let mut response = ResponseBits::default();
        let processor = processor(
            Vec::new(),
            Some(SecurityHeadersConfig {
                enabled: false,
                ..SecurityHeadersConfig::reference_default()
            }),
            None,
            IpBanManager::new(),
        );
        processor.process(&request(None), &mut response, None, SystemTime::now());
        assert!(response.headers.is_empty());
    }

    #[test]
    fn cors_composes_on_top_of_the_security_headers() {
        let mut response = ResponseBits::default();
        let processor = processor(
            Vec::new(),
            Some(SecurityHeadersConfig::reference_default()),
            Some(CorsConfig {
                enabled: true,
                allow_origins: vec!["https://app.example.com".to_owned()],
                ..CorsConfig::default()
            }),
            IpBanManager::new(),
        );
        processor.process(
            &request(Some("https://app.example.com")),
            &mut response,
            None,
            SystemTime::now(),
        );
        assert_eq!(
            response
                .headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("https://app.example.com")
        );
        assert_eq!(
            response.headers.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );

        // A disallowed origin gets no CORS headers but keeps the set.
        let mut response = ResponseBits::default();
        processor.process(
            &request(Some("https://evil.example.com")),
            &mut response,
            None,
            SystemTime::now(),
        );
        assert!(!response.headers.contains_key("Access-Control-Allow-Origin"));
        assert_eq!(
            response.headers.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );
    }

    #[test]
    fn tripped_rules_ban_into_the_shared_store_without_touching_the_response() {
        let bans = IpBanManager::new();
        let mut response = ResponseBits {
            status: 404,
            body: Some("ok".to_owned()),
            headers: std::collections::BTreeMap::default(),
        };
        let processor = processor(
            vec![ban_rule(2)],
            Some(SecurityHeadersConfig::reference_default()),
            None,
            bans.clone(),
        );
        let now = SystemTime::now();
        let req = request(None);
        assert_eq!(processor.process(&req, &mut response, None, now), None);
        assert_eq!(processor.process(&req, &mut response, None, now), None);
        assert!(!bans.is_banned(ip("192.0.2.10")));
        assert_eq!(
            processor.process(&req, &mut response, None, now),
            Some(BehaviorAction::Ban { duration: 900 })
        );
        assert!(
            bans.is_banned(ip("192.0.2.10")),
            "the ban landed in the store"
        );
        assert_eq!(
            response.status, 404,
            "return rules never modify the response"
        );
    }

    #[test]
    fn passive_mode_never_bans() {
        let bans = IpBanManager::new();
        let mut response = ResponseBits {
            status: 404,
            ..ResponseBits::default()
        };
        let processor = ResponseProcessor::new(
            Some(SecurityHeadersConfig::reference_default()),
            None,
            vec![ban_rule(1)],
            Arc::new(Mutex::new(BehaviorTracker::new())),
            bans.clone(),
            true,
            DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
            true,
        );
        let now = SystemTime::now();
        let req = request(None);
        // The first 404 stays below the threshold (no action); the second
        // trips the rule but passive mode reduces the dispatch to a log.
        assert_eq!(processor.process(&req, &mut response, None, now), None);
        assert_eq!(
            processor.process(&req, &mut response, None, now),
            Some(BehaviorAction::LoggedOnly)
        );
        assert!(!bans.is_banned(ip("192.0.2.10")));
    }

    #[test]
    fn body_prefix_only_feeds_body_patterns_within_the_budget() {
        let mut tracker = BehaviorTracker::new();
        let rule = BehaviorRule {
            pattern: "regex:NOT FOUND".to_owned(),
            ..ban_rule(1)
        };
        assert_eq!(
            tracker.check_response_pattern(200, Some(b"oops Not Found"), &rule.pattern, 262_144),
            Some(true)
        );
    }

    #[test]
    fn hsts_default_extends_the_set_like_the_reference_block() {
        let mut response = ResponseBits::default();
        let processor = processor(
            Vec::new(),
            Some(SecurityHeadersConfig {
                hsts: Some(HstsConfig {
                    max_age: Some(1000),
                    ..HstsConfig::default()
                }),
                ..SecurityHeadersConfig::reference_default()
            }),
            None,
            IpBanManager::new(),
        );
        processor.process(&request(None), &mut response, None, SystemTime::now());
        assert_eq!(
            response
                .headers
                .get("Strict-Transport-Security")
                .map(String::as_str),
            Some("max-age=1000; includeSubDomains")
        );
    }

    #[test]
    fn the_free_function_shape_matches_the_stateful_one() {
        let tracker = Arc::new(Mutex::new(BehaviorTracker::new()));
        let rules = vec![ban_rule(1)];
        let headers = SecurityHeadersConfig::reference_default();
        let mut response = ResponseBits {
            status: 404,
            ..ResponseBits::default()
        };
        let req = request(None);
        let now = SystemTime::now();
        assert!(
            process_response(
                Some(&headers),
                None,
                &rules,
                &tracker,
                &req,
                &mut response,
                false,
                now,
            )
            .is_empty(),
            "below the threshold the rule only tracks"
        );
        let actions = process_response(
            Some(&headers),
            None,
            &rules,
            &tracker,
            &req,
            &mut response,
            false,
            now,
        );
        assert_eq!(actions, vec![BehaviorAction::Ban { duration: 900 }]);
        assert_eq!(
            response
                .headers
                .get("X-Content-Type-Options")
                .map(String::as_str),
            Some("nosniff")
        );
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;

    fn processor(
        rules: Vec<BehaviorRule>,
        headers: Option<SecurityHeadersConfig>,
        cors: Option<CorsConfig>,
        bans: IpBanManager,
    ) -> ResponseProcessor {
        ResponseProcessor::new(
            headers,
            cors,
            rules,
            Arc::new(Mutex::new(BehaviorTracker::new())),
            bans,
            true,
            DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
            false,
        )
    }

    fn request(origin: Option<&str>) -> RequestBits {
        RequestBits {
            method: "GET".to_owned(),
            url_path: "/api".to_owned(),
            client_ip: "192.0.2.10".to_owned(),
            origin: origin.map(ToOwned::to_owned),
        }
    }

    fn non_return_rule() -> BehaviorRule {
        BehaviorRule {
            rule_type: "detection_exclusion".to_owned(),
            threshold: 1,
            window: 60,
            pattern: "*".to_owned(),
            action: "log".to_owned(),
            ban_duration: None,
            correlate_with_detection: false,
        }
    }

    #[test]
    fn a_non_return_pattern_rule_never_trips_the_processor() {
        // the response pass only dispatches `return_pattern` rules: other
        // rule kinds ride in the list untouched
        let mut response = ResponseBits {
            status: 404,
            body: Some("ok".to_owned()),
            headers: std::collections::BTreeMap::default(),
        };
        let processor = processor(vec![non_return_rule()], None, None, IpBanManager::new());
        assert_eq!(
            processor.process(&request(None), &mut response, None, SystemTime::now()),
            None
        );
        assert_eq!(response.status, 404);
    }

    #[test]
    fn the_free_pass_without_rules_or_headers_leaves_the_response_alone() {
        // no global rules: the whole rule block is skipped; no security
        // headers and no cors: the response rides through untouched
        let tracker = Arc::new(Mutex::new(BehaviorTracker::new()));
        let mut response = ResponseBits::default();
        let actions = process_response(
            None,
            None,
            &[],
            &tracker,
            &request(None),
            &mut response,
            true,
            SystemTime::now(),
        );
        assert!(actions.is_empty());
        assert!(response.headers.is_empty());
    }

    #[test]
    fn the_free_pass_skips_other_rules_and_renders_headers_and_cors() {
        // a non-`return_pattern` rule is skipped, then the enabled security
        // headers render, then the CORS verdict composes for the allowed
        // origin
        let tracker = Arc::new(Mutex::new(BehaviorTracker::new()));
        let mut response = ResponseBits::default();
        let actions = process_response(
            Some(&SecurityHeadersConfig::reference_default()),
            Some(&CorsConfig {
                enabled: true,
                allow_origins: vec!["https://app.example.com".to_owned()],
                ..CorsConfig::default()
            }),
            &[non_return_rule()],
            &tracker,
            &request(Some("https://app.example.com")),
            &mut response,
            true,
            SystemTime::now(),
        );
        assert!(actions.is_empty(), "no return_pattern rule tripped");
        assert_eq!(
            response
                .headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("https://app.example.com")
        );
        assert_eq!(
            response.headers.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );
    }

    #[test]
    fn a_wired_metrics_collector_emits_per_response_after_the_rules() {
        use crate::metrics::{METRIC_ERROR_RATE, METRIC_REQUEST_COUNT, MetricsCollector};
        use std::collections::BTreeMap;

        let seen: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let collector = MetricsCollector::new(true).with_handler(Arc::new(
            move |metric: &crate::metrics::SecurityMetric| {
                sink.lock().expect("sink").push((
                    metric.metric_type.clone(),
                    metric
                        .tags
                        .get("status")
                        .and_then(|status| status.parse().ok())
                        .unwrap_or(0),
                ));
            },
        ));
        let pass = processor(
            Vec::new(),
            Some(SecurityHeadersConfig::reference_default()),
            None,
            IpBanManager::new(),
        )
        .with_metrics(collector);

        let mut response = ResponseBits {
            status: 404,
            body: None,
            headers: BTreeMap::new(),
        };
        pass.process(
            &request(Some("https://app.example.com")),
            &mut response,
            None,
            SystemTime::now(),
        );

        let emitted = seen.lock().expect("sink").clone();
        // The reference emits the request count and, for a `>= 400`
        // status, the error sample; the response_time sample is the
        // caller's (the pass does not time the request).
        // The request-count sample carries no status tag (the reference
        // tags it endpoint + method only), hence the 0 sentinel.
        assert_eq!(
            emitted,
            vec![
                (METRIC_REQUEST_COUNT.to_owned(), 0),
                (METRIC_ERROR_RATE.to_owned(), 404)
            ]
        );
        // The headers still render after the emission point.
        assert!(
            response.headers.contains_key("X-Content-Type-Options"),
            "headers must survive the metrics pass"
        );
    }
}
