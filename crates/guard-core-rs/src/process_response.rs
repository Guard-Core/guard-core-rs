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
//! use guard_core_engine::behavior::{unix_now, BehaviorRule, BehaviorTracker};
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
    unix_now,
};
use guard_core_engine::cors::{CorsConfig, cors_response_headers, downgrade_wildcard_credentials};

use guard_core_engine::ip_ban::IpBanManager;
pub use guard_core_engine::payload::{RequestBits, ResponseBits};
use guard_core_engine::security_headers::{
    SecurityHeadersConfig, security_headers as render_security_headers,
};

pub use guard_core_engine::behavior::rule_from_config;

/// The response the pass mutates in place: the status and body pass
/// through untouched, the headers gain the security-header set and the
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
    response_modifier: Option<guard_core_engine::payload::ResponseModifierFn>,
    on_error: Option<crate::responses::OnErrorHook>,
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
            response_modifier: None,
            on_error: None,
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

    /// Wire the reference `custom_response_modifier`: the callback runs
    /// LAST in the pass (after the CORS verdict, the reference
    /// `apply_modifier` position) over every response the pass touches -
    /// forwarded and blocked alike. A panicking callback leaves the
    /// response unmodified (the reference's except arm: the modifier
    /// never fails the request) and reports through the
    /// [`Self::with_on_error`] hook when one is installed.
    #[must_use]
    pub fn with_response_modifier(
        mut self,
        modifier: guard_core_engine::payload::ResponseModifierFn,
    ) -> Self {
        self.response_modifier = Some(modifier);
        self
    }

    /// Wire the reference `on_error` best-effort hook: invoked when a
    /// middleware step fails, receiving `(stage, error, context)` (the
    /// reference stages: `agent_init`, `geoip`, `transport_send`,
    /// `encryption`; the pass reports the modifier's failures under
    /// `custom_response_modifier`). A raising callback is caught and
    /// dropped, never propagated.
    #[must_use]
    pub fn with_on_error(mut self, hook: crate::responses::OnErrorHook) -> Self {
        self.on_error = Some(hook);
        self
    }

    /// The reference `invoke_error_hook`: fire the installed `on_error`
    /// best-effort hook; a panicking callback is caught and dropped.
    pub fn report_error(&self, stage: &str, error: &str, context: &[(&str, &str)]) {
        let Some(hook) = &self.on_error else {
            return;
        };
        let pairs: Vec<(String, String)> = context
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let stage = stage.to_owned();
        let error = error.to_owned();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook(&stage, &error, &pairs);
        }));
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

        // The reference `apply_modifier`: the callback runs LAST over the
        // finished response view. A panicking callback restores the
        // unmodified response (the reference's except arm) and reports
        // through the on_error hook.
        if let Some(modifier) = &self.response_modifier {
            let unmodified = response.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                modifier(response);
            }));
            if outcome.is_err() {
                *response = unmodified;
                self.report_error(
                    "custom_response_modifier",
                    "the response modifier panicked; returning unmodified response",
                    &[("path", request.url_path.as_str())],
                );
            }
        }

        last_action
    }

    /// The reference `process_usage_rules` (the usage/frequency half of
    /// the behavioral processor): record one request observation per rule
    /// for `(endpoint_id, client_ip)`, and dispatch the action of every
    /// rule that crossed its threshold (a `ban` lands in the shared ban
    /// manager, exactly like the response pass's return rules).
    ///
    /// `rules` are the route's `behavior_rules` (the carrier knob); the
    /// reference reads them from the matched `RouteConfig`.
    #[must_use]
    pub fn process_usage_rules(
        &self,
        endpoint_id: &str,
        client_ip: &str,
        rules: &[BehaviorRule],
        now: SystemTime,
    ) -> Vec<BehaviorAction> {
        let mut actions = Vec::new();
        if rules.is_empty() {
            return actions;
        }
        let mut tracker = self.tracker.lock().expect("behavior tracker");
        for rule in rules {
            if rule.rule_type != "usage" && rule.rule_type != "frequency" {
                continue;
            }
            if tracker.track_endpoint_usage(endpoint_id, client_ip, rule, unix_now(now)) {
                let action = BehaviorTracker::dispatch_action(rule, client_ip, self.passive_mode);
                if let (BehaviorAction::Ban { duration }, Ok(ip)) = (&action, client_ip.parse()) {
                    let _ = self.bans.ban_ip(ip, *duration, "behavioral_violation");
                }
                actions.push(action);
            }
        }
        actions
    }

    /// Whether the processor carries CORS (the preflight short-circuit's
    /// gate: the reference answers preflights only when CORS is enabled).
    #[must_use]
    pub fn cors_enabled(&self) -> bool {
        self.cors.as_ref().is_some_and(|cors| cors.enabled)
    }

    /// The CORS config the processor renders (the preflight short-circuit
    /// reads the same resolved surface the response pass does).
    #[must_use]
    pub const fn cors(&self) -> Option<&CorsConfig> {
        self.cors.as_ref()
    }

    /// The security-headers config the processor renders (the adapter
    /// funnels read the resolved surface to compose the
    /// `security_headers_applied` event over the exact set the pass lands:
    /// the count and the CSP/HSTS flags of
    /// [`guard_core_engine::security_headers::security_headers`] over this
    /// config, before the CORS verdict and the response modifier touch the
    /// view). `None` (or a disabled config) renders no set, and the
    /// reference fires the event only when the set lands.
    #[must_use]
    pub const fn security_headers(&self) -> Option<&SecurityHeadersConfig> {
        self.security_headers.as_ref()
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
    #[test]
    fn the_response_modifier_runs_last_and_restores_on_panic() {
        let hooked = processor(
            Vec::new(),
            Some(SecurityHeadersConfig::default()),
            None,
            IpBanManager::new(),
        )
        .with_response_modifier(Arc::new(|response: &mut ResponseBits| {
            response
                .headers
                .insert("X-Modified".to_owned(), "yes".to_owned());
        }));
        let request = request(None);
        let mut response = ResponseBits {
            status: 200,
            body: None,
            headers: std::collections::BTreeMap::new(),
        };
        hooked.process(&request, &mut response, None, std::time::SystemTime::now());
        assert_eq!(
            response.headers.get("X-Modified").map(String::as_str),
            Some("yes"),
            "the modifier runs after the header passes"
        );

        // A panicking modifier restores the unmodified response and
        // reports through the on_error hook.
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let hooked = processor(
            Vec::new(),
            Some(SecurityHeadersConfig::reference_default()),
            None,
            IpBanManager::new(),
        )
        .with_response_modifier(Arc::new(|_response: &mut ResponseBits| {
            panic!("modifier exploded");
        }))
        .with_on_error(Arc::new(move |stage, error, _context| {
            sink.lock()
                .expect("sink")
                .push((stage.to_owned(), error.to_owned()));
        }));
        let mut response = ResponseBits {
            status: 200,
            body: None,
            headers: std::collections::BTreeMap::new(),
        };
        hooked.process(&request, &mut response, None, std::time::SystemTime::now());
        assert!(
            response.headers.contains_key("X-Content-Type-Options"),
            "the security headers survive the panicking modifier"
        );
        let seen = seen.lock().expect("sink").clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "custom_response_modifier");
    }

    #[test]
    fn a_panicking_modifier_without_on_error_still_restores() {
        let hooked = processor(
            Vec::new(),
            Some(SecurityHeadersConfig::reference_default()),
            None,
            IpBanManager::new(),
        )
        .with_response_modifier(Arc::new(|_response: &mut ResponseBits| {
            panic!("modifier exploded");
        }));
        let request = request(None);
        let mut response = ResponseBits {
            status: 200,
            body: None,
            headers: std::collections::BTreeMap::new(),
        };
        hooked.process(&request, &mut response, None, std::time::SystemTime::now());
        assert!(response.headers.contains_key("X-Content-Type-Options"));
    }

    #[test]
    fn the_on_error_hook_survives_a_panicking_callback() {
        let hooked = processor(Vec::new(), None, None, IpBanManager::new()).with_on_error(
            Arc::new(|_stage, _error, _context| {
                panic!("the error hook itself exploded");
            }),
        );
        hooked.report_error("geoip", "lookup failed", &[("client_ip", "192.0.2.1")]);
        let request = request(None);
        let mut response = ResponseBits {
            status: 200,
            body: None,
            headers: std::collections::BTreeMap::new(),
        };
        let action = hooked.process(&request, &mut response, None, std::time::SystemTime::now());
        assert_eq!(action, None, "the pass is unaffected");
    }

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
    fn usage_rules_track_per_identity_and_the_ban_lands_in_the_shared_store() {
        let bans = IpBanManager::new();
        let usage_processor = processor(
            vec![BehaviorRule {
                rule_type: String::from("usage"),
                threshold: 2,
                window: 60,
                pattern: String::new(),
                action: String::from("ban"),
                ban_duration: Some(3600),
                correlate_with_detection: false,
            }],
            None,
            None,
            bans.clone(),
        );
        let rules = [BehaviorRule {
            rule_type: String::from("usage"),
            threshold: 2,
            window: 60,
            pattern: String::new(),
            action: String::from("ban"),
            ban_duration: Some(3600),
            correlate_with_detection: false,
        }];
        let now = std::time::SystemTime::now();

        // Two observations: under the strict threshold, no action.
        assert!(
            usage_processor
                .process_usage_rules("GET:/api", "192.0.2.70", &rules, now)
                .is_empty()
        );
        assert!(
            usage_processor
                .process_usage_rules("GET:/api", "192.0.2.70", &rules, now)
                .is_empty()
        );
        // The third crossing dispatches the ban...
        let actions = usage_processor.process_usage_rules("GET:/api", "192.0.2.70", &rules, now);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            guard_core_engine::behavior::BehaviorAction::Ban { .. }
        ));
        // ...and the ban stands in the shared store (the pipeline consults
        // the same manager).
        let ip: std::net::IpAddr = "192.0.2.70".parse().expect("ip");
        assert!(bans.is_banned(ip));

        // A return_pattern rule never feeds the usage pass (the type gate
        // skips it before any tracking).
        let return_rule = [BehaviorRule {
            rule_type: String::from("return_pattern"),
            threshold: 1,
            window: 60,
            pattern: String::from("status:404"),
            action: String::from("log"),
            ban_duration: None,
            correlate_with_detection: false,
        }];
        let return_only = processor(Vec::new(), None, None, IpBanManager::new());
        assert!(
            return_only
                .process_usage_rules("GET:/api", "192.0.2.71", &return_rule, now)
                .is_empty()
        );
        // An empty rule set answers without touching the tracker.
        let no_rules = processor(Vec::new(), None, None, IpBanManager::new());
        assert!(
            no_rules
                .process_usage_rules("GET:/api", "192.0.2.71", &[], now)
                .is_empty()
        );

        // The preflight short-circuit's gates read the same surface: a
        // CORS-enabled processor answers both accessors.
        let cors_on = processor(
            Vec::new(),
            None,
            Some(CorsConfig {
                enabled: true,
                ..CorsConfig::default()
            }),
            IpBanManager::new(),
        );
        assert!(cors_on.cors_enabled());
        assert!(cors_on.cors().is_some_and(|cors| cors.enabled));
        let cors_off = processor(Vec::new(), None, None, IpBanManager::new());
        assert!(!cors_off.cors_enabled());
        assert!(cors_off.cors().is_none());
    }

    #[test]
    fn the_security_headers_accessor_exposes_the_rendered_surface() {
        // The headers-on processor answers with its config; a disabled
        // config still surfaces (the caller filters on `enabled`, exactly
        // like the pass), and no config answers `None`.
        let headers_on = processor(
            Vec::new(),
            Some(SecurityHeadersConfig::reference_default()),
            None,
            IpBanManager::new(),
        );
        let config = headers_on.security_headers().expect("the config surfaces");
        assert!(config.enabled);
        // The set the accessor's config renders is the set the pass
        // lands: the count and the CSP/HSTS flags line up.
        let set = guard_core_engine::security_headers::security_headers(config);
        let mut response = ResponseBits::default();
        headers_on.process(&request(None), &mut response, None, SystemTime::now());
        assert_eq!(response.headers.len(), set.len());
        assert_eq!(
            set.contains_key("Content-Security-Policy"),
            response.headers.contains_key("Content-Security-Policy")
        );
        assert_eq!(
            set.contains_key("Strict-Transport-Security"),
            response.headers.contains_key("Strict-Transport-Security")
        );
        assert!(headers_on.security_headers().is_some());

        let headers_off = processor(
            Vec::new(),
            Some(SecurityHeadersConfig {
                enabled: false,
                ..SecurityHeadersConfig::reference_default()
            }),
            None,
            IpBanManager::new(),
        );
        assert!(
            headers_off
                .security_headers()
                .is_some_and(|config| !config.enabled)
        );

        let bare = processor(Vec::new(), None, None, IpBanManager::new());
        assert!(bare.security_headers().is_none());
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
