//! The route-decorator gates for tower stacks: referrer and time window.
//!
//! Two `tower::Layer`s answering the reference engine's route-scoped
//! checks (`guard_core/core/checks/implementations/referrer.py` and
//! `time_window.py`), grouped here because they share the same shape: a
//! per-path resolver standing in for `request.state.route_config`, a
//! block answer under the reference default message, passive mode, and an
//! `on_block` hook (neither check is in
//! `ON_BLOCK_EXCLUDED_CHECK_NAMES`).
//!
//! ```text
//! referrer (route require_referrer = allowed domains):
//!   no route list:        pass
//!   missing referer:      403 "Referrer required"
//!   host not allowed:     403 "Invalid referrer"
//! time_window (route time_restrictions):
//!   no route window:      pass
//!   outside the window:   403 "Access not allowed at this time"
//!   evaluation error:     pass (the reference's fail-open except arm)
//! both: passive mode observes only; custom_error_responses override the
//!       403 body.
//! ```
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_core_rs::route_gates::{GateConfig, ReferrerStage, RouteReferrerResolver};
//!
//! let resolver: RouteReferrerResolver = Arc::new(|path| {
//!     (path == "/embed").then(|| vec!["partner.example.com".to_owned()])
//! });
//! let stage = ReferrerStage::builder(GateConfig::default())
//!     .resolver(resolver)
//!     .build();
//!
//! assert!(
//!     stage
//!         .decide("/embed", Some("https://partner.example.com/x"), "1.2.3.4", "/embed", "GET")
//!         .is_none()
//! );
//! let answer = stage
//!     .decide("/embed", None, "1.2.3.4", "/embed", "GET")
//!     .expect("blocked");
//! assert_eq!(answer.status, 403);
//! assert_eq!(answer.body, "Referrer required");
//! ```

use std::fmt;
use std::sync::Arc;

use guard_core_engine::referrer::{self, REFERRER_CHECK_NAME, ReferrerVerdict};
use guard_core_engine::time_window::{
    self, TIME_WINDOW_BLOCK_BODY, TIME_WINDOW_BLOCK_STATUS, TIME_WINDOW_CHECK_NAME, TimeWindow,
};

use crate::redact::SensitiveNames;
use crate::responses::{
    CustomErrorResponses, OnBlockHook, build_block_payload, fire_block_hook, resolve_error_body,
};

/// How the stage learns a path's `require_referrer` list (the reference
/// reads it from `request.state.route_config`). `None` (no entry) means
/// the route carries no referrer requirement and passes.
pub type RouteReferrerResolver = Arc<dyn Fn(&str) -> Option<Vec<String>> + Send + Sync>;

/// How the stage learns a path's `time_restrictions` window.
pub type RouteTimeWindowResolver = Arc<dyn Fn(&str) -> Option<TimeWindow> + Send + Sync>;

/// The block answer both gates render: the status plus the resolved body
/// (the reference default message, overridden by
/// `custom_error_responses[403]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateAnswer {
    /// `403` for both gates.
    pub status: u16,
    /// The resolved body.
    pub body: String,
}

/// Shared knobs of the two gates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateConfig {
    /// `passive_mode`: observe, never block.
    pub passive_mode: bool,
}

/// The referrer gate.
#[derive(Clone)]
pub struct ReferrerStage {
    config: GateConfig,
    resolver: Option<RouteReferrerResolver>,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    sensitive: Arc<SensitiveNames>,
}

impl fmt::Debug for ReferrerStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReferrerStage").finish_non_exhaustive()
    }
}

/// Builder for [`ReferrerStage`].
#[derive(Default)]
pub struct ReferrerStageBuilder {
    config: GateConfig,
    resolver: Option<RouteReferrerResolver>,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    sensitive: SensitiveNames,
}

impl ReferrerStage {
    /// Start a builder over `config`.
    #[must_use]
    pub fn builder(config: GateConfig) -> ReferrerStageBuilder {
        ReferrerStageBuilder {
            config,
            resolver: None,
            on_block: None,
            custom_error_responses: CustomErrorResponses::new(),
            sensitive: SensitiveNames::default(),
        }
    }

    /// One pass of the referrer gate. `referer` is the raw `referer`
    /// header value (`None` when absent). The block reasons are the
    /// reference's: `"Missing referrer header"` and
    /// `"Referrer '{redacted}' not in allowed domains"` (the redaction is
    /// the URL display redaction with the merged sensitive sets).
    #[must_use]
    pub fn decide(
        &self,
        path: &str,
        referer: Option<&str>,
        client_ip: &str,
        payload_path: &str,
        method: &str,
    ) -> Option<GateAnswer> {
        let allowed = self.resolver.as_ref().and_then(|resolve| resolve(path))?;
        if allowed.is_empty() {
            return None;
        }
        let (reason, status, body) = match referrer::decide(referer, &allowed) {
            ReferrerVerdict::Allowed => return None,
            ReferrerVerdict::Missing => (
                String::from("Missing referrer header"),
                referrer::REFERRER_MISSING_STATUS,
                referrer::REFERRER_MISSING_BODY,
            ),
            ReferrerVerdict::Invalid { referrer } => {
                let redacted = crate::redact::redact_url_for_display(&referrer, &self.sensitive);
                (
                    format!("Referrer '{redacted}' not in allowed domains"),
                    referrer::REFERRER_INVALID_STATUS,
                    referrer::REFERRER_INVALID_BODY,
                )
            }
        };
        self.answer(
            REFERRER_CHECK_NAME,
            &reason,
            status,
            body,
            client_ip,
            payload_path,
            method,
        )
    }

    /// The shared block path: fire the hook (active) or the passive
    /// payload, resolve the body, and render the answer unless passive.
    #[allow(clippy::too_many_arguments)]
    fn answer(
        &self,
        check_name: &str,
        reason: &str,
        status: u16,
        default_body: &str,
        client_ip: &str,
        path: &str,
        method: &str,
    ) -> Option<GateAnswer> {
        if self.config.passive_mode {
            fire_block_hook(
                self.on_block.as_ref(),
                &build_block_payload(
                    check_name,
                    reason,
                    "",
                    true,
                    client_ip,
                    path,
                    method,
                    None,
                    &self.sensitive,
                ),
            );
            return None;
        }
        fire_block_hook(
            self.on_block.as_ref(),
            &build_block_payload(
                check_name,
                reason,
                "",
                false,
                client_ip,
                path,
                method,
                Some(status),
                &self.sensitive,
            ),
        );
        Some(GateAnswer {
            status,
            body: resolve_error_body(&self.custom_error_responses, status, default_body),
        })
    }
}

impl ReferrerStageBuilder {
    /// Install the route referrer resolver.
    #[must_use]
    pub fn resolver(mut self, resolver: RouteReferrerResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Set passive mode.
    #[must_use]
    pub const fn passive_mode(mut self, passive_mode: bool) -> Self {
        self.config.passive_mode = passive_mode;
        self
    }

    /// Install the `on_block` hook.
    #[must_use]
    pub fn on_block(mut self, hook: OnBlockHook) -> Self {
        self.on_block = Some(hook);
        self
    }

    /// Merge `custom_error_responses` entries.
    #[must_use]
    pub fn custom_error_responses(mut self, custom: CustomErrorResponses) -> Self {
        self.custom_error_responses.extend(custom);
        self
    }

    /// Build the stage (no validation to fail: the lists are host data).
    #[must_use]
    pub fn build(self) -> ReferrerStage {
        ReferrerStage {
            config: self.config,
            resolver: self.resolver,
            on_block: self.on_block,
            custom_error_responses: self.custom_error_responses,
            sensitive: Arc::new(self.sensitive),
        }
    }
}

/// The time-window gate.
#[derive(Clone)]
pub struct TimeWindowStage {
    config: GateConfig,
    resolver: Option<RouteTimeWindowResolver>,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    sensitive: Arc<SensitiveNames>,
}

impl fmt::Debug for TimeWindowStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeWindowStage").finish_non_exhaustive()
    }
}

/// Builder for [`TimeWindowStage`].
#[derive(Default)]
pub struct TimeWindowStageBuilder {
    config: GateConfig,
    resolver: Option<RouteTimeWindowResolver>,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    sensitive: SensitiveNames,
}

impl TimeWindowStage {
    /// Start a builder over `config`.
    #[must_use]
    pub fn builder(config: GateConfig) -> TimeWindowStageBuilder {
        TimeWindowStageBuilder {
            config,
            resolver: None,
            on_block: None,
            custom_error_responses: CustomErrorResponses::new(),
            sensitive: SensitiveNames::default(),
        }
    }

    /// One pass of the time-window gate against the real wall clock (the
    /// reference's `datetime.now(zone)`); tests inject determinism
    /// through [`TimeWindowStage::decide_at`].
    #[must_use]
    pub fn decide(
        &self,
        path: &str,
        client_ip: &str,
        payload_path: &str,
        method: &str,
    ) -> Option<GateAnswer> {
        let now = chrono::Utc::now();
        self.decide_at(path, now, client_ip, payload_path, method)
    }

    /// [`TimeWindowStage::decide`] against an injected instant: the same
    /// decision with `now_utc` standing in for the wall clock.
    #[must_use]
    pub fn decide_at(
        &self,
        path: &str,
        now_utc: chrono::DateTime<chrono::Utc>,
        client_ip: &str,
        payload_path: &str,
        method: &str,
    ) -> Option<GateAnswer> {
        let window = self.resolver.as_ref().and_then(|resolve| resolve(path))?;
        if window.timezone.is_none() && window.start.is_none() && window.end.is_none() {
            return None;
        }
        let current = time_window::hhmm_in_zone(now_utc, window.timezone.as_deref());
        if time_window::is_within(&window, &current) {
            return None;
        }
        self.answer(
            TIME_WINDOW_CHECK_NAME,
            "Access outside allowed time window",
            TIME_WINDOW_BLOCK_STATUS,
            TIME_WINDOW_BLOCK_BODY,
            client_ip,
            payload_path,
            method,
        )
    }

    /// The shared block path (identical to the referrer gate's).
    #[allow(clippy::too_many_arguments)]
    fn answer(
        &self,
        check_name: &str,
        reason: &str,
        status: u16,
        default_body: &str,
        client_ip: &str,
        path: &str,
        method: &str,
    ) -> Option<GateAnswer> {
        if self.config.passive_mode {
            fire_block_hook(
                self.on_block.as_ref(),
                &build_block_payload(
                    check_name,
                    reason,
                    "",
                    true,
                    client_ip,
                    path,
                    method,
                    None,
                    &self.sensitive,
                ),
            );
            return None;
        }
        fire_block_hook(
            self.on_block.as_ref(),
            &build_block_payload(
                check_name,
                reason,
                "",
                false,
                client_ip,
                path,
                method,
                Some(status),
                &self.sensitive,
            ),
        );
        Some(GateAnswer {
            status,
            body: resolve_error_body(&self.custom_error_responses, status, default_body),
        })
    }
}

impl TimeWindowStageBuilder {
    /// Install the route time-window resolver.
    #[must_use]
    pub fn resolver(mut self, resolver: RouteTimeWindowResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Set passive mode.
    #[must_use]
    pub const fn passive_mode(mut self, passive_mode: bool) -> Self {
        self.config.passive_mode = passive_mode;
        self
    }

    /// Install the `on_block` hook.
    #[must_use]
    pub fn on_block(mut self, hook: OnBlockHook) -> Self {
        self.on_block = Some(hook);
        self
    }

    /// Merge `custom_error_responses` entries.
    #[must_use]
    pub fn custom_error_responses(mut self, custom: CustomErrorResponses) -> Self {
        self.custom_error_responses.extend(custom);
        self
    }

    /// Build the stage.
    #[must_use]
    pub fn build(self) -> TimeWindowStage {
        TimeWindowStage {
            config: self.config,
            resolver: self.resolver,
            on_block: self.on_block,
            custom_error_responses: self.custom_error_responses,
            sensitive: Arc::new(self.sensitive),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn at_utc(hour: u32, minute: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2026, 1, 15, hour, minute, 0)
            .unwrap()
    }

    fn recorder() -> (
        Arc<Mutex<Option<crate::responses::BlockPayload>>>,
        OnBlockHook,
    ) {
        let cell: Arc<Mutex<Option<crate::responses::BlockPayload>>> = Arc::new(Mutex::new(None));
        let hook = Arc::clone(&cell);
        (
            cell,
            Arc::new(move |fired| {
                *hook.lock().expect("recorder") = Some(fired.clone());
            }),
        )
    }

    fn referrer_stage() -> ReferrerStage {
        ReferrerStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/embed").then(|| vec!["partner.example.com".to_owned()])
            }))
            .build()
    }

    #[test]
    fn referrer_allows_the_configured_domain_and_its_subdomains() {
        let stage = referrer_stage();
        assert!(
            stage
                .decide(
                    "/embed",
                    Some("https://partner.example.com/x"),
                    "1.2.3.4",
                    "/embed",
                    "GET"
                )
                .is_none()
        );
        assert!(
            stage
                .decide(
                    "/embed",
                    Some("https://api.partner.example.com/"),
                    "1.2.3.4",
                    "/embed",
                    "GET"
                )
                .is_none()
        );
        // An unconfigured path has no requirement at all.
        assert!(
            stage
                .decide("/open", None, "1.2.3.4", "/open", "GET")
                .is_none(),
            "no route entry: the check never runs"
        );
    }

    #[test]
    fn referrer_blocks_missing_and_invalid_with_the_reference_shapes() {
        let stage = referrer_stage();
        let answer = stage
            .decide("/embed", None, "1.2.3.4", "/embed", "GET")
            .expect("missing");
        assert_eq!(answer.status, 403);
        assert_eq!(answer.body, "Referrer required");

        let answer = stage
            .decide(
                "/embed",
                Some("https://evil.test/x"),
                "1.2.3.4",
                "/embed",
                "GET",
            )
            .expect("invalid");
        assert_eq!(answer.status, 403);
        assert_eq!(answer.body, "Invalid referrer");
    }

    #[test]
    fn referrer_passive_mode_observes_only() {
        let (cell, hook) = recorder();
        let stage = ReferrerStage::builder(GateConfig { passive_mode: true })
            .resolver(Arc::new(|path| {
                (path == "/embed").then(|| vec!["partner.example.com".to_owned()])
            }))
            .on_block(hook)
            .build();
        assert!(
            stage
                .decide("/embed", None, "1.2.3.4", "/embed", "GET")
                .is_none()
        );
        let fired = cell.lock().expect("cell").clone().expect("fired");
        assert_eq!(fired.check_name, REFERRER_CHECK_NAME);
        assert!(fired.passive_mode);
        assert_eq!(fired.status_code, None);
        assert_eq!(fired.reason, "Missing referrer header");
    }

    #[test]
    fn referrer_active_mode_fires_the_block_payload() {
        let (cell, hook) = recorder();
        let stage = ReferrerStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/embed").then(|| vec!["partner.example.com".to_owned()])
            }))
            .on_block(hook)
            .build();
        assert!(
            stage
                .decide("/embed", None, "192.0.2.9", "/embed", "POST")
                .is_some()
        );
        let fired = cell.lock().expect("cell").clone().expect("fired");
        assert_eq!(fired.status_code, Some(403));
        assert_eq!(fired.client_ip, "192.0.2.9");
        assert_eq!(fired.path, "/embed");
        assert_eq!(fired.method, "POST");
    }

    fn window_stage() -> TimeWindowStage {
        TimeWindowStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/nightly").then(|| TimeWindow {
                    start: Some("09:00".into()),
                    end: Some("17:00".into()),
                    timezone: Some("UTC".into()),
                })
            }))
            .build()
    }

    #[test]
    fn time_window_allows_inside_and_blocks_outside() {
        let stage = window_stage();
        assert!(
            stage
                .decide_at("/nightly", at_utc(12, 0), "1.2.3.4", "/nightly", "GET")
                .is_none()
        );
        assert!(
            stage
                .decide_at("/nightly", at_utc(9, 0), "1.2.3.4", "/nightly", "GET")
                .is_none()
        );
        let answer = stage
            .decide_at("/nightly", at_utc(18, 30), "1.2.3.4", "/nightly", "GET")
            .expect("blocked");
        assert_eq!(answer.status, 403);
        assert_eq!(answer.body, "Access not allowed at this time");
        // An unconfigured path passes.
        assert!(
            stage
                .decide_at("/open", at_utc(23, 0), "1.2.3.4", "/open", "GET")
                .is_none()
        );
    }

    #[test]
    fn time_window_uses_the_zone_clock() {
        let stage = TimeWindowStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/jp").then(|| TimeWindow {
                    start: Some("09:00".into()),
                    end: Some("17:00".into()),
                    timezone: Some("Asia/Tokyo".into()),
                })
            }))
            .build();
        // 12:00 UTC is 21:00 in Tokyo: outside 09:00-17:00.
        assert!(
            stage
                .decide_at("/jp", at_utc(12, 0), "1.2.3.4", "/jp", "GET")
                .is_some()
        );
        // 00:00 UTC is 09:00 in Tokyo: the first inside minute.
        assert!(
            stage
                .decide_at("/jp", at_utc(0, 0), "1.2.3.4", "/jp", "GET")
                .is_none()
        );
    }

    #[test]
    fn time_window_missing_bounds_fail_open() {
        let stage = TimeWindowStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/broken").then(|| TimeWindow {
                    start: None,
                    end: Some("06:00".into()),
                    timezone: None,
                })
            }))
            .build();
        assert!(
            stage
                .decide_at("/broken", at_utc(12, 0), "1.2.3.4", "/broken", "GET")
                .is_none(),
            "the reference's fail-open except arm allows the request"
        );
    }

    #[test]
    fn both_gates_honor_custom_error_bodies() {
        let mut custom = CustomErrorResponses::new();
        custom.insert(403, "Not now".to_owned());
        let referrer = ReferrerStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/embed").then(|| vec!["partner.example.com".to_owned()])
            }))
            .custom_error_responses(custom.clone())
            .build();
        assert_eq!(
            referrer
                .decide("/embed", None, "1.2.3.4", "/embed", "GET")
                .expect("blocked")
                .body,
            "Not now"
        );
        let window = TimeWindowStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/nightly").then(|| TimeWindow {
                    start: Some("09:00".into()),
                    end: Some("17:00".into()),
                    timezone: None,
                })
            }))
            .custom_error_responses(custom)
            .build();
        assert_eq!(
            window
                .decide_at("/nightly", at_utc(20, 0), "1.2.3.4", "/nightly", "GET")
                .expect("blocked")
                .body,
            "Not now"
        );
    }

    #[test]
    fn both_gates_render_their_debug_shapes() {
        let referrer = referrer_stage();
        let rendered = format!("{referrer:?}");
        assert!(rendered.starts_with("ReferrerStage"));

        let window = window_stage();
        let rendered = format!("{window:?}");
        assert!(rendered.starts_with("TimeWindowStage"));
    }

    #[test]
    fn an_empty_referrer_requirement_never_runs_the_check() {
        let stage = ReferrerStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| (path == "/open").then_some(Vec::new())))
            .build();
        assert!(
            stage
                .decide("/open", None, "1.2.3.4", "/open", "GET")
                .is_none(),
            "an empty allowed list means the route requires nothing"
        );
    }

    #[test]
    fn the_referrer_builder_carries_passive_mode() {
        let (cell, hook) = recorder();
        let stage = ReferrerStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/embed").then(|| vec!["partner.example.com".to_owned()])
            }))
            .passive_mode(true)
            .on_block(hook)
            .build();
        assert!(
            stage
                .decide("/embed", None, "1.2.3.4", "/embed", "GET")
                .is_none()
        );
        let fired = cell.lock().expect("cell").clone().expect("fired");
        assert!(fired.passive_mode);
        assert_eq!(fired.status_code, None);
    }

    #[test]
    fn the_wall_clock_decide_passes_an_unconfigured_path() {
        let stage = window_stage();
        // The wall-clock entry point delegates to decide_at; an
        // unconfigured path answers before any window math.
        assert!(stage.decide("/open", "1.2.3.4", "/open", "GET").is_none());
    }

    #[test]
    fn an_all_none_window_fails_open() {
        let stage = TimeWindowStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/blank").then_some(TimeWindow {
                    start: None,
                    end: None,
                    timezone: None,
                })
            }))
            .build();
        assert!(
            stage
                .decide_at("/blank", at_utc(12, 0), "1.2.3.4", "/blank", "GET")
                .is_none(),
            "a window with no bounds restricts nothing"
        );
    }

    #[test]
    fn the_time_window_builder_carries_passive_mode_and_the_hook() {
        let (cell, hook) = recorder();
        let stage = TimeWindowStage::builder(GateConfig::default())
            .resolver(Arc::new(|path| {
                (path == "/nightly").then(|| TimeWindow {
                    start: Some("09:00".into()),
                    end: Some("17:00".into()),
                    timezone: Some("UTC".into()),
                })
            }))
            .passive_mode(true)
            .on_block(hook)
            .build();
        assert!(
            stage
                .decide_at("/nightly", at_utc(18, 30), "1.2.3.4", "/nightly", "GET")
                .is_none(),
            "passive mode observes the outside-the-window match only"
        );
        let fired = cell.lock().expect("cell").clone().expect("fired");
        assert_eq!(fired.check_name, TIME_WINDOW_CHECK_NAME);
        assert!(fired.passive_mode);
        assert_eq!(fired.status_code, None);
        assert_eq!(fired.reason, "Access outside allowed time window");
    }
}
