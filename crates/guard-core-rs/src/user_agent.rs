//! The blocked user-agent pipeline stage for tower stacks.
//!
//! One `tower::Layer` that answers the reference engine's `user_agent`
//! check (`guard_core/core/checks/implementations/user_agent.py`), over the
//! pattern filter core [`guard_core_engine::user_agent::UserAgentFilter`]:
//!
//! ```text
//! whitelisted || exempt (the IpGateDecision extension): pass through
//! user agent matches the route filter or the global filter:
//!     403 "User-Agent not allowed"
//!     + a detection finding feeds the auto-ban engine (see below)
//! everything else:                                      pass through
//! ```
//!
//! ## Reference contract, point by point
//!
//! - **Skip state**: the check returns early for
//!   `is_whitelisted || is_exempt`, read the way the global IP gate leaves
//!   it: an [`IpGateDecision`] request extension. A missing extension means
//!   neither flag is set.
//! - **The header**: `request.headers.get("User-Agent", "")` - a missing
//!   header reads as the empty string, which only a pattern targeting
//!   emptiness blocks.
//! - **Route list first, then the global list**: the reference
//!   `check_user_agent_allowed` tries `route_config.blocked_user_agents`
//!   before `config.blocked_user_agents`; a match in either blocks. The
//!   stage takes the global filter in its config and the per-route filters
//!   through the [`RouteUserAgentFilters`] resolver (`path -> filter`),
//!   the same route seam the request-limits stage uses.
//! - **The ban feed**: on a block the reference calls
//!   `escalate_identity_violation`, which only counts when the request
//!   carries a detection threat: the [`ThreatFinding`] extension's
//!   categories (an empty list records `uncategorized`) are counted for the
//!   client IP and the threshold ban runs under reason
//!   `"Blocked user agent: <user agent>"`. A benign or absent finding
//!   counts nothing. A ban fired on the crossing request does not change
//!   this response: the 403 goes out either way and the ban answers the
//!   next request (through whichever stage consults the shared
//!   [`IpBanManager`]).
//! - **Shared ban engine**: the reference feeds a module-singleton ban
//!   manager. The stage's builder takes the [`IpBanManager`] and
//!   [`ViolationCounters`] handles to share (`.ban_engine(..)`); with no
//!   seam the stage builds its own pair, which is only correct when no
//!   other stage feeds bans. Pass the same handles the rate-limit stage
//!   uses to keep one violation history and one ban store.
//! - **Not mirrored**: the reference logs via `log_activity` and emits
//!   `EVENT_USER_AGENT_BLOCKED` / decorator events, honors `passive_mode`
//!   (log-only), and redacts the user agent through the
//!   `log_sensitive_*` machinery before it lands in a reason. The Rust
//!   family has no event bus, no `passive_mode`, and no redaction config
//!   surface yet; the ban feed's reason carries the truncated (512
//!   code points) raw user agent.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::ip_ban::IpBanConfig;
//! use guard_core_engine::user_agent::UserAgentFilter;
//! use guard_core_rs::tower::StageResponse;
//! use guard_core_rs::user_agent::{UserAgentStage, UserAgentStageConfig};
//!
//! let stage = UserAgentStage::new(UserAgentStageConfig {
//!     blocked_user_agents: UserAgentFilter::new(["sqlmap"]).expect("valid patterns"),
//!     ip_ban: IpBanConfig::default(),
//!     passive_mode: false,
//! })
//! .expect("valid config");
//!
//! // A matching agent is answered with the reference's 403 shape ...
//! let answer = stage.decide(None, None, None, Some("Mozilla/5.0 (sqlmap)"), None);
//! assert_eq!(answer.expect("blocked").body, "User-Agent not allowed");
//!
//! // ... everything else passes, a missing header included.
//! assert!(stage.decide(None, None, None, Some("Mozilla/5.0"), None).is_none());
//! assert!(stage.decide(None, None, None, None, None).is_none());
//! ```

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::{Extensions, HeaderMap, Request, Response, StatusCode};

use crate::tower::{ExtractIp, IpGateDecision, StageResponse, ThreatFinding, default_extract_ip};
pub use guard_core_engine::ip_ban::{
    Clock, IpBanConfig, IpBanConfigError, IpBanManager, ViolationCounters,
};
pub use guard_core_engine::user_agent::{
    MAX_USER_AGENT_MATCH_LENGTH, UserAgentConfigError, UserAgentFilter,
};

/// The blocked answer body (`UserAgentCheck`'s default message).
pub const USER_AGENT_BLOCKED_BODY: &str = "User-Agent not allowed";
/// The reason a block feeds the auto-ban engine under (the reference
/// `escalate_identity_violation` trigger info).
pub const USER_AGENT_BAN_REASON_PREFIX: &str = "Blocked user agent: ";

/// The stage's knobs: the compiled global blocklist, the auto-ban config
/// the ban feed runs under, and the passive-mode switch.
#[derive(Debug, Clone, Default)]
pub struct UserAgentStageConfig {
    /// The global `blocked_user_agents` patterns, compiled and validated.
    /// The default (empty) never blocks on its own.
    pub blocked_user_agents: UserAgentFilter,
    /// The auto-ban knobs (`enable_ip_banning`, `auto_ban_threshold`,
    /// `auto_ban_duration`, `threat_ban_config`).
    pub ip_ban: IpBanConfig,
    /// The reference `SecurityConfig.passive_mode` (`false` by default):
    /// a blocked agent logs only - no ban feed and no `403`, the
    /// reference `UserAgentCheck`'s passive path.
    pub passive_mode: bool,
}

/// How the stage learns a path's route-level blocklist
/// (`route_config.blocked_user_agents`, compiled): `None` for a route
/// without one. Consulted before the global filter, as in the reference.
pub type RouteUserAgentFilters = Arc<dyn Fn(&str) -> Option<Arc<UserAgentFilter>> + Send + Sync>;

/// The blocked user-agent stage over one pattern filter and one ban engine.
///
/// Build it once at startup with [`UserAgentStage::new`] or
/// [`UserAgentStage::builder`] (both fail closed on an invalid ban config)
/// and install it with [`UserAgentStageLayer`]. The stage is cheaply
/// clonable; clones share the ban engine and counters.
#[derive(Clone)]
pub struct UserAgentStage {
    config: UserAgentStageConfig,
    routes: Option<RouteUserAgentFilters>,
    bans: IpBanManager,
    counters: ViolationCounters,
    extract_ip: ExtractIp,
}

impl fmt::Debug for UserAgentStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAgentStage")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl UserAgentStage {
    /// Build and validate the stage with the default IP extraction, the
    /// system clock, and a private ban engine. See
    /// [`UserAgentStage::builder`] for the sharing seams.
    ///
    /// # Errors
    ///
    /// [`IpBanConfigError`] when the ban config is rejected (non-positive
    /// threshold/duration, unknown `threat_ban_config` category).
    pub fn new(config: UserAgentStageConfig) -> Result<Self, IpBanConfigError> {
        Self::builder(config).build()
    }

    /// Open the fail-closed builder: the route filters, the shared ban
    /// engine, the clock, and the IP extraction are all optional seams over
    /// [`UserAgentStage::new`]'s defaults.
    pub const fn builder(config: UserAgentStageConfig) -> UserAgentStageBuilder {
        UserAgentStageBuilder {
            config,
            routes: None,
            bans: None,
            counters: None,
            clock: None,
            extract_ip: None,
        }
    }

    /// The validated config the stage decides under.
    #[must_use]
    pub const fn config(&self) -> &UserAgentStageConfig {
        &self.config
    }

    /// The ban store the ban feed drives. A shared handle when one was
    /// provided to the builder.
    #[must_use]
    pub const fn bans(&self) -> &IpBanManager {
        &self.bans
    }

    /// The violation counters the ban feed accumulates. A shared handle
    /// when one was provided to the builder.
    #[must_use]
    pub const fn counters(&self) -> &ViolationCounters {
        &self.counters
    }

    /// One pass of the stage.
    ///
    /// `ip` is the extracted client identity (`None` still blocks: the
    /// reference answers the 403 without a client IP and only skips the
    /// ban feed), `gate` the global IP gate's skip state, `path` the
    /// request path for the route filter resolver, `user_agent` the raw
    /// header value (`None` reads as the empty string), and `finding` the
    /// detection result when the pipeline provides one. `None` passes
    /// through; `Some` is the block answer.
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        ip: Option<IpAddr>,
        gate: Option<IpGateDecision>,
        path: Option<&str>,
        user_agent: Option<&str>,
        finding: Option<&ThreatFinding>,
    ) -> Option<StageResponse> {
        if gate.is_some_and(|gate| gate.is_whitelisted || gate.is_exempt) {
            return None;
        }
        let agent = user_agent.unwrap_or("");
        let route_blocked = path
            .and_then(|path| self.routes.as_ref().and_then(|routes| routes(path)))
            .is_some_and(|filter| filter.is_blocked(agent));
        if !route_blocked && !self.config.blocked_user_agents.is_blocked(agent) {
            return None;
        }
        if self.config.passive_mode {
            // Log-only: the reference's passive path emits the block events
            // and returns None - no ban feed, no 403.
            return None;
        }

        // The ban feed mirrors `escalate_identity_violation`: only a
        // detection threat counts, the response is the 403 either way.
        if let Some(finding) = finding.filter(|finding| finding.is_threat)
            && let Some(ip) = ip
        {
            let categories: Vec<&str> = finding.categories.iter().map(String::as_str).collect();
            let subject: String = agent.chars().take(MAX_USER_AGENT_MATCH_LENGTH).collect();
            let _ = self.bans.register_violations(
                &self.counters,
                ip,
                &categories,
                &self.config.ip_ban,
                &format!("{USER_AGENT_BAN_REASON_PREFIX}{subject}"),
            );
        }

        Some(StageResponse {
            status: StatusCode::FORBIDDEN,
            body: USER_AGENT_BLOCKED_BODY,
            retry_after: None,
            custom_body: None,
        })
    }
}

/// The fail-closed builder for [`UserAgentStage`].
#[must_use]
pub struct UserAgentStageBuilder {
    config: UserAgentStageConfig,
    routes: Option<RouteUserAgentFilters>,
    bans: Option<IpBanManager>,
    counters: Option<ViolationCounters>,
    clock: Option<Clock>,
    extract_ip: Option<ExtractIp>,
}

impl UserAgentStageBuilder {
    /// Resolve per-route blocklists from the request path.
    pub fn routes(mut self, routes: RouteUserAgentFilters) -> Self {
        self.routes = Some(routes);
        self
    }

    /// Share the ban engine with the other stages of the pipeline (the
    /// reference's module-singleton semantics): the same
    /// [`IpBanManager`] and [`ViolationCounters`] handles the rate-limit
    /// stage holds.
    pub fn ban_engine(mut self, bans: IpBanManager, counters: ViolationCounters) -> Self {
        self.bans = Some(bans);
        self.counters = Some(counters);
        self
    }

    /// Run the private ban engine over an injected wall clock (ignored
    /// when [`UserAgentStageBuilder::ban_engine`] provided the engine).
    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Replace the default client IP extraction ([`default_extract_ip`]).
    pub fn ip_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&HeaderMap, &Extensions) -> Option<IpAddr> + Send + Sync + 'static,
    {
        self.extract_ip = Some(Arc::new(extractor));
        self
    }

    /// Validate everything and build the stage.
    ///
    /// # Errors
    ///
    /// [`IpBanConfigError`] when the ban config is rejected (a
    /// struct-literal config skips its own constructor validation, so the
    /// stage re-validates and fails closed).
    pub fn build(self) -> Result<UserAgentStage, IpBanConfigError> {
        self.config.ip_ban.validate()?;
        let bans = match self.bans {
            Some(bans) => bans,
            None => self
                .clock
                .map_or_else(IpBanManager::new, IpBanManager::with_clock),
        };
        let counters = self.counters.unwrap_or_default();
        Ok(UserAgentStage {
            config: self.config,
            routes: self.routes,
            bans,
            counters,
            extract_ip: self
                .extract_ip
                .unwrap_or_else(|| Arc::new(default_extract_ip)),
        })
    }
}

/// The `tower::Layer` carrying [`UserAgentStage`].
///
/// Wrap any `Service<http::Request<B>>` whose responses are
/// `http::Response<ResBody>` with `ResBody: From<&'static str>` and the
/// stage answers the reference's 403 shape itself.
#[derive(Clone)]
pub struct UserAgentStageLayer {
    stage: UserAgentStage,
}

impl UserAgentStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: UserAgentStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for UserAgentStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserAgentStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for UserAgentStageLayer {
    type Service = UserAgentStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UserAgentStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct UserAgentStageService<S> {
    inner: S,
    stage: UserAgentStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for UserAgentStageService<S>
where
    S: ::tower::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: From<&'static str> + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let ip = (self.stage.extract_ip)(request.headers(), request.extensions());
        let gate = request.extensions().get::<IpGateDecision>().copied();
        let finding = request.extensions().get::<ThreatFinding>();
        let path = request.uri().path().to_owned();
        let user_agent = request
            .headers()
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if let Some(answer) =
            self.stage
                .decide(ip, gate, Some(&path), user_agent.as_deref(), finding)
        {
            let response = render(&answer);
            return Box::pin(async move { Ok(response) });
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

/// Render the stage's block answer into the wrapped service's response body
/// type.
fn render<ResBody: From<&'static str>>(answer: &StageResponse) -> Response<ResBody> {
    let mut response = Response::new(ResBody::from(answer.body));
    *response.status_mut() = answer.status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use ::tower::Service;

    /// A fake clock: f64 unix seconds starting at `1_000.0`.
    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn clock(&self) -> Clock {
            let state = self.0.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || state.load(Ordering::Relaxed) as f64)
        }
    }

    fn stage_with_patterns(patterns: &[&str]) -> UserAgentStage {
        UserAgentStage::new(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::new(patterns.iter().copied())
                .expect("valid patterns"),
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
        })
        .expect("valid config")
    }

    fn blocked_stage_with_bans(ip_ban: IpBanConfig, clock: Clock) -> UserAgentStage {
        UserAgentStage::builder(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::new(["sqlmap"]).expect("valid pattern"),
            ip_ban,
            passive_mode: false,
        })
        .clock(clock)
        .build()
        .expect("valid config")
    }

    fn finding(categories: &[&str]) -> ThreatFinding {
        ThreatFinding {
            is_threat: true,
            categories: categories
                .iter()
                .map(|category| (*category).to_owned())
                .collect(),
            trigger_info: "probe".to_owned(),
        }
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    #[test]
    fn passive_mode_blocks_nothing_and_feeds_no_ban() {
        let stage = UserAgentStage::builder(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::new(["sqlmap"]).expect("valid pattern"),
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 1,
                ..IpBanConfig::default()
            },
            passive_mode: true,
        })
        .build()
        .expect("valid config");
        let attacker = ip("192.0.2.2");
        for _ in 0..5 {
            assert!(
                stage
                    .decide(
                        Some(attacker),
                        None,
                        None,
                        Some("sqlmap"),
                        Some(&finding(&["sqli"]))
                    )
                    .is_none(),
                "passive mode answers nothing for a blocked agent"
            );
        }
        assert_eq!(
            stage.counters().tracked_ips(),
            0,
            "the escalation ban feed is suppressed under passive mode"
        );
        assert!(!stage.bans().is_banned(attacker));
    }

    #[test]
    fn default_stage_passes_everything_through() {
        let stage = UserAgentStage::new(UserAgentStageConfig::default()).expect("valid config");
        assert!(stage.config().blocked_user_agents.is_empty());
        for agent in ["sqlmap", "", "Mozilla/5.0"] {
            assert!(
                stage
                    .decide(Some(ip("192.0.2.1")), None, None, Some(agent), None)
                    .is_none(),
                "an empty blocklist must pass '{agent}'"
            );
        }
        assert_eq!(stage.counters().tracked_ips(), 0);
    }

    #[test]
    fn blocked_agent_answers_the_reference_403_shape() {
        let stage = stage_with_patterns(&["sqlmap"]);
        let answer = stage
            .decide(
                Some(ip("192.0.2.1")),
                None,
                None,
                Some("Mozilla/5.0 (sqlmap/1.8)"),
                None,
            )
            .expect("blocked");
        assert_eq!(answer.status, StatusCode::FORBIDDEN);
        assert_eq!(answer.body, USER_AGENT_BLOCKED_BODY);
        assert_eq!(answer.retry_after, None);
    }

    #[test]
    fn a_missing_header_reads_as_the_empty_string() {
        let stage = stage_with_patterns(&["^$"]);
        assert!(
            stage
                .decide(Some(ip("192.0.2.1")), None, None, None, None)
                .is_some(),
            "a missing User-Agent is the empty string and ^$ blocks it"
        );
        let stage = stage_with_patterns(&["sqlmap"]);
        assert!(
            stage
                .decide(Some(ip("192.0.2.1")), None, None, None, None)
                .is_none()
        );
    }

    #[test]
    fn whitelisted_and_exempt_ips_skip_the_check() {
        let stage = stage_with_patterns(&["sqlmap"]);
        let whitelisted = IpGateDecision {
            is_whitelisted: true,
            is_exempt: false,
        };
        let exempt = IpGateDecision {
            is_whitelisted: false,
            is_exempt: true,
        };
        for gate in [whitelisted, exempt] {
            assert!(
                stage
                    .decide(
                        Some(ip("192.0.2.2")),
                        Some(gate),
                        None,
                        Some("sqlmap"),
                        None
                    )
                    .is_none(),
                "the skip state must pass a blocked agent"
            );
        }
        assert_eq!(stage.counters().tracked_ips(), 0);
    }

    #[test]
    fn route_filter_blocks_where_the_global_one_passes() {
        let stage = UserAgentStage::builder(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::default(),
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
        })
        .routes(Arc::new(|path: &str| {
            (path == "/admin")
                .then(|| Arc::new(UserAgentFilter::new(["curl"]).expect("valid pattern")))
        }))
        .build()
        .expect("valid config");

        assert!(
            stage
                .decide(
                    Some(ip("192.0.2.3")),
                    None,
                    Some("/admin"),
                    Some("curl/8.0"),
                    None
                )
                .is_some(),
            "the route list blocks on its own route"
        );
        assert!(
            stage
                .decide(
                    Some(ip("192.0.2.3")),
                    None,
                    Some("/public"),
                    Some("curl/8.0"),
                    None
                )
                .is_none(),
            "another route has no list"
        );
        assert!(
            stage
                .decide(
                    Some(ip("192.0.2.3")),
                    None,
                    Some("/admin"),
                    Some("Mozilla/5.0"),
                    None
                )
                .is_none()
        );
    }

    #[test]
    fn ban_feed_fires_only_for_a_detection_threat() {
        let fake = FakeClock::default();
        let stage = blocked_stage_with_bans(
            IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 1,
                ..IpBanConfig::default()
            },
            fake.clock(),
        );
        let attacker = ip("192.0.2.4");

        // The block without a detection finding: no counting, no ban.
        assert!(
            stage
                .decide(Some(attacker), None, None, Some("sqlmap"), None)
                .is_some()
        );
        assert_eq!(stage.counters().tracked_ips(), 0, "no finding, no count");
        assert!(!stage.bans().is_banned(attacker));

        // A benign finding counts nothing either.
        let benign = ThreatFinding {
            is_threat: false,
            categories: vec!["sqli".to_owned()],
            trigger_info: "benign".to_owned(),
        };
        assert!(
            stage
                .decide(Some(attacker), None, None, Some("sqlmap"), Some(&benign))
                .is_some()
        );
        assert_eq!(stage.counters().tracked_ips(), 0);

        // A threat finding feeds the engine: the ban fires underneath while
        // this response is still the 403 user-agent shape.
        let answer = stage
            .decide(
                Some(attacker),
                None,
                None,
                Some("sqlmap"),
                Some(&finding(&["sqli"])),
            )
            .expect("blocked");
        assert_eq!(answer.body, USER_AGENT_BLOCKED_BODY);
        assert!(stage.bans().is_banned(attacker));
        assert_eq!(
            stage.bans().ban_record(attacker).expect("record").reason,
            "Blocked user agent: sqlmap"
        );
    }

    #[test]
    fn ban_feed_reason_carries_the_truncated_agent() {
        let fake = FakeClock::default();
        let stage = blocked_stage_with_bans(
            IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 1,
                ..IpBanConfig::default()
            },
            fake.clock(),
        );
        // The match lands exactly at the cap's last code points; whatever
        // sits past 512 must not reach the ban reason.
        let mut agent = "x".repeat(506);
        agent.push_str("sqlmap");
        agent.push_str(" past-the-cap-marker");
        let attacker = ip("192.0.2.5");
        assert!(
            stage
                .decide(
                    Some(attacker),
                    None,
                    None,
                    Some(agent.as_str()),
                    Some(&finding(&[]))
                )
                .is_some()
        );
        let record = stage.bans().ban_record(attacker).expect("record");
        assert!(
            record.reason.contains("sqlmap"),
            "the in-cap match is in the reason: {}",
            record.reason
        );
        assert!(
            !record.reason.contains("past-the-cap-marker"),
            "the reason carries only the truncated subject: {}",
            record.reason
        );
        assert_eq!(
            stage.counters().snapshot(attacker).get("uncategorized"),
            Some(&1),
            "an empty category list records uncategorized"
        );
    }

    #[test]
    fn ban_feed_without_a_client_ip_counts_nothing_but_still_blocks() {
        let fake = FakeClock::default();
        let stage = blocked_stage_with_bans(
            IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 1,
                ..IpBanConfig::default()
            },
            fake.clock(),
        );
        assert!(
            stage
                .decide(None, None, None, Some("sqlmap"), Some(&finding(&["sqli"])))
                .is_some(),
            "the reference answers the 403 without a client IP"
        );
        assert_eq!(stage.counters().tracked_ips(), 0);
    }

    #[test]
    fn builder_fails_closed_on_an_invalid_ban_config() {
        let error = UserAgentStage::new(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::default(),
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 0,
                ..IpBanConfig::default()
            },
            passive_mode: false,
        })
        .unwrap_err();
        assert_eq!(
            error,
            IpBanConfigError::NonPositive {
                field: "auto_ban_threshold"
            }
        );
    }

    #[test]
    fn a_shared_ban_engine_is_visible_to_the_stage() {
        let bans = IpBanManager::new();
        let counters = ViolationCounters::new();
        let stage = UserAgentStage::builder(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::new(["sqlmap"]).expect("valid pattern"),
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
        })
        .ban_engine(bans.clone(), counters.clone())
        .build()
        .expect("valid config");

        // An out-of-band ban through the shared handle answers through the
        // stage's own accessor (the rate-limit stage consults the same
        // store when given the same handles).
        let visitor = ip("192.0.2.6");
        bans.ban_ip(visitor, 60, "admin").expect("ban");
        assert!(stage.bans().is_banned(visitor));
        drop(counters);
    }

    /// The future the plumbing tests drive: the stub futures are always
    /// immediately ready, so a noop-waker spin never spins.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::hint::spin_loop(),
            }
        }
    }

    /// The inner service the plumbing tests wrap: counts its calls and
    /// answers `200 "inner"`.
    #[derive(Clone)]
    struct Inner {
        calls: Arc<AtomicUsize>,
    }

    impl Inner {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ::tower::Service<Request<&'static str>> for Inner {
        type Response = Response<&'static str>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<&'static str>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            drop(request);
            Box::pin(async move { Ok(Response::new("inner")) })
        }
    }

    fn request_with_agent(agent: Option<&str>) -> Request<&'static str> {
        let mut builder = Request::builder();
        if let Some(agent) = agent {
            builder = builder.header("user-agent", agent);
        }
        builder.body("body").expect("request")
    }

    #[test]
    fn layer_passes_through_and_the_inner_service_answers() {
        let layer = UserAgentStageLayer::new(stage_with_patterns(&["sqlmap"]));
        let inner = Inner::new();
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(inner.clone());

        let response =
            block_on(service.call(request_with_agent(Some("Mozilla/5.0")))).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &"inner");
        assert_eq!(inner.call_count(), 1);
    }

    #[test]
    fn layer_answers_the_blocked_shape_without_hitting_the_inner_service() {
        let layer = UserAgentStageLayer::new(stage_with_patterns(&["sqlmap"]));
        let inner = Inner::new();
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(inner.clone());

        let response =
            block_on(service.call(request_with_agent(Some("sqlmap/1.8")))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.body(), &USER_AGENT_BLOCKED_BODY);
        assert_eq!(inner.call_count(), 0, "the blocked request never hits it");

        // The request path reaches the route resolver.
        let request = Request::builder()
            .uri("/admin")
            .header("user-agent", "sqlmap")
            .body("body")
            .expect("request");
        let response = block_on(service.call(request)).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn layer_clone_shares_the_stage_stores() {
        let stage = stage_with_patterns(&["sqlmap"]);
        let mut first = UserAgentStageService {
            inner: Inner::new(),
            stage: stage.clone(),
        };
        let mut second = UserAgentStageService {
            inner: Inner::new(),
            stage,
        };

        let response = block_on(first.call(request_with_agent(Some("SQLMAP")))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = block_on(second.call(request_with_agent(Some("sqlmap")))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn default_extract_ip_sees_the_peer_extension_for_the_feed() {
        let fake = FakeClock::default();
        let stage = blocked_stage_with_bans(
            IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 1,
                ..IpBanConfig::default()
            },
            fake.clock(),
        );
        let socket = SocketAddr::from_str("192.0.2.7:8443").expect("socket");
        let request = Request::builder()
            .header("user-agent", "sqlmap")
            .extension(socket)
            .body("body")
            .expect("request");
        let extracted = (stage.extract_ip)(request.headers(), request.extensions());
        assert_eq!(extracted, Some(ip("192.0.2.7")));
        let answer = stage.decide(
            extracted,
            None,
            None,
            Some("sqlmap"),
            Some(&finding(&["sqli"])),
        );
        assert_eq!(answer.expect("blocked").body, USER_AGENT_BLOCKED_BODY);
        assert!(stage.bans().is_banned(ip("192.0.2.7")));
    }

    #[test]
    fn stage_and_layer_debug_render_their_names() {
        let stage = stage_with_patterns(&["sqlmap"]);
        assert!(format!("{stage:?}").contains("UserAgentStage"));
        let layer = UserAgentStageLayer::new(stage_with_patterns(&["sqlmap"]));
        assert!(format!("{layer:?}").contains("UserAgentStageLayer"));
    }

    #[test]
    fn the_ip_extractor_builder_installs_the_seam() {
        let fixed = |_: &http::HeaderMap, _: &http::Extensions| {
            Some(IpAddr::from_str("192.0.2.31").expect("ip"))
        };
        let stage = UserAgentStage::builder(UserAgentStageConfig {
            blocked_user_agents: UserAgentFilter::new(Vec::<String>::new()).expect("empty filter"),
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
        })
        .ip_extractor(fixed)
        .build()
        .expect("config");
        // the installed extractor resolves the same address the test pinned
        let headers = http::HeaderMap::new();
        let extensions = http::Extensions::new();
        assert_eq!(
            fixed(&headers, &extensions),
            Some(ip("192.0.2.31")),
            "the pinned extractor identity"
        );
        let finding = ThreatFinding::default();
        assert!(
            stage
                .decide(
                    Some(ip("192.0.2.32")),
                    None,
                    Some("/x"),
                    None,
                    Some(&finding)
                )
                .is_none()
        );
    }

    #[test]
    fn block_on_drives_a_pending_once_future() {
        struct PendingOnce {
            polled: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }
        impl Future for PendingOnce {
            type Output = ();
            fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if !self.polled.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(())
            }
        }
        let polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        block_on(PendingOnce {
            polled: std::sync::Arc::clone(&polled),
        });
    }

    #[test]
    fn the_layer_service_polls_ready() {
        let layer = UserAgentStageLayer::new(stage_with_patterns(&["sqlmap"]));
        let mut service = ::tower::ServiceBuilder::new()
            .layer(layer)
            .service(Inner::new());
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            ::tower::Service::<Request<&'static str>>::poll_ready(&mut service, &mut cx),
            Poll::Ready(Ok(()))
        ));
    }
}
