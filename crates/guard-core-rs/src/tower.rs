//! The rate-limit and dynamic-ban pipeline stage for tower stacks: one
//! `tower::Layer` that Axum, tonic, and any `tower::Service` consumer install
//! around their inner service.
//!
//! This is the Rust family's first pipeline stage over the stateful modules
//! (`guard_core_engine::rate_limit`, `guard_core_engine::ip_ban`), mirroring
//! the reference engine's behavior for the two checks the stage owns
//! (`guard_core/core/checks/implementations/rate_limit.py`, the ban check of
//! `ip_security.py`, and the detection feed of `suspicious_activity.py`).
//! One request pass decides:
//!
//! ```text
//! no client IP:                                   pass through
//! banned (no exemption skip):                     403 "IP address banned"
//! over the rate limit (skipped for
//!   whitelisted || exempt):                       429 "Too many requests"
//!                                                 + `Retry-After`: window
//! detection finding crosses a ban threshold
//!   (skipped for whitelisted, never exempt):      403 "IP has been banned"
//! everything else:                                pass through
//! ```
//!
//! ## Reference contract, point by point
//!
//! - **Bans first**: the reference pipeline answers a banned IP from
//!   `ip_security._check_banned_ip` before any later stage runs, with no
//!   whitelist/exemption guard on that check, so the stage consults
//!   [`IpBanManager::is_banned`] before anything else and answers the 403
//!   banned shape.
//! - **Exempt handling**: `RateLimitCheck.check` returns early for
//!   `is_whitelisted || is_exempt`, so an exempt IP is never rate limited
//!   (and never feeds the rate-limit auto-ban counter) while bans and
//!   detection still apply. The skip state arrives the way the global IP
//!   gate leaves it: an [`IpGateDecision`] request extension.
//! - **Throttled shape**: the reference's
//!   `ratelimit_handler.check_rate_limit` answers `429 "Too many requests"`
//!   with `Retry-After: <window seconds>`; the window and limit semantics
//!   are exactly [`RateLimiter::check`]'s (the global per-IP tier, the
//!   reference pipeline's default).
//! - **The rate-limit auto-ban feed**: a crossing feeds
//!   [`IpBanManager::register_violations`] with the `rate_limit`
//!   pseudo-category under reason `rate_limit_exceeded`
//!   (`RateLimitCheck._record_rate_limit_autoban`) when
//!   `enable_rate_limit_auto_ban` is on. The `429` still goes out: the
//!   reference returns the limit response either way, and the ban answers
//!   the next request.
//! - **The detection feed**: a [`ThreatFinding`] request extension (what a
//!   prior detection stage inserts) feeds the same engine with its
//!   categories under reason `penetration_attempt`, exactly the reference's
//!   `suspicious_activity` check: skipped for a whitelisted IP, never for an
//!   exempt one, and the crossing request itself is answered with the 403
//!   "IP has been banned" shape.
//!
//! ## Scope and honesty
//!
//! - The reference pipeline's rate-limit tiers are ported: the
//!   `endpoint_rate_limits` map lives on [`RateLimitConfig`], and the route
//!   decorator tiers (`rate_limit`, `rate_limit_window`, `geo_rate_limits`,
//!   a [`RouteRateLimits`] request extension or a [`RouteRateResolver`])
//!   resolve per path - see [`RateLimitStage::decide_for_path`]. With no
//!   tiers configured the stage runs the global per-IP window only, the
//!   reference pipeline's default tier, byte-identical to the pre-tier
//!   behavior.
//! - **Passive mode**: `passive_mode` (the reference `SecurityConfig`
//!   flag, default `false`) turns every block answer into log-only
//!   behavior: the sliding window and the violation counters still record,
//!   but no `403`/`429` is rendered and the auto-ban feeds are suppressed
//!   (the reference's passive paths skip `_record_rate_limit_autoban`,
//!   `_try_threshold_ban`, and `escalate_identity_violation`).
//! - A detection threat that does not cross a ban threshold passes through
//!   here; the reference's `400 "Suspicious activity detected"` answer
//!   belongs to the suspicious-activity stage, which has no tower
//!   counterpart yet.
//! - The default client IP extraction prefers the peer address a stack
//!   inserts as a `SocketAddr` extension, then falls back to forwarded
//!   headers; see [`default_extract_ip`] for the exact policy and the
//!   spoofing caveat.
//!
//! # Example
//!
//! ```
//! use guard_core_rs::tower::{
//!     IpBanConfig, RateLimitConfig, RateLimitStage, RateLimitStageConfig,
//! };
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! let stage = RateLimitStage::new(RateLimitStageConfig {
//!     rate_limit: RateLimitConfig {
//!         enable_rate_limiting: true,
//!         rate_limit: 1,
//!         ..RateLimitConfig::default()
//!     },
//!     ip_ban: IpBanConfig::default(),
//!     passive_mode: false,
//!     custom_error_responses: std::collections::HashMap::new(),
//! })
//! .expect("valid stage config");
//! let visitor = IpAddr::from_str("192.0.2.1").unwrap();
//!
//! // The first request passes, the second is throttled with the family's
//! // 429 shape, and a request without a client IP passes untouched.
//! assert!(stage.decide(Some(visitor), None, None).is_none());
//! let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
//! assert_eq!(throttled.status, 429);
//! assert_eq!(throttled.body, "Too many requests");
//! assert_eq!(throttled.retry_after, Some(60));
//! assert!(stage.decide(None, None, None).is_none());
//! ```
//!
//! # Tower wiring
//!
//! The layer is an ordinary `tower::Layer`, so `ServiceBuilder`, Axum's
//! `Router::layer`, and hand-rolled tower chains all accept it (shown for
//! Axum, not compiled here):
//!
//! ```rust,ignore
//! use axum::{routing::get, Router};
//! use guard_core_rs::tower::{RateLimitStage, RateLimitStageConfig, RateLimitStageLayer};
//! use tower::ServiceBuilder;
//!
//! let stage = RateLimitStage::new(RateLimitStageConfig::default()).expect("default config");
//! let app = Router::new()
//!     .route("/", get(|| async { "hello" }))
//!     .layer(RateLimitStageLayer::new(stage));
//! ```

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::tower::Layer;
use http::header::RETRY_AFTER;
use http::{Extensions, HeaderMap, HeaderValue, Request, Response, StatusCode};

use crate::event_types::{EVENT_IP_BANNED, EVENT_PENETRATION_ATTEMPT, EVENT_RATE_LIMITED};
use crate::events::{
    IP_BAN_HANDLER_NAME, RATE_LIMIT_HANDLER_NAME, SecurityEvent, SecurityEventBus,
};
use crate::logging::{LogLevel, LogType, log_activity};
use crate::redact::SensitiveNames;
use crate::responses::{CustomErrorResponses, OnBlockHook, build_block_payload, fire_block_hook};

pub use guard_core_engine::distributed::{BanStore, SlidingWindowStore};
pub use guard_core_engine::geo::GeoIpHandler;
pub use guard_core_engine::ip_ban::{
    BanError, BanRecord, IpBanConfig, IpBanConfigError, IpBanManager, RATE_LIMIT_CATEGORY,
    ResolvedBan, ThreatBanEntry, ViolationCounters,
};
pub use guard_core_engine::ip_gate::{IpGateDecision, IpGateError};
pub use guard_core_engine::rate_limit::{
    Clock, RateLimitConfig, RateLimitConfigError, RateLimitEntry, RateLimitTier, RateLimiter,
    RouteRateLimits, TierDecision, system_clock,
};

/// The banned answer body (`ip_security._check_banned_ip`'s default message).
pub const BANNED_BODY: &str = "IP address banned";
/// The crossing-ban answer body (`suspicious_activity`'s "banned" message,
/// answered on the request whose finding crossed the threshold).
pub const BAN_CROSSED_BODY: &str = "IP has been banned";
/// The throttled answer body (`ratelimit_handler.check_rate_limit`'s default
/// message).
pub const THROTTLED_BODY: &str = "Too many requests";
/// The fail-closed Redis-unavailable answer body (the reference raises
/// `GuardRedisError(503, "Redis rate limiting unavailable")` when
/// `redis_fail_open` is off).
pub const REDIS_UNAVAILABLE_BODY: &str = "Redis rate limiting unavailable";
/// The reason the rate-limit crossing feeds the auto-ban engine under
/// (`RateLimitCheck._record_rate_limit_autoban`).
pub const RATE_LIMIT_BAN_REASON: &str = "rate_limit_exceeded";
/// The reason a detection finding feeds the auto-ban engine under
/// (`_try_threshold_ban`'s default reason).
pub const PENETRATION_BAN_REASON: &str = "penetration_attempt";

/// The per-route rate-limit tier resolver: `path -> Option<RouteRateLimits>`.
///
/// The tower counterpart of the reference's `request.state.route_config`
/// (the same seam the request-limits stage's `RouteLimitsResolver` uses).
/// A resolver returning `None` for a path means the path has no route tier.
pub type RouteRateResolver = Arc<dyn Fn(&str) -> Option<RouteRateLimits> + Send + Sync>;

/// What the stage needs to know about the request it is emitting events
/// and log lines for.
///
/// These are the pieces the reference's `GuardRequest` carries into
/// `send_middleware_event` and `log_activity`. Everything is optional; a
/// field the host cannot supply stays `None` and the composed lines
/// carry the empty placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestObservation {
    /// The HTTP method (`request.method`).
    pub method: Option<String>,
    /// The full URL the log lines redact and events carry as `endpoint`
    /// (path plus query, `request.url_path` / `request.url_full`).
    pub url: Option<String>,
    /// The raw `User-Agent` header value, redacted into the event's
    /// `user_agent` field.
    pub user_agent: Option<String>,
}

/// The `SecurityConfig` log knobs the stage's emissions read
/// (`log_suspicious_level`, `muted_check_logs`, and the merged
/// `log_sensitive_*` redaction sets).
#[derive(Debug, Clone, Default)]
pub struct ObservabilityConfig {
    /// `log_suspicious_level`, `"WARNING"` in the reference; `None` means
    /// the reference's `level=None` (compose nothing).
    pub log_suspicious_level: Option<LogLevel>,
    /// `muted_check_logs`: check names suppressed from pipeline logging.
    pub muted_check_logs: Option<HashSet<String>>,
    /// The merged sensitive-name sets for the redaction.
    pub sensitive: SensitiveNames,
}

/// The detection result a prior pipeline stage may attach to the request
/// extensions.
///
/// Adapters insert it with `request.extensions_mut().insert(..)`; the stage
/// feeds its categories into the auto-ban engine exactly as the reference
/// pipeline's `suspicious_activity` check does. Adapters translate their
/// `guard_core_engine::detect::DetectVerdict` into this shape after running
/// the engine's detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThreatFinding {
    /// `true` when the detection stage judged the request a threat.
    pub is_threat: bool,
    /// The detection categories the finding matched (`sqli`, `xss`, ...).
    /// An empty list records the `uncategorized` pseudo-category, the
    /// reference's `_increment_suspicious_counts` mapping.
    pub categories: Vec<String>,
    /// The human-readable trigger description (the reference
    /// `trigger_info`), carried for observability.
    pub trigger_info: String,
}

/// The stage's block answer, one of the three family shapes: the status, the
/// default message body, and the `Retry-After` seconds for the throttled
/// shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageResponse {
    /// The HTTP status (`403` for the banned shapes, `429` for throttling).
    pub status: StatusCode,
    /// The reference default message body.
    pub body: &'static str,
    /// `Retry-After` seconds (set only for the throttled shape).
    pub retry_after: Option<u64>,
    /// The `custom_error_responses` body override for this status; the
    /// renderer prefers it over `body` when set (the reference
    /// `ErrorResponseFactory.create_error_response`'s
    /// `custom_error_responses.get(status_code, default_message)`).
    pub custom_body: Option<String>,
}

/// The stage knobs: the two stateful configs the reference pipeline reads,
/// plus the passive-mode switch.
///
/// The config defaults are the reference `SecurityConfig` defaults: rate
/// limiting and IP banning both on, with the reference thresholds, so a
/// stage built from [`RateLimitStageConfig::default`] throttles at 10
/// requests per 60 s window per client IP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitStageConfig {
    /// The rate-limiting knobs (`enable_rate_limiting`, `rate_limit`,
    /// `rate_limit_window`, `enable_rate_limit_auto_ban`).
    pub rate_limit: RateLimitConfig,
    /// The auto-ban knobs (`enable_ip_banning`, `auto_ban_threshold`,
    /// `auto_ban_duration`, `threat_ban_config`).
    pub ip_ban: IpBanConfig,
    /// The reference `SecurityConfig.passive_mode` (`false` by default):
    /// log-only mode. The stage still records windows and violation
    /// counts, but renders no block answer and runs no auto-ban feed,
    /// exactly the reference's passive paths.
    pub passive_mode: bool,
    /// The reference `SecurityConfig.custom_error_responses` map: status
    /// code to message body, overriding the family default for that
    /// status. Empty by default (every answer keeps its default body).
    pub custom_error_responses: CustomErrorResponses,
}

/// An invalid stage config: the error [`RateLimitStage::new`] fails closed
/// with, naming the part that rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitStageError {
    /// The [`RateLimitConfig`] was rejected (zero limit or window).
    RateLimit(RateLimitConfigError),
    /// A trusted-proxy entry was neither an IP nor a CIDR range.
    TrustedProxy(IpGateError),
    /// The [`IpBanConfig`] was rejected (non-positive threshold/duration or
    /// an unknown `threat_ban_config` category).
    IpBan(IpBanConfigError),
}

impl fmt::Display for RateLimitStageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimit(error) => write!(f, "invalid rate limit config: {error}"),
            Self::TrustedProxy(error) => write!(f, "invalid trusted proxies: {error}"),
            Self::IpBan(error) => write!(f, "invalid ip ban config: {error}"),
        }
    }
}

impl std::error::Error for RateLimitStageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RateLimit(error) => Some(error),
            Self::TrustedProxy(error) => Some(error),
            Self::IpBan(error) => Some(error),
        }
    }
}

/// How the stage learns the request's client IP from the tower request
/// pieces the layer has: the header map and the extensions.
pub type ExtractIp = Arc<dyn Fn(&HeaderMap, &Extensions) -> Option<IpAddr> + Send + Sync>;

/// The default client IP extraction.
///
/// The peer address a tower stack inserts as a `SocketAddr` request
/// extension wins (the deployment-controlled, spoof-proof source); without
/// one, the leftmost `x-forwarded-for` entry, then `x-real-ip`. The header
/// fallbacks exist for stacks that cannot carry the peer address, and they
/// trust the inbound headers: deployments behind a proxy that needs a
/// different forwarded policy install their own extractor with
/// [`RateLimitStageBuilder::ip_extractor`].
#[must_use]
pub fn default_extract_ip(headers: &HeaderMap, extensions: &Extensions) -> Option<IpAddr> {
    if let Some(peer) = extensions.get::<SocketAddr>() {
        return Some(peer.ip());
    }
    if let Some(entry) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(parse_ip_entry)
    {
        return Some(entry);
    }
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_ip_entry)
}

/// Parse one address entry: a bare IP, or an `ip:port` / `[v6]:port` socket
/// literal whose address part is taken.
fn parse_ip_entry(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    IpAddr::from_str(entry)
        .or_else(|_| SocketAddr::from_str(entry).map(|socket| socket.ip()))
        .ok()
}

/// The rate-limit and dynamic-ban stage over one shared set of stores.
///
/// Build it once at startup with [`RateLimitStage::new`] or
/// [`RateLimitStage::builder`] (both fail closed on an invalid config) and
/// install it with [`RateLimitStageLayer`]. The stage is cheaply clonable:
/// the clone shares the window, ban, and counter stores (the references'
/// singleton semantics), so adapters can keep out-of-band handles (admin
/// unban endpoints, stats) alongside the installed layer.
#[derive(Clone)]
pub struct RateLimitStage {
    config: RateLimitStageConfig,
    limiter: RateLimiter,
    bans: IpBanManager,
    counters: ViolationCounters,
    extract_ip: ExtractIp,
    route_resolver: Option<RouteRateResolver>,
    geo_handler: Option<Arc<dyn GeoIpHandler>>,
    events: Option<Arc<SecurityEventBus>>,
    observability: Option<Arc<ObservabilityConfig>>,
    on_block: Option<OnBlockHook>,
}

/// The distributed-store installation: the engine seam plus the
/// reference `redis_prefix` and `redis_fail_open` knobs.
#[derive(Clone)]
struct DistributedSeam {
    window_store: Arc<dyn SlidingWindowStore>,
    ban_store: Option<Arc<dyn BanStore>>,
    redis_prefix: String,
    redis_fail_open: bool,
}

impl fmt::Debug for RateLimitStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimitStage")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RateLimitStage {
    /// Build and validate the stage with the default IP extraction and the
    /// system clock. See [`RateLimitStage::builder`] for the optional seams
    /// (injected clock, trusted proxies, custom extraction).
    ///
    /// # Errors
    ///
    /// [`RateLimitStageError`] naming the config part that was rejected.
    pub fn new(config: RateLimitStageConfig) -> Result<Self, RateLimitStageError> {
        Self::builder(config).build()
    }

    /// Open the fail-closed builder: the clock, the trusted proxies, and the
    /// IP extraction are all optional seams over [`RateLimitStage::new`]'s
    /// defaults.
    pub const fn builder(config: RateLimitStageConfig) -> RateLimitStageBuilder {
        RateLimitStageBuilder {
            config,
            clock: None,
            trusted_proxies: Vec::new(),
            limiter: None,
            bans: None,
            extract_ip: None,
            route_resolver: None,
            geo_handler: None,
            events: None,
            observability: None,
            on_block: None,
            distributed: None,
        }
    }

    /// The validated config the stage decides under.
    #[must_use]
    pub const fn config(&self) -> &RateLimitStageConfig {
        &self.config
    }

    /// The rate limiter the stage drives (the global per-IP tier). A shared
    /// handle: clones see the same sliding windows.
    #[must_use]
    pub const fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// The ban store the stage consults. A shared handle: `ban_ip` and
    /// `unban` through it are visible to the installed layer immediately.
    #[must_use]
    pub const fn bans(&self) -> &IpBanManager {
        &self.bans
    }

    /// The violation counters the auto-ban feed accumulates. A shared
    /// handle, for tests and observability.
    #[must_use]
    pub const fn counters(&self) -> &ViolationCounters {
        &self.counters
    }

    /// One pass of the stage over a request that carries a URL path: the
    /// same decision as [`RateLimitStage::decide`] with the reference
    /// pipeline's rate-limit tiers active. `path` keys the route tiers
    /// (matched against [`RateLimitConfig`]'s `endpoint_rate_limits` and
    /// fed through the stage's [`RouteRateResolver`] to resolve the
    /// decorator tiers, an explicit `route` argument winning when both are
    /// present), and the geo tier resolves its country through the stage's
    /// [`GeoIpHandler`] seam.
    ///
    /// `None` still means pass-through; a tier crossing answers the same
    /// `429` + `Retry-After: <blocking tier's window>` shape the global
    /// tier answers, and feeds the auto-ban engine identically (the
    /// reference records the crossing under every tier's reason with the
    /// same `rate_limit` category).
    #[must_use]
    pub fn decide_for_path(
        &self,
        ip: Option<IpAddr>,
        path: Option<&str>,
        route: Option<&RouteRateLimits>,
        gate: Option<IpGateDecision>,
        finding: Option<&ThreatFinding>,
    ) -> Option<StageResponse> {
        self.decide_for_path_observed(ip, path, route, gate, finding, None)
    }

    /// [`RateLimitStage::decide_for_path`] plus the reference's event and
    /// log emissions: every crossing, ban, and passive observation on the
    /// paths this stage owns emits what the reference emits (the
    /// `penetration_attempt`, `rate_limited`, and `ip_banned` events, the
    /// `log_activity` "suspicious" lines, redacted through the installed
    /// [`ObservabilityConfig`]). The request pieces arrive through
    /// `observation`; `None` composes from what the decision carries.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn decide_for_path_observed(
        &self,
        ip: Option<IpAddr>,
        path: Option<&str>,
        route: Option<&RouteRateLimits>,
        gate: Option<IpGateDecision>,
        finding: Option<&ThreatFinding>,
        observation: Option<&RequestObservation>,
    ) -> Option<StageResponse> {
        let ip = ip?;
        let passive = self.config.passive_mode;

        if self.bans.is_banned(ip) && !passive {
            return Some(self.error_response(
                StatusCode::FORBIDDEN,
                BANNED_BODY,
                None,
                "ip_security",
                "IP is banned",
                ip,
                observation,
            ));
        }

        let whitelisted = gate.is_some_and(|gate| gate.is_whitelisted);
        let skip_rate_limit = whitelisted || gate.is_some_and(|gate| gate.is_exempt);

        if !skip_rate_limit {
            // An explicit route argument wins; otherwise the stage's
            // resolver produces the route tiers from the path.
            let resolved_from_path;
            let resolved_route: Option<&RouteRateLimits> =
                match (route, path, self.route_resolver.as_ref()) {
                    (Some(route), _, _) => Some(route),
                    (None, Some(path), Some(resolver)) => {
                        resolved_from_path = resolver(path);
                        resolved_from_path.as_ref()
                    }
                    (None, _, _) => None,
                };
            let country_of_ip = self.geo_handler.as_deref().map(|handler| {
                // The closure borrows the handler for the duration of the
                // tiered check only; the stage outlives the call.
                move |ip: IpAddr| handler.get_country(ip)
            });
            // The distributed variant degrades to the in-memory window
            // when no store is installed, and internally under
            // fail-open; only a fail-closed backend error surfaces, as
            // the reference 503 (never firing on_block, which the
            // reference excludes for adapter Redis-unavailable
            // responses).
            let Ok(decision) = self.limiter.check_tiers_distributed(
                ip,
                path,
                resolved_route,
                country_of_ip
                    .as_ref()
                    .map(|f| f as &dyn Fn(IpAddr) -> Option<String>),
            ) else {
                // Fail-closed backend error: the reference 503, which
                // never fires `on_block` (the reference excludes the
                // adapter's Redis-unavailable response from the hook).
                return Some(StageResponse {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    body: REDIS_UNAVAILABLE_BODY,
                    retry_after: None,
                    custom_body: None,
                });
            };
            if !decision.allowed() {
                // The reference logs and emits the rate-limited event on
                // every crossing, passive mode included; only the 429 and
                // the auto-ban feed are passive-suppressed.
                self.observe_rate_limited(ip, &decision, observation);
                if !passive {
                    // The crossing feeds the auto-ban engine with the
                    // `rate_limit` pseudo-category; the 429 still goes out
                    // (the reference returns the limit response either way)
                    // and the ban answers the next request.
                    if self.config.rate_limit.enable_rate_limit_auto_ban {
                        // Whether the ban resolved or was refused does not
                        // change this response: the 429 goes out either way
                        // and the ban (if any) answers the next request.
                        let _ = self.bans.register_violations(
                            &self.counters,
                            ip,
                            &[RATE_LIMIT_CATEGORY],
                            &self.config.ip_ban,
                            RATE_LIMIT_BAN_REASON,
                        );
                    }
                    return Some(self.error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        THROTTLED_BODY,
                        Some(decision.retry_after()),
                        "rate_limit",
                        &format!(
                            "Rate limit exceeded: {} requests in {}s window",
                            decision.count(),
                            decision.retry_after()
                        ),
                        ip,
                        observation,
                    ));
                }
            }
        }

        // The detection feed (the reference pipeline's suspicious-activity
        // stage), factored out as [`RateLimitStage::feed_finding`] so a
        // host whose framework splits the pipeline (Rocket's `on_request`
        // never sees the body) can feed the body finding through the same
        // logic without re-recording the rate-limit window.
        self.feed_finding(Some(ip), whitelisted, finding, observation)
    }

    /// The detection-feed half of [`RateLimitStage::decide_for_path_observed`]
    /// as its own entry point: the counters record the finding's categories,
    /// a crossed threshold bans on the spot (the passive path counts and
    /// observes only), and the reference emissions fire - but the ban check
    /// and the rate-limit tiers do NOT run again. This is the tower
    /// counterpart of feeding the reference's `suspicious_activity` stage
    /// without paying the `rate_limit` stage twice; for frameworks whose
    /// pipeline runs in one place, [`RateLimitStage::decide_for_path_observed`]
    /// already calls it. `Some` is the crossing block answer (`403 "IP has
    /// been banned"`), exactly what [`RateLimitStage::decide_for_path_observed`]
    /// would return for the same finding.
    ///
    /// `whitelisted` is the global IP gate's skip state (a whitelisted IP
    /// never feeds - the reference skips a whitelisted IP only; exemption
    /// never shields counting).
    #[must_use]
    pub fn feed_finding(
        &self,
        ip: Option<IpAddr>,
        whitelisted: bool,
        finding: Option<&ThreatFinding>,
        observation: Option<&RequestObservation>,
    ) -> Option<StageResponse> {
        let ip = ip?;
        let passive = self.config.passive_mode;
        if let Some(finding) = finding.filter(|finding| finding.is_threat && !whitelisted) {
            let categories: Vec<&str> = finding.categories.iter().map(String::as_str).collect();
            if passive {
                // Log-only: the categories still count (the reference's
                // `_increment_suspicious_counts` runs either way) but the
                // threshold ban and the block answer are suppressed. The
                // reference still logs the passive line and emits the
                // `logged_only` penetration_attempt event.
                self.counters.record(ip, &categories);
                self.observe_penetration(ip, finding, observation, true, None);
                // The reference's passive-mode log_activity fires the
                // hook with `status_code = None`: no response is ever
                // sent, the request is only flagged.
                if let Some(sensitive) = self.sensitive_names() {
                    let payload = build_block_payload(
                        "suspicious_activity",
                        &format!("Suspicious activity detected: {ip}"),
                        &finding.trigger_info,
                        true,
                        &ip.to_string(),
                        observation
                            .and_then(|obs| obs.url.as_deref())
                            .unwrap_or("/"),
                        observation
                            .and_then(|obs| obs.method.as_deref())
                            .unwrap_or(""),
                        None,
                        &sensitive,
                    );
                    fire_block_hook(self.on_block.as_ref(), &payload);
                }
            } else {
                let resolved = self.bans.register_violations(
                    &self.counters,
                    ip,
                    &categories,
                    &self.config.ip_ban,
                    PENETRATION_BAN_REASON,
                );
                if let Some(resolved) = &resolved {
                    self.observe_ban_fired(ip, resolved);
                }
                // The reference's suspicious-activity check logs and emits
                // on every active detection, crossing or not; only the
                // ban crossing turns this request into the 403.
                let log_reason = match resolved.as_ref().and_then(|r| r.category.as_deref()) {
                    Some(category) => Some(format!(
                        "IP banned due to {category} threshold: {ip} - {}",
                        finding.trigger_info
                    )),
                    None if resolved.is_some() => Some(format!(
                        "IP banned due to suspicious activity: {ip} - {}",
                        finding.trigger_info
                    )),
                    None => Some(format!(
                        "Suspicious activity detected for IP: {ip} - {}",
                        finding.trigger_info
                    )),
                };
                self.observe_penetration(ip, finding, observation, false, log_reason.as_deref());
                if resolved.is_some() {
                    return Some(self.error_response(
                        StatusCode::FORBIDDEN,
                        BAN_CROSSED_BODY,
                        None,
                        "suspicious_activity",
                        &format!("Penetration attempt detected: {}", finding.trigger_info),
                        ip,
                        observation,
                    ));
                }
            }
        }
        None
    }

    /// One pass of the stage over the pieces a tower request carries.
    ///
    /// `ip` is the extracted client identity (`None` passes through, the
    /// reference skips the check without a client IP), `gate` the global IP
    /// gate's skip state when the stack provides one, and `finding` the
    /// detection result when the pipeline provides one. `None` means the
    /// request passes through to the inner service; `Some` is the block
    /// answer the layer renders.
    ///
    /// The order is the reference pipeline's: bans first (no exemption
    /// skip), then the rate limit (skipped for `is_whitelisted ||
    /// is_exempt`), then the detection feed (skipped for `is_whitelisted`
    /// only, since a throttled request never reaches the suspicious-activity
    /// stage in the reference).
    ///
    /// Under [`RateLimitStageConfig::passive_mode`] the observations still
    /// happen (the window records, the detection categories count) but no
    /// block answer is rendered and the auto-ban feeds are suppressed: the
    /// reference's passive paths return `None` where they would block.
    #[must_use]
    pub fn decide(
        &self,
        ip: Option<IpAddr>,
        gate: Option<IpGateDecision>,
        finding: Option<&ThreatFinding>,
    ) -> Option<StageResponse> {
        self.decide_for_path(ip, None, None, gate, finding)
    }

    /// Compose the reference "suspicious" log line (`log_activity` with
    /// `log_type="suspicious"`): the reference wording, the redacted URL
    /// and headers, the `muted_check_logs` and `log_suspicious_level`
    /// knobs. `Some(line)` is the composed message the host logs; `None`
    /// mirrors the reference logging nothing (level `None`, muted check).
    #[must_use]
    pub fn compose_suspicious_log(
        &self,
        ip: IpAddr,
        reason: &str,
        observation: Option<&RequestObservation>,
        passive_mode: bool,
        trigger_info: &str,
        check_name: &str,
    ) -> Option<String> {
        let knobs = self.observability.as_deref().cloned().unwrap_or_default();
        log_activity(
            LogType::Suspicious,
            knobs.log_suspicious_level.or(Some(LogLevel::Warning)),
            reason,
            Some(&ip.to_string()),
            observation.and_then(|obs| obs.method.as_deref()),
            observation.and_then(|obs| obs.url.as_deref()),
            None,
            passive_mode,
            trigger_info,
            Some(check_name),
            knobs.muted_check_logs.as_ref(),
            &knobs.sensitive,
        )
    }

    /// The reference `log_activity` emission for a crossing: composed with
    /// this stage's knobs, dropped on the floor when nothing would log.
    fn log_rate_limited(&self, ip: IpAddr, decision: &TierDecision) {
        let _ = self.compose_suspicious_log(
            ip,
            &format!(
                "Rate limit exceeded for IP: {ip} ({} requests in {}s window)",
                decision.count(),
                decision.retry_after()
            ),
            None,
            false,
            "",
            "rate_limit",
        );
    }

    /// The block answer with the reference `custom_body` and `on_block`
    /// semantics: the body resolves through `custom_error_responses`
    /// (`get(status, default)`), and the hook fires exactly once with the
    /// reference payload keys (check name, reason, redacted path, method,
    /// status).
    #[allow(clippy::too_many_arguments)]
    fn error_response(
        &self,
        status: StatusCode,
        default: &'static str,
        retry_after: Option<u64>,
        check_name: &str,
        reason: &str,
        ip: IpAddr,
        observation: Option<&RequestObservation>,
    ) -> StageResponse {
        let custom_body = self
            .config
            .custom_error_responses
            .get(&status.as_u16())
            .cloned();
        if let Some(sensitive) = self.sensitive_names() {
            let payload = build_block_payload(
                check_name,
                reason,
                "",
                false,
                &ip.to_string(),
                observation
                    .and_then(|obs| obs.url.as_deref())
                    .unwrap_or("/"),
                observation
                    .and_then(|obs| obs.method.as_deref())
                    .unwrap_or(""),
                Some(status.as_u16()),
                &sensitive,
            );
            fire_block_hook(self.on_block.as_ref(), &payload);
        }
        StageResponse {
            status,
            body: default,
            retry_after,
            custom_body,
        }
    }

    /// The merged sensitive sets for the payload redaction, when the
    /// observability seam is installed (the reference passes its config
    /// sets into `build_block_payload`).
    fn sensitive_names(&self) -> Option<SensitiveNames> {
        self.observability
            .as_deref()
            .map(|knobs| knobs.sensitive.clone())
    }

    /// The rate-limit crossing emission (`_send_rate_limit_event` +
    /// `log_activity`): the `rate_limited` event under
    /// `handler_name = "rate_limit"` with the reference metadata, and the
    /// `log_activity` suspicious line. Passive mode flips the action to
    /// `logged_only`, exactly `_send_rate_limit_event`'s passive branch.
    fn observe_rate_limited(
        &self,
        ip: IpAddr,
        decision: &TierDecision,
        observation: Option<&RequestObservation>,
    ) {
        self.log_rate_limited(ip, decision);
        let Some(bus) = &self.events else {
            return;
        };
        let passive = self.config.passive_mode;
        let knobs = self.observability.as_deref().cloned().unwrap_or_default();
        let endpoint = observation
            .and_then(|obs| obs.url.as_deref())
            .map(|url| crate::redact::redact_url_for_display(url, &knobs.sensitive));
        let mut event = SecurityEvent::new(
            EVENT_RATE_LIMITED,
            &ip.to_string(),
            if passive {
                "logged_only"
            } else {
                "request_blocked"
            },
            &format!(
                "Rate limit exceeded: {} requests in {}s window",
                decision.count(),
                decision.retry_after()
            ),
            RATE_LIMIT_HANDLER_NAME,
        );
        event.endpoint = endpoint;
        event.method = observation.and_then(|obs| obs.method.clone());
        event.user_agent = observation
            .and_then(|obs| obs.user_agent.as_deref())
            .map(|agent| crate::redact::redact_blob_for_display(agent, &knobs.sensitive));
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            "request_count".to_owned(),
            serde_json::json!(decision.count()),
        );
        metadata.insert(
            "rate_limit".to_owned(),
            serde_json::json!(self.config.rate_limit.rate_limit),
        );
        metadata.insert(
            "window".to_owned(),
            serde_json::json!(decision.retry_after()),
        );
        event.metadata = metadata;
        bus.send_event(&event);
    }

    /// The ban-fired emission (`IpBanEventMixin._send_ban_event`): the
    /// `ip_banned` event under `handler_name = "ip_ban"` with the applied
    /// duration, exactly when a ban now stands.
    fn observe_ban_fired(&self, ip: IpAddr, resolved: &ResolvedBan) {
        let Some(bus) = &self.events else {
            return;
        };
        let mut event = SecurityEvent::new(
            EVENT_IP_BANNED,
            &ip.to_string(),
            "banned",
            &resolved.reason,
            IP_BAN_HANDLER_NAME,
        );
        let mut metadata = serde_json::Map::new();
        metadata.insert("duration".to_owned(), serde_json::json!(resolved.duration));
        event.metadata = metadata;
        bus.send_event(&event);
    }

    /// The penetration-attempt emission (`suspicious_activity.py`): the
    /// `log_activity` suspicious line plus the `penetration_attempt`
    /// event, active (`request_blocked`) or passive (`logged_only` with
    /// the reference passive reason and `passive_mode` metadata).
    fn observe_penetration(
        &self,
        ip: IpAddr,
        finding: &ThreatFinding,
        observation: Option<&RequestObservation>,
        passive: bool,
        log_reason: Option<&str>,
    ) {
        let trigger_info = &finding.trigger_info;
        if passive {
            let _ = self.compose_suspicious_log(
                ip,
                &format!("Suspicious activity detected: {ip}"),
                observation,
                true,
                trigger_info,
                "suspicious_activity",
            );
        } else if let Some(log_reason) = log_reason {
            let _ = self.compose_suspicious_log(
                ip,
                log_reason,
                observation,
                false,
                "",
                "suspicious_activity",
            );
        }
        let Some(bus) = &self.events else {
            return;
        };
        let knobs = self.observability.as_deref().cloned().unwrap_or_default();
        let total_count: u64 = self.counters.snapshot(ip).values().sum();
        let mut event = if passive {
            let mut event = SecurityEvent::new(
                EVENT_PENETRATION_ATTEMPT,
                &ip.to_string(),
                "logged_only",
                &format!("Suspicious pattern detected (passive mode): {trigger_info}"),
                crate::events::MIDDLEWARE_HANDLER_NAME,
            );
            let mut metadata = serde_json::Map::new();
            metadata.insert("passive_mode".to_owned(), serde_json::json!(true));
            metadata.insert("request_count".to_owned(), serde_json::json!(total_count));
            metadata.insert("trigger_info".to_owned(), serde_json::json!(trigger_info));
            event.metadata = metadata;
            event
        } else {
            let mut event = SecurityEvent::new(
                EVENT_PENETRATION_ATTEMPT,
                &ip.to_string(),
                "request_blocked",
                &format!("Penetration attempt detected: {trigger_info}"),
                crate::events::MIDDLEWARE_HANDLER_NAME,
            );
            let mut metadata = serde_json::Map::new();
            metadata.insert("request_count".to_owned(), serde_json::json!(total_count));
            metadata.insert("trigger_info".to_owned(), serde_json::json!(trigger_info));
            event.metadata = metadata;
            event
        };
        event.endpoint = observation
            .and_then(|obs| obs.url.as_deref())
            .map(|url| crate::redact::redact_url_for_display(url, &knobs.sensitive));
        event.method = observation.and_then(|obs| obs.method.clone());
        event.user_agent = observation
            .and_then(|obs| obs.user_agent.as_deref())
            .map(|agent| crate::redact::redact_blob_for_display(agent, &knobs.sensitive));
        bus.send_event(&event);
    }
}

/// The fail-closed builder for [`RateLimitStage`]: every seam is optional
/// and [`RateLimitStageBuilder::build`] validates the whole config.
#[must_use]
pub struct RateLimitStageBuilder {
    config: RateLimitStageConfig,
    clock: Option<Clock>,
    trusted_proxies: Vec<String>,
    limiter: Option<RateLimiter>,
    bans: Option<(IpBanManager, ViolationCounters)>,
    extract_ip: Option<ExtractIp>,
    route_resolver: Option<RouteRateResolver>,
    geo_handler: Option<Arc<dyn GeoIpHandler>>,
    events: Option<Arc<SecurityEventBus>>,
    observability: Option<Arc<ObservabilityConfig>>,
    on_block: Option<OnBlockHook>,
    distributed: Option<DistributedSeam>,
}

impl RateLimitStageBuilder {
    /// Run the stage over an injected wall clock: the seam deterministic
    /// window-sliding and ban-expiry coverage uses instead of sleeping.
    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Trust these proxy networks for the ban engine's self-DoS refusal (a
    /// bare IP or a CIDR range per entry, the ban store's own parsing).
    pub fn trusted_proxies<I>(mut self, entries: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.trusted_proxies = entries.into_iter().map(Into::into).collect();
        self
    }

    /// Bring your own limiter handle: the stage drives this shared
    /// [`RateLimiter`] (its clock, its distributed store, its already
    /// recorded windows) instead of building one from the config. The
    /// stage's [`RateLimitStage::limiter`] returns the same handle, so
    /// hosts can keep out-of-band views of the sliding windows. Only the
    /// limiter's config part of [`RateLimitStageConfig`] matters for
    /// decisions; validation still reads it.
    pub fn limiter(mut self, limiter: RateLimiter) -> Self {
        self.limiter = Some(limiter);
        self
    }

    /// Bring your own ban handles: the stage consults this shared
    /// [`IpBanManager`] and accumulates into this shared
    /// [`ViolationCounters`] instead of building fresh ones. The stage's
    /// [`RateLimitStage::bans`] and [`RateLimitStage::counters`] return
    /// the same handles, so hosts can keep out-of-band ban and count
    /// views (admin unban endpoints, stats) alongside the installed
    /// layer. The config part of [`RateLimitStageConfig`] still gates
    /// banning; the manager's own clock and trusted proxies apply.
    pub fn ban_manager(mut self, bans: IpBanManager, counters: ViolationCounters) -> Self {
        self.bans = Some((bans, counters));
        self
    }

    /// Replace the default client IP extraction ([`default_extract_ip`])
    /// with a deployment-specific policy.
    pub fn ip_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&HeaderMap, &Extensions) -> Option<IpAddr> + Send + Sync + 'static,
    {
        self.extract_ip = Some(Arc::new(extractor));
        self
    }

    /// Resolve the per-route rate-limit tiers (`path ->
    /// Option<RouteRateLimits>`, the tower counterpart of the reference's
    /// `request.state.route_config`). A `RouteRateLimits` request
    /// extension, when a stack provides one, wins over the resolver.
    pub fn route_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&str) -> Option<RouteRateLimits> + Send + Sync + 'static,
    {
        self.route_resolver = Some(Arc::new(resolver));
        self
    }

    /// Resolve the geolocation the geo rate-limit tier reads (the
    /// reference `geo_handler.get_country`; the MMDB reading is adapter
    /// work). Without a handler the geo tier never applies, exactly the
    /// reference's `if not geo_handler: return None`.
    pub fn geo_handler(mut self, handler: Arc<dyn GeoIpHandler>) -> Self {
        self.geo_handler = Some(handler);
        self
    }

    /// Install the event bus the stage's emissions dispatch through (the
    /// reference `event_bus` / `agent_handler` pair). Without one the
    /// stage still composes the reference log lines but sends no events.
    pub fn events(mut self, bus: Arc<SecurityEventBus>) -> Self {
        self.events = Some(bus);
        self
    }

    /// Run the limiter and ban engine over a distributed store (the
    /// reference `enable_redis && redis_handler` conjunction). The
    /// window/ban keys and the failure semantics are the reference's:
    /// `redis_fail_open = false` (the default) answers the fail-closed
    /// `503 "Redis rate limiting unavailable"` on a backend error,
    /// `true` degrades to the in-memory window. The 503 never fires the
    /// `on_block` hook, matching the reference's excluded
    /// Redis-unavailable response.
    pub fn distributed_store(
        mut self,
        window_store: Arc<dyn SlidingWindowStore>,
        redis_prefix: &str,
        redis_fail_open: bool,
    ) -> Self {
        self.distributed = Some(DistributedSeam {
            window_store,
            ban_store: None,
            redis_prefix: redis_prefix.to_owned(),
            redis_fail_open,
        });
        self
    }

    /// Attach the ban store the distributed mode shares (the reference
    /// `{prefix}banned_ips:{ip}` namespace). Only meaningful together
    /// with [`RateLimitStageBuilder::distributed_store`].
    pub fn distributed_ban_store(mut self, ban_store: Arc<dyn BanStore>) -> Self {
        if let Some(distributed) = &mut self.distributed {
            distributed.ban_store = Some(ban_store);
        }
        self
    }

    /// Install the reference `on_block` callback: fired exactly once per
    /// blocked request (and once per passive-mode-flagged request, with
    /// `status_code = None`) with the reference payload keys. Never fired
    /// for the excluded check names; a raising callback is swallowed.
    pub fn on_block(mut self, hook: OnBlockHook) -> Self {
        self.on_block = Some(hook);
        self
    }

    /// Install the log knobs (`log_suspicious_level`,
    /// `muted_check_logs`, and the `log_sensitive_*` redaction sets) the
    /// stage's `log_activity` emissions read. Without one the reference
    /// defaults apply: `WARNING` suspicious level, nothing muted, the
    /// hardcoded sensitive sets.
    pub fn observability(mut self, config: ObservabilityConfig) -> Self {
        self.observability = Some(Arc::new(config));
        self
    }

    /// Validate everything and build the stage.
    ///
    /// # Errors
    ///
    /// [`RateLimitStageError`] naming the part that was rejected: the rate
    /// limit config (zero limit or window), a trusted-proxy entry that is
    /// neither an IP nor a CIDR range, or the ban config (non-positive
    /// threshold/duration, unknown `threat_ban_config` category).
    pub fn build(self) -> Result<RateLimitStage, RateLimitStageError> {
        self.config
            .ip_ban
            .validate()
            .map_err(RateLimitStageError::IpBan)?;
        let clock = self.clock.unwrap_or_else(|| Arc::new(system_clock));
        let mut limiter = match self.limiter {
            // An injected handle carries its own clock, trusted state, and
            // possibly a distributed store already; only the config part of
            // the stage config drives its decisions.
            Some(limiter) => limiter,
            None => RateLimiter::with_config_and_clock(
                self.config.rate_limit.clone(),
                Arc::clone(&clock),
            )
            .map_err(RateLimitStageError::RateLimit)?,
        };
        let (mut bans, counters) = match self.bans {
            Some((bans, counters)) => (bans, counters),
            None => (
                IpBanManager::with_trusted_proxies_and_clock(self.trusted_proxies, clock)
                    .map_err(RateLimitStageError::TrustedProxy)?,
                ViolationCounters::new(),
            ),
        };
        if let Some(seam) = &self.distributed {
            if let Some(ban_store) = &seam.ban_store {
                bans = bans
                    .clone()
                    .with_distributed_store(Arc::clone(ban_store), &seam.redis_prefix);
            }
            limiter = limiter.with_distributed_store(
                Arc::clone(&seam.window_store),
                &seam.redis_prefix,
                seam.redis_fail_open,
            );
        }
        Ok(RateLimitStage {
            config: self.config,
            limiter,
            bans,
            counters,
            extract_ip: self
                .extract_ip
                .unwrap_or_else(|| Arc::new(default_extract_ip)),
            route_resolver: self.route_resolver,
            geo_handler: self.geo_handler,
            events: self.events,
            observability: self.observability,
            on_block: self.on_block,
        })
    }
}

/// The `tower::Layer` carrying [`RateLimitStage`].
///
/// Wrap any `Service<http::Request<B>>` whose responses are
/// `http::Response<ResBody>` with `ResBody: From<&'static str>` (Axum's
/// body, `http_body_util::Full<Bytes>`, and the plain `&'static str` body
/// all qualify) and the stage answers the family's block shapes itself.
#[derive(Clone)]
pub struct RateLimitStageLayer {
    stage: RateLimitStage,
}

impl RateLimitStageLayer {
    /// Carry `stage` into every service this layer wraps.
    #[must_use]
    pub const fn new(stage: RateLimitStage) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for RateLimitStageLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimitStageLayer")
            .field("stage", &self.stage)
            .finish()
    }
}

impl<S> Layer<S> for RateLimitStageLayer {
    type Service = RateLimitStageService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitStageService {
            inner,
            stage: self.stage.clone(),
        }
    }
}

/// The stage as a `tower::Service` around the inner service it wrapped.
#[derive(Clone)]
pub struct RateLimitStageService<S> {
    inner: S,
    stage: RateLimitStage,
}

impl<S, B, ResBody> ::tower::Service<Request<B>> for RateLimitStageService<S>
where
    S: ::tower::Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: From<&'static str> + From<String> + Send + 'static,
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
        // The route tier overrides ride in as a request extension (what an
        // adapter's routing layer inserts) when the stack provides one.
        let route = request.extensions().get::<RouteRateLimits>();
        let path = request.uri().path();
        // The request pieces the event and log emissions carry (the
        // reference's GuardRequest fields for `send_middleware_event` and
        // `log_activity`).
        let observation = RequestObservation {
            method: Some(request.method().to_string()),
            url: Some(
                request
                    .uri()
                    .path_and_query()
                    .map_or_else(|| path.to_owned(), std::string::ToString::to_string),
            ),
            user_agent: request
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
        };
        if let Some(answer) = self.stage.decide_for_path_observed(
            ip,
            Some(path),
            route,
            gate,
            finding,
            Some(&observation),
        ) {
            let response = render(answer);
            return Box::pin(async move { Ok(response) });
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

/// Render the stage's block answer into the wrapped service's response body
/// type: status, default message body, and the `Retry-After` header for the
/// throttled shape.
fn render<ResBody: From<&'static str> + From<String>>(answer: StageResponse) -> Response<ResBody> {
    let mut response = Response::new(match answer.custom_body {
        Some(custom) => ResBody::from(custom),
        None => ResBody::from(answer.body),
    });
    *response.status_mut() = answer.status;
    if let Some(value) = answer
        .retry_after
        .and_then(|after| HeaderValue::from_str(&after.to_string()).ok())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use ::tower::{Service, ServiceBuilder};

    /// A fake clock: f64 unix seconds starting at `1_000.0`, advanced by
    /// `advance`.
    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }

        fn clock(&self) -> Clock {
            let state = self.0.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || state.load(Ordering::Relaxed) as f64)
        }
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    fn stage_with(config: RateLimitStageConfig, clock: Clock) -> RateLimitStage {
        RateLimitStage::builder(config)
            .clock(clock)
            .build()
            .expect("valid stage config")
    }

    fn throttling_stage(rate_limit: u32, clock: Clock) -> RateLimitStage {
        stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit,
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig::default(),
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            },
            clock,
        )
    }

    fn assert_banned_shape(answer: &StageResponse) {
        assert_eq!(answer.status, StatusCode::FORBIDDEN);
        assert_eq!(answer.body, BANNED_BODY);
        assert_eq!(answer.retry_after, None);
    }

    fn assert_crossing_ban_shape(answer: &StageResponse) {
        assert_eq!(answer.status, StatusCode::FORBIDDEN);
        assert_eq!(answer.body, BAN_CROSSED_BODY);
        assert_eq!(answer.retry_after, None);
    }

    #[test]
    fn default_stage_throttles_at_the_reference_threshold() {
        let stage = RateLimitStage::new(RateLimitStageConfig::default()).expect("default config");
        let visitor = ip("192.0.2.0");
        // The reference defaults: 10 requests per 60 s window per IP, so
        // the first ten pass and the eleventh is throttled.
        for _ in 0..10 {
            assert!(stage.decide(Some(visitor), None, None).is_none());
        }
        let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(stage.limiter().tracked_windows(), 1);
        assert_eq!(stage.counters().tracked_ips(), 0, "no autoban feed");
    }

    #[test]
    fn default_ip_ban_config_resolves_threshold_bans() {
        // The reference defaults enable banning: enough recorded violations
        // from one IP cross the flat threshold and ban it.
        let stage = RateLimitStage::new(RateLimitStageConfig::default()).expect("default config");
        let attacker = ip("192.0.2.1");
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["sqli".to_owned()],
            trigger_info: "probe".to_owned(),
        };
        for _ in 1..stage.config().ip_ban.auto_ban_threshold {
            assert!(stage.decide(Some(attacker), None, Some(&finding)).is_none());
        }
        // The violation that reaches the flat threshold bans and answers
        // with the crossing-ban shape on the same request.
        assert_crossing_ban_shape(
            &stage
                .decide(Some(attacker), None, Some(&finding))
                .expect("threshold crossed"),
        );
        assert!(stage.bans().is_banned(attacker));
    }

    #[test]
    fn throttled_shape_mirrors_the_reference() {
        let stage = throttling_stage(2, Arc::new(system_clock));
        let visitor = ip("192.0.2.1");
        assert!(stage.decide(Some(visitor), None, None).is_none());
        assert!(stage.decide(Some(visitor), None, None).is_none());
        let answer = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(answer.body, THROTTLED_BODY);
        assert_eq!(answer.retry_after, Some(60), "Retry-After is the window");
    }

    #[test]
    fn window_slide_restores_the_budget_through_the_stage() {
        let fake = FakeClock::default();
        let stage = throttling_stage(2, fake.clock());
        let visitor = ip("192.0.2.1");
        assert!(stage.decide(Some(visitor), None, None).is_none());
        assert!(stage.decide(Some(visitor), None, None).is_none());
        assert!(stage.decide(Some(visitor), None, None).is_some());

        // Half the window later the crossing request is still remembered.
        fake.advance(30);
        assert!(stage.decide(Some(visitor), None, None).is_some());
        // Past the window the budget is whole again.
        fake.advance(31);
        assert!(stage.decide(Some(visitor), None, None).is_none());
    }

    #[test]
    fn exempt_ip_skips_rate_limiting_but_bans_still_answer() {
        let stage = throttling_stage(2, Arc::new(system_clock));
        let exempt = ip("192.0.2.7");
        let gate = IpGateDecision {
            is_whitelisted: false,
            is_exempt: true,
        };
        for _ in 0..50 {
            assert!(
                stage.decide(Some(exempt), Some(gate), None).is_none(),
                "an exempt IP is never rate limited"
            );
        }
        assert_eq!(
            stage.limiter().tracked_windows(),
            0,
            "the exempt window was never recorded"
        );

        // Bans still apply to an exempt IP: no exemption skip on the ban
        // check.
        stage.bans().ban_ip(exempt, 60, "x").expect("ban");
        assert_banned_shape(
            &stage
                .decide(Some(exempt), Some(gate), None)
                .expect("banned"),
        );
    }

    #[test]
    fn whitelisted_ip_skips_rate_limiting() {
        let stage = throttling_stage(1, Arc::new(system_clock));
        let whitelisted = ip("192.0.2.8");
        let gate = IpGateDecision {
            is_whitelisted: true,
            is_exempt: false,
        };
        for _ in 0..10 {
            assert!(stage.decide(Some(whitelisted), Some(gate), None).is_none());
        }
        assert_eq!(stage.limiter().tracked_windows(), 0);
    }

    #[test]
    fn ban_check_beats_throttle_and_exemption() {
        let stage = throttling_stage(1, Arc::new(system_clock));
        let attacker = ip("192.0.2.9");
        let gate = IpGateDecision {
            is_whitelisted: false,
            is_exempt: true,
        };
        stage.bans().ban_ip(attacker, 60, "x").expect("ban");
        // Over the limit and exempt, yet the banned shape wins: bans are
        // consulted first.
        assert_banned_shape(
            &stage
                .decide(Some(attacker), Some(gate), None)
                .expect("banned"),
        );
    }

    #[test]
    fn missing_ip_passes_through_without_side_effects() {
        let stage = throttling_stage(1, Arc::new(system_clock));
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["sqli".to_owned()],
            trigger_info: "probe".to_owned(),
        };
        for _ in 0..10 {
            assert!(
                stage.decide(None, None, Some(&finding)).is_none(),
                "no client identity, no stage decision"
            );
        }
        assert_eq!(stage.limiter().tracked_windows(), 0);
        assert_eq!(stage.counters().tracked_ips(), 0);
    }

    #[test]
    fn auto_ban_feed_fires_on_the_crossing_and_the_next_request_is_banned() {
        let fake = FakeClock::default();
        let stage = stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit: 1,
                    enable_rate_limit_auto_ban: true,
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig {
                    enable_ip_banning: true,
                    auto_ban_threshold: 1,
                    ..IpBanConfig::default()
                },
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            },
            fake.clock(),
        );
        let attacker = ip("192.0.2.9");

        // The crossing request gets the 429 (the reference answers the limit
        // response either way) while the ban fires underneath.
        assert!(stage.decide(Some(attacker), None, None).is_none());
        let answer = stage.decide(Some(attacker), None, None).expect("throttled");
        assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(stage.bans().is_banned(attacker));
        assert_eq!(
            stage.bans().ban_record(attacker).expect("record").reason,
            RATE_LIMIT_BAN_REASON
        );
        assert_eq!(
            stage.counters().snapshot(attacker).get("rate_limit"),
            Some(&1),
            "the crossing counted one rate_limit violation"
        );

        // The next request meets the ban check first: the banned shape.
        assert_banned_shape(&stage.decide(Some(attacker), None, None).expect("banned"));
    }

    #[test]
    fn auto_ban_feed_is_gated_on_the_toggle_but_counts_when_banning_is_off() {
        let attacker = ip("192.0.2.9");

        // The toggle off: no violations recorded on a crossing.
        let stage = throttling_stage(1, Arc::new(system_clock));
        assert!(stage.decide(Some(attacker), None, None).is_none());
        assert_eq!(
            stage.counters().tracked_ips(),
            0,
            "enable_rate_limit_auto_ban gates the feed entirely"
        );

        // The toggle on with banning off: the crossing counts (enabling
        // banning later starts from observed history) but nobody is banned.
        let fake = FakeClock::default();
        let stage = stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit: 1,
                    enable_rate_limit_auto_ban: true,
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig {
                    enable_ip_banning: false,
                    ..IpBanConfig::default()
                },
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            },
            fake.clock(),
        );
        assert!(stage.decide(Some(attacker), None, None).is_none());
        assert!(
            stage.decide(Some(attacker), None, None).is_some(),
            "still throttled, not banned"
        );
        assert_eq!(
            stage.counters().snapshot(attacker).get("rate_limit"),
            Some(&1)
        );
        assert!(!stage.bans().is_banned(attacker), "banning is off");
    }

    #[test]
    fn rate_limit_category_entry_overrides_the_flat_threshold() {
        let fake = FakeClock::default();
        let stage = stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit: 1,
                    enable_rate_limit_auto_ban: true,
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig {
                    enable_ip_banning: true,
                    auto_ban_threshold: 100,
                    auto_ban_duration: 3600,
                    threat_ban_config: std::iter::once((
                        "rate_limit".to_owned(),
                        ThreatBanEntry {
                            threshold: 2,
                            duration: 30,
                        },
                    ))
                    .collect(),
                },
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            },
            fake.clock(),
        );
        let attacker = ip("192.0.2.9");

        // Request 1 passes (the limit is 1): no crossing, no violation.
        assert!(stage.decide(Some(attacker), None, None).is_none());
        assert_eq!(stage.counters().snapshot(attacker).get("rate_limit"), None);

        // First crossing: one violation, below the entry's threshold of 2.
        // The 429 still goes out.
        let first_crossing = stage.decide(Some(attacker), None, None);
        assert_eq!(
            first_crossing.expect("429").status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(!stage.bans().is_banned(attacker));
        assert_eq!(
            stage.counters().snapshot(attacker).get("rate_limit"),
            Some(&1)
        );

        // Second crossing: the entry fires (reason "<reason>:<category>").
        assert!(stage.decide(Some(attacker), None, None).is_some());
        assert!(stage.bans().is_banned(attacker));
        assert_eq!(
            stage.bans().ban_record(attacker).expect("record").reason,
            format!("{RATE_LIMIT_BAN_REASON}:rate_limit")
        );

        // The next request meets the banned shape, not the throttled one.
        assert_banned_shape(&stage.decide(Some(attacker), None, None).expect("banned"));
    }

    #[test]
    fn detection_finding_records_and_bans_at_the_threshold() {
        let fake = FakeClock::default();
        let stage = stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig::default(),
                ip_ban: IpBanConfig {
                    enable_ip_banning: true,
                    auto_ban_threshold: 100,
                    auto_ban_duration: 3600,
                    threat_ban_config: std::iter::once((
                        "sqli".to_owned(),
                        ThreatBanEntry {
                            threshold: 2,
                            duration: 60,
                        },
                    ))
                    .collect(),
                },
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            },
            fake.clock(),
        );
        let attacker = ip("192.0.2.9");
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["sqli".to_owned()],
            trigger_info: "union select".to_owned(),
        };

        // Below the threshold the request passes through: the 400
        // "Suspicious activity detected" answer belongs to a later stage
        // this port does not ship yet.
        assert!(stage.decide(Some(attacker), None, Some(&finding)).is_none());
        assert_eq!(stage.counters().snapshot(attacker).get("sqli"), Some(&1));

        // The crossing request itself is answered with the crossing-ban
        // shape.
        assert_crossing_ban_shape(
            &stage
                .decide(Some(attacker), None, Some(&finding))
                .expect("banned on the crossing"),
        );
        assert_eq!(
            stage.bans().ban_record(attacker).expect("record").reason,
            format!("{PENETRATION_BAN_REASON}:sqli")
        );

        // Every later request meets the ban check first.
        assert_banned_shape(&stage.decide(Some(attacker), None, None).expect("banned"));
    }

    #[test]
    fn benign_finding_records_nothing_and_passes_through() {
        let stage = RateLimitStage::new(RateLimitStageConfig {
            rate_limit: RateLimitConfig::default(),
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                ..IpBanConfig::default()
            },
            passive_mode: false,
            custom_error_responses: CustomErrorResponses::default(),
        })
        .expect("valid config");
        let visitor = ip("192.0.2.3");
        let finding = ThreatFinding {
            is_threat: false,
            categories: vec!["sqli".to_owned()],
            trigger_info: "benign".to_owned(),
        };
        assert!(stage.decide(Some(visitor), None, Some(&finding)).is_none());
        assert_eq!(stage.counters().tracked_ips(), 0);
    }

    #[test]
    fn whitelisted_finding_is_not_recorded_but_exempt_finding_is() {
        let stage = RateLimitStage::new(RateLimitStageConfig::default()).expect("valid config");
        let whitelisted = ip("192.0.2.4");
        let exempt = ip("192.0.2.5");
        let whitelist_gate = IpGateDecision {
            is_whitelisted: true,
            is_exempt: false,
        };
        let exempt_gate = IpGateDecision {
            is_whitelisted: false,
            is_exempt: true,
        };
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["xss".to_owned()],
            trigger_info: "probe".to_owned(),
        };

        // A whitelisted IP skips detection entirely (the reference's
        // `suspicious_activity` guard).
        assert!(
            stage
                .decide(Some(whitelisted), Some(whitelist_gate), Some(&finding))
                .is_none()
        );
        assert_eq!(stage.counters().tracked_ips(), 0);

        // An exempt IP is never skipped by detection: the finding counts.
        assert!(
            stage
                .decide(Some(exempt), Some(exempt_gate), Some(&finding))
                .is_none()
        );
        assert_eq!(stage.counters().snapshot(exempt).get("xss"), Some(&1));
    }

    #[test]
    fn passive_mode_records_but_never_blocks_or_feeds_the_autoban() {
        let fake = FakeClock::default();
        let stage = stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit: 1,
                    enable_rate_limit_auto_ban: true,
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig {
                    enable_ip_banning: true,
                    auto_ban_threshold: 1,
                    ..IpBanConfig::default()
                },
                passive_mode: true,
                custom_error_responses: CustomErrorResponses::default(),
            },
            fake.clock(),
        );
        let visitor = ip("192.0.2.30");
        let attacker = ip("192.0.2.31");
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["sqli".to_owned()],
            trigger_info: "probe".to_owned(),
        };

        // A live ban no longer answers: the reference's banned check logs
        // and returns None under passive mode.
        stage.bans().ban_ip(visitor, 60, "x").expect("ban");
        assert!(stage.decide(Some(visitor), None, None).is_none());

        // A rate-limit crossing still records the window but renders no
        // 429 and runs no autoban feed (the reference skips
        // `_record_rate_limit_autoban` under passive mode).
        assert!(stage.decide(Some(attacker), None, None).is_none());
        assert!(stage.decide(Some(attacker), None, None).is_none());
        assert_eq!(stage.limiter().tracked_windows(), 2);
        assert_eq!(stage.counters().tracked_ips(), 0);
        assert!(!stage.bans().is_banned(attacker));

        // A detection finding still counts its categories (the reference's
        // `_increment_suspicious_counts` runs either way) but the threshold
        // ban is suppressed and nothing is answered.
        assert!(stage.decide(Some(attacker), None, Some(&finding)).is_none());
        assert_eq!(
            stage.counters().snapshot(attacker).get("sqli"),
            Some(&1),
            "the categories counted without banning"
        );
        assert!(!stage.bans().is_banned(attacker));
    }

    #[test]
    fn ipv4_mapped_ip_shares_the_ipv4_bucket() {
        let stage = throttling_stage(1, Arc::new(system_clock));
        assert!(
            stage
                .decide(Some(ip("::ffff:192.0.2.6")), None, None)
                .is_none()
        );
        let answer = stage.decide(Some(ip("192.0.2.6")), None, None);
        assert_eq!(
            answer.expect("throttled").status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    /// A fixed-country geo handler for the geo-tier tests.
    struct FixedCountry(&'static str);

    impl GeoIpHandler for FixedCountry {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some(self.0.to_owned())
        }
    }

    fn entry(requests: u32, window: u64) -> RateLimitEntry {
        RateLimitEntry::new(requests, window).expect("valid entry")
    }

    #[test]
    fn endpoint_tier_crosses_at_its_own_limit_and_window() {
        let fake = FakeClock::default();
        let stage = stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    rate_limit: 10,
                    endpoint_rate_limits: std::iter::once(("/login".to_owned(), entry(1, 30)))
                        .collect(),
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig::default(),
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            },
            fake.clock(),
        );
        let visitor = ip("192.0.2.60");

        // The first request passes; the second crosses the endpoint tier
        // (not the global one) and carries its window in Retry-After.
        assert!(
            stage
                .decide_for_path(Some(visitor), Some("/login"), None, None, None)
                .is_none()
        );
        let answer = stage
            .decide_for_path(Some(visitor), Some("/login"), None, None, None)
            .expect("throttled");
        assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(answer.retry_after, Some(30), "the endpoint tier's window");

        // An unconfigured path still runs the global tier only.
        assert!(
            stage
                .decide_for_path(Some(visitor), Some("/other"), None, None, None)
                .is_none()
        );
    }

    #[test]
    fn route_tier_rides_in_as_a_request_extension() {
        let fake = FakeClock::default();
        let stage = stage_with(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    rate_limit: 10,
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig::default(),
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            },
            fake.clock(),
        );
        let visitor = ip("192.0.2.61");
        let route = RouteRateLimits::new(Some(1), Some(45), None).expect("valid route");

        assert!(
            stage
                .decide_for_path(Some(visitor), Some("/x"), Some(&route), None, None)
                .is_none()
        );
        let answer = stage
            .decide_for_path(Some(visitor), Some("/x"), Some(&route), None, None)
            .expect("throttled");
        assert_eq!(answer.retry_after, Some(45), "the route tier's window");
    }

    #[test]
    fn route_resolver_resolves_the_decorator_tiers_by_path() {
        let fake = FakeClock::default();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                rate_limit: 10,
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
            custom_error_responses: CustomErrorResponses::default(),
        })
        .clock(fake.clock())
        .route_resolver(|path| {
            (path == "/admin").then(|| RouteRateLimits::new(Some(1), None, None).expect("route"))
        })
        .build()
        .expect("valid stage config");
        let visitor = ip("192.0.2.62");

        assert!(
            stage
                .decide_for_path(Some(visitor), Some("/admin"), None, None, None)
                .is_none()
        );
        let answer = stage
            .decide_for_path(Some(visitor), Some("/admin"), None, None, None)
            .expect("throttled");
        assert_eq!(
            answer.retry_after,
            Some(60),
            "the reference default route window"
        );

        // A path the resolver does not know runs the global tier only.
        assert!(
            stage
                .decide_for_path(Some(visitor), Some("/public"), None, None, None)
                .is_none()
        );
    }

    #[test]
    fn explicit_route_argument_wins_over_the_resolver() {
        let fake = FakeClock::default();
        let stage = RateLimitStage::builder(RateLimitStageConfig::default())
            .clock(fake.clock())
            .route_resolver(|_path| {
                Some(RouteRateLimits::new(Some(1), None, None).expect("valid route"))
            })
            .build()
            .expect("valid stage config");
        let visitor = ip("192.0.2.63");
        // The explicit route is inert (no tier configured): the resolver's
        // tier must not apply.
        let inert = RouteRateLimits::new(None, None, None).expect("valid route");
        for _ in 0..5 {
            assert!(
                stage
                    .decide_for_path(Some(visitor), Some("/x"), Some(&inert), None, None)
                    .is_none()
            );
        }
    }

    #[test]
    fn geo_tier_needs_the_handler_and_falls_back_to_star() {
        let fake = FakeClock::default();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                rate_limit: 100,
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
            custom_error_responses: CustomErrorResponses::default(),
        })
        .clock(fake.clock())
        .geo_handler(Arc::new(FixedCountry("RU")))
        .route_resolver(|_path| {
            Some(
                RouteRateLimits::new(
                    None,
                    None,
                    Some(
                        [
                            ("RU".to_owned(), entry(1, 60)),
                            ("*".to_owned(), entry(5, 20)),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                )
                .expect("valid route"),
            )
        })
        .build()
        .expect("valid stage config");
        let russian = ip("192.0.2.64");

        assert!(
            stage
                .decide_for_path(Some(russian), Some("/x"), None, None, None)
                .is_none()
        );
        let answer = stage
            .decide_for_path(Some(russian), Some("/x"), None, None, None)
            .expect("throttled");
        assert_eq!(
            answer.retry_after,
            Some(60),
            "the resolved country's entry window"
        );

        // Without a handler the geo tier never applies (the reference's
        // `if not geo_handler: return None`): an identical config without
        // the handler runs the global tier only.
        let stage_no_geo = RateLimitStage::builder(stage.config().clone())
            .clock(fake.clock())
            .route_resolver(|_path| {
                Some(
                    RouteRateLimits::new(
                        None,
                        None,
                        Some(std::iter::once(("*".to_owned(), entry(1, 60))).collect()),
                    )
                    .expect("valid route"),
                )
            })
            .build()
            .expect("valid stage config");
        for _ in 0..5 {
            assert!(
                stage_no_geo
                    .decide_for_path(Some(ip("192.0.2.65")), Some("/x"), None, None, None)
                    .is_none()
            );
        }
    }

    #[test]
    fn exempt_ip_skips_every_tier() {
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                rate_limit: 10,
                endpoint_rate_limits: std::iter::once(("/login".to_owned(), entry(1, 60)))
                    .collect(),
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
            custom_error_responses: CustomErrorResponses::default(),
        })
        .clock(Arc::new(system_clock))
        .route_resolver(|_path| {
            Some(RouteRateLimits::new(Some(1), None, None).expect("valid route"))
        })
        .build()
        .expect("valid stage config");
        let exempt = ip("192.0.2.66");
        let gate = IpGateDecision {
            is_whitelisted: false,
            is_exempt: true,
        };
        for _ in 0..20 {
            assert!(
                stage
                    .decide_for_path(Some(exempt), Some("/login"), None, Some(gate), None)
                    .is_none(),
                "an exempt IP skips every tier"
            );
        }
        assert_eq!(stage.limiter().tracked_windows(), 0);
    }

    #[test]
    fn tier_crossing_feeds_the_auto_ban_engine_like_the_global_tier() {
        let fake = FakeClock::default();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                rate_limit: 100,
                enable_rate_limit_auto_ban: true,
                endpoint_rate_limits: std::iter::once(("/login".to_owned(), entry(1, 60)))
                    .collect(),
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 1,
                ..IpBanConfig::default()
            },
            passive_mode: false,
            custom_error_responses: CustomErrorResponses::default(),
        })
        .clock(fake.clock())
        .build()
        .expect("valid stage config");
        let attacker = ip("192.0.2.67");

        assert!(
            stage
                .decide_for_path(Some(attacker), Some("/login"), None, None, None)
                .is_none()
        );
        let answer = stage
            .decide_for_path(Some(attacker), Some("/login"), None, None, None)
            .expect("throttled");
        assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(stage.bans().is_banned(attacker), "the tier crossing banned");
        assert_eq!(
            stage.bans().ban_record(attacker).expect("record").reason,
            RATE_LIMIT_BAN_REASON
        );
    }

    #[test]
    fn layer_wires_the_path_through_the_tiered_decision() {
        let layer = RateLimitStageLayer::new(
            RateLimitStage::builder(RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    rate_limit: 10,
                    endpoint_rate_limits: std::iter::once(("/login".to_owned(), entry(1, 90)))
                        .collect(),
                    ..RateLimitConfig::default()
                },
                ip_ban: IpBanConfig::default(),
                passive_mode: false,
                custom_error_responses: CustomErrorResponses::default(),
            })
            .build()
            .expect("valid stage config"),
        );
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let mut request = request_from_client("192.0.2.68");
        *request.uri_mut() = "/login".parse().expect("path");
        let first = block_on(service.call(request)).expect("ready");
        assert_eq!(first.status(), StatusCode::OK);

        let mut request = request_from_client("192.0.2.68");
        *request.uri_mut() = "/login".parse().expect("path");
        let second = block_on(service.call(request)).expect("ready");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            second
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("90"),
            "Retry-After carries the endpoint tier's window"
        );
        assert_eq!(inner.call_count(), 1);
    }

    #[test]
    fn layer_wires_the_route_extension_through_the_tiered_decision() {
        let stage = throttling_stage(10, Arc::new(system_clock));
        let mut service = RateLimitStageService {
            inner: Inner::new(),
            stage,
        };

        let mut request = request_from_client("192.0.2.69");
        *request.uri_mut() = "/x".parse().expect("path");
        request
            .extensions_mut()
            .insert(RouteRateLimits::new(Some(1), Some(15), None).expect("valid route"));
        assert_eq!(
            block_on(service.call(request)).expect("ready").status(),
            StatusCode::OK
        );

        let mut request = request_from_client("192.0.2.69");
        *request.uri_mut() = "/x".parse().expect("path");
        request
            .extensions_mut()
            .insert(RouteRateLimits::new(Some(1), Some(15), None).expect("valid route"));
        let response = block_on(service.call(request)).expect("ready");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("15"),
            "the route extension's tier window"
        );
    }

    #[test]
    fn builder_fails_closed_on_every_rejected_part() {
        let error = RateLimitStage::new(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                rate_limit: 0,
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig::default(),
            passive_mode: false,
            custom_error_responses: CustomErrorResponses::default(),
        })
        .unwrap_err();
        assert_eq!(
            error,
            RateLimitStageError::RateLimit(RateLimitConfigError {
                field: "rate_limit".into(),
                reason: "must be at least 1 request per window",
            })
        );
        assert!(error.to_string().starts_with("invalid rate limit config:"));
        assert!(std::error::Error::source(&error).is_some());

        // A struct-literal ban config skips its own constructor validation,
        // so the stage re-validates and fails closed.
        let error = RateLimitStage::new(RateLimitStageConfig {
            rate_limit: RateLimitConfig::default(),
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 0,
                ..IpBanConfig::default()
            },
            passive_mode: false,
            custom_error_responses: CustomErrorResponses::default(),
        })
        .unwrap_err();
        assert_eq!(
            error,
            RateLimitStageError::IpBan(IpBanConfigError::NonPositive {
                field: "auto_ban_threshold",
            })
        );

        let error = RateLimitStage::builder(RateLimitStageConfig::default())
            .trusted_proxies(["not-an-ip"])
            .build()
            .unwrap_err();
        assert_eq!(
            error,
            RateLimitStageError::TrustedProxy(IpGateError {
                list: "trusted_proxies",
                entry: "not-an-ip".to_owned(),
            })
        );
        assert_eq!(
            error.to_string(),
            "invalid trusted proxies: invalid trusted_proxies entry 'not-an-ip': \
             expected an IP address or CIDR range"
        );
    }

    #[test]
    fn shared_store_handles_are_live_for_the_layer() {
        let stage = throttling_stage(10, Arc::new(system_clock));
        let visitor = ip("192.0.2.10");
        // An out-of-band ban through the shared handle is visible to the
        // stage immediately (the admin-unban-endpoint shape).
        stage.bans().ban_ip(visitor, 60, "admin").expect("ban");
        assert_banned_shape(&stage.decide(Some(visitor), None, None).expect("banned"));
        stage.bans().unban(visitor);
        assert!(stage.decide(Some(visitor), None, None).is_none());
    }

    #[test]
    fn default_extract_ip_prefers_the_peer_extension() {
        let mut request = Request::builder()
            .header("x-forwarded-for", "junk")
            .body(())
            .expect("request");
        request
            .extensions_mut()
            .insert(SocketAddr::from_str("203.0.113.9:8443").expect("socket"));
        assert_eq!(
            default_extract_ip(request.headers(), request.extensions()),
            Some(ip("203.0.113.9")),
            "the peer address wins over any header"
        );
    }

    #[test]
    fn default_extract_ip_falls_back_to_forwarded_headers() {
        let request_with = |header: &str, value: &str| {
            Request::builder()
                .header(header, value)
                .body(())
                .expect("request")
        };

        let request = request_with("x-forwarded-for", "198.51.100.7, 10.0.0.1");
        assert_eq!(
            default_extract_ip(request.headers(), request.extensions()),
            Some(ip("198.51.100.7")),
            "the leftmost entry is the client"
        );

        let request = request_with("x-forwarded-for", "192.0.2.5:8443");
        assert_eq!(
            default_extract_ip(request.headers(), request.extensions()),
            Some(ip("192.0.2.5")),
            "a socket-literal entry contributes its address"
        );

        let request = request_with("x-real-ip", "203.0.113.8");
        assert_eq!(
            default_extract_ip(request.headers(), request.extensions()),
            Some(ip("203.0.113.8"))
        );

        let request = request_with("x-forwarded-for", "not-an-ip");
        assert_eq!(
            default_extract_ip(request.headers(), request.extensions()),
            None,
            "a junk header is not a client"
        );

        let request = request_with("x-other", "203.0.113.8");
        assert_eq!(
            default_extract_ip(request.headers(), request.extensions()),
            None,
            "no peer and no forwarded header, no identity"
        );

        let request = request_with("x-forwarded-for", "::ffff:192.0.2.7");
        assert_eq!(
            default_extract_ip(request.headers(), request.extensions()),
            Some(ip("::ffff:192.0.2.7")),
            "the mapped form parses; the stores canonicalize it"
        );
    }

    #[test]
    fn custom_ip_extractor_replaces_the_default() {
        let stage = RateLimitStage::builder(RateLimitStageConfig::default())
            .ip_extractor(|_headers, _extensions| Some(ip("192.0.2.99")))
            .build()
            .expect("valid config");
        let request = Request::builder().body(()).expect("request");
        let extracted = (stage.extract_ip)(request.headers(), request.extensions());
        assert_eq!(extracted, Some(ip("192.0.2.99")));
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
        type Response = Response<String>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<&'static str>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            drop(request);
            Box::pin(async move { Ok(Response::new("inner".to_owned())) })
        }
    }

    /// A request the default extractor can read the client IP from: the
    /// peer address as a `SocketAddr` extension, the wire convention.
    fn request_from_client(ip_text: &str) -> Request<&'static str> {
        let socket = SocketAddr::from_str(&format!("{ip_text}:65535")).expect("socket");
        Request::builder()
            .extension(socket)
            .body("body")
            .expect("request")
    }

    #[test]
    fn layer_passes_through_and_the_inner_service_answers() {
        let layer = RateLimitStageLayer::new(
            RateLimitStage::new(RateLimitStageConfig::default()).expect("default config"),
        );
        let inner = Inner::new();
        let mut service = ServiceBuilder::new().layer(layer).service(inner.clone());

        let response = block_on(service.call(request_from_client("192.0.2.20"))).expect("ready");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &"inner");
        assert_eq!(inner.call_count(), 1);
    }

    #[test]
    fn layer_answers_the_throttle_without_hitting_the_inner_service() {
        let stage = throttling_stage(1, Arc::new(system_clock));
        let inner = Inner::new();
        let mut service = ServiceBuilder::new()
            .layer(RateLimitStageLayer::new(stage))
            .service(inner.clone());

        let first = block_on(service.call(request_from_client("192.0.2.21"))).expect("ready");
        assert_eq!(first.status(), StatusCode::OK);

        let second = block_on(service.call(request_from_client("192.0.2.21"))).expect("ready");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            second
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("60"),
            "Retry-After carries the window"
        );
        assert_eq!(second.body(), &THROTTLED_BODY);
        assert_eq!(inner.call_count(), 1, "the throttled request never hits it");
    }

    #[test]
    fn layer_answers_the_banned_shape() {
        let stage = throttling_stage(10, Arc::new(system_clock));
        stage.bans().ban_ip(ip("192.0.2.22"), 60, "x").expect("ban");
        let inner = Inner::new();
        let mut service = ServiceBuilder::new()
            .layer(RateLimitStageLayer::new(stage))
            .service(inner.clone());

        let response = block_on(service.call(request_from_client("192.0.2.22"))).expect("ready");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.body(), &BANNED_BODY);
        assert_eq!(inner.call_count(), 0, "bans answer before the inner runs");
    }

    #[test]
    fn layer_clone_shares_the_stage_stores() {
        let stage = throttling_stage(1, Arc::new(system_clock));
        let mut first = RateLimitStageService {
            inner: Inner::new(),
            stage,
        };
        let mut second = first.clone();

        let _ = block_on(first.call(request_from_client("192.0.2.23"))).expect("ready");
        let second_response =
            block_on(second.call(request_from_client("192.0.2.23"))).expect("ready");
        assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // ---- Event and log emissions (the reference event surface) ----

    use std::sync::Mutex;

    use crate::event_types::{EVENT_IP_BANNED, EVENT_PENETRATION_ATTEMPT, EVENT_RATE_LIMITED};
    use crate::events::{EventFilter, MIDDLEWARE_HANDLER_NAME};

    type EventLog = Arc<Mutex<Vec<(String, String, String)>>>;

    fn recording_bus() -> (EventLog, Arc<SecurityEventBus>) {
        let seen: EventLog = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let bus = Arc::new(SecurityEventBus::new(true).on_event(Arc::new(
            move |event: &SecurityEvent| {
                sink.lock().expect("sink").push((
                    event.event_type.clone(),
                    event.action_taken.clone(),
                    event.reason.clone(),
                ));
            },
        )));
        (seen, bus)
    }

    fn event_stage(
        config: RateLimitStageConfig,
        clock: Clock,
        bus: Arc<SecurityEventBus>,
    ) -> RateLimitStage {
        RateLimitStage::builder(config)
            .clock(clock)
            .events(bus)
            .build()
            .expect("valid stage config")
    }

    #[test]
    fn rate_limit_crossing_emits_the_reference_rate_limited_event() {
        let (seen, bus) = recording_bus();
        let stage = event_stage(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit: 1,
                    ..RateLimitConfig::default()
                },
                ..RateLimitStageConfig::default()
            },
            Arc::new(system_clock),
            bus,
        );
        let visitor = ip("192.0.2.41");
        assert!(stage.decide(Some(visitor), None, None).is_none());
        let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);

        let events = seen.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        let (event_type, action_taken, reason) = &events[0];
        assert_eq!(event_type, EVENT_RATE_LIMITED);
        assert_eq!(action_taken, "request_blocked");
        assert_eq!(reason, "Rate limit exceeded: 2 requests in 60s window");
    }

    #[test]
    fn detection_crossing_emits_penetration_attempt_and_ip_banned() {
        let (seen, bus) = recording_bus();
        let stage = event_stage(
            RateLimitStageConfig {
                ip_ban: IpBanConfig::new(true, 1, 3600, Vec::<(String, ThreatBanEntry)>::new())
                    .expect("valid ban config"),
                ..RateLimitStageConfig::default()
            },
            Arc::new(system_clock),
            bus,
        );
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["sqli".to_owned()],
            trigger_info: "sqli in ?q=1".to_owned(),
        };
        let answer = stage
            .decide(Some(ip("192.0.2.42")), None, Some(&finding))
            .expect("ban crossing");
        assert_eq!(answer.body, BAN_CROSSED_BODY);

        let events = seen.lock().expect("sink").clone();
        let types: Vec<&str> = events.iter().map(|(t, _, _)| t.as_str()).collect();
        assert_eq!(types, [EVENT_IP_BANNED, EVENT_PENETRATION_ATTEMPT]);
        assert_eq!(events[0].1, "banned");
        assert_eq!(events[1].1, "request_blocked");
        assert_eq!(events[1].2, "Penetration attempt detected: sqli in ?q=1");
    }

    #[test]
    fn passive_detection_emits_logged_only_penetration_attempt() {
        let (seen, bus) = recording_bus();
        let stage = event_stage(
            RateLimitStageConfig {
                passive_mode: true,
                ..RateLimitStageConfig::default()
            },
            Arc::new(system_clock),
            bus,
        );
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["xss".to_owned()],
            trigger_info: "script tag".to_owned(),
        };
        assert!(
            stage
                .decide(Some(ip("192.0.2.43")), None, Some(&finding))
                .is_none()
        );

        let events = seen.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, EVENT_PENETRATION_ATTEMPT);
        assert_eq!(events[0].1, "logged_only");
        assert_eq!(
            events[0].2,
            "Suspicious pattern detected (passive mode): script tag"
        );
    }

    #[test]
    fn muted_event_types_never_reach_the_bus() {
        let (seen, _bus) = recording_bus();
        let filtered = Arc::new(
            SecurityEventBus::new(true)
                .with_filter(EventFilter {
                    muted_event_types: HashSet::from([EVENT_RATE_LIMITED.to_owned()]),
                })
                .on_event({
                    let sink = seen.clone();
                    Arc::new(move |event: &SecurityEvent| {
                        sink.lock().expect("sink").push((
                            event.event_type.clone(),
                            String::new(),
                            String::new(),
                        ));
                    })
                }),
        );
        let stage = event_stage(
            RateLimitStageConfig {
                rate_limit: RateLimitConfig {
                    enable_rate_limiting: true,
                    rate_limit: 1,
                    ..RateLimitConfig::default()
                },
                ..RateLimitStageConfig::default()
            },
            Arc::new(system_clock),
            filtered,
        );
        let visitor = ip("192.0.2.44");
        let _ = stage.decide(Some(visitor), None, None);
        let _ = stage.decide(Some(visitor), None, None);
        assert!(seen.lock().expect("sink").is_empty());
    }

    #[test]
    fn compose_suspicious_log_matches_the_reference_wording_and_redaction() {
        let stage = RateLimitStage::new(RateLimitStageConfig::default()).expect("config");
        let observation = RequestObservation {
            method: Some("GET".to_owned()),
            url: Some("/login?token=abc".to_owned()),
            user_agent: None,
        };
        let line = stage
            .compose_suspicious_log(
                ip("192.0.2.45"),
                "Rate limit exceeded for IP: 192.0.2.45 (11 requests in 60s window)",
                Some(&observation),
                false,
                "",
                "rate_limit",
            )
            .expect("logged");
        assert_eq!(
            line,
            "Suspicious activity detected from 192.0.2.45: GET /login?token=[REDACTED] - \
             Reason: Rate limit exceeded for IP: 192.0.2.45 (11 requests in 60s window) - \
             Headers: {}"
        );
        assert_eq!(MIDDLEWARE_HANDLER_NAME, "middleware");
    }

    // ---- custom_error_responses and on_block (the reference response
    // factory and block-hook contract) ----

    use crate::responses::{BlockPayload, CustomErrorResponses};

    type BlockLog = Arc<Mutex<Vec<BlockPayload>>>;

    fn recording_hook() -> (BlockLog, OnBlockHook) {
        let seen: BlockLog = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let hook: OnBlockHook = Arc::new(move |payload: &BlockPayload| {
            sink.lock().expect("sink").push(payload.clone());
        });
        (seen, hook)
    }

    #[test]
    fn custom_error_responses_override_the_default_body() {
        let mut custom = CustomErrorResponses::new();
        custom.insert(429, "Slow down".to_owned());
        let stage = RateLimitStage::new(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                ..RateLimitConfig::default()
            },
            passive_mode: false,
            custom_error_responses: custom,
            ..RateLimitStageConfig::default()
        })
        .expect("config");
        let visitor = ip("192.0.2.61");
        let _ = stage.decide(Some(visitor), None, None);
        let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(throttled.body, THROTTLED_BODY, "default recorded");
        assert_eq!(throttled.custom_body.as_deref(), Some("Slow down"));
    }

    #[test]
    fn statuses_without_an_entry_keep_the_default_body() {
        let mut custom = CustomErrorResponses::new();
        custom.insert(403, "Nope".to_owned());
        let stage = RateLimitStage::new(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                ..RateLimitConfig::default()
            },
            passive_mode: false,
            custom_error_responses: custom,
            ..RateLimitStageConfig::default()
        })
        .expect("config");
        let visitor = ip("192.0.2.62");
        let _ = stage.decide(Some(visitor), None, None);
        let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(throttled.custom_body, None, "429 not configured");
    }

    #[test]
    fn on_block_fires_once_per_block_with_the_reference_keys() {
        let (seen, hook) = recording_hook();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                ..RateLimitConfig::default()
            },
            passive_mode: false,
            ..RateLimitStageConfig::default()
        })
        .clock(Arc::new(system_clock))
        .observability(ObservabilityConfig {
            log_suspicious_level: Some(LogLevel::Warning),
            muted_check_logs: None,
            sensitive: SensitiveNames::default(),
        })
        .on_block(hook)
        .build()
        .expect("config");
        let visitor = ip("192.0.2.63");
        let _ = stage.decide(Some(visitor), None, None);
        let _ = stage.decide(Some(visitor), None, None);
        let events = seen.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        let payload = &events[0];
        assert_eq!(payload.check_name, "rate_limit");
        assert_eq!(payload.client_ip, "192.0.2.63");
        assert_eq!(payload.status_code, Some(429));
        assert!(!payload.passive_mode);
        assert!(payload.path.starts_with('/'), "path present");
    }

    #[test]
    fn passive_detection_fires_on_block_with_no_status() {
        let (seen, hook) = recording_hook();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            passive_mode: true,
            ..RateLimitStageConfig::default()
        })
        .clock(Arc::new(system_clock))
        .observability(ObservabilityConfig {
            log_suspicious_level: Some(LogLevel::Warning),
            muted_check_logs: None,
            sensitive: SensitiveNames::default(),
        })
        .on_block(hook)
        .build()
        .expect("config");
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["xss".to_owned()],
            trigger_info: "script tag".to_owned(),
        };
        assert!(
            stage
                .decide(Some(ip("192.0.2.64")), None, Some(&finding))
                .is_none()
        );
        let events = seen.lock().expect("sink").clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].check_name, "suspicious_activity");
        assert_eq!(events[0].status_code, None);
        assert!(events[0].passive_mode);
        assert_eq!(events[0].trigger_info, "script tag");
    }

    #[test]
    fn the_payload_path_is_redacted_through_the_sensitivity_sets() {
        let (seen, hook) = recording_hook();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                ..RateLimitConfig::default()
            },
            passive_mode: false,
            ..RateLimitStageConfig::default()
        })
        .clock(Arc::new(system_clock))
        .observability(ObservabilityConfig {
            log_suspicious_level: Some(LogLevel::Warning),
            muted_check_logs: None,
            sensitive: SensitiveNames::default(),
        })
        .on_block(hook)
        .build()
        .expect("config");
        let visitor = ip("192.0.2.65");
        let observation = RequestObservation {
            method: Some("GET".to_owned()),
            url: Some("/login?token=abc".to_owned()),
            user_agent: None,
        };
        let _ = stage.decide_for_path_observed(
            Some(visitor),
            None,
            None,
            None,
            None,
            Some(&observation),
        );
        let _ = stage.decide_for_path_observed(
            Some(visitor),
            None,
            None,
            None,
            None,
            Some(&observation),
        );
        let events = seen.lock().expect("sink").clone();
        assert_eq!(events[0].path, "/login?token=[REDACTED]");
    }

    // ---- distributed store mode (the reference Redis-backed windows
    // and bans) ----

    use guard_core_engine::distributed::StoreError;

    use guard_core_engine::distributed::MemoryStore;

    #[test]
    fn fail_closed_distributed_store_answers_the_reference_503() {
        let store = Arc::new(MemoryStore::default());
        store.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 10,
                ..RateLimitConfig::default()
            },
            passive_mode: false,
            ..RateLimitStageConfig::default()
        })
        .clock(Arc::new(system_clock))
        .distributed_store(
            Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
            "guard_core:",
            false,
        )
        .build()
        .expect("config");
        let answer = stage
            .decide(Some(ip("192.0.2.91")), None, None)
            .expect("fail closed");
        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer.body, REDIS_UNAVAILABLE_BODY);
    }

    #[test]
    fn fail_open_distributed_store_falls_back_to_the_local_window() {
        let store = Arc::new(MemoryStore::default());
        store.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 1,
                ..RateLimitConfig::default()
            },
            passive_mode: false,
            ..RateLimitStageConfig::default()
        })
        .clock(Arc::new(system_clock))
        .distributed_store(
            Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
            "guard_core:",
            true,
        )
        .build()
        .expect("config");
        let visitor = ip("192.0.2.92");
        assert!(stage.decide(Some(visitor), None, None).is_none());
        let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn a_live_distributed_store_shares_one_budget_through_the_stage() {
        let store = Arc::new(MemoryStore::default());
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 2,
                ..RateLimitConfig::default()
            },
            passive_mode: false,
            ..RateLimitStageConfig::default()
        })
        .clock(Arc::new(system_clock))
        .distributed_store(
            Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
            "guard_core:",
            false,
        )
        .build()
        .expect("config");
        let visitor = ip("192.0.2.93");
        assert!(stage.decide(Some(visitor), None, None).is_none());
        assert!(stage.decide(Some(visitor), None, None).is_none());
        let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(throttled.custom_body, None);
        // The hits landed under the reference Redis key layout.
        assert!(
            store
                .windows
                .lock()
                .expect("windows")
                .contains_key("guard_core:rate_limit:rate:192.0.2.93")
        );
        let _ = StoreError(String::new());
    }

    // ---- the handle-injection seams (limiter / ban_manager) ----

    #[test]
    fn an_injected_limiter_handle_shares_its_windows_with_the_stage() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let stage = RateLimitStage::builder(RateLimitStageConfig::default())
            .limiter(limiter.clone())
            .build()
            .expect("config");
        let visitor = ip("192.0.2.94");
        assert!(stage.decide(Some(visitor), None, None).is_none());
        let throttled = stage.decide(Some(visitor), None, None).expect("throttled");
        assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
        // The out-of-band handle sees the same window: the injected handle
        // is the stage's, not a rebuilt one.
        assert!(!stage.limiter().check(visitor, None).allowed);
        let _ = &limiter;
    }

    #[test]
    fn an_injected_ban_handle_shares_bans_and_counters_with_the_stage() {
        let manager = IpBanManager::new();
        let counters = ViolationCounters::new();
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                ..IpBanConfig::default()
            },
            ..RateLimitStageConfig::default()
        })
        .ban_manager(manager.clone(), counters.clone())
        .build()
        .expect("config");
        let visitor = ip("192.0.2.95");
        // Out-of-band ban (an operator did it) is visible to the stage.
        manager.ban_ip(visitor, 60, "operator").expect("ban");
        let banned = stage.decide(Some(visitor), None, None).expect("banned");
        assert_eq!(banned.status, StatusCode::FORBIDDEN);
        assert_eq!(banned.body, BANNED_BODY);
        // And the stage counts into the injected counters.
        stage.counters().record(visitor, &["sqli"]);
        let snapshot = counters.snapshot(visitor);
        assert_eq!(snapshot.get("sqli"), Some(&1));
    }

    // ---- the feed_finding split (the two-phase frameworks' seam) ----

    #[test]
    fn feed_finding_after_decide_records_exactly_one_window_hit() {
        // The two-phase flow (Rocket): the on_request pass decides with the
        // metadata finding, then the data guard feeds the body finding. The
        // rate window must record exactly ONE hit across both, and each
        // finding counts its own categories once.
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 2,
                ..RateLimitConfig::default()
            },
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 100,
                ..IpBanConfig::default()
            },
            ..RateLimitStageConfig::default()
        })
        .build()
        .expect("config");
        let visitor = ip("192.0.2.96");
        let metadata_finding = ThreatFinding {
            is_threat: true,
            categories: vec!["sqli".to_owned()],
            trigger_info: "metadata".to_owned(),
        };
        let body_finding = ThreatFinding {
            is_threat: true,
            categories: vec!["xss".to_owned()],
            trigger_info: "body".to_owned(),
        };
        assert!(
            stage
                .decide_for_path(
                    Some(visitor),
                    Some("/submit"),
                    None,
                    None,
                    Some(&metadata_finding)
                )
                .is_none()
        );
        assert!(
            stage
                .feed_finding(Some(visitor), false, Some(&body_finding), None)
                .is_none()
        );
        // The window has one hit, not two: hits 2 and 3 of a limit-2
        // limiter decide allowed and throttled.
        assert!(
            stage.limiter().check(visitor, None).allowed,
            "the window recorded exactly one hit across decide and feed"
        );
        assert!(
            !stage.limiter().check(visitor, None).allowed,
            "the second fresh hit crosses the limit-2 window"
        );
        // Each finding fed exactly once.
        let snapshot = stage.counters().snapshot(visitor);
        assert_eq!(snapshot.get("sqli"), Some(&1));
        assert_eq!(snapshot.get("xss"), Some(&1));
    }

    #[test]
    fn feed_finding_crosses_the_threshold_with_the_same_answer() {
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            ip_ban: IpBanConfig {
                enable_ip_banning: true,
                auto_ban_threshold: 100,
                threat_ban_config: std::iter::once((
                    "dir_traversal".to_owned(),
                    ThreatBanEntry {
                        threshold: 2,
                        duration: 60,
                    },
                ))
                .collect(),
                ..IpBanConfig::default()
            },
            ..RateLimitStageConfig::default()
        })
        .build()
        .expect("config");
        let visitor = ip("192.0.2.97");
        let finding = ThreatFinding {
            is_threat: true,
            categories: vec!["dir_traversal".to_owned()],
            trigger_info: "traversal".to_owned(),
        };
        // Violation 1 through the full decide, violation 2 through the
        // split feed: both count, and the feed answers the same 403 the
        // decide path would.
        assert!(
            stage
                .decide_for_path(Some(visitor), None, None, None, Some(&finding))
                .is_none()
        );
        let crossed = stage.feed_finding(Some(visitor), false, Some(&finding), None);
        let crossed = crossed.expect("the crossed threshold bans");
        assert_eq!(crossed.status, StatusCode::FORBIDDEN);
        assert_eq!(crossed.body, BAN_CROSSED_BODY);
        // A whitelisted IP never feeds (the reference skips a whitelisted
        // IP only), and an unattributed request never feeds.
        let other = ip("192.0.2.98");
        assert!(
            stage
                .feed_finding(Some(other), true, Some(&finding), None)
                .is_none()
        );
        assert!(
            stage
                .feed_finding(None, false, Some(&finding), None)
                .is_none()
        );
        assert_eq!(stage.counters().snapshot(other).len(), 0);
    }
    #[test]
    fn dbg_window_counting() {
        let stage = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit: RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 2,
                ..RateLimitConfig::default()
            },
            ..RateLimitStageConfig::default()
        })
        .build()
        .expect("config");
        let visitor = ip("192.0.2.96");
        let d = stage.limiter().check(visitor, Some("/submit"));
        println!("after check1: allowed={} count={}", d.allowed, d.count);
        let d = stage.limiter().check(visitor, Some("/submit"));
        println!("after check2: allowed={} count={}", d.allowed, d.count);
        let d = stage.limiter().check(visitor, None);
        println!("after check3 None: allowed={} count={}", d.allowed, d.count);
        println!("tracked={}", stage.limiter().tracked_windows());
    }
}
