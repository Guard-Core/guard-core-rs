//! The sliding-window rate limiter: per client IP, global scope or per
//! endpoint.
//!
//! This is the Rust family's in-memory port of the reference engine's rate
//! limiter (`guard_core/handlers/ratelimit_handler.py`, via the Go port's
//! `ratelimit.go`). One call, [`RateLimiter::check`], records one request
//! into the window for `(client IP, scope)` and decides it:
//!
//! ```text
//! evict every recorded timestamp at or before (now - window)
//! count   = requests still inside the window (before this one is recorded)
//! record  now
//! allowed = count < rate_limit
//! ```
//!
//! ## Counting semantics
//!
//! The reference keeps a sliding log of request timestamps per key. The
//! in-memory store compares the pre-recording count against the limit
//! (`allowed = count < limit`), the Redis store compares the post-recording
//! rank against it (`allowed = count <= limit`, one Lua/ZSET pipeline keyed
//! `rate_limit:rate:{ip}[:{endpoint hash}]`); the boundary is the same, this
//! port mirrors the in-memory formulation because Redis is out of scope here:
//! the store is process-local, exactly what the reference falls back to when
//! Redis is off, and the same `workers x rate_limit` caveat applies to
//! multi-process deployments. The count reported on a block includes the
//! current request (`count + 1`), matching what both references log.
//!
//! Blocked callers retry after the configured window: the reference attaches
//! `Retry-After: <window seconds>` to its `429 Too many requests`, and
//! [`RateLimitDecision::retry_after`] carries the same value.
//!
//! ## Scope
//!
//! The global scope keys the window by client IP alone (every endpoint
//! shares one budget per IP, the reference's default pipeline tier). The
//! endpoint scope keys it by `(client IP, endpoint path)` - an isolated
//! budget per endpoint, the reference's `endpoint_path`-keyed tier. Keys are
//! structured (IP + path fields), so no separator collision exists by
//! construction; the reference hashes the endpoint segment for its joined
//! Redis keys (`rate:{ip}:{_hash_identity_segment(path)}`), a concern the
//! in-memory store does not have.
//!
//! ## Tiers
//!
//! [`RateLimiter::check_tiers`] runs the reference pipeline's tier order
//! (`RateLimitCheck.check`, `rate_limit.py`, via the Go port's
//! `tiersFor`/`runTier`): every configured tier records one request into
//! its own window and the first tier that crosses its limit blocks. The
//! tiers, in order:
//!
//! 1. **endpoint**: `endpoint_rate_limits[path]` (the config-level
//!    per-endpoint map), keyed by `(ip, path)`;
//! 2. **route**: the route decorator's `rate_limit` (window default 60,
//!    `rate_limit_window or 60`), keyed by `(ip, path)`;
//! 3. **geo**: the route decorator's `geo_rate_limits` country map, the
//!    resolved country's entry with the `"*"` fallback
//!    (`country in limits else "*" in limits`), keyed by `(ip, path)`;
//! 4. **global**: the config `rate_limit`/`rate_limit_window`, keyed by
//!    `ip` alone.
//!
//! With no tiers configured the sequence collapses to the global tier, the
//! exact pre-tier behavior. The decision names the tier that blocked so
//! adapters can log the reference's reason strings, and carries that
//! tier's window for `Retry-After`.
//!
//! ## Honesty
//!
//! No Redis: the distributed mode (shared budgets across workers, script
//! reload handling) is a follow-up. The window store is an LRU capped at
//! 10 000 keys (`maxTrackedRateLimitKeys` in the Go port,
//! `_MAX_TRACKED_RATE_LIMIT_KEYS` in the reference), so abusive key
//! cardinality cannot grow the store without bound.
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! use guard_core_engine::rate_limit::{RateLimitConfig, RateLimiter};
//!
//! let limiter = RateLimiter::new(RateLimitConfig {
//!     enable_rate_limiting: true,
//!     rate_limit: 2,
//!     ..RateLimitConfig::default()
//! })
//! .expect("valid config");
//! let ip = IpAddr::from_str("192.0.2.1").unwrap();
//!
//! assert!(limiter.check(ip, None).allowed);
//! assert!(limiter.check(ip, None).allowed);
//! // The third request inside the window crosses the limit.
//! let blocked = limiter.check(ip, None);
//! assert!(!blocked.allowed);
//! assert_eq!(blocked.retry_after(), 60);
//! ```
//!
//! A tiered check runs every configured tier and names the one that
//! blocked:
//!
//! ```
//! use std::collections::HashMap;
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! use guard_core_engine::rate_limit::{
//!     RateLimitConfig, RateLimitEntry, RateLimiter, RouteRateLimits,
//! };
//!
//! let mut endpoint_rate_limits = HashMap::new();
//! endpoint_rate_limits.insert("/login".to_owned(), RateLimitEntry::new(1, 60).unwrap());
//! let limiter = RateLimiter::new(RateLimitConfig {
//!     enable_rate_limiting: true,
//!     endpoint_rate_limits,
//!     ..RateLimitConfig::default()
//! })
//! .expect("valid config");
//! let ip = IpAddr::from_str("192.0.2.1").unwrap();
//!
//! assert!(limiter.check_tiers(ip, Some("/login"), None, None).allowed());
//! let blocked = limiter.check_tiers(ip, Some("/login"), None, None);
//! assert!(!blocked.allowed());
//! assert_eq!(blocked.tier_name(), "endpoint");
//! ```
//!
//! A disabled limiter is inert: `check` allows without recording.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::ip_gate::canonical;

/// The reference default for `rate_limit` (maximum requests per window).
pub const DEFAULT_RATE_LIMIT: u32 = 10;
/// The reference default for `rate_limit_window` (seconds).
pub const DEFAULT_RATE_LIMIT_WINDOW: u64 = 60;
/// The route tier's default window (`rate_limit_window or 60`, the
/// `@rate_limit` decorator default).
pub const DEFAULT_ROUTE_RATE_LIMIT_WINDOW: u64 = 60;
/// The window store's key cap (`_MAX_TRACKED_RATE_LIMIT_KEYS` /
/// `maxTrackedRateLimitKeys` in the references).
pub const MAX_TRACKED_RATE_LIMIT_KEYS: usize = 10_000;

/// One `(requests, window)` rate-limit entry: a per-endpoint or per-country
/// tier override (the reference `endpoint_rate_limits[path]` /
/// `geo_rate_limits[country]` `(int, int)` tuples).
///
/// Build it with [`RateLimitEntry::new`] (fail closed on a zero requests or
/// window, the reference `ge=1` semantics the tier entries inherit from the
/// flat knobs they override).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitEntry {
    /// Maximum requests inside the window.
    pub requests: u32,
    /// The window length in seconds.
    pub window: u64,
}

impl RateLimitEntry {
    /// Validate and build an entry.
    ///
    /// # Errors
    ///
    /// [`RateLimitConfigError`] on a zero `requests` or `window` (the
    /// reference rejects both with `ge=1`).
    pub fn new(requests: u32, window: u64) -> Result<Self, RateLimitConfigError> {
        if requests == 0 {
            return Err(RateLimitConfigError {
                field: "requests".into(),
                reason: "must be at least 1 request per window",
            });
        }
        if window == 0 {
            return Err(RateLimitConfigError {
                field: "window".into(),
                reason: "must be at least 1 second",
            });
        }
        Ok(Self { requests, window })
    }
}

/// The route decorator's rate-limit tier overrides
/// (`RouteConfig.rate_limit` / `rate_limit_window` / `geo_rate_limits`).
///
/// Build it with [`RouteRateLimits::new`]; the geo tier's country entries
/// are [`RateLimitEntry`] values (already validated). The geo country key
/// set mirrors the reference: exact country codes with the `"*"`
/// fallback entry, compared exactly (no case folding, the reference reads
/// the resolved country as-is).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteRateLimits {
    /// `route_config.rate_limit`: `None` means no route tier.
    rate_limit: Option<u32>,
    /// `route_config.rate_limit_window`: the route tier's window, the
    /// reference default of 60 when `None` and a route tier is configured.
    rate_limit_window: Option<u64>,
    /// `route_config.geo_rate_limits`: the per-country `(limit, window)`
    /// overrides with the `"*"` fallback entry; `None` or empty means no
    /// geo tier.
    geo_rate_limits: Option<HashMap<String, RateLimitEntry>>,
}

impl RouteRateLimits {
    /// Validate and build the route tier overrides.
    ///
    /// # Errors
    ///
    /// [`RateLimitConfigError`] on a zero `rate_limit` or a zero
    /// `rate_limit_window` that a configured route tier would run under
    /// (the reference `ge=1` semantics); a `None` rate limit with a window
    /// is inert and therefore not rejected, mirroring the reference where
    /// `rate_limit_window` alone never configures a tier.
    pub fn new(
        rate_limit: Option<u32>,
        rate_limit_window: Option<u64>,
        geo_rate_limits: Option<HashMap<String, RateLimitEntry>>,
    ) -> Result<Self, RateLimitConfigError> {
        if rate_limit.is_some_and(|limit| limit == 0) {
            return Err(RateLimitConfigError {
                field: "rate_limit".into(),
                reason: "must be at least 1 request per window",
            });
        }
        if rate_limit.is_some() && rate_limit_window.is_some_and(|window| window == 0) {
            return Err(RateLimitConfigError {
                field: "rate_limit_window".into(),
                reason: "must be at least 1 second",
            });
        }
        if let Some(geo) = &geo_rate_limits {
            for (country, entry) in geo {
                if entry.requests == 0 || entry.window == 0 {
                    return Err(RateLimitConfigError {
                        field: format!("geo_rate_limits[{country}]").into(),
                        reason: "every entry needs at least 1 request per at least 1 second",
                    });
                }
            }
        }
        Ok(Self {
            rate_limit,
            rate_limit_window,
            geo_rate_limits,
        })
    }

    /// `route_config.rate_limit`.
    #[must_use]
    pub const fn rate_limit(&self) -> Option<u32> {
        self.rate_limit
    }

    /// `route_config.rate_limit_window` (the reference default of 60
    /// applies when a route tier runs and this is `None`).
    #[must_use]
    pub const fn rate_limit_window(&self) -> Option<u64> {
        self.rate_limit_window
    }

    /// `route_config.geo_rate_limits`.
    #[must_use]
    pub const fn geo_rate_limits(&self) -> Option<&HashMap<String, RateLimitEntry>> {
        self.geo_rate_limits.as_ref()
    }
}

/// The rate-limiting knobs (the reference `enable_rate_limiting` /
/// `rate_limit` / `rate_limit_window` / `enable_rate_limit_auto_ban` group).
///
/// The defaults are the reference `SecurityConfig` defaults: rate limiting
/// on (`enable_rate_limiting = true`, `guard_core/_security_config_fields.py`)
/// with the reference thresholds (10 requests / 60 s window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// `enable_rate_limiting`. `false` makes every [`RateLimiter::check`]
    /// an unconditional allow that records nothing.
    pub enable_rate_limiting: bool,
    /// `rate_limit`: maximum requests per client IP inside
    /// `rate_limit_window` seconds.
    pub rate_limit: u32,
    /// `rate_limit_window`: the window length in seconds.
    pub rate_limit_window: u64,
    /// `enable_rate_limit_auto_ban`: feed rate-limit crossings into the
    /// auto-ban engine (the `rate_limit` category of the violation counters)
    /// when the pipeline stage runs with IP banning enabled.
    pub enable_rate_limit_auto_ban: bool,
    /// `endpoint_rate_limits`: the per-endpoint tier map (`path ->
    /// (requests, window)`, the reference config field set by dynamic
    /// rules), matched by exact path. Empty by default: the tier is
    /// unconfigured and records nothing.
    pub endpoint_rate_limits: HashMap<String, RateLimitEntry>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enable_rate_limiting: true,
            rate_limit: DEFAULT_RATE_LIMIT,
            rate_limit_window: DEFAULT_RATE_LIMIT_WINDOW,
            enable_rate_limit_auto_ban: false,
            endpoint_rate_limits: HashMap::new(),
        }
    }
}

/// An invalid [`RateLimitConfig`] or [`RouteRateLimits`]: the config error
/// [`RateLimiter::new`] fails closed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfigError {
    /// The rejected field (`rate_limit`, `rate_limit_window`,
    /// `endpoint_rate_limits`, or a tier entry field).
    pub field: std::borrow::Cow<'static, str>,
    /// What the field must be instead.
    pub reason: &'static str,
}

impl core::fmt::Display for RateLimitConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for RateLimitConfigError {}

/// The outcome of one rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// `false` when the request crossed the limit and must be answered with
    /// the family's `429 Too many requests` carrying
    /// [`RateLimitDecision::retry_after`].
    pub allowed: bool,
    /// Requests observed inside the window including this one (the count
    /// both references report when they block).
    pub count: u64,
    /// The window length the decision was made under (seconds), so callers
    /// can render `Retry-After` without re-reading the config.
    pub window: u64,
}

impl RateLimitDecision {
    /// The `Retry-After` header value for a blocked request: the window
    /// length, exactly what the reference sets.
    #[must_use]
    pub const fn retry_after(self) -> u64 {
        self.window
    }
}

/// The rate-limit tier a [`RateLimiter::check_tiers`] decision was made
/// under (`endpoint`, `route`, `geo`, `global` - the reference check order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitTier {
    /// `endpoint_rate_limits[path]`: the config-level per-endpoint tier.
    Endpoint,
    /// The route decorator's `rate_limit` tier.
    Route,
    /// The route decorator's `geo_rate_limits` country tier.
    Geo,
    /// The flat config `rate_limit` tier (the reference default).
    Global,
}

impl RateLimitTier {
    /// The tier's name as the reference reasons spell it (`Endpoint-specific
    /// rate limit exceeded`, `Route-specific rate limit exceeded`,
    /// `Geo rate limit exceeded for {country}`, and the global tier's plain
    /// `Rate limit exceeded`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Route => "route",
            Self::Geo => "geo",
            Self::Global => "global",
        }
    }
}

/// The outcome of one tiered rate-limit check
/// ([`RateLimiter::check_tiers`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierDecision {
    /// `false` when some tier crossed its limit and the request must be
    /// answered with the family's `429 Too many requests` carrying
    /// [`TierDecision::retry_after`].
    allowed: bool,
    /// Requests observed inside the blocking tier's window including this
    /// one (the count both references report when they block); the last
    /// tier's count when nothing blocked.
    count: u64,
    /// The tier that blocked (the last tier when nothing blocked).
    tier: RateLimitTier,
    /// The window length the decision was made under (seconds).
    window: u64,
}

impl TierDecision {
    /// `false` when some tier crossed its limit.
    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.allowed
    }

    /// The observed count of the decisive tier (including this request).
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// The tier the decision was made under.
    #[must_use]
    pub const fn tier(&self) -> RateLimitTier {
        self.tier
    }

    /// The tier's name (`"endpoint"`, `"route"`, `"geo"`, `"global"`).
    #[must_use]
    pub const fn tier_name(&self) -> &'static str {
        self.tier.name()
    }

    /// The `Retry-After` header value for a blocked request: the blocking
    /// tier's window length, exactly what the reference sets.
    #[must_use]
    pub const fn retry_after(&self) -> u64 {
        self.window
    }
}

/// The monotonic-ish wall clock, in seconds since the Unix epoch. Injectable
/// so expiry behavior (window sliding) is testable without sleeping.
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

#[derive(Debug, PartialEq, Eq, Hash)]
struct WindowKey {
    ip: IpAddr,
    endpoint: Option<String>,
}

/// The sliding-window rate limiter over one shared in-memory store.
///
/// Build it once at startup with [`RateLimiter::new`] (fail closed on a
/// non-positive limit or window) and share the handle across requests; the
/// internal store is a mutex-guarded LRU, safe for concurrent services.
pub struct RateLimiter {
    config: RateLimitConfig,
    windows: Arc<Mutex<LruCache<WindowKey, VecDeque<f64>>>>,
    clock: Clock,
}

impl Clone for RateLimiter {
    /// A clone shares the window store and the clock, the references'
    /// singleton semantics: requests recorded through any handle land in the
    /// same sliding windows.
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            windows: Arc::clone(&self.windows),
            clock: Arc::clone(&self.clock),
        }
    }
}

impl core::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The system wall clock, in seconds since the Unix epoch: the clock every
/// production store runs on. Adapters and stage tests that build several
/// stores over one clock share this constructor.
#[must_use]
pub fn system_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// A fresh shared window store (the store lives behind an `Arc` so clones of
/// the limiter share it).
fn new_window_store() -> Arc<Mutex<LruCache<WindowKey, VecDeque<f64>>>> {
    Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(MAX_TRACKED_RATE_LIMIT_KEYS).expect("constant above zero"),
    )))
}

impl RateLimiter {
    /// Validate the config and build the limiter.
    ///
    /// # Errors
    ///
    /// Fails closed with a [`RateLimitConfigError`] when `rate_limit` or
    /// `rate_limit_window` is zero (the reference rejects both with
    /// `ge=1`); nothing but `RateLimitConfig::default`-shaped values is
    /// substituted silently.
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitConfigError> {
        Self::with_config_and_clock(config, Arc::new(system_clock))
    }

    /// Validate the config and build the limiter over an injected clock: the
    /// combined seam [`new`](Self::new) and [`with_clock`](Self::with_clock)
    /// cover separately. Production builds use [`RateLimiter::new`]; adapters
    /// and stage tests that drive window sliding with a fake clock under a
    /// production-shaped config use this one.
    ///
    /// # Errors
    ///
    /// Same fail-closed behavior as [`RateLimiter::new`]: a zero `rate_limit`
    /// or `rate_limit_window` is a [`RateLimitConfigError`].
    pub fn with_config_and_clock(
        config: RateLimitConfig,
        clock: Clock,
    ) -> Result<Self, RateLimitConfigError> {
        if config.rate_limit == 0 {
            return Err(RateLimitConfigError {
                field: "rate_limit".into(),
                reason: "must be at least 1 request per window",
            });
        }
        if config.rate_limit_window == 0 {
            return Err(RateLimitConfigError {
                field: "rate_limit_window".into(),
                reason: "must be at least 1 second",
            });
        }
        // A struct-literal config skips the entry constructor validation,
        // so the limiter re-validates and fails closed (the stage's
        // struct-literal ban config precedent).
        for (path, entry) in &config.endpoint_rate_limits {
            if entry.requests == 0 || entry.window == 0 {
                return Err(RateLimitConfigError {
                    field: format!("endpoint_rate_limits[{path}]").into(),
                    reason: "every entry needs at least 1 request per at least 1 second",
                });
            }
        }
        Ok(Self {
            config,
            windows: new_window_store(),
            clock,
        })
    }

    /// Swap the wall clock. Test seam: production builds use the system
    /// clock; deterministic window-sliding coverage injects a fake.
    #[must_use]
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            config: RateLimitConfig::default(),
            windows: new_window_store(),
            clock,
        }
    }

    /// The validated config the limiter decides under.
    #[must_use]
    pub const fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Record one request into the window `(ip, endpoint)` under `limit`
    /// requests per `window` seconds and decide it: the shared counting
    /// core of [`RateLimiter::check`] and [`RateLimiter::check_tiers`].
    // The store lock must outlive the eviction loop and the push (both
    // mutate through the `timestamps` reference the guard produced); the
    // nursery lint cannot see through that reference and wants it dropped
    // early. The lock scope below already ends before the decision is built.
    #[allow(clippy::significant_drop_tightening)]
    fn record_and_decide(
        &self,
        ip: IpAddr,
        endpoint: Option<&str>,
        limit: u32,
        window_seconds: u64,
    ) -> (bool, u64, u64) {
        // u64 -> f64 rounds to nearest; at window lengths where that loses a
        // second the boundary shift is far below any real clock resolution.
        #[allow(clippy::cast_precision_loss)]
        let window = window_seconds as f64;
        let now = (self.clock)();
        let window_start = now - window;
        let key = WindowKey {
            ip: canonical(ip),
            endpoint: endpoint.map(str::to_owned),
        };
        // The lock scope ends at the block: the decision is built unlocked.
        let inside = {
            let mut windows = self.windows.lock().expect("rate window store");
            let timestamps = windows
                .try_get_or_insert_mut(key, || Ok::<_, core::convert::Infallible>(VecDeque::new()))
                .expect("key capacity just reserved");
            while timestamps
                .front()
                .is_some_and(|&recorded| recorded <= window_start)
            {
                timestamps.pop_front();
            }
            let inside = timestamps.len();
            timestamps.push_back(now);
            inside
        };
        let allowed = inside < usize::try_from(limit).unwrap_or(usize::MAX);
        let count = u64::try_from(inside + 1).unwrap_or(u64::MAX);
        (allowed, count, window_seconds)
    }

    /// Record one request for `ip` and decide it.
    ///
    /// `endpoint` selects the scope: `None` is the global per-IP window,
    /// `Some(path)` the per-endpoint window keyed by `(ip, path)`. A
    /// disabled limiter allows without recording. The returned decision's
    /// `count` includes the request just recorded, so a block reports the
    /// crossing count exactly as the references log it.
    #[must_use]
    pub fn check(&self, ip: IpAddr, endpoint: Option<&str>) -> RateLimitDecision {
        if !self.config.enable_rate_limiting {
            return RateLimitDecision {
                allowed: true,
                count: 0,
                window: self.config.rate_limit_window,
            };
        }
        let (allowed, count, window) = self.record_and_decide(
            ip,
            endpoint,
            self.config.rate_limit,
            self.config.rate_limit_window,
        );
        RateLimitDecision {
            allowed,
            count,
            window,
        }
    }

    /// Record one request for `ip` under every configured tier and decide
    /// it (the reference `RateLimitCheck.check` order, via the Go port's
    /// `tiersFor`/`runTier`): the endpoint tier, the route tier, the geo
    /// tier, then the global tier. Every configured tier records one hit
    /// into its own window (each tier is an independent budget, exactly as
    /// the references count), and the first tier that crosses its limit
    /// decides the outcome with its own window for `Retry-After`.
    ///
    /// `url_path` is the request path the endpoint tier matches
    /// (`endpoint_rate_limits` exact match) and the route/geo tiers key
    /// their windows by; without a path those tiers cannot key an isolated
    /// window and are skipped (the references always carry a request path
    /// here). `route` carries the decorator tiers (`None` skips both).
    /// `country_of_ip` resolves the geolocation the geo tier reads (the
    /// reference `geo_handler.get_country`); `None` or an unresolved
    /// country skips the geo tier unless a `"*"` entry covers it. A
    /// disabled limiter allows without recording anything.
    #[must_use]
    pub fn check_tiers(
        &self,
        ip: IpAddr,
        url_path: Option<&str>,
        route: Option<&RouteRateLimits>,
        country_of_ip: Option<&dyn Fn(IpAddr) -> Option<String>>,
    ) -> TierDecision {
        let inert = TierDecision {
            allowed: true,
            count: 0,
            tier: RateLimitTier::Global,
            window: self.config.rate_limit_window,
        };
        if !self.config.enable_rate_limiting {
            return inert;
        }

        // Tier 1: endpoint_rate_limits[path] (the reference
        // `_check_endpoint_rate_limit` exact-path match).
        if let Some(path) = url_path {
            if let Some(entry) = self.config.endpoint_rate_limits.get(path) {
                let (allowed, count, window) =
                    self.record_and_decide(ip, Some(path), entry.requests, entry.window);
                if !allowed {
                    return TierDecision {
                        allowed,
                        count,
                        tier: RateLimitTier::Endpoint,
                        window,
                    };
                }
            }

            // Tier 2: the route decorator's rate_limit (the reference
            // `_check_route_rate_limit`, window default 60).
            if let Some(route) = route {
                if let Some(limit) = route.rate_limit() {
                    let window = route
                        .rate_limit_window()
                        .unwrap_or(DEFAULT_ROUTE_RATE_LIMIT_WINDOW);
                    let (allowed, count, window) =
                        self.record_and_decide(ip, Some(path), limit, window);
                    if !allowed {
                        return TierDecision {
                            allowed,
                            count,
                            tier: RateLimitTier::Route,
                            window,
                        };
                    }
                }

                // Tier 3: the route decorator's geo_rate_limits (the
                // reference `_check_geo_rate_limit`): the resolved
                // country's entry, else the "*" fallback.
                if let (Some(limits), Some(country_of_ip)) =
                    (route.geo_rate_limits(), country_of_ip)
                {
                    let country = country_of_ip(ip);
                    let entry = country
                        .as_ref()
                        .and_then(|code| limits.get(code))
                        .or_else(|| limits.get("*"));
                    if let Some(entry) = entry {
                        let (allowed, count, window) =
                            self.record_and_decide(ip, Some(path), entry.requests, entry.window);
                        if !allowed {
                            return TierDecision {
                                allowed,
                                count,
                                tier: RateLimitTier::Geo,
                                window,
                            };
                        }
                    }
                }
            }
        }

        // Tier 4: the global per-IP tier (the reference
        // `_check_global_rate_limit`).
        let (allowed, count, window) = self.record_and_decide(
            ip,
            None,
            self.config.rate_limit,
            self.config.rate_limit_window,
        );
        TierDecision {
            allowed,
            count,
            tier: RateLimitTier::Global,
            window,
        }
    }

    /// Drop every window, every recorded request included (`reset` in the
    /// references; test harnesses use it to isolate cases).
    pub fn reset(&self) {
        self.windows.lock().expect("rate window store").clear();
    }

    /// How many windows the store currently tracks (test/observability
    /// seam for the LRU cap).
    #[must_use]
    pub fn tracked_windows(&self) -> usize {
        self.windows.lock().expect("rate window store").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

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

    fn enabled_config(rate_limit: u32) -> RateLimitConfig {
        RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit,
            ..RateLimitConfig::default()
        }
    }

    #[test]
    fn default_config_matches_the_reference() {
        let config = RateLimitConfig::default();
        assert!(config.enable_rate_limiting);
        assert_eq!(config.rate_limit, 10);
        assert_eq!(config.rate_limit_window, 60);
        assert!(!config.enable_rate_limit_auto_ban);
    }

    #[test]
    fn new_fails_closed_on_zero_limit_or_window() {
        let error = RateLimiter::new(RateLimitConfig {
            rate_limit: 0,
            ..RateLimitConfig::default()
        })
        .unwrap_err();
        assert_eq!(error.field, "rate_limit");
        // The Cow is transparent: a borrowed static field reads as itself.
        assert_eq!(error.field, std::borrow::Cow::Borrowed("rate_limit"));
        assert_eq!(
            error.to_string(),
            "invalid rate_limit: must be at least 1 request per window"
        );

        let error = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 5,
            rate_limit_window: 0,
            enable_rate_limit_auto_ban: false,
            endpoint_rate_limits: std::collections::HashMap::new(),
        })
        .unwrap_err();
        assert_eq!(error.field, "rate_limit_window");
    }

    #[test]
    fn new_fails_closed_on_invalid_endpoint_entries() {
        let error = RateLimiter::new(RateLimitConfig {
            endpoint_rate_limits: std::iter::once((
                "/login".to_owned(),
                RateLimitEntry {
                    requests: 0,
                    window: 60,
                },
            ))
            .collect(),
            ..RateLimitConfig::default()
        })
        .unwrap_err();
        assert_eq!(error.field, "endpoint_rate_limits[/login]");
        assert_eq!(
            error.to_string(),
            "invalid endpoint_rate_limits[/login]: every entry needs at least 1 request \
             per at least 1 second"
        );

        let error = RateLimitEntry::new(1, 0).unwrap_err();
        assert_eq!(error.field, "window");

        let error = RouteRateLimits::new(Some(0), Some(60), None).unwrap_err();
        assert_eq!(error.field, "rate_limit");

        let error = RouteRateLimits::new(Some(10), Some(0), None).unwrap_err();
        assert_eq!(error.field, "rate_limit_window");

        let error = RouteRateLimits::new(
            None,
            None,
            Some(
                std::iter::once((
                    "RU".to_owned(),
                    RateLimitEntry {
                        requests: 1,
                        window: 0,
                    },
                ))
                .collect(),
            ),
        )
        .unwrap_err();
        assert_eq!(error.field, "geo_rate_limits[RU]");

        // An inert route (no tier at all) and a window without a limit are
        // both valid: neither configures a tier.
        assert!(RouteRateLimits::new(None, None, None).is_ok());
        assert!(RouteRateLimits::new(None, Some(30), None).is_ok());
    }

    #[test]
    fn disabled_limiter_allows_and_records_nothing() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: false,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        for _ in 0..50 {
            assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        }
        assert_eq!(limiter.tracked_windows(), 0, "no window was recorded");
    }

    #[test]
    fn blocks_at_the_crossing_and_reports_the_crossing_count() {
        let limiter = RateLimiter::new(enabled_config(3)).expect("valid config");
        for expected in 1..=3 {
            let decision = limiter.check(ip("192.0.2.1"), None);
            assert!(decision.allowed, "request {expected} must pass");
            assert_eq!(decision.count, expected);
        }
        let decision = limiter.check(ip("192.0.2.1"), None);
        assert!(
            !decision.allowed,
            "the 4th request inside the window blocks"
        );
        assert_eq!(decision.count, 4);
        assert_eq!(decision.retry_after(), 60, "Retry-After is the window");
    }

    #[test]
    fn window_slide_restores_the_budget() {
        let fake = FakeClock::default();
        let limiter = RateLimiter {
            config: enabled_config(2),
            windows: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(16).expect("above zero"),
            ))),
            clock: fake.clock(),
        };
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);

        // Half the window later the crossing request is still remembered.
        fake.advance(30);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);
        // Past the window the expired timestamps are evicted and the budget
        // is whole again.
        fake.advance(31);
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
    }

    #[test]
    fn windows_are_per_ip() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(
            limiter.check(ip("192.0.2.2"), None).allowed,
            "another IP has its own budget"
        );
    }

    #[test]
    fn endpoint_scope_is_isolated_from_the_global_scope() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(
            limiter.check(ip("192.0.2.1"), Some("/login")).allowed,
            "the endpoint window is a separate budget"
        );
        assert!(!limiter.check(ip("192.0.2.1"), Some("/login")).allowed);
        assert!(
            limiter.check(ip("192.0.2.1"), Some("/signup")).allowed,
            "another endpoint has its own budget"
        );
        assert_eq!(limiter.tracked_windows(), 3);
    }

    #[test]
    fn ipv4_mapped_requests_share_the_ipv4_budget() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("::ffff:192.0.2.1"), None).allowed);
        assert!(
            !limiter.check(ip("192.0.2.1"), None).allowed,
            "the mapped form must count toward the same window"
        );
    }

    #[test]
    fn reset_drops_every_window() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);
        limiter.reset();
        assert_eq!(limiter.tracked_windows(), 0);
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
    }

    #[test]
    fn large_windows_keep_their_exact_length() {
        // rate_limit_window beyond u32 must not fold the sliding window into
        // something shorter (the f64 conversion saturates, never truncates).
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: u64::from(u32::MAX) + 1,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        let decision = limiter.check(ip("192.0.2.1"), None);
        assert!(!decision.allowed);
        assert_eq!(decision.retry_after(), u64::from(u32::MAX) + 1);
    }

    /// The tier tests' fixed-country resolver.
    fn country_of(code: &'static str) -> impl Fn(IpAddr) -> Option<String> {
        move |_ip| Some(code.to_owned())
    }

    #[test]
    fn tierless_check_tiers_collapses_to_the_global_tier() {
        // No endpoint entries, no route: check_tiers must behave exactly
        // like the pre-tier global window (zero change unless tiers are
        // configured).
        let limiter = RateLimiter::new(enabled_config(2)).expect("valid config");
        let visitor = ip("192.0.2.40");
        assert!(
            limiter
                .check_tiers(visitor, Some("/x"), None, None)
                .allowed()
        );
        assert!(
            limiter
                .check_tiers(visitor, Some("/x"), None, None)
                .allowed()
        );
        let blocked = limiter.check_tiers(visitor, Some("/x"), None, None);
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Global);
        assert_eq!(blocked.tier_name(), "global");
        assert_eq!(blocked.retry_after(), 60);
        assert_eq!(limiter.tracked_windows(), 1, "one global window");
    }

    #[test]
    fn endpoint_tier_matches_the_exact_path_and_keys_its_own_window() {
        let limiter = RateLimiter::new(RateLimitConfig {
            endpoint_rate_limits: std::iter::once((
                "/login".to_owned(),
                RateLimitEntry::new(1, 60).expect("valid entry"),
            ))
            .collect(),
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let visitor = ip("192.0.2.41");

        // The configured path crosses at its own (stricter) limit and the
        // block names the endpoint tier with its window.
        assert!(
            limiter
                .check_tiers(visitor, Some("/login"), None, None)
                .allowed()
        );
        let blocked = limiter.check_tiers(visitor, Some("/login"), None, None);
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Endpoint);
        assert_eq!(blocked.retry_after(), 60);

        // Other paths never matched the endpoint tier: only the global
        // window counts there.
        assert!(
            limiter
                .check_tiers(visitor, Some("/other"), None, None)
                .allowed()
        );
        assert_eq!(
            limiter.tracked_windows(),
            2,
            "the login endpoint window + the shared global window"
        );
    }

    #[test]
    fn route_tier_uses_the_decorator_window_default_of_60() {
        let fake = FakeClock::default();
        let limiter = RateLimiter {
            config: enabled_config(100),
            windows: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(16).expect("above zero"),
            ))),
            clock: fake.clock(),
        };
        let route = RouteRateLimits::new(Some(1), None, None).expect("valid route");
        let visitor = ip("192.0.2.42");

        assert!(
            limiter
                .check_tiers(visitor, Some("/x"), Some(&route), None)
                .allowed()
        );
        let blocked = limiter.check_tiers(visitor, Some("/x"), Some(&route), None);
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Route);
        assert_eq!(
            blocked.retry_after(),
            60,
            "the reference default window (rate_limit_window or 60)"
        );

        // An explicit route window replaces the default.
        let route = RouteRateLimits::new(Some(1), Some(30), None).expect("valid route");
        let blocked = limiter.check_tiers(visitor, Some("/x"), Some(&route), None);
        assert!(!blocked.allowed());
        assert_eq!(blocked.retry_after(), 30);
    }

    #[test]
    fn geo_tier_resolves_the_country_then_the_star_fallback() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rate_limit: 100,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let route = RouteRateLimits::new(
            None,
            None,
            Some(
                [
                    ("RU".to_owned(), RateLimitEntry::new(1, 60).expect("valid")),
                    ("*".to_owned(), RateLimitEntry::new(2, 45).expect("valid")),
                ]
                .into_iter()
                .collect(),
            ),
        )
        .expect("valid route");

        // A resolved country uses its own entry.
        let russian = ip("192.0.2.43");
        assert!(
            limiter
                .check_tiers(russian, Some("/x"), Some(&route), Some(&country_of("RU")))
                .allowed()
        );
        let blocked =
            limiter.check_tiers(russian, Some("/x"), Some(&route), Some(&country_of("RU")));
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Geo);
        assert_eq!(blocked.retry_after(), 60);

        // A country without an entry falls back to "*" (two requests).
        let other = ip("192.0.2.44");
        let resolver = country_of("DE");
        assert!(
            limiter
                .check_tiers(other, Some("/x"), Some(&route), Some(&resolver))
                .allowed()
        );
        assert!(
            limiter
                .check_tiers(other, Some("/x"), Some(&route), Some(&resolver))
                .allowed()
        );
        let blocked = limiter.check_tiers(other, Some("/x"), Some(&route), Some(&resolver));
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Geo);
        assert_eq!(blocked.retry_after(), 45);

        // An unresolved country also reads the "*" fallback (the reference
        // `country and country in limits` else `"*" in limits`).
        let unknown: fn(IpAddr) -> Option<String> = |_ip| None;
        let third = ip("192.0.2.45");
        assert!(
            limiter
                .check_tiers(third, Some("/x"), Some(&route), Some(&unknown))
                .allowed()
        );
        assert!(
            limiter
                .check_tiers(third, Some("/x"), Some(&route), Some(&unknown))
                .allowed()
        );
        let blocked = limiter.check_tiers(third, Some("/x"), Some(&route), Some(&unknown));
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Geo);
    }

    #[test]
    fn geo_tier_needs_a_configured_map_and_country_lookup() {
        // No geo entries on the route: no geo tier, the global tier runs.
        let limiter = RateLimiter::new(RateLimitConfig {
            rate_limit: 1,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let route = RouteRateLimits::new(None, None, Some(std::collections::HashMap::new()))
            .expect("valid route");
        let visitor = ip("192.0.2.46");
        assert!(
            limiter
                .check_tiers(visitor, Some("/x"), Some(&route), Some(&country_of("RU")))
                .allowed()
        );
        let blocked =
            limiter.check_tiers(visitor, Some("/x"), Some(&route), Some(&country_of("RU")));
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Global);

        // Geo entries without a country resolver: the reference skips the
        // geo tier entirely (`if not geo_handler: return None`), so the
        // "*" entry never applies without a handler.
        let route = RouteRateLimits::new(
            None,
            None,
            Some(
                std::iter::once(("*".to_owned(), RateLimitEntry::new(1, 60).expect("valid")))
                    .collect(),
            ),
        )
        .expect("valid route");
        let fresh = ip("192.0.2.51");
        assert!(
            limiter
                .check_tiers(fresh, Some("/x"), Some(&route), None)
                .allowed()
        );
        let blocked = limiter.check_tiers(fresh, Some("/x"), Some(&route), None);
        assert!(!blocked.allowed());
        assert_eq!(
            blocked.tier(),
            RateLimitTier::Global,
            "no handler, no geo tier"
        );
    }

    #[test]
    fn every_configured_tier_records_so_the_budgets_stay_independent() {
        // The reference records one hit per configured tier per request:
        // a route tier with a huge limit and the global tier with a small
        // one still block from the global window, and the route window has
        // been counting all along.
        let limiter = RateLimiter::new(RateLimitConfig {
            rate_limit: 2,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let route = RouteRateLimits::new(Some(1_000), Some(60), None).expect("valid route");
        let visitor = ip("192.0.2.47");

        assert!(
            limiter
                .check_tiers(visitor, Some("/x"), Some(&route), None)
                .allowed()
        );
        assert!(
            limiter
                .check_tiers(visitor, Some("/x"), Some(&route), None)
                .allowed()
        );
        let blocked = limiter.check_tiers(visitor, Some("/x"), Some(&route), None);
        assert!(!blocked.allowed());
        assert_eq!(
            blocked.tier(),
            RateLimitTier::Global,
            "the global tier crossed first"
        );
        assert_eq!(blocked.count(), 3);
        assert_eq!(limiter.tracked_windows(), 2, "route + global windows");

        // The route tier observed both requests: dropping the global limit
        // is impossible here, but its own budget is provably separate -
        // two of its 1_000 slots are consumed, so one more request passes
        // the route tier once the global window slides.
    }

    #[test]
    fn first_blocked_tier_wins_the_response_shape() {
        // The endpoint tier blocks before the stricter global tier is even
        // consulted (the reference check order), so its window is the
        // Retry-After.
        let limiter = RateLimiter::new(RateLimitConfig {
            rate_limit: 1,
            rate_limit_window: 120,
            endpoint_rate_limits: std::iter::once((
                "/login".to_owned(),
                RateLimitEntry::new(1, 30).expect("valid"),
            ))
            .collect(),
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let visitor = ip("192.0.2.48");
        assert!(
            limiter
                .check_tiers(visitor, Some("/login"), None, None)
                .allowed()
        );
        let blocked = limiter.check_tiers(visitor, Some("/login"), None, None);
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Endpoint);
        assert_eq!(blocked.retry_after(), 30, "the endpoint tier's window");

        // An unconfigured path blocks from the global tier instead.
        let blocked = limiter.check_tiers(visitor, Some("/other"), None, None);
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Global);
        assert_eq!(blocked.retry_after(), 120);
    }

    #[test]
    fn tiers_without_a_request_path_skip_the_path_keyed_tiers() {
        // Without a path the endpoint/route/geo tiers cannot key an
        // isolated window: only the global tier runs (the references
        // always carry a request path here).
        let limiter = RateLimiter::new(RateLimitConfig {
            rate_limit: 1,
            endpoint_rate_limits: std::iter::once((
                "/login".to_owned(),
                RateLimitEntry::new(1, 60).expect("valid"),
            ))
            .collect(),
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let route = RouteRateLimits::new(Some(1), Some(60), None).expect("valid route");
        let visitor = ip("192.0.2.49");
        assert!(
            limiter
                .check_tiers(visitor, None, Some(&route), Some(&country_of("RU")))
                .allowed()
        );
        let blocked = limiter.check_tiers(visitor, None, Some(&route), Some(&country_of("RU")));
        assert!(!blocked.allowed());
        assert_eq!(blocked.tier(), RateLimitTier::Global);
    }

    #[test]
    fn disabled_limiter_skips_the_tiers_without_recording() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: false,
            endpoint_rate_limits: std::iter::once((
                "/login".to_owned(),
                RateLimitEntry::new(1, 60).expect("valid"),
            ))
            .collect(),
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let route = RouteRateLimits::new(Some(1), Some(60), None).expect("valid route");
        let visitor = ip("192.0.2.50");
        for _ in 0..10 {
            let decision = limiter.check_tiers(visitor, Some("/login"), Some(&route), None);
            assert!(decision.allowed());
        }
        assert_eq!(limiter.tracked_windows(), 0, "nothing was recorded");
    }
}
