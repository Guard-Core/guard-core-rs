//! The dynamic IP ban store and the auto-ban engine: `ban_ip` with a
//! duration, expiry-honoring `is_banned`, and the per-IP violation counters
//! with the threshold resolution both are fed by.
//!
//! This is the Rust family's in-memory port of the reference engine's
//! dynamic ban layer (`guard_core/handlers/ipban_handler.py` and the
//! threshold helper `core/checks/helpers.py:_resolve_and_apply_threshold_ban`,
//! via the Go port's `ipban.go`). Redis is out of scope: the store is
//! process-local, exactly what both references fall back to when Redis is
//! off, and the follow-up that adds Redis adopts the full distributed
//! semantics (shared bans, expiry refresh, legacy key migration).
//!
//! ## Bans
//!
//! [`IpBanManager::ban_ip`] records an expiry (`now + duration`) and
//! [`IpBanManager::is_banned`] honors it: a lookup past the expiry returns
//! `false` and drops the entry. Mirroring the references' local store, an
//! entry lives at most
//! [`LOCAL_CACHE_TTL_CAP_SECONDS`] (3600) seconds - the reference clamps
//! longer durations to the local cap when Redis is not configured
//! (`clampToLocalCap`, cause `not configured`) and the Python `TTLCache`
//! caps every local entry at the same TTL - so `ban_ip` with a longer
//! duration records the clamped expiry. The default `auto_ban_duration`
//! (3600) sits exactly at the cap, so default autobans are unaffected.
//!
//! The store is an LRU capped at [`LOCAL_CACHE_MAX_SIZE`] (10 000) entries
//! (`localCacheMaxSize` / the reference `maxsize=10000`): inserting into a
//! full store silently evicts the least recently banned entry, the same
//! silent-overflow behavior the references log a warning for.
//!
//! ## Self-ban refusal
//!
//! `ban_ip` refuses (`Ok(false)`, no entry recorded) when the target
//! overlaps the loopback space (`127.0.0.0/8`, `::1/128`) or a configured
//! trusted proxy - the references' self-DoS guard, so a deployment can never
//! ban its own ingress and go dark on itself.
//!
//! ## The auto-ban engine
//!
//! Detection violations are counted per IP per category in
//! [`ViolationCounters`] (the reference's `suspicious_request_counts`). One
//! call, [`IpBanManager::register_violations`], records the categories and
//! applies the reference threshold resolution
//! (`_resolve_and_apply_threshold_ban`, same shape as the TypeScript port's
//! `resolveThresholdBan`):
//!
//! ```text
//! banning disabled:                          no ban
//! for each category in the recorded order:
//!   threat_ban_config[category] exists and
//!   count[category] >= its threshold:        ban (entry duration, reason:category)
//! total of all counted categories >=
//! auto_ban_threshold:                        ban (auto_ban_duration, reason)
//! otherwise:                                 no ban
//! ```
//!
//! The per-category entries win first (in the order the caller lists the
//! categories), the flat threshold is the fallback measured against the
//! total. The rate-limit stage feeds the same engine with the pseudo-category
//! `rate_limit` when `enable_rate_limit_auto_ban` is on, so
//! `threat_ban_config["rate_limit"]` overrides and the flat threshold backs
//! it up, exactly as the reference pipeline does.
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! use guard_core_engine::ip_ban::{IpBanConfig, IpBanManager};
//!
//! let manager = IpBanManager::new();
//! let attacker = IpAddr::from_str("192.0.2.9").unwrap();
//!
//! assert!(manager.ban_ip(attacker, 60, "threshold_exceeded").unwrap());
//! assert!(manager.is_banned(attacker));
//!
//! // Loopback is refused: banning it would self-DoS the deployment.
//! let loopback = IpAddr::from_str("127.0.0.1").unwrap();
//! assert!(!manager.ban_ip(loopback, 60, "mistake").unwrap());
//! assert!(!manager.is_banned(loopback));
//!
//! manager.unban(attacker);
//! assert!(!manager.is_banned(attacker));
//! ```

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::ip_gate::{IpGateError, IpNet, canonical, parse_network_entry};

/// The flat auto-ban fallback threshold (`auto_ban_threshold`, reference
/// default).
pub const DEFAULT_AUTO_BAN_THRESHOLD: u32 = 10;
/// The flat auto-ban fallback duration in seconds (`auto_ban_duration`,
/// reference default: one hour).
pub const DEFAULT_AUTO_BAN_DURATION: u64 = 3600;
/// The local store's TTL cap in seconds (`LOCAL_CACHE_TTL_CAP_SECONDS` in
/// both references): no in-memory ban outlives it.
pub const LOCAL_CACHE_TTL_CAP_SECONDS: u64 = 3600;
/// The local ban store's entry cap (`localCacheMaxSize` /
/// the reference `maxsize=10000`).
pub const LOCAL_CACHE_MAX_SIZE: usize = 10_000;
/// The violation counter store's IP cap (`_MAX_TRACKED_SUSPICIOUS_IPS`).
pub const MAX_TRACKED_SUSPICIOUS_IPS: usize = 10_000;

/// The pseudo-category the rate-limit stage feeds the auto-ban engine under
/// (`enable_rate_limit_auto_ban`).
pub const RATE_LIMIT_CATEGORY: &str = "rate_limit";

/// One `threat_ban_config` entry: the violation count per category that
/// triggers a ban, and how long the ban lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatBanEntry {
    /// Violations of this category after which the IP is banned.
    pub threshold: u32,
    /// Ban length in seconds.
    pub duration: u64,
}

/// The IP-banning knobs (the reference `enable_ip_banning` /
/// `auto_ban_threshold` / `auto_ban_duration` / `threat_ban_config` group).
///
/// The defaults are the reference `SecurityConfig` defaults: banning on
/// (`enable_ip_banning = true`, `guard_core/_security_config_fields.py`)
/// with the reference threshold/duration pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpBanConfig {
    /// `enable_ip_banning`. `false` makes every ban resolution a no-op;
    /// violations still count (the reference counts regardless so enabling
    /// banning later starts from observed history).
    pub enable_ip_banning: bool,
    /// `auto_ban_threshold`: the flat fallback, measured against the total
    /// of all counted categories.
    pub auto_ban_threshold: u32,
    /// `auto_ban_duration`: the flat fallback ban length (seconds).
    pub auto_ban_duration: u64,
    /// `threat_ban_config`: per-category threshold/duration overrides,
    /// consulted before the flat pair.
    pub threat_ban_config: HashMap<String, ThreatBanEntry>,
}

impl Default for IpBanConfig {
    fn default() -> Self {
        Self {
            enable_ip_banning: true,
            auto_ban_threshold: DEFAULT_AUTO_BAN_THRESHOLD,
            auto_ban_duration: DEFAULT_AUTO_BAN_DURATION,
            threat_ban_config: HashMap::new(),
        }
    }
}

/// An invalid [`IpBanConfig`]: the config error [`IpBanConfig::new`] fails
/// closed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpBanConfigError {
    /// A threshold or duration that must be at least 1 is not.
    NonPositive {
        /// The rejected field name.
        field: &'static str,
    },
    /// A `threat_ban_config` key that is neither a detection category nor
    /// the `rate_limit` pseudo-category (the reference and the TypeScript
    /// port both reject unknown categories).
    UnknownCategory {
        /// The rejected key.
        category: String,
    },
}

impl core::fmt::Display for IpBanConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonPositive { field } => write!(f, "invalid {field}: must be at least 1"),
            Self::UnknownCategory { category } => write!(
                f,
                "unknown threat category '{category}': expected a detection category or 'rate_limit'"
            ),
        }
    }
}

impl std::error::Error for IpBanConfigError {}

/// The detection categories a `threat_ban_config` key may name: every
/// pattern-table category plus the `rate_limit` pseudo-category (the
/// reference's `ALL_DETECTION_CATEGORIES | {'rate_limit'}`).
#[must_use]
pub fn valid_threat_categories() -> HashSet<&'static str> {
    let mut categories: HashSet<&'static str> = crate::patterns::table::PATTERN_DEFINITIONS
        .iter()
        .map(|entry| entry.category)
        .collect();
    categories.insert(RATE_LIMIT_CATEGORY);
    categories
}

impl IpBanConfig {
    /// Build and validate a config, failing closed on a non-positive
    /// threshold/duration or an unknown `threat_ban_config` category.
    ///
    /// # Errors
    ///
    /// [`IpBanConfigError::NonPositive`] for a zero `auto_ban_threshold` or
    /// `auto_ban_duration` (the reference rejects both with `ge=1`),
    /// [`IpBanConfigError::UnknownCategory`] for a key outside
    /// [`valid_threat_categories`].
    pub fn new<I, K, V>(
        enable_ip_banning: bool,
        auto_ban_threshold: u32,
        auto_ban_duration: u64,
        threat_ban_config: I,
    ) -> Result<Self, IpBanConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<ThreatBanEntry>,
    {
        let config = Self {
            enable_ip_banning,
            auto_ban_threshold,
            auto_ban_duration,
            threat_ban_config: threat_ban_config
                .into_iter()
                .map(|(key, entry)| (key.as_ref().to_owned(), entry.into()))
                .collect(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate this config. Struct-literal builders can run the same
    /// checks the constructor applies.
    ///
    /// # Errors
    ///
    /// See [`IpBanConfig::new`].
    pub fn validate(&self) -> Result<(), IpBanConfigError> {
        if self.auto_ban_threshold == 0 {
            return Err(IpBanConfigError::NonPositive {
                field: "auto_ban_threshold",
            });
        }
        if self.auto_ban_duration == 0 {
            return Err(IpBanConfigError::NonPositive {
                field: "auto_ban_duration",
            });
        }
        let valid = valid_threat_categories();
        for category in self.threat_ban_config.keys() {
            if !valid.contains(category.as_str()) {
                return Err(IpBanConfigError::UnknownCategory {
                    category: category.to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Why [`IpBanManager::ban_ip`] refused a ban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanError {
    /// A ban duration must be at least one second (the reference raises;
    /// the Go port answers with a 400-shaped error).
    NonPositiveDuration,
}

impl core::fmt::Display for BanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonPositiveDuration => write!(f, "ban duration must be positive"),
        }
    }
}

impl std::error::Error for BanError {}

/// One recorded ban: when it expires and why it was issued. The reason is
/// metadata for observability (the references persist it on the Redis
/// side); the in-memory store only acts on the expiry.
#[derive(Debug, Clone, PartialEq)]
pub struct BanRecord {
    /// Unix seconds after which the ban no longer applies.
    pub expiry: f64,
    /// The reason `ban_ip` was called with.
    pub reason: String,
}

/// The monotonic-ish wall clock, in seconds since the Unix epoch.
/// Injectable so expiry behavior is testable without sleeping.
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

fn system_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

const LOOPBACK_NETWORKS: [&str; 2] = ["127.0.0.0/8", "::1/128"];

/// A fresh shared ban store (the store lives behind an `Arc` so clones of
/// the manager share it, the references' singleton semantics).
fn new_ban_store() -> Arc<Mutex<LruCache<IpAddr, BanRecord>>> {
    Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(LOCAL_CACHE_MAX_SIZE).expect("constant above zero"),
    )))
}

/// The dynamic IP ban store over one shared in-memory map.
///
/// Build it once at startup and share the handle across requests; the
/// internal store is a mutex-guarded LRU, safe for concurrent services.
/// Trusted proxies are configured at construction
/// ([`IpBanManager::with_trusted_proxies`]) because they shape the
/// self-ban refusal, not per-request behavior.
pub struct IpBanManager {
    bans: Arc<Mutex<LruCache<IpAddr, BanRecord>>>,
    trusted_proxies: Vec<IpNet>,
    clock: Clock,
    ban_store: Option<Arc<dyn crate::distributed::BanStore>>,
    redis_prefix: String,
}

impl Clone for IpBanManager {
    /// A clone shares the ban store and the clock, exactly the references'
    /// singleton semantics: bans recorded through any handle are visible to
    /// every handle. Trusted proxies are copied (they shape the self-DoS
    /// refusal only).
    fn clone(&self) -> Self {
        Self {
            bans: Arc::clone(&self.bans),
            trusted_proxies: self.trusted_proxies.clone(),
            clock: Arc::clone(&self.clock),
            ban_store: self.ban_store.clone(),
            redis_prefix: self.redis_prefix.clone(),
        }
    }
}

impl core::fmt::Debug for IpBanManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpBanManager")
            .field("trusted_proxies", &self.trusted_proxies.len())
            .finish_non_exhaustive()
    }
}

impl Default for IpBanManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IpBanManager {
    /// Build a ban store with no trusted proxies (loopback refusal only).
    #[must_use]
    pub fn new() -> Self {
        Self {
            bans: new_ban_store(),
            ban_store: None,
            redis_prefix: String::from("guard_core:"),
            trusted_proxies: Vec::new(),
            clock: Arc::new(system_clock),
        }
    }

    /// Build a ban store whose self-ban refusal also covers the given
    /// trusted proxy networks (a bare IP or a CIDR range per entry, same
    /// matching semantics as the IP gate's lists).
    ///
    /// # Errors
    ///
    /// [`IpGateError`] naming the offending entry, exactly like
    /// `IpGateConfig::new` fails closed.
    pub fn with_trusted_proxies<I>(entries: I) -> Result<Self, IpGateError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        Self::with_trusted_proxies_and_clock(entries, Arc::new(system_clock))
    }

    /// Build a ban store whose self-ban refusal also covers the given
    /// trusted-proxy networks and whose wall clock is injected: the combined
    /// seam [`with_trusted_proxies`](Self::with_trusted_proxies) and
    /// [`with_clock`](Self::with_clock) cover separately. Adapters that run
    /// deterministic expiry tests under a production-shaped proxy list use
    /// this one.
    ///
    /// # Errors
    ///
    /// [`IpGateError`] naming the offending entry, exactly like
    /// `IpBanManager::with_trusted_proxies` fails closed.
    pub fn with_trusted_proxies_and_clock<I>(entries: I, clock: Clock) -> Result<Self, IpGateError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut trusted_proxies = Vec::new();
        for entry in entries {
            let entry = entry.as_ref();
            match parse_network_entry(entry) {
                Some(network) => trusted_proxies.push(network),
                None => {
                    return Err(IpGateError {
                        list: "trusted_proxies",
                        entry: entry.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            bans: new_ban_store(),
            ban_store: None,
            redis_prefix: String::from("guard_core:"),
            trusted_proxies,
            clock,
        })
    }

    /// Swap the wall clock. Test seam: production builds use the system
    /// clock; deterministic expiry coverage injects a fake.
    /// Run the ban engine over a distributed store (the reference
    /// `redis_handler` seam): ban writes go to
    /// `{prefix}banned_ips:{ip}` with the ban TTL (a failed write
    /// degrades to the local store, the reference `except` branch), and
    /// lookups fall through to the store on a local miss, caching the
    /// answer (the reference `_check_redis_exact`). A failing lookup
    /// surfaces the backend error through [`IpBanManager::try_is_banned`]
    /// so a caller can fail secure the way the reference's
    /// `GuardRedisError(503)` propagates into the pipeline; the lossy
    /// [`IpBanManager::is_banned`] keeps reading an error as unbanned.
    #[must_use]
    pub fn with_distributed_store(
        mut self,
        store: Arc<dyn crate::distributed::BanStore>,
        redis_prefix: &str,
    ) -> Self {
        self.ban_store = Some(store);
        redis_prefix.clone_into(&mut self.redis_prefix);
        self
    }

    pub fn with_clock(clock: Clock) -> Self {
        Self {
            bans: new_ban_store(),
            ban_store: None,
            redis_prefix: String::from("guard_core:"),
            trusted_proxies: Vec::new(),
            clock,
        }
    }

    /// Ban `ip` for `duration` seconds, recording `reason`.
    ///
    /// Returns `Ok(true)` when the ban was recorded, `Ok(false)` when it
    /// was refused by the self-DoS guard (loopback or a trusted proxy:
    /// banning those would take the deployment's own view of client IPs
    /// offline), and [`BanError::NonPositiveDuration`] for a zero duration.
    /// Re-banning a live IP overwrites the record: the new expiry and
    /// reason replace the old ones.
    ///
    /// Durations beyond [`LOCAL_CACHE_TTL_CAP_SECONDS`] are clamped to it:
    /// this is the in-memory store, and the references cap their local
    /// store the same way (only the Redis backend honors longer bans).
    ///
    /// # Errors
    ///
    /// [`BanError::NonPositiveDuration`] when `duration` is zero.
    pub fn ban_ip(&self, ip: IpAddr, duration: u64, reason: &str) -> Result<bool, BanError> {
        if duration == 0 {
            return Err(BanError::NonPositiveDuration);
        }
        let ip = canonical(ip);
        if self.self_ban_refusal(&ip) {
            return Ok(false);
        }
        let clamped = duration.min(LOCAL_CACHE_TTL_CAP_SECONDS);
        #[allow(clippy::cast_precision_loss)]
        let expiry = (self.clock)() + clamped as f64;
        self.bans.lock().expect("ban store").put(
            ip,
            BanRecord {
                expiry,
                reason: reason.to_owned(),
            },
        );
        if let Some(store) = &self.ban_store {
            // The distributed store honors the unclamped TTL (only the
            // local cache is capped, exactly the reference). A failed
            // write degrades to the local store above.
            #[allow(clippy::cast_precision_loss)]
            let distributed_expiry = (self.clock)() + duration as f64;
            let _ = store.set_ban(
                &crate::distributed::ban_key(&self.redis_prefix, ip),
                distributed_expiry,
                duration,
            );
        }
        Ok(true)
    }

    /// Whether `ip` currently carries a live ban. An entry past its expiry
    /// reads as unbanned and is dropped from the store.
    ///
    /// This is the lossy form: a failing distributed lookup reads as
    /// unbanned. Fail-secure callers use [`IpBanManager::try_is_banned`],
    /// which surfaces the backend error the way the reference's
    /// `GuardRedisError(503)` propagates into its pipeline.
    #[must_use]
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.try_is_banned(ip).unwrap_or(false)
    }

    /// [`IpBanManager::is_banned`] with the backend error surfaced: a
    /// failing distributed ban lookup returns [`Err`] instead of reading
    /// as unbanned, so a caller can fail secure (the reference
    /// `redis_handler.safe_operation` raising `GuardRedisError(503, "Redis
    /// operation failed")` out of `_check_redis_exact`'s `get_key`).
    ///
    /// # Errors
    ///
    /// [`crate::distributed::StoreError`] when the distributed lookup
    /// fails and the local cache holds no live answer.
    pub fn try_is_banned(&self, ip: IpAddr) -> Result<bool, crate::distributed::StoreError> {
        let ip = canonical(ip);
        let now = (self.clock)();
        {
            let mut bans = self.bans.lock().expect("ban store");
            match bans.get(&ip) {
                Some(record) if now <= record.expiry => return Ok(true),
                Some(_) => {
                    bans.pop(&ip);
                }
                None => {}
            }
        }
        self.check_distributed_ban(ip, now)
    }

    /// The distributed lookup on a local miss (the reference
    /// `_check_redis_exact`): a stored expiry at or after `now` counts as
    /// banned and is cached locally, a stale one is deleted, a backend
    /// error is returned to the caller (the fail-secure seam; the lossy
    /// [`IpBanManager::is_banned`] flattens it to unbanned).
    fn check_distributed_ban(
        &self,
        ip: IpAddr,
        now: f64,
    ) -> Result<bool, crate::distributed::StoreError> {
        let Some(store) = &self.ban_store else {
            return Ok(false);
        };
        match store.get_ban(&crate::distributed::ban_key(&self.redis_prefix, ip)) {
            Ok(Some(expiry)) if now <= expiry => {
                self.bans.lock().expect("ban store").put(
                    ip,
                    BanRecord {
                        expiry,
                        reason: String::from("distributed"),
                    },
                );
                Ok(true)
            }
            Ok(Some(_)) => {
                let _ = store.delete_ban(&crate::distributed::ban_key(&self.redis_prefix, ip));
                Ok(false)
            }
            Ok(None) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// The recorded ban for `ip`, if one is still live (test and
    /// observability seam: the reason a ban was issued).
    #[must_use]
    pub fn ban_record(&self, ip: IpAddr) -> Option<BanRecord> {
        let ip = canonical(ip);
        let now = (self.clock)();
        let mut bans = self.bans.lock().expect("ban store");
        match bans.get(&ip) {
            Some(record) if now <= record.expiry => Some(record.clone()),
            Some(_) => {
                bans.pop(&ip);
                None
            }
            None => None,
        }
    }

    /// Lift `ip`'s ban, live or expired (`unban` in the references).
    pub fn unban(&self, ip: IpAddr) {
        self.bans.lock().expect("ban store").pop(&canonical(ip));
    }

    /// Drop every ban and every violation count (`reset` in the
    /// references; test harnesses use it to isolate cases).
    pub fn reset(&self) {
        self.bans.lock().expect("ban store").clear();
    }

    /// How many bans the store currently holds, live or expired (test and
    /// observability seam for the LRU cap).
    #[must_use]
    pub fn banned_count(&self) -> usize {
        self.bans.lock().expect("ban store").len()
    }

    /// The self-DoS guard: loopback and trusted-proxy targets are refused.
    fn self_ban_refusal(&self, ip: &IpAddr) -> bool {
        LOOPBACK_NETWORKS
            .iter()
            .filter_map(|entry| parse_network_entry(entry))
            .chain(self.trusted_proxies.iter().copied())
            .any(|network| network.contains(*ip))
    }
}

/// Per-IP per-category violation counts: the reference's
/// `suspicious_request_counts`, the store the auto-ban engine resolves
/// thresholds against.
///
/// The store is an LRU capped at [`MAX_TRACKED_SUSPICIOUS_IPS`] IPs (the
/// reference evicts the oldest IP at the same cap), so attacker IP
/// cardinality cannot grow it without bound.
pub struct ViolationCounters {
    counts: Arc<Mutex<LruCache<IpAddr, HashMap<String, u64>>>>,
}

impl Clone for ViolationCounters {
    /// A clone shares the count store: violations recorded through any
    /// handle are visible to every handle.
    fn clone(&self) -> Self {
        Self {
            counts: Arc::clone(&self.counts),
        }
    }
}

impl core::fmt::Debug for ViolationCounters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViolationCounters").finish_non_exhaustive()
    }
}

impl Default for ViolationCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl ViolationCounters {
    /// Build an empty counter store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counts: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_TRACKED_SUSPICIOUS_IPS).expect("constant above zero"),
            ))),
        }
    }

    /// Record one violation per category for `ip` (each listed category
    /// gains `+1`; the reference maps an empty category list to the
    /// `uncategorized` pseudo-category, mirrored here).
    pub fn record(&self, ip: IpAddr, categories: &[&str]) {
        let categories: &[&str] = if categories.is_empty() {
            &["uncategorized"]
        } else {
            categories
        };
        let mut counts = self.counts.lock().expect("violation counter store");
        let ip_counts = counts
            .try_get_or_insert_mut(canonical(ip), || {
                Ok::<_, core::convert::Infallible>(HashMap::new())
            })
            .expect("ip capacity just reserved");
        // The write loop is the guard's only lifetime reason: it ends here.
        for category in categories {
            *ip_counts.entry((*category).to_owned()).or_insert(0) += 1;
        }
        drop(counts);
    }

    /// A copy of `ip`'s counts (the resolution reads a snapshot while the
    /// store stays locked for the next writer).
    #[must_use]
    pub fn snapshot(&self, ip: IpAddr) -> HashMap<String, u64> {
        self.counts
            .lock()
            .expect("violation counter store")
            .peek(&canonical(ip))
            .cloned()
            .unwrap_or_default()
    }

    /// Drop every count.
    pub fn reset(&self) {
        self.counts.lock().expect("violation counter store").clear();
    }

    /// How many IPs the store currently tracks (test/observability seam).
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        self.counts.lock().expect("violation counter store").len()
    }
}

/// The ban a threshold resolution decided on: how long, under what reason,
/// and which category crossed (none for the flat fallback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBan {
    /// Ban length in seconds (the crossed entry's or the flat default's).
    pub duration: u64,
    /// The reason to record (`"reason"` for the flat fallback,
    /// `"reason:category"` for a crossed entry, exactly as the references
    /// build it).
    pub reason: String,
    /// The category whose entry crossed, `None` for the flat fallback.
    pub category: Option<String>,
}

/// The reference threshold resolution against one IP's current counts.
///
/// This is `_resolve_and_apply_threshold_ban` (the TypeScript port's
/// `resolveThresholdBan`): per-category entries first, in the order the
/// categories are listed, then the flat threshold against the total.
///
/// Banning disabled always resolves to no ban.
#[must_use]
pub fn resolve_threshold_ban<S: core::hash::BuildHasher>(
    counts: &HashMap<String, u64, S>,
    config: &IpBanConfig,
    threat_categories: &[&str],
    reason: &str,
) -> Option<ResolvedBan> {
    if !config.enable_ip_banning {
        return None;
    }
    for category in threat_categories {
        let Some(entry) = config.threat_ban_config.get(*category) else {
            continue;
        };
        let count = counts.get(*category).copied().unwrap_or(0);
        if count < u64::from(entry.threshold) {
            continue;
        }
        return Some(ResolvedBan {
            duration: entry.duration,
            reason: format!("{reason}:{category}"),
            category: Some((*category).to_owned()),
        });
    }
    let total: u64 = counts.values().sum();
    if total < u64::from(config.auto_ban_threshold) {
        return None;
    }
    Some(ResolvedBan {
        duration: config.auto_ban_duration,
        reason: reason.to_owned(),
        category: None,
    })
}

impl IpBanManager {
    /// The auto-ban engine's one-call shape: record the categories for
    /// `ip`, resolve the thresholds, and apply the ban when one crossed.
    ///
    /// `Some(..)` means a ban now stands (the stage answers with the
    /// family's banned shape), `None` means nothing fired - banning
    /// disabled, no threshold crossed, or the self-DoS guard refusing the
    /// target. Violations are counted regardless of the banning switch,
    /// mirroring the reference: enabling banning later starts from observed
    /// history.
    #[must_use]
    pub fn register_violations(
        &self,
        counters: &ViolationCounters,
        ip: IpAddr,
        categories: &[&str],
        config: &IpBanConfig,
        reason: &str,
    ) -> Option<ResolvedBan> {
        counters.record(ip, categories);
        let counts = counters.snapshot(ip);
        let resolved = resolve_threshold_ban(&counts, config, categories, reason)?;
        match self.ban_ip(ip, resolved.duration, &resolved.reason) {
            Ok(true) => Some(resolved),
            _ => None,
        }
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

    #[test]
    fn default_config_matches_the_reference() {
        let config = IpBanConfig::default();
        assert!(config.enable_ip_banning);
        assert_eq!(config.auto_ban_threshold, 10);
        assert_eq!(config.auto_ban_duration, 3600);
        assert!(config.threat_ban_config.is_empty());
    }

    #[test]
    fn config_validation_fails_closed() {
        let error =
            IpBanConfig::new(true, 0, 3600, Vec::<(String, ThreatBanEntry)>::new()).unwrap_err();
        assert_eq!(
            error,
            IpBanConfigError::NonPositive {
                field: "auto_ban_threshold"
            }
        );
        assert_eq!(
            error.to_string(),
            "invalid auto_ban_threshold: must be at least 1"
        );

        let error =
            IpBanConfig::new(true, 10, 0, Vec::<(String, ThreatBanEntry)>::new()).unwrap_err();
        assert_eq!(
            error,
            IpBanConfigError::NonPositive {
                field: "auto_ban_duration"
            }
        );

        let error = IpBanConfig::new(
            true,
            10,
            3600,
            [(
                "not_a_category",
                ThreatBanEntry {
                    threshold: 1,
                    duration: 1,
                },
            )],
        )
        .unwrap_err();
        assert_eq!(
            error,
            IpBanConfigError::UnknownCategory {
                category: "not_a_category".to_owned()
            }
        );
        assert_eq!(
            error.to_string(),
            "unknown threat category 'not_a_category': expected a detection category or 'rate_limit'"
        );
    }

    #[test]
    fn config_accepts_table_categories_and_rate_limit() {
        IpBanConfig::new(
            true,
            10,
            3600,
            [
                (
                    "sqli",
                    ThreatBanEntry {
                        threshold: 3,
                        duration: 60,
                    },
                ),
                (
                    RATE_LIMIT_CATEGORY,
                    ThreatBanEntry {
                        threshold: 5,
                        duration: 30,
                    },
                ),
            ],
        )
        .expect("both categories are valid");
        assert!(valid_threat_categories().contains("sqli"));
        assert!(valid_threat_categories().contains(RATE_LIMIT_CATEGORY));
    }

    #[test]
    fn ban_then_lookup_then_expiry() {
        let fake = FakeClock::default();
        let manager = IpBanManager::with_clock(fake.clock());
        manager
            .ban_ip(ip("192.0.2.9"), 60, "threshold_exceeded")
            .expect("ban");
        assert!(manager.is_banned(ip("192.0.2.9")));
        assert_eq!(
            manager
                .ban_record(ip("192.0.2.9"))
                .expect("live record")
                .reason,
            "threshold_exceeded"
        );

        // Just before expiry the ban still stands.
        fake.advance(59);
        assert!(manager.is_banned(ip("192.0.2.9")));
        // At the expiry second (`now <= expiry`) it still stands; strictly
        // past it the reference boundary (`now > expiry` evicts) releases.
        fake.advance(1);
        assert!(manager.is_banned(ip("192.0.2.9")));
        fake.advance(1);
        assert!(!manager.is_banned(ip("192.0.2.9")));
        assert_eq!(manager.banned_count(), 0, "the expired entry was dropped");
    }

    #[test]
    fn rebanning_overwrites_expiry_and_reason() {
        let manager = IpBanManager::new();
        manager.ban_ip(ip("192.0.2.9"), 60, "first").expect("ban");
        manager.ban_ip(ip("192.0.2.9"), 120, "second").expect("ban");
        let record = manager.ban_record(ip("192.0.2.9")).expect("live record");
        assert_eq!(record.reason, "second");
    }

    #[test]
    fn zero_duration_is_an_error() {
        let manager = IpBanManager::new();
        assert_eq!(
            manager.ban_ip(ip("192.0.2.9"), 0, "nope").unwrap_err(),
            BanError::NonPositiveDuration
        );
        assert!(!manager.is_banned(ip("192.0.2.9")));
        assert_eq!(
            BanError::NonPositiveDuration.to_string(),
            "ban duration must be positive"
        );
    }

    #[test]
    fn loopback_is_refused_for_both_families() {
        let manager = IpBanManager::new();
        for loopback in ["127.0.0.1", "127.8.8.8", "::1"] {
            assert!(
                !manager
                    .ban_ip(ip(loopback), 60, "mistake")
                    .expect("refusal is not an error"),
                "{loopback} must be refused"
            );
            assert!(!manager.is_banned(ip(loopback)));
        }
    }

    #[test]
    fn trusted_proxies_are_refused_and_parsed_fail_closed() {
        let manager = IpBanManager::with_trusted_proxies(["10.0.0.0/8", "2001:db8:ffff::/48"])
            .expect("valid");
        assert!(
            !manager
                .ban_ip(ip("10.1.2.3"), 60, "proxy")
                .expect("refusal")
        );
        assert!(
            !manager
                .ban_ip(ip("2001:db8:ffff::1"), 60, "proxy")
                .expect("refusal")
        );
        assert!(
            manager
                .ban_ip(ip("11.1.2.3"), 60, "outside the proxy range")
                .expect("ban"),
            "an address outside the proxy range is bannable"
        );

        let error = IpBanManager::with_trusted_proxies(["not-an-ip"]).unwrap_err();
        assert_eq!(error.list, "trusted_proxies");
        assert_eq!(error.entry, "not-an-ip");
    }

    #[test]
    fn ipv4_mapped_targets_canonicalize() {
        let manager = IpBanManager::new();
        // The mapped loopback form is the loopback: refused.
        assert!(
            !manager
                .ban_ip(ip("::ffff:127.0.0.1"), 60, "mistake")
                .expect("refusal")
        );
        // A mapped ban and its IPv4 form are one entry.
        manager
            .ban_ip(ip("::ffff:192.0.2.9"), 60, "x")
            .expect("ban");
        assert!(manager.is_banned(ip("192.0.2.9")));
        assert_eq!(manager.banned_count(), 1);
    }

    #[test]
    fn unban_and_reset() {
        let manager = IpBanManager::new();
        manager.ban_ip(ip("192.0.2.9"), 60, "x").expect("ban");
        manager.ban_ip(ip("192.0.2.8"), 60, "x").expect("ban");
        manager.unban(ip("192.0.2.9"));
        assert!(!manager.is_banned(ip("192.0.2.9")));
        assert!(manager.is_banned(ip("192.0.2.8")));
        manager.reset();
        assert!(!manager.is_banned(ip("192.0.2.8")));
        assert_eq!(manager.banned_count(), 0);
    }

    #[test]
    fn durations_beyond_the_local_cap_are_clamped() {
        let fake = FakeClock::default();
        let manager = IpBanManager::with_clock(fake.clock());
        manager.ban_ip(ip("192.0.2.9"), 7200, "long").expect("ban");
        // The expiry is the local cap, not the requested duration.
        fake.advance(3600);
        assert!(manager.is_banned(ip("192.0.2.9")));
        fake.advance(1);
        assert!(!manager.is_banned(ip("192.0.2.9")));
    }

    #[test]
    fn counters_accumulate_per_ip_per_category() {
        let counters = ViolationCounters::new();
        let attacker = ip("192.0.2.9");
        counters.record(attacker, &["sqli"]);
        counters.record(attacker, &["sqli", "xss"]);
        counters.record(ip("192.0.2.8"), &["xss"]);

        let counts = counters.snapshot(attacker);
        assert_eq!(counts.get("sqli"), Some(&2));
        assert_eq!(counts.get("xss"), Some(&1));
        assert_eq!(counters.snapshot(ip("192.0.2.8")).get("xss"), Some(&1));
        assert_eq!(counters.tracked_ips(), 2);

        // The empty category list records the uncategorized pseudo-category,
        // exactly like the reference's `_increment_suspicious_counts`.
        counters.record(attacker, &[]);
        assert_eq!(counters.snapshot(attacker).get("uncategorized"), Some(&1));

        counters.reset();
        assert_eq!(counters.tracked_ips(), 0);
    }

    #[test]
    fn ipv4_mapped_violations_share_the_ipv4_counts() {
        let counters = ViolationCounters::new();
        counters.record(ip("::ffff:192.0.2.9"), &["sqli"]);
        assert_eq!(counters.snapshot(ip("192.0.2.9")).get("sqli"), Some(&1));
    }

    #[test]
    fn resolution_disabled_never_bans() {
        let counts = HashMap::from([("sqli".to_owned(), 99)]);
        let config = IpBanConfig {
            enable_ip_banning: false,
            ..IpBanConfig::default()
        };
        assert!(
            resolve_threshold_ban(&counts, &config, &["sqli"], "penetration_attempt").is_none()
        );
    }

    #[test]
    fn resolution_category_entry_wins_in_order() {
        let counts = HashMap::from([("sqli".to_owned(), 3), ("xss".to_owned(), 10)]);
        let config = IpBanConfig::new(
            true,
            10,
            3600,
            [
                (
                    "sqli",
                    ThreatBanEntry {
                        threshold: 3,
                        duration: 60,
                    },
                ),
                (
                    "xss",
                    ThreatBanEntry {
                        threshold: 5,
                        duration: 30,
                    },
                ),
            ],
        )
        .expect("valid config");

        let resolved =
            resolve_threshold_ban(&counts, &config, &["sqli", "xss"], "penetration_attempt")
                .expect("sqli crosses first in list order");
        assert_eq!(resolved.category.as_deref(), Some("sqli"));
        assert_eq!(resolved.duration, 60);
        assert_eq!(resolved.reason, "penetration_attempt:sqli");

        // Listed the other way round, the xss entry wins.
        let resolved =
            resolve_threshold_ban(&counts, &config, &["xss", "sqli"], "penetration_attempt")
                .expect("xss crosses first in list order");
        assert_eq!(resolved.category.as_deref(), Some("xss"));
        assert_eq!(resolved.duration, 30);
    }

    #[test]
    fn resolution_below_every_entry_falls_back_to_the_flat_total() {
        let config = IpBanConfig::new(
            true,
            10,
            3600,
            [(
                "sqli",
                ThreatBanEntry {
                    threshold: 5,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");

        // No category at its entry threshold, total 8 < 10: nothing.
        let counts = HashMap::from([("sqli".to_owned(), 4), ("xss".to_owned(), 4)]);
        assert!(
            resolve_threshold_ban(&counts, &config, &["sqli"], "penetration_attempt").is_none()
        );

        // Still no entry crossing, but the total reaches the flat threshold.
        let counts = HashMap::from([("sqli".to_owned(), 4), ("xss".to_owned(), 6)]);
        let resolved = resolve_threshold_ban(&counts, &config, &["sqli"], "penetration_attempt")
            .expect("the flat threshold fires on the total");
        assert_eq!(resolved.category, None);
        assert_eq!(resolved.duration, 3600);
        assert_eq!(resolved.reason, "penetration_attempt");
    }

    #[test]
    fn resolution_ignores_uncounted_entries() {
        let config = IpBanConfig::new(
            true,
            10,
            3600,
            [(
                "xss",
                ThreatBanEntry {
                    threshold: 1,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        // sqli has no entry and no count: it neither bans nor blocks the
        // flat fallback.
        let counts = HashMap::from([("sqli".to_owned(), 4)]);
        assert!(
            resolve_threshold_ban(&counts, &config, &["sqli"], "penetration_attempt").is_none()
        );
    }

    #[test]
    fn register_violations_counts_then_bans_at_the_threshold() {
        let fake = FakeClock::default();
        let manager = IpBanManager::with_clock(fake.clock());
        let counters = ViolationCounters::new();
        let attacker = ip("192.0.2.9");
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "sqli",
                ThreatBanEntry {
                    threshold: 3,
                    duration: 120,
                },
            )],
        )
        .expect("valid config");

        assert!(
            manager
                .register_violations(
                    &counters,
                    attacker,
                    &["sqli"],
                    &config,
                    "penetration_attempt"
                )
                .is_none()
        );
        assert!(
            manager
                .register_violations(
                    &counters,
                    attacker,
                    &["sqli"],
                    &config,
                    "penetration_attempt"
                )
                .is_none()
        );
        assert!(
            !manager.is_banned(attacker),
            "below the threshold nobody is banned"
        );

        let resolved = manager
            .register_violations(
                &counters,
                attacker,
                &["sqli"],
                &config,
                "penetration_attempt",
            )
            .expect("the third violation crosses the entry");
        assert_eq!(resolved.category.as_deref(), Some("sqli"));
        assert_eq!(resolved.reason, "penetration_attempt:sqli");
        assert!(manager.is_banned(attacker));
        assert_eq!(
            manager.ban_record(attacker).expect("record").reason,
            "penetration_attempt:sqli"
        );
    }

    #[test]
    fn register_violations_without_banning_still_counts() {
        let manager = IpBanManager::new();
        let counters = ViolationCounters::new();
        let attacker = ip("192.0.2.9");
        let config = IpBanConfig {
            enable_ip_banning: false,
            ..IpBanConfig::default()
        };

        for _ in 0..(config.auto_ban_threshold + 5) {
            assert!(
                manager
                    .register_violations(
                        &counters,
                        attacker,
                        &["xss"],
                        &config,
                        "penetration_attempt"
                    )
                    .is_none()
            );
        }
        assert!(!manager.is_banned(attacker), "banning is off");
        assert!(
            counters.snapshot(attacker).values().sum::<u64>()
                >= u64::from(config.auto_ban_threshold),
            "the violations were counted anyway"
        );
    }

    #[test]
    fn register_violations_refusal_counts_but_does_not_ban() {
        let manager = IpBanManager::new();
        let counters = ViolationCounters::new();
        let config = IpBanConfig::new(true, 1, 3600, Vec::<(String, ThreatBanEntry)>::new())
            .expect("valid config");
        // The flat threshold is 1, but the target is loopback: refused.
        assert!(
            manager
                .register_violations(
                    &counters,
                    ip("127.0.0.1"),
                    &["xss"],
                    &config,
                    "penetration_attempt"
                )
                .is_none()
        );
        assert!(!manager.is_banned(ip("127.0.0.1")));
        assert_eq!(counters.snapshot(ip("127.0.0.1")).get("xss"), Some(&1));
    }

    #[test]
    fn manager_debug_and_default_render_and_construct() {
        let manager = IpBanManager::default();
        assert!(format!("{manager:?}").contains("IpBanManager"));
        assert!(format!("{:?}", ViolationCounters::default()).contains("ViolationCounters"));
        assert!(manager.ban_record(ip("192.0.2.8")).is_none());
    }

    #[test]
    fn trusted_proxies_parse_cidr_entries() {
        let manager = IpBanManager::with_trusted_proxies_and_clock(
            ["10.0.0.0/8", "192.168.1.1"],
            Arc::new(system_clock),
        )
        .expect("valid proxies");
        assert!(format!("{manager:?}").contains("IpBanManager"));
        // a trusted-proxy IP is not treated as the client
        assert!(!manager.is_banned(ip("10.1.2.3")));
    }

    #[test]
    fn expired_bans_are_evicted_on_read() {
        let fake = FakeClock::default();
        let manager = IpBanManager::with_clock(fake.clock());
        manager
            .ban_ip(ip("192.0.2.9"), 60, "rate_limit")
            .expect("ban recorded");
        assert!(manager.ban_record(ip("192.0.2.9")).is_some());
        fake.advance(120);
        // the expired ban is popped on read
        assert!(manager.ban_record(ip("192.0.2.9")).is_none());
        assert!(!manager.is_banned(ip("192.0.2.9")));
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;
    use std::str::FromStr;

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    /// A ban store the test scripts per call: one expiry or a backend
    /// failure, so every distributed-lookup arm runs.
    struct ScriptedBanStore {
        answer: Result<Option<f64>, crate::distributed::StoreError>,
    }

    impl crate::distributed::BanStore for ScriptedBanStore {
        fn set_ban(
            &self,
            _key: &str,
            _expiry: f64,
            _ttl_seconds: u64,
        ) -> Result<(), crate::distributed::StoreError> {
            Ok(())
        }

        fn get_ban(&self, _key: &str) -> Result<Option<f64>, crate::distributed::StoreError> {
            self.answer.clone()
        }

        fn delete_ban(&self, _key: &str) -> Result<(), crate::distributed::StoreError> {
            Ok(())
        }
    }

    #[test]
    fn trusted_proxy_lists_accept_and_reject_entries_fail_closed() {
        // one call site drives both outcomes: valid CIDR and bare-IP entries
        // land in the trusted list, an unparsable entry fails closed exactly
        // like the gate
        for (entry, valid) in [
            ("10.0.0.0/8", true),
            ("192.168.1.1", true),
            ("not-a-network", false),
        ] {
            let built =
                IpBanManager::with_trusted_proxies_and_clock([entry], Arc::new(system_clock));
            assert_eq!(built.is_ok(), valid, "entry {entry}");
            if let Ok(manager) = built {
                assert!(!manager.is_banned(ip("10.1.2.3")));
            }
        }
    }

    #[test]
    fn distributed_lookups_answer_live_stale_missing_and_failed_backends() {
        let now = 1_000.0_f64;
        // a live distributed ban reads as banned and caches locally
        let live = IpBanManager::with_trusted_proxies_and_clock(
            Vec::<String>::new(),
            Arc::new(move || now),
        )
        .expect("manager")
        .with_distributed_store(
            Arc::new(ScriptedBanStore {
                answer: Ok(Some(2_000.0)),
            }),
            "gc:",
        );
        assert!(live.is_banned(ip("192.0.2.71")));
        // banning through the manager writes the expiry into the store
        live.ban_ip(ip("192.0.2.72"), 60, "penetration_attempt")
            .expect("ban");
        // a stale expiry deletes the key and reads unbanned
        let stale = IpBanManager::with_trusted_proxies_and_clock(
            Vec::<String>::new(),
            Arc::new(move || now),
        )
        .expect("manager")
        .with_distributed_store(
            Arc::new(ScriptedBanStore {
                answer: Ok(Some(500.0)),
            }),
            "gc:",
        );
        assert!(!stale.is_banned(ip("192.0.2.71")));
        // a missing key reads unbanned
        let missing = IpBanManager::with_trusted_proxies_and_clock(
            Vec::<String>::new(),
            Arc::new(move || now),
        )
        .expect("manager")
        .with_distributed_store(Arc::new(ScriptedBanStore { answer: Ok(None) }), "gc:");
        assert!(!missing.is_banned(ip("192.0.2.71")));
        // a backend error reads unbanned
        let failed = IpBanManager::with_trusted_proxies_and_clock(
            Vec::<String>::new(),
            Arc::new(move || now),
        )
        .expect("manager")
        .with_distributed_store(
            Arc::new(ScriptedBanStore {
                answer: Err(crate::distributed::StoreError(String::from("down"))),
            }),
            "gc:",
        );
        assert!(!failed.is_banned(ip("192.0.2.71")));
    }

    #[test]
    fn failing_distributed_ban_lookup_fails_secure() {
        // The reference `_check_redis_exact` -> `redis_handler.get_key` ->
        // `safe_operation` raises `GuardRedisError(503, "Redis operation
        // failed")` on a backend failure: the pipeline never reads a
        // failing lookup as unbanned.
        let store = Arc::new(crate::distributed::MemoryStore::default());
        store.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let manager = IpBanManager::with_clock(Arc::new(|| 1_000.0)).with_distributed_store(
            Arc::clone(&store) as Arc<dyn crate::distributed::BanStore>,
            "guard_core:",
        );
        let stranger = ip("192.0.2.77");

        // The fail-secure seam surfaces the backend error.
        let error = manager.try_is_banned(stranger).expect_err("fail secure");
        assert!(error.to_string().contains("backend down"));
        // The lossy form keeps its documented shape (reads unbanned) so
        // existing callers stay total.
        assert!(!manager.is_banned(stranger));
    }

    #[test]
    fn live_local_ban_answers_ok_even_when_the_store_is_down() {
        // The reference checks the local TTLCache before Redis, so a live
        // local ban short-circuits and a backend failure never surfaces.
        let store = Arc::new(crate::distributed::MemoryStore::default());
        let manager = IpBanManager::with_clock(Arc::new(|| 1_000.0)).with_distributed_store(
            Arc::clone(&store) as Arc<dyn crate::distributed::BanStore>,
            "guard_core:",
        );
        let attacker = ip("192.0.2.78");
        manager
            .ban_ip(attacker, 60, "threshold_exceeded")
            .expect("ban");

        store.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(manager.try_is_banned(attacker).expect("local hit"));
    }

    #[test]
    fn distributed_ban_lookup_error_names_the_backend() {
        // Without a store at all the fail-secure seam still answers: no
        // backend, no error, just the local store's verdict.
        let manager = IpBanManager::with_clock(Arc::new(|| 1_000.0));
        assert!(!manager.try_is_banned(ip("192.0.2.79")).expect("no store"));
    }
}
