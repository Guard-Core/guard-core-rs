//! The distributed-store seam: the engine-side traits and key helpers
//! for Redis-backed (or any backend) rate limiting and bans.
//!
//! Sources: `guard_core/handlers/ratelimit_handler.py`, `_ipban_bans.py`,
//! `_ipban_queries.py`, `redis_handler.py`. The traits are synchronous
//! and assumption-ready, the same pattern the geo handler seam uses.
//!
//! The engine stays I/O-free: the traits are synchronous and
//! assumption-ready (the same pattern the [`crate::geo::GeoIpHandler`]
//! seam uses), and backends live in adapters - the facade crate ships a
//! Redis implementation behind its `redis` feature.
//!
//! ## The reference window semantics, point by point
//!
//! One recorded hit runs the reference's four operations in one
//! transaction over the key `{prefix}rate_limit:rate:{ip}` (global
//! scope) or `{prefix}rate_limit:rate:{ip}:{sha256(endpoint)}` (endpoint
//! scope, `_hash_identity_segment`):
//!
//! 1. `ZADD key now now`
//! 2. `ZREMRANGEBYSCORE key 0 (now - window)` (the reference bounds are
//!    inclusive, exactly its Lua/pipeline arguments)
//! 3. `ZCARD key`
//! 4. `EXPIRE key window * 2`
//!
//! The Redis store compares the post-recording count against the limit
//! (`allowed = count <= limit`); the in-memory store compares the
//! pre-recording count (`count < limit`) - the same boundary, as the
//! reference documents on its own module docstring.
//!
//! ## Ban storage
//!
//! A ban writes `SET {prefix}banned_ips:{ip} <expiry unix seconds> EX
//! ttl` (the reference `set_key("banned_ips", ip, str(expiry),
//! ttl=duration)`); a lookup reads the key, honors `now <= expiry`,
//! and deletes the stale key otherwise (the reference
//! `_check_redis_exact`). A failed ban write degrades to the local
//! store with the TTL clamped to the local cap, exactly the reference
//! `except` branch.
//!
//! ## Failure semantics
//!
//! The reference `redis_fail_open` flag (`false` by default): a failing
//! Redis call raises `GuardRedisError(503, "Redis rate limiting
//! unavailable")` when closed, and falls back to the in-memory window
//! (with a one-time warning) when open. The port mirrors both: a
//! [`StoreError`] from the window store surfaces as `Err` (the facade
//! stage answers the 503) or degrades to the in-memory window under
//! fail-open.

use std::net::IpAddr;

/// A backend failure, wrapped losslessly as a string (the engine never
/// sees backend types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "distributed store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// The reference rate-limit window operations, one hit per call.
pub trait SlidingWindowStore: Send + Sync {
    /// Record one hit at `now` into the window `key` and return the
    /// post-eviction `ZCARD` count. The four reference operations run
    /// atomically (one transaction).
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the backend call fails.
    fn record_hit(&self, key: &str, now: f64, window: u64) -> Result<u64, StoreError>;
}

/// The reference `banned_ips` storage operations (the
/// `{prefix}banned_ips:{ip}` namespace).
pub trait BanStore: Send + Sync {
    /// `SET key expiry EX ttl` with the expiry as unix seconds (the
    /// reference `set_key("banned_ips", ip, str(expiry), ttl=duration)`).
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the backend call fails.
    fn set_ban(&self, key: &str, expiry: f64, ttl_seconds: u64) -> Result<(), StoreError>;

    /// `GET key`, parsed to the stored expiry unix seconds.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the backend call fails.
    fn get_ban(&self, key: &str) -> Result<Option<f64>, StoreError>;

    /// `DEL key` for a stale ban (the reference `_check_redis_exact`).
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the backend call fails.
    fn delete_ban(&self, key: &str) -> Result<(), StoreError>;
}

/// The `{prefix}rate_limit:rate:{ip}` window key, the global tier's
/// bucket (`rate_key = f"rate:{client_ip}"`).
#[must_use]
pub fn rate_window_key(prefix: &str, ip: IpAddr) -> String {
    format!("{prefix}rate_limit:rate:{ip}")
}

/// The `{prefix}rate_limit:rate:{ip}:{endpoint hash}` window key, the
/// endpoint tier's bucket (`_hash_identity_segment` = sha256 hex).
#[must_use]
pub fn rate_window_key_endpoint(prefix: &str, ip: IpAddr, endpoint_path: &str) -> String {
    format!(
        "{prefix}rate_limit:rate:{ip}:{}",
        identity_hash(endpoint_path)
    )
}

/// The `{prefix}banned_ips:{ip}` ban key (`set_key("banned_ips", ip,
/// ...)`'s full key).
#[must_use]
pub fn ban_key(prefix: &str, ip: IpAddr) -> String {
    format!("{prefix}banned_ips:{ip}")
}

/// `_hash_identity_segment`: the sha256 hex digest of the UTF-8 value.
#[must_use]
pub fn identity_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn key_layouts_match_the_reference() {
        let ip = IpAddr::from_str("192.0.2.1").unwrap();
        assert_eq!(
            rate_window_key("guard_core:", ip),
            "guard_core:rate_limit:rate:192.0.2.1"
        );
        assert_eq!(
            ban_key("guard_core:", ip),
            "guard_core:banned_ips:192.0.2.1"
        );
    }

    #[test]
    fn endpoint_keys_hash_the_path_segment() {
        let ip = IpAddr::from_str("192.0.2.1").unwrap();
        let key = rate_window_key_endpoint("guard_core:", ip, "/login");
        assert!(key.starts_with("guard_core:rate_limit:rate:192.0.2.1:"));
        let digest = &key["guard_core:rate_limit:rate:192.0.2.1:".len()..];
        assert_eq!(digest.len(), 64, "sha256 hex digest");
    }

    #[test]
    fn identity_hash_matches_the_reference_vectors() {
        // `hashlib.sha256(b"").hexdigest()`
        assert_eq!(
            identity_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // `hashlib.sha256(b"/login").hexdigest()`
        assert_eq!(
            identity_hash("/login"),
            "7e93fba0bc7adda858a2500090e639e4f563a3965c7cf4c719fb56eb6b12c666"
        );
    }
}

/// An in-memory backend for the distributed paths: the same operations a
/// Redis runs, keyed the same way, so the engine's store paths are
/// testable without a backend process.
#[derive(Default)]
pub struct MemoryStore {
    pub windows: std::sync::Mutex<std::collections::HashMap<String, Vec<(f64, f64)>>>,
    pub bans: std::sync::Mutex<std::collections::HashMap<String, f64>>,
    /// When set, every operation fails (the fail-closed/fail-open tests).
    pub fail: std::sync::atomic::AtomicBool,
}

impl SlidingWindowStore for MemoryStore {
    fn record_hit(&self, key: &str, now: f64, window: u64) -> Result<u64, StoreError> {
        if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StoreError(String::from("backend down")));
        }
        let count;
        {
            let mut windows = self.windows.lock().expect("windows");
            let entries = windows.entry(key.to_owned()).or_default();
            entries.push((now, now));
            let window_start = now - f64::from(u32::try_from(window).unwrap_or(u32::MAX));
            entries.retain(|&(score, _)| score > window_start);
            count = entries.len();
            drop(windows);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(count as u64)
    }
}

impl BanStore for MemoryStore {
    fn set_ban(&self, key: &str, expiry: f64, _ttl_seconds: u64) -> Result<(), StoreError> {
        if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StoreError(String::from("backend down")));
        }
        self.bans
            .lock()
            .expect("bans")
            .insert(key.to_owned(), expiry);
        Ok(())
    }

    fn get_ban(&self, key: &str) -> Result<Option<f64>, StoreError> {
        if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StoreError(String::from("backend down")));
        }
        Ok(self.bans.lock().expect("bans").get(key).copied())
    }

    fn delete_ban(&self, key: &str) -> Result<(), StoreError> {
        if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StoreError(String::from("backend down")));
        }
        self.bans.lock().expect("bans").remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod distributed_tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::Arc;

    use crate::ip_ban::IpBanManager;
    use crate::rate_limit::{RateLimitConfig, RateLimiter};

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    fn store_config(limit: u32) -> RateLimitConfig {
        RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: limit,
            ..RateLimitConfig::default()
        }
    }

    #[test]
    fn distributed_windows_share_one_budget_across_limiter_clones() {
        let store = Arc::new(MemoryStore::default());
        let limiter = RateLimiter::new(store_config(3))
            .expect("config")
            .with_distributed_store(
                Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
                "guard_core:",
                false,
            );
        let visitor = ip("192.0.2.81");
        assert!(
            limiter
                .check_distributed(visitor, None)
                .expect("ok")
                .allowed
        );
        assert!(
            limiter
                .check_distributed(visitor, None)
                .expect("ok")
                .allowed
        );
        assert!(
            limiter
                .check_distributed(visitor, None)
                .expect("ok")
                .allowed
        );
        // The post-recording formulation: the 4th hit records (count 4)
        // and decides count <= limit.
        let blocked = limiter.check_distributed(visitor, None).expect("ok");
        assert!(!blocked.allowed);
        assert_eq!(blocked.count, 4);
        // The shared store is the Redis key, visible to a second limiter.
        assert!(
            store
                .windows
                .lock()
                .expect("windows")
                .contains_key("guard_core:rate_limit:rate:192.0.2.81")
        );
    }

    #[test]
    fn fail_closed_surfaces_the_backend_error() {
        let store = Arc::new(MemoryStore::default());
        store.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let limiter = RateLimiter::new(store_config(3))
            .expect("config")
            .with_distributed_store(
                Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
                "guard_core:",
                false,
            );
        let error = limiter
            .check_distributed(ip("192.0.2.82"), None)
            .expect_err("fail closed");
        assert!(error.to_string().contains("backend down"));
    }

    #[test]
    fn fail_open_degrades_to_the_in_memory_window() {
        let store = Arc::new(MemoryStore::default());
        store.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let limiter = RateLimiter::new(store_config(1))
            .expect("config")
            .with_distributed_store(
                Arc::clone(&store) as Arc<dyn SlidingWindowStore>,
                "guard_core:",
                true,
            );
        let visitor = ip("192.0.2.83");
        assert!(
            limiter
                .check_distributed(visitor, None)
                .expect("ok")
                .allowed
        );
        let blocked = limiter.check_distributed(visitor, None).expect("ok");
        assert!(!blocked.allowed);
        // Nothing reached the failing backend; the in-memory window ran.
        assert!(store.windows.lock().expect("windows").is_empty());
    }

    #[test]
    fn distributed_bans_read_through_and_expire() {
        let store = Arc::new(MemoryStore::default());
        let bans = IpBanManager::with_clock(Arc::new(|| 1_000.0))
            .with_distributed_store(Arc::clone(&store) as Arc<dyn BanStore>, "guard_core:");
        let attacker = ip("192.0.2.84");
        // A local ban writes through to the store under the reference key.
        assert!(
            bans.ban_ip(attacker, 60, "penetration_attempt")
                .expect("ban")
        );
        assert_eq!(
            store
                .bans
                .lock()
                .expect("bans")
                .get("guard_core:banned_ips:192.0.2.84"),
            Some(&1_060.0)
        );
        // A fresh manager (a cold local cache, another worker) reads the
        // distributed ban and caches it.
        let other_worker = IpBanManager::with_clock(Arc::new(|| 1_010.0))
            .with_distributed_store(Arc::clone(&store) as Arc<dyn BanStore>, "guard_core:");
        assert!(other_worker.is_banned(attacker));
        // Past expiry the same read deletes the stale key.
        let expired_worker = IpBanManager::with_clock(Arc::new(|| 2_000.0))
            .with_distributed_store(Arc::clone(&store) as Arc<dyn BanStore>, "guard_core:");
        assert!(!expired_worker.is_banned(attacker));
        assert!(
            !store
                .bans
                .lock()
                .expect("bans")
                .contains_key("guard_core:banned_ips:192.0.2.84")
        );
    }
}
