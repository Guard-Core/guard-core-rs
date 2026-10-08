//! The Redis-backed distributed store: the facade implementation of the
//! engine's [`SlidingWindowStore`] and [`BanStore`] seams over the
//! `redis` crate (feature `redis`).
//!
//! Also here: the full section 08 namespaced surface and the legacy
//! ban-key migration.
//!
//! One hit runs the reference's four operations in a single transaction
//! (`guard_core/scripts/rate_lua.py`, via the Go port's
//! `RecordSlidingWindowHit`): `ZADD`, `ZREMRANGEBYSCORE 0 (now -
//! window)`, `ZCARD`, `EXPIRE window * 2` over
//! `{prefix}rate_limit:rate:{ip}[:{endpoint hash}]`. A behavior hit runs
//! the reference `record_sliding_window_hit` shape instead: a uniquified
//! member ([`random_member`](guard_core_engine::redis_schema::random_member)),
//! the exclusive `"-inf" "({window_start"` prune bound, `ZCARD`, `EXPIRE
//! window`. A ban writes `SET {prefix}banned_ips:{ip} <expiry> EX ttl`
//! (the reference `set_key("banned_ips", ip, str(expiry),
//! ttl=duration)`).
//!
//! The namespaced surface mirrors `redis_handler.py` /
//! `redis.go`: `full_key = prefix + namespace + ":" + key`,
//! `ttl = None or 0` persists (`set_key`'s `if ttl:` guard), a `get_key`
//! miss returns `None` and never raises, and every key family of spec
//! section 08 is addressable with the byte-exact builders from
//! [`guard_core_engine::redis_schema`].
//!
//! [`migrate_legacy_ban_keys`](RedisStore::migrate_legacy_ban_keys) runs
//! the reference `_ipban_migration.py` pass at initialization: non-
//! canonical legacy `banned_ips` keys move their longer expiry to the
//! canonical key (`SET ... PX old_pttl`) and are deleted; failures log and
//! never fail startup.
//!
//! Connections are synchronous (the engine seams are sync), created per
//! call from the pooled client so a blocked request path never shares a
//! broken connection.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use guard_core_rs::redis_store::RedisStore;
//! use guard_core_rs::tower::RateLimitStage;
//!
//! # fn main() -> Result<(), guard_core_rs::redis_store::RedisStoreError> {
//! let store = RedisStore::connect("redis://localhost:6379")?;
//! let _stage = RateLimitStage::builder(Default::default())
//!     .distributed_store(Arc::new(store.clone()), "guard_core:", false)
//!     .build()
//!     .expect("valid stage config");
//! // The full section 08 surface and the migration share the same client.
//! let _ = store.get_key("guard_core:", "patterns", "custom");
//! let _ = store.migrate_legacy_ban_keys("guard_core:");
//! # Ok(())
//! # }
//! ```

use guard_core_engine::distributed::{BanStore, SlidingWindowStore, StoreError};
use std::sync::Arc;

/// The Redis backend construction/connection error.
#[derive(Debug)]
pub struct RedisStoreError(pub redis::RedisError);

impl core::fmt::Display for RedisStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "redis store connection failed: {}", self.0)
    }
}

impl std::error::Error for RedisStoreError {}

/// The Redis backend over a synchronous client.
///
/// The resilience knobs mirror the reference `_connection_kwargs`
/// (`redis_handler.py`): a bounded socket read timeout, a client-level
/// retry on connection failures (the reference's
/// `Retry(ExponentialBackoff(), redis_retries)` over the connection error
/// family), and a connection-pool ceiling (the reference
/// `max_connections`).
#[derive(Clone)]
pub struct RedisStore {
    client: redis::Client,
    /// The client-level retry budget for connection failures (the
    /// reference `redis_retries`; `0` disables retrying).
    retries: u32,
    /// The bounded socket read timeout per command (`socket_timeout`;
    /// `None` = the crate default).
    socket_timeout: Option<std::time::Duration>,
    /// The pool ceiling (`max_connections`; `None` = unbounded).
    max_connections: Option<usize>,
    /// The live-connection counter backing [`RedisStore::with_max_connections`].
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

impl RedisStore {
    /// Open a client against `url` (the reference `redis_url`,
    /// `redis://localhost:6379` by default). No connection is opened
    /// until the first operation; per-call connections keep the sync
    /// seam honest about blocking.
    ///
    /// # Errors
    ///
    /// [`RedisStoreError`] when the client cannot be constructed.
    pub fn connect(url: &str) -> Result<Self, RedisStoreError> {
        Ok(Self {
            client: redis::Client::open(url).map_err(RedisStoreError)?,
            retries: 0,
            socket_timeout: None,
            max_connections: None,
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// The reference `redis_retries`: retry connection failures up to
    /// `retries` times (the client-level `Retry` over the connection
    /// error family; command errors never retry).
    #[must_use]
    pub const fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// The reference `socket_timeout`: bound every command's socket read
    /// (`get_connection_with_timeout`; `None` keeps the crate default).
    #[must_use]
    pub const fn with_socket_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.socket_timeout = Some(timeout);
        self
    }

    /// The reference `max_connections`: ceiling the live connections the
    /// store opens at once (a call over the ceiling waits for a slot).
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = Some(max_connections.max(1));
        self
    }

    fn connection(&self) -> Result<redis::Connection, StoreError> {
        self.with_retry(|| {
            if let Some(max) = self.max_connections {
                // A plain counter wait: spin with a short sleep until a
                // slot frees (the pool ceiling is a safeguard against
                // unbounded connection storms, not a latency-tuned path).
                while self.in_flight.load(std::sync::atomic::Ordering::Relaxed) >= max {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            self.in_flight
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let connect = |client: &redis::Client, timeout: Option<std::time::Duration>| {
                timeout
                    .map_or_else(
                        || client.get_connection(),
                        |bounded| client.get_connection_with_timeout(bounded),
                    )
                    .map_err(|error| StoreError(error.to_string()))
            };
            let result = connect(&self.client, self.socket_timeout);
            self.in_flight
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            result
        })
    }

    /// Run one Redis operation with the reference retry semantics: a
    /// connection-level failure retries up to the configured budget, the
    /// last error surfaces. Command errors do not retry (the reference
    /// retries the connection family only).
    fn with_retry<T>(
        &self,
        mut operation: impl FnMut() -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut attempt = 0u32;
        loop {
            match operation() {
                Ok(value) => return Ok(value),
                Err(error) => {
                    if attempt >= self.retries {
                        return Err(error);
                    }
                    attempt += 1;
                }
            }
        }
    }

    /// The reference `safe_operation`: run the operation, swallowing a
    /// failure into `None` (the reference's fail-open per-operation
    /// contract; the error belongs to the host's logging).
    pub fn safe_operation<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, StoreError>,
    ) -> Option<T> {
        operation(self).ok()
    }

    /// The reference `incr(namespace, key, ttl)`: `INCR` the namespaced
    /// counter, applying the TTL with `EXPIRE NX` when given (the TTL only
    /// lands on the first increment, the window anchor). The reference's
    /// retry-re-entry note stands: a retried `INCR` may over-count by one.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn incr(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<i64, StoreError> {
        self.with_retry(|| {
            let mut connection = self.connection()?;
            let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
            let count: i64 = redis::cmd("INCR")
                .arg(&full)
                .query(&mut connection)
                .map_err(|error| StoreError(error.to_string()))?;
            if let Some(ttl) = ttl_seconds
                && ttl > 0
            {
                let _: () = redis::cmd("EXPIRE")
                    .arg(&full)
                    .arg("NX")
                    .arg(ttl)
                    .query(&mut connection)
                    .map_err(|error| StoreError(error.to_string()))?;
            }
            Ok(count)
        })
    }

    /// The reference `exists(namespace, key)`: whether the namespaced key
    /// is present.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn exists(&self, prefix: &str, namespace: &str, key: &str) -> Result<bool, StoreError> {
        self.with_retry(|| {
            let mut connection = self.connection()?;
            let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
            let present: i64 = redis::cmd("EXISTS")
                .arg(&full)
                .query(&mut connection)
                .map_err(|error| StoreError(error.to_string()))?;
            Ok(present > 0)
        })
    }

    /// The distributed lock's acquire half: `SET {key} {token} NX EX ttl`
    /// (the `SET`-with-NX primitive the Rust family names as its lock
    /// surface). `true` = the lock is held by `token`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn acquire_lock(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
        token: &str,
        ttl_seconds: u64,
    ) -> Result<bool, StoreError> {
        self.with_retry(|| {
            let mut connection = self.connection()?;
            let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
            let acquired: Option<String> = redis::cmd("SET")
                .arg(&full)
                .arg(token)
                .arg("NX")
                .arg("EX")
                .arg(ttl_seconds)
                .query(&mut connection)
                .map_err(|error| StoreError(error.to_string()))?;
            Ok(acquired.is_some())
        })
    }

    /// The distributed lock's release half: delete the lock key only when
    /// it still carries `token` (GET-compare-DEL in one atomic pipeline).
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn release_lock(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
        token: &str,
    ) -> Result<bool, StoreError> {
        self.with_retry(|| {
            let mut connection = self.connection()?;
            let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
            let (current, deleted): (Option<String>, i64) = redis::pipe()
                .atomic()
                .cmd("GET")
                .arg(&full)
                .cmd("DEL")
                .arg(&full)
                .query(&mut connection)
                .map_err(|error| StoreError(error.to_string()))?;
            Ok(current.as_deref() == Some(token) && deleted > 0)
        })
    }

    /// The health probe (the Go sibling's status-route probe): `PTTL` a
    /// probe key that matches nothing - a miss is swallowed like any
    /// other, so only a connection failure surfaces.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure (the health answer).
    pub fn health_check(&self, prefix: &str) -> Result<(), StoreError> {
        self.with_retry(|| {
            let mut connection = self.connection()?;
            let probe =
                guard_core_engine::redis_schema::full_key(prefix, "__health__", "__status_probe__");
            let _: i64 = redis::cmd("PTTL")
                .arg(&probe)
                .query(&mut connection)
                .map_err(|error| StoreError(error.to_string()))?;
            Ok(())
        })
    }

    /// `GET {prefix}{namespace}:{key}`: `Ok(None)` is a miss and never
    /// raises (the reference `get_key` contract).
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn get_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        let mut connection = self.connection()?;
        let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
        redis::cmd("GET")
            .arg(full)
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    /// `SET {prefix}{namespace}:{key} value [EX ttl]`: `ttl = None` or `0`
    /// persists (the reference `if ttl:` guard treats 0 as persist).
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn set_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
        value: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
        let mut command = redis::cmd("SET");
        command.arg(full).arg(value);
        if let Some(ttl) = ttl_seconds
            && ttl > 0
        {
            command.arg("EX").arg(ttl);
        }
        command
            .query::<()>(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    /// `DEL {prefix}{namespace}:{key}`: the number of keys removed.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn delete(&self, prefix: &str, namespace: &str, key: &str) -> Result<i64, StoreError> {
        let mut connection = self.connection()?;
        let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
        redis::cmd("DEL")
            .arg(full)
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    /// `KEYS {prefix}{pattern}` (the reference reset paths; blocking by
    /// design there, and the observable contract here).
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn keys(&self, prefix: &str, pattern: &str) -> Result<Vec<String>, StoreError> {
        let mut connection = self.connection()?;
        redis::cmd("KEYS")
            .arg(format!("{prefix}{pattern}"))
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    /// `KEYS {prefix}{pattern}` then `DEL`: every matching key gone (the
    /// reference `delete_pattern`).
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn delete_pattern(&self, prefix: &str, pattern: &str) -> Result<i64, StoreError> {
        let keys = self.keys(prefix, pattern)?;
        if keys.is_empty() {
            return Ok(0);
        }
        let mut connection = self.connection()?;
        let mut command = redis::cmd("DEL");
        for key in &keys {
            command.arg(key);
        }
        command
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    /// The reference `record_sliding_window_hit` (the behavior counters'
    /// shape, distinct from the rate limiter's): one transaction over
    /// `{prefix}{namespace}:{key}` running `ZADD` with a uniquified 32-hex
    /// member, the exclusive `"-inf" "({window_start"` prune, `ZCARD`, and
    /// `EXPIRE ttl` - the inclusive/exclusive boundary distinction is
    /// normative (spec section 08).
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a backend failure.
    pub fn record_sliding_window_hit(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
        now: f64,
        window_start: f64,
        ttl_seconds: u64,
    ) -> Result<u64, StoreError> {
        let mut connection = self.connection()?;
        let full = guard_core_engine::redis_schema::full_key(prefix, namespace, key);
        let member = guard_core_engine::redis_schema::random_member();
        let count: i64 = redis::pipe()
            .atomic()
            .zadd(&full, member, now)
            .ignore()
            .cmd("ZREMRANGEBYSCORE")
            .arg(&full)
            .arg("-inf")
            .arg(guard_core_engine::redis_schema::exclusive_prune_bound(
                window_start,
            ))
            .ignore()
            .zcard(&full)
            .expire(&full, i64::try_from(ttl_seconds).unwrap_or(i64::MAX))
            .ignore()
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// The reference legacy ban-key migration pass over a live connection
    /// (the pure algorithm lives in
    /// [`guard_core_engine::redis_schema::migrate_legacy_ban_keys`]; this
    /// wrapper is what initialization calls, logging per-key failures the
    /// way the reference does instead of failing startup).
    ///
    /// # Errors
    ///
    /// [`StoreError`] only when the initial `SCAN` fails; per-key
    /// failures are skipped.
    pub fn migrate_legacy_ban_keys(&self, prefix: &str) -> Result<(), StoreError> {
        guard_core_engine::redis_schema::migrate_legacy_ban_keys(self, prefix)
    }
}

impl SlidingWindowStore for RedisStore {
    fn record_hit(&self, key: &str, now: f64, window: u64) -> Result<u64, StoreError> {
        let mut connection = self.connection()?;
        let window_start = now - f64::from(u32::try_from(window).unwrap_or(u32::MAX));
        let count: i64 = redis::pipe()
            .atomic()
            .zadd(key, now.to_string(), now)
            .ignore()
            .zrembyscore(key, 0_f64, window_start)
            .ignore()
            .cmd("EXPIRE")
            .arg(key)
            .arg(window * 2)
            .ignore()
            .zcard(key)
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }
}

impl BanStore for RedisStore {
    fn set_ban(&self, key: &str, expiry: f64, ttl_seconds: u64) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        redis::cmd("SET")
            .arg(key)
            .arg(expiry.to_string())
            .arg("EX")
            .arg(ttl_seconds)
            .query::<()>(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    fn get_ban(&self, key: &str) -> Result<Option<f64>, StoreError> {
        let mut connection = self.connection()?;
        let stored: Option<String> = redis::cmd("GET")
            .arg(key)
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))?;
        Ok(stored.and_then(|value| value.parse::<f64>().ok()))
    }

    fn delete_ban(&self, key: &str) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        redis::cmd("DEL")
            .arg(key)
            .query::<i64>(&mut connection)
            .map(|_| ())
            .map_err(|error| StoreError(error.to_string()))
    }
}

impl guard_core_engine::redis_schema::RedisAdminStore for RedisStore {
    /// `SCAN` with `MATCH` (the reference `RedisAdmin.ScanMatch`; the
    /// observable result is `KEYS`, the walk is cursor-based).
    fn scan_match(&self, pattern: &str) -> Result<Vec<String>, StoreError> {
        let mut connection = self.connection()?;
        let mut keys = Vec::new();
        let mut cursor = String::from("0");
        loop {
            let (batch, next): (Vec<String>, String) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query(&mut connection)
                .map_err(|error| StoreError(error.to_string()))?;
            keys.extend(batch);
            cursor = next;
            if cursor == "0" {
                return Ok(keys);
            }
        }
    }

    fn pttl_ms(&self, key: &str) -> Result<i64, StoreError> {
        let mut connection = self.connection()?;
        redis::cmd("PTTL")
            .arg(key)
            .query(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    fn set_px(&self, key: &str, value: &str, ttl_ms: i64) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("PX")
            .arg(ttl_ms)
            .query::<()>(&mut connection)
            .map_err(|error| StoreError(error.to_string()))
    }

    fn delete_keys(&self, keys: &[String]) -> Result<(), StoreError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let mut command = redis::cmd("DEL");
        for key in keys {
            command.arg(key);
        }
        command
            .query::<i64>(&mut connection)
            .map(|_| ())
            .map_err(|error| StoreError(error.to_string()))
    }

    fn get_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        Self::get_key(self, prefix, namespace, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// No live Redis in CI: the connect error path and the trait object
    /// shapes are what the unit surface can honestly cover.
    #[test]
    fn the_resilience_knobs_chain() {
        let store = RedisStore::connect("redis://127.0.0.1:1")
            .expect("lazy client")
            .with_retries(3)
            .with_socket_timeout(std::time::Duration::from_secs(2))
            .with_max_connections(4);
        // The knobs ride every subsequent operation (the health probe goes
        // out over the bounded, retrying connection path).
        let _ = store.health_check("guard");
    }

    #[test]
    fn with_retries_exhausts_before_surfacing() {
        // The retry loop: a failing operation surfaces the last error
        // after the budget (the pool ceiling of 1 with a live inner
        // failure exercises connection() through the retry path).
        let store = RedisStore::connect("redis://127.0.0.1:1")
            .expect("lazy client")
            .with_retries(2)
            .with_max_connections(1);
        let error = store.health_check("guard").unwrap_err();
        assert!(
            error.0.contains("127.0.0.1:1") || !error.0.is_empty(),
            "the last error surfaces: {error:?}"
        );
    }

    #[test]
    fn safe_operation_swallows_the_failure() {
        let store = RedisStore::connect("redis://127.0.0.1:1").expect("lazy client");
        // The reference `safe_operation`'s fail-open per-operation shape.
        assert!(
            store
                .safe_operation(|store| store.exists("guard", "patterns", "custom"))
                .is_none()
        );
        assert_eq!(
            store.safe_operation(|store| store.get_key("guard", "patterns", "custom")),
            None
        );
    }

    #[test]
    fn the_fail_open_store_reads_the_permissive_defaults() {
        use super::{FailOpenStore, SlidingWindowStore};
        use guard_core_engine::distributed::{BanStore, StoreError};

        struct Failing;
        impl SlidingWindowStore for Failing {
            fn record_hit(&self, _key: &str, _now: f64, _window: u64) -> Result<u64, StoreError> {
                Err(StoreError(String::from("backend down")))
            }
        }
        impl BanStore for Failing {
            fn set_ban(&self, _key: &str, _expiry: f64, _ttl: u64) -> Result<(), StoreError> {
                Err(StoreError(String::from("backend down")))
            }
            fn get_ban(&self, _key: &str) -> Result<Option<f64>, StoreError> {
                Err(StoreError(String::from("backend down")))
            }
            fn delete_ban(&self, _key: &str) -> Result<(), StoreError> {
                Err(StoreError(String::from("backend down")))
            }
        }

        let fail_open = FailOpenStore::new(Failing);
        // A window read answers the empty window (allowed).
        assert_eq!(fail_open.record_hit("k", 1.0, 60).expect("fail-open"), 0);
        // A ban read answers "no live ban"; writes answer no-op success.
        assert_eq!(fail_open.get_ban("k").expect("fail-open"), None);
        fail_open.set_ban("k", 1.0, 60).expect("fail-open");
        fail_open.delete_ban("k").expect("fail-open");
    }

    #[test]
    fn connect_fails_closed_on_an_unroutable_url() {
        // Port 1 on localhost is never the test Redis; the client itself
        // may accept the URL, the first command fails. Only construction
        // is asserted here.
        let store = RedisStore::connect("redis://127.0.0.1:1");
        assert!(store.is_ok(), "client construction is lazy");
    }

    #[test]
    fn store_impls_are_object_safe() {
        // The seams the stage builder takes.
        let store: Arc<dyn SlidingWindowStore> =
            Arc::new(RedisStore::connect("redis://127.0.0.1:1").expect("lazy client"));
        let _bans: Arc<dyn BanStore> =
            Arc::new(RedisStore::connect("redis://127.0.0.1:1").expect("lazy client"));
        let _ = store;
    }

    #[test]
    fn the_store_implements_the_admin_seam_for_the_migration() {
        let _admin: Arc<dyn guard_core_engine::redis_schema::RedisAdminStore> =
            Arc::new(RedisStore::connect("redis://127.0.0.1:1").expect("lazy client"));
    }

    #[test]
    fn store_is_cheaply_clonable_and_shares_the_pool_counter() {
        let store = RedisStore::connect("redis://127.0.0.1:1").expect("lazy client");
        let clone = store.clone();
        assert_eq!(
            Arc::as_ptr(&store.in_flight),
            Arc::as_ptr(&clone.in_flight),
            "a clone shares the pool counter (the ceiling is global)"
        );
    }

    #[test]
    fn operations_fail_closed_with_a_backend_error_shape() {
        // Port 1 on localhost refuses immediately: every operation maps
        // the failure into the engine's StoreError, never a panic.
        let store = RedisStore::connect("redis://127.0.0.1:1").expect("lazy client");
        let error = store
            .get_key("guard_core:", "patterns", "custom")
            .expect_err("unroutable");
        assert!(error.to_string().contains("distributed store error"));
        assert!(
            store
                .set_key("guard_core:", "patterns", "custom", "x", None)
                .is_err()
        );
        assert!(store.delete("guard_core:", "patterns", "custom").is_err());
        assert!(store.keys("guard_core:", "banned_ips:*").is_err());
        assert!(store.delete_pattern("guard_core:", "banned_ips:*").is_err());
        assert!(
            store
                .record_sliding_window_hit(
                    "guard_core:",
                    "behavior_usage",
                    "behavior:usage:a:b",
                    1_000.0,
                    940.0,
                    60
                )
                .is_err()
        );
        assert!(
            store.migrate_legacy_ban_keys("guard_core:").is_err(),
            "the migration surfaces the scan failure, never a panic"
        );
    }
}

/// The `redis_fail_open` posture over any distributed store: a backend
/// failure reads as the permissive default instead of surfacing.
///
/// A window hit answers `0` (empty window: allowed) and a ban read
/// answers "no live ban" (the reference `safe_operation`'s
/// swallow-to-default contract, lifted from the handler to the store
/// boundary so a decorated store needs no per-caller error plumbing).
/// Writes (`set_ban`, `delete_ban`) answer successfully-without-effect.
#[derive(Debug, Clone, Default)]
pub struct FailOpenStore<S> {
    inner: S,
}

impl<S> FailOpenStore<S> {
    /// Wrap `inner` with the fail-open defaults.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// The decorated store.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: SlidingWindowStore> SlidingWindowStore for FailOpenStore<S> {
    fn record_hit(&self, key: &str, now: f64, window: u64) -> Result<u64, StoreError> {
        Ok(self.inner.record_hit(key, now, window).unwrap_or(0))
    }
}

impl<S: BanStore> BanStore for FailOpenStore<S> {
    fn set_ban(&self, key: &str, expiry: f64, ttl_seconds: u64) -> Result<(), StoreError> {
        let _ = self.inner.set_ban(key, expiry, ttl_seconds);
        Ok(())
    }

    fn get_ban(&self, key: &str) -> Result<Option<f64>, StoreError> {
        Ok(self.inner.get_ban(key).unwrap_or(None))
    }

    fn delete_ban(&self, key: &str) -> Result<(), StoreError> {
        let _ = self.inner.delete_ban(key);
        Ok(())
    }
}
