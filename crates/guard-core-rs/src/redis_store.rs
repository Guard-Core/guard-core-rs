//! The Redis-backed distributed store: the facade implementation of the
//! engine's [`SlidingWindowStore`](guard_core_engine::distributed::SlidingWindowStore)
//! and [`BanStore`](guard_core_engine::distributed::BanStore) seams over
//! the `redis` crate (feature `redis`), plus the full section 08 namespaced
//! surface and the legacy ban-key migration.
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
#[derive(Clone)]
pub struct RedisStore {
    client: redis::Client,
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
        })
    }

    fn connection(&self) -> Result<redis::Connection, StoreError> {
        self.client
            .get_connection()
            .map_err(|error| StoreError(error.to_string()))
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
    pub fn delete(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
    ) -> Result<i64, StoreError> {
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
            .arg(guard_core_engine::redis_schema::exclusive_prune_bound(window_start))
            .ignore()
            .zcard(&full)
            .expire(&full, usize::try_from(ttl_seconds).unwrap_or(usize::MAX))
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
        RedisStore::get_key(self, prefix, namespace, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// No live Redis in CI: the connect error path and the trait object
    /// shapes are what the unit surface can honestly cover.
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
        let store: Arc<dyn SlidingWindowStore> = Arc::new(
            RedisStore::connect("redis://127.0.0.1:1").expect("lazy client"),
        );
        let _bans: Arc<dyn BanStore> = Arc::new(
            RedisStore::connect("redis://127.0.0.1:1").expect("lazy client"),
        );
        let _ = store;
    }

    #[test]
    fn the_store_implements_the_admin_seam_for_the_migration() {
        let _admin: Arc<dyn guard_core_engine::redis_schema::RedisAdminStore> = Arc::new(
            RedisStore::connect("redis://127.0.0.1:1").expect("lazy client"),
        );
    }

    #[test]
    fn store_is_cheaply_clonable_and_shares_the_client() {
        let store = RedisStore::connect("redis://127.0.0.1:1").expect("lazy client");
        let clone = store.clone();
        let first: *const redis::Client = &store.client;
        let second: *const redis::Client = &clone.client;
        assert_eq!(first, second, "a clone shares the pooled client");
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
            store
                .migrate_legacy_ban_keys("guard_core:")
                .is_err(),
            "the migration surfaces the scan failure, never a panic"
        );
    }
}
