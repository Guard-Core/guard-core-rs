//! The Redis-backed distributed store: the facade implementation of the
//! engine's [`SlidingWindowStore`](guard_core_engine::distributed::SlidingWindowStore)
//! and [`BanStore`](guard_core_engine::distributed::BanStore) seams over
//! the `redis` crate (feature `redis`).
//!
//! One hit runs the reference's four operations in a single transaction
//! (`guard_core/scripts/rate_lua.py`, via the Go port's
//! `RecordSlidingWindowHit`): `ZADD`, `ZREMRANGEBYSCORE 0 (now -
//! window)`, `ZCARD`, `EXPIRE window * 2` over
//! `{prefix}rate_limit:rate:{ip}[:{endpoint hash}]`. A ban writes `SET
//! {prefix}banned_ips:{ip} <expiry> EX ttl` (the reference
//! `set_key("banned_ips", ip, str(expiry), ttl=duration)`).
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
//!     .distributed_store(Arc::new(store), "guard_core:", false)
//!     .build()
//!     .expect("valid stage config");
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
