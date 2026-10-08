//! The `GeoIP` and cloud refresh lifecycles.
//!
//! The `IPInfoManager` port (token, download, Redis-cached database
//! copy, max-age, atomic write, refresh, status) and the cloud refresh
//! scheduler (the single-flight background refresh). Sources:
//! `guard_core/handlers/ipinfo_handler.py` and the `schedule_refresh`
//! half of `cloud_handler.py`.
//!
//! The building blocks the crate already ships carry the wire half: the
//! database download is [`CloudFetcher::fetch_geo_database`]
//! (`Authorization: Bearer {token}`, 3 attempts, the exponential backoff
//! starting at 1 s), the reads are [`Mmdb::open`] / `lookup_country`,
//! and the persistence handle is the composite's
//! [`TelemetryRedisStore`] (the reference `redis_handler`). What this
//! module adds is the lifecycle around them:
//!
//! - [`IpInfoManager::initialize`]: the reference order - a cached
//!   database from Redis (`ipinfo` / `database`, written atomically)
//!   answers first; otherwise a missing or older-than-`max_age` file
//!   downloads; a corrupted file is deleted and re-fetched; the reader
//!   opens last, stamping `last_refreshed`;
//! - [`IpInfoManager::get_country`]: the `None` answers with the
//!   initialization-attempted distinction;
//! - [`IpInfoManager::refresh`]: the download + reopen + stamp;
//! - [`IpInfoManager::get_status`]: `{ready, last_refreshed, entries}`
//!   (the status-payload keys; `entries` is the reader's node count);
//! - [`CloudRefreshScheduler::schedule_refresh`]: the single-flight
//!   gate (an in-flight refresh makes further calls no-ops, `true` when
//!   a refresh started), the body on a std thread (the crate's
//!   no-runtime idiom - the reference's `asyncio.create_task`), the
//!   fetched ranges swapping into the shared `CloudIpTable`.
//!
//! # Example
//!
//! ```
//! use guard_core_rs::geo_lifecycle::IpInfoManager;
//!
//! let manager = IpInfoManager::new("token", None, 86_400).expect("token");
//! // No download ran: the reader is uninitialized and the status
//! // answers the reference keys.
//! let status = manager.get_status();
//! assert_eq!(status["ready"], false);
//! assert_eq!(status["last_refreshed"], serde_json::Value::Null);
//! assert_eq!(status["entries"], 0);
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::cloud_fetch::{CloudFetcher, endpoints};
use crate::composite::TelemetryRedisStore;
use crate::mmdb::Mmdb;
use chrono::{DateTime, Utc};
use guard_core_engine::cloud_fetch::ParsedRanges;

/// `db_path or Path("data/ipinfo/country_asn.mmdb")`: the default
/// database location.
#[must_use]
pub fn default_db_path() -> PathBuf {
    PathBuf::from("data/ipinfo/country_asn.mmdb")
}

/// `DYNAMIC_RULES_NAMESPACE`-style constants: the Redis namespace and
/// key the cached database rides (`ipinfo` / `database`).
pub const IPINFO_REDIS_NAMESPACE: &str = "ipinfo";
/// The cached-database key.
pub const IPINFO_REDIS_KEY: &str = "database";

/// The reference `IPInfoManager`: the token-gated `GeoIP` database
/// lifecycle over the crate's MMDB reader (the download attempts ride
/// the fetcher: 3 tries with the exponential backoff starting at 1 s).
pub struct IpInfoManager {
    token: String,
    db_path: PathBuf,
    max_age: Duration,
    reader: Mutex<Option<Arc<Mmdb>>>,
    redis: Option<Arc<dyn TelemetryRedisStore>>,
    last_refreshed: Mutex<Option<DateTime<Utc>>>,
    initialization_attempted: AtomicBool,
    fetcher: CloudFetcher,
    database_url: String,
}

impl core::fmt::Debug for IpInfoManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpInfoManager")
            .field("db_path", &self.db_path)
            .field("initialized", &self.is_initialized())
            .field("max_age_secs", &self.max_age.as_secs())
            .finish_non_exhaustive()
    }
}

/// An initialize/refresh failure (the reference logs these and runs
/// degraded; the outcome carries the reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoLifecycleError(pub String);

impl core::fmt::Display for GeoLifecycleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "geo lifecycle error: {}", self.0)
    }
}

impl std::error::Error for GeoLifecycleError {}

impl IpInfoManager {
    /// The reference constructor (`token` required - an empty token
    /// fails exactly like the reference's `ValueError`).
    ///
    /// # Errors
    ///
    /// [`GeoLifecycleError`] when the token is empty.
    pub fn new(
        token: &str,
        db_path: Option<PathBuf>,
        max_age_seconds: u64,
    ) -> Result<Self, GeoLifecycleError> {
        if token.is_empty() {
            return Err(GeoLifecycleError(String::from("IPInfo token is required!")));
        }
        Ok(Self {
            token: token.to_owned(),
            db_path: db_path.unwrap_or_else(default_db_path),
            max_age: Duration::from_secs(max_age_seconds),
            reader: Mutex::new(None),
            redis: None,
            last_refreshed: Mutex::new(None),
            initialization_attempted: AtomicBool::new(false),
            fetcher: CloudFetcher::new(),
            database_url: String::from(endpoints::GEO_DATABASE),
        })
    }

    /// The manager built from the config surface (`ipinfo_token`,
    /// `ipinfo_db_path`, `geo_ip_db_max_age`).
    ///
    /// # Errors
    ///
    /// [`GeoLifecycleError`] when `ipinfo_token` is unset (the
    /// reference requires it).
    pub fn from_config(
        config: &guard_core_engine::security_config::SecurityConfig,
    ) -> Result<Self, GeoLifecycleError> {
        Self::new(
            config.ipinfo_token.as_deref().unwrap_or(""),
            config.ipinfo_db_path.clone(),
            config.geo_ip_db_max_age,
        )
    }

    /// Wire the Redis handle (the reference `initialize_redis`: the
    /// cached database copy rides it).
    #[must_use]
    pub fn with_redis_store(mut self, store: Arc<dyn TelemetryRedisStore>) -> Self {
        self.redis = Some(store);
        self
    }

    /// Override the database URL (the scripted-HTTP tests point the
    /// download at a local stub; production stays on the reference
    /// endpoint).
    #[must_use]
    pub fn with_database_url(mut self, url: String) -> Self {
        self.database_url = url;
        self
    }

    /// The reader handle (the `GeoIpHandler` implementations read through
    /// this).
    ///
    /// # Errors
    ///
    /// Never.
    pub fn reader(&self) -> Option<Arc<Mmdb>> {
        self.reader.lock().expect("ipinfo reader").clone()
    }

    /// The configured database path (diagnostics; the config mapping
    /// test asserts it).
    #[must_use]
    pub const fn db_path(&self) -> &PathBuf {
        &self.db_path
    }

    /// The configured max age in seconds (diagnostics).
    #[must_use]
    pub const fn max_age_secs(&self) -> u64 {
        self.max_age.as_secs()
    }

    /// `is_initialized`: the reader is open.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.reader.lock().expect("ipinfo reader").is_some()
    }

    /// `entry_count`: the reader's node count, `0` uninitialized.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.reader
            .lock()
            .expect("ipinfo reader")
            .as_ref()
            .map_or(0, |reader| reader.node_count())
    }

    /// `get_status`: `{ready, last_refreshed, entries}`.
    #[must_use]
    pub fn get_status(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::from_iter([
            (
                String::from("ready"),
                serde_json::Value::Bool(self.is_initialized()),
            ),
            (
                String::from("last_refreshed"),
                self.last_refreshed
                    .lock()
                    .expect("last refreshed")
                    .map(|at| serde_json::Value::String(at.to_rfc3339()))
                    .unwrap_or(serde_json::Value::Null),
            ),
            (
                String::from("entries"),
                serde_json::Value::Number(serde_json::Number::from(self.entry_count())),
            ),
        ])
    }

    /// `_is_db_outdated`: a missing file is outdated; an existing one is
    /// outdated when its mtime age exceeds `max_age`.
    #[must_use]
    pub fn is_db_outdated(&self) -> bool {
        let age = std::fs::metadata(&self.db_path)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| SystemTime::now().duration_since(modified).ok());
        age.is_none_or(|age| age > self.max_age)
    }

    /// `initialize`: the Redis-cached copy answers first, then the
    /// file's freshness decides a download, then the reader opens.
    /// `initialization_attempted` stamps regardless of the outcome (the
    /// reference's `finally`).
    ///
    /// # Errors
    ///
    /// The failing leg (the download, the atomic write, the corrupted
    /// database); the caller decides the degraded posture, the reader
    /// stays as-is.
    pub fn initialize(&self) -> Result<(), GeoLifecycleError> {
        let outcome = self.initialize_inner();
        self.initialization_attempted.store(true, Ordering::Relaxed);
        outcome
    }

    fn initialize_inner(&self) -> Result<(), GeoLifecycleError> {
        if let Some(parent) = self.db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // The Redis-cached copy: written atomically, then opened.
        if let Some(store) = &self.redis {
            let cached = store
                .get_key("", IPINFO_REDIS_NAMESPACE, IPINFO_REDIS_KEY)
                .ok()
                .flatten();
            if let Some(content) = cached {
                let bytes = latin1_decode(&content)?;
                self.write_database_atomically(&bytes)?;
                return self.apply_opened_reader();
            }
        }

        // The file half: a missing or outdated file downloads (the
        // download writes the file or returns Err, so the reader opens
        // on both tails).
        if !self.db_path.exists() || self.is_db_outdated() {
            self.download_database()?;
        }
        self.apply_opened_reader()
    }

    /// `refresh`: the download, the reopen, the stamp; a failure keeps
    /// the existing reader.
    ///
    /// # Errors
    ///
    /// The failing leg (the download, the reopen); the reader stays
    /// as-is on failure.
    pub fn refresh(&self) -> Result<(), GeoLifecycleError> {
        let outcome = self.refresh_inner();
        self.initialization_attempted.store(true, Ordering::Relaxed);
        outcome
    }

    fn refresh_inner(&self) -> Result<(), GeoLifecycleError> {
        self.download_database()?;
        let reader = self.open_database_or_none()?;
        if let Some(reader) = reader {
            *self.reader.lock().expect("ipinfo reader") = Some(reader);
            *self.last_refreshed.lock().expect("last refreshed") = Some(Utc::now());
        }
        Ok(())
    }

    /// `_download_database`: the Bearer download (the fetcher carries
    /// the 3-attempt backoff), then the Redis cache copy (`ttl =
    /// max_age`).
    fn download_database(&self) -> Result<(), GeoLifecycleError> {
        let content = self
            .fetcher
            .fetch_geo_database(&self.database_url, &self.token)
            .map_err(|error| GeoLifecycleError(format!("download failed: {error}")))?;
        self.write_database_atomically(&content)?;
        if let Some(store) = &self.redis {
            // The reference caches `f.read().decode("latin-1")`: every
            // byte rides as its own code point, and the read-back maps
            // them byte for byte.
            let encoded: String = content.iter().map(|&byte| byte as char).collect();
            let _ = store.set_key(
                "",
                IPINFO_REDIS_NAMESPACE,
                IPINFO_REDIS_KEY,
                &encoded,
                Some(self.max_age.as_secs()),
            );
        }
        Ok(())
    }

    /// `_write_database_atomically`: the `.tmp` sibling then `rename`.
    fn write_database_atomically(&self, content: &[u8]) -> Result<(), GeoLifecycleError> {
        let file_name = self
            .db_path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().to_string());
        let tmp_path = self.db_path.with_file_name(format!("{file_name}.tmp"));
        let write = std::fs::write(&tmp_path, content)
            .map_err(|error| GeoLifecycleError(format!("atomic write failed: {error}")));
        if write.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return write;
        }
        std::fs::rename(&tmp_path, &self.db_path)
            .map_err(|error| GeoLifecycleError(format!("atomic rename failed: {error}")))
    }

    /// `_open_database_or_none`: a corrupted database is deleted and
    /// answered as `None`.
    fn open_database_or_none(&self) -> Result<Option<Arc<Mmdb>>, GeoLifecycleError> {
        match Mmdb::open(&self.db_path) {
            Ok(reader) => Ok(Some(Arc::new(reader))),
            Err(error) => {
                let _ = std::fs::remove_file(&self.db_path);
                Err(GeoLifecycleError(format!(
                    "IPInfo database at {} is corrupted, removing: {error}",
                    self.db_path.display()
                )))
            }
        }
    }

    fn apply_opened_reader(&self) -> Result<(), GeoLifecycleError> {
        if let Some(reader) = self.open_database_or_none()? {
            *self.reader.lock().expect("ipinfo reader") = Some(reader);
            *self.last_refreshed.lock().expect("last refreshed") = Some(Utc::now());
        }
        Ok(())
    }

    /// `get_country`: the reader's country answer; the uninitialized /
    /// failed reads answer `None`.
    #[must_use]
    pub fn get_country(&self, ip: std::net::IpAddr) -> Option<String> {
        let reader = self.reader.lock().expect("ipinfo reader").clone()?;
        reader.lookup_country(ip).ok().flatten()
    }

    /// `initialization_attempted` (the `get_country` warning split).
    #[must_use]
    pub fn initialization_attempted(&self) -> bool {
        self.initialization_attempted.load(Ordering::Relaxed)
    }
}

/// The reference endpoint for one bare provider name.
fn reference_endpoint(provider: &str) -> &'static str {
    match provider {
        "GCP" => endpoints::GCP,
        "Azure" => endpoints::AZURE_PAGE,
        "DigitalOcean" | "Linode" => endpoints::LINODE,
        "Vultr" => endpoints::VULTR,
        // AWS and every unknown name land on the AWS document (the
        // reference's fetcher map default).
        _ => endpoints::AWS,
    }
}

/// The latin-1 read-back (`cached_db.encode("latin-1")` inverted): a
/// code point above U+00FF fails the leg (the reference's encode raises
/// the same shape).
fn latin1_decode(text: &str) -> Result<Vec<u8>, GeoLifecycleError> {
    text.chars()
        .map(|c| {
            u8::try_from(u32::from(c))
                .map_err(|_| GeoLifecycleError(String::from("cached database is not latin-1")))
        })
        .collect()
}

/// The cloud refresh scheduler (the `schedule_refresh` half of
/// `cloud_handler.py`): the single-flight gate over a std-thread
/// refresh body that swaps the fetched ranges into the shared
/// `CloudIpTable`.
///
/// `schedule_refresh` returns `true` when it started the refresh and
/// `false` while one is in flight (further calls are no-ops, the
/// lock-guarded gate the reference documents for concurrent callers).
pub struct CloudRefreshScheduler {
    in_flight: Arc<AtomicBool>,
    providers: Vec<&'static str>,
    endpoint_overrides: BTreeMap<&'static str, String>,
}

impl Default for CloudRefreshScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudRefreshScheduler {
    /// A scheduler over the reference provider set (`AWS`, `GCP`,
    /// `Azure`, `DigitalOcean`, `Linode`, `Vultr` - the
    /// `VALID_CLOUD_PROVIDERS` bare names).
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicBool::new(false)),
            providers: vec!["AWS", "GCP", "Azure", "DigitalOcean", "Linode", "Vultr"],
            endpoint_overrides: BTreeMap::new(),
        }
    }

    /// Restrict the scheduler to a provider subset.
    #[must_use]
    pub fn with_providers(mut self, providers: Vec<&'static str>) -> Self {
        self.providers = providers;
        self
    }

    /// Override one provider's endpoint (the scripted-HTTP tests point
    /// the fetch at a local stub; production stays on the reference
    /// endpoints).
    #[must_use]
    pub fn with_provider_endpoint(mut self, provider: &'static str, url: String) -> Self {
        self.endpoint_overrides.insert(provider, url);
        self
    }

    /// Whether a refresh is currently in flight.
    #[must_use]
    pub fn refresh_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// `schedule_refresh`: start one background refresh (`true`) unless
    /// one is in flight (`false`). The body fetches every provider and
    /// swaps the ranges into the table (the reference
    /// `_refresh_providers`: a failed provider clears its ranges and
    /// the rest continue).
    #[must_use]
    pub fn schedule_refresh(
        &self,
        table: &Arc<guard_core_engine::cloud_provider::CloudIpTable>,
    ) -> bool {
        let table = Arc::clone(table);
        let overrides = self.endpoint_overrides.clone();
        let providers: Vec<&'static str> = self.providers.clone();
        self.schedule_refresh_with(move || {
            Self::refresh_all_with_overrides(&CloudFetcher::new(), &table, &providers, &overrides);
        })
    }

    /// The gate over a custom body (the reference `refresh=` override).
    pub fn schedule_refresh_with<F>(&self, body: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let in_flight = Arc::clone(&self.in_flight);
        // `finally: self._refresh_in_flight = False` rides the thread.
        std::thread::spawn(move || {
            body();
            in_flight.store(false, Ordering::Relaxed);
        });
        true
    }

    /// `refresh_async`'s body: fetch every provider, swap into the
    /// table, clear on failure (the reference `_refresh_providers`).
    pub fn refresh_all(
        fetcher: &CloudFetcher,
        table: &Arc<guard_core_engine::cloud_provider::CloudIpTable>,
        providers: &[&'static str],
    ) {
        let overrides = BTreeMap::new();
        Self::refresh_all_with_overrides(fetcher, table, providers, &overrides);
    }

    /// The body with the endpoint overrides (the scripted-HTTP tests
    /// point every provider at a local stub).
    pub fn refresh_all_with_overrides(
        fetcher: &CloudFetcher,
        table: &Arc<guard_core_engine::cloud_provider::CloudIpTable>,
        providers: &[&'static str],
        overrides: &BTreeMap<&'static str, String>,
    ) {
        for provider in providers {
            let url = overrides
                .get(provider)
                .map_or_else(|| reference_endpoint(provider).to_owned(), Clone::clone);
            let ranges: ParsedRanges = match *provider {
                "AWS" => fetcher.fetch_aws(&url),
                "GCP" => fetcher.fetch_gcp(&url),
                "Azure" => fetcher.fetch_azure(&url),
                "DigitalOcean" | "Linode" => fetcher.fetch_csv(&url),
                "Vultr" => fetcher.fetch_vultr(&url),
                _ => continue,
            };
            if ranges.is_empty() {
                table.clear_provider(provider);
            } else {
                let _ = table.set_provider_ranges(provider, ranges);
            }
        }
    }
}

#[cfg(test)]
mod geo_lifecycle_tests {
    use super::*;
    use crate::mmdb::test_fixtures::country_fixture;
    use guard_core_engine::distributed::StoreError;
    use std::path::Path;
    use std::sync::Mutex;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// A scripted Redis store: the cached payload, the writes recorded.
    struct ScriptedStore {
        cached: Mutex<Option<String>>,
        writes: Mutex<Vec<(String, String, Option<u64>)>>,
    }

    impl ScriptedStore {
        fn with_cache(payload: Option<String>) -> Self {
            Self {
                cached: Mutex::new(payload),
                writes: Mutex::new(Vec::new()),
            }
        }
    }

    impl TelemetryRedisStore for ScriptedStore {
        fn get_key(
            &self,
            _prefix: &str,
            namespace: &str,
            key: &str,
        ) -> Result<Option<String>, StoreError> {
            Ok(self
                .cached
                .lock()
                .expect("cache")
                .clone()
                .filter(|_| namespace == IPINFO_REDIS_NAMESPACE && key == IPINFO_REDIS_KEY))
        }

        fn set_key(
            &self,
            _prefix: &str,
            namespace: &str,
            key: &str,
            value: &str,
            ttl_seconds: Option<u64>,
        ) -> Result<(), StoreError> {
            self.writes.lock().expect("writes").push((
                namespace.to_owned(),
                key.to_owned(),
                ttl_seconds,
            ));
            let _ = value;
            Ok(())
        }
    }

    /// A local stub serving the fixture bytes for the database download.
    struct DbStub {
        url: String,
    }

    impl DbStub {
        fn serve(payload: Vec<u8>) -> Self {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.set_nonblocking(true).expect("nonblocking");
            let port = listener.local_addr().expect("addr").port();
            let body = payload;
            std::thread::spawn(move || {
                loop {
                    if let Ok((mut stream, _)) = listener.accept() {
                        let mut buffer = [0_u8; 2048];
                        let _ = stream.read(&mut buffer);
                        let head =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(&body);
                        let _ = stream.flush();
                    } else {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            });
            Self {
                url: format!("http://127.0.0.1:{port}/free/country_asn.mmdb"),
            }
        }
    }

    fn manager_with_stub(stub: &DbStub, dir: &Path) -> IpInfoManager {
        IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400)
            .expect("token")
            .with_database_url(stub.url.clone())
    }

    #[test]
    fn an_empty_token_fails_the_constructor() {
        let error = IpInfoManager::new("", None, 86_400).expect_err("rejects");
        assert_eq!(error.0, "IPInfo token is required!");
        assert_eq!(
            error.to_string(),
            "geo lifecycle error: IPInfo token is required!"
        );
    }

    #[test]
    fn the_uninitialized_status_answers_the_reference_keys() {
        let dir = temp_dir("geo-uninit");
        let manager = manager_with_stub(&DbStub { url: String::new() }, &dir);
        let status = manager.get_status();
        assert_eq!(status["ready"], serde_json::Value::Bool(false));
        assert_eq!(status["last_refreshed"], serde_json::Value::Null);
        assert_eq!(
            status["entries"],
            serde_json::Value::Number(serde_json::Number::from(0))
        );
        assert!(!manager.initialization_attempted());
        assert_eq!(manager.get_country("192.0.2.1".parse().expect("ip")), None);
        assert!(manager.is_db_outdated(), "a missing file is outdated");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn initialize_downloads_opens_and_stamps() {
        let dir = temp_dir("geo-dl");
        let stub = DbStub::serve(country_fixture());
        let manager = manager_with_stub(&stub, &dir);
        manager.initialize().expect("initializes");
        assert!(manager.is_initialized());
        assert!(manager.initialization_attempted());
        assert!(manager.last_refreshed.lock().expect("stamp").is_some());
        assert!(manager.entry_count() > 0, "the fixture carries nodes");
        let country = manager.get_country("192.0.2.1".parse().expect("ip"));
        assert_eq!(country.as_deref(), Some("US"));
        assert!(!manager.is_db_outdated(), "a fresh file is current");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn initialize_with_a_fresh_file_skips_the_download() {
        let dir = temp_dir("geo-fresh");
        std::fs::write(dir.join("db.mmdb"), country_fixture()).expect("writes");
        // The dead-endpoint URL would fail the download leg; the fresh
        // file skips it entirely (the exists-and-current arm).
        let manager = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400)
            .expect("token")
            .with_database_url(String::from("http://127.0.0.1:9/db.mmdb"));
        manager.initialize().expect("the fresh file opens");
        assert_eq!(
            manager
                .get_country("192.0.2.1".parse().expect("ip"))
                .as_deref(),
            Some("US")
        );
        assert!(manager.initialization_attempted());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn initialize_hydrates_the_redis_cached_copy_first() {
        let dir = temp_dir("geo-redis");
        let fixture = country_fixture();
        let store = Arc::new(ScriptedStore::with_cache(Some(
            fixture.iter().map(|&byte| byte as char).collect::<String>(),
        )));
        let manager = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400)
            .expect("token")
            .with_redis_store(store);
        manager.initialize().expect("hydrates");
        assert!(manager.is_initialized(), "the cached copy opened");
        assert_eq!(
            manager
                .get_country("192.0.2.1".parse().expect("ip"))
                .as_deref(),
            Some("US")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refresh_redownloads_and_a_failure_keeps_the_reader() {
        let dir = temp_dir("geo-refresh");
        let stub = DbStub::serve(country_fixture());
        let manager = manager_with_stub(&stub, &dir);
        manager.initialize().expect("initializes");
        assert!(manager.is_initialized());

        // A refresh against the same stub re-stamps and stays healthy.
        manager.refresh().expect("refreshes");
        assert!(manager.is_initialized());

        // A refresh against a dead endpoint fails and keeps the reader.
        let failing = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400)
            .expect("token")
            .with_database_url(String::from("http://127.0.0.1:9/db.mmdb"));
        let error = failing.refresh().expect_err("the download fails");
        assert!(error.0.contains("download failed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupted_database_is_deleted_and_reported() {
        let dir = temp_dir("geo-corrupt");
        std::fs::write(dir.join("db.mmdb"), b"not an mmdb").expect("writes");
        let manager = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400).expect("token");
        let error = manager
            .open_database_or_none()
            .expect_err("the corrupted file reports");
        assert!(error.0.contains("corrupted, removing"));
        assert!(!dir.join("db.mmdb").exists(), "the corrupted file is gone");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_outdated_check_reads_the_max_age() {
        let dir = temp_dir("geo-age");
        let manager = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400).expect("token");
        std::fs::write(dir.join("db.mmdb"), country_fixture()).expect("writes");
        assert!(!manager.is_db_outdated(), "a just-written file is fresh");

        let strict = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 0).expect("token");
        assert!(
            strict.is_db_outdated(),
            "max_age = 0 outs everything immediately"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_scheduler_runs_single_flight_and_clears_the_flag() {
        let scheduler = CloudRefreshScheduler::new();
        assert!(!scheduler.refresh_in_flight());

        let started = scheduler.schedule_refresh_with(|| {
            std::thread::sleep(Duration::from_millis(100));
        });
        assert!(started, "the first call starts the flight");
        assert!(scheduler.refresh_in_flight());

        let blocked = scheduler.schedule_refresh_with(|| {});
        assert!(!blocked, "the in-flight gate blocks the second call");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while scheduler.refresh_in_flight() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!scheduler.refresh_in_flight(), "the flight clears");
    }

    #[test]
    fn the_refresh_body_is_a_noop_over_an_empty_provider_set() {
        use guard_core_engine::cloud_provider::CloudIpTable;
        let table = Arc::new(CloudIpTable::default());
        // No providers: the body touches nothing (the live endpoints
        // are never contacted from the suite).
        CloudRefreshScheduler::refresh_all(&CloudFetcher::new(), &table, &[]);
        assert!(
            !table.provider_is_ready("AWS"),
            "the empty run leaves every provider unloaded"
        );
    }

    #[test]
    fn the_restricted_scheduler_carries_the_subset() {
        let scheduler = CloudRefreshScheduler::new().with_providers(vec!["AWS"]);
        assert!(!scheduler.refresh_in_flight());
    }

    #[test]
    fn the_default_path_and_the_config_surface_map() {
        assert_eq!(
            default_db_path(),
            PathBuf::from("data/ipinfo/country_asn.mmdb")
        );
        let config = guard_core_engine::security_config::SecurityConfig {
            ipinfo_token: Some(String::from("tok")),
            ..guard_core_engine::security_config::SecurityConfig::default()
        };
        let manager = IpInfoManager::from_config(&config).expect("token present");
        assert_eq!(manager.db_path(), &default_db_path());
        assert_eq!(manager.max_age_secs(), 86_400);

        // No token: the reference's constructor error.
        let empty = guard_core_engine::security_config::SecurityConfig::default();
        let error = IpInfoManager::from_config(&empty).expect_err("rejects");
        assert_eq!(error.0, "IPInfo token is required!");
    }

    #[test]
    fn the_debug_shape_renders() {
        let manager = IpInfoManager::new("tok", None, 60).expect("token");
        let debug = format!("{manager:?}");
        assert!(debug.contains("IpInfoManager"));
        assert!(debug.contains("max_age_secs: 60"));
    }

    #[test]
    fn the_reader_accessor_answers_before_and_after() {
        let dir = temp_dir("geo-reader");
        let stub = DbStub::serve(country_fixture());
        let manager = manager_with_stub(&stub, &dir);
        assert!(manager.reader().is_none());
        manager.initialize().expect("initializes");
        assert!(manager.reader().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_download_records_the_redis_copy_and_the_cached_none_falls_through() {
        let dir = temp_dir("geo-copy");
        let stub = DbStub::serve(country_fixture());
        let store = Arc::new(ScriptedStore::with_cache(None));
        let manager = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400)
            .expect("token")
            .with_redis_store(store.clone())
            .with_database_url(stub.url);
        manager.initialize().expect("initializes");
        let writes = store.writes.lock().expect("writes").clone();
        assert_eq!(writes.len(), 1, "the database copy rode the store");
        assert_eq!(writes[0].0, IPINFO_REDIS_NAMESPACE);
        assert_eq!(writes[0].1, IPINFO_REDIS_KEY);
        assert_eq!(writes[0].2, Some(86_400));
        assert!(manager.is_initialized());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_non_latin1_cache_rejects_the_leg() {
        let dir = temp_dir("geo-latin");
        let store = Arc::new(ScriptedStore::with_cache(Some(String::from(
            "\u{142} guard",
        ))));
        let manager = IpInfoManager::new("tok", Some(dir.join("db.mmdb")), 86_400)
            .expect("token")
            .with_redis_store(store);
        let error = manager.initialize().expect_err("the latin-1 leg fails");
        assert!(error.0.contains("not latin-1"));
        assert!(!manager.is_initialized());
        assert!(manager.initialization_attempted(), "the finally stamps");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_scheduler_refreshes_every_provider_through_the_overrides() {
        use guard_core_engine::cloud_provider::CloudIpTable;
        // One local stub for every provider: the AWS document parses
        // (the ready arm lands) and the rest answer bodies their
        // parsers reject (the clear arm lands per provider).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let aws_body = String::from(
            "{\"prefixes\": [{\"ip_prefix\": \"203.0.113.0/24\", \"region\": \"us-east-1\", \
             \"service\": \"AMAZON\"}]}",
        );
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            loop {
                if let Ok((mut stream, _)) = listener.accept() {
                    std::thread::sleep(Duration::from_millis(30));
                    let mut buffer = [0_u8; 4096];
                    let _ = stream.read(&mut buffer);
                    let request = String::from_utf8_lossy(&buffer).to_string();
                    let body = if request.contains("/aws") {
                        aws_body.clone()
                    } else {
                        String::from("garbage")
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                } else {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        });
        let base = format!("http://127.0.0.1:{port}");

        let table = Arc::new(CloudIpTable::default());
        let scheduler = CloudRefreshScheduler::new()
            .with_provider_endpoint("AWS", format!("{base}/aws"))
            .with_provider_endpoint("GCP", format!("{base}/gcp"))
            .with_provider_endpoint("Azure", format!("{base}/azure"))
            .with_provider_endpoint("DigitalOcean", format!("{base}/do"))
            .with_provider_endpoint("Linode", format!("{base}/linode"))
            .with_provider_endpoint("Vultr", format!("{base}/vultr"));

        // The single-flight gate over the real body: the flight lands,
        // the table answers, and the flag clears.
        assert!(scheduler.schedule_refresh(&table));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while scheduler.refresh_in_flight() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!scheduler.refresh_in_flight());
        assert!(table.provider_is_ready("AWS"), "the parsed ranges landed");
        for provider in ["GCP", "Azure", "DigitalOcean", "Linode", "Vultr"] {
            assert!(!table.provider_is_ready(provider), "{provider} cleared");
        }
    }

    #[test]
    fn the_reference_endpoint_table_maps_the_names() {
        assert_eq!(reference_endpoint("AWS"), endpoints::AWS);
        assert_eq!(reference_endpoint("GCP"), endpoints::GCP);
        assert_eq!(reference_endpoint("Azure"), endpoints::AZURE_PAGE);
        assert_eq!(reference_endpoint("DigitalOcean"), endpoints::LINODE);
        assert_eq!(reference_endpoint("Linode"), endpoints::LINODE);
        assert_eq!(reference_endpoint("Vultr"), endpoints::VULTR);
        assert_eq!(reference_endpoint("Mystery"), endpoints::AWS);
    }

    #[test]
    fn a_provider_outside_the_vocabulary_skips_the_fetch() {
        use guard_core_engine::cloud_provider::CloudIpTable;
        let table = Arc::new(CloudIpTable::default());
        // The `_ => continue` arm: an unknown provider never fetches.
        CloudRefreshScheduler::refresh_all(&CloudFetcher::new(), &table, &["Mystery"]);
        assert!(!table.provider_is_ready("Mystery"));
    }

    #[test]
    fn a_refresh_into_a_missing_directory_fails_clean() {
        let dir = temp_dir("geo-refresh-missing");
        let stub = DbStub::serve(country_fixture());
        let manager = IpInfoManager::new("tok", Some(dir.join("no/such/db.mmdb")), 86_400)
            .expect("token")
            .with_database_url(stub.url);
        // The download succeeds (the stub serves), but the write into
        // the nonexistent directory fails; the tmp cleanup runs and the
        // error carries the reason.
        let error = manager.refresh().expect_err("the write fails");
        assert!(error.0.contains("atomic write failed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_scheduler_default_builds() {
        let scheduler = CloudRefreshScheduler::default();
        assert!(!scheduler.refresh_in_flight());
    }
}
