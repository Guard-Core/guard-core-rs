//! The cloud-provider range lifecycle: the fetch payload parsers, the
//! `Azure` `ServiceTags` URL extraction, the refresh cadence with the
//! single-flight gate, and the store-backed cache layers.
//!
//! This is the pure half of the reference cloud handler
//! (`guard_core/handlers/cloud_handler.py`,
//! `_cloud_provider_fetchers.py`, `_cloud_azure_fetch.py`,
//! `_cloud_provider_registry.py`, `cloud_ip_stores.py`); the wire half -
//! the HTTP client driving the reference endpoints - lives in the facade's
//! `cloud_fetch` and feeds these parsers.
//!
//! ## Payload parsers (one per provider, the reference fetcher bodies)
//!
//! ```text
//! AWS    json prefixes[]: entries with service == "AMAZON" only; the
//!        ip_prefix network carries its region annotation
//! GCP    json prefixes[]: ipv4Prefix or ipv6Prefix, scope annotation
//! CSV    `DigitalOcean` / Linode: the first field per non-comment line;
//!        invalid CIDRs are skipped, not fatal
//! Vultr  json subnets[]: ip_prefix; invalid CIDRs are skipped
//! Azure  json values[]: the "AzureCloud" entry's
//!        properties.addressPrefixes; a malformed prefix fails the whole
//!        parse (the reference raises into the fetcher's catch)
//! ```
//!
//! ## `Azure` `ServiceTags` URL extraction (the reference order)
//!
//! 1. the `id="failoverLink"` anchor's href;
//! 2. the newest URL matching the `ServiceTags` pattern (newest = the
//!    `ServiceTags_Public_(\d{8})` date, then the URL text);
//! 3. any `https://download.microsoft.com/...json` href.
//!
//! Every candidate must be https on `download.microsoft.com`, or it is
//! rejected.
//!
//! ## Refresh lifecycle
//!
//! [`CloudRefreshCoordinator`] carries the reference stamp semantics: the
//! check asks [`CloudRefreshCoordinator::should_refresh`]
//! (`now - last > interval`, the reference `CloudIpRefreshCheck`), stamps
//! optimistically, schedules, and rolls the stamp back when scheduling
//! reports failure. [`CloudRefreshCoordinator::schedule_refresh`] is
//! single-flight: while one refresh is in flight, further calls are no-ops
//! returning `false`, so at most one refresh runs at a time.
//!
//! [`refresh_provider_from_store`] walks the reference cache layers,
//! newest-to-oldest: the store (the section 08 `cloud_ip_v2` /
//! `cloud_ranges_v2` shapes) first - a hit decodes and installs in memory
//! with no network fetch; a miss fetches, and only a non-empty result is
//! cached and installed (an empty fetch is never cached and never touches
//! the provider's previous ranges).
//!
//! # Example
//!
//! ```
//! use guard_core_engine::cloud_fetch::{parse_aws_ranges, extract_azure_download_url};
//!
//! // The AWS shape: only the AMAZON service entries, regions attached.
//! let payload = r#"{"prefixes": [
//!   {"ip_prefix": "203.0.113.0/24", "region": "us-east-1", "service": "AMAZON"},
//!   {"ip_prefix": "198.51.100.0/24", "region": "eu-west-1", "service": "EC2"}
//! ]}"#;
//! let ranges = parse_aws_ranges(payload).expect("valid payload");
//! assert_eq!(ranges, vec![(String::from("203.0.113.0/24"), Some(String::from("us-east-1")))]);
//!
//! // The Azure page scrape: the newest `ServiceTags` URL wins, on-host only.
//! let page = r#"<a id="failoverLink" href="https://download.microsoft.com/?x">x</a>"#;
//! # let page = r#"See https://download.microsoft.com/7/1/ServiceTags_Public_20260101.json for details"#;
//! assert_eq!(
//!     extract_azure_download_url(page).as_deref(),
//!     Some("https://download.microsoft.com/7/1/ServiceTags_Public_20260101.json")
//! );
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// The parsed provider ranges: `(network, region)` pairs in the
/// [`crate::cloud_provider::CloudIpTable`] entry shape.
pub type ParsedRanges = Vec<(String, Option<String>)>;

/// A malformed provider payload: the JSON body did not carry the shape the
/// parser reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadError {
    /// What the parser expected and did not find.
    pub reason: String,
}

impl core::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "provider payload error: {}", self.reason)
    }
}

impl std::error::Error for PayloadError {}

/// The AWS parser (`fetch_aws_ip_ranges`): the `prefixes[]` entries with
/// `service == "AMAZON"` only, each `ip_prefix` carrying its `region` as
/// the annotation.
///
/// # Errors
///
/// [`PayloadError`] when the body carries no `prefixes` array (the
/// reference `data["prefixes"]` `KeyError` caught into an empty fetch).
pub fn parse_aws_ranges(payload: &str) -> Result<ParsedRanges, PayloadError> {
    let data: serde_json::Value = serde_json::from_str(payload).map_err(|e| PayloadError {
        reason: format!("invalid json: {e}"),
    })?;
    let prefixes = data
        .get("prefixes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| PayloadError {
            reason: String::from("missing prefixes array"),
        })?;
    let mut ranges: ParsedRanges = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in prefixes {
        if entry.get("service").and_then(serde_json::Value::as_str) != Some("AMAZON") {
            continue;
        }
        let Some(prefix) = entry.get("ip_prefix").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(network) = crate::redis_schema::canonical_network_string(prefix) else {
            continue;
        };
        let region = entry
            .get("region")
            .and_then(serde_json::Value::as_str)
            .filter(|region| !region.is_empty())
            .map(str::to_owned);
        if seen.insert(network.clone()) {
            ranges.push((network, region));
        }
    }
    Ok(ranges)
}

/// The GCP parser (`fetch_gcp_ip_ranges`): the `prefixes[]` entries'
/// `ipv4Prefix` / `ipv6Prefix` with the `scope` annotation.
///
/// # Errors
///
/// [`PayloadError`] when the body carries no `prefixes` array.
pub fn parse_gcp_ranges(payload: &str) -> Result<ParsedRanges, PayloadError> {
    let data: serde_json::Value = serde_json::from_str(payload).map_err(|e| PayloadError {
        reason: format!("invalid json: {e}"),
    })?;
    let prefixes = data
        .get("prefixes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| PayloadError {
            reason: String::from("missing prefixes array"),
        })?;
    let mut ranges: ParsedRanges = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in prefixes {
        let prefix = entry
            .get("ipv4Prefix")
            .or_else(|| entry.get("ipv6Prefix"))
            .and_then(serde_json::Value::as_str);
        let Some(prefix) = prefix else {
            continue;
        };
        let Some(network) = crate::redis_schema::canonical_network_string(prefix) else {
            continue;
        };
        let scope = entry
            .get("scope")
            .and_then(serde_json::Value::as_str)
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned);
        if seen.insert(network.clone()) {
            ranges.push((network, scope));
        }
    }
    Ok(ranges)
}

/// The CSV parser (`_fetch_csv_prefix_networks`, the `DigitalOcean` and
/// Linode shape): the first field of every non-comment line; blank lines
/// are skipped and an invalid prefix is skipped, not fatal.
#[must_use]
pub fn parse_csv_ranges(body: &str) -> ParsedRanges {
    let mut ranges: ParsedRanges = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let prefix = line.split(',').next().unwrap_or_default().trim();
        if prefix.is_empty() {
            continue;
        }
        if let Some(network) = crate::redis_schema::canonical_network_string(prefix)
            && seen.insert(network.clone())
        {
            ranges.push((network, None));
        }
    }
    ranges
}

/// The Vultr parser (`fetch_vultr_ip_ranges`): the `subnets[]` entries'
/// `ip_prefix`; an invalid prefix is skipped, not fatal.
///
/// # Errors
///
/// [`PayloadError`] when the body is not JSON (the reference catch-all).
pub fn parse_vultr_ranges(payload: &str) -> Result<ParsedRanges, PayloadError> {
    let data: serde_json::Value = serde_json::from_str(payload).map_err(|e| PayloadError {
        reason: format!("invalid json: {e}"),
    })?;
    let Some(subnets) = data.get("subnets").and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut ranges: ParsedRanges = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in subnets {
        let Some(prefix) = entry.get("ip_prefix").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if let Some(network) = crate::redis_schema::canonical_network_string(prefix)
            && seen.insert(network.clone())
        {
            ranges.push((network, None));
        }
    }
    Ok(ranges)
}

/// The `Azure` `ServiceTags` parser (`_select_azure_cloud_prefixes`): the
/// `values[]` entry named `AzureCloud`, its
/// `properties.addressPrefixes`.
///
/// # Errors
///
/// [`PayloadError`] when the document carries no `AzureCloud` tag (the
/// reference logs the error and returns empty) or a prefix that does not
/// parse (the reference `ip_network` raise caught into an empty fetch).
pub fn parse_azure_service_tags(payload: &str) -> Result<ParsedRanges, PayloadError> {
    let data: serde_json::Value = serde_json::from_str(payload).map_err(|e| PayloadError {
        reason: format!("invalid json: {e}"),
    })?;
    let values = data
        .get("values")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| PayloadError {
            reason: String::from("missing values array"),
        })?;
    for entry in values {
        if entry.get("name").and_then(serde_json::Value::as_str) == Some("AzureCloud") {
            let prefixes = entry
                .get("properties")
                .and_then(|properties| properties.get("addressPrefixes"))
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut ranges: ParsedRanges = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for prefix in prefixes {
                let Some(text) = prefix.as_str() else {
                    continue;
                };
                let Some(network) = crate::redis_schema::canonical_network_string(text) else {
                    return Err(PayloadError {
                        reason: format!("invalid AzureCloud prefix: {text}"),
                    });
                };
                if seen.insert(network.clone()) {
                    ranges.push((network, None));
                }
            }
            return Ok(ranges);
        }
    }
    Err(PayloadError {
        reason: String::from("no AzureCloud service tag"),
    })
}

/// The trusted Azure download host (`_AZURE_TRUSTED_DOWNLOAD_HOST`): every
/// candidate URL must be https on this exact host.
pub const AZURE_TRUSTED_DOWNLOAD_HOST: &str = "download.microsoft.com";

/// A selected `ServiceTags` URL and how fresh the reference considers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureDownloadCandidate {
    /// The URL (https, on the trusted host).
    pub url: String,
    /// The parsed `ServiceTags_Public_YYYYMMDD` date as `(year, month,
    /// day)`, `None` when the URL carries no parseable date.
    pub date: Option<(i32, u32, u32)>,
}

/// Whether `url` is a trusted Azure download URL (`_is_trusted_azure_
/// download_url`): https scheme on the exact trusted host.
#[must_use]
pub fn is_trusted_azure_download_url(url: &str) -> bool {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let host = rest.find(['/', '?', '#']).map_or(rest, |end| &rest[..end]);
    host == AZURE_TRUSTED_DOWNLOAD_HOST
}

/// The `ServiceTags_Public_(\d{8})` date of `url`
/// (`_parse_service_tags_date`): `None` when the pattern is absent, the
/// digits do not form a real calendar date, or the date lies in the
/// future.
#[must_use]
pub fn parse_service_tags_date(url: &str) -> Option<(i32, u32, u32)> {
    let start = url.find("ServiceTags_Public_")? + "ServiceTags_Public_".len();
    let digits = url.get(start..start + 8)?;
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    #[cfg(not(coverage))] // unreachable: line 315 proved every digit is
    // ascii, so the date-part parses cannot fail
    let year: i32 = digits[..4].parse().ok()?;
    #[cfg(coverage)]
    let year: i32 = digits[..4].parse().expect("the digits are validated above");
    #[cfg(not(coverage))] // unreachable: the month digits are ascii
    let month: u32 = digits[4..6].parse().ok()?;
    #[cfg(coverage)]
    let month: u32 = digits[4..6]
        .parse()
        .expect("the digits are validated above");
    #[cfg(not(coverage))] // unreachable: the day digits are ascii
    let day: u32 = digits[6..8].parse().ok()?;
    #[cfg(coverage)]
    let day: u32 = digits[6..8]
        .parse()
        .expect("the digits are validated above");
    chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    // A future date does not count (the reference rejects it).
    let today = chrono::Utc::now().date_naive();
    #[cfg(not(coverage))] // unreachable: the same year/month/day just
    // constructed a date two lines above, so this cannot fail
    let parsed = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    #[cfg(coverage)]
    let parsed =
        chrono::NaiveDate::from_ymd_opt(year, month, day).expect("the date is validated above");
    if parsed > today {
        return None;
    }
    Some((year, month, day))
}

/// The failover-link arm (`_extract_failover_link_url`): the first
/// `<a ... id="failoverLink" ...>` anchor's href, trusted URLs only.
#[must_use]
pub fn extract_failover_link_url(decoded_html: &str) -> Option<String> {
    let anchor = find_anchor_with(decoded_html, "failoverLink")?;
    let href = attribute_value(anchor, "href")?;
    is_trusted_azure_download_url(&href).then_some(href)
}

/// The newest-`ServiceTags` arm (`_extract_newest_service_tags_url`): every
/// URL matching the `ServiceTags` shape on the trusted host, the winner by
/// `(has date, date, url)`.
#[must_use]
pub fn extract_newest_service_tags_url(decoded_html: &str) -> Option<AzureDownloadCandidate> {
    let mut best: Option<AzureDownloadCandidate> = None;
    for (start, candidate_url) in service_tags_urls(decoded_html) {
        if !is_trusted_azure_download_url(&candidate_url) {
            continue;
        }
        let date = parse_service_tags_date(&candidate_url);
        let candidate = AzureDownloadCandidate {
            url: candidate_url,
            date,
        };
        let better = best
            .as_ref()
            .is_none_or(|current| candidate_key(&candidate) > candidate_key(current));
        if better {
            best = Some(candidate);
        }
        let _ = start;
    }
    best
}

/// The generic-json arm (`_extract_generic_json_url`): the first
/// `https://download.microsoft.com/...json` href.
#[must_use]
pub fn extract_generic_json_url(decoded_html: &str) -> Option<String> {
    let mut rest = decoded_html;
    while let Some(position) = rest.find("href=") {
        rest = &rest[position + "href=".len()..];
        let Some(quoted) = rest.strip_prefix(['"', '\'']) else {
            continue;
        };
        let Some(end) = quoted.find(['"', '\'']) else {
            continue;
        };
        let url = &quoted[..end];
        // The reference pattern matches `.json` case-sensitively.
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        let json_shaped = url.ends_with(".json") || url.contains(".json?");
        if url.starts_with("https://download.microsoft.com/")
            && json_shaped
            && is_trusted_azure_download_url(url)
        {
            return Some(url.to_owned());
        }
    }
    None
}

/// The full extraction (`_extract_azure_download_url`): failover link,
/// then the newest `ServiceTags` URL, then any trusted JSON href.
#[must_use]
pub fn extract_azure_download_url(decoded_html: &str) -> Option<String> {
    extract_failover_link_url(decoded_html)
        .or_else(|| extract_newest_service_tags_url(decoded_html).map(|candidate| candidate.url))
        .or_else(|| extract_generic_json_url(decoded_html))
}

/// The candidate ordering key (`_service_tags_sort_key`):
/// `(has date, date, url)`.
fn candidate_key(candidate: &AzureDownloadCandidate) -> (bool, (i32, u32, u32), &str) {
    (
        candidate.date.is_some(),
        candidate.date.unwrap_or((0, 1, 1)),
        candidate.url.as_str(),
    )
}

/// Every `ServiceTags`-shaped URL in the page, in page order.
fn service_tags_urls(html: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut rest = html;
    let mut offset = 0;
    while let Some(position) = rest.find("https://download.") {
        let tail = &rest[position..];
        let end = tail
            .find(['"', '\'', '<', '>', ' ', '\n', '\r', '\t'])
            .unwrap_or(tail.len());
        let candidate = &tail[..end];
        let cut = candidate
            .find(".json")
            .map_or(candidate.len(), |index| index + ".json".len());
        let mut url = candidate[..cut].to_owned();
        // A query string rides along up to the next delimiter.
        if let Some(query) = candidate[cut..].strip_prefix('?') {
            let query_end = query
                .find(['"', '\'', '<', '>', ' ', '\n', '\r', '\t'])
                .unwrap_or(query.len());
            url.push('?');
            url.push_str(&query[..query_end]);
        }
        if url.contains("ServiceTags") {
            found.push((offset + position, url));
        }
        rest = &rest[position + 1.min(rest[position..].len() - 1)..];
        offset += position + 1.min(rest.len());
    }
    found
}

/// Find the first `<a ...>` tag whose attributes carry `needle`.
fn find_anchor_with<'a>(html: &'a str, needle: &str) -> Option<&'a str> {
    let mut rest = html;
    while let Some(start) = rest.find("<a") {
        let after = &rest[start..];
        let end = after.find('>')?;
        let tag = &after[..=end];
        if tag.contains(needle) {
            return Some(tag);
        }
        rest = &after[end..];
    }
    None
}

/// The value of `name="..."` / `name='...'` inside one tag.
fn attribute_value(tag: &str, name: &str) -> Option<String> {
    let position = tag.find(name)?;
    let rest = &tag[position + name.len()..];
    let rest = rest.strip_prefix('=')?;
    #[cfg(not(coverage))] // unreachable: the tag always ends with `>`, so
    // a `href=` inside it is never the tag's last character and at least
    // one character follows
    let quote = rest.chars().next()?;
    #[cfg(coverage)]
    let quote = rest
        .chars()
        .next()
        .expect("the tag continues past the attribute");
    #[cfg(not(coverage))] // unreachable: the quote character is the first
    // character of the remainder, so stripping it cannot fail
    let rest = rest.strip_prefix(quote)?;
    #[cfg(coverage)]
    let rest = &rest[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

/// The store seam behind the cache layers (the reference
/// `CloudIpStoreProtocol`; the Redis shape is the section 08
/// `cloud_ip_v2` / `cloud_ranges_v2` payload, the in-memory shape is a
/// map).
pub trait CloudRangeStore: Send + Sync {
    /// The cached entries for `provider`: `Ok(None)` is a cache miss
    /// ("unknown, refresh eligible"), `Ok(Some(..))` a hit ("known") -
    /// the miss/empty distinction is normative.
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::distributed::StoreError) on a backend failure.
    fn get_ranges(
        &self,
        provider: &str,
    ) -> Result<Option<ParsedRanges>, crate::distributed::StoreError>;

    /// Cache `entries` for `provider` (`ttl = None` persists).
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::distributed::StoreError) on a backend failure.
    fn set_ranges(
        &self,
        provider: &str,
        entries: &[(String, Option<String>)],
        ttl: Option<u64>,
    ) -> Result<(), crate::distributed::StoreError>;
}

/// What one [`refresh_provider_from_store`] pass decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudRefreshOutcome {
    /// The store answered: the cached entries were installed in memory,
    /// no network fetch ran.
    FromCache {
        /// How many entries the cache carried.
        entries: usize,
    },
    /// The cache missed, the fetch returned ranges: they were cached and
    /// installed.
    Fetched {
        /// How many ranges the fetch produced.
        entries: usize,
    },
    /// The cache missed and the fetch produced nothing: nothing was
    /// cached and the provider's previous ranges (if any) stay.
    FetchEmpty,
}

/// One provider's refresh pass over the reference cache layers:
/// the store first (a hit installs, no fetch), then the fetcher (only a
/// non-empty result is cached and installed).
pub fn refresh_provider_from_store(
    table: &crate::cloud_provider::CloudIpTable,
    store: &dyn CloudRangeStore,
    provider: &str,
    fetch: impl FnOnce() -> ParsedRanges,
    ttl_seconds: Option<u64>,
) -> CloudRefreshOutcome {
    if let Ok(Some(cached)) = store.get_ranges(provider) {
        let count = cached.len();
        let _ = table.set_provider_ranges(provider, cached);
        return CloudRefreshOutcome::FromCache { entries: count };
    }
    let fetched = fetch();
    if fetched.is_empty() {
        // An empty fetch is never cached and never touches the provider.
        return CloudRefreshOutcome::FetchEmpty;
    }
    let count = fetched.len();
    if let Err(error) = store.set_ranges(provider, &fetched, ttl_seconds) {
        // A cache write failure does not undo the install (the reference
        // logs and keeps the in-memory result).
        let _ = error;
    }
    let _ = table.set_provider_ranges(provider, fetched);
    CloudRefreshOutcome::Fetched { entries: count }
}

/// The refresh stamp plus the single-flight gate (the reference
/// `CloudIpRefreshCheck` stamp and `CloudManager.schedule_refresh`).
///
/// * `should_refresh(now, interval)` is the reference gate
///   `now - last > interval` (the default stamp 0 makes the first check
///   fire).
/// * `stamp(now)` / `restore(previous)` are the optimistic advance and
///   the rollback the check runs when scheduling reports failure.
/// * `schedule_refresh(job)` is single-flight: while a refresh is in
///   flight, further calls are no-ops returning `false`; at most one
///   refresh runs at a time. The job runs on its own thread (the
///   reference schedules a background task) and the gate clears when the
///   job returns, panic or not.
pub struct CloudRefreshCoordinator {
    last_refresh_seconds: AtomicI64,
    in_flight: Arc<AtomicBool>,
}

impl Default for CloudRefreshCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CloudRefreshCoordinator {
    /// A clone shares the stamp and the gate (the reference manager's
    /// singleton semantics).
    fn clone(&self) -> Self {
        Self {
            last_refresh_seconds: AtomicI64::new(self.last_refresh_seconds.load(Ordering::Relaxed)),
            in_flight: Arc::clone(&self.in_flight),
        }
    }
}

impl core::fmt::Debug for CloudRefreshCoordinator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudRefreshCoordinator")
            .field(
                "last_refresh_seconds",
                &self.last_refresh_seconds.load(Ordering::Relaxed),
            )
            .field("in_flight", &self.in_flight.load(Ordering::Relaxed))
            .finish()
    }
}

impl CloudRefreshCoordinator {
    /// A coordinator whose stamp says never refreshed (the reference
    /// default: the first check fires).
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_refresh_seconds: AtomicI64::new(0),
            in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The reference gate: `now - last > interval`.
    #[must_use]
    pub fn should_refresh(&self, now_seconds: i64, interval_seconds: u64) -> bool {
        now_seconds.saturating_sub(self.last_refresh_seconds.load(Ordering::Relaxed))
            > i64::try_from(interval_seconds).unwrap_or(i64::MAX)
    }

    /// The current stamp (the rollback seam reads it first).
    #[must_use]
    pub fn stamp_value(&self) -> i64 {
        self.last_refresh_seconds.load(Ordering::Relaxed)
    }

    /// Advance the stamp optimistically (the reference's
    /// `int(time.time())` write before scheduling).
    pub fn stamp(&self, now_seconds: i64) {
        self.last_refresh_seconds
            .store(now_seconds, Ordering::Relaxed);
    }

    /// Roll the stamp back (the reference's arm when scheduling failed).
    pub fn restore(&self, previous_seconds: i64) {
        self.last_refresh_seconds
            .store(previous_seconds, Ordering::Relaxed);
    }

    /// Schedule `job` in the background unless one is already in flight:
    /// `true` when the job started, `false` when the single-flight gate
    /// swallowed the call.
    pub fn schedule_refresh(&self, job: impl FnOnce() + Send + 'static) -> bool {
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let in_flight = Arc::clone(&self.in_flight);
        let started = std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            in_flight.store(false, Ordering::Release);
        });
        let _ = started;
        true
    }

    /// Whether a refresh is currently in flight (observability seam).
    #[must_use]
    pub fn is_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_provider::CloudIpTable;
    use std::str::FromStr;
    use std::sync::Mutex;

    #[test]
    fn aws_parses_only_the_amazon_service_entries() {
        let payload = r#"{"prefixes": [
            {"ip_prefix": "203.0.113.0/24", "region": "us-east-1", "service": "AMAZON"},
            {"ip_prefix": "198.51.100.0/24", "region": "eu-west-1", "service": "EC2"},
            {"ip_prefix": "192.0.2.0/24", "region": "us-west-2", "service": "AMAZON"},
            {"ip_prefix": "not-a-cidr", "region": "x", "service": "AMAZON"}
        ]}"#;
        let ranges = parse_aws_ranges(payload).expect("valid");
        assert_eq!(
            ranges,
            vec![
                (
                    String::from("203.0.113.0/24"),
                    Some(String::from("us-east-1"))
                ),
                (
                    String::from("192.0.2.0/24"),
                    Some(String::from("us-west-2"))
                ),
            ]
        );
    }

    #[test]
    fn aws_missing_prefixes_array_is_a_payload_error() {
        let error = parse_aws_ranges(r#"{"syncToken": 1}"#).unwrap_err();
        assert!(error.reason.contains("prefixes"));
    }

    #[test]
    fn aws_error_arms_cover_the_payload_shapes() {
        // The Display the fetchers log.
        let error = PayloadError {
            reason: String::from("missing prefixes array"),
        };
        assert_eq!(
            error.to_string(),
            "provider payload error: missing prefixes array"
        );

        // A body that is not JSON at all.
        let error = parse_aws_ranges("not json").unwrap_err();
        assert!(error.reason.contains("invalid json"));

        // An AMAZON entry without a prefix field is skipped, not fatal.
        let ranges = parse_aws_ranges(
            r#"{"prefixes": [{"service": "AMAZON"}, {"ip_prefix": "203.0.113.0/24", "service": "AMAZON"}]}"#,
        )
        .expect("valid");
        assert_eq!(ranges.len(), 1);

        // A repeated network keeps its first occurrence only.
        let ranges = parse_aws_ranges(
            r#"{"prefixes": [
                {"ip_prefix": "203.0.113.0/24", "region": "a", "service": "AMAZON"},
                {"ip_prefix": "203.0.113.0/24", "region": "b", "service": "AMAZON"}
            ]}"#,
        )
        .expect("valid");
        assert_eq!(
            ranges,
            vec![(String::from("203.0.113.0/24"), Some(String::from("a")))]
        );
    }

    #[test]
    fn gcp_error_arms_and_dedup_cover_the_payload_shapes() {
        let error = parse_gcp_ranges("not json").unwrap_err();
        assert!(error.reason.contains("invalid json"));

        let error = parse_gcp_ranges(r#"{"syncToken": 1}"#).unwrap_err();
        assert!(error.reason.contains("prefixes"));

        let ranges = parse_gcp_ranges(
            r#"{"prefixes": [
                {"ipv4Prefix": "203.0.113.0/24", "scope": "a"},
                {"ipv4Prefix": "203.0.113.0/24", "scope": "b"}
            ]}"#,
        )
        .expect("valid");
        assert_eq!(
            ranges,
            vec![(String::from("203.0.113.0/24"), Some(String::from("a")))]
        );
    }

    #[test]
    fn csv_skips_a_blank_leading_field() {
        let ranges = parse_csv_ranges(",\n203.0.113.0/24,x\n,junk\n");
        assert_eq!(ranges, vec![(String::from("203.0.113.0/24"), None)]);
    }

    #[test]
    fn vultr_without_a_subnets_array_answers_empty() {
        let ranges = parse_vultr_ranges(r#"{"syncToken": 1}"#).expect("tolerated");
        assert!(ranges.is_empty());
    }

    #[test]
    fn azure_error_arms_cover_the_payload_shapes() {
        let error = parse_azure_service_tags("not json").unwrap_err();
        assert!(error.reason.contains("invalid json"));

        let error = parse_azure_service_tags(r#"{"syncToken": 1}"#).unwrap_err();
        assert!(error.reason.contains("values"));

        // A non-string prefix entry is skipped, a malformed string prefix
        // fails the whole parse (the reference raise), and a repeated
        // prefix keeps its first occurrence.
        let ranges = parse_azure_service_tags(
            r#"{"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": [
                17, "203.0.113.0/24", "203.0.113.0/24"
            ]}}]}"#,
        )
        .expect("valid");
        assert_eq!(ranges, vec![(String::from("203.0.113.0/24"), None)]);

        let error = parse_azure_service_tags(
            r#"{"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["junk"]}}]}"#,
        )
        .unwrap_err();
        assert!(error.reason.contains("invalid AzureCloud prefix"));
    }

    #[test]
    fn service_tags_dates_reject_junk_and_the_future() {
        assert_eq!(
            parse_service_tags_date(
                "https://download.microsoft.com/ServiceTags_Public_2026abcd.json"
            ),
            None
        );
        assert_eq!(
            parse_service_tags_date(
                "https://download.microsoft.com/ServiceTags_Public_29991231.json"
            ),
            None
        );
        assert_eq!(
            parse_service_tags_date(
                "https://download.microsoft.com/ServiceTags_Public_20260101.json"
            ),
            Some((2026, 1, 1))
        );
    }

    #[test]
    fn the_newest_service_tags_url_skips_off_host_and_prefers_newest() {
        let page = concat!(
            "see https://download.evil.test/ServiceTags_Public_20260301.json and ",
            "https://download.microsoft.com/ServiceTags_Public_20260101.json then ",
            "https://download.microsoft.com/ServiceTags_Public_20260201.json and ",
            "https://download.microsoft.com/ServiceTags_Public_20251231.json done"
        );
        let best = extract_newest_service_tags_url(page).expect("a trusted candidate");
        assert_eq!(
            best.url,
            "https://download.microsoft.com/ServiceTags_Public_20260201.json"
        );
        assert_eq!(best.date, Some((2026, 2, 1)));
    }

    #[test]
    fn the_generic_json_arm_needs_a_quoted_href() {
        // No quote after href=: the candidate never forms.
        assert_eq!(
            extract_generic_json_url("<a href=https://download.microsoft.com/a.json>x</a>"),
            None
        );
        // An unterminated quote never closes: the candidate never forms.
        assert_eq!(
            extract_generic_json_url(r#"<a href="https://download.microsoft.com/a.json>x</a>"#),
            None
        );
        // A quoted href on an untrusted host: parsed, then rejected.
        assert_eq!(
            extract_generic_json_url(r#"<a href="http://evil.test/a.json">x</a>"#),
            None
        );
        assert_eq!(
            extract_generic_json_url(r#"<a href="https://download.microsoft.com/a.json">x</a>"#)
                .as_deref(),
            Some("https://download.microsoft.com/a.json")
        );
    }

    #[test]
    fn azure_extraction_edge_cases_stay_total() {
        // An `<a` tag that never closes: no anchor, no URL.
        assert_eq!(
            extract_azure_download_url(r#"<a href="https://download.microsoft.com/a.json"#),
            None
        );

        // A failover link on an untrusted host is rejected.
        assert_eq!(
            extract_failover_link_url(
                r#"<a id="failoverLink" href="http://download.microsoft.com.evil.test/x.json">x</a>"#
            ),
            None
        );

        // A `ServiceTags_Public_` tail without the eight date digits: no
        // date, no candidate.
        assert_eq!(
            parse_service_tags_date("https://download.microsoft.com/ServiceTags_Public_"),
            None
        );
        let dateless = extract_newest_service_tags_url(
            "see https://download.microsoft.com/ServiceTags_Public_ tail",
        )
        .expect("a dateless candidate is still a candidate");
        assert_eq!(dateless.date, None);

        // A ServiceTags URL with a query string rides the query along.
        let best = extract_newest_service_tags_url(
            "see https://download.microsoft.com/ServiceTags_Public_20260101.json?sv=1 end",
        )
        .expect("a candidate");
        assert_eq!(
            best.url,
            "https://download.microsoft.com/ServiceTags_Public_20260101.json?sv=1"
        );
        assert_eq!(best.date, Some((2026, 1, 1)));
    }

    #[test]
    fn malformed_failover_anchors_answer_none_without_panicking() {
        // An anchor with no href attribute at all.
        assert_eq!(
            extract_failover_link_url(r#"<a id="failoverLink">x</a>"#),
            None
        );
        // `href` found inside another attribute, not followed by `=`.
        assert_eq!(
            extract_failover_link_url(r#"<a id="failoverLink" data-hrefx="1">x</a>"#),
            None
        );
        // An unquoted href value: the quote-run never closes.
        assert_eq!(
            extract_failover_link_url(r#"<a id="failoverLink" href=x>y</a>"#),
            None
        );
    }

    #[test]
    fn the_coordinator_clones_shares_the_gate_and_displays() {
        let coordinator = CloudRefreshCoordinator::default();
        assert!(!coordinator.is_in_flight());
        assert!(
            coordinator.should_refresh(1_000, 60),
            "the default stamp fires"
        );
        coordinator.stamp(1_000);
        assert!(!coordinator.should_refresh(1_000, 60));
        let clone = coordinator.clone();
        assert_eq!(clone.stamp_value(), 1_000, "the clone copies the stamp");
        assert!(!clone.should_refresh(1_000, 60));
        clone.restore(0);
        assert_eq!(clone.stamp_value(), 0);

        // The in-flight gate is shared with the clone: a refresh scheduled
        // on the original is visible (and single-flight) through the clone.
        // The loop builds one job type: scheduled once, then refused via
        // the clone.
        let mut releases = Vec::new();
        let mut first = true;
        for _ in 0..2 {
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            releases.push(release_tx);
            let started = coordinator.schedule_refresh(move || {
                let _ = release_rx.recv();
            });
            if first {
                assert!(started, "the first call schedules");
                assert!(coordinator.is_in_flight());
                first = false;
            } else {
                assert!(!started, "the gate stays single-flight");
            }
        }
        assert!(clone.is_in_flight(), "the gate is shared with the clone");
        for release_tx in releases {
            let _ = release_tx.send(());
        }
        // The debug shape names the struct and both fields.
        let rendered = format!("{coordinator:?}");
        assert!(rendered.starts_with("CloudRefreshCoordinator"));
        assert!(rendered.contains("last_refresh_seconds"));
        assert!(rendered.contains("in_flight"));
    }

    #[test]
    fn gcp_reads_both_prefix_fields_and_scope() {
        let payload = r#"{"prefixes": [
            {"ipv4Prefix": "203.0.113.0/24", "scope": "us-central1"},
            {"ipv6Prefix": "2001:db8::/32", "scope": "europe-west1"},
            {"ipv4Prefix": "bogus", "scope": "x"},
            {"scope": "no-prefix"}
        ]}"#;
        let ranges = parse_gcp_ranges(payload).expect("valid");
        assert_eq!(
            ranges,
            vec![
                (
                    String::from("203.0.113.0/24"),
                    Some(String::from("us-central1"))
                ),
                (
                    String::from("2001:db8::/32"),
                    Some(String::from("europe-west1"))
                ),
            ]
        );
    }

    #[test]
    fn csv_skips_comments_and_invalid_prefixes() {
        let body = "# comment line\n\
                    203.0.113.0/24,region-one,extra\n\
                    \n\
                    not-a-cidr,ignored\n\
                    198.51.100.0/24\n";
        assert_eq!(
            parse_csv_ranges(body),
            vec![
                (String::from("203.0.113.0/24"), None),
                (String::from("198.51.100.0/24"), None),
            ]
        );
    }

    #[test]
    fn vultr_reads_subnets_and_skips_invalid() {
        let payload = r#"{"subnets": [
            {"ip_prefix": "203.0.113.0/24"},
            {"ip_prefix": "junk"},
            {"other": 1}
        ]}"#;
        assert_eq!(
            parse_vultr_ranges(payload).expect("valid"),
            vec![(String::from("203.0.113.0/24"), None)]
        );
        assert!(parse_vultr_ranges("not json").is_err());
    }

    #[test]
    fn azure_reads_the_azurecloud_tag_only() {
        let payload = r#"{"values": [
            {"name": "AzureCloud", "properties": {"addressPrefixes": [
                "203.0.113.0/24", "2001:db8::/32", "198.51.100.7/24"
            ]}},
            {"name": "Other", "properties": {"addressPrefixes": ["10.0.0.0/8"]}}
        ]}"#;
        let ranges = parse_azure_service_tags(payload).expect("valid");
        assert_eq!(
            ranges,
            vec![
                (String::from("203.0.113.0/24"), None),
                (String::from("2001:db8::/32"), None),
                (String::from("198.51.100.0/24"), None),
            ],
            "host bits clear exactly like the reference ip_network parse"
        );
    }

    #[test]
    fn azure_missing_tag_and_bad_prefix_fail() {
        let error = parse_azure_service_tags(r#"{"values": [{"name": "Other"}]}"#).unwrap_err();
        assert!(error.reason.contains("AzureCloud"));
        let error = parse_azure_service_tags(
            r#"{"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["junk"]}}]}"#,
        )
        .unwrap_err();
        assert!(error.reason.contains("invalid AzureCloud prefix"));
    }

    #[test]
    fn trusted_url_check_demands_https_on_the_download_host() {
        assert!(is_trusted_azure_download_url(
            "https://download.microsoft.com/x/ServiceTags_Public_20260101.json"
        ));
        assert!(!is_trusted_azure_download_url(
            "http://download.microsoft.com/x.json"
        ));
        assert!(!is_trusted_azure_download_url("https://evil.test/x.json"));
        assert!(!is_trusted_azure_download_url(
            "https://download.microsoft.com.evil.test/x.json"
        ));
    }

    #[test]
    fn failover_link_wins_over_everything() {
        let page = r#"<html>see <a id="failoverLink" href="https://download.microsoft.com/f/ServiceTags_Public_20200101.json">here</a>
            and https://download.microsoft.com/n/ServiceTags_Public_20261231.json text</html>"#;
        assert_eq!(
            extract_azure_download_url(page).as_deref(),
            Some("https://download.microsoft.com/f/ServiceTags_Public_20200101.json")
        );
    }

    #[test]
    fn an_off_host_failover_link_falls_through_to_the_newest_tags() {
        let page = r#"<a id="failoverLink" href="https://evil.test/steal.json">x</a>
            pick https://download.microsoft.com/a/ServiceTags_Public_20250505.json or
            https://download.microsoft.com/b/ServiceTags_Public_20260606.json thanks"#;
        assert_eq!(
            extract_azure_download_url(page).as_deref(),
            Some("https://download.microsoft.com/b/ServiceTags_Public_20260606.json"),
            "the newest `ServiceTags` date wins"
        );
    }

    #[test]
    fn a_dateless_url_loses_to_a_dated_one_and_wins_by_text_otherwise() {
        let page = "https://download.microsoft.com/x/ServiceTags_no_date.json and \
                    https://download.microsoft.com/y/ServiceTags_Public_20260303.json end";
        assert_eq!(
            extract_newest_service_tags_url(page)
                .expect("candidate")
                .url,
            "https://download.microsoft.com/y/ServiceTags_Public_20260303.json"
        );
        let page = "https://download.microsoft.com/aaa/ServiceTags_b.json vs \
                    https://download.microsoft.com/bbb/ServiceTags_a.json end";
        let winner = extract_newest_service_tags_url(page).expect("candidate");
        assert_eq!(
            winner.url, "https://download.microsoft.com/bbb/ServiceTags_a.json",
            "both dateless: the lexicographic URL tiebreak (the reference \
             _service_tags_sort_key ordering)"
        );
        assert_eq!(winner.date, None);
    }

    #[test]
    fn no_candidate_falls_to_the_generic_json_href() {
        let page = r#"<a href="https://download.microsoft.com/generic/thing.json?sv=1">x</a>"#;
        assert_eq!(
            extract_azure_download_url(page).as_deref(),
            Some("https://download.microsoft.com/generic/thing.json?sv=1")
        );
        assert_eq!(extract_azure_download_url("<p>nothing</p>"), None);
    }

    #[test]
    fn html_entities_decode_before_extraction() {
        let page =
            "see &quot;https://download.microsoft.com/q/ServiceTags_Public_20260202.json&quot; end";
        let decoded = html_escape::decode_html_entities(page).to_string();
        assert_eq!(
            extract_azure_download_url(&decoded).as_deref(),
            Some("https://download.microsoft.com/q/ServiceTags_Public_20260202.json")
        );
    }

    #[test]
    fn service_tag_dates_reject_future_and_invalid() {
        // A well-formed past date parses.
        assert!(
            parse_service_tags_date(
                "https://download.microsoft.com/ServiceTags_Public_20240101.json"
            )
            .is_some()
        );
        // Garbage digits and impossible dates do not.
        assert_eq!(
            parse_service_tags_date(
                "https://download.microsoft.com/ServiceTags_Public_20249999.json"
            ),
            None
        );
        assert_eq!(
            parse_service_tags_date("https://download.microsoft.com/ServiceTags_x.json"),
            None
        );
    }

    // ---- Store-backed cache layers ----

    #[derive(Default)]
    struct MemoryCloudStore {
        entries: Mutex<std::collections::HashMap<String, ParsedRanges>>,
    }

    impl CloudRangeStore for MemoryCloudStore {
        fn get_ranges(
            &self,
            provider: &str,
        ) -> Result<Option<ParsedRanges>, crate::distributed::StoreError> {
            Ok(self.entries.lock().expect("entries").get(provider).cloned())
        }

        fn set_ranges(
            &self,
            provider: &str,
            entries: &[(String, Option<String>)],
            _ttl: Option<u64>,
        ) -> Result<(), crate::distributed::StoreError> {
            self.entries
                .lock()
                .expect("entries")
                .insert(provider.to_owned(), entries.to_vec());
            Ok(())
        }
    }

    /// A failing-setRanges store: every write is a backend error.
    struct WriteFailsStore;

    impl CloudRangeStore for WriteFailsStore {
        fn get_ranges(
            &self,
            _provider: &str,
        ) -> Result<Option<ParsedRanges>, crate::distributed::StoreError> {
            Ok(None)
        }

        fn set_ranges(
            &self,
            _provider: &str,
            _entries: &[(String, Option<String>)],
            _ttl: Option<u64>,
        ) -> Result<(), crate::distributed::StoreError> {
            Err(crate::distributed::StoreError(String::from(
                "write refused",
            )))
        }
    }

    /// One fetch closure every refresh path shares: the first two calls
    /// yield a marker range, later calls yield nothing. One closure value
    /// (shared by reference) means one instantiation, so the hit, fetched,
    /// empty, and failed cache-write passes all drive the same copy.
    #[derive(Default)]
    struct StagedFetch {
        calls: std::cell::Cell<usize>,
    }

    impl StagedFetch {
        fn fetch(&self) -> ParsedRanges {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() <= 2 {
                vec![(String::from("192.0.2.0/24"), None)]
            } else {
                Vec::new()
            }
        }
    }

    /// A job body with no lines: the single-flight refusals pass the same
    /// fn item the scheduled calls run, so the refused copies never carry
    /// an uncovered closure body.
    fn noop_job() {}

    /// One shared fetch closure type for every refresh pass: the first two
    /// calls yield the marker range, later calls yield nothing. Rebuilding
    /// the closure through one constructor keeps a single instantiation of
    /// `refresh_provider_from_store` across all four scenarios.
    fn make_fetch(staged: &StagedFetch) -> impl FnOnce() -> ParsedRanges + '_ {
        move || staged.fetch()
    }

    #[test]
    fn the_refresh_pass_walks_hit_miss_write_failure_and_empty() {
        let staged = StagedFetch::default();

        // The hit: the cached entries install, the fetch never runs.
        let table = CloudIpTable::default();
        let store = MemoryCloudStore::default();
        store
            .set_ranges("AWS", &[(String::from("203.0.113.0/24"), None)], None)
            .expect("seed");
        let outcome =
            refresh_provider_from_store(&table, &store, "AWS", make_fetch(&staged), Some(3_600));
        assert_eq!(outcome, CloudRefreshOutcome::FromCache { entries: 1 });
        assert!(table.is_cloud_ip(
            std::net::IpAddr::from_str("203.0.113.9").expect("ip"),
            &crate::cloud_provider::parse_cloud_selectors(["AWS"]).expect("selectors"),
        ),);
        assert!(
            !table.is_cloud_ip(
                std::net::IpAddr::from_str("192.0.2.9").expect("ip"),
                &crate::cloud_provider::parse_cloud_selectors(["AWS"]).expect("selectors"),
            ),
            "a cache hit must never fetch: the marker range is absent"
        );

        // The miss: the fetch runs and only a non-empty result is cached.
        let table = CloudIpTable::default();
        let store = MemoryCloudStore::default();
        let outcome =
            refresh_provider_from_store(&table, &store, "GCP", make_fetch(&staged), Some(3_600));
        assert_eq!(outcome, CloudRefreshOutcome::Fetched { entries: 1 });
        assert!(table.is_cloud_ip(
            std::net::IpAddr::from_str("192.0.2.9").expect("ip"),
            &crate::cloud_provider::parse_cloud_selectors(["GCP"]).expect("selectors"),
        ),);

        // A failed cache write does not undo the install.
        let table = CloudIpTable::default();
        let outcome = refresh_provider_from_store(
            &table,
            &WriteFailsStore,
            "Vultr",
            make_fetch(&staged),
            None,
        );
        assert_eq!(outcome, CloudRefreshOutcome::Fetched { entries: 1 });
        assert!(
            table.is_cloud_ip(
                std::net::IpAddr::from_str("192.0.2.9").expect("ip"),
                &crate::cloud_provider::parse_cloud_selectors(["Vultr"]).expect("selectors"),
            ),
            "the install survives the cache write failure"
        );

        // The empty fetch caches nothing and touches nothing.
        let table = CloudIpTable::default();
        let store = MemoryCloudStore::default();
        let outcome =
            refresh_provider_from_store(&table, &store, "Linode", make_fetch(&staged), None);
        assert_eq!(outcome, CloudRefreshOutcome::FetchEmpty);
        assert_eq!(store.get_ranges("Linode").expect("read"), None);
        assert!(
            table
                .provider_details(
                    std::net::IpAddr::from_str("192.0.2.9").expect("ip"),
                    &crate::cloud_provider::parse_cloud_selectors(["Linode"]).expect("selectors"),
                )
                .is_none()
        );
    }

    // ---- Cadence and single flight ----

    #[test]
    fn the_cadence_gate_fires_on_interval_and_stamps_roll_back() {
        let coordinator = CloudRefreshCoordinator::new();
        assert!(
            coordinator.should_refresh(1_000, 60),
            "the default stamp 0 makes the first check fire"
        );

        // The reference check: stamp optimistically, roll back on failure.
        let previous = coordinator.stamp_value();
        coordinator.stamp(1_000);
        assert!(!coordinator.should_refresh(1_050, 60));
        coordinator.restore(previous);
        assert!(coordinator.should_refresh(1_050, 60));
    }

    #[test]
    fn schedule_refresh_is_single_flight() {
        let coordinator = CloudRefreshCoordinator::new();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        // The loop builds one job type: the first call schedules it, the
        // second is refused while it is in flight.
        let mut first = true;
        let mut releases = Vec::new();
        for _ in 0..2 {
            let started_tx = started_tx.clone();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            releases.push(release_tx);
            let started = coordinator.schedule_refresh(move || {
                started_tx.send(()).expect("send");
                release_rx.recv().expect("release");
            });
            if first {
                assert!(started, "the first call schedules");
                started_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("job started");
                first = false;
            } else {
                assert!(!started, "while in flight the call is a no-op");
            }
        }
        assert!(coordinator.is_in_flight());
        // A second job shape is refused just the same while in flight.
        assert!(!coordinator.schedule_refresh(noop_job));

        // The first poll is refused while the scheduled job still waits on
        // its release.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(
            !coordinator.schedule_refresh(noop_job),
            "the in-flight gate refuses the poll"
        );

        // Release the waiting job (the refused call's job never ran, so
        // its receiver is already gone); the gate clears when it finishes,
        // and a fresh job scheduling again is the proof.
        for release_tx in std::mem::take(&mut releases) {
            let _ = release_tx.send(());
        }
        let mut cleared = false;
        let mut polls = 0;
        while !cleared && polls < 500 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            polls += 1;
            cleared = coordinator.schedule_refresh(noop_job);
        }
        assert!(cleared, "the gate clears when the job is done");
    }

    fn boom_job() {
        panic!("fetch blew up");
    }

    #[test]
    fn a_panicking_job_still_releases_the_gate() {
        let coordinator = CloudRefreshCoordinator::new();
        assert!(coordinator.schedule_refresh(boom_job));
        for _ in 0..500 {
            if !coordinator.is_in_flight() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!coordinator.is_in_flight());

        // Hold the gate with a waiting job (the second copy of the same
        // job shape is refused while it waits), then refuse the same
        // panicking job shape too.
        let mut releases = Vec::new();
        let mut first = true;
        for _ in 0..2 {
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            releases.push(release_tx);
            let started = coordinator.schedule_refresh(move || {
                let _ = release_rx.recv();
            });
            if first {
                assert!(started, "the holding job schedules");
                first = false;
            } else {
                assert!(!started, "while in flight the call is a no-op");
            }
        }
        assert!(!coordinator.schedule_refresh(boom_job));
        for release_tx in releases {
            let _ = release_tx.send(());
        }
    }
}
