//! The Redis key schema (spec section 08, interop): every key pattern,
//! every value format, and the ban-key migration, byte-compatible with the
//! Go and Python family ports.
//!
//! A Rust deployment pointed at the same Redis as a Python guard-core or a
//! Go port MUST interoperate byte-for-byte: shared bans, shared counters,
//! shared caches. This module is the pure half - the key builders and the
//! value codecs; the wire half lives in the facade's `redis_store` (the
//! `redis` feature), which drives these shapes over a real connection.
//!
//! ## Key namespace
//!
//! Every key is `prefix + namespace + ":" + key` (plain concatenation, no
//! normalization; the namespace itself may carry `:` and so may the inner
//! key). The default prefix is `guard_core:`. `sha256hex(x)` is the
//! lowercase hex SHA-256 of the UTF-8 encoding ([`identity_hash`]).
//!
//! | Pattern | Type | Builder |
//! |---|---|---|
//! | `{P}rate_limit:rate:{ip}` | zset | [`crate::distributed::rate_window_key`] |
//! | `{P}rate_limit:rate:{ip}:{sha256hex(path)}` | zset | [`crate::distributed::rate_window_key_endpoint`] |
//! | `{P}banned_ips:{ip}` | string | [`crate::distributed::ban_key`] |
//! | `{P}banned_networks:{cidr}` | string | [`ban_network_key`] |
//! | `{P}behavior_usage:behavior:usage:{sha256hex(endpoint)}:{sha256hex(ip)}` | zset | [`behavior_usage_key`] |
//! | `{P}behavior_returns:behavior:return:{sha256hex(endpoint)}:{sha256hex(ip)}:{sha256hex(pattern)}` | zset | [`behavior_return_key`] |
//! | `{P}security_headers:csp_config` / `hsts_config` / `custom_headers` | string (JSON) | [`security_headers_config_key`] |
//! | `{P}patterns:custom` | string | [`patterns_custom_key`] |
//! | `{P}ipinfo:database` | string | [`ipinfo_database_key`] |
//! | `{P}cloud_ranges_v2:{provider}` | string | [`cloud_ranges_key`] |
//! | `{P}cloud_ip_v2:{provider}` | string (JSON) | [`cloud_ip_key`] |
//! | `{P}dynamic_rules:last_known` | string | [`dynamic_rules_last_known_key`] |
//!
//! The behavior keys' double segment (`behavior_usage:behavior:usage:`) is
//! a verbatim reference oddity: namespace plus an in-key literal prefix.
//! Do not clean it up.
//!
//! ## Value formats
//!
//! - `banned_ips` / `banned_networks`: the ban expiry as the Go
//!   `FormatFloat(expiry, 'f', -1, 64)` decimal string
//!   ([`format_expiry`]), read back with a plain float parse and
//!   `now <= expiry` (the reference `_check_redis_exact`).
//! - behavior zsets: member = 32 lowercase hex chars ([`random_member`]),
//!   score = the float epoch; pruning is the exclusive
//!   `ZREMRANGEBYSCORE key "-inf" "({window_start"` bound ([`exclusive_prune_bound`]).
//! - `patterns:custom`: the custom patterns joined with `,`
//!   ([`encode_patterns_custom`]); restored by splitting on `,`
//!   ([`decode_patterns_custom`]).
//! - `cloud_ranges_v2`: comma-joined, lexically sorted
//!   `"<network>"` / `"<network>|<region>"` entries
//!   ([`encode_cloud_ranges`] / [`decode_cloud_ranges`]); `<network>` is
//!   the canonical masked CIDR string ([`canonical_network_string`]), an
//!   unparseable prefix decodes as a corrupt-cache error, not a skip.
//! - `cloud_ip_v2`: a JSON array of CIDR strings, sorted lexically
//!   ([`encode_cloud_ip_v2`] / [`decode_cloud_ip_v2`]); a non-list or
//!   undecodable payload is a cache miss.
//! - `ipinfo:database`: the full `MaxMindDB` file bytes carried as the
//!   latin-1 string of their byte values ([`latin1_to_wire`] /
//!   [`wire_to_latin1`]).
//! - `security_headers:*`: `json.dumps` of the config object
//!   ([`encode_json_object`]).
//! - `dynamic_rules:last_known`: the snapshot payload stored verbatim, no
//!   TTL.
//!
//! ## Legacy ban-key migration
//!
//! [`migrate_legacy_ban_keys`] is the versioning bridge for IP
//! canonicalization changes (the reference `_ipban_migration.py`, via the
//! Go port's `migrateLegacyBanKeys`): SCAN the `{P}banned_ips:*` keys,
//! canonicalize each raw IP segment, skip keys already canonical, move the
//! longer expiry to the canonical key (`SET ... PX old_pttl`) when the
//! canonical key's remaining TTL is shorter, and delete the legacy key.
//! Failures never fail startup: callers log and continue.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::redis_schema::*;
//!
//! // The key grammar, byte-identical to the Python and Go ports.
//! assert_eq!(
//!     ban_network_key("guard_core:", "10.9.9.9/8").expect("valid cidr"),
//!     "guard_core:banned_networks:10.0.0.0/8"
//! );
//! assert_eq!(
//!     patterns_custom_key("guard_core:"),
//!     "guard_core:patterns:custom"
//! );
//!
//! // The ban expiry value: the Go FormatFloat('f', -1) decimal string.
//! assert_eq!(format_expiry(1060.0), "1060");
//!
//! // The cloud ranges round-trip, sorted and comma-joined.
//! let payload = encode_cloud_ranges(&[
//!     (String::from("203.0.113.0/24"), Some("us-east")),
//!     (String::from("198.51.100.0/24"), None),
//! ]);
//! assert_eq!(payload, "198.51.100.0/24,203.0.113.0/24|us-east");
//! ```

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use crate::distributed::identity_hash;
use crate::ip_gate::{IpGateError, parse_network_entry};

/// The default key prefix (`SecurityConfig.redis_prefix`).
pub const DEFAULT_REDIS_PREFIX: &str = "guard_core:";

/// The security-headers config namespace.
pub const SECURITY_HEADERS_NAMESPACE: &str = "security_headers";
/// The CSP config key segment (`security_headers:csp_config`).
pub const CSP_CONFIG_KEY: &str = "csp_config";
/// The HSTS config key segment (`security_headers:hsts_config`).
pub const HSTS_CONFIG_KEY: &str = "hsts_config";
/// The custom-headers key segment (`security_headers:custom_headers`).
pub const CUSTOM_HEADERS_KEY: &str = "custom_headers";
/// The security-headers config TTL in seconds (the reference
/// `_cache_configuration`).
pub const SECURITY_HEADERS_TTL_SECONDS: u64 = 86_400;

/// The custom-pattern registry namespace and key (`patterns:custom`).
pub const PATTERNS_NAMESPACE: &str = "patterns";
/// The custom-patterns key segment.
pub const PATTERNS_CUSTOM_KEY: &str = "custom";

/// The `GeoIP` database cache namespace and key (`ipinfo:database`).
pub const IPINFO_NAMESPACE: &str = "ipinfo";
/// The `ipinfo` database key segment.
pub const IPINFO_DATABASE_KEY: &str = "database";
/// The `GeoIP` database cache TTL default (the reference constructor
/// `max_age`).
pub const IPINFO_DATABASE_TTL_DEFAULT_SECONDS: u64 = 86_400;

/// The cloud ranges cache namespace (`cloud_ranges_v2:{provider}`).
pub const CLOUD_RANGES_NAMESPACE: &str = "cloud_ranges_v2";
/// The cloud ranges cache TTL default (the reference `ttl` param).
pub const CLOUD_RANGES_TTL_DEFAULT_SECONDS: u64 = 3_600;
/// The cloud IP store protocol namespace (`cloud_ip_v2:{provider}`).
pub const CLOUD_IP_NAMESPACE: &str = "cloud_ip_v2";

/// The dynamic-rules namespace and last-known key
/// (`dynamic_rules:last_known`, no TTL).
pub const DYNAMIC_RULES_NAMESPACE: &str = "dynamic_rules";
/// The last-known-rules key segment.
pub const LAST_KNOWN_RULES_KEY: &str = "last_known";

/// `{prefix}{namespace}:{key}`: the reference namespaced helper's plain
/// concatenation.
#[must_use]
pub fn full_key(prefix: &str, namespace: &str, key: &str) -> String {
    format!("{prefix}{namespace}:{key}")
}

/// The `{prefix}banned_networks:{cidr}` key: a CIDR ban, stored under the
/// canonical network string (host bits cleared, the reference
/// `str(ipaddress.ip_network(cidr, strict=False))`).
///
/// # Errors
///
/// [`IpGateError`] when `cidr` is neither a valid IP nor a valid CIDR
/// range.
pub fn ban_network_key(prefix: &str, cidr: &str) -> Result<String, IpGateError> {
    let canonical = canonical_network_string(cidr).ok_or_else(|| IpGateError {
        list: "banned_networks",
        entry: cidr.to_owned(),
    })?;
    Ok(full_key(prefix, "banned_networks", &canonical))
}

/// The `{prefix}behavior_usage:behavior:usage:{sha256(endpoint)}:{sha256(ip)}`
/// zset key: the reference behavior usage rules.
///
/// The doubled `behavior_usage:behavior:usage:` segment is a verbatim
/// reference oddity; reproduce it exactly.
#[must_use]
pub fn behavior_usage_key(prefix: &str, endpoint_id: &str, ip: &str) -> String {
    full_key(
        prefix,
        "behavior_usage",
        &format!(
            "behavior:usage:{}:{}",
            identity_hash(endpoint_id),
            identity_hash(ip)
        ),
    )
}

/// The behavior return-patterns zset key.
///
/// Shape:
/// `{prefix}behavior_returns:behavior:return:{sha256(endpoint)}:{sha256(ip)}:{sha256(pattern)}`.
#[must_use]
pub fn behavior_return_key(prefix: &str, endpoint_id: &str, ip: &str, pattern: &str) -> String {
    full_key(
        prefix,
        "behavior_returns",
        &format!(
            "behavior:return:{}:{}:{}",
            identity_hash(endpoint_id),
            identity_hash(ip),
            identity_hash(pattern)
        ),
    )
}

/// The `{prefix}security_headers:{segment}` config key for one of
/// [`CSP_CONFIG_KEY`], [`HSTS_CONFIG_KEY`], [`CUSTOM_HEADERS_KEY`].
#[must_use]
pub fn security_headers_config_key(prefix: &str, segment: &str) -> String {
    full_key(prefix, SECURITY_HEADERS_NAMESPACE, segment)
}

/// The `{prefix}patterns:custom` key: the custom-pattern registry.
#[must_use]
pub fn patterns_custom_key(prefix: &str) -> String {
    full_key(prefix, PATTERNS_NAMESPACE, PATTERNS_CUSTOM_KEY)
}

/// The `{prefix}ipinfo:database` key: the `GeoIP` DB cache.
#[must_use]
pub fn ipinfo_database_key(prefix: &str) -> String {
    full_key(prefix, IPINFO_NAMESPACE, IPINFO_DATABASE_KEY)
}

/// The `{prefix}cloud_ranges_v2:{provider}` key: the cloud-range cache.
#[must_use]
pub fn cloud_ranges_key(prefix: &str, provider: &str) -> String {
    full_key(prefix, CLOUD_RANGES_NAMESPACE, provider)
}

/// The `{prefix}cloud_ip_v2:{provider}` key: the cloud IP store protocol.
#[must_use]
pub fn cloud_ip_key(prefix: &str, provider: &str) -> String {
    full_key(prefix, CLOUD_IP_NAMESPACE, provider)
}

/// The `{prefix}dynamic_rules:last_known` key: the last-known dynamic
/// rules snapshot (persisted, no TTL).
#[must_use]
pub fn dynamic_rules_last_known_key(prefix: &str) -> String {
    full_key(prefix, DYNAMIC_RULES_NAMESPACE, LAST_KNOWN_RULES_KEY)
}

/// The ban expiry string, the Go port's `FormatFloat(expiry, 'f', -1, 64)`
/// decimal form.
///
/// The Python reference writes `str(float)`, whose only difference is a
/// trailing `.0` on integral values; readers on every family parse
/// either, and the Go port is this family's wire reference.
#[must_use]
pub fn format_expiry(expiry: f64) -> String {
    format!("{expiry}")
}

/// A fresh zset member: 32 lowercase hex chars, 16 random bytes
/// hex-encoded.
///
/// The reference `uuid4().hex` on the Python side,
/// `hex.EncodeToString(rand 16)` on the Go side; uniqueness is the
/// contract, the shape is the interop guarantee.
#[must_use]
pub fn random_member() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .fold(String::with_capacity(32), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The behavior window's prune bound: `"(x"`, the exclusive lower bound.
///
/// Shape: `ZREMRANGEBYSCORE key "-inf" "(<window_start>"`, exactly the
/// reference's `f"({window_start}"`. The rate window prunes with the
/// inclusive `0 window_start` pair instead - the two boundaries MUST NOT
/// be swapped (spec section 08).
#[must_use]
pub fn exclusive_prune_bound(window_start: f64) -> String {
    format!("({}", format_expiry(window_start))
}

/// The canonical network string of a bare IP or CIDR entry.
///
/// The host bits cleared, the family's own textual form (`10.9.9.9/8` ->
/// `10.0.0.0/8`, a bare `10.0.0.9` -> `10.0.0.9/32`).
#[must_use]
pub fn canonical_network_string(entry: &str) -> Option<String> {
    let network = parse_network_entry(entry)?;
    Some(network.to_string())
}

/// The custom-pattern registry payload: the patterns joined with `,`
/// (the reference `",".join(custom_patterns)`).
///
/// A pattern containing a comma would corrupt this payload; the
/// pattern-safety validation is the only guard, exactly as in the
/// reference.
#[must_use]
pub fn encode_patterns_custom(patterns: &[String]) -> String {
    patterns.join(",")
}

/// Split the registry payload back into patterns (the reference
/// `cached_patterns.split(",")`).
#[must_use]
pub fn decode_patterns_custom(payload: &str) -> Vec<&str> {
    if payload.is_empty() {
        Vec::new()
    } else {
        payload.split(',').collect()
    }
}

/// A corrupt `cloud_ranges_v2` payload.
///
/// An entry whose prefix does not parse is a corrupt-cache error, not a
/// skip (the reference `_decode_cached` raises).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudRangeDecodeError {
    /// The offending entry.
    pub entry: String,
}

impl core::fmt::Display for CloudRangeDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "corrupt cloud range entry: {}", self.entry)
    }
}

impl std::error::Error for CloudRangeDecodeError {}

/// The `cloud_ranges_v2` payload: comma-joined, lexically sorted entries.
///
/// Each entry is `"<network>"` or `"<network>|<region>"` (the reference
/// `",".join(sorted(_encode_cached(ranges, regions)))`). A region value
/// carries at most one `|` annotation; callers MUST NOT let a region
/// contain `|` (the reference `partition` semantics).
#[must_use]
pub fn encode_cloud_ranges(ranges: &[(String, Option<&str>)]) -> String {
    let mut encoded: Vec<String> = ranges
        .iter()
        .map(|(network, region)| {
            region
                .as_ref()
                .map_or_else(|| network.clone(), |region| format!("{network}|{region}"))
        })
        .collect();
    encoded.sort();
    encoded.join(",")
}

/// Decode the `cloud_ranges_v2` payload into `(networks, regions)`.
///
/// # Errors
///
/// [`CloudRangeDecodeError`] naming the first entry whose prefix does
/// not parse as a network (a corrupt cache, never a skip).
pub fn decode_cloud_ranges(
    payload: &str,
) -> Result<(Vec<String>, BTreeMap<String, String>), CloudRangeDecodeError> {
    let mut networks = Vec::new();
    let mut regions = BTreeMap::new();
    for entry in payload.split(',') {
        if entry.is_empty() {
            continue;
        }
        let (prefix, separator, region) = partition(entry, '|');
        let Some(network) = canonical_network_string(prefix) else {
            return Err(CloudRangeDecodeError {
                entry: entry.to_owned(),
            });
        };
        if !separator || region.is_empty() {
            networks.push(network);
        } else {
            networks.push(network.clone());
            regions.insert(network, region.to_owned());
        }
    }
    networks.sort();
    networks.dedup();
    Ok((networks, regions))
}

/// `str.partition` semantics: split at the first occurrence, keeping all
/// three pieces (the separator empty when absent).
fn partition(text: &str, separator: char) -> (&str, bool, &str) {
    match text.split_once(separator) {
        Some((before, after)) => (before, true, after),
        None => (text, false, ""),
    }
}

/// The `cloud_ip_v2` payload: `json.dumps(sorted(ranges))`.
///
/// A JSON array of CIDR strings sorted lexically.
#[must_use]
pub fn encode_cloud_ip_v2(ranges: &[String]) -> String {
    let mut sorted: Vec<&String> = ranges.iter().collect();
    sorted.sort();
    let items: Vec<serde_json::Value> = sorted
        .iter()
        .map(|range| serde_json::Value::String((*range).clone()))
        .collect();
    serde_json::Value::Array(items).to_string()
}

/// Decode the `cloud_ip_v2` payload: `Some(ranges)` for a JSON array of
/// strings, `None` for anything else.
///
/// A non-list or undecodable payload is a cache miss triggering refresh,
/// the reference `RedisCloudIpStore`.
#[must_use]
pub fn decode_cloud_ip_v2(payload: &str) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    let items = value.as_array()?;
    items
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// A JSON object payload (`json.dumps` of a name -> value mapping), the
/// `security_headers:*` config value shape. The pairs are written in the
/// given order (Python dict insertion order).
#[must_use]
pub fn encode_json_object(pairs: &[(String, String)]) -> String {
    let mut map = serde_json::Map::new();
    for (name, value) in pairs {
        map.insert(name.clone(), serde_json::Value::String(value.clone()));
    }
    serde_json::Value::Object(map).to_string()
}

/// Decode a JSON object payload into its string pairs (the
/// `custom_headers` load arm). `None` when the payload is not an object of
/// strings.
#[must_use]
pub fn decode_json_object(payload: &str) -> Option<Vec<(String, String)>> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    let map = value.as_object()?;
    Some(
        map.iter()
            .filter_map(|(name, value)| {
                value.as_str().map(|value| (name.clone(), value.to_owned()))
            })
            .collect(),
    )
}

/// The `ipinfo:database` wire encoding: the `MaxMindDB` file bytes read
/// as the latin-1 string of their byte values.
///
/// Each byte maps to the code point with the same number, which the
/// reference stores with `decode_responses=True`. The reverse of
/// [`wire_to_latin1`]; a reader MUST run exactly this to recover the
/// binary DB.
#[must_use]
pub fn latin1_to_wire(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

/// Recover the binary `GeoIP` database from the cached string.
///
/// Every char must be at or below U+00FF (the latin-1 range); anything
/// above is a corrupt cache and reads as `None`.
#[must_use]
pub fn wire_to_latin1(payload: &str) -> Option<Vec<u8>> {
    payload
        .chars()
        .map(|c| u32::from(c).try_into().ok())
        .collect()
}

/// The string-level IP canonicalization the migration runs on each
/// scanned key segment (`_canonicalize_ip` / the Go `CanonicalizeIP`).
///
/// Strip the `[...]` bracket form, parse, collapse the IPv4-mapped form
/// to its IPv4 text; an unparseable segment comes back unchanged.
#[must_use]
pub fn canonicalize_ip_string(raw: &str) -> String {
    let stripped = raw
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(raw);
    IpAddr::from_str(stripped).map_or_else(
        |_| raw.to_owned(),
        |addr| crate::ip_gate::canonical(addr).to_string(),
    )
}

/// The admin surface the legacy ban-key migration needs (the reference
/// `RedisAdmin`, the sync seam pattern of [`crate::distributed`]).
pub trait RedisAdminStore: Send + Sync {
    /// `SCAN` with `MATCH pattern` (the observable `KEYS` result).
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::distributed::StoreError) on a backend failure.
    fn scan_match(&self, pattern: &str) -> Result<Vec<String>, crate::distributed::StoreError>;

    /// `PTTL key` in milliseconds: `-1` persistent, `-2` missing (the
    /// Redis semantics; the seconds/milliseconds distinction is
    /// normative).
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::distributed::StoreError) on a backend failure.
    fn pttl_ms(&self, key: &str) -> Result<i64, crate::distributed::StoreError>;

    /// `SET key value PX ttl_ms`: value and millisecond TTL land in one
    /// command (the migration's write shape).
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::distributed::StoreError) on a backend failure.
    fn set_px(
        &self,
        key: &str,
        value: &str,
        ttl_ms: i64,
    ) -> Result<(), crate::distributed::StoreError>;

    /// `DEL keys...`.
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::distributed::StoreError) on a backend failure.
    fn delete_keys(&self, keys: &[String]) -> Result<(), crate::distributed::StoreError>;

    /// `GET {prefix}{namespace}:{key}` (the namespaced read the migration
    /// uses to carry the legacy value over). `Ok(None)` is a miss.
    ///
    /// # Errors
    ///
    /// [`StoreError`](crate::distributed::StoreError) on a backend failure.
    fn get_key(
        &self,
        prefix: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, crate::distributed::StoreError>;
}

/// The legacy ban-key migration (the reference `_ipban_migration.py`,
/// via the Go port's `migrateLegacyBanKeys`).
///
/// For every `{prefix}banned_ips:*` key whose IP segment is not already
/// canonical, carry the longer expiry over to the canonical key and
/// delete the legacy one. Runs once at IP-ban-handler Redis
/// initialization; a failure on one key is that key's loss, never a
/// startup failure (callers log and continue, the reference's
/// `"Legacy ban-key migration skipped: {reason}"`).
///
/// # Errors
///
/// The first [`StoreError`](crate::distributed::StoreError) from the scan
/// itself; per-key errors are skipped (the reference logs and moves on).
pub fn migrate_legacy_ban_keys(
    store: &dyn RedisAdminStore,
    prefix: &str,
) -> Result<(), crate::distributed::StoreError> {
    let pattern = format!("{prefix}banned_ips:*");
    let keys = store.scan_match(&pattern)?;
    for key in keys {
        let _ = migrate_one_ban_key(store, prefix, &key);
    }
    Ok(())
}

/// One key's migration pass. `Ok(false)` when the key was already
/// canonical (untouched), `Ok(true)` when it was migrated or dropped.
///
/// # Errors
///
/// [`StoreError`](crate::distributed::StoreError) propagates from the
/// backend calls (the reference logs and skips the key).
pub fn migrate_one_ban_key(
    store: &dyn RedisAdminStore,
    prefix: &str,
    key: &str,
) -> Result<bool, crate::distributed::StoreError> {
    let key_prefix = format!("{prefix}banned_ips:");
    let Some(raw_ip) = key.strip_prefix(&key_prefix) else {
        return Ok(false);
    };
    let canonical_ip = canonicalize_ip_string(raw_ip);
    if canonical_ip == raw_ip {
        return Ok(false);
    }
    let Some(value) = store.get_key(prefix, "banned_ips", raw_ip)? else {
        return Ok(false);
    };
    let old_pttl = store.pttl_ms(key)?;
    if old_pttl <= 0 {
        // Persistent or expired: delete, done.
        store.delete_keys(std::slice::from_ref(&key.to_owned()))?;
        return Ok(true);
    }
    let canonical_key = format!("{key_prefix}{canonical_ip}");
    let new_pttl = store.pttl_ms(&canonical_key)?;
    if new_pttl < old_pttl {
        // Keep the longer expiry on the canonical key.
        store.set_px(&canonical_key, &value, old_pttl)?;
    }
    store.delete_keys(std::slice::from_ref(&key.to_owned()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ---- Key grammar fixtures (byte parity with the Go/Python ports) ----

    #[test]
    fn key_layouts_match_the_reference_grammar() {
        let p = "guard_core:";
        assert_eq!(
            ban_network_key(p, "10.9.9.9/8").expect("valid"),
            "guard_core:banned_networks:10.0.0.0/8"
        );
        assert_eq!(
            ban_network_key(p, "192.0.2.9").expect("valid"),
            "guard_core:banned_networks:192.0.2.9/32",
            "a bare IP ban canonicalizes to its single-host network form"
        );
        assert_eq!(
            behavior_usage_key(p, "endpoint:/api/users", "192.0.2.9"),
            "guard_core:behavior_usage:behavior:usage:\
             63141da573fd6925654bd16c44894798afd79c2ec3fc2668e877ca61ef090043:\
             d27fb1b45c2670fa64c03d01d426156940ddb94b545556c84f544abb737f0e76"
        );
        assert_eq!(
            behavior_return_key(p, "endpoint:/api/users", "192.0.2.9", "(?i)union.*select"),
            "guard_core:behavior_returns:behavior:return:\
             63141da573fd6925654bd16c44894798afd79c2ec3fc2668e877ca61ef090043:\
             d27fb1b45c2670fa64c03d01d426156940ddb94b545556c84f544abb737f0e76:\
             d34240a593ec6d8fed32c72e0ed162e1f0cd98eb536df504f77169c1abac52a6"
        );
        assert_eq!(
            security_headers_config_key(p, CSP_CONFIG_KEY),
            "guard_core:security_headers:csp_config"
        );
        assert_eq!(
            security_headers_config_key(p, HSTS_CONFIG_KEY),
            "guard_core:security_headers:hsts_config"
        );
        assert_eq!(
            security_headers_config_key(p, CUSTOM_HEADERS_KEY),
            "guard_core:security_headers:custom_headers"
        );
        assert_eq!(patterns_custom_key(p), "guard_core:patterns:custom");
        assert_eq!(ipinfo_database_key(p), "guard_core:ipinfo:database");
        assert_eq!(cloud_ranges_key(p, "AWS"), "guard_core:cloud_ranges_v2:AWS");
        assert_eq!(cloud_ip_key(p, "GCP"), "guard_core:cloud_ip_v2:GCP");
        assert_eq!(
            dynamic_rules_last_known_key(p),
            "guard_core:dynamic_rules:last_known"
        );
    }

    #[test]
    fn ban_network_key_fails_closed_on_a_bad_cidr() {
        let error = ban_network_key("guard_core:", "not-a-network").unwrap_err();
        assert_eq!(error.list, "banned_networks");
        assert_eq!(error.entry, "not-a-network");
    }

    #[test]
    fn ipv6_networks_canonicalize_compressed() {
        assert_eq!(
            canonical_network_string("2001:0db8:0000:0000:0000:0000:0000:0000/32").expect("valid"),
            "2001:db8::/32"
        );
        assert_eq!(
            ban_network_key("guard_core:", "2001:0db8::/32").expect("valid"),
            "guard_core:banned_networks:2001:db8::/32"
        );
    }

    // ---- Value format fixtures ----

    #[test]
    fn expiry_strings_match_the_go_format_float_shape() {
        assert_eq!(format_expiry(1060.0), "1060");
        assert_eq!(format_expiry(1_735_689_600.123_456), "1735689600.123456");
        assert_eq!(format_expiry(1_000.5), "1000.5");
    }

    #[test]
    fn random_members_are_the_reference_hex_shape() {
        let first = random_member();
        let second = random_member();
        assert_eq!(first.len(), 32);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(first, second, "uniqueness is the contract");
    }

    #[test]
    fn the_behavior_prune_bound_is_exclusive() {
        assert_eq!(exclusive_prune_bound(100.5), "(100.5");
    }

    #[test]
    fn patterns_custom_round_trips_comma_joined() {
        let patterns = vec![
            String::from("(?i)union.*select"),
            String::from(r"(?i)<script>"),
        ];
        let payload = encode_patterns_custom(&patterns);
        assert_eq!(payload, "(?i)union.*select,(?i)<script>");
        assert_eq!(
            decode_patterns_custom(&payload),
            vec!["(?i)union.*select", "(?i)<script>"]
        );
        assert!(decode_patterns_custom("").is_empty());
    }

    #[test]
    fn cloud_ranges_round_trip_sorted_with_regions() {
        let payload = encode_cloud_ranges(&[
            (String::from("203.0.113.0/24"), Some("us-east")),
            (String::from("198.51.100.0/24"), None),
            (String::from("2001:db8::/32"), Some("eu-west")),
        ]);
        // Lexically sorted encoded entries, comma-joined: the exact bytes
        // the Python reference writes for this set.
        assert_eq!(
            payload,
            "198.51.100.0/24,2001:db8::/32|eu-west,203.0.113.0/24|us-east"
        );
        let (networks, regions) = decode_cloud_ranges(&payload).expect("decodable");
        assert_eq!(
            networks,
            vec![
                String::from("198.51.100.0/24"),
                String::from("2001:db8::/32"),
                String::from("203.0.113.0/24"),
            ]
        );
        assert_eq!(regions.get("2001:db8::/32"), Some(&"eu-west".to_owned()));
        assert_eq!(regions.get("203.0.113.0/24"), Some(&"us-east".to_owned()));
        assert!(!regions.contains_key("198.51.100.0/24"));
    }

    #[test]
    fn cloud_ranges_decode_normalizes_host_bits() {
        // An entry carrying host bits canonicalizes on decode, exactly the
        // reference `ip_network(prefix)` parse.
        let (networks, _) = decode_cloud_ranges("198.51.100.7/24").expect("decodable");
        assert_eq!(networks, vec![String::from("198.51.100.0/24")]);
    }

    #[test]
    fn cloud_ranges_decode_fails_closed_on_a_corrupt_entry() {
        let error = decode_cloud_ranges("198.51.100.0/24,garbage").unwrap_err();
        assert_eq!(error.entry, "garbage");
        assert_eq!(error.to_string(), "corrupt cloud range entry: garbage");
    }

    #[test]
    fn cloud_ip_v2_is_a_sorted_json_array() {
        let payload = encode_cloud_ip_v2(&[
            String::from("203.0.113.0/24"),
            String::from("198.51.100.0/24"),
        ]);
        assert_eq!(payload, r#"["198.51.100.0/24","203.0.113.0/24"]"#);
        assert_eq!(
            decode_cloud_ip_v2(&payload),
            Some(vec![
                String::from("198.51.100.0/24"),
                String::from("203.0.113.0/24"),
            ])
        );
        // A non-list or undecodable payload is a cache miss.
        assert_eq!(decode_cloud_ip_v2(r#"{"a":1}"#), None);
        assert_eq!(decode_cloud_ip_v2("not json"), None);
        assert_eq!(decode_cloud_ip_v2("[1,2]"), None);
    }

    #[test]
    fn json_object_round_trips_in_order() {
        let payload = encode_json_object(&[
            (String::from("X-Frame-Options"), String::from("SAMEORIGIN")),
            (String::from("X-Actuators"), String::from("none")),
        ]);
        assert_eq!(
            payload,
            r#"{"X-Frame-Options":"SAMEORIGIN","X-Actuators":"none"}"#
        );
        assert_eq!(
            decode_json_object(&payload),
            Some(vec![
                (String::from("X-Frame-Options"), String::from("SAMEORIGIN")),
                (String::from("X-Actuators"), String::from("none")),
            ])
        );
        assert_eq!(decode_json_object("[]"), None);
    }

    #[test]
    fn latin1_carries_arbitrary_binary_payloads() {
        // Every byte value round-trips, including the ones UTF-8 would
        // mangle (>= 0x80).
        let db_bytes: Vec<u8> = (0..=255).collect();
        let wire = latin1_to_wire(&db_bytes);
        assert_eq!(wire_to_latin1(&wire), Some(db_bytes));
        // A char above the latin-1 range is a corrupt cache.
        assert_eq!(wire_to_latin1("guar\u{100}"), None);
    }

    #[test]
    fn ip_string_canonicalization_mirrors_the_references() {
        assert_eq!(canonicalize_ip_string("::ffff:192.0.2.9"), "192.0.2.9");
        assert_eq!(canonicalize_ip_string("[::ffff:192.0.2.9]"), "192.0.2.9");
        assert_eq!(canonicalize_ip_string("2001:0db8::0001"), "2001:db8::1");
        assert_eq!(
            canonicalize_ip_string("192.0.2.9"),
            "192.0.2.9",
            "already canonical: unchanged"
        );
        assert_eq!(
            canonicalize_ip_string("not-an-ip"),
            "not-an-ip",
            "unparseable segments come back unchanged"
        );
    }

    // ---- Migration ----

    #[derive(Default)]
    struct MemoryAdmin {
        strings: Mutex<BTreeMap<String, String>>,
        ttls_ms: Mutex<BTreeMap<String, i64>>,
    }

    impl MemoryAdmin {
        fn seed(&self, key: &str, value: &str, ttl_ms: i64) {
            self.strings
                .lock()
                .expect("strings")
                .insert(key.to_owned(), value.to_owned());
            self.ttls_ms
                .lock()
                .expect("ttls")
                .insert(key.to_owned(), ttl_ms);
        }

        fn has(&self, key: &str) -> bool {
            self.strings.lock().expect("strings").contains_key(key)
        }
    }

    impl RedisAdminStore for MemoryAdmin {
        fn scan_match(&self, pattern: &str) -> Result<Vec<String>, crate::distributed::StoreError> {
            // A glob with only a trailing * is what the migration uses.
            let stem = pattern.strip_suffix('*').unwrap_or(pattern);
            Ok(self
                .strings
                .lock()
                .expect("strings")
                .keys()
                .filter(|key| key.starts_with(stem))
                .cloned()
                .collect())
        }

        fn pttl_ms(&self, key: &str) -> Result<i64, crate::distributed::StoreError> {
            Ok(*self.ttls_ms.lock().expect("ttls").get(key).unwrap_or(&-2))
        }

        fn set_px(
            &self,
            key: &str,
            value: &str,
            ttl_ms: i64,
        ) -> Result<(), crate::distributed::StoreError> {
            self.seed(key, value, ttl_ms);
            Ok(())
        }

        // Test scaffolding: the two guards live exactly for this loop.
        #[allow(clippy::significant_drop_tightening)]
        fn delete_keys(&self, keys: &[String]) -> Result<(), crate::distributed::StoreError> {
            let mut strings = self.strings.lock().expect("strings");
            let mut ttls = self.ttls_ms.lock().expect("ttls");
            for key in keys {
                strings.remove(key);
                ttls.remove(key);
            }
            Ok(())
        }

        fn get_key(
            &self,
            prefix: &str,
            namespace: &str,
            key: &str,
        ) -> Result<Option<String>, crate::distributed::StoreError> {
            Ok(self
                .strings
                .lock()
                .expect("strings")
                .get(&full_key(prefix, namespace, key))
                .cloned())
        }
    }

    #[test]
    fn migration_moves_the_longer_expiry_to_the_canonical_key() {
        let admin = MemoryAdmin::default();
        // A legacy v4-mapped key with 60s left; the canonical key exists
        // but with only 10s left.
        admin.seed(
            "guard_core:banned_ips:::ffff:192.0.2.9",
            "1735689600.5",
            60_000,
        );
        admin.seed("guard_core:banned_ips:192.0.2.9", "1735689600.5", 10_000);

        migrate_legacy_ban_keys(&admin, "guard_core:").expect("scan");

        // The canonical key now carries the legacy value with the longer
        // (60s) expiry; the legacy key is gone.
        assert_eq!(
            admin
                .strings
                .lock()
                .expect("strings")
                .get("guard_core:banned_ips:192.0.2.9"),
            Some(&"1735689600.5".to_owned())
        );
        assert_eq!(
            admin
                .ttls_ms
                .lock()
                .expect("ttls")
                .get("guard_core:banned_ips:192.0.2.9"),
            Some(&60_000)
        );
        assert!(!admin.has("guard_core:banned_ips:::ffff:192.0.2.9"));
    }

    #[test]
    fn migration_keeps_the_canonical_key_when_it_is_already_longer() {
        let admin = MemoryAdmin::default();
        admin.seed(
            "guard_core:banned_ips:::ffff:192.0.2.9",
            "1735689600.5",
            10_000,
        );
        admin.seed("guard_core:banned_ips:192.0.2.9", "1735689600.5", 60_000);

        migrate_legacy_ban_keys(&admin, "guard_core:").expect("scan");

        // The canonical key kept its own 60s TTL; the legacy key is gone.
        assert_eq!(
            admin
                .ttls_ms
                .lock()
                .expect("ttls")
                .get("guard_core:banned_ips:192.0.2.9"),
            Some(&60_000)
        );
        assert!(!admin.has("guard_core:banned_ips:::ffff:192.0.2.9"));
    }

    #[test]
    fn migration_drops_expired_and_persistent_legacy_keys() {
        let admin = MemoryAdmin::default();
        admin.seed("guard_core:banned_ips:::ffff:192.0.2.8", "1000.0", 0);
        admin.seed("guard_core:banned_ips:::ffff:192.0.2.7", "1000.0", -1);

        migrate_legacy_ban_keys(&admin, "guard_core:").expect("scan");

        assert!(!admin.has("guard_core:banned_ips:::ffff:192.0.2.8"));
        assert!(!admin.has("guard_core:banned_ips:::ffff:192.0.2.7"));
        assert!(
            !admin.has("guard_core:banned_ips:192.0.2.8"),
            "an expired legacy ban is dropped, not carried over"
        );
        assert!(
            !admin.has("guard_core:banned_ips:192.0.2.7"),
            "a persistent legacy ban is dropped, not carried over"
        );
    }

    #[test]
    fn migration_touches_only_non_canonical_keys() {
        let admin = MemoryAdmin::default();
        admin.seed("guard_core:banned_ips:192.0.2.9", "1735689600.5", 60_000);

        migrate_legacy_ban_keys(&admin, "guard_core:").expect("scan");

        assert!(admin.has("guard_core:banned_ips:192.0.2.9"));
        assert_eq!(
            admin
                .ttls_ms
                .lock()
                .expect("ttls")
                .get("guard_core:banned_ips:192.0.2.9"),
            Some(&60_000),
            "a canonical key is left untouched"
        );
    }

    #[test]
    fn one_bad_key_never_fails_the_rest() {
        let admin = MemoryAdmin::default();
        // A segment that is not an IP canonicalizes to itself: skipped.
        admin.seed("guard_core:banned_ips:junk", "1735689600.5", 60_000);
        // A real legacy key next to it still migrates.
        admin.seed(
            "guard_core:banned_ips:::ffff:192.0.2.9",
            "1735689600.5",
            60_000,
        );

        migrate_legacy_ban_keys(&admin, "guard_core:").expect("scan");

        assert!(admin.has("guard_core:banned_ips:junk"));
        assert!(!admin.has("guard_core:banned_ips:::ffff:192.0.2.9"));
        assert!(admin.has("guard_core:banned_ips:192.0.2.9"));
    }
}
