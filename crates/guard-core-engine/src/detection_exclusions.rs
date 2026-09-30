//! Per-request detection exclusion resolution and the multi-surface request
//! scan.
//!
//! The Rust port of `guard_core/_utils/detection_config.py` (via the Go
//! port's `detectionexclusions.go` / `headerexclusions.go` and the pipeline
//! `detectThreat`). Every route surface overrides the global config when the route carries a
//! non-`None` value (the Python sentinel is `None`), and the header
//! exclusion set is additive - the hardcoded defaults merge with the config
//! set and the route set (`_resolve_excluded_headers`), while the param,
//! body-field, and enabled-category sets replace (`_resolve_excluded_params`
//! and friends). Matching is case-insensitive: the resolved sets are
//! lowercased at resolution time.
//!
//! An excluded surface is not skipped outright in every case: excluded
//! headers whose values are known to false-positive a category (the ssrf
//! category for address-carrying proxy headers and for address-chain
//! values) still scan with every other enabled category, so an attack
//! payload smuggled into an excluded header still detects
//! (`_excluded_header_skip_categories`).
//!
//! # Example
//!
//! ```
//! use guard_core_engine::detection_exclusions::{
//!     resolve, DetectionExclusionConfig, RouteDetectionExclusions,
//! };
//! use std::collections::HashSet;
//!
//! // The global config excludes two params; the route replaces the set.
//! let global = DetectionExclusionConfig {
//!     excluded_detection_params: vec!["debug".to_owned(), "Trace".to_owned()],
//!     ..DetectionExclusionConfig::default()
//! };
//! let route = RouteDetectionExclusions {
//!     excluded_detection_params: Some(vec!["session".to_owned()]),
//!     ..RouteDetectionExclusions::default()
//! };
//! let resolved = resolve(Some(&global), Some(&route));
//!
//! assert!(resolved.excluded_params.contains("session"));
//! assert!(
//!     !resolved.excluded_params.contains("debug") && !resolved.excluded_params.contains("trace"),
//!     "a non-None route set replaces the global one"
//! );
//! // The sets are lowercased at resolution time: the global config's
//! // mixed-case "Trace" entry resolves to "trace" when no route replaces it.
//! let inherited = resolve(Some(&global), None);
//! assert!(inherited.excluded_params.contains("trace"));
//! // The header set always merges the hardcoded proxy defaults.
//! assert!(resolved.excluded_headers.contains("x-forwarded-for"));
//! // Unset route surfaces keep the global resolution; unset everywhere
//! // means every category scans and the body surface scans.
//! assert!(resolved.enabled_categories.is_none());
//! assert!(resolved.scan_body);
//! ```

use std::collections::HashSet;

use crate::body_scan::BodyScanValue;
use crate::detect::{self, DetectConfig, Threat};

/// The categories an excluded header skips for a value known to
/// false-positive them.
const SSRF_SKIP: &[&str] = &["ssrf"];

/// The hardcoded header exclusion defaults (`_DEFAULT_EXCLUDED_HEADERS`).
///
/// The proxy identity, forwarding, and browser-fingerprint headers that
/// enter the detection scan through the excluded-header routing instead of
/// the full category sweep. Lowercase names, always merged with the config
/// and route sets.
pub const DEFAULT_EXCLUDED_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "origin",
    "referer",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "fly-client-ip",
    "x-envoy-external-address",
];

/// `_HEADER_CATEGORY_EXCLUSIONS`'s address-carrying names: an excluded match
/// on one of these headers skips the ssrf category for any value.
const ADDRESS_HEADER_NAMES: &[&str] = &[
    "host",
    "origin",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "fly-client-ip",
    "x-envoy-external-address",
    "via",
];

/// The global config's detection-exclusion surface.
///
/// The reference `SecurityConfig` fields of the same names. The category
/// set is `None` when nothing is configured (every category scans); the
/// scan-body flag is `None` for the reference default (`true`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionExclusionConfig {
    /// `excluded_detection_headers` (merged with the defaults, never a
    /// replacement).
    pub excluded_detection_headers: Vec<String>,
    /// `excluded_detection_params`.
    pub excluded_detection_params: Vec<String>,
    /// `excluded_detection_body_fields`.
    pub excluded_detection_body_fields: Vec<String>,
    /// `enabled_detection_categories`: `None` scans every category.
    pub enabled_detection_categories: Option<Vec<String>>,
    /// `detection_scan_body`: `None` is the reference default (`true`).
    pub detection_scan_body: Option<bool>,
}

/// The route decorator's detection-exclusion surface.
///
/// The reference `RouteConfig` fields of the same names. A `None` field
/// inherits the global resolution for that surface; a `Some` value
/// replaces it (the header set is the exception: it always merges).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteDetectionExclusions {
    /// `excluded_detection_headers` (merged with the defaults and the
    /// config set).
    pub excluded_detection_headers: Option<Vec<String>>,
    /// `excluded_detection_params`.
    pub excluded_detection_params: Option<Vec<String>>,
    /// `excluded_detection_body_fields`.
    pub excluded_detection_body_fields: Option<Vec<String>>,
    /// `enabled_detection_categories`: a `Some` (even empty) replaces the
    /// global set - an empty set disables every category, the reference's
    /// empty frozenset.
    pub enabled_detection_categories: Option<Vec<String>>,
    /// `detection_scan_body`: a `Some` overrides the global flag both
    /// directions.
    pub detection_scan_body: Option<bool>,
}

/// The resolved exclusion sets for one request (`routeDetectionExclusions`
/// in the Go port).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedExclusions {
    /// Lowercased: query-param names the scan skips.
    pub excluded_params: HashSet<String>,
    /// Lowercased: body field names the scan skips.
    pub excluded_body_fields: HashSet<String>,
    /// Lowercased: header names routed through the excluded-header scan
    /// (defaults + config + route, merged).
    pub excluded_headers: HashSet<String>,
    /// Lowercased: the categories that may contribute a detection. `None`
    /// means every category scans.
    pub enabled_categories: Option<HashSet<String>>,
    /// Whether the body surface scans at all.
    pub scan_body: bool,
}

/// Merge and lowercase one list into the set.
fn extend_lowered(set: &mut HashSet<String>, values: impl IntoIterator<Item = String>) {
    set.extend(values.into_iter().map(|value| value.to_ascii_lowercase()));
}

/// `_resolve_*`: every route surface overrides the global config when the
/// route carries a non-`None` value, except the header set which merges
/// defaults + config + route.
#[must_use]
pub fn resolve(
    config: Option<&DetectionExclusionConfig>,
    route: Option<&RouteDetectionExclusions>,
) -> ResolvedExclusions {
    let mut resolved = ResolvedExclusions::default();

    // Header set: additive, always (defaults + config + route).
    resolved
        .excluded_headers
        .extend(DEFAULT_EXCLUDED_HEADERS.iter().map(|h| (*h).to_owned()));
    if let Some(config) = config {
        extend_lowered(
            &mut resolved.excluded_headers,
            config.excluded_detection_headers.clone(),
        );
    }
    if let Some(headers) = route.and_then(|route| route.excluded_detection_headers.as_ref()) {
        extend_lowered(&mut resolved.excluded_headers, headers.clone());
    }

    // Param / body-field / category sets: a non-None route value replaces
    // the global one.
    let params: Option<Vec<String>> = route
        .and_then(|route| route.excluded_detection_params.clone())
        .or_else(|| config.map(|config| config.excluded_detection_params.clone()));
    if let Some(params) = params {
        extend_lowered(&mut resolved.excluded_params, params);
    }
    let body_fields: Option<Vec<String>> = route
        .and_then(|route| route.excluded_detection_body_fields.clone())
        .or_else(|| config.map(|config| config.excluded_detection_body_fields.clone()));
    if let Some(body_fields) = body_fields {
        extend_lowered(&mut resolved.excluded_body_fields, body_fields);
    }
    let categories: Option<Vec<String>> = route
        .and_then(|route| route.enabled_detection_categories.clone())
        .or_else(|| config.and_then(|config| config.enabled_detection_categories.clone()));
    if let Some(categories) = categories {
        let mut set = HashSet::new();
        extend_lowered(&mut set, categories);
        resolved.enabled_categories = Some(set);
    }

    // `_resolve_scan_body`: route > config > the default of true.
    resolved.scan_body = route
        .and_then(|route| route.detection_scan_body)
        .or_else(|| config.and_then(|config| config.detection_scan_body))
        .unwrap_or(true);

    resolved
}

/// The categories an excluded header skips for one value
/// (`_excluded_header_skip_categories`).
///
/// Address-carrying proxy headers skip `ssrf` for any value; every other
/// excluded header skips `ssrf` only when its whole value parses as an
/// address chain (so an attack payload in the same header still detects).
/// An empty slice means the header scans with every enabled category.
#[must_use]
pub fn excluded_header_skip_categories(name: &str, value: &str) -> &'static [&'static str] {
    let normalized = name.trim().to_ascii_lowercase();
    if ADDRESS_HEADER_NAMES.contains(&normalized.as_str()) {
        return SSRF_SKIP;
    }
    if value_looks_like_address_chain(value) {
        return SSRF_SKIP;
    }
    &[]
}

/// Remove the port from a forwarded-list entry
/// (`_strip_forwarded_entry_port`).
///
/// `1.2.3.4:8080` -> `1.2.3.4`, `[::1]:8080` -> `::1`, so the address
/// itself can be parsed.
#[must_use]
pub fn strip_forwarded_entry_port(value: &str) -> &str {
    if let Some(rest) = value.strip_prefix('[') {
        let Some(closing) = rest.find(']') else {
            return value;
        };
        let remainder = &rest[closing + 1..];
        let port_valid =
            remainder.starts_with(':') && remainder[1..].bytes().all(|b| b.is_ascii_digit());
        if !(remainder.is_empty() || port_valid) {
            return value;
        }
        return &rest[..closing];
    }
    if value.matches(':').count() == 1
        && let Some((host, port)) = value.split_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return host;
    }
    value
}

/// Address-chain detection (`_value_looks_like_address_chain`).
///
/// Every comma-separated token parses as an IP address once its port entry
/// is stripped, so a value like `10.0.0.5, 172.16.0.1` reads as a proxy
/// chain, not an attack payload.
#[must_use]
pub fn value_looks_like_address_chain(value: &str) -> bool {
    let tokens: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.is_empty() {
        return false;
    }
    tokens.iter().all(|token| {
        strip_forwarded_entry_port(token)
            .parse::<std::net::IpAddr>()
            .is_ok()
    })
}

/// The request surfaces one scan pass covers (the `detectThreat` input
/// shape). Headers and query params are `(name, value)` pairs; body values
/// are the [`crate::body_scan`] extraction's output.
#[derive(Debug, Clone, Default)]
pub struct RequestSurfaces<'a> {
    /// The URL path, scanned first under the `url_path` context.
    pub url_path: Option<&'a str>,
    /// Query parameter pairs, scanned under the `query_param` context.
    pub query_params: &'a [(String, String)],
    /// Header pairs, scanned under the `header` context.
    pub headers: &'a [(String, String)],
    /// Content type of `raw_body` (the body extraction's router).
    pub content_type: &'a str,
    /// The raw request body, extracted into scan values when
    /// [`ResolvedExclusions::scan_body`] is set.
    pub raw_body: &'a str,
}

/// The multi-surface verdict (`detectThreat`'s return shape).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestScanVerdict {
    /// `true` when some scanned value produced at least one enabled
    /// category.
    pub is_threat: bool,
    /// The contributing categories, sorted (the reference emits them
    /// alphabetically in the reason).
    pub categories: Vec<String>,
    /// The reference reason string naming the categories.
    pub reason: String,
}

/// The multi-surface scan (`detectThreat`).
///
/// Scan the request surfaces in the reference order - URL path, query
/// params (skipping excluded names), headers (excluded names scan with
/// their known-false-positive categories suppressed), then the body surface
/// when [`ResolvedExclusions::scan_body`] is set - and return the first
/// value that produces an enabled category.
///
/// A value that is a threat but whose categories are all filtered out ends
/// the scan with a clean verdict, exactly like the reference: the
/// per-value category filter is terminal, not a reason to keep scanning
/// later values. Regex threats carry the category; semantic threats carry
/// none (the reference's semantic payloads have no `category` and never
/// contribute here), but still mark the value a threat.
#[must_use]
pub fn scan_request(
    surfaces: &RequestSurfaces<'_>,
    exclusions: &ResolvedExclusions,
    config: &DetectConfig,
) -> RequestScanVerdict {
    struct Value<'a> {
        content: &'a str,
        context: &'a str,
        skip_categories: &'static [&'static str],
    }

    let mut values: Vec<Value<'_>> = Vec::new();
    if let Some(path) = surfaces.url_path.filter(|path| !path.is_empty()) {
        values.push(Value {
            content: path,
            context: "url_path",
            skip_categories: &[],
        });
    }
    for (name, value) in surfaces.query_params {
        if exclusions
            .excluded_params
            .contains(&name.to_ascii_lowercase())
        {
            continue;
        }
        values.push(Value {
            content: value,
            context: "query_param",
            skip_categories: &[],
        });
    }
    for (name, value) in surfaces.headers {
        if value.is_empty() {
            continue;
        }
        let skip_categories = if exclusions
            .excluded_headers
            .contains(&name.to_ascii_lowercase())
        {
            excluded_header_skip_categories(name, value)
        } else {
            &[]
        };
        values.push(Value {
            content: value,
            context: "header",
            skip_categories,
        });
    }
    // The body values borrow the extraction's owned strings, so the owned
    // vector is kept in a binding that outlives the scan loop.
    let body_values: Vec<BodyScanValue> = if exclusions.scan_body {
        crate::body_scan::extract_body_scan_values_with_exclusions(
            surfaces.raw_body,
            surfaces.content_type,
            config,
            crate::body_scan::ExcludedBodyFields::new(&exclusions.excluded_body_fields),
        )
    } else {
        Vec::new()
    };
    for value in &body_values {
        if let Some(forced) = value.forced_category {
            // JSON mongo-operator keys hit straight from the walk
            // (`_mongo_operator_key_hit`), unfiltered by the enabled
            // categories.
            return forced_verdict(core::slice::from_ref(&forced));
        }
        values.push(Value {
            content: &value.content,
            context: &value.context,
            skip_categories: &[],
        });
    }

    for value in &values {
        let verdict = detect::detect(value.content, value.context, config);
        if !verdict.is_threat {
            continue;
        }
        let mut categories: Vec<String> = Vec::new();
        for threat in &verdict.threats {
            let category = match threat {
                Threat::Regex(regex) => Some(regex.category.clone()),
                // Semantic threats carry no category (the reference's
                // semantic payloads have no `category` key and are
                // skipped by the `category == ""` guard).
                Threat::Semantic(_) => None,
            };
            let Some(category) = category else {
                continue;
            };
            if !category_enabled(&category, exclusions.enabled_categories.as_ref())
                || value.skip_categories.contains(&category.as_str())
                || categories.contains(&category)
            {
                continue;
            }
            categories.push(category);
        }
        if categories.is_empty() {
            // A threat whose categories are all filtered out ends the scan
            // clean, exactly the reference's terminal per-value filter.
            return RequestScanVerdict::default();
        }
        categories.sort();
        return verdict_from(categories);
    }

    RequestScanVerdict::default()
}

/// Forced-category verdict (`_mongo_operator_key_hit`): the category
/// reports without a pattern scan or a category filter.
fn forced_verdict(categories: &[&str]) -> RequestScanVerdict {
    let categories: Vec<String> = categories.iter().map(|c| (*c).to_owned()).collect();
    verdict_from(categories)
}

fn verdict_from(mut categories: Vec<String>) -> RequestScanVerdict {
    categories.sort();
    let reason = format!("Penetration patterns detected: {}", categories.join(", "));
    RequestScanVerdict {
        is_threat: true,
        categories,
        reason,
    }
}

fn category_enabled(category: &str, enabled: Option<&HashSet<String>>) -> bool {
    enabled.is_none_or(|set| set.contains(category))
}

/// The route toggle's request-time semantics.
///
/// `route_config.enable_suspicious_detection`: a route carrying the flag
/// overrides the global `enable_penetration_detection` in both directions;
/// without a route flag the global value applies.
#[must_use]
pub fn detection_enabled(global_enabled: bool, route_enabled: Option<bool>) -> bool {
    route_enabled.unwrap_or(global_enabled)
}

/// The check-set liveness semantics (`SuspiciousActivityCheck.applies_to`).
///
/// The suspicious-activity check stays alive while the global flag is on or
/// any route enables its toggle (or dynamic rules are on, which can route
/// requests anywhere).
#[must_use]
pub fn check_applies(
    global_enabled: bool,
    route_toggles: impl IntoIterator<Item = bool>,
    dynamic_rules: bool,
) -> bool {
    global_enabled || route_toggles.into_iter().any(|flag| flag) || dynamic_rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::DetectConfig;

    fn corpus_config() -> DetectConfig {
        DetectConfig {
            max_content_length: 10_000,
            max_full_scan_bytes: 262_144,
            preserve_attack_patterns: true,
            semantic_threshold: 0.7,
            threat_score_threshold: 1.0,
            binary_min_run_length: 16,
        }
    }

    fn config_of(params: &[&str]) -> DetectionExclusionConfig {
        DetectionExclusionConfig {
            excluded_detection_params: params.iter().map(|s| (*s).to_owned()).collect(),
            ..DetectionExclusionConfig::default()
        }
    }

    #[test]
    fn resolve_defaults_scan_everything() {
        let resolved = resolve(None, None);
        assert!(resolved.excluded_params.is_empty());
        assert!(resolved.excluded_body_fields.is_empty());
        assert!(resolved.enabled_categories.is_none());
        assert!(resolved.scan_body);
        // The hardcoded header defaults are present with no config at all.
        assert!(resolved.excluded_headers.contains("host"));
        assert!(resolved.excluded_headers.contains("x-forwarded-for"));
        assert!(!resolved.excluded_headers.contains("x-custom"));
    }

    #[test]
    fn non_none_route_sets_replace_and_unset_inherit() {
        let global = config_of(&["debug", "trace"]);
        let route = RouteDetectionExclusions {
            excluded_detection_params: Some(vec!["session".to_owned()]),
            ..RouteDetectionExclusions::default()
        };
        let resolved = resolve(Some(&global), Some(&route));
        assert!(resolved.excluded_params.contains("session"));
        assert!(!resolved.excluded_params.contains("debug"));

        // An unset route surface inherits the global set.
        let inheriting = resolve(Some(&global), Some(&RouteDetectionExclusions::default()));
        assert!(inheriting.excluded_params.contains("debug"));
        assert!(inheriting.excluded_params.contains("trace"));
    }

    #[test]
    fn header_set_merges_defaults_config_and_route() {
        let global = DetectionExclusionConfig {
            excluded_detection_headers: vec!["X-Custom-Global".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let route = RouteDetectionExclusions {
            excluded_detection_headers: Some(vec!["x-custom-route".to_owned()]),
            ..RouteDetectionExclusions::default()
        };
        let resolved = resolve(Some(&global), Some(&route));
        assert!(resolved.excluded_headers.contains("x-custom-global"));
        assert!(resolved.excluded_headers.contains("x-custom-route"));
        assert!(
            resolved.excluded_headers.contains("referer"),
            "defaults survive"
        );
    }

    #[test]
    fn empty_route_category_set_disables_every_category() {
        let route = RouteDetectionExclusions {
            enabled_detection_categories: Some(Vec::new()),
            ..RouteDetectionExclusions::default()
        };
        let resolved = resolve(None, Some(&route));
        let enabled = resolved.enabled_categories.clone().expect("some");
        assert!(enabled.is_empty(), "an empty Some replaces, not inherits");
        assert!(!category_enabled(
            "sqli",
            resolved.enabled_categories.as_ref()
        ));

        // Without the route override the global set decides.
        let global = DetectionExclusionConfig {
            enabled_detection_categories: Some(vec!["sqli".to_owned()]),
            ..DetectionExclusionConfig::default()
        };
        let inheriting = resolve(Some(&global), None);
        assert!(category_enabled(
            "sqli",
            inheriting.enabled_categories.as_ref()
        ));
        assert!(!category_enabled(
            "xss",
            inheriting.enabled_categories.as_ref()
        ));
    }

    #[test]
    fn scan_body_toggle_overrides_both_directions() {
        // Route false over a global true.
        let global = DetectionExclusionConfig {
            detection_scan_body: Some(true),
            ..DetectionExclusionConfig::default()
        };
        let route = RouteDetectionExclusions {
            detection_scan_body: Some(false),
            ..RouteDetectionExclusions::default()
        };
        assert!(!resolve(Some(&global), Some(&route)).scan_body);

        // Route true over a global false.
        let global = DetectionExclusionConfig {
            detection_scan_body: Some(false),
            ..DetectionExclusionConfig::default()
        };
        let route = RouteDetectionExclusions {
            detection_scan_body: Some(true),
            ..RouteDetectionExclusions::default()
        };
        assert!(resolve(Some(&global), Some(&route)).scan_body);

        // Global false with no route flag.
        let global = DetectionExclusionConfig {
            detection_scan_body: Some(false),
            ..DetectionExclusionConfig::default()
        };
        assert!(!resolve(Some(&global), None).scan_body);
    }

    #[test]
    fn scan_body_false_still_scans_headers_params_and_path() {
        let route = RouteDetectionExclusions {
            detection_scan_body: Some(false),
            ..RouteDetectionExclusions::default()
        };
        let exclusions = resolve(None, Some(&route));
        let surfaces = RequestSurfaces {
            url_path: Some("/files?x=../../etc/passwd"),
            query_params: &[("q".to_owned(), "1 UNION SELECT password".to_owned())],
            headers: &[(
                "x-payload".to_owned(),
                "<script>alert(1)</script>".to_owned(),
            )],
            content_type: "application/x-www-form-urlencoded",
            raw_body: "payload=<img src=x onerror=alert(1)>",
        };
        let verdict = scan_request(&surfaces, &exclusions, &corpus_config());
        assert!(
            verdict.is_threat,
            "the body surface is skipped, the rest still detect"
        );
    }

    #[test]
    fn excluded_param_skips_only_itself() {
        let global = config_of(&["debug"]);
        let exclusions = resolve(Some(&global), None);
        let surfaces = RequestSurfaces {
            url_path: Some("/search"),
            query_params: &[
                ("debug".to_owned(), "1 UNION SELECT password".to_owned()),
                ("q".to_owned(), "<script>alert(1)</script>".to_owned()),
            ],
            headers: &[],
            content_type: "",
            raw_body: "",
        };
        let verdict = scan_request(&surfaces, &exclusions, &corpus_config());
        assert!(verdict.is_threat);
        assert!(
            !verdict.categories.contains(&"sqli".to_owned()),
            "the excluded param did not contribute"
        );
        // Case-insensitive: DEBUG is excluded too.
        let surfaces = RequestSurfaces {
            url_path: Some("/search"),
            query_params: &[("DEBUG".to_owned(), "1 UNION SELECT password".to_owned())],
            headers: &[],
            content_type: "",
            raw_body: "",
        };
        assert!(!scan_request(&surfaces, &exclusions, &corpus_config()).is_threat);
    }

    #[test]
    fn excluded_body_field_skips_only_that_field() {
        let global = DetectionExclusionConfig {
            excluded_detection_body_fields: vec!["secret".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let exclusions = resolve(Some(&global), None);
        let surfaces = RequestSurfaces {
            url_path: Some("/api"),
            query_params: &[],
            headers: &[],
            content_type: "application/x-www-form-urlencoded",
            raw_body: "secret=1 UNION SELECT password&safe=<script>alert(1)</script>",
        };
        let verdict = scan_request(&surfaces, &exclusions, &corpus_config());
        assert!(verdict.is_threat, "the untouched field still scans");
        assert_eq!(verdict.categories, vec!["xss"]);

        // And the excluded field alone is clean.
        let surfaces = RequestSurfaces {
            url_path: Some("/api"),
            query_params: &[],
            headers: &[],
            content_type: "application/x-www-form-urlencoded",
            raw_body: "secret=1 UNION SELECT password",
        };
        assert!(!scan_request(&surfaces, &exclusions, &corpus_config()).is_threat);
    }

    #[test]
    fn excluded_header_with_attack_payload_still_detects() {
        let exclusions = resolve(None, None);
        let surfaces = RequestSurfaces {
            url_path: Some("/x"),
            query_params: &[],
            headers: &[(
                "x-custom".to_owned(),
                "<script>alert(1)</script>".to_owned(),
            )],
            content_type: "",
            raw_body: "",
        };
        let verdict = scan_request(&surfaces, &exclusions, &corpus_config());
        assert!(verdict.is_threat, "an excluded header is not a skip hole");
        assert_eq!(verdict.categories, vec!["xss"]);
    }

    #[test]
    fn address_chain_headers_skip_ssrf_only() {
        // A whole address chain in an unlisted excluded header reads as a
        // proxy chain, not an ssrf probe.
        let chain = "10.0.0.5, 172.16.0.1";
        assert_eq!(
            excluded_header_skip_categories("x-custom", chain),
            &["ssrf"][..]
        );
        assert_eq!(
            excluded_header_skip_categories("via", chain),
            &["ssrf"][..],
            "the address-carrying name skips for any value"
        );
        assert_eq!(
            excluded_header_skip_categories("x-custom", "<script>alert(1)</script>"),
            &[] as &[&str],
            "a non-address value skips nothing"
        );
        assert_eq!(
            excluded_header_skip_categories("x-custom", "10.0.0.5, not-an-ip"),
            &[] as &[&str],
            "one non-address token breaks the chain"
        );
    }

    #[test]
    fn port_stripping_feeds_the_address_parser() {
        assert_eq!(strip_forwarded_entry_port("1.2.3.4:8080"), "1.2.3.4");
        assert_eq!(strip_forwarded_entry_port("[::1]:8080"), "::1");
        assert_eq!(strip_forwarded_entry_port("::1"), "::1");
        assert_eq!(strip_forwarded_entry_port("not-an-ip"), "not-an-ip");
        assert_eq!(
            strip_forwarded_entry_port("[::1]:nope"),
            "[::1]:nope",
            "a non-numeric port keeps the value unparsed"
        );
        assert!(
            value_looks_like_address_chain("1.2.3.4:8080, [::1]:8080"),
            "socket-literal entries parse once the port is stripped"
        );
    }

    #[test]
    fn filtered_out_threat_ends_the_scan_clean() {
        // The reference's terminal per-value filter: a threat whose
        // categories are all disabled ends the scan with a clean verdict
        // instead of continuing to later values.
        let route = RouteDetectionExclusions {
            enabled_detection_categories: Some(vec!["xss".to_owned()]),
            ..RouteDetectionExclusions::default()
        };
        let exclusions = resolve(None, Some(&route));
        let surfaces = RequestSurfaces {
            url_path: Some("/x"),
            query_params: &[("q".to_owned(), "1 UNION SELECT password".to_owned())],
            headers: &[],
            content_type: "",
            raw_body: "",
        };
        let verdict = scan_request(&surfaces, &exclusions, &corpus_config());
        assert!(!verdict.is_threat);
        assert!(verdict.categories.is_empty());
    }

    #[test]
    fn enabled_categories_route_the_verdict() {
        let route = RouteDetectionExclusions {
            enabled_detection_categories: Some(vec!["sqli".to_owned()]),
            ..RouteDetectionExclusions::default()
        };
        let exclusions = resolve(None, Some(&route));
        let surfaces = RequestSurfaces {
            url_path: Some("/x"),
            query_params: &[("q".to_owned(), "1 UNION SELECT password".to_owned())],
            headers: &[(
                "x-payload".to_owned(),
                "<script>alert(1)</script>".to_owned(),
            )],
            content_type: "",
            raw_body: "",
        };
        let verdict = scan_request(&surfaces, &exclusions, &corpus_config());
        assert!(verdict.is_threat);
        assert_eq!(verdict.categories, vec!["sqli"]);
        assert!(verdict.reason.contains("sqli"));
        assert!(!verdict.reason.contains("xss"), "xss is not enabled here");
    }

    #[test]
    fn mongo_operator_keys_hit_through_the_body_walk() {
        let exclusions = resolve(None, None);
        let surfaces = RequestSurfaces {
            url_path: Some("/x"),
            query_params: &[],
            headers: &[],
            content_type: "application/json",
            raw_body: "{\"$where\": \"1 OR 1=1\"}",
        };
        let verdict = scan_request(&surfaces, &exclusions, &corpus_config());
        assert!(verdict.is_threat);
        assert_eq!(verdict.categories, vec!["nosql"]);
    }

    #[test]
    fn route_toggles_and_liveness_mirror_the_reference() {
        // Request-time: the route flag overrides both directions.
        assert!(detection_enabled(false, Some(true)));
        assert!(!detection_enabled(true, Some(false)));
        assert!(detection_enabled(true, None));
        assert!(!detection_enabled(false, None));

        // Check-set liveness: alive while any route enables the toggle.
        assert!(check_applies(false, [false, true], false));
        assert!(!check_applies(false, [false, false], false));
        assert!(check_applies(true, [], false));
        assert!(
            check_applies(false, [false], true),
            "dynamic rules keep it alive"
        );
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    fn config() -> DetectConfig {
        DetectConfig {
            max_content_length: 10_000,
            max_full_scan_bytes: 262_144,
            preserve_attack_patterns: true,
            semantic_threshold: 0.7,
            threat_score_threshold: 1.0,
            binary_min_run_length: 16,
        }
    }

    #[test]
    fn an_unterminated_bracket_entry_keeps_its_port_text() {
        assert_eq!(strip_forwarded_entry_port("[::1"), "[::1");
    }

    #[test]
    fn a_chain_of_only_empty_tokens_is_not_an_address_chain() {
        assert!(!value_looks_like_address_chain(" , ,, "));
    }

    #[test]
    fn empty_header_values_never_scan() {
        let exclusions = ResolvedExclusions {
            excluded_params: std::collections::HashSet::new(),
            excluded_headers: std::collections::HashSet::new(),
            excluded_body_fields: std::collections::HashSet::new(),
            enabled_categories: None,
            scan_body: false,
        };
        let headers = vec![
            ("x-empty".to_owned(), String::new()),
            ("x-attack".to_owned(), "10.0.0.5, 127.0.0.1".to_owned()),
        ];
        let verdict = scan_request(
            &RequestSurfaces {
                url_path: None,
                query_params: &[],
                headers: &headers,
                content_type: "",
                raw_body: "",
            },
            &exclusions,
            &config(),
        );
        // only the non-empty header scans
        assert!(verdict.is_threat);
        assert_eq!(verdict.categories, vec!["ssrf".to_owned()]);
    }

    #[test]
    fn an_excluded_address_header_suppresses_its_ssrf_category() {
        let mut excluded_headers = std::collections::HashSet::new();
        excluded_headers.insert("x-forwarded-for".to_owned());
        let exclusions = ResolvedExclusions {
            excluded_params: std::collections::HashSet::new(),
            excluded_headers,
            excluded_body_fields: std::collections::HashSet::new(),
            enabled_categories: None,
            scan_body: false,
        };
        let headers = vec![(
            "x-forwarded-for".to_owned(),
            "10.0.0.5, 127.0.0.1".to_owned(),
        )];
        let verdict = scan_request(
            &RequestSurfaces {
                url_path: None,
                query_params: &[],
                headers: &headers,
                content_type: "",
                raw_body: "",
            },
            &exclusions,
            &config(),
        );
        // the ssrf category is filtered out, and with nothing left the scan
        // ends clean (the terminal per-value filter)
        assert!(!verdict.is_threat);
        assert!(verdict.categories.is_empty());
    }

    #[test]
    fn a_semantic_threat_contributes_no_category_to_the_reason() {
        // the obfuscated keyword blob trips the semantic analyzer alongside
        // the regex sqli hits: only the regex categories are reportable
        let content = format!(
            "select union insert update delete drop from where order group having concat \
             substring database table column (1 OR 1=1) {}",
            "A".repeat(120)
        );
        let verdict = scan_request(
            &RequestSurfaces {
                url_path: None,
                query_params: &[],
                headers: &[],
                content_type: "text/plain",
                raw_body: &content,
            },
            &ResolvedExclusions {
                excluded_params: std::collections::HashSet::new(),
                excluded_headers: std::collections::HashSet::new(),
                excluded_body_fields: std::collections::HashSet::new(),
                enabled_categories: None,
                scan_body: true,
            },
            &config(),
        );
        assert!(verdict.is_threat);
        assert_eq!(verdict.categories, vec!["sqli".to_owned()]);
    }
}
