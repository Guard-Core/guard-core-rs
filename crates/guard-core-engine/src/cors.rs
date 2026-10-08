//! CORS handling, ported from the reference response-side CORS surface.
//!
//! The engine owns the verdict; adapters (and the conformance runner)
//! apply the returned map to their responses, composing on top of the
//! security-header set exactly like `apply_cors_headers`. Reference
//! sources: `get_cors_headers` (`_security_headers_cors.py`), the config
//! resolution (`_compute_cors_config`), and the `SecurityConfig` CORS
//! field defaults.
//!
//! The wildcard + credentials misconfiguration is NOT rejected: the
//! reference `_compute_cors_config` logs an error and drops the
//! credentials flag at resolution time, so the wildcard policy answers
//! without the allow-credentials header (the browser blocks credentialed
//! CORS), and a disallowed origin simply gets no CORS headers (the browser
//! enforces).
//!
//! # Example
//!
//! ```
//! use guard_core_engine::cors::{CorsConfig, cors_response_headers};
//!
//! let cors = CorsConfig {
//!     enabled: true,
//!     allow_origins: vec!["https://app.example.com".to_owned()],
//!     ..CorsConfig::default()
//! };
//! let headers = cors_response_headers(&cors, Some("https://app.example.com"));
//! assert_eq!(
//!     headers.get("Access-Control-Allow-Origin").map(String::as_str),
//!     Some("https://app.example.com")
//! );
//! assert_eq!(
//!     headers.get("Access-Control-Allow-Methods").map(String::as_str),
//!     Some("GET, POST, PUT, PATCH, DELETE, OPTIONS")
//! );
//!
//! // A disallowed origin gets nothing (the browser enforces).
//! assert!(cors_response_headers(&cors, Some("https://evil.example.com")).is_empty());
//! ```

use std::collections::BTreeMap;

/// The resolved CORS configuration: `_compute_cors_config`'s returned
/// state, with the `SecurityConfig` CORS field defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsConfig {
    /// The reference `enable_cors` (`false` by default): a disabled switch
    /// means no CORS headers on any response.
    pub enabled: bool,
    /// The allowed origins; `"*"` is the wildcard origin.
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    /// The reference `cors_max_age` (600 by default): the preflight
    /// cache lifetime the `Access-Control-Max-Age` header carries.
    pub max_age: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_origins: vec!["*".to_owned()],
            allow_methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            allow_headers: vec!["*".to_owned()],
            allow_credentials: false,
            max_age: 600,
        }
    }
}

/// `_compute_cors_config`'s wildcard + credentials downgrade, in place.
///
/// The reference does not reject the combination: it logs an error and
/// drops the credentials flag at resolution time (a CORS-disabled config
/// resolves to no CORS surface upstream).
pub fn downgrade_wildcard_credentials(cors: &mut CorsConfig) {
    if cors.allow_origins.iter().any(|origin| origin == "*") && cors.allow_credentials {
        cors.allow_credentials = false;
    }
}

/// `_is_origin_allowed`: the wildcard or exact membership.
#[must_use]
pub fn is_origin_allowed(origin: &str, allowed_origins: &[String]) -> bool {
    allowed_origins.iter().any(|allowed| allowed == "*")
        || allowed_origins.iter().any(|allowed| allowed == origin)
}

/// `get_cors_headers` composed with `_build_cors_headers`.
///
/// No CORS headers without an enabled config or for a disallowed origin;
/// otherwise the echoed origin (or `"*"` for a wildcard policy), the
/// joined methods and headers lists, the hardcoded 3600 max-age, and the
/// allow-credentials header only when the (already downgraded)
/// configuration still carries credentials. `origin` is the request's
/// `Origin` header value; `None` (or an empty value, the reference falsy
/// check) means the request carries no Origin and gets no CORS headers.
#[must_use]
pub fn cors_response_headers(cors: &CorsConfig, origin: Option<&str>) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    let origin = match origin.filter(|origin| !origin.is_empty()) {
        Some(origin) if cors.enabled => origin,
        _ => return headers,
    };
    if cors.allow_origins.is_empty() {
        return headers;
    }
    // `_is_wildcard_with_credentials`: a wildcard policy whose credentials
    // flag survived the resolution downgrade would block CORS entirely;
    // after `downgrade_wildcard_credentials` the flag is always off, so
    // this only fires on a hand-built un-downgraded config, exactly like
    // the reference's second line of defense.
    if cors.allow_origins.iter().any(|allowed| allowed == "*") && cors.allow_credentials {
        return headers;
    }
    if !is_origin_allowed(origin, &cors.allow_origins) {
        return headers;
    }
    let allow_origin =
        if cors.allow_origins.iter().any(|allowed| allowed == "*") && !cors.allow_credentials {
            "*".to_owned()
        } else {
            origin.to_owned()
        };
    headers.insert("Access-Control-Allow-Origin".to_owned(), allow_origin);
    headers.insert(
        "Access-Control-Allow-Methods".to_owned(),
        cors.allow_methods.join(", "),
    );
    headers.insert(
        "Access-Control-Allow-Headers".to_owned(),
        cors.allow_headers.join(", "),
    );
    headers.insert("Access-Control-Max-Age".to_owned(), "3600".to_owned());
    if cors.allow_credentials {
        headers.insert(
            "Access-Control-Allow-Credentials".to_owned(),
            "true".to_owned(),
        );
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allowed_preflight_answers_the_full_header_set() {
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://app.example.com".to_owned()],
            allow_methods: vec!["GET".to_owned(), "POST".to_owned()],
            allow_headers: vec!["content-type".to_owned(), "x-custom".to_owned()],
            allow_credentials: true,
            max_age: 900,
        };
        let answer = build_preflight_response(
            &cors,
            PreflightRequest {
                origin: Some("https://app.example.com"),
                request_method: Some("post"),
                request_headers_raw: Some("Content-Type, X-Custom"),
            },
        );
        assert_eq!(answer.status_code, 200);
        assert_eq!(answer.body, "OK");
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("https://app.example.com"),
            "credentials keep the exact origin (no wildcard echo)"
        );
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Allow-Methods")
                .map(String::as_str),
            Some("GET, POST")
        );
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Max-Age")
                .map(String::as_str),
            Some("900")
        );
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Allow-Credentials")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            answer.headers.get("Vary").map(String::as_str),
            Some("Origin")
        );
    }

    #[test]
    fn a_disallowed_preflight_answers_the_failure_list() {
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://app.example.com".to_owned()],
            allow_methods: vec!["GET".to_owned()],
            allow_headers: vec!["content-type".to_owned()],
            allow_credentials: false,
            max_age: 600,
        };
        let answer = build_preflight_response(
            &cors,
            PreflightRequest {
                origin: Some("https://evil.example.com"),
                request_method: Some("DELETE"),
                request_headers_raw: Some("X-Injected"),
            },
        );
        assert_eq!(answer.status_code, 400);
        assert_eq!(answer.body, "Disallowed CORS: origin, method, headers");
        // The failure still carries the method list, the max age, and Vary.
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Allow-Methods")
                .map(String::as_str),
            Some("GET")
        );
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Max-Age")
                .map(String::as_str),
            Some("600")
        );
        assert!(!answer.headers.contains_key("Access-Control-Allow-Origin"));
    }

    #[test]
    fn the_wildcard_config_downgrades_the_credentials_echo() {
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["*".to_owned()],
            allow_methods: vec!["PATCH".to_owned()],
            allow_headers: vec!["*".to_owned()],
            allow_credentials: false,
            max_age: 600,
        };
        let answer = build_preflight_response(
            &cors,
            PreflightRequest {
                origin: Some("https://any.example.com"),
                request_method: Some("PATCH"),
                request_headers_raw: Some("X-Anything"),
            },
        );
        assert_eq!(answer.status_code, 200);
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("*")
        );
        assert_eq!(
            answer
                .headers
                .get("Access-Control-Allow-Headers")
                .map(String::as_str),
            Some("X-Anything"),
            "the wildcard header policy echoes the requested list"
        );
    }

    #[test]
    fn is_preflight_needs_options_and_the_request_method_header() {
        let headers = vec![
            (
                String::from("Origin"),
                String::from("https://app.example.com"),
            ),
            (
                String::from("Access-Control-Request-Method"),
                String::from("POST"),
            ),
        ];
        assert!(is_preflight("OPTIONS", &headers));
        assert!(is_preflight("options", &headers));
        // A plain OPTIONS (no preflight header) is not a preflight.
        let plain = vec![(
            String::from("Origin"),
            String::from("https://app.example.com"),
        )];
        assert!(!is_preflight("OPTIONS", &plain));
        assert!(!is_preflight("GET", &headers));
    }

    #[test]
    fn wildcard_policy_with_downgraded_credentials_answers_the_wildcard() {
        // The corpus cors_wildcard_with_credentials_blocked shape: the
        // config asks for credentials with the wildcard, the resolution
        // drops the flag, and the response still answers "*" without the
        // allow-credentials header.
        let mut cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["*".to_owned()],
            allow_credentials: true,
            ..CorsConfig::default()
        };
        downgrade_wildcard_credentials(&mut cors);
        let headers = cors_response_headers(&cors, Some("https://app.example.com"));
        assert_eq!(
            headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("*")
        );
        assert!(!headers.contains_key("Access-Control-Allow-Credentials"));
        assert_eq!(
            headers
                .get("Access-Control-Allow-Methods")
                .map(String::as_str),
            Some("GET, POST, PUT, PATCH, DELETE, OPTIONS")
        );
        assert_eq!(
            headers
                .get("Access-Control-Allow-Headers")
                .map(String::as_str),
            Some("*")
        );
        assert_eq!(
            headers.get("Access-Control-Max-Age").map(String::as_str),
            Some("3600")
        );
    }

    #[test]
    fn allowed_origin_is_echoed() {
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://app.example.com".to_owned()],
            ..CorsConfig::default()
        };
        let headers = cors_response_headers(&cors, Some("https://app.example.com"));
        assert_eq!(
            headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("https://app.example.com")
        );
    }

    #[test]
    fn disallowed_origin_and_disabled_cors_get_nothing() {
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://app.example.com".to_owned()],
            ..CorsConfig::default()
        };
        assert!(cors_response_headers(&cors, Some("https://evil.example.com")).is_empty());
        assert!(
            cors_response_headers(
                &CorsConfig {
                    enabled: false,
                    ..CorsConfig::default()
                },
                Some("https://app.example.com")
            )
            .is_empty()
        );
        // No Origin header at all: no CORS headers.
        assert!(cors_response_headers(&cors, None).is_empty());
    }

    #[test]
    fn credentials_survive_for_an_exact_origin_policy() {
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://app.example.com".to_owned()],
            allow_credentials: true,
            ..CorsConfig::default()
        };
        let headers = cors_response_headers(&cors, Some("https://app.example.com"));
        assert_eq!(
            headers
                .get("Access-Control-Allow-Credentials")
                .map(String::as_str),
            Some("true")
        );
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn cors_headers_require_an_origin_and_a_nonempty_allowlist() {
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://good".to_owned()],
            ..CorsConfig::default()
        };
        // no Origin header: nothing emitted
        assert!(cors_response_headers(&cors, None).is_empty());
        // an empty Origin is falsy in the reference: nothing emitted
        assert!(cors_response_headers(&cors, Some("")).is_empty());
        // an empty allowlist: nothing emitted
        let empty = CorsConfig {
            enabled: true,
            allow_origins: Vec::new(),
            allow_methods: Vec::new(),
            allow_headers: Vec::new(),
            allow_credentials: false,
            max_age: 600,
        };
        assert!(cors_response_headers(&empty, Some("https://good")).is_empty());
    }

    #[test]
    fn cors_headers_block_undowngraded_wildcard_credentials() {
        // a hand-built wildcard policy that still carries credentials is
        // blocked outright (the second line of defense)
        let cors = CorsConfig {
            enabled: true,
            allow_origins: vec!["*".to_owned()],
            allow_credentials: true,
            ..CorsConfig::default()
        };
        assert!(cors_response_headers(&cors, Some("https://good")).is_empty());
    }
}

/// The preflight request header the reference gates an OPTIONS request on
/// (`ALLOWED_PREFLIGHT_REQUEST_HEADER`).
pub const ALLOWED_PREFLIGHT_REQUEST_HEADER: &str = "access-control-request-method";

/// The reference `is_preflight`: an `OPTIONS` method (case-insensitive)
/// carrying the `access-control-request-method` header.
#[must_use]
pub fn is_preflight(method: &str, request_headers: &[(String, String)]) -> bool {
    method.eq_ignore_ascii_case("OPTIONS")
        && request_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(ALLOWED_PREFLIGHT_REQUEST_HEADER))
}

/// The reference `build_preflight_response`'s request view: the three
/// headers the preflight validation reads (each already extracted by the
/// adapter from its own header map).
#[derive(Debug, Clone, Copy, Default)]
pub struct PreflightRequest<'a> {
    /// The `Origin` header value, if present.
    pub origin: Option<&'a str>,
    /// The `Access-Control-Request-Method` value, if present.
    pub request_method: Option<&'a str>,
    /// The raw `Access-Control-Request-Headers` value, if present.
    pub request_headers_raw: Option<&'a str>,
}

/// The reference `CorsPreflightResponse`: the status, the header set, and
/// the plain-text body the preflight answer renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsPreflightResponse {
    /// `200` for an allowed preflight, `400` for a disallowed one.
    pub status_code: u16,
    /// The CORS headers the answer carries (`Vary`, allow-origin,
    /// allow-methods, max-age, credentials, allow-headers).
    pub headers: BTreeMap<String, String>,
    /// `"OK"` allowed, `"Disallowed CORS: <failures>"` otherwise.
    pub body: String,
}

/// The reference `build_preflight_response` (`cors_handler.py`).
///
/// Validate the origin, the requested method, and the requested headers
/// against the resolved config; always carry the method list, the max
/// age, and the credentials flag; a failure answers `400` with the
/// joined failure list.
#[must_use]
pub fn build_preflight_response(
    cors: &CorsConfig,
    request: PreflightRequest<'_>,
) -> CorsPreflightResponse {
    let mut failures: Vec<&'static str> = Vec::new();
    let mut response_headers = BTreeMap::from([(String::from("Vary"), String::from("Origin"))]);

    // The origin arm (`_validate_preflight_origin`): an allowed origin
    // gets the wildcard (unless credentials downgrade it) or itself.
    let origin = request.origin.unwrap_or_default();
    if is_origin_allowed(origin, &cors.allow_origins) {
        let wildcard = cors.allow_origins.iter().any(|o| o == "*");
        let allow_origin = if wildcard && !cors.allow_credentials {
            "*"
        } else {
            origin
        };
        response_headers.insert(
            String::from("Access-Control-Allow-Origin"),
            allow_origin.to_owned(),
        );
    } else {
        failures.push("origin");
    }

    // The method arm: the uppercased request method must be listed.
    let requested_method = request
        .request_method
        .unwrap_or_default()
        .to_ascii_uppercase();
    if !cors
        .allow_methods
        .iter()
        .any(|method| method.to_ascii_uppercase() == requested_method)
    {
        failures.push("method");
    }

    // The headers arm (`_validate_preflight_headers`): the wildcard echoes
    // the requested list, a listed set rejects any unlisted name, and an
    // exact set echoes the raw value.
    let requested_headers: Vec<String> = request
        .request_headers_raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let requested_headers_raw = request.request_headers_raw.unwrap_or_default();
    let allow_all_headers = cors.allow_headers.iter().any(|h| h == "*");
    if allow_all_headers {
        if !requested_headers_raw.is_empty() {
            response_headers.insert(
                String::from("Access-Control-Allow-Headers"),
                requested_headers_raw.to_owned(),
            );
        }
    } else if requested_headers.iter().any(|name| {
        !cors
            .allow_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
    }) {
        failures.push("headers");
    }

    response_headers.insert(
        String::from("Access-Control-Allow-Methods"),
        cors.allow_methods.join(", "),
    );
    response_headers.insert(
        String::from("Access-Control-Max-Age"),
        cors.max_age.to_string(),
    );

    if cors.allow_credentials {
        response_headers.insert(
            String::from("Access-Control-Allow-Credentials"),
            String::from("true"),
        );
    }

    if failures.is_empty() {
        CorsPreflightResponse {
            status_code: 200,
            headers: response_headers,
            body: String::from("OK"),
        }
    } else {
        CorsPreflightResponse {
            status_code: 400,
            headers: response_headers,
            body: format!("Disallowed CORS: {}", failures.join(", ")),
        }
    }
}
