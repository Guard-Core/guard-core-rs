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
