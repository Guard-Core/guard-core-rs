//! Security headers management, ported from the reference handler.
//!
//! The engine owns the logic; adapters (and the conformance runner) apply
//! the returned map to their responses. [`security_headers`] ports
//! `get_headers` resolved against a `security_headers` dict: a disabled
//! configuration yields no headers, the class defaults apply, the
//! configured overrides replace the matching class header, the CSP and
//! HSTS blocks extend them, and the custom headers land last.
//!
//! Reference sources: `security_headers_handler.py`, its config mixin
//! (`_security_headers_config.py`), and the field defaults
//! (`_security_config_fields.py`).
//!
//! # Example
//!
//! ```
//! use guard_core_engine::security_headers::{security_headers, SecurityHeadersConfig};
//!
//! // The reference default block: the class defaults plus the
//! // max-age=31536000; includeSubDomains HSTS header.
//! let headers = security_headers(&SecurityHeadersConfig::reference_default());
//! assert_eq!(headers.get("X-Content-Type-Options").map(String::as_str), Some("nosniff"));
//! assert_eq!(
//!     headers.get("Strict-Transport-Security").map(String::as_str),
//!     Some("max-age=31536000; includeSubDomains")
//! );
//!
//! // Disabled: no headers at all (the reference `get_headers` early return).
//! let off = SecurityHeadersConfig {
//!     enabled: false,
//!     ..SecurityHeadersConfig::default()
//! };
//! assert!(security_headers(&off).is_empty());
//! ```

use std::collections::BTreeMap;

/// The reference `security_headers["hsts"]` block: `max_age`,
/// `include_subdomains`, `preload`.
///
/// `max_age: None` means no Strict-Transport-Security header, exactly
/// like the reference `hsts_config = None` when `max_age` is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HstsConfig {
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        // The reference security_headers dict default
        // (_security_config_fields.py security_headers).
        Self {
            max_age: Some(31_536_000),
            include_subdomains: true,
            preload: false,
        }
    }
}

/// One Content-Security-Policy directive with its sources, in the
/// insertion order the reference dict keeps (a Vec keeps the built header
/// deterministic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspDirective {
    pub name: String,
    pub sources: Vec<String>,
}

impl CspDirective {
    /// A directive with a single source list, the corpus shape.
    #[must_use]
    pub fn new(name: &str, sources: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            sources: sources.iter().map(|source| (*source).to_owned()).collect(),
        }
    }
}

/// The reference `security_headers` dict: `enabled`, `hsts`, `csp`,
/// `frame_options`, `content_type_options`, `xss_protection`,
/// `referrer_policy`, `permissions_policy`, and `custom`.
///
/// `None` in the override fields keeps the class default header (the
/// reference dict lookup returning no key); a set value overrides it. The
/// reference's three-way `permissions_policy` ("UNSET" sentinel keeps the
/// default, a falsy value removes the header) resolves the same way:
/// `None` keeps the default and an empty string removes the header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityHeadersConfig {
    pub enabled: bool,
    pub hsts: Option<HstsConfig>,
    pub csp: Vec<CspDirective>,
    pub frame_options: Option<String>,
    pub content_type_options: Option<String>,
    pub xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    /// `None` keeps the class default, `Some("")` removes the header, any
    /// other value overrides it.
    pub permissions_policy: Option<String>,
    pub custom: BTreeMap<String, String>,
}

impl SecurityHeadersConfig {
    /// The reference `SecurityConfig.security_headers` default block
    /// (`_security_config_fields.py`): enabled, HSTS
    /// max-age=31536000+includeSubDomains, no CSP, SAMEORIGIN / nosniff /
    /// `1; mode=block` / strict-origin-when-cross-origin, the camera and
    /// microphone lockdown Permissions-Policy, no custom headers.
    #[must_use]
    pub fn reference_default() -> Self {
        Self {
            enabled: true,
            hsts: Some(HstsConfig::default()),
            csp: Vec::new(),
            frame_options: Some("SAMEORIGIN".to_owned()),
            content_type_options: Some("nosniff".to_owned()),
            xss_protection: Some("1; mode=block".to_owned()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_owned()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_owned()),
            custom: BTreeMap::new(),
        }
    }

    /// Validate the configured values the way the reference `configure()`
    /// raises out of `_validate_header_name` / `_validate_header_value`:
    /// a custom name must be a non-empty RFC 7230 token, and no configured
    /// value may carry CR/LF, exceed 8192 bytes, or (after sanitization)
    /// keep control characters below 0x20 other than tab.
    ///
    /// # Errors
    ///
    /// [`SecurityHeadersError`] naming the offending header on the first
    /// invalid entry.
    pub fn validate(&self) -> Result<(), SecurityHeadersError> {
        for (name, value) in &self.custom {
            if !is_valid_header_name(name) {
                return Err(SecurityHeadersError::InvalidName { name: name.clone() });
            }
            validate_header_value(value).map_err(|reason| SecurityHeadersError::InvalidValue {
                name: name.clone(),
                reason,
            })?;
        }
        for (name, value) in [
            ("X-Frame-Options", &self.frame_options),
            ("X-Content-Type-Options", &self.content_type_options),
            ("X-XSS-Protection", &self.xss_protection),
            ("Referrer-Policy", &self.referrer_policy),
            ("Permissions-Policy", &self.permissions_policy),
        ] {
            if let Some(value) = value {
                validate_header_value(value).map_err(|reason| {
                    SecurityHeadersError::InvalidValue {
                        name: name.to_owned(),
                        reason,
                    }
                })?;
            }
        }
        Ok(())
    }
}

/// A rejected security-headers configuration: the reference raises out of
/// `configure()`, so a deployment never starts with these values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityHeadersError {
    /// A custom header name that is not an RFC 7230 token.
    InvalidName {
        /// The rejected name.
        name: String,
    },
    /// A header value carrying a newline, exceeding 8192 bytes, or
    /// otherwise unsanitizable.
    InvalidValue {
        /// The header the value belongs to.
        name: String,
        /// Why the value was rejected.
        reason: &'static str,
    },
}

impl std::fmt::Display for SecurityHeadersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName { name } => write!(f, "invalid header name: {name}"),
            Self::InvalidValue { name, reason } => {
                write!(f, "invalid value for header {name}: {reason}")
            }
        }
    }
}

impl std::error::Error for SecurityHeadersError {}

/// `_HEADER_NAME_TOKEN_RE`: a non-empty RFC 7230 token.
#[must_use]
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| matches!(c, '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~' | '0'..='9' | 'A'..='Z' | 'a'..='z'))
}

const MAX_HEADER_VALUE_BYTES: usize = 8192;

/// `_validate_header_value`: no CR/LF, at most 8192 bytes, control
/// characters below 0x20 dropped except tab.
///
/// # Errors
///
/// A static reason string naming the first violated rule.
pub fn validate_header_value(value: &str) -> Result<String, &'static str> {
    if value.contains('\r') || value.contains('\n') {
        return Err("invalid header value contains newline");
    }
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return Err("header value too long");
    }
    Ok(value.chars().filter(|c| *c >= ' ' || *c == '\t').collect())
}

/// `_build_csp`: "directive source1 source2" joined with "; ", bare
/// directives kept when they carry no sources.
#[must_use]
pub fn build_csp(csp: &[CspDirective]) -> String {
    csp.iter()
        .map(|directive| {
            if directive.sources.is_empty() {
                directive.name.clone()
            } else {
                format!("{} {}", directive.name, directive.sources.join(" "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `_build_hsts` plus the `_compute_hsts_config` preload corrections.
///
/// Preload requires `max_age >= 31536000` and includeSubDomains (the
/// reference logs a warning and drops/corrects the flag instead of
/// rejecting).
#[must_use]
pub fn build_hsts(hsts: &HstsConfig) -> Option<String> {
    let max_age = hsts.max_age?;
    let mut preload = hsts.preload;
    let mut include_subdomains = hsts.include_subdomains;
    if preload {
        if max_age < 31_536_000 {
            preload = false;
        }
        if !include_subdomains {
            include_subdomains = true;
        }
    }
    let mut parts = vec![format!("max-age={max_age}")];
    if include_subdomains {
        parts.push("includeSubDomains".to_owned());
    }
    if preload {
        parts.push("preload".to_owned());
    }
    Some(parts.join("; "))
}

/// `SecurityHeadersManager.default_headers`, in table order.
pub const CLASS_DEFAULT_HEADERS: [(&str, &str); 10] = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "SAMEORIGIN"),
    ("X-XSS-Protection", "1; mode=block"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    (
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
    ),
    ("X-Permitted-Cross-Domain-Policies", "none"),
    ("X-Download-Options", "noopen"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
];

/// `SecurityHeadersManager.get_headers` resolved against the reference
/// `security_headers` dict.
///
/// A disabled configuration yields no headers, the class defaults apply,
/// the configured overrides replace the matching class header, the CSP
/// and HSTS blocks extend them, and the custom headers land last.
#[must_use]
pub fn security_headers(config: &SecurityHeadersConfig) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    if !config.enabled {
        return headers;
    }
    for (name, value) in CLASS_DEFAULT_HEADERS {
        headers.insert(name.to_owned(), value.to_owned());
    }
    for (name, value) in [
        ("X-Frame-Options", &config.frame_options),
        ("X-Content-Type-Options", &config.content_type_options),
        ("X-XSS-Protection", &config.xss_protection),
        ("Referrer-Policy", &config.referrer_policy),
    ] {
        if let Some(value) = value {
            headers.insert(name.to_owned(), value.clone());
        }
    }
    match &config.permissions_policy {
        Some(value) if value.is_empty() => {
            headers.remove("Permissions-Policy");
        }
        Some(value) => {
            headers.insert("Permissions-Policy".to_owned(), value.clone());
        }
        None => {}
    }
    if !config.csp.is_empty() {
        headers.insert("Content-Security-Policy".to_owned(), build_csp(&config.csp));
    }
    if let Some(hsts) = config.hsts.as_ref()
        && let Some(header) = build_hsts(hsts)
    {
        headers.insert("Strict-Transport-Security".to_owned(), header);
    }
    for (name, value) in &config.custom {
        headers.insert(name.clone(), value.clone());
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_default_matches_the_corpus_default_set() {
        let headers = security_headers(&SecurityHeadersConfig::reference_default());
        assert_eq!(headers.len(), 11, "the ten class defaults plus HSTS");
        assert_eq!(
            headers.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(
            headers.get("X-Frame-Options").map(String::as_str),
            Some("SAMEORIGIN")
        );
        assert!(!headers.contains_key("Content-Security-Policy"));
    }

    #[test]
    fn disabled_yields_no_headers() {
        let config = SecurityHeadersConfig {
            enabled: false,
            ..SecurityHeadersConfig::reference_default()
        };
        assert!(security_headers(&config).is_empty());
    }

    #[test]
    fn overrides_custom_csp_and_hsts_compose_like_the_reference() {
        let config = SecurityHeadersConfig {
            enabled: true,
            hsts: Some(HstsConfig {
                max_age: Some(63_072_000),
                include_subdomains: true,
                preload: false,
            }),
            csp: vec![CspDirective::new("default-src", &["'self'"])],
            frame_options: Some("DENY".to_owned()),
            content_type_options: None,
            xss_protection: None,
            referrer_policy: None,
            permissions_policy: None,
            custom: BTreeMap::from([("X-Custom-Header".to_owned(), "custom-value".to_owned())]),
        };
        let headers = security_headers(&config);
        assert_eq!(
            headers.get("X-Frame-Options").map(String::as_str),
            Some("DENY")
        );
        assert_eq!(
            headers.get("Content-Security-Policy").map(String::as_str),
            Some("default-src 'self'")
        );
        assert_eq!(
            headers.get("Strict-Transport-Security").map(String::as_str),
            Some("max-age=63072000; includeSubDomains")
        );
        assert_eq!(
            headers.get("X-Custom-Header").map(String::as_str),
            Some("custom-value")
        );
        assert_eq!(
            headers.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff"),
            "a None override keeps the class default"
        );
    }

    #[test]
    fn empty_permissions_policy_removes_the_header() {
        let config = SecurityHeadersConfig {
            permissions_policy: Some(String::new()),
            ..SecurityHeadersConfig::reference_default()
        };
        assert!(!security_headers(&config).contains_key("Permissions-Policy"));
    }

    #[test]
    fn csp_bare_directives_survive_the_build() {
        let csp = vec![
            CspDirective::new("default-src", &["'self'", "https:"]),
            CspDirective::new("upgrade-insecure-requests", &[]),
        ];
        assert_eq!(
            build_csp(&csp),
            "default-src 'self' https:; upgrade-insecure-requests"
        );
    }

    #[test]
    fn hsts_preload_corrections_apply() {
        let corrected = build_hsts(&HstsConfig {
            max_age: Some(1000),
            include_subdomains: false,
            preload: true,
        })
        .expect("max_age set");
        assert_eq!(
            corrected, "max-age=1000; includeSubDomains",
            "preload drops below the max-age floor and forces includeSubDomains"
        );
        let full = build_hsts(&HstsConfig {
            max_age: Some(31_536_000),
            include_subdomains: true,
            preload: true,
        })
        .expect("max_age set");
        assert_eq!(full, "max-age=31536000; includeSubDomains; preload");
        assert!(
            build_hsts(&HstsConfig {
                max_age: None,
                include_subdomains: true,
                preload: false,
            })
            .is_none()
        );
    }

    #[test]
    fn validation_rejects_the_reference_failures() {
        let bad_name = SecurityHeadersConfig {
            custom: BTreeMap::from([("bad name\n".to_owned(), "v".to_owned())]),
            ..SecurityHeadersConfig::reference_default()
        };
        assert!(matches!(
            bad_name.validate(),
            Err(SecurityHeadersError::InvalidName { .. })
        ));
        let bad_value = SecurityHeadersConfig {
            frame_options: Some("DENY\r\nX-Evil: 1".to_owned()),
            ..SecurityHeadersConfig::reference_default()
        };
        assert_eq!(
            bad_value.validate(),
            Err(SecurityHeadersError::InvalidValue {
                name: "X-Frame-Options".to_owned(),
                reason: "invalid header value contains newline",
            })
        );
        let long = SecurityHeadersConfig {
            frame_options: Some("x".repeat(MAX_HEADER_VALUE_BYTES + 1)),
            ..SecurityHeadersConfig::reference_default()
        };
        assert!(matches!(
            long.validate(),
            Err(SecurityHeadersError::InvalidValue {
                reason: "header value too long",
                ..
            })
        ));
        assert!(
            SecurityHeadersConfig::reference_default()
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn header_value_sanitization_drops_control_characters_except_tab() {
        assert_eq!(
            validate_header_value("a\u{8}b\tc").expect("sanitizable"),
            "ab\tc"
        );
        assert!(is_valid_header_name("X-Custom-Header"));
        assert!(!is_valid_header_name("X Custom"));
        assert!(!is_valid_header_name(""));
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;

    #[test]
    fn a_custom_header_with_an_unsanitizable_value_is_rejected() {
        let config = SecurityHeadersConfig {
            custom: std::iter::once(("X-Custom".to_owned(), "bad\nvalue".to_owned())).collect(),
            ..SecurityHeadersConfig::reference_default()
        };
        let error = config.validate().expect_err("newline value");
        assert_eq!(
            error,
            SecurityHeadersError::InvalidValue {
                name: "X-Custom".to_owned(),
                reason: validate_header_value("bad\nvalue").unwrap_err(),
            }
        );
    }

    #[test]
    fn an_invalid_custom_header_name_displays_the_reference_message() {
        let config = SecurityHeadersConfig {
            custom: std::iter::once(("X Custom".to_owned(), "value".to_owned())).collect(),
            ..SecurityHeadersConfig::reference_default()
        };
        let error = config.validate().expect_err("space in name");
        assert_eq!(error.to_string(), "invalid header name: X Custom");
    }
}

#[cfg(test)]
mod unit_twins {
    use super::*;

    #[test]
    fn a_valid_optional_header_passes_validation() {
        // a populated fixed header (frame options) walks the Some arm of
        // the fixed-header loop and validates clean
        let config = SecurityHeadersConfig {
            frame_options: Some("DENY".to_owned()),
            ..SecurityHeadersConfig::reference_default()
        };
        assert!(config.validate().is_ok());
        // unset fixed headers skip their arm and still validate clean
        let config = SecurityHeadersConfig {
            frame_options: None,
            content_type_options: None,
            xss_protection: None,
            referrer_policy: None,
            permissions_policy: None,
            custom: std::collections::BTreeMap::new(),
            ..SecurityHeadersConfig::reference_default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn the_error_variants_display_the_reference_messages() {
        let name_error = SecurityHeadersError::InvalidName {
            name: "X Custom".to_owned(),
        };
        assert_eq!(name_error.to_string(), "invalid header name: X Custom");
        let value_error = SecurityHeadersError::InvalidValue {
            name: "X-Custom".to_owned(),
            reason: "control character",
        };
        assert_eq!(
            value_error.to_string(),
            "invalid value for header X-Custom: control character"
        );
    }
}
