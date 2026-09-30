//! The route referrer gate: the reference pipeline's eighth check.
//!
//! This is the Rust family's port of
//! `guard_core/core/checks/implementations/referrer.py` plus its matcher
//! `guard_core/core/checks/helpers.py::is_referrer_domain_allowed`. A route
//! with `require_referrer` (a list of allowed domains) admits requests
//! whose `referer` header carries a host the list allows:
//!
//! ```text
//! missing (empty) referer header:  Missing (the reference's
//!                                  403 "Referrer required")
//! host of the referer URL equals an allowed entry's host
//!   (both lowercased) or is a subdomain of it:  Allowed
//! anything else:                   Invalid (the reference's
//!                                  403 "Invalid referrer")
//! ```
//!
//! ## Details that mirror the reference exactly
//!
//! - The wire header is `referer` (the historic HTTP spelling; the check
//!   is *named* referrer).
//! - An allowed entry may be a bare domain (`example.com`), a
//!   path-suffixed domain (`example.com/page`), or a full URL
//!   (`https://example.com/page`) - the entry is normalized to its host:
//!   a `scheme://` entry is parsed to its netloc, anything else is cut at
//!   the first `/`, all lowercased (`_normalize_allowed_referrer_domain`).
//! - The referer's host is its URL netloc, lowercased; a referer with no
//!   scheme parses to an empty netloc (Python's `urlparse`), which never
//!   matches a non-empty entry.
//! - The subdomain arm is exact: `endswith("." + domain)`, so
//!   `notexample.com` never matches `example.com` while
//!   `api.example.com` does.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::referrer::{decide, ReferrerVerdict};
//!
//! let allowed = vec!["example.com".to_owned()];
//! assert_eq!(
//!     decide(Some("https://example.com/page"), &allowed),
//!     ReferrerVerdict::Allowed
//! );
//! assert_eq!(
//!     decide(Some("https://api.example.com/x"), &allowed),
//!     ReferrerVerdict::Allowed
//! );
//! assert_eq!(
//!     decide(Some("https://notexample.com/"), &allowed),
//!     ReferrerVerdict::Invalid { referrer: "https://notexample.com/".to_owned() }
//! );
//! assert_eq!(decide(None, &allowed), ReferrerVerdict::Missing);
//! ```

/// The check's stable name (`check_name`).
pub const REFERRER_CHECK_NAME: &str = "referrer";

/// The missing-referrer block status (`403 "Referrer required"`).
pub const REFERRER_MISSING_STATUS: u16 = 403;
/// The missing-referrer block body.
pub const REFERRER_MISSING_BODY: &str = "Referrer required";
/// The invalid-referrer block status (`403 "Invalid referrer"`).
pub const REFERRER_INVALID_STATUS: u16 = 403;
/// The invalid-referrer block body.
pub const REFERRER_INVALID_BODY: &str = "Invalid referrer";

/// What [`decide`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferrerVerdict {
    /// The referer host is allowed (or the route required no referrer).
    Allowed,
    /// The `referer` header is absent or empty: the reference's
    /// `"Referrer required"` shape.
    Missing,
    /// The referer is present but its host is not allowed: the reference's
    /// `"Invalid referrer"` shape, carrying the raw value (the stage
    /// redacts it for logs and events, exactly the reference).
    Invalid {
        /// The raw `referer` header value.
        referrer: String,
    },
}

/// The URL's netloc, the piece of `urlparse` the matcher reads.
///
/// The authority after `scheme://`, cut at the first `/`, `?`, or `#`. A
/// URL without a scheme parses to an empty netloc, exactly like Python's
/// `urlparse` (which then reads the whole text as the path).
#[must_use]
pub fn url_netloc(url: &str) -> &str {
    let Some(rest) = url.split_once("://").map(|(_, after)| after) else {
        return "";
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    &rest[..end]
}

/// An allowed entry normalized to its host (`_normalize_allowed_referrer_domain`):
/// a `scheme://` entry parses to its netloc, anything else is lowercased
/// and cut at the first `/`.
#[must_use]
pub fn normalize_allowed_domain(entry: &str) -> String {
    if entry.contains("://") {
        url_netloc(entry).to_lowercase()
    } else {
        let lowered = entry.to_lowercase();
        match lowered.find('/') {
            Some(slash) => lowered[..slash].to_owned(),
            None => lowered,
        }
    }
}

/// The reference matcher: the referer's host equals an allowed entry's
/// host (both lowercased) or is a subdomain of it.
#[must_use]
pub fn is_referrer_domain_allowed(referrer: &str, allowed_domains: &[String]) -> bool {
    let referrer_domain = url_netloc(referrer).to_lowercase();
    for allowed in allowed_domains {
        let normalized = normalize_allowed_domain(allowed);
        if referrer_domain == normalized || referrer_domain.ends_with(&format!(".{normalized}")) {
            return true;
        }
    }
    false
}

/// The reference check body: an absent or empty `referer` is missing, a
/// host the list allows passes, everything else is invalid.
///
/// `referrer` is the raw header value; `None` when the header is absent.
/// A route with no configured list never reaches this decision (the
/// reference returns before reading the header), but the shape mirrors it
/// anyway: an empty list allows nothing, so callers gate on the route
/// first.
#[must_use]
pub fn decide(referrer: Option<&str>, allowed_domains: &[String]) -> ReferrerVerdict {
    let Some(raw) = referrer else {
        return ReferrerVerdict::Missing;
    };
    if raw.is_empty() {
        return ReferrerVerdict::Missing;
    }
    if is_referrer_domain_allowed(raw, allowed_domains) {
        ReferrerVerdict::Allowed
    } else {
        ReferrerVerdict::Invalid {
            referrer: raw.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    #[test]
    fn netloc_extraction_matches_urlparse_shapes() {
        assert_eq!(url_netloc("https://example.com/path"), "example.com");
        assert_eq!(
            url_netloc("http://example.com:8080/x?y=1#z"),
            "example.com:8080"
        );
        assert_eq!(
            url_netloc("https://user:pw@example.com/"),
            "user:pw@example.com"
        );
        assert_eq!(url_netloc("https://example.com"), "example.com");
        // No scheme: urlparse reads no netloc at all.
        assert_eq!(url_netloc("example.com/path"), "");
        assert_eq!(url_netloc(""), "");
    }

    #[test]
    fn allowed_entry_normalization_covers_the_three_shapes() {
        assert_eq!(normalize_allowed_domain("Example.COM"), "example.com");
        assert_eq!(
            normalize_allowed_domain("example.com/page"),
            "example.com",
            "a path-suffixed entry is cut at the first slash"
        );
        assert_eq!(
            normalize_allowed_domain("https://Example.com/page"),
            "example.com",
            "a full-URL entry parses to its netloc"
        );
    }

    #[test]
    fn exact_and_subdomain_hosts_pass_others_fail() {
        let domains = allowed(&["example.com"]);
        assert!(is_referrer_domain_allowed(
            "https://example.com/x",
            &domains
        ));
        assert!(is_referrer_domain_allowed(
            "https://EXAMPLE.com/x",
            &domains
        ));
        assert!(is_referrer_domain_allowed(
            "https://api.example.com/x",
            &domains
        ));
        assert!(
            !is_referrer_domain_allowed("https://notexample.com/x", &domains),
            "the subdomain arm is endswith(.domain), never a substring test"
        );
        assert!(
            !is_referrer_domain_allowed("https://example.com.evil.test/x", &domains),
            "a suffixed host is not a subdomain"
        );
        assert!(!is_referrer_domain_allowed(
            "https://other.test/x",
            &domains
        ));
    }

    #[test]
    fn schemeless_referrers_have_no_host_and_fail() {
        let domains = allowed(&["example.com"]);
        assert!(!is_referrer_domain_allowed("example.com", &domains));
    }

    #[test]
    fn decide_splits_missing_allowed_invalid() {
        let domains = allowed(&["example.com"]);
        assert_eq!(decide(None, &domains), ReferrerVerdict::Missing);
        assert_eq!(decide(Some(""), &domains), ReferrerVerdict::Missing);
        assert_eq!(
            decide(Some("https://example.com/"), &domains),
            ReferrerVerdict::Allowed
        );
        assert_eq!(
            decide(Some("https://evil.test/"), &domains),
            ReferrerVerdict::Invalid {
                referrer: "https://evil.test/".to_owned()
            }
        );
    }

    #[test]
    fn multiple_entries_allow_any_match() {
        let domains = allowed(&["a.test", "https://b.test/page"]);
        assert_eq!(
            decide(Some("https://a.test/x"), &domains),
            ReferrerVerdict::Allowed
        );
        assert_eq!(
            decide(Some("https://b.test/y"), &domains),
            ReferrerVerdict::Allowed
        );
        assert_eq!(
            decide(Some("https://c.test/y"), &domains),
            ReferrerVerdict::Invalid {
                referrer: "https://c.test/y".to_owned()
            }
        );
    }
}
