//! The HTTPS enforcement gate: the reference pipeline's third check.
//!
//! This is the Rust family's port of
//! `guard_core/core/checks/implementations/https_enforcement.py`. One call,
//! [`decide`], decides whether a request that reached the engine over plain
//! HTTP must be redirected to its `https` form:
//!
//! ```text
//! route require_https set:  the route verdict wins (Some(false) disables)
//! otherwise:                the global enforce_https knob decides
//! not required:             pass
//! request already https:    pass
//! trusted-proxy upgrade:    X-Forwarded-Proto: https counts as https, but
//!                           only when trust_x_forwarded_proto is on, the
//!                           trusted-proxy list is non-empty, the connecting
//!                           IP is on it, and the header is present
//! violation:                Redirect (the reference's
//!                           create_https_redirect: a 301 to the https URL)
//! ```
//!
//! ## Details that mirror the reference exactly
//!
//! - The route config's `require_https` wins whenever a route config exists,
//!   even when it is `false` (the reference's
//!   `route_config.require_https if route_config else enforce_https`), so
//!   the route input is [`Option<bool>`] and `Some(false)` opts a route out
//!   of a globally enforced HTTPS.
//! - The proxy-upgrade arm is the reference `_is_request_https`: the header
//!   alone never decides - a forged `X-Forwarded-Proto` from a client the
//!   deployment does not trust is ignored, exactly as in the reference. The
//!   header comparison is case-insensitive on the value (`forwarded.lower()
//!   == "https"`); a bare-IP proxy entry compares exactly, a CIDR entry
//!   parses the connecting address (the reference raises on an unparseable
//!   address into the pipeline's error handling; this port reads an
//!   unparseable address as not trusted, which keeps the seam total).
//! - The verdict never says what to send: the reference's redirect comes
//!   from the response factory (`301`, `Location` = the request URL with
//!   the scheme replaced by `https`, then the response modifier). The
//!   stage that wires this seam composes the target URL - the engine only
//!   decides that the request must go there.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::https_enforcement::{decide, HttpsEnforcementConfig, HttpsRequest, HttpsVerdict};
//!
//! let config = HttpsEnforcementConfig::new(true, false, Vec::<String>::new()).expect("valid");
//!
//! // Plain HTTP under a global enforcement is a redirect.
//! let request = HttpsRequest { url_scheme: "http", client_host: None, x_forwarded_proto: None, route_require_https: None };
//! assert!(matches!(decide(&request, &config), HttpsVerdict::Redirect { .. }));
//!
//! // HTTPS passes, and a route can opt out of the global arm.
//! let request = HttpsRequest { url_scheme: "https", client_host: None, x_forwarded_proto: None, route_require_https: None };
//! assert_eq!(decide(&request, &config), HttpsVerdict::Allowed);
//! let request = HttpsRequest { url_scheme: "http", client_host: None, x_forwarded_proto: None, route_require_https: Some(false) };
//! assert_eq!(decide(&request, &config), HttpsVerdict::Allowed);
//! ```

use std::net::IpAddr;
use std::str::FromStr;

use crate::ip_gate::{IpGateError, canonical, parse_network_entry};

/// The check's stable name (`check_name`).
pub const HTTPS_ENFORCEMENT_CHECK_NAME: &str = "https_enforcement";

/// The redirect status the reference's `create_https_redirect` answers with
/// (`create_redirect_response(https_url, 301)`).
pub const HTTPS_REDIRECT_STATUS: u16 = 301;

/// The enforcement knobs (`SecurityConfig.enforce_https`,
/// `.trust_x_forwarded_proto`, `.trusted_proxies`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpsEnforcementConfig {
    /// `enforce_https`: the global arm, used when no route config exists.
    pub enforce_https: bool,
    /// `trust_x_forwarded_proto`: whether the upgrade header is believed at
    /// all (never without a trusted connecting IP).
    pub trust_x_forwarded_proto: bool,
    /// `trusted_proxies` as written: bare IPs compare exactly, CIDR ranges
    /// parse the connecting address.
    trusted_proxies_raw: Vec<String>,
}

impl HttpsEnforcementConfig {
    /// Parse the trusted-proxy list, failing closed on an invalid entry
    /// (the error names the list `trusted_proxies`, like the IP gate's
    /// config errors).
    ///
    /// # Errors
    ///
    /// [`IpGateError`] naming the first entry that is neither a valid IP
    /// nor a valid CIDR range.
    pub fn new<I>(
        enforce_https: bool,
        trust_x_forwarded_proto: bool,
        trusted_proxies: I,
    ) -> Result<Self, IpGateError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut proxies = Vec::new();
        for entry in trusted_proxies {
            let entry = entry.as_ref();
            if parse_network_entry(entry).is_none() {
                return Err(IpGateError {
                    list: "trusted_proxies",
                    entry: entry.to_owned(),
                });
            }
            proxies.push(entry.to_owned());
        }
        Ok(Self {
            enforce_https,
            trust_x_forwarded_proto,
            trusted_proxies_raw: proxies,
        })
    }

    /// Whether `connecting` sits on a trusted proxy, the reference
    /// `_is_trusted_proxy`: a bare entry compares exactly as written, a
    /// CIDR entry parses the connecting address (an unparseable address
    /// never matches, keeping the seam total where the reference raises).
    fn is_trusted_proxy(&self, connecting: &str) -> bool {
        for entry in &self.trusted_proxies_raw {
            if !entry.contains('/') {
                if connecting == entry {
                    return true;
                }
            } else if let Ok(addr) = IpAddr::from_str(connecting) {
                // `parse_network_entry` accepted it at construction.
                if let Some(network) = parse_network_entry(entry)
                    && (network.contains(canonical(addr)) || network.contains(addr))
                {
                    return true;
                }
            }
        }
        false
    }
}

/// The request facts the decision reads (`request.url_scheme`,
/// `request.client_host`, the `X-Forwarded-Proto` header, and the route
/// config's `require_https` when a route config exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpsRequest<'a> {
    /// `request.url_scheme` (`http` / `https`).
    pub url_scheme: &'a str,
    /// `request.client_host`: the connecting address, when known.
    pub client_host: Option<&'a str>,
    /// The `X-Forwarded-Proto` header value, when present.
    pub x_forwarded_proto: Option<&'a str>,
    /// The route config's `require_https`; `None` means no route config
    /// (the global knob decides).
    pub route_require_https: Option<bool>,
}

/// What [`decide`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsVerdict {
    /// The request stays on its scheme (already https, or not required).
    Allowed,
    /// The request must be redirected to its https form (the reference's
    /// `create_https_redirect` shape: a [`HTTPS_REDIRECT_STATUS`] to the
    /// scheme-upgraded URL). `route_scoped` splits the reference's two
    /// event paths (`decorator_violation` when a route required HTTPS,
    /// `https_enforced` for the global arm).
    Redirect {
        /// Whether a route config's `require_https` triggered the check.
        route_scoped: bool,
    },
}

/// Whether the request counts as HTTPS, the reference `_is_request_https`:
/// the scheme decides, plus the trusted-proxy upgrade arm.
fn is_request_https(request: &HttpsRequest<'_>, config: &HttpsEnforcementConfig) -> bool {
    let mut is_https = request.url_scheme == "https";
    if !is_https
        && config.trust_x_forwarded_proto
        && !config.trusted_proxies_raw.is_empty()
        && let Some(host) = request.client_host
        && config.is_trusted_proxy(host)
        && let Some(forwarded) = request.x_forwarded_proto
    {
        is_https = forwarded.to_lowercase() == "https";
    }
    is_https
}

/// The reference check body: the route's `require_https` wins when a route
/// config exists, else the global knob; a required plain-HTTP request is a
/// redirect verdict.
#[must_use]
pub fn decide(request: &HttpsRequest<'_>, config: &HttpsEnforcementConfig) -> HttpsVerdict {
    let https_required = request.route_require_https.unwrap_or(config.enforce_https);
    if !https_required || is_request_https(request, config) {
        return HttpsVerdict::Allowed;
    }
    HttpsVerdict::Redirect {
        route_scoped: request.route_require_https.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(
        scheme: &'a str,
        client_host: Option<&'a str>,
        xfp: Option<&'a str>,
        route: Option<bool>,
    ) -> HttpsRequest<'a> {
        HttpsRequest {
            url_scheme: scheme,
            client_host,
            x_forwarded_proto: xfp,
            route_require_https: route,
        }
    }

    #[test]
    fn global_enforcement_redirects_plain_http() {
        let config = HttpsEnforcementConfig::new(true, false, Vec::<String>::new()).unwrap();
        assert_eq!(
            decide(&request("http", None, None, None), &config),
            HttpsVerdict::Redirect {
                route_scoped: false
            }
        );
        assert_eq!(
            decide(&request("https", None, None, None), &config),
            HttpsVerdict::Allowed
        );
        // Off globally, no route: pass.
        let off = HttpsEnforcementConfig::new(false, false, Vec::<String>::new()).unwrap();
        assert_eq!(
            decide(&request("http", None, None, None), &off),
            HttpsVerdict::Allowed
        );
    }

    #[test]
    fn route_require_https_wins_both_ways() {
        let config = HttpsEnforcementConfig::new(true, false, Vec::<String>::new()).unwrap();
        // A route that opts out beats the global arm.
        assert_eq!(
            decide(&request("http", None, None, Some(false)), &config),
            HttpsVerdict::Allowed
        );
        // A route that requires it on a globally-off engine still redirects,
        // and the verdict knows it was route-scoped.
        let off = HttpsEnforcementConfig::new(false, false, Vec::<String>::new()).unwrap();
        assert_eq!(
            decide(&request("http", None, None, Some(true)), &off),
            HttpsVerdict::Redirect { route_scoped: true }
        );
    }

    #[test]
    fn forwarded_proto_never_decides_without_trust() {
        let config = HttpsEnforcementConfig::new(true, false, ["10.0.0.1"]).unwrap();
        assert_eq!(
            decide(
                &request("http", Some("10.0.0.1"), Some("https"), None),
                &config
            ),
            HttpsVerdict::Redirect {
                route_scoped: false
            },
            "trust_x_forwarded_proto is off: the header is ignored"
        );
    }

    #[test]
    fn forwarded_proto_never_decides_from_an_untrusted_client() {
        let config = HttpsEnforcementConfig::new(true, true, ["10.0.0.0/8"]).unwrap();
        assert_eq!(
            decide(
                &request("http", Some("203.0.113.9"), Some("https"), None),
                &config
            ),
            HttpsVerdict::Redirect {
                route_scoped: false
            },
            "a client outside the trusted proxies cannot upgrade itself"
        );
        assert_eq!(
            decide(&request("http", None, Some("https"), None), &config),
            HttpsVerdict::Redirect {
                route_scoped: false
            },
            "no connecting address: no upgrade"
        );
    }

    #[test]
    fn forwarded_proto_upgrades_from_a_trusted_proxy() {
        let config = HttpsEnforcementConfig::new(true, true, ["10.0.0.0/8", "192.0.2.40"]).unwrap();
        assert_eq!(
            decide(
                &request("http", Some("10.1.2.3"), Some("HTTPS"), None),
                &config
            ),
            HttpsVerdict::Allowed,
            "the value comparison is case-insensitive"
        );
        assert_eq!(
            decide(
                &request("http", Some("192.0.2.40"), Some("https"), None),
                &config
            ),
            HttpsVerdict::Allowed,
            "a bare-IP proxy entry matches exactly"
        );
        // A non-https forwarded value from a trusted proxy stays a violation.
        assert_eq!(
            decide(
                &request("http", Some("10.1.2.3"), Some("http"), None),
                &config
            ),
            HttpsVerdict::Redirect {
                route_scoped: false
            }
        );
    }

    #[test]
    fn config_fails_closed_on_a_bad_proxy_entry() {
        let error = HttpsEnforcementConfig::new(true, true, ["not-an-ip"]).unwrap_err();
        assert_eq!(error.list, "trusted_proxies");
        assert_eq!(error.entry, "not-an-ip");
    }

    #[test]
    fn families_never_cross_on_the_proxy_match() {
        let config = HttpsEnforcementConfig::new(true, true, ["10.0.0.0/8"]).unwrap();
        assert_eq!(
            decide(
                &request("http", Some("::ffff:10.1.2.3"), Some("https"), None),
                &config
            ),
            HttpsVerdict::Allowed,
            "a v4-mapped connecting address matches its IPv4 proxy entry"
        );
        assert_eq!(
            decide(
                &request("http", Some("2001:db8::1"), Some("https"), None),
                &config
            ),
            HttpsVerdict::Redirect {
                route_scoped: false
            }
        );
    }

    #[test]
    fn a_mismatched_bare_entry_falls_through_and_junk_addresses_never_match() {
        // A bare entry the connecting address does not equal is skipped in
        // favor of the next entry.
        let config = HttpsEnforcementConfig::new(true, true, ["10.0.0.1", "10.0.0.0/8"]).unwrap();
        assert_eq!(
            decide(
                &request("http", Some("10.1.2.3"), Some("https"), None),
                &config
            ),
            HttpsVerdict::Allowed,
            "the CIDR entry answers after the bare entry missed"
        );
        // A CIDR entry with an unparseable connecting address never matches
        // (the seam stays total where the reference raises).
        let config = HttpsEnforcementConfig::new(true, true, ["10.0.0.0/8"]).unwrap();
        assert_eq!(
            decide(&request("http", Some("junk"), Some("https"), None), &config),
            HttpsVerdict::Redirect {
                route_scoped: false
            },
            "junk cannot upgrade itself"
        );
    }
}
