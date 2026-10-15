//! The country gate: `whitelist_countries` and `blocked_countries`.
//!
//! This is the Rust family's port of the reference engine's global country
//! check - the country branch of `check_ip_access`
//! (`guard_core/_utils/access_control.py`) with the verdict logic of
//! `_resolve_country_verdict` and `_evaluate_country_access`, plus the
//! config coercion of `_validate_country_set_value`. One call,
//! [`check_countries`], decides a request IP's country access:
//!
//! ```text
//! skip (a global whitelist match set it):          pass
//! no rules configured:                             pass
//! loopback address:                                pass (the loopback exemption)
//! geolocation unresolved (or empty):
//!     blocked iff whitelist_countries is non-empty
//! whitelist_countries non-empty:
//!     country in the whitelist:                    pass
//!     anything else:                               blocked
//! blocked_countries non-empty:
//!     country in the blocklist:                    blocked
//!     anything else:                               pass
//! ```
//!
//! ## Details that mirror the reference exactly
//!
//! - The country lists are sets of ISO 3166-1 alpha-2 codes, uppercased at
//!   config time (`_validate_country_set_value` coerces with `upper()`) and
//!   compared exactly - a handler returning `"us"` does not match `"US"`.
//! - The loopback exemption runs before geolocation: `127.0.0.1` and `::1`
//!   pass even under a restrictive whitelist.
//! - An unresolved country is blocked only under a restrictive
//!   whitelist (the reference `return bool(config.whitelist_countries)`),
//!   with the generic list reason instead of a country reason.
//! - An explicit whitelist match outranks `blocked_countries`: the
//!   whitelist branch decides first, exactly as the reference
//!   `_evaluate_country_access` returns from it.
//! - The reference initializes its geo handler on first use
//!   (`is_initialized` / `initialize()`); the Rust handler trait is sync
//!   and assumed ready.
//!
//! The geolocation itself comes from the [`GeoIpHandler`] seam: the
//! reference resolves countries through an `IPInfo` `MMDB` database (or a
//! custom handler); the MMDB reading is adapter work, the gate takes the
//! resolved country code.
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! use guard_core_engine::geo::{
//!     check_countries, parse_country_lists, CountryGate, GeoIpHandler,
//! };
//!
//! struct FixedUS;
//! impl GeoIpHandler for FixedUS {
//!     fn get_country(&self, _ip: IpAddr) -> Option<String> {
//!         Some("US".to_owned())
//!     }
//! }
//!
//! // A restrictive whitelist: only US traffic passes.
//! let gate: CountryGate = parse_country_lists(["us"], [] as [&str; 0]);
//! let handler = FixedUS;
//!
//! let passed = check_countries(
//!     IpAddr::from_str("192.0.2.1").unwrap(),
//!     &gate,
//!     &handler,
//!     false,
//! );
//! assert!(passed.is_none(), "US is whitelisted");
//!
//! // Under the same rules a non-US address is blocked with the reference
//! // reason, and a whitelist match carries the skip flag past this check.
//! struct FixedDE;
//! impl GeoIpHandler for FixedDE {
//!     fn get_country(&self, _ip: IpAddr) -> Option<String> {
//!         Some("DE".to_owned())
//!     }
//! }
//! let blocked = check_countries(
//!     IpAddr::from_str("192.0.2.2").unwrap(),
//!     &gate,
//!     &FixedDE,
//!     false,
//! )
//! .expect("blocked");
//! assert_eq!(blocked.reason, "IP from blocked country: DE");
//!
//! let skipped = check_countries(
//!     IpAddr::from_str("192.0.2.2").unwrap(),
//!     &gate,
//!     &FixedDE,
//!     true,
//! );
//! assert!(skipped.is_none(), "a whitelist match skips the country check");
//! ```

use std::fmt;
use std::net::IpAddr;

/// The country gate: the parsed `whitelist_countries` and
/// `blocked_countries` sets.
///
/// Build it with [`parse_country_lists`] (which uppercases and dedups the
/// codes, the reference `_validate_country_set_value` coercion). The
/// default has no rules: [`check_countries`] passes everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CountryGate {
    /// `whitelist_countries`: restrictive when non-empty (an unresolved or
    /// unlisted country is blocked).
    pub whitelist_countries: Vec<String>,
    /// `blocked_countries`: always blocked, consulted when the whitelist is
    /// empty.
    pub blocked_countries: Vec<String>,
}

impl CountryGate {
    /// Whether any rule is configured (the reference `_has_country_rules`).
    #[must_use]
    pub const fn has_rules(&self) -> bool {
        !self.whitelist_countries.is_empty() || !self.blocked_countries.is_empty()
    }
}

/// Coerce the two country-code lists into the gate: every code is
/// uppercased and duplicates dropped (`_validate_country_set_value`'s
/// `frozenset(str(item).upper())`).
#[must_use]
pub fn parse_country_lists<I, J>(whitelist: I, blocked: J) -> CountryGate
where
    I: IntoIterator,
    I::Item: AsRef<str>,
    J: IntoIterator,
    J::Item: AsRef<str>,
{
    CountryGate {
        whitelist_countries: normalize_codes(whitelist),
        blocked_countries: normalize_codes(blocked),
    }
}

/// Uppercase and dedup one code list, preserving first-seen order.
fn normalize_codes<I>(codes: I) -> Vec<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut normalized: Vec<String> = Vec::new();
    for code in codes {
        let code = code.as_ref().to_ascii_uppercase();
        if !code.is_empty() && !normalized.iter().any(|known| known == &code) {
            normalized.push(code);
        }
    }
    normalized
}

/// The geolocation seam: the ISO 3166-1 alpha-2 country code of an
/// address, `None` when the address is not geolocated.
///
/// The reference protocol is `GeoIPHandler.get_country(ip)`; this port is
/// sync and assumed ready (the reference initializes its handler on first
/// use). An empty string reads as unresolved, like Python's falsy check.
pub trait GeoIpHandler: Send + Sync {
    /// The country code of `ip`, or `None` when not geolocated.
    fn get_country(&self, ip: IpAddr) -> Option<String>;
}

/// The block answer of a failed country check: the reference
/// `IpAccessResult` reason and the resolved country when one exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryBlock {
    /// The resolved country code, absent for an unresolved address (the
    /// generic reason carries the IP instead).
    pub country: Option<String>,
    /// The reference `IpAccessResult.reason`
    /// (`"IP from blocked country: {code}"`, or the generic list reason
    /// for an unresolved address).
    pub reason: String,
}

impl fmt::Display for CountryBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// The generic block reason (`_GENERIC_LIST_BLOCK_REASON` with the IP
/// filled in) used when an address under a restrictive whitelist is not
/// geolocated.
#[must_use]
pub fn generic_list_block_reason(ip: IpAddr) -> String {
    generic_list_block_reason_for(&ip.to_string())
}

/// The generic block reason for an arbitrary identity string: the
/// reference formats the same template with `UNKNOWN_CLIENT_IDENTITY`
/// (`"unknown"`) when a request carries no client IP.
#[must_use]
pub fn generic_list_block_reason_for(identity: &str) -> String {
    format!("IP {identity} not in global allowlist/blocklist")
}

/// The country branch of the reference `check_ip_access`.
///
/// `skip` is the whitelist-match skip flag (`skip_countries` in the
/// reference: a global whitelist match outranks the country rules).
/// `None` passes; `Some(block)` is the reference denial (the
/// `_check_global_ip_restrictions` shape answers `403 "Forbidden"` with
/// [`CountryBlock::reason`] as the log reason).
#[must_use]
pub fn check_countries(
    ip: IpAddr,
    gate: &CountryGate,
    handler: &dyn GeoIpHandler,
    skip: bool,
) -> Option<CountryBlock> {
    if skip || !gate.has_rules() {
        return None;
    }
    // The loopback exemption runs before geolocation.
    if ip.is_loopback() {
        return None;
    }
    // An empty string reads as unresolved, like Python's falsy country.
    // The handler's code is compared exactly (no case folding), mirroring
    // Python's `country in config.blocked_countries` membership.
    let country = handler.get_country(ip).filter(|code| !code.is_empty());
    let Some(country) = country else {
        // `return bool(config.whitelist_countries), None` in the reference:
        // an unresolved address blocks only under a restrictive whitelist.
        if gate.whitelist_countries.is_empty() {
            return None;
        }
        return Some(CountryBlock {
            country: None,
            reason: generic_list_block_reason(ip),
        });
    };
    let blocked_reason = format!("IP from blocked country: {country}");
    if !gate.whitelist_countries.is_empty() {
        return if gate.whitelist_countries.iter().any(|code| code == &country) {
            None
        } else {
            Some(CountryBlock {
                country: Some(country),
                reason: blocked_reason,
            })
        };
    }
    if gate.blocked_countries.iter().any(|code| code == &country) {
        return Some(CountryBlock {
            country: Some(country),
            reason: blocked_reason,
        });
    }
    None
}

/// The route-level country verdict: the reference `check_country_access`
/// (`guard_core/core/checks/helpers.py`), the country arm of
/// `check_route_ip_access`.
///
/// ```text
/// no handler:                                       None (no verdict)
/// blocked_countries non-empty, country listed:      Some(false)
/// whitelist_countries non-empty:
///     country resolved and listed:                  Some(true)
///     anything else (unresolved, unlisted):         Some(false)
/// otherwise:                                        None
/// ```
///
/// Unlike [`check_countries`] this has no loopback exemption and no
/// "whitelist outranks blocklist" shortcut: `blocked_countries` is asked
/// first, so a country in both lists is `Some(false)`, and the verdict is
/// tri-state because a route whitelist match (`Some(true)`) also skips the
/// global country stage. An empty country string reads as unresolved.
#[must_use]
pub fn check_route_country(
    ip: IpAddr,
    gate: &CountryGate,
    handler: Option<&dyn GeoIpHandler>,
) -> Option<bool> {
    let handler = handler?;
    let resolve = || handler.get_country(ip).filter(|code| !code.is_empty());
    let mut country = None;
    if !gate.blocked_countries.is_empty() {
        country = resolve();
        if country
            .as_ref()
            .is_some_and(|code| gate.blocked_countries.contains(code))
        {
            return Some(false);
        }
    }
    if !gate.whitelist_countries.is_empty() {
        let country = country.or_else(resolve);
        return Some(country.is_some_and(|code| gate.whitelist_countries.contains(&code)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// A handler answering a fixed country for every address.
    struct Fixed(&'static str);

    impl GeoIpHandler for Fixed {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            (!self.0.is_empty()).then(|| self.0.to_owned())
        }
    }

    /// A handler resolving nothing.
    struct Nowhere;

    impl GeoIpHandler for Nowhere {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            None
        }
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    #[test]
    fn parse_uppercases_and_dedups_the_codes() {
        let gate = parse_country_lists(["us", "US", "de"], ["FR", "fr", ""]);
        assert_eq!(
            gate.whitelist_countries,
            vec!["US".to_owned(), "DE".to_owned()]
        );
        assert_eq!(gate.blocked_countries, vec!["FR".to_owned()]);
        assert!(gate.has_rules());
        // Empty lists are the no-rules default.
        let gate = parse_country_lists([] as [&str; 0], [] as [&str; 0]);
        assert!(!gate.has_rules());
        assert_eq!(gate, CountryGate::default());
    }

    #[test]
    fn no_rules_pass_everything() {
        let gate = CountryGate::default();
        assert!(check_countries(ip("192.0.2.1"), &gate, &Fixed("RU"), false).is_none());
        assert!(check_countries(ip("127.0.0.1"), &gate, &Fixed("RU"), false).is_none());
    }

    #[test]
    fn skip_flag_passes_even_under_a_restrictive_whitelist() {
        let gate = parse_country_lists(["US"], [] as [&str; 0]);
        assert!(check_countries(ip("192.0.2.1"), &gate, &Fixed("RU"), true).is_none());
        // The skip flag mirrors `skip_countries`, set by a global whitelist
        // match; exemption (the second flag) does not reach this check.
    }

    #[test]
    fn loopback_is_exempt_before_geolocation() {
        let gate = parse_country_lists(["US"], ["RU"]);
        // Even a handler that resolves nothing cannot block loopback.
        assert!(check_countries(ip("127.0.0.1"), &gate, &Nowhere, false).is_none());
        assert!(check_countries(ip("::1"), &gate, &Fixed("RU"), false).is_none());
        assert!(check_countries(ip("127.0.0.1"), &gate, &Fixed("RU"), false).is_none());
    }

    #[test]
    fn blocklist_blocks_only_listed_countries() {
        let gate = parse_country_lists([] as [&str; 0], ["RU", "CN"]);
        let block = check_countries(ip("192.0.2.1"), &gate, &Fixed("RU"), false).expect("blocked");
        assert_eq!(block.country.as_deref(), Some("RU"));
        assert_eq!(block.reason, "IP from blocked country: RU");
        assert_eq!(block.to_string(), "IP from blocked country: RU");
        assert!(check_countries(ip("192.0.2.1"), &gate, &Fixed("DE"), false).is_none());
        // An unresolved address under a blocklist-only gate passes.
        assert!(check_countries(ip("192.0.2.1"), &gate, &Nowhere, false).is_none());
        assert!(check_countries(ip("192.0.2.1"), &gate, &Fixed(""), false).is_none());
    }

    #[test]
    fn whitelist_is_restrictive_and_blocks_the_unresolved() {
        let gate = parse_country_lists(["US"], ["RU"]);
        assert!(check_countries(ip("192.0.2.1"), &gate, &Fixed("US"), false).is_none());
        // A non-member is blocked even though RU is also in blocked_countries:
        // the whitelist branch decides first.
        let block = check_countries(ip("192.0.2.1"), &gate, &Fixed("DE"), false).expect("blocked");
        assert_eq!(block.reason, "IP from blocked country: DE");
        // Unresolved blocks under the whitelist, with the generic reason.
        let block = check_countries(ip("192.0.2.1"), &gate, &Nowhere, false).expect("blocked");
        assert_eq!(block.country, None);
        assert_eq!(
            block.reason,
            "IP 192.0.2.1 not in global allowlist/blocklist"
        );
    }

    #[test]
    fn membership_is_exact_no_case_folding() {
        // The config side is uppercased at parse time; the handler side is
        // compared exactly, like Python's set membership.
        let gate = parse_country_lists([] as [&str; 0], ["RU"]);
        let block = check_countries(ip("192.0.2.1"), &gate, &Fixed("ru"), false);
        assert!(
            block.is_none(),
            "a lowercase handler code must not match the uppercased config"
        );
        let gate = parse_country_lists(["us"], [] as [&str; 0]);
        // Under a restrictive whitelist the same mismatch fails closed.
        assert!(check_countries(ip("192.0.2.1"), &gate, &Fixed("us"), false).is_some());
    }

    #[test]
    fn generic_reason_carries_the_ip() {
        let gate = parse_country_lists(["US"], [] as [&str; 0]);
        let block = check_countries(ip("198.51.100.7"), &gate, &Nowhere, false).expect("blocked");
        assert_eq!(
            block.reason,
            "IP 198.51.100.7 not in global allowlist/blocklist"
        );
    }
}
