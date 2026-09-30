//! The global IP gate: `whitelist`, `blacklist`, and `exempt_ips`.
//!
//! This is the Rust family's minimal port of the reference engine's global IP
//! stage (guard-core `check_ip_access`, frozen by the ecosystem
//! `exempt_ips` contract). One call,
//! [`IpGateConfig::evaluate`], decides a request IP:
//!
//! ```text
//! if a whitelist is configured and the IP is not on it:  deny (not in whitelist)
//! otherwise, if the IP is on the blacklist:              deny (blacklisted)
//! allowed: is_whitelisted = matched the whitelist
//!          is_exempt     = matched exempt_ips
//! ```
//!
//! ## The `exempt_ips` contract
//!
//! `exempt_ips` is the skip-list for known-friendly automation (monitoring
//! probes, VPN egress, a partner's server). A match sets the same skip state
//! a whitelist match sets ([`IpGateDecision::is_exempt`]), but it carries no
//! deny path of its own: exemption can never open the whitelist gate, and an
//! exempt IP on the blacklist is still denied. `whitelist` keeps its
//! allowlist semantics untouched: when it is non-empty, every unlisted IP is
//! denied exactly as before, exemption included.
//!
//! Matching semantics are identical for all three lists: an entry is a bare
//! IP or a CIDR range (host bits are cleared at parse time, so `1.2.3.4/24`
//! and `1.2.3.0/24` are the same network), an IPv4-mapped request address
//! (`::ffff:203.0.113.7`) matches its IPv4 canonical form, and families never
//! cross (an IPv4 entry never matches an unrelated IPv6 address).
//!
//! Invalid entries are config errors: [`IpGateConfig::new`] fails closed, so
//! an adapter that builds its gate at startup never serves with a broken
//! list.
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! use guard_core_engine::ip_gate::{IpGateConfig, IpGateVerdict};
//!
//! let gate = IpGateConfig::new(
//!     [] as [&str; 0],
//!     ["203.0.113.9"],
//!     ["198.51.100.7", "198.51.100.16/28"],
//! )
//! .expect("valid lists");
//!
//! // An exempt IP passes with the skip flag set.
//! let exempt = gate.evaluate(IpAddr::from_str("198.51.100.7").unwrap());
//! assert!(matches!(exempt, IpGateVerdict::Allowed(decision) if decision.is_exempt));
//!
//! // A CIDR entry matches the whole range, the flag carried along.
//! let in_range = gate.evaluate(IpAddr::from_str("198.51.100.20").unwrap());
//! assert!(matches!(in_range, IpGateVerdict::Allowed(decision) if decision.is_exempt));
//!
//! // The blacklist wins over exemption: no deny path is added, but none is
//! // removed either.
//! assert_eq!(
//!     gate.evaluate(IpAddr::from_str("203.0.113.9").unwrap()),
//!     IpGateVerdict::Denied(guard_core_engine::ip_gate::IpGateDenial::Blacklisted)
//! );
//!
//! // Everyone else passes unimpeded: an empty whitelist denies nobody.
//! let other = gate.evaluate(IpAddr::from_str("192.0.2.1").unwrap());
//! assert!(matches!(other, IpGateVerdict::Allowed(decision) if !decision.is_exempt));
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// The skip state a request carries after it passed the global IP gate.
///
/// This is the family-local equivalent of the reference engine's
/// `state.is_whitelisted` / `state.is_exempt` pair. The stateful stages the
/// engine ships (the rate limiter and the auto-ban violation counter, see
/// [`crate::rate_limit`] and [`crate::ip_ban`]) skip for
/// `is_whitelisted || is_exempt` exactly what the reference skips for a
/// whitelist match, and never skip penetration detection. A stage that lands
/// later (user-agent filter, cloud-provider blocker) must follow the same
/// rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpGateDecision {
    /// A non-empty `whitelist` matched the request IP.
    pub is_whitelisted: bool,
    /// `exempt_ips` matched the request IP. Per the contract, an IP on both
    /// lists is simply a whitelist match with no observable difference, so
    /// this flag adds nothing a whitelist match does not already carry.
    pub is_exempt: bool,
}

/// Why the global IP gate denied a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpGateDenial {
    /// The IP is on the `blacklist` (exemption does not win).
    Blacklisted,
    /// A non-empty `whitelist` matched neither the IP nor any exemption (a
    /// match would be a plain whitelist pass; exemption never opens the gate).
    NotInWhitelist,
}

impl IpGateDenial {
    /// The denial reason, in the ecosystem's reason vocabulary (same strings
    /// the Go engine port emits).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Blacklisted => "IP is blacklisted",
            Self::NotInWhitelist => "IP not in whitelist",
        }
    }
}

/// The outcome of the global IP gate for one request IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpGateVerdict {
    /// The IP passed the gate; the decision carries the skip state.
    Allowed(IpGateDecision),
    /// The IP was denied; exemption never applies to a denial.
    Denied(IpGateDenial),
}

/// One parsed list entry: a bare IP or a CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Exact(IpAddr),
    Network(IpNet),
}

/// A CIDR range with the host bits cleared at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IpNet {
    pub(crate) addr: IpAddr,
    pub(crate) prefix: u8,
}

impl IpNet {
    /// Parse an `addr/prefix` entry, clearing the host bits.
    ///
    /// The network keeps the family its literal was written in: Python and Go
    /// both treat `::ffff:0:0/96` as an IPv6 network, so the request side is
    /// what gets canonicalized (see [`entry_matches`]), never the entry.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (addr_part, prefix_part) = text.split_once('/')?;
        let addr = IpAddr::from_str(addr_part).ok()?;
        let prefix = u8::from_str(prefix_part).ok()?;
        let bits = family_bits(addr);
        if prefix > bits {
            return None;
        }
        Some(Self {
            addr: masked(addr, prefix),
            prefix,
        })
    }

    /// Family-preserving membership: an IPv4 network never contains an IPv6
    /// address and vice versa.
    pub(crate) fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(net) == (u32::from(ip) & v4_mask(self.prefix))
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(net) == (u128::from(ip) & v6_mask(self.prefix))
            }
            _ => false,
        }
    }
}

/// Parse one list entry into its exact or network form.
fn parse_entry(text: &str) -> Option<Entry> {
    if text.contains('/') {
        return Some(Entry::Network(IpNet::parse(text)?));
    }
    Some(Entry::Exact(canonical(IpAddr::from_str(text).ok()?)))
}

/// Parse one list entry into a network: a CIDR range as written (host bits
/// cleared) or a bare IP as a single-host network of its own family. The
/// overlap checks of the dynamic ban store (loopback and trusted-proxy
/// refusal) compare request addresses against networks built from this.
pub(crate) fn parse_network_entry(text: &str) -> Option<IpNet> {
    match parse_entry(text)? {
        Entry::Exact(addr) => Some(IpNet {
            addr,
            prefix: family_bits(addr),
        }),
        Entry::Network(net) => Some(net),
    }
}

/// Undo a `::ffff:a.b.c.d` mapping: the canonical form exact entries, request
/// addresses, and every stateful store key (rate windows, ban entries) are
/// compared in, so a v4-mapped request counts toward the same bucket as its
/// IPv4 form.
pub(crate) const fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// The address family's bit width.
const fn family_bits(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Clear the host bits of `addr` below `prefix`.
fn masked(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & v4_mask(prefix))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & v6_mask(prefix))),
    }
}

/// The IPv4 network mask for a prefix length (0 for `/0`).
const fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// The IPv6 network mask for a prefix length (0 for `/0`).
const fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Whether one entry matches a request address.
///
/// The CIDR arms mirror the Go engine port exactly: the request address is
/// tried in canonical (IPv4-unmapped) form first, then raw, so a v4-mapped
/// request matches an IPv4 network while a raw v6 request still matches a v6
/// network such as `::ffff:0:0/96`. Exact entries compare canonical forms on
/// both sides.
fn entry_matches(entry: &Entry, addr: IpAddr) -> bool {
    match entry {
        Entry::Exact(expected) => *expected == canonical(addr),
        Entry::Network(net) => net.contains(canonical(addr)) || net.contains(addr),
    }
}

/// Whether any entry of `entries` matches `addr`; an empty list matches
/// nothing.
fn list_matches(entries: &[Entry], addr: IpAddr) -> bool {
    entries.iter().any(|entry| entry_matches(entry, addr))
}

/// An invalid list entry: the config error [`IpGateConfig::new`] fails with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpGateError {
    /// The list the rejected entry came from (`whitelist`, `blacklist`, or
    /// `exempt_ips`).
    pub list: &'static str,
    /// The rejected entry.
    pub entry: String,
}

impl fmt::Display for IpGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} entry '{}': expected an IP address or CIDR range",
            self.list, self.entry
        )
    }
}

impl std::error::Error for IpGateError {}

/// The global IP gate: the parsed `whitelist`, `blacklist`, and `exempt_ips`
/// lists.
///
/// Build it once at startup with [`IpGateConfig::new`] (which fails closed on
/// an invalid entry) and evaluate request IPs with
/// [`IpGateConfig::evaluate`]. The default value is three empty lists: the
/// gate is inert, denying nobody and exempting nobody.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpGateConfig {
    whitelist: Vec<Entry>,
    blacklist: Vec<Entry>,
    exempt_ips: Vec<Entry>,
}

impl IpGateConfig {
    /// Parse and validate the three lists, failing closed on the first
    /// invalid entry.
    ///
    /// Entry semantics match the reference whitelist matcher: a bare IP or a
    /// `addr/prefix` CIDR range, IPv4-mapped forms included, host bits
    /// cleared. The empty iterator is valid for any list.
    ///
    /// # Errors
    ///
    /// Returns an [`IpGateError`] naming the list and the first entry that is
    /// neither a valid IP nor a valid CIDR range.
    pub fn new<W, B, E>(whitelist: W, blacklist: B, exempt_ips: E) -> Result<Self, IpGateError>
    where
        W: IntoIterator,
        W::Item: AsRef<str>,
        B: IntoIterator,
        B::Item: AsRef<str>,
        E: IntoIterator,
        E::Item: AsRef<str>,
    {
        Ok(Self {
            whitelist: parse_list("whitelist", whitelist)?,
            blacklist: parse_list("blacklist", blacklist)?,
            exempt_ips: parse_list("exempt_ips", exempt_ips)?,
        })
    }

    /// Evaluate a request IP against the gate.
    ///
    /// The ordering is the reference contract's: with a non-empty whitelist
    /// the whitelist gate decides (an unlisted, non-exempt IP is denied; an
    /// exempt IP does **not** pass the gate), otherwise the blacklist decides.
    /// The exemption flag is only set on an allowed verdict: it never adds a
    /// deny path and never removes one.
    #[must_use]
    pub fn evaluate(&self, ip: IpAddr) -> IpGateVerdict {
        if !self.whitelist.is_empty() {
            if !list_matches(&self.whitelist, ip) {
                return IpGateVerdict::Denied(IpGateDenial::NotInWhitelist);
            }
            return IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                is_exempt: list_matches(&self.exempt_ips, ip),
            });
        }
        if !self.blacklist.is_empty() && list_matches(&self.blacklist, ip) {
            return IpGateVerdict::Denied(IpGateDenial::Blacklisted);
        }
        IpGateVerdict::Allowed(IpGateDecision {
            is_whitelisted: false,
            is_exempt: list_matches(&self.exempt_ips, ip),
        })
    }
}

/// The outcome of the route-level IP gate for one request IP
/// (`check_route_ip_access`'s tri-state, the country arms aside).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteIpVerdict {
    /// The route IP lists leave the request alone: neither list matched in a
    /// denying way and no restrictive whitelist claims the route. The global
    /// gate decides as usual.
    Unrestricted,
    /// A configured route whitelist matched the IP (or nothing denied): the
    /// route stage passes.
    Allowed,
    /// A route blacklist match, or a miss under a configured route
    /// whitelist: the route stage denies.
    Denied,
}

/// The route-level IP gate: a route decorator's `ip_whitelist` and
/// `ip_blacklist` (`RouteConfig.ip_whitelist` / `.ip_blacklist`).
///
/// This is the Rust family's port of the reference engine's route IP stage
/// (`guard_core/core/checks/helpers.py::check_route_ip_access`, the IP-list
/// arms; the Go and PHP family ports run the same order). One call,
/// [`RouteIpGate::evaluate`], decides a request IP against one route:
///
/// ```text
/// whitelist configured, match: pass the route stage (the whitelist verdict
///                              wins, even over a blacklist match)
/// whitelist configured, miss:  deny (the whitelist takes over the route
///                              verdict; the blacklist is never consulted)
/// blacklist match:             deny
/// neither list configured:     unrestricted (the global gate decides)
/// ```
///
/// The precedence is the reference's `check_route_ip_access`: the whitelist
/// is asked first and its answer settles the IP verdict (`ip_result`); the
/// blacklist is only consulted when the whitelist gives no verdict (it is
/// not configured), so a whitelisted IP that is also blacklisted still
/// passes the route stage.
///
/// Matching semantics are the global gate's ([`IpGateConfig`]): a bare IP or
/// a CIDR range per entry, IPv4-mapped request addresses canonicalized,
/// families never crossing. Invalid entries are config errors:
/// [`RouteIpGate::new`] fails closed.
///
/// The global lists are still enforced afterwards by the caller, so a route
/// whitelist match never relaxes the global gate; it only clears the route
/// verdict.
///
/// # Example
///
/// ```
/// use std::net::IpAddr;
/// use std::str::FromStr;
///
/// use guard_core_engine::ip_gate::{RouteIpGate, RouteIpVerdict};
///
/// let gate = RouteIpGate::new(["192.0.2.40"], ["203.0.113.9"]).expect("valid lists");
///
/// // A whitelist member passes the route stage, even a blacklisted one:
/// // the whitelist verdict wins over the blacklist.
/// assert_eq!(
///     gate.evaluate(IpAddr::from_str("192.0.2.40").unwrap()),
///     RouteIpVerdict::Allowed
/// );
/// // Everyone else on the route is denied: the whitelist takes over.
/// assert_eq!(
///     gate.evaluate(IpAddr::from_str("192.0.2.11").unwrap()),
///     RouteIpVerdict::Denied
/// );
/// // A blacklisted IP outside the whitelist is denied.
/// assert_eq!(
///     gate.evaluate(IpAddr::from_str("203.0.113.9").unwrap()),
///     RouteIpVerdict::Denied
/// );
///
/// // No lists: the route leaves the request to the global gate.
/// let open = RouteIpGate::new([] as [&str; 0], [] as [&str; 0]).expect("valid lists");
/// assert_eq!(
///     open.evaluate(IpAddr::from_str("192.0.2.11").unwrap()),
///     RouteIpVerdict::Unrestricted
/// );
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteIpGate {
    whitelist: Vec<Entry>,
    blacklist: Vec<Entry>,
}

impl RouteIpGate {
    /// Parse the route's two lists, failing closed on the first invalid
    /// entry (the list names in the error are `ip_whitelist` and
    /// `ip_blacklist`).
    ///
    /// # Errors
    ///
    /// Returns an [`IpGateError`] naming the list and the first entry that is
    /// neither a valid IP nor a valid CIDR range.
    pub fn new<W, B>(whitelist: W, blacklist: B) -> Result<Self, IpGateError>
    where
        W: IntoIterator,
        W::Item: AsRef<str>,
        B: IntoIterator,
        B::Item: AsRef<str>,
    {
        Ok(Self {
            whitelist: parse_list("ip_whitelist", whitelist)?,
            blacklist: parse_list("ip_blacklist", blacklist)?,
        })
    }

    /// Whether a route whitelist is configured (non-empty). The reference
    /// `_route_overrides_ip_lists`: a configured route whitelist also
    /// overrides the global IP lists for the request, so the caller skips
    /// the global gate's deny paths.
    #[must_use]
    pub const fn whitelist_configured(&self) -> bool {
        !self.whitelist.is_empty()
    }

    /// Evaluate a request IP against the route's lists: a configured
    /// whitelist takes over the route verdict first (a match passes, a miss
    /// denies, exactly the reference's `ip_result` order), then the
    /// blacklist denies, and no list leaves the request unrestricted.
    #[must_use]
    pub fn evaluate(&self, ip: IpAddr) -> RouteIpVerdict {
        if !self.whitelist.is_empty() {
            return if list_matches(&self.whitelist, ip) {
                RouteIpVerdict::Allowed
            } else {
                RouteIpVerdict::Denied
            };
        }
        if !self.blacklist.is_empty() && list_matches(&self.blacklist, ip) {
            return RouteIpVerdict::Denied;
        }
        RouteIpVerdict::Unrestricted
    }
}

/// Parse one list, reporting the first invalid entry with the list's name.
fn parse_list<I>(list: &'static str, entries: I) -> Result<Vec<Entry>, IpGateError>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut parsed = Vec::new();
    for entry in entries {
        let entry = entry.as_ref();
        match parse_entry(entry) {
            Some(parsed_entry) => parsed.push(parsed_entry),
            None => {
                return Err(IpGateError {
                    list,
                    entry: entry.to_owned(),
                });
            }
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty list, typed so the `new` calls stay inferable.
    const NIL: [&str; 0] = [];

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    #[test]
    fn parse_entry_forms() {
        assert_eq!(
            parse_entry("203.0.113.7"),
            Some(Entry::Exact(ip("203.0.113.7")))
        );
        assert_eq!(
            parse_entry("198.51.100.16/28"),
            Some(Entry::Network(IpNet {
                addr: ip("198.51.100.16"),
                prefix: 28
            }))
        );
        // Host bits are cleared at parse time.
        assert_eq!(
            parse_entry("198.51.100.20/28"),
            parse_entry("198.51.100.16/28")
        );
        // IPv4-mapped exact entries canonicalize to IPv4.
        assert_eq!(
            parse_entry("::ffff:203.0.113.7"),
            Some(Entry::Exact(ip("203.0.113.7")))
        );
        // A mapped CIDR entry keeps its IPv6 family, as in Python and Go.
        assert_eq!(
            parse_entry("::ffff:0:0/96"),
            Some(Entry::Network(IpNet {
                addr: ip("::ffff:0:0"),
                prefix: 96
            }))
        );
    }

    #[test]
    fn parse_entry_rejects_junk() {
        for junk in [
            "not-an-ip",
            "",
            "203.0.113.0/33",
            "203.0.113.7/",
            "/24",
            "::1/129",
        ] {
            assert_eq!(parse_entry(junk), None, "{junk} must not parse");
        }
    }

    #[test]
    fn family_never_crosses() {
        let net = IpNet::parse("203.0.113.0/24").expect("v4 network");
        assert!(net.contains(ip("203.0.113.7")));
        // An unrelated v6 address is never inside a v4 network. The v4-mapped
        // v6 form matches through the mapped arm of `entry_matches`, never
        // through a family crossing here.
        assert!(!net.contains(ip("::1")));
        let net = IpNet::parse("2001:db8::/32").expect("v6 network");
        assert!(net.contains(ip("2001:db8::1")));
        assert!(!net.contains(ip("203.0.113.7")));
    }

    #[test]
    fn zero_prefix_networks_match_everything_in_family() {
        let net = IpNet::parse("0.0.0.0/0").expect("v4 /0");
        assert!(net.contains(ip("203.0.113.7")));
        assert!(!net.contains(ip("2001:db8::1")));
        let net = IpNet::parse("::/0").expect("v6 /0");
        assert!(net.contains(ip("2001:db8::1")));
        assert!(!net.contains(ip("203.0.113.7")));
    }

    #[test]
    fn new_reports_the_list_and_entry_of_the_first_reject() {
        let error = RouteIpGate::new(["203.0.113.0/33"], NIL).unwrap_err();
        assert_eq!(error.list, "ip_whitelist");
        assert_eq!(error.entry, "203.0.113.0/33");

        let error = RouteIpGate::new(NIL, ["junk"]).unwrap_err();
        assert_eq!(error.list, "ip_blacklist");
        assert_eq!(error.entry, "junk");

        let error = IpGateConfig::new(["203.0.113.7"], ["ok-but-not-an-ip"], NIL).unwrap_err();
        assert_eq!(error.list, "blacklist");
        assert_eq!(error.entry, "ok-but-not-an-ip");
        assert_eq!(
            error.to_string(),
            "invalid blacklist entry 'ok-but-not-an-ip': expected an IP address or CIDR range"
        );

        let error = IpGateConfig::new(NIL, NIL, ["203.0.113.0/33"]).unwrap_err();
        assert_eq!(error.list, "exempt_ips");

        let error = IpGateConfig::new(["::1/129"], NIL, NIL).unwrap_err();
        assert_eq!(error.list, "whitelist");
    }

    #[test]
    fn new_accepts_empty_lists_and_the_default_is_inert() {
        let gate = IpGateConfig::new(NIL, NIL, NIL).expect("empty lists");
        for address in ["203.0.113.7", "2001:db8::1", "::ffff:203.0.113.7"] {
            assert_eq!(
                gate.evaluate(ip(address)),
                IpGateVerdict::Allowed(IpGateDecision::default())
            );
        }
        assert_eq!(
            IpGateConfig::default().evaluate(ip("192.0.2.1")),
            IpGateVerdict::Allowed(IpGateDecision::default())
        );
    }

    #[test]
    fn blacklist_denies_and_exemption_does_not_win() {
        let gate =
            IpGateConfig::new(NIL, ["203.0.113.9", "198.51.100.0/24"], ["203.0.113.9"]).unwrap();
        assert_eq!(
            gate.evaluate(ip("203.0.113.9")),
            IpGateVerdict::Denied(IpGateDenial::Blacklisted)
        );
        assert_eq!(
            gate.evaluate(ip("198.51.100.77")),
            IpGateVerdict::Denied(IpGateDenial::Blacklisted)
        );
        assert_eq!(
            gate.evaluate(ip("203.0.113.9")).unwrap_denied().reason(),
            "IP is blacklisted"
        );
        // A blacklisted range does not leak onto its neighbors.
        assert!(matches!(
            gate.evaluate(ip("198.51.200.1")),
            IpGateVerdict::Allowed(_)
        ));
    }

    #[test]
    fn exemption_never_opens_the_whitelist_gate() {
        let gate = IpGateConfig::new(["192.0.2.1"], NIL, ["203.0.113.7"]).unwrap();
        assert_eq!(
            gate.evaluate(ip("203.0.113.7")),
            IpGateVerdict::Denied(IpGateDenial::NotInWhitelist)
        );
        assert_eq!(
            gate.evaluate(ip("203.0.113.7")).unwrap_denied().reason(),
            "IP not in whitelist"
        );
        assert!(matches!(
            gate.evaluate(ip("192.0.2.1")),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                is_exempt: false
            })
        ));
    }

    #[test]
    fn an_ip_on_both_lists_is_simply_a_whitelist_match() {
        let gate = IpGateConfig::new(["203.0.113.7"], NIL, ["203.0.113.7"]).unwrap();
        assert_eq!(
            gate.evaluate(ip("203.0.113.7")),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                is_exempt: true
            })
        );
    }

    #[test]
    fn exempt_exact_and_cidr_matches_set_the_flag_without_deny_paths() {
        let gate = IpGateConfig::new(NIL, NIL, ["198.51.100.7", "198.51.100.16/28"]).unwrap();
        for address in ["198.51.100.7", "198.51.100.20", "::ffff:198.51.100.7"] {
            assert_eq!(
                gate.evaluate(ip(address)),
                IpGateVerdict::Allowed(IpGateDecision {
                    is_whitelisted: false,
                    is_exempt: true
                }),
                "{address} must be exempt"
            );
        }
        assert_eq!(
            gate.evaluate(ip("198.51.100.15")),
            IpGateVerdict::Allowed(IpGateDecision::default()),
            "the address just below the CIDR range is not exempt"
        );
    }

    #[test]
    fn ipv4_mapped_parity_across_all_list_forms() {
        // v4-mapped request against an exact v4 entry.
        let gate = IpGateConfig::new(["::ffff:203.0.113.7"], NIL, NIL).unwrap();
        assert!(matches!(
            gate.evaluate(ip("203.0.113.7")),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                ..
            })
        ));
        // v4-mapped request against a v4 CIDR entry.
        let gate = IpGateConfig::new(["203.0.113.0/24"], NIL, NIL).unwrap();
        assert!(matches!(
            gate.evaluate(ip("::ffff:203.0.113.99")),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                ..
            })
        ));
        // A v6-mapped CIDR entry still matches the raw v6 form.
        let gate = IpGateConfig::new(["::ffff:0:0/96"], NIL, NIL).unwrap();
        assert!(matches!(
            gate.evaluate(ip("::ffff:203.0.113.99")),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                ..
            })
        ));
        assert!(!matches!(
            gate.evaluate(ip("2001:db8::1")),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                ..
            })
        ));
    }

    #[test]
    fn exempt_flag_is_only_set_after_the_deny_checks_pass() {
        let gate = IpGateConfig::new(NIL, ["198.51.100.7"], ["198.51.100.7"]).unwrap();
        assert!(matches!(
            gate.evaluate(ip("198.51.100.7")),
            IpGateVerdict::Denied(IpGateDenial::Blacklisted)
        ));
    }

    impl IpGateVerdict {
        /// The denial of a `Denied` verdict, for assertions.
        fn unwrap_denied(self) -> IpGateDenial {
            match self {
                Self::Allowed(_) => panic!("expected a denial"),
                Self::Denied(denial) => denial,
            }
        }
    }

    #[test]
    fn unwrap_denied_extracts_the_denial_reason() {
        let gate = IpGateConfig::new(Vec::<String>::new(), ["198.51.100.7"], Vec::<String>::new())
            .unwrap();
        let denial = gate.evaluate(ip("198.51.100.7")).unwrap_denied();
        assert_eq!(denial, IpGateDenial::Blacklisted);
    }

    #[test]
    fn route_gate_whitelist_takes_over_the_route_verdict() {
        // The corpus shape (pipeline_ip_control::route_ip_whitelist_denies_other_ip).
        let gate = RouteIpGate::new(["192.0.2.40"], NIL).unwrap();
        assert!(gate.whitelist_configured());
        assert_eq!(
            gate.evaluate(ip("192.0.2.40")),
            RouteIpVerdict::Allowed,
            "a whitelist member passes the route stage"
        );
        assert_eq!(
            gate.evaluate(ip("192.0.2.11")),
            RouteIpVerdict::Denied,
            "a miss under a configured whitelist denies"
        );
    }

    #[test]
    fn route_gate_whitelist_verdict_wins_over_the_blacklist() {
        // The reference order (`check_route_ip_access`): the whitelist is
        // asked first and its answer settles the IP verdict; the blacklist
        // is only consulted when the whitelist is not configured.
        let gate = RouteIpGate::new(["192.0.2.40"], ["203.0.113.9", "198.51.100.0/24"]).unwrap();
        assert_eq!(
            gate.evaluate(ip("203.0.113.9")),
            RouteIpVerdict::Denied,
            "a blacklist match outside the whitelist denies"
        );
        assert_eq!(
            gate.evaluate(ip("198.51.100.7")),
            RouteIpVerdict::Denied,
            "a blacklist-range miss under the whitelist denies"
        );
        assert_eq!(
            gate.evaluate(ip("192.0.2.40")),
            RouteIpVerdict::Allowed,
            "the whitelist passes its members"
        );
        assert_eq!(
            gate.evaluate(ip("192.0.2.11")),
            RouteIpVerdict::Denied,
            "the whitelist denies its misses"
        );
    }

    #[test]
    fn route_gate_whitelisted_blacklisted_ip_passes() {
        // An IP on both lists passes: the whitelist verdict wins, exactly
        // the reference's `ip_result = _check_ip_whitelist(...)` settling
        // before the blacklist is ever consulted.
        let gate = RouteIpGate::new(["192.0.2.40"], ["192.0.2.40"]).unwrap();
        assert_eq!(
            gate.evaluate(ip("192.0.2.40")),
            RouteIpVerdict::Allowed,
            "a whitelisted IP that is also blacklisted passes the route stage"
        );
    }

    #[test]
    fn route_gate_blacklist_only_denies_its_matches() {
        let gate = RouteIpGate::new(NIL, ["203.0.113.9"]).unwrap();
        assert!(!gate.whitelist_configured());
        assert_eq!(gate.evaluate(ip("203.0.113.9")), RouteIpVerdict::Denied);
        assert_eq!(
            gate.evaluate(ip("192.0.2.11")),
            RouteIpVerdict::Unrestricted,
            "a non-member is left to the global gate"
        );
    }

    #[test]
    fn route_gate_empty_is_unrestricted() {
        let gate = RouteIpGate::new(NIL, NIL).unwrap();
        assert!(!gate.whitelist_configured());
        assert_eq!(
            gate.evaluate(ip("192.0.2.11")),
            RouteIpVerdict::Unrestricted
        );
    }

    #[test]
    fn route_gate_entries_match_like_the_global_gate() {
        // CIDR entries and IPv4-mapped request addresses go through the
        // same matcher as the global lists.
        let gate = RouteIpGate::new(["198.51.100.16/28"], NIL).unwrap();
        assert_eq!(gate.evaluate(ip("198.51.100.20")), RouteIpVerdict::Allowed);
        assert_eq!(gate.evaluate(ip("198.51.100.32")), RouteIpVerdict::Denied);

        let gate = RouteIpGate::new(["203.0.113.7"], NIL).unwrap();
        assert_eq!(
            gate.evaluate(IpAddr::from_str("::ffff:203.0.113.7").unwrap()),
            RouteIpVerdict::Allowed,
            "a v4-mapped request matches its IPv4 entry"
        );
    }

    #[test]
    #[should_panic(expected = "expected a denial")]
    fn unwrap_denied_panics_on_an_allowed_verdict() {
        // the helper's contract: it is only called on denied verdicts
        let gate = IpGateConfig::new(["198.51.100.7"], NIL, NIL).unwrap();
        let _ = gate.evaluate(ip("198.51.100.7")).unwrap_denied();
    }
}
