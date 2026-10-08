//! The client-IP extraction from the forwarded chain: the reference
//! `_utils/ip_extraction.py`'s depth-limited `X-Forwarded-For` walk, driven
//! by the `trusted_proxies` / `trusted_proxy_depth` knobs.
//!
//! Semantics, mirroring `_resolve_client_ip_from_forwarded_chain` exactly:
//!
//! ```text
//! no header:                        the connecting peer is the client
//! chain shorter than the depth:     the connecting peer (warn once)
//! right side holds unlisted peers:  walk right to left, skip trusted
//!                                   entries, first untrusted wins (warn)
//! otherwise:                        the entry `depth` from the right,
//!                                   port-stripped and canonicalized
//! ```
//!
//! A selected entry that is itself on the trusted list surfaces the
//! over-declared-depth warning as data ([`ChainWarnings`]) - the engine
//! has no logger, so the once-only warnings ride the result for the
//! caller to log. Unparseable entries and metacharacter candidates
//! (`*?[]\`) resolve back to the connecting peer, never to a spoof.
//!
//! # Example
//!
//! ```
//! use guard_core_engine::ip_extraction::{extract_client_ip, ClientIpSource};
//!
//! // A trusted proxy's claim is honored one hop deep.
//! let extraction = extract_client_ip(
//!     Some("10.0.0.1"),
//!     Some("203.0.113.7"),
//!     &["10.0.0.0/8".to_owned()],
//!     1,
//! );
//! assert_eq!(extraction.client_ip, "203.0.113.7");
//! assert_eq!(extraction.source, ClientIpSource::ForwardedChain);
//!
//! // An untrusted peer's header is ignored (the spoof signal rides along).
//! let extraction = extract_client_ip(
//!     Some("192.0.2.9"),
//!     Some("203.0.113.7"),
//!     &["10.0.0.0/8".to_owned()],
//!     1,
//! );
//! assert_eq!(extraction.client_ip, "192.0.2.9");
//! assert!(extraction.untrusted_forwarded_header);
//!
//! // No trusted proxies at all: the header never decides.
//! let extraction = extract_client_ip(Some("192.0.2.9"), Some("203.0.113.7"), &[], 1);
//! assert_eq!(extraction.client_ip, "192.0.2.9");
//! assert_eq!(extraction.source, ClientIpSource::Connecting);
//! ```

use std::net::IpAddr;
use std::str::FromStr;

use crate::ip_gate::{canonical, parse_network_entry};

/// The reference `UNKNOWN_CLIENT_IDENTITY`: the identity a request with no
/// connecting peer carries.
pub const UNKNOWN_CLIENT_IDENTITY: &str = "unknown";

/// Where the extracted client identity came from (the reference
/// `extract_client_ip`'s arms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIpSource {
    /// The connecting peer itself (not a trusted proxy, or nothing to walk).
    Connecting,
    /// Resolved from the `X-Forwarded-For` chain at the declared depth.
    ForwardedChain,
    /// No connecting peer at all (the `unknown` identity, or the `unix`
    /// proxy arm walking from unknown).
    Unknown,
}

/// The once-only warnings the reference logs, surfaced as data (the engine
/// has no logger; the caller logs and de-duplicates).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainWarnings {
    /// The chain had fewer entries than `trusted_proxy_depth` (the
    /// reference `_warn_forwarded_header_chain_too_short`).
    pub chain_too_short: bool,
    /// The declared depth over-counts the real hops: `Some(count)` of
    /// right-side entries are not on the trusted list (the reference
    /// `_warn_forwarded_header_depth_overcounts_hops`).
    pub depth_overcounts: Option<usize>,
    /// The selected entry is itself a trusted proxy (the reference
    /// `_warn_forwarded_header_selected_entry_trusted_proxy`).
    pub selected_entry_trusted: bool,
}

/// One extraction: the identity plus where it came from and what the
/// caller should log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIpExtraction {
    /// The resolved client identity (`UNKNOWN_CLIENT_IDENTITY` when the
    /// request has no peer and the `unix` arm does not apply).
    pub client_ip: String,
    /// Which arm produced the identity.
    pub source: ClientIpSource,
    /// An untrusted peer sent an `X-Forwarded-For` header (the reference's
    /// spoof-attempt signal: the header is ignored, the event is the
    /// caller's to emit).
    pub untrusted_forwarded_header: bool,
    /// The chain-walk warnings (empty unless [`ClientIpSource::
    /// ForwardedChain`] or the too-short arm ran).
    pub warnings: ChainWarnings,
}

/// `_strip_ip_brackets`.
#[must_use]
fn strip_ip_brackets(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value)
}

/// `_strip_forwarded_entry_port`: `[v6]:port` and `host:port` lose the
/// port; anything else passes through untouched.
#[must_use]
pub fn strip_forwarded_entry_port(value: &str) -> &str {
    if let Some(rest) = value.strip_prefix('[') {
        let Some(closing) = rest.find(']') else {
            return value;
        };
        let remainder = &rest[closing + 1..];
        let port_form = remainder.len() > 1
            && remainder.starts_with(':')
            && remainder[1..].chars().all(|c| c.is_ascii_digit());
        if remainder.is_empty() || port_form {
            return &rest[..closing];
        }
        return value;
    }
    match value.split_once(':') {
        Some((host, port))
            if !host.contains(':')
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            host
        }
        _ => value,
    }
}

/// `_canonicalize_ip`: canonical text for a parseable address (an
/// IPv4-mapped IPv6 collapses to its IPv4 text), the raw value otherwise.
#[must_use]
pub fn canonicalize_ip(value: &str) -> String {
    IpAddr::from_str(strip_ip_brackets(value)).map_or_else(|_| value.to_owned(), canonical_ip_text)
}

/// `_canonical_ip_text`.
#[must_use]
pub fn canonical_ip_text(addr: IpAddr) -> String {
    match addr {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |mapped| mapped.to_string()),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// `_forwarded_header_candidate_has_metachar`.
#[must_use]
pub fn candidate_has_metachar(candidate: &str) -> bool {
    candidate
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '\\'))
}

/// `_forwarded_header_ips`: the entries, comma-split, port-stripped.
#[must_use]
pub fn forwarded_header_ips(forwarded_for: &str) -> Vec<String> {
    forwarded_for
        .split(',')
        .map(|entry| strip_forwarded_entry_port(entry.trim()).to_owned())
        .collect()
}

/// `_proxy_matches` / `_is_trusted_proxy`: a bare entry compares exactly
/// (the `unix` token never matches a real peer), a CIDR entry contains the
/// canonicalized address.
#[must_use]
pub fn is_trusted_proxy(connecting: &str, trusted_proxies: &[String]) -> bool {
    trusted_proxies.iter().any(|proxy| {
        parse_network_entry(proxy).map_or_else(
            || connecting == proxy,
            |network| {
                IpAddr::from_str(connecting)
                    .is_ok_and(|addr| network.contains(canonical(addr)) || network.contains(addr))
            },
        )
    })
}

/// `_forwarded_header_candidate_addr`.
#[must_use]
fn candidate_addr(candidate: &str) -> Option<IpAddr> {
    IpAddr::from_str(candidate).ok()
}

/// `_forwarded_header_right_side_unlisted_count`.
#[must_use]
fn right_side_unlisted_count(
    ips: &[String],
    proxy_depth: u32,
    trusted_proxies: &[String],
) -> usize {
    let depth = usize::try_from(proxy_depth).unwrap_or(ips.len());
    let start = ips.len().saturating_sub(depth.saturating_sub(1));
    ips[start..]
        .iter()
        .filter(|entry| !is_trusted_proxy(&canonicalize_ip(entry), trusted_proxies))
        .count()
}

/// `_resolve_forwarded_chain_right_to_left`: the first untrusted entry
/// from the right, `None` when only trusted entries remain or a candidate
/// is unparseable or carries a metacharacter.
#[must_use]
fn resolve_chain_right_to_left(ips: &[String], trusted_proxies: &[String]) -> Option<String> {
    ips.iter()
        .rev()
        .find(|entry| !is_trusted_proxy(&canonicalize_ip(entry), trusted_proxies))
        .and_then(|entry| {
            // Metachar first: a metachar candidate never parses as an
            // address, so the reference's parse-then-metachar pair has
            // this exact truth table (the reference keeps the order only
            // for readability).
            if candidate_has_metachar(entry) {
                return None;
            }
            candidate_addr(entry).map(|_| canonicalize_ip(entry))
        })
}

/// `_resolve_client_ip_from_forwarded_chain`: the depth-limited walk with
/// the warnings as data. Failures and short chains degrade to the
/// connecting identity, never to a header claim.
#[must_use]
pub fn resolve_client_ip_from_forwarded_chain(
    canonical_connecting: &str,
    forwarded_for: Option<&str>,
    proxy_depth: u32,
    trusted_proxies: &[String],
) -> ClientIpExtraction {
    let mut warnings = ChainWarnings::default();
    let Some(forwarded_for) = forwarded_for.filter(|value| !value.is_empty()) else {
        return ClientIpExtraction {
            client_ip: canonical_connecting.to_owned(),
            source: ClientIpSource::Connecting,
            untrusted_forwarded_header: false,
            warnings,
        };
    };

    let ips = forwarded_header_ips(forwarded_for);
    let chain_length = ips.len();

    let depth = usize::try_from(proxy_depth).unwrap_or(0);
    if depth == 0 || chain_length < depth {
        warnings.chain_too_short = true;
        return ClientIpExtraction {
            client_ip: canonical_connecting.to_owned(),
            source: ClientIpSource::Connecting,
            untrusted_forwarded_header: false,
            warnings,
        };
    }

    if !trusted_proxies.is_empty() {
        let unlisted = right_side_unlisted_count(&ips, proxy_depth, trusted_proxies);
        if unlisted > 0 {
            warnings.depth_overcounts = Some(unlisted);
            let Some(resolved) = resolve_chain_right_to_left(&ips, trusted_proxies) else {
                return ClientIpExtraction {
                    client_ip: canonical_connecting.to_owned(),
                    source: ClientIpSource::Connecting,
                    untrusted_forwarded_header: false,
                    warnings,
                };
            };
            return ClientIpExtraction {
                client_ip: resolved,
                source: ClientIpSource::ForwardedChain,
                untrusted_forwarded_header: false,
                warnings,
            };
        }
    }

    // The depth gate above guarantees an entry at `depth` from the right.
    let candidate = ips[chain_length - depth].as_str();
    // Metachar first: a metachar candidate never parses as an address, so
    // the reference's parse-then-metachar pair has this exact truth table.
    if candidate_has_metachar(candidate) || candidate_addr(candidate).is_none() {
        return ClientIpExtraction {
            client_ip: canonical_connecting.to_owned(),
            source: ClientIpSource::Connecting,
            untrusted_forwarded_header: false,
            warnings,
        };
    }

    let client_ip = canonicalize_ip(candidate);
    warnings.selected_entry_trusted = is_trusted_proxy(&client_ip, trusted_proxies);
    ClientIpExtraction {
        client_ip,
        source: ClientIpSource::ForwardedChain,
        untrusted_forwarded_header: false,
        warnings,
    }
}

/// `extract_client_ip`: the reference entry point. `client_host` is the
/// connecting peer (`None` for a socket connection); `forwarded_for` the
/// raw `X-Forwarded-For` header.
#[must_use]
pub fn extract_client_ip(
    client_host: Option<&str>,
    forwarded_for: Option<&str>,
    trusted_proxies: &[String],
    proxy_depth: u32,
) -> ClientIpExtraction {
    let Some(client_host) = client_host else {
        // The socket arm: with `unix` on the proxy list the chain is still
        // walked, from the unknown identity (the reference `_handle` arm).
        if trusted_proxies.iter().any(|proxy| proxy == "unix") {
            let mut extraction = resolve_client_ip_from_forwarded_chain(
                UNKNOWN_CLIENT_IDENTITY,
                forwarded_for,
                proxy_depth,
                trusted_proxies,
            );
            if extraction.source == ClientIpSource::Connecting {
                UNKNOWN_CLIENT_IDENTITY.clone_into(&mut extraction.client_ip);
                extraction.source = ClientIpSource::Unknown;
            }
            return extraction;
        }
        return ClientIpExtraction {
            client_ip: UNKNOWN_CLIENT_IDENTITY.to_owned(),
            source: ClientIpSource::Unknown,
            untrusted_forwarded_header: false,
            warnings: ChainWarnings::default(),
        };
    };

    let canonical_connecting = canonicalize_ip(client_host);

    if trusted_proxies.is_empty() {
        // The preempted-header warning is the caller's (it rides the flag).
        return ClientIpExtraction {
            client_ip: canonical_connecting,
            source: ClientIpSource::Connecting,
            untrusted_forwarded_header: forwarded_for.is_some_and(|value| !value.is_empty()),
            warnings: ChainWarnings::default(),
        };
    }

    if !is_trusted_proxy(&canonical_connecting, trusted_proxies) {
        return ClientIpExtraction {
            client_ip: canonical_connecting,
            source: ClientIpSource::Connecting,
            untrusted_forwarded_header: forwarded_for.is_some_and(|value| !value.is_empty()),
            warnings: ChainWarnings::default(),
        };
    }

    resolve_client_ip_from_forwarded_chain(
        &canonical_connecting,
        forwarded_for,
        proxy_depth,
        trusted_proxies,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies(entries: &[&str]) -> Vec<String> {
        entries.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn the_depth_selects_the_entry_from_the_right() {
        // One appending proxy (depth 1): the client is the last entry.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("203.0.113.7"),
            &proxies(&["10.0.0.0/8"]),
            1,
        );
        assert_eq!(extraction.client_ip, "203.0.113.7");
        assert_eq!(extraction.source, ClientIpSource::ForwardedChain);
        assert!(!extraction.warnings.selected_entry_trusted);

        // Two appending proxies (depth 3, both hops trusted): the client
        // is third from the right.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("203.0.113.7, 198.51.100.4, 10.0.0.1"),
            &proxies(&["10.0.0.0/8", "198.51.100.0/24"]),
            3,
        );
        assert_eq!(extraction.client_ip, "203.0.113.7");

        // A depth that lands on a trusted entry still answers it, with
        // the over-declared-depth warning (the reference warns and
        // returns the selected entry).
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("203.0.113.7, 10.0.0.1"),
            &proxies(&["10.0.0.0/8"]),
            1,
        );
        assert_eq!(extraction.client_ip, "10.0.0.1");
        assert!(extraction.warnings.selected_entry_trusted);
    }

    #[test]
    fn a_short_chain_falls_back_to_the_connecting_peer() {
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("203.0.113.7"),
            &proxies(&["10.0.0.0/8"]),
            3,
        );
        assert_eq!(extraction.client_ip, "10.0.0.1");
        assert_eq!(extraction.source, ClientIpSource::Connecting);
        assert!(extraction.warnings.chain_too_short);
    }

    #[test]
    fn an_over_counting_depth_walks_right_to_left() {
        // The declared depth counts a hop the trusted list does not
        // cover: an entry to the right of the selection is unlisted, the
        // walk skips trusted entries and answers the first untrusted one.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("203.0.113.7, 198.51.100.4, 10.0.0.1"),
            &proxies(&["10.0.0.0/8"]),
            3,
        );
        assert_eq!(extraction.client_ip, "198.51.100.4");
        assert_eq!(extraction.warnings.depth_overcounts, Some(1));

        // A depth whose right side is fully trusted never walks.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("10.0.0.2, 10.0.0.1"),
            &proxies(&["10.0.0.0/8"]),
            1,
        );
        assert_eq!(extraction.client_ip, "10.0.0.1");
        assert_eq!(extraction.source, ClientIpSource::ForwardedChain);
        assert_eq!(extraction.warnings.depth_overcounts, None);
    }

    #[test]
    fn unparseable_and_metachar_candidates_degrade_to_connecting() {
        // The depth-selected entry is unparseable: connecting wins.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("not-an-ip"),
            &proxies(&["10.0.0.0/8"]),
            1,
        );
        assert_eq!(extraction.client_ip, "10.0.0.1");

        // The depth-selected entry carries a metacharacter: connecting.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("*.evil.example"),
            &proxies(&["10.0.0.0/8"]),
            1,
        );
        assert_eq!(extraction.client_ip, "10.0.0.1");

        // The right-to-left walk refuses a metachar candidate too: the
        // rightmost untrusted entry is malformed, so the walk has no
        // answer and the connecting identity stands.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("203.0.113.7, *.evil.example, 10.0.0.1"),
            &proxies(&["10.0.0.0/8"]),
            3,
        );
        assert_eq!(extraction.client_ip, "10.0.0.1");
        assert_eq!(extraction.warnings.depth_overcounts, Some(1));
    }

    #[test]
    fn a_selected_trusted_entry_warns() {
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("10.0.0.9, 10.0.0.1"),
            &proxies(&["10.0.0.0/8"]),
            2,
        );
        assert_eq!(extraction.client_ip, "10.0.0.9");
        assert!(extraction.warnings.selected_entry_trusted);
    }

    #[test]
    fn untrusted_peers_and_absent_proxies_ignore_the_header() {
        let extraction = extract_client_ip(
            Some("192.0.2.9"),
            Some("203.0.113.7"),
            &proxies(&["10.0.0.0/8"]),
            1,
        );
        assert_eq!(extraction.client_ip, "192.0.2.9");
        assert_eq!(extraction.source, ClientIpSource::Connecting);
        assert!(extraction.untrusted_forwarded_header);

        let extraction = extract_client_ip(Some("192.0.2.9"), Some("203.0.113.7"), &[], 1);
        assert_eq!(extraction.client_ip, "192.0.2.9");
        assert!(extraction.untrusted_forwarded_header);

        // No header at all: no spoof signal.
        let extraction = extract_client_ip(Some("192.0.2.9"), None, &proxies(&["10.0.0.0/8"]), 1);
        assert!(!extraction.untrusted_forwarded_header);
    }

    #[test]
    fn canonicalization_strips_brackets_ports_and_v4_mapping() {
        assert_eq!(
            strip_forwarded_entry_port("[2001:db8::1]:443"),
            "2001:db8::1"
        );
        assert_eq!(strip_forwarded_entry_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(
            strip_forwarded_entry_port("203.0.113.7:8443"),
            "203.0.113.7"
        );
        assert_eq!(strip_forwarded_entry_port("203.0.113.7"), "203.0.113.7");
        // A bare v6 with one colon-free host:port shape stays intact.
        assert_eq!(strip_forwarded_entry_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(canonicalize_ip("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(canonicalize_ip("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(canonicalize_ip("not-an-ip"), "not-an-ip");
    }

    #[test]
    fn the_unknown_arm_walks_only_for_unix_proxies() {
        let extraction = extract_client_ip(None, Some("203.0.113.7"), &proxies(&["unix"]), 1);
        assert_eq!(extraction.client_ip, "203.0.113.7");
        assert_eq!(extraction.source, ClientIpSource::ForwardedChain);

        let extraction = extract_client_ip(None, Some("203.0.113.7"), &[], 1);
        assert_eq!(extraction.client_ip, UNKNOWN_CLIENT_IDENTITY);
        assert_eq!(extraction.source, ClientIpSource::Unknown);

        // The unix walk degrading to connecting reports the unknown identity.
        let extraction = extract_client_ip(None, None, &proxies(&["unix"]), 1);
        assert_eq!(extraction.client_ip, UNKNOWN_CLIENT_IDENTITY);
        assert_eq!(extraction.source, ClientIpSource::Unknown);
    }

    #[test]
    fn malformed_bracket_entries_pass_through_untouched() {
        // An unterminated bracket form is not an address.
        assert_eq!(strip_forwarded_entry_port("[2001:db8::1"), "[2001:db8::1");
        // A bracket form with trailing junk past the closing bracket is
        // not `host]:port` either.
        assert_eq!(
            strip_forwarded_entry_port("[2001:db8::1]junk"),
            "[2001:db8::1]junk"
        );
        // The clean forms still strip.
        assert_eq!(strip_forwarded_entry_port("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(
            strip_forwarded_entry_port("[2001:db8::1]:443"),
            "2001:db8::1"
        );
    }

    #[test]
    fn an_empty_trusted_list_still_walks_at_the_declared_depth() {
        // Direct resolve with no proxy list: the depth arm answers the
        // entry (the caller decided trust before calling).
        let extraction =
            resolve_client_ip_from_forwarded_chain("10.0.0.1", Some("203.0.113.7"), 1, &[]);
        assert_eq!(extraction.client_ip, "203.0.113.7");
        assert_eq!(extraction.source, ClientIpSource::ForwardedChain);
        assert_eq!(extraction.warnings, ChainWarnings::default());
    }

    #[test]
    fn an_unparseable_rightmost_untrusted_entry_ends_the_walk() {
        // The rightmost untrusted entry does not parse: the walk has no
        // answer and the connecting identity stands.
        let extraction = extract_client_ip(
            Some("10.0.0.1"),
            Some("203.0.113.7, not-an-ip, 10.0.0.1"),
            &proxies(&["10.0.0.0/8"]),
            3,
        );
        assert_eq!(extraction.client_ip, "10.0.0.1");
        assert_eq!(extraction.warnings.depth_overcounts, Some(1));
    }

    #[test]
    fn the_unix_token_never_matches_a_real_peer() {
        assert!(!is_trusted_proxy("127.0.0.1", &proxies(&["unix"])));
        assert!(is_trusted_proxy(
            "10.1.2.3",
            &proxies(&["unix", "10.0.0.0/8"])
        ));
        assert!(is_trusted_proxy("10.1.2.3", &proxies(&["10.1.2.3"])));
    }
}
